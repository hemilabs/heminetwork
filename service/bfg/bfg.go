// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
)

const (
	logLevel = "INFO"
	appName  = "bfg" // Prometheus
)

var log = loggo.GetLogger(appName)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	ListenAddress           string
	LogLevel                string
	PrometheusListenAddress string
	PrometheusNamespace     string
	PprofListenAddress      string
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenAddress:       bfgapi.DefaultListenAddress,
		LogLevel:            logLevel,
		PrometheusNamespace: appName,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	server *http.ServeMux

	// Prometheus
	promCollectors  []prometheus.Collector
	promPollVerbose bool // set to true to print stats during poll
	isRunning       bool
	cmdsProcessed   prometheus.Counter
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg:    cfg,
		server: http.NewServeMux(),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: cfg.PrometheusNamespace,
			Name:      "web_calls_total",
			Help:      "The total number of successful web commands",
		}),
	}

	return s, nil
}

func (s *Server) handleKeystoneFinality(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleKeystoneFinality: %v", r.RemoteAddr)
	defer log.Tracef("handleKeystoneFinality exit: %v", r.RemoteAddr)

	if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}

	q := r.URL.Query()
	keystone, ok := q["keystone"]
	if !ok || (ok && keystone[0] == "") {
		fmt.Fprintf(w, "this is the last keystone")
		return
	}

	ks, err := chainhash.NewHashFromStr(keystone[0])
	if err != nil {
		e := fmt.Sprintf("invalid keystone: %v\n\n%v - %v\n", err,
			http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		http.Error(w, e, http.StatusBadRequest)
		return
	}

	log.Infof("looking for keystone: %v", ks)

	e := fmt.Sprintf("keystone not found: %v\n\n%v - %v\n", ks,
		http.StatusNotFound, http.StatusText(http.StatusNotFound))
	http.Error(w, e, http.StatusNotFound)
}

func (s *Server) running() bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return s.isRunning
}

func (s *Server) testAndSetRunning(b bool) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	old := s.isRunning
	s.isRunning = b
	return old != s.isRunning
}

func (s *Server) promRunning() float64 {
	r := s.running()
	if r {
		return 1
	}
	return 0
}

// Collectors returns the Prometheus collectors available for the server.
func (s *Server) Collectors() []prometheus.Collector {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.promCollectors == nil {
		// Naming: https://prometheus.io/docs/practices/naming/
		s.promCollectors = []prometheus.Collector{
			s.cmdsProcessed,
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "running",
				Help:      "Whether the BFG service is running",
			}, s.promRunning),
		}
	}
	return s.promCollectors
}

func (s *Server) promPoll(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}

		if s.promPollVerbose {
			s.mtx.RLock()
			log.Infof("FIXME PROMETHEUS POLL")
			s.mtx.RUnlock()
		}

	}
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return errors.New("bfg already running")
	}
	defer s.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// HTTP server
	httpErrCh := make(chan error)
	if s.cfg.ListenAddress != "" {
		mux := http.NewServeMux()
		log.Infof("handle keystone finality: %s", bfgapi.RouteKeystoneFinality)
		mux.HandleFunc(bfgapi.RouteKeystoneFinality, s.handleKeystoneFinality)

		httpServer := &http.Server{
			Addr:        s.cfg.ListenAddress,
			Handler:     mux,
			BaseContext: func(_ net.Listener) context.Context { return ctx },
		}
		go func() {
			log.Infof("Listening: %s", s.cfg.ListenAddress)
			httpErrCh <- httpServer.ListenAndServe()
		}()
		defer func() {
			if err := httpServer.Shutdown(ctx); err != nil {
				log.Errorf("http server exit: %v", err)
				return
			}
			log.Infof("web server shutdown cleanly")
		}()
	}

	// pprof
	if s.cfg.PprofListenAddress != "" {
		p, err := pprof.NewServer(&pprof.Config{
			ListenAddress: s.cfg.PprofListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create pprof server: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := p.Run(ctx); !errors.Is(err, context.Canceled) {
				log.Errorf("pprof server terminated with error: %v", err)
				return
			}
			log.Infof("pprof server clean shutdown")
		}()
	}

	// Prometheus
	if s.cfg.PrometheusListenAddress != "" {
		d, err := deucalion.New(&deucalion.Config{
			ListenAddress: s.cfg.PrometheusListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := d.Run(ctx, s.Collectors()); !errors.Is(err, context.Canceled) {
				log.Errorf("prometheus terminated with error: %v", err)
				return
			}
			log.Infof("prometheus clean shutdown")
		}()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			err := s.promPoll(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Errorf("prometheus poll terminated with error: %v", err)
				}
				return
			}
		}()
	}

	// Welcome user.

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-httpErrCh:
	}
	cancel()

	log.Infof("bfg service shutting down")
	s.wg.Wait()
	log.Infof("bfg service clean shutdown")

	return err
}
