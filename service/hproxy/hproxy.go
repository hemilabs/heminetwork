// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
)

const (
	appName = "hproxy" // Prometheus

	logLevel = "INFO"

	promSubsystem = "hproxy_service" // Prometheus

	DefaultRequestTimeout = 9 * time.Second  // Smaller than 12s
	DefaultListenAddress  = "localhost:8545" // Default geth port

	expectedClients = 1000
)

var log = loggo.GetLogger(appName)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	HVMURLs                 []string
	ListenAddress           string
	LogLevel                string
	Network                 string
	PrometheusListenAddress string
	PrometheusNamespace     string
	PprofListenAddress      string
	RequestTimeout          time.Duration
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenAddress:       DefaultListenAddress,
		Network:             "mainnet",
		PrometheusNamespace: appName,
		RequestTimeout:      DefaultRequestTimeout,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	hvmHandlers []HVMHandler   // hvm nodes
	clients     map[string]int // [ip_address]server_id

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
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}

	s := &Server{
		cfg:     cfg,
		clients: make(map[string]int, expectedClients),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: cfg.PrometheusNamespace,
			Name:      "proxy_calls",
			Help:      "The total number of successful proxy calls",
		}),
	}

	switch strings.ToLower(cfg.Network) {
	case "mainnet":
	case "sepolia":
	default:
		return nil, fmt.Errorf("unknown network %q", cfg.Network)
	}

	return s, nil
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
				Help:      "Whether the hproxy service is running",
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

func (s *Server) running() bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
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

func (s *Server) isHealthy(_ context.Context) bool {
	return true // XXX
}

func (s *Server) health(ctx context.Context) (bool, any, error) {
	log.Tracef("health")
	defer log.Tracef("health exit")

	type health struct {
		Healthy bool   `json:"health"`
		Remove  string `json:"remove"`
	}

	return s.isHealthy(ctx), health{Healthy: true, Remove: "FIXME"}, nil // XXX
}

type HVMState int

const (
	StateInvalid   HVMState = 0
	StateHealthy            = 1
	StateUnhealthy          = 2
	StateRemoved            = 3
)

type HVMHandler struct {
	id int // server id
	rp *httputil.ReverseProxy
	u  *url.URL // XXX remove?

	state HVMState
}

func lowest(x []int) int {
	if len(x) == 0 {
		return -1
	}

	minIndex := 0
	for i := 1; i < len(x); i++ {
		if x[i] < x[minIndex] {
			minIndex = i
		}
	}
	return minIndex
}

func (s *Server) handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProxyRequest: %v", r.RemoteAddr)
	defer log.Tracef("handleProxyRequest exit: %v", r.RemoteAddr)

	// Select host to call
	// XXX expire client connections at some point
	s.mtx.Lock()
	var (
		id int
		ok bool
	)
	connections := make([]int, len(s.hvmHandlers))
	if id, ok = s.clients[r.RemoteAddr]; !ok {
		for _, v := range s.clients {
			connections[v]++
		}
		// spew.Dump(connections)
		id = lowest(connections)
		s.clients[r.RemoteAddr] = id
	}
	hvm := s.hvmHandlers[id]
	s.mtx.Unlock()

	// XXX handle aggressive timeputs for ServeHTTP
	log.Debugf("handleProxyRequest: remote %v url '%v' -> node %v",
		r.RemoteAddr, r.URL, id)

	// Throw call over the fence
	w.Header().Set("X-Hproxy", strconv.Itoa(id))
	hvm.rp.ServeHTTP(w, r)

	s.cmdsProcessed.Inc()
}

func (s *Server) Run(pctx context.Context) error {
	if !s.testAndSetRunning(true) {
		return errors.New("hproxy already running")
	}
	defer s.testAndSetRunning(false)

	// Validate urls
	if len(s.cfg.HVMURLs) == 0 {
		return errors.New("must provide hvm url(s)")
	}
	s.hvmHandlers = make([]HVMHandler, 0, len(s.cfg.HVMURLs))
	for k := range s.cfg.HVMURLs {
		u, err := url.Parse(s.cfg.HVMURLs[k])
		if err != nil {
			return fmt.Errorf("invalid url %v: %v", s.cfg.HVMURLs[k], err)
		}
		switch u.Scheme {
		case "http", "https":
		default:
			return fmt.Errorf("unsuported scheme [%v]: %v", k, u.Scheme)
		}

		s.hvmHandlers = append(s.hvmHandlers, HVMHandler{
			id: k,
			u:  u, // XXX do we need this?
			rp: &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(u)
					r.SetXForwarded()
				},
				ErrorLog:     nil, // XXX wrap in loggo
				ErrorHandler: nil, // XXX add this to deal with errors
			},
		})
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// HTTP server
	httpErrCh := make(chan error)
	if s.cfg.ListenAddress == "" {
		return errors.New("must provide listen address")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleProxyRequest)

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
			if err := d.Run(ctx, s.Collectors(), s.health); !errors.Is(err, context.Canceled) {
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

	log.Infof("Starting hproxy")

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-httpErrCh:
	}
	cancel()

	log.Infof("hproxy shutting down...")
	s.wg.Wait()
	log.Infof("hproxy shutdown cleanly")

	return err
}
