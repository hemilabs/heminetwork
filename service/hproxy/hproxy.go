// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
)

const (
	logLevel = "INFO"

	promSubsystem = "hproxy_service" // Prometheus

)

var log = loggo.GetLogger("hproxy")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	HVMURLs                 []string
	Network                 string
	RequestTimeout          time.Duration
	LogLevel                string
	PrometheusListenAddress string
	PprofListenAddress      string
}

const DefaultRequestTimeout = 9 * time.Second // Smaller than 12s

func NewDefaultConfig() *Config {
	return &Config{
		Network:        "mainnet",
		RequestTimeout: DefaultRequestTimeout,
	}
}

type HProxy struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// Prometheus
	isRunning bool
}

func NewHProxy(cfg *Config) (*HProxy, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}

	hp := &HProxy{
		cfg: cfg,
	}

	switch strings.ToLower(cfg.Network) {
	case "mainnet":
	case "sepolia":
	default:
		return nil, fmt.Errorf("unknown network %q", cfg.Network)
	}

	return hp, nil
}

func (h *HProxy) handlePrometheus(ctx context.Context) error {
	d, err := deucalion.New(&deucalion.Config{
		ListenAddress: h.cfg.PrometheusListenAddress,
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	cs := []prometheus.Collector{
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Subsystem: promSubsystem,
			Name:      "running",
			Help:      "Is hproxy service running.",
		}, h.promRunning),
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		if err := d.Run(ctx, cs, nil); !errors.Is(err, context.Canceled) {
			log.Errorf("prometheus terminated with error: %v", err)
			return
		}
		log.Infof("prometheus clean shutdown")
	}()

	return nil
}

func (h *HProxy) running() bool {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.isRunning
}

func (h *HProxy) testAndSetRunning(b bool) bool {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	old := h.isRunning
	h.isRunning = b
	return old != h.isRunning
}

func (h *HProxy) promRunning() float64 {
	r := h.running()
	if r {
		return 1
	}
	return 0
}

type ProxyHandler struct {
	p      *httputil.ReverseProxy
	remote *url.URL
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Infof("ServeHTTP %v", r.URL)
	w.Header().Set("X-Cow", "Moo")
	r.Host = p.remote.Host
	p.p.ServeHTTP(w, r)
}

func (h *HProxy) Run(pctx context.Context) error {
	if !h.testAndSetRunning(true) {
		return errors.New("hproxy already running")
	}
	defer h.testAndSetRunning(false)

	// Validate urls
	if len(h.cfg.HVMURLs) == 0 {
		return errors.New("must provide hvm url(s)")
	}
	for k := range h.cfg.HVMURLs {
		u, err := url.Parse(h.cfg.HVMURLs[k])
		if err != nil {
			return fmt.Errorf("invalid url %v: %v", h.cfg.HVMURLs[k], err)
		}
		switch u.Scheme {
		case "http", "https":
		default:
			return fmt.Errorf("unsuported scheme [%v]: %v", k, u.Scheme)
		}

		proxy := httputil.NewSingleHostReverseProxy(u)
		// use http.Handle instead of http.HandleFunc when your struct implements http.Handler interface
		http.Handle("/", &ProxyHandler{p: proxy, remote: u})
		err = http.ListenAndServe(":8080", nil)
		if err != nil {
			panic(err)
		}
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// Prometheus
	if h.cfg.PrometheusListenAddress != "" {
		if err := h.handlePrometheus(ctx); err != nil {
			return fmt.Errorf("handlePrometheus: %w", err)
		}
	}

	// pprof
	if h.cfg.PprofListenAddress != "" {
		p, err := pprof.NewServer(&pprof.Config{
			ListenAddress: h.cfg.PprofListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create pprof server: %w", err)
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
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
	}
	cancel()

	log.Infof("hproxy shutting down...")

	h.wg.Wait()
	log.Infof("hproxy shutdown cleanly")

	return err
}
