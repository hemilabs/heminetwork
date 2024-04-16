// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package deucalion provides an easy-to-use Prometheus metrics server.
//
// The deucalion package provides an automatic Prometheus server that will
// start automatically when the PROMETHEUS_ADDRESS environment variable is set.
// To use the deucalion package only for the automatic metrics server, you may
// import it as:
//
//	import _ "github.com/hemilabs/heminetwork/service/deucalion"
//
// After being imported, the application may be run with the PROMETHEUS_ADDRESS
// environment variable set to an address to start the Prometheus metrics server:
//
//	PROMETHEUS_ADDRESS=localhost:2112 myapp
//
// The deucalion package may also be used to create a Prometheus metrics
// server with custom collectors:
//
//	d, _ := deucalion.New(&deucalion.Config{
//	    ListenAddress: PrometheusListenAddress,
//	})
//
//	_ = d.Run(ctx, []prometheus.Collector{})
package deucalion

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hemilabs/heminetwork/config"
)

const (
	daemonName      = "deucalion"
	defaultLogLevel = daemonName + "=INFO"
)

var (
	log = loggo.GetLogger(daemonName)

	cfg = NewDefaultConfig()
	cm  = config.CfgMap{
		"DEUCALION_LOG_LEVEL": config.Config{
			Value:        &cfg.logLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for this package; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.ListenAddress,
			DefaultValue: "", // bssapi.DefaultPrometheusListen,
			Help:         "address and port automatic prometheus listens on",
			Print:        config.PrintAll,
		},
	}
)

func init() {
	if err := config.Parse(cm); err != nil {
		panic(fmt.Errorf("could not parse config during init: %w", err))
	}
	if cfg.ListenAddress == "" {
		return
	}

	loggo.ConfigureLoggers(cfg.logLevel)

	// launch prometheus automatically
	ctx := context.Background()
	d, err := New(cfg)
	if err != nil {
		panic(fmt.Errorf("create server: %w", err))
	}
	go func() {
		if err = d.Run(ctx, nil); !errors.Is(err, context.Canceled) {
			log.Errorf("Deucalion server terminated with error: %v", err)
		}
	}()
}

type Config struct {
	logLevel      string
	ListenAddress string
}

func NewDefaultConfig() *Config {
	return &Config{
		logLevel:      defaultLogLevel,
		ListenAddress: "", // localhost:2112
	}
}

type Deucalion struct {
	mtx       sync.RWMutex
	wg        sync.WaitGroup
	isRunning bool
	cfg       *Config
}

func New(cfg *Config) (*Deucalion, error) {
	return &Deucalion{cfg: cfg}, nil
}

func handle(service string, mux *http.ServeMux, pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandleFunc(pattern, handler)
	log.Infof("handle (%v): %v", service, pattern)
}

func (d *Deucalion) running() bool {
	d.mtx.RLock()
	defer d.mtx.RUnlock()
	return d.isRunning
}

func (d *Deucalion) testAndSetRunning(b bool) bool {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	old := d.isRunning
	d.isRunning = b
	return old != d.isRunning
}

func (d *Deucalion) Run(ctx context.Context, cs []prometheus.Collector) error {
	if !d.testAndSetRunning(true) {
		return errors.New("already running")
	}
	defer d.testAndSetRunning(false)

	if d.cfg.ListenAddress == "" {
		return errors.New("listen address is required")
	}

	reg := prometheus.NewRegistry()
	allCollectors := []prometheus.Collector{
		collectors.NewBuildInfoCollector(),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	}
	if cs != nil {
		allCollectors = append(allCollectors, cs...)
	}
	for _, c := range allCollectors {
		if err := reg.Register(c); err != nil {
			return fmt.Errorf("register collector: %w", err)
		}
	}

	prometheusMux := http.NewServeMux()
	handle("prometheus", prometheusMux, "/metrics", promhttp.HandlerFor(reg,
		promhttp.HandlerOpts{Registry: reg}).ServeHTTP)
	httpPrometheusServer := &http.Server{
		Addr:        d.cfg.ListenAddress,
		Handler:     prometheusMux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	httpPrometheusErrCh := make(chan error)
	go func() {
		log.Infof("Prometheus listening: %v", d.cfg.ListenAddress)
		httpPrometheusErrCh <- httpPrometheusServer.ListenAndServe()
	}()
	defer func() {
		if err := httpPrometheusServer.Shutdown(ctx); err != nil {
			log.Errorf("http prometheus server exit: %v", err)
		}
	}()

	var (
		done bool
		err  error
	)
	for !done {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			done = true
		case err = <-httpPrometheusErrCh:
			return err
		}
	}

	log.Infof("deucalion service shutting down")

	d.wg.Wait()
	log.Infof("deucalion service clean shutdown")

	return err
}
