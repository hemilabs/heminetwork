// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package pprof

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/pprof"
	"sync/atomic"

	"github.com/juju/loggo"
)

var log = loggo.GetLogger("pprof")

type Config struct {
	ListenAddress string
}

type Server struct {
	cfg     *Config
	running atomic.Bool
}

func NewServer(cfg *Config) (*Server, error) {
	return &Server{cfg: cfg}, nil
}

func (s *Server) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}
	defer s.running.CompareAndSwap(true, false)

	if s.cfg.ListenAddress == "" {
		return errors.New("listen address is required")
	}

	pprofMux := http.NewServeMux()
	pprofMux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	pprofMux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	pprofMux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	pprofMux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	pprofMux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))

	pprofHttpServer := &http.Server{
		Addr:        s.cfg.ListenAddress,
		Handler:     pprofMux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	httpErrCh := make(chan error)
	go func() {
		log.Infof("pprof listening: %s", s.cfg.ListenAddress)
		httpErrCh <- pprofHttpServer.ListenAndServe()
	}()
	defer func() {
		if err := pprofHttpServer.Shutdown(ctx); err != nil {
			log.Errorf("pprof http server exit: %v", err)
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-httpErrCh:
		return err
	}
}
