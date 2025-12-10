// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package continuum implements the service that runs the p2p network for
// MinerFI Multi-Party Threshold Signature Scheme.
package continuum

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo/v2"
	"github.com/mitchellh/go-homedir"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/v2/service/deucalion"
	"github.com/hemilabs/heminetwork/v2/service/pprof"
)

const (
	logLevel = "INFO"
	appName  = "continuum"

	defaultListenAddress  = "localhost:45067"
	defaultMaxConnections = 8
)

var log = loggo.GetLogger(appName)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	Home                    string
	LogLevel                string
	PprofListenAddress      string
	PrometheusListenAddress string
	PrometheusNamespace     string
	PrivateKey              string
	ListenAddress           string
	MaxConnections          int
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// Sessions
	sessions map[string]*Transport

	// Secrets
	secret *Secret

	// Listener
	listenConfig *net.ListenConfig

	// Prometheus
	promCollectors  []prometheus.Collector
	promPollVerbose bool // set to true to print stats during poll
	isRunning       bool
}

type Info struct {
	Online bool
}

func NewDefaultConfig() *Config {
	return &Config{
		LogLevel:            logLevel,
		PrometheusNamespace: appName,
		PrivateKey:          "",
		ListenAddress:       defaultListenAddress,
		MaxConnections:      defaultMaxConnections,
	}
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	return &Server{
		cfg:          cfg,
		listenConfig: &net.ListenConfig{},
	}, nil
}

func genID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Errorf("read random: %w", err))
	}
	return hex.EncodeToString(buf)
}

func (s *Server) newSession(t *Transport) string {
	for {
		id := genID()
		s.mtx.Lock()
		if _, ok := s.sessions[id]; ok {
			s.mtx.Unlock()

			// ID is already used, retry.
			continue
		}
		s.sessions[id] = t
		s.mtx.Unlock()
		return id
	}
}

func (s *Server) deleteSession(id string) {
	s.mtx.Lock()
	t, ok := s.sessions[id]
	delete(s.sessions, id)
	s.mtx.Unlock()
	if !ok {
		log.Errorf("id not found in sessions %s", id)
	}
	if err := t.Close(); err != nil {
		log.Errorf("close session %s: %v", id, err)
	}
}

func (s *Server) deleteAllSessions() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for id, t := range s.sessions {
		if err := t.Close(); err != nil {
			log.Errorf("close session %s: %v", id, err)
		}
	}
	s.sessions = nil
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	log.Infof("handle: %v", conn.RemoteAddr())
	defer log.Infof("handle exit: %v", conn.RemoteAddr())

	defer s.wg.Done()
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Errorf("close %v: %v", conn.RemoteAddr(), err)
		}
	}()

	transport, err := NewTransportFromCurve(ecdh.X25519()) // XXX config option
	if err != nil {
		log.Errorf("create new transport: %v", err)
		return
	}
	id := s.newSession(transport)
	defer s.deleteSession(id)

	err = transport.KeyExchange(ctx, conn)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		log.Errorf("key exchange: %v", err)
		return
	}

	hr, err := transport.Handshake(ctx, s.secret)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		log.Errorf("handshake: %v", err)
		return
	}

	log.Infof("connected %v: %v", conn.RemoteAddr(), hr)
	for {
		header, payload, err := transport.Read()
		if err != nil {
			panic(err) // XXX
		}
		log.Infof("%v", spew.Sdump(header))
		log.Infof("%v", spew.Sdump(payload))
	}
}

// Collectors returns the Prometheus collectors available for the server.
func (s *Server) Collectors() []prometheus.Collector {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.promCollectors == nil {
		// Naming: https://prometheus.io/docs/practices/naming/
		s.promCollectors = []prometheus.Collector{
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "running",
				Help:      "Whether the TBC service is running",
			}, s.promRunning),
		}
	}
	return s.promCollectors
}

func (s *Server) Running() bool {
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

func (s *Server) promPoll(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
		}

		if s.promPollVerbose {
			s.mtx.RLock()
			log.Infof("promPoll XXX")
			s.mtx.RUnlock()
		}
	}
}

func (s *Server) promRunning() float64 {
	r := s.Running()
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

	return s.isHealthy(ctx), Info{Online: true}, nil
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return errors.New("continuum already running")
	}
	defer s.testAndSetRunning(false)

	var err error
	s.cfg.Home, err = homedir.Expand(s.cfg.Home)
	if err != nil {
		return fmt.Errorf("expand: %w", err)
	}
	s.secret, err = NewSecretFromString(s.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	s.cfg.PrivateKey = "" // hopefully PrivateKey is reaped later.

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

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

	errC := make(chan error)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		listener, err := s.listenConfig.Listen(ctx, "tcp", s.cfg.ListenAddress)
		if err != nil {
			errC <- err
			return
		}
		go func() {
			<-ctx.Done()
			if err := listener.Close(); err != nil {
				log.Errorf("listner close: %v", err)
			}
			s.deleteAllSessions()
		}()

		for {
			conn, err := listener.Accept()
			if errors.Is(ctx.Err(), context.Canceled) {
				return
			}
			if err != nil {
				log.Errorf("accept: %v", err)
				continue
			}

			s.mtx.RLock()
			conNum := len(s.sessions)
			s.mtx.RUnlock()
			if conNum >= s.cfg.MaxConnections {
				// XXX send a "busy" message?
				log.Debugf("server full, connection rejected: %s",
					conn.RemoteAddr())
				if err := conn.Close(); err != nil {
					log.Errorf("close connection %s:  %v", err)
				}
				continue
			}

			// handle connection
			s.wg.Add(1)
			go s.handle(ctx, conn)
		}
	}()

	log.Infof("Identity: %v", s.secret)

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errC:
	}
	cancel()

	log.Infof("continuum service shutting down")
	s.wg.Wait()
	log.Infof("continuum service clean shutdown")

	return err
}
