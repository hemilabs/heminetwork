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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo/v2"
	"github.com/mitchellh/go-homedir"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/tss"

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
	Connect                 []string
	Home                    string
	ListenAddress           string
	LogLevel                string
	MaxConnections          int
	PprofListenAddress      string
	PrivateKey              string
	PrometheusListenAddress string
	PrometheusNamespace     string
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg  *Config
	data string // Data directory home+identity

	// Sessions
	sessions map[Identity]*Transport

	// Secrets
	secret *Secret

	// TSS
	preParams keygen.LocalPreParams

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
		sessions:     make(map[Identity]*Transport, cfg.MaxConnections),
	}, nil
}

// genID is used in testing only.
func genID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Errorf("read random: %w", err))
	}
	return hex.EncodeToString(buf)
}

func (s *Server) newSession(id *Identity, t *Transport) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if _, ok := s.sessions[*id]; ok {
		return errors.New("duplicate identity")
	}
	s.sessions[*id] = t

	return nil
}

func (s *Server) deleteSession(id *Identity) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	t := s.sessions[*id]
	if t == nil {
		return fmt.Errorf("no session: %v", id)
	}
	delete(s.sessions, *id)
	return t.Close()
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

func (s *Server) allSessionIDs() tss.UnSortedPartyIDs {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	ids := make(tss.UnSortedPartyIDs, 0, len(s.sessions)+1)
	for k := range s.sessions {
		id := tss.NewPartyID(k.String(), k.String(), new(big.Int).SetBytes(k[:]))
		ids = append(ids, id)
	}
	// XXX include self, this is a little clunky but roll with it for now
	self := s.secret.Identity.String()
	ids = append(ids, tss.NewPartyID(self, self,
		new(big.Int).SetBytes(s.secret.Identity[:])))
	return ids
}

func (s *Server) newTransport(ctx context.Context, conn net.Conn) (*Identity, *Transport, error) {
	transport, err := NewTransportFromCurve(ecdh.X25519()) // XXX config option
	if err != nil {
		return nil, nil, fmt.Errorf("new transport: %w", err)
	}

	err = transport.KeyExchange(ctx, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("key exchange: %w", err) // XXX too loud?
	}

	id, err := transport.Handshake(ctx, s.secret)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err) // XXX too loud?
	}

	return id, transport, nil
}

func (s *Server) handle(ctx context.Context, id *Identity, t *Transport) {
	defer s.deleteSession(id)
	defer s.wg.Done()

	log.Debugf("handle: %v", id)
	defer log.Debugf("handle exit: %v", id)

	for {
		header, payload, err := t.Read()
		if err != nil {
			// XXX too loud?
			log.Errorf("read %v: %v", id, err)
			return
		}
		log.Infof("%v", spew.Sdump(header))
		log.Infof("%v", spew.Sdump(payload))

		// XXX make this a map like str2pt with callbacks
		switch payload.(type) {
		case *PingRequest:
			err := t.Write(s.secret.Identity, PingResponse{
				OriginTimestamp: payload.(*PingRequest).OriginTimestamp,
				PeerTimestamp:   time.Now().Unix(),
			})
			if err != nil {
				panic(err)
			}

			// XXX use ping request for now to kick off keygen
			committee := s.allSessionIDs()
			log.Infof("%v", spew.Sdump(committee))
			err = t.Write(s.secret.Identity, KeygenRequest{
				Curve:     "secp256k1",
				Committee: committee,
				Threshold: len(committee) - 1,
			})
			if err != nil {
				panic(err)
			}

		default:
		}
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

func (s *Server) client(ctx context.Context, them *Identity, t *Transport) error {
	log.Infof("client: %v", them)
	defer log.Infof("client: %v exit", them)

	// Always ping
	// XXX make this a call, not a write.
	err := t.Write(s.secret.Identity, PingRequest{
		OriginTimestamp: time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("ping %v: %w", them, err)
	}

	for {
		header, cmd, err := t.Read()
		if err != nil {
			return fmt.Errorf("read %v: %w", them, err)
		}
		log.Infof("%v", spew.Sdump(header))
		log.Infof("%v", spew.Sdump(cmd))
	}

	return nil
}

func (s *Server) connect(ctx context.Context, c string, errC chan error) {
	defer s.wg.Done()

	// XXX timeout

	log.Infof("connect: %v", c)
	defer log.Infof("connect: %v exit", c)

	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", c)
	if err != nil {
		errC <- err
		return
	}
	clientTransport := new(Transport)
	defer func() {
		if err := clientTransport.Close(); err != nil {
			log.Errorf("client close: %v", err)
			return
		}
	}()

	if err := clientTransport.KeyExchange(ctx, conn); err != nil {
		errC <- err
		return
	}
	them, err := clientTransport.Handshake(ctx, s.secret)
	if err != nil {
		errC <- err
		return
	}

	// This should no longer be terminal since we made it through key
	// exchange.
	if err := s.client(ctx, them, clientTransport); err != nil {
		log.Errorf("client: %v", err)
		return
	}
}

func (s *Server) connectAll(ctx context.Context, errC chan error) {
	defer s.wg.Done()

	log.Tracef("connectAll")
	defer log.Tracef("connectAll")

	// XXX should we exit when we can't connect?
	for k := range s.cfg.Connect {
		s.wg.Add(1)
		go s.connect(ctx, s.cfg.Connect[k], errC)
	}
}

func (s *Server) listen(ctx context.Context, errC chan error) {
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

		// XXX this can cause rate limitting since it isn't in a go
		// routine. This is obviously a DDOS and needs fixing.
		id, transport, err := s.newTransport(ctx, conn)
		if err != nil {
			log.Errorf("transport: %v", err)
			continue
		}

		// Insert into sessions
		if err := s.newSession(id, transport); err != nil {
			log.Errorf("session: %v", err)
			continue
		}

		log.Infof("connected %v: %v", conn.RemoteAddr(), id)

		// handle connection
		s.wg.Add(1)
		go s.handle(ctx, id, transport)
	}
}

func (s *Server) initPaillierPrimes(pctx context.Context) error {
	log.Tracef("initPaillierPrimes")
	defer log.Tracef("initPaillierPrimes exit")

	ctx, cancel := context.WithTimeout(pctx, 1*time.Minute)
	defer cancel()

	preparamsFilename := filepath.Join(s.data, "preparams.json")
	ppf, err := os.Open(preparamsFilename)
	if errors.Is(err, os.ErrNotExist) {
		log.Infof("Generating TSS Paillier primes")
		lpp, err := keygen.GeneratePreParamsWithContextAndRandom(ctx, rand.Reader)
		if err != nil {
			return err
		}
		jpp, err := json.MarshalIndent(lpp, "  ", "  ")
		if err != nil {
			return err
		}
		err = os.WriteFile(preparamsFilename, jpp, 0o400)
		if err != nil {
			return err
		}
		s.preParams = *lpp
		log.Infof("Generating TSS Paillier primes complete")
		return nil
	} else if err != nil {
		return err
	}

	if err := json.NewDecoder(ppf).Decode(&s.preParams); err != nil {
		return err
	}
	return ppf.Close()
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return errors.New("continuum already running")
	}
	defer s.testAndSetRunning(false)

	// Make sure we have a valid secret
	var err error
	s.secret, err = NewSecretFromString(s.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	s.cfg.PrivateKey = "" // hopefully PrivateKey is reaped later.

	// Setup home
	s.cfg.Home, err = homedir.Expand(s.cfg.Home)
	if err != nil {
		return fmt.Errorf("expand: %w", err)
	}
	s.data = filepath.Join(s.cfg.Home, s.secret.Identity.String())
	err = os.MkdirAll(s.data, 0o700)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// Read or generate Paillier primes.
	err = s.initPaillierPrimes(ctx)
	if err != nil {
		return fmt.Errorf("party: %w", err)
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
	if s.cfg.ListenAddress != "" {
		s.wg.Add(1)
		go s.listen(ctx, errC)
	}

	if len(s.cfg.Connect) != 0 {
		s.wg.Add(1)
		go s.connectAll(ctx, errC)
	}

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
