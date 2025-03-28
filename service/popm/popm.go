// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
)

const (
	logLevel = "INFO"
	appName  = "popm"

	defaultPopAccount     = 1337
	defaultPopChild       = 0
	defaultRequestTimeout = 3 * time.Second
)

var log = loggo.GetLogger("popm")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	Network                 string
	BitcoinSecret           string
	LogLevel                string
	OpgethURL               string
	PrometheusListenAddress string
	PrometheusNamespace     string
	PprofListenAddress      string
}

func NewDefaultConfig() *Config {
	return &Config{
		Network:             "testnet3",
		PrometheusNamespace: appName,
		OpgethURL:           "http://127.0.0.1:9999/v1/ws", // XXX set this using defaults
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// bitcoin
	params  *chaincfg.Params
	public  *hdkeychain.ExtendedKey
	address btcutil.Address

	// Prometheus
	isRunning      bool
	promCollectors []prometheus.Collector

	// opgeth
	opgethClient *ethclient.Client // XXX evaluate if ok
	opgethWG     sync.WaitGroup
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}

	s := &Server{
		cfg: cfg,
	}

	switch strings.ToLower(cfg.Network) {
	case "mainnet":
		s.params = &chaincfg.MainNetParams
	case "testnet", "testnet3":
		s.params = &chaincfg.TestNet3Params
	default:
		return nil, fmt.Errorf("unknown bitcoin network %v", cfg.Network)
	}

	if cfg.BitcoinSecret == "" {
		return nil, errors.New("no bitcoin secret provided")
	}
	vc, err := vinzclortho.VinzClorthoNew(s.params)
	if err != nil {
		return nil, err
	}
	err = vc.Unlock(cfg.BitcoinSecret)
	if err != nil {
		return nil, err
	}
	ek, err := vc.DeriveHD(defaultPopAccount, defaultPopChild)
	if err != nil {
		return nil, err
	}
	s.address, s.public, err = vinzclortho.AddressAndPublicFromExtended(s.params, ek)
	if err != nil {
		return nil, err
	}
	return s, nil
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

func (s *Server) handleOpgethSubscription(ctx context.Context) error {
	log.Tracef("subscribeOpgeth")
	defer log.Tracef("subscribeOpgeth exit")

	headersCh := make(chan *types.Header, 10)
	sub, err := s.opgethClient.SubscribeNewHead(context.Background(), headersCh)
	if err != nil {
		return err
	}

	for {
		select {
		case err = <-sub.Err():
		case <-ctx.Done():
			err = ctx.Err()
		case n := <-headersCh:
			log.Infof(spew.Sdump(n)) // XXX
			continue
		}
		return err
	}
}

func (s *Server) connectOpgeth(pctx context.Context) error {
	log.Tracef("connectOpnode")
	defer log.Tracef("connectOpgeth exit")

	var err error
	s.opgethClient, err = ethclient.Dial(s.cfg.OpgethURL)
	if err != nil {
		return err
	}
	defer s.opgethClient.Close()

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	log.Debugf("connected to opgeth: %s", s.cfg.OpgethURL)

	rWSCh := make(chan error)
	s.opgethWG.Add(1)
	go func() {
		s.opgethWG.Done()
		rWSCh <- s.handleOpgethSubscription(ctx)
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-rWSCh:
	}
	cancel()
	s.opgethClient.Close()

	// Wait for exit
	s.opgethWG.Wait()

	return err
}

func (s *Server) opgeth(ctx context.Context) {
	log.Tracef("opgeth")
	defer log.Tracef("opgeth exit")

	for {
		log.Tracef("connecting to: %v", s.cfg.OpgethURL)
		if err := s.connectOpgeth(ctx); err != nil {
			// Do nothing
			log.Tracef("connectOpgeth: %v", err)
		} else {
			log.Infof("Connected to opgeth: %s", s.cfg.OpgethURL)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		log.Debugf("reconnecting to: %v", s.cfg.OpgethURL)
	}
}

func (s *Server) promPoll(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}

		// Insert prometheus poll here
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
				Help:      "Whether the pop miner service is running",
			}, s.promRunning),
		}
	}
	return s.promCollectors
}

func (s *Server) Run(pctx context.Context) error {
	if !s.testAndSetRunning(true) {
		return errors.New("popmd already running")
	}
	defer s.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

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

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.opgeth(ctx)
	}()

	log.Infof("bitcoin address   : %v", s.address)
	log.Infof("bitcoin public key: %v", s.public)

	<-ctx.Done()
	err := ctx.Err()

	log.Infof("pop miner shutting down")

	s.wg.Wait()
	log.Infof("pop miner has shutdown cleanly")

	return err
}
