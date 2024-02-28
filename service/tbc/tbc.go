// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/postgres"
)

const (
	logLevel = "INFO"

	promSubsystem = "tbc_service" // Prometheus
)

var log = loggo.GetLogger("tbc")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type Config struct {
	LogLevel                string
	PgURI                   string
	PrometheusListenAddress string
	Network                 string
}

func NewDefaultConfig() *Config {
	return &Config{
		LogLevel: logLevel,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// bitcoin network
	wireNet     wire.BitcoinNet
	chainParams *chaincfg.Params
	peer        *peer // make plural

	db tbcd.Database

	// Prometheus
	isRunning bool
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg: cfg,
	}
	// We could use a PGURI verification here.
	// single peer for now

	mainnetPort := "8333"
	testnetPort := "18333"
	var port string
	switch cfg.Network {
	case "mainnet":
		port = mainnetPort
		s.wireNet = wire.MainNet
		s.chainParams = &chaincfg.MainNetParams
	case "testnet", "testnet3":
		port = testnetPort
		s.wireNet = wire.TestNet3
		s.chainParams = &chaincfg.TestNet3Params
	default:
		return nil, fmt.Errorf("invalid network: %v", cfg.Network)
	}

	var err error
	s.peer, err = NewPeer(s.wireNet, "140.238.169.133:"+port)
	if err != nil {
		return nil, fmt.Errorf("new peer: %v", err)
	}

	return s, nil
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

func (s *Server) p2p(ctx context.Context, btcNet string) {
	defer s.wg.Done()

	log.Tracef("p2p")
	defer log.Tracef("p2p exit")

	err := s.peer.connect(ctx)
	if err != nil {
		// XXX use a pool
		log.Errorf("connect: %v", err)
		return
	}

	log.Debugf("p2p handshake complete with: %v\n", s.peer.address)

	// send ibd start using get blocks
	fmt.Printf("genesis hash: %v\n", s.chainParams.GenesisHash)
	getBlocks := wire.NewMsgGetBlocks(s.chainParams.GenesisHash)
	err = s.peer.write(getBlocks)
	if err != nil {
		log.Errorf("write getBlocks: %v", err)
		return
	}

	verbose := false
	for {
		// see if we were interrupted
		select {
		case <-ctx.Done():
			log.Errorf("p2p: %v", ctx.Err())
			return
		default:
		}

		msg, err := s.peer.read()
		if err == wire.ErrUnknownMessage {
			// skip unknown
			continue
		} else if err != nil {
			// XXX this is why we need a pool
			log.Errorf("read: %w", err)
			return
		}

		if verbose {
			spew.Dump(msg)
		}

		switch m := msg.(type) {
		case *wire.MsgPing:
			go handlePing(s.peer, m)

		case *wire.MsgInv:
			go handleInv(s.peer, m)

		case *wire.MsgBlock:
			go handleBlock(s.peer, m)

		default:
			log.Errorf("unhandled message type: %T\n", msg)
		}
	}
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return fmt.Errorf("tbc already running")
	}
	defer s.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// Connect to db.
	// XXX should we reconnect?
	var err error
	s.db, err = postgres.New(ctx, s.cfg.PgURI)
	if err != nil {
		return fmt.Errorf("Failed to connect to database: %v", err)
	}
	defer s.db.Close()

	// Prometheus
	if s.cfg.PrometheusListenAddress != "" {
		d, err := deucalion.New(&deucalion.Config{
			ListenAddress: s.cfg.PrometheusListenAddress,
		})
		if err != nil {
			return fmt.Errorf("failed to create server: %w", err)
		}
		cs := []prometheus.Collector{
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Subsystem: promSubsystem,
				Name:      "running",
				Help:      "Is tbc service running.",
			}, s.promRunning),
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := d.Run(ctx, cs); err != context.Canceled {
				log.Errorf("prometheus terminated with error: %v", err)
				return
			}
			log.Infof("prometheus clean shutdown")
		}()
	}

	s.wg.Add(1)
	go s.p2p(ctx, "testnet3")

	select {
	case <-ctx.Done():
		err = ctx.Err()
	}
	cancel()

	log.Infof("tbc service shutting down")
	s.wg.Wait()
	log.Infof("tbc service clean shutdown")

	return err
}
