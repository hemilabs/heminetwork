package p2pproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/juju/loggo"
)

const (
	logLevel = "INFO"
)

var log = loggo.GetLogger("p2p")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type Config struct {
	Network string
}

func NewDefaultConfig() *Config {
	return &Config{}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// service control
	isRunning bool

	// bitcoin network
	wireNet     wire.BitcoinNet
	chainParams *chaincfg.Params
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg: cfg,
	}

	switch cfg.Network {
	case "mainnet":
		s.wireNet = wire.MainNet
		s.chainParams = &chaincfg.MainNetParams

	case "testnet3":
		s.wireNet = wire.TestNet3
		s.chainParams = &chaincfg.TestNet3Params

	case "regnet":
		s.wireNet = wire.TestNet
		s.chainParams = &chaincfg.RegressionNetParams

	default:
		return nil, fmt.Errorf("invalid network: %v", cfg.Network)
	}

	return s, nil
}

func (s *Server) testAndSetRunning(b bool) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	old := s.isRunning
	s.isRunning = b
	return old != s.isRunning
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return errors.New("tbc already running")
	}
	defer s.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
		//case err = <-errC:
		//case err = <-httpErrCh:
	}
	cancel()

	log.Infof("p2p service shutting down")
	s.wg.Wait()
	log.Infof("p2p service clean shutdown")

	return err
}
