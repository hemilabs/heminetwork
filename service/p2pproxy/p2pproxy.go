package p2pproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/juju/loggo"
)

const (
	logLevel = "TRACE"
)

var log = loggo.GetLogger("p2p")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type Config struct {
	Network string
	Address string
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
	p           *tbc.Peer
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

func (s *Server) BlockByHash(pctx context.Context, h *chainhash.Hash) (*btcutil.Block, error) {
	log.Tracef("BlockByHash: %v", h)
	defer log.Tracef("BlockByHash exit %v", h)

	getData := wire.NewMsgGetData()
	getData.InvList = append(getData.InvList,
		&wire.InvVect{
			Type: wire.InvTypeBlock,
			Hash: *h,
		})

	err := s.p.Write(0, getData)
	if err != nil {
		return nil, err
	}
	time.Sleep(2 * time.Second)
	return nil, nil
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

	p, err := tbc.NewPeer(s.wireNet, 1, s.cfg.Address)
	if err != nil {
		return err
	}
	err = p.Connect(ctx)
	if err != nil {
		return err
	}
	s.p = p

	for {
		var rmsg wire.Message
		rmsg, _, err = p.Read(0)
		if errors.Is(err, wire.ErrUnknownMessage) {
			log.Infof("unknown command")
			continue
		} else if err != nil {
			break
		}
		log.Infof("%T", rmsg)

		select {
		case <-ctx.Done():
			err = ctx.Err()
			//case err = <-errC:
			//case err = <-httpErrCh:
		}

		switch m := rmsg.(type) {
		case *wire.MsgPing:
			err = p.Write(0, wire.NewMsgPong(m.Nonce))
			if err != nil {
				break
			}
			log.Infof("replied pong")

		default:
			log.Infof("unknown command: %T", rmsg)
			continue
		}
	}
	cancel()

	log.Infof("p2p service shutting down")
	s.wg.Wait()
	log.Infof("p2p service clean shutdown")

	return err
}
