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
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
)

const (
	logLevel = "INFO"
	appName  = "popm"

	defaultPopAccount = 1337
	defaultPopChild   = 0
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
	PrometheusListenAddress string
	PrometheusNamespace     string
	PprofListenAddress      string
}

func NewDefaultConfig() *Config {
	return &Config{
		Network:             "testnet3",
		PrometheusNamespace: appName,
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

////nolint:unused // IT IS FUCKING USED
//func (m *Miner) callTBC(pctx context.Context, timeout time.Duration, msg any) (any, error) {
//	log.Tracef("callTBC %T", msg)
//	defer log.Tracef("callTBC exit %T", msg)
//
//	bc := tbcCmd{
//		msg: msg,
//		ch:  make(chan any),
//	}
//
//	ctx, cancel := context.WithTimeout(pctx, timeout)
//	defer cancel()
//
//	// attempt to send
//	select {
//	case <-ctx.Done():
//		return nil, ctx.Err()
//	case m.tbcCmdCh <- bc:
//	default:
//		return nil, errors.New("tbc command queue full")
//	}
//
//	// Wait for response
//	select {
//	case <-ctx.Done():
//		return nil, ctx.Err()
//	case payload := <-bc.ch:
//		if err, ok := payload.(error); ok {
//			return nil, err
//		}
//		return payload, nil
//	}
//
//	// Won't get here
//}
//
//func (m *Miner) handleTBCWebsocketRead(ctx context.Context, conn *protocol.Conn) {
//	defer m.tbcWg.Done()
//
//	log.Tracef("handleTBCWebsocketRead")
//	defer log.Tracef("handleTBCWebsocketRead exit")
//	for {
//		_, _, _, err := tbcapi.ReadConn(ctx, conn)
//		if err != nil {
//
//			// See if we were terminated
//			select {
//			case <-ctx.Done():
//				// XXX too loud
//				log.Errorf("handleTBCWebsocketRead: %v", ctx.Err())
//			case <-time.After(m.holdoffTimeout):
//			}
//
//			log.Infof("Connection with TBC server was lost, reconnecting...")
//			continue
//		}
//	}
//}
//
//func (m *Miner) handleTBCCallCompletion(pctx context.Context, conn *protocol.Conn, bc tbcCmd) {
//	log.Tracef("handleTBCCallCompletion")
//	defer log.Tracef("handleTBCCallCompletion exit")
//
//	ctx, cancel := context.WithTimeout(pctx, m.requestTimeout)
//	defer cancel()
//
//	log.Tracef("handleTBCCallCompletion: %v", spew.Sdump(bc.msg))
//
//	_, _, payload, err := tbcapi.Call(ctx, conn, bc.msg)
//	if err != nil {
//		log.Errorf("handleTBCCallCompletion %T: %v", bc.msg, err)
//		select {
//		case bc.ch <- err:
//		default:
//		}
//	}
//	select {
//	case bc.ch <- payload:
//		log.Tracef("handleTBCCallCompletion returned: %v", spew.Sdump(payload))
//	default:
//	}
//}
//
//func (m *Miner) handleTBCWebsocketCallUnauth(ctx context.Context, conn *protocol.Conn) {
//	defer m.tbcWg.Done()
//
//	log.Tracef("handleTBCWebsocketCallUnauth")
//	defer log.Tracef("handleTBCWebsocketCallUnauth exit")
//	for {
//		select {
//		case <-ctx.Done():
//			return
//		case bc := <-m.tbcCmdCh:
//			go m.handleTBCCallCompletion(ctx, conn, bc)
//		}
//	}
//}
//
//func (m *Miner) connectTBC(pctx context.Context) error {
//	log.Tracef("connectTBC")
//	defer log.Tracef("connectTBC exit")
//
//	conn, err := protocol.NewConn(m.cfg.TBCWSURL, &protocol.ConnOptions{
//		ReadLimit: 6 * (1 << 20), // 6 MiB
//	})
//	if err != nil {
//		return err
//	}
//
//	ctx, cancel := context.WithCancel(pctx)
//	defer cancel()
//
//	err = conn.Connect(ctx)
//	if err != nil {
//		return err
//	}
//
//	m.tbcWg.Add(1)
//	go m.handleTBCWebsocketCallUnauth(ctx, conn)
//
//	m.tbcWg.Add(1)
//	go m.handleTBCWebsocketRead(ctx, conn)
//
//	log.Debugf("Connected to TBC: %s", m.cfg.TBCWSURL)
//	m.tbcConnected.Store(true)
//
//	// Wait for exit
//	m.tbcWg.Wait()
//	m.tbcConnected.Store(false)
//
//	return nil
//}
//
//func (m *Miner) tbc(ctx context.Context) {
//	defer m.wg.Done()
//
//	log.Tracef("tbc")
//	defer log.Tracef("tbc exit")
//
//	for {
//		if err := m.connectTBC(ctx); err != nil {
//			// Do nothing
//			log.Tracef("connectTBC: %v", err)
//		} else {
//			log.Infof("Connected to TBC: %s", m.cfg.TBCWSURL)
//		}
//		// See if we were terminated
//		select {
//		case <-ctx.Done():
//			return
//		case <-time.After(m.holdoffTimeout):
//		}
//
//		log.Debugf("Reconnecting to: %v", m.cfg.TBCWSURL)
//	}
//}

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
				Help:      "Whether the TBC service is running",
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

	log.Infof("bitcoin address %v", s.address)
	log.Infof("bitcoin public key %v", s.public)

	<-ctx.Done()
	err := ctx.Err()

	log.Infof("pop miner shutting down")

	s.wg.Wait()
	log.Infof("pop miner has shutdown cleanly")

	return err
}
