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
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/api/popapi"
	"github.com/hemilabs/heminetwork/api/protocol"
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

type opnodeCmd struct {
	msg any
	ch  chan any
}

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	Network                 string
	BitcoinSecret           string
	LogLevel                string
	OpnodeURL               string
	PrometheusListenAddress string
	PrometheusNamespace     string
	PprofListenAddress      string
}

func NewDefaultConfig() *Config {
	return &Config{
		Network:             "testnet3",
		PrometheusNamespace: appName,
		OpnodeURL:           "http://127.0.0.1:9999/v1/ws", // XXX set this using defaults
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

	// opnode
	opnodeWG    sync.WaitGroup
	opnodeCmdCh chan opnodeCmd
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

//nolint:unused // IT IS FUCKING USED
func (s *Server) callOpnode(pctx context.Context, timeout time.Duration, msg any) (any, error) {
	// XXX this code does not go here. move to caller
	log.Tracef("callOpnode %T", msg)
	defer log.Tracef("callOpnode exit %T", msg)

	bc := opnodeCmd{
		msg: msg,
		ch:  make(chan any),
	}

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	// attempt to send
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s.opnodeCmdCh <- bc:
	default:
		return nil, errors.New("pop command queue full")
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case payload := <-bc.ch:
		if err, ok := payload.(error); ok {
			return nil, err
		}
		return payload, nil
	}

	// Won't get here
}

func (s *Server) handleOpnodeWebsocketRead(ctx context.Context, conn *protocol.Conn) error {
	defer s.opnodeWG.Done()

	log.Tracef("handleOpnodeWebsocketRead")
	defer log.Tracef("handleOpnodeWebsocketRead exit")
	for {
		cmd, rid, payload, err := popapi.ReadConn(ctx, conn)
		if err != nil {

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			log.Infof("Connection to opnode was lost, reconnecting...")
			continue
		}

		switch cmd {
		case popapi.CmdPingRequest:
			p := payload.(*popapi.PingRequest)
			response := &popapi.PingResponse{
				OriginTimestamp: p.Timestamp,
				Timestamp:       time.Now().Unix(),
			}

			if err := popapi.Write(ctx, conn, rid, response); err != nil {
				log.Errorf("Failed to write ping response to opnode server: %v", err)
			}
		case popapi.CmdL2KeystoneNotification:
			// TODO: Add L2KeystoneHandle
			continue
		default:
			return fmt.Errorf("unknown command: %v", cmd)
		}
	}
}

func (s *Server) handleOpnodeCallCompletion(pctx context.Context, conn *protocol.Conn, bc opnodeCmd) {
	log.Tracef("handleOpnodeCallCompletion")
	defer log.Tracef("handleOpnodeCallCompletion exit")

	ctx, cancel := context.WithTimeout(pctx, defaultRequestTimeout)
	defer cancel()

	log.Tracef("handleOpnodeCallCompletion: %v", spew.Sdump(bc.msg))

	_, _, payload, err := popapi.Call(ctx, conn, bc.msg)
	if err != nil {
		log.Errorf("handleOpnodeCallCompletion %T: %v", bc.msg, err)
		select {
		case bc.ch <- err:
		default:
		}
	}
	select {
	case bc.ch <- payload:
		log.Tracef("handleOpnodeCallCompletion returned: %v", spew.Sdump(payload))
	default:
	}
}

func (s *Server) connectOpnode(pctx context.Context) error {
	log.Tracef("connectOpnode")
	defer log.Tracef("connectOpnode exit")

	conn, err := protocol.NewConn(s.cfg.OpnodeURL, &protocol.ConnOptions{
		ReadLimit: 1 * (1 << 20), // 1 MiB
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	err = conn.Connect(ctx)
	if err != nil {
		return err
	}

	s.opnodeWG.Add(1)
	go s.handleOpnodeWebsocketRead(ctx, conn)

	log.Debugf("connected to opnode: %s", s.cfg.OpnodeURL)

	// Wait for exit
	s.opnodeWG.Wait()

	return nil
}

func (s *Server) opnode(ctx context.Context) {
	log.Tracef("opnode")
	defer log.Tracef("opnode exit")

	for {
		log.Tracef("connecting to: %v", s.cfg.OpnodeURL)
		if err := s.connectOpnode(ctx); err != nil {
			// Do nothing
			log.Tracef("connectOpnode: %v", err)
		} else {
			log.Infof("Connected to opnode: %s", s.cfg.OpnodeURL)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		log.Debugf("reconnecting to: %v", s.cfg.OpnodeURL)
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
		s.opnode(ctx)
	}()

	log.Infof("bitcoin address %v", s.address)
	log.Infof("bitcoin public key %v", s.public)

	<-ctx.Done()
	err := ctx.Err()

	log.Infof("pop miner shutting down")

	s.wg.Wait()
	log.Infof("pop miner has shutdown cleanly")

	return err
}
