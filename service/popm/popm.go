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
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/api/popapi"
	"github.com/hemilabs/heminetwork/bitcoin/wallet"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer/blockstream"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer/tbcgozer"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/zuul/memory"
	"github.com/hemilabs/heminetwork/hemi"
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
	GozerType               string
	TBCURL                  string
}

func NewDefaultConfig() *Config {
	return &Config{
		Network:             "testnet3",
		PrometheusNamespace: appName,
		OpgethURL:           "http://127.0.0.1:9999/v1/ws", // XXX set this using defaults
		GozerType:           "TBC",
		TBCURL:              tbcgozer.DefaultURL,
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

	// wallet
	gozer gozer.Gozer
	mz    zuul.Zuul
	vc    *vinzclortho.VinzClortho
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
	var err error
	s.vc, err = vinzclortho.VinzClorthoNew(s.params)
	if err != nil {
		return nil, err
	}
	err = s.vc.Unlock(cfg.BitcoinSecret)
	if err != nil {
		return nil, err
	}
	ek, err := s.vc.DeriveHD(defaultPopAccount, defaultPopChild)
	if err != nil {
		return nil, err
	}
	s.address, s.public, err = vinzclortho.AddressAndPublicFromExtended(s.params, ek)
	if err != nil {
		return nil, err
	}

	s.mz, err = memory.MemoryNew(s.params)
	if err != nil {
		return nil, err
	}
	err = s.mz.Put(&zuul.NamedKey{
		Name:       "private",
		Account:    defaultPopAccount,
		Child:      defaultPopChild,
		HD:         true,
		PrivateKey: ek,
	})
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

// XXX broadcasting should be in a different function
func (s *Server) mineKeystone(ctx context.Context, ks *hemi.L2Keystone) error {
	log.Infof("Mining an L2 keystone at height %d...", ks.L2BlockNumber)

	// go m.dispatchEvent(EventTypeMineKeystone, EventMineKeystone{Keystone: ks})

	btcHeight, err := s.gozer.BtcHeight(ctx)
	if err != nil {
		return fmt.Errorf("get Bitcoin height: %w", err)
	}

	payToScript, err := vinzclortho.ScriptFromPubKeyHash(s.address)
	if err != nil {
		return fmt.Errorf("get pay to address script: %w", err)
	}
	if len(payToScript) != 25 {
		return fmt.Errorf("incorrect length for pay to public key script (%d != 25)", len(payToScript))
	}
	scriptHash := vinzclortho.ScriptHashFromScript(payToScript)

	// Estimate BTC fees.
	feeEstimates, err := s.gozer.FeeEstimates(ctx)
	if err != nil {
		return fmt.Errorf("get fee estimates: %w", err)
	}
	feeAmount, err := gozer.FeeByConfirmations(6, feeEstimates)
	if err != nil {
		return fmt.Errorf("get fee by confirmations: %w", err)
	}

	// Retrieve available UTXOs for the miner.
	utxos, err := s.gozer.UtxosByAddress(ctx, s.address, 0, 0)
	if err != nil {
		return fmt.Errorf("retrieve available Bitcoin UTXOs: %w", err)
	}
	log.Tracef("Looking for UTXOs for script hash %v", scriptHash)

	log.Debugf("Miner has %d available UTXOs for script hash %v at Bitcoin height %d",
		len(utxos), scriptHash, btcHeight)

	// Build transaction.
	popTx, prevOut, err := wallet.PoPTransactionCreate(ks, uint32(btcHeight),
		btcutil.Amount(feeAmount.SatsPerByte), utxos, payToScript)
	if err != nil {
		return fmt.Errorf("create Bitcoin transaction: %w", err)
	}

	// Sign input.
	err = wallet.TransactionSign(&chaincfg.TestNet3Params, s.mz, popTx, prevOut)
	if err != nil {
		return fmt.Errorf("sign Bitcoin transaction: %w", err)
	}

	// broadcast tx
	log.Tracef("Broadcasting Bitcoin transaction %x", popTx)
	log.Infof("Broadcasting PoP transaction to Bitcoin %s...",
		s.params.Name)

	txHash, err := s.gozer.BroadcastTx(ctx, popTx)
	if err != nil {
		return fmt.Errorf("broadcast PoP transaction: %w", err)
	}

	log.Infof(
		"Successfully broadcast PoP transaction to Bitcoin %s with TX hash %v",
		s.params.Name, txHash,
	)

	// go s.dispatchEvent(EventTypeTransactionBroadcast,
	// EventTransactionBroadcast{Keystone: ks, TxHash: txHash.String()})

	return nil
}

// XXX Test ONLY. Subscription and dealing
// with keystones needs to be properly done.
func (s *Server) handleOpgethSubscription(ctx context.Context) error {
	log.Tracef("subscribeOpgeth")
	defer log.Tracef("subscribeOpgeth exit")

	// headersCh := make(chan *types.Header, 10)
	headersCh := make(chan string, 10)
	sub, err := s.opgethClient.Client().Subscribe(ctx, "kss", headersCh)
	// sub, err := s.opgethClient.SubscribeNewHead(context.Background(), headersCh)
	if err != nil {
		return err
	}

	for {
		select {
		case err = <-sub.Err():
		case <-ctx.Done():
			err = ctx.Err()
		case n := <-headersCh:
			log.Tracef("kss notification received: %s", n)
			result := popapi.L2KeystoneResponse{}
			log.Tracef("Sending Keystone Request")
			if err := s.opgethClient.Client().Call(&result, "keystone_request", 3); err != nil {
				return err
			}
			for _, ks := range result.L2Keystones {
				log.Tracef("Received keystone at height %v", ks.L2BlockNumber)
				err = s.mineKeystone(ctx, ks)
				if err != nil {
					log.Errorf("Failed to mine keystone: %v", err)
				}
			}
			continue
		}
		return err
	}
}

func (s *Server) connectOpgeth(pctx context.Context) error {
	log.Tracef("connectOpgeth")
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
		defer s.opgethWG.Done()
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

	// XXX this should be in New() but tbcgozer requires context
	var err error
	switch strings.ToLower(s.cfg.GozerType) {
	case "tbc":
		s.gozer, err = tbcgozer.TBCGozerNew(ctx, s.cfg.TBCURL)
		if err != nil {
			log.Errorf("TBC gozer creation failed: %v", err)
		}
	case "blockstream":
		s.gozer, err = blockstream.BlockstreamNew(s.params)
		if err != nil {
			log.Errorf("Blockstream gozer creation failed: %v", err)
		}
	default:
		return fmt.Errorf("unknown gozer type %v", s.cfg.GozerType)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.opgeth(ctx)
	}()

	log.Infof("bitcoin address   : %v", s.address)
	log.Infof("bitcoin public key: %v", s.public)

	<-ctx.Done()
	err = ctx.Err()

	log.Infof("pop miner shutting down")

	s.wg.Wait()
	log.Infof("pop miner has shutdown cleanly")

	return err
}
