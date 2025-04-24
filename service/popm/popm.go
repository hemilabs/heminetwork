// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
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

	l2KeystonesLen = 10

	bitcoinSourceBlockstream = "blockstream"
	bitcoinSourceTBC         = "tbc"
)

var (
	log                    = loggo.GetLogger("popm")
	l2KeystoneRetryTimeout = 15 * time.Second
)

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
	BitcoinSource           string
	BitcoinURL              string
	RetryMineThreshold      uint
}

func NewDefaultConfig() *Config {
	return &Config{
		Network:             "testnet3",
		PrometheusNamespace: appName,
		OpgethURL:           "http://127.0.0.1:9999/v1/ws", // XXX set this using defaults
		BitcoinSource:       bitcoinSourceTBC,
		BitcoinURL:          tbcgozer.DefaultURL,
	}
}

type L2KeystoneProcessingContainer struct {
	l2Keystone hemi.L2Keystone
	// transaction        *wire.MsgTx
	requiresProcessing bool
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// bitcoin
	params  *chaincfg.Params
	public  *hdkeychain.ExtendedKey
	address btcutil.Address

	isRunning      bool
	promCollectors []prometheus.Collector

	// opgeth
	opgethClient *ethclient.Client // XXX evaluate if ok
	opgethWG     sync.WaitGroup

	// wallet
	gozer gozer.Gozer
	mz    zuul.Zuul
	vc    *vinzclortho.VinzClortho

	// mining
	retryThreshold uint32
	lastKeystone   *hemi.L2Keystone
	l2Keystones    map[chainhash.Hash]L2KeystoneProcessingContainer
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}

	s := &Server{
		cfg:            cfg,
		l2Keystones:    make(map[chainhash.Hash]L2KeystoneProcessingContainer, l2KeystonesLen),
		retryThreshold: uint32(cfg.RetryMineThreshold) * hemi.KeystoneHeaderPeriod,
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

func (s *Server) processKeystones(ctx context.Context, l2Keystones []hemi.L2Keystone) bool {
	log.Tracef("processKeystones")
	defer log.Tracef("processKeystones exit")

	// Sort L2 keystones by block number. This is ok because opgeth ensures
	// block number order. XXX max please confirm
	slices.SortFunc(l2Keystones, func(a, b hemi.L2Keystone) int {
		return cmp.Compare(a.L2BlockNumber, b.L2BlockNumber)
	})

	var work bool
	for _, kh := range l2Keystones {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		// s.lastKeystone does not race because it only touched here.
		var lastL2BlockNumber uint32
		if s.lastKeystone != nil {
			lastL2BlockNumber = s.lastKeystone.L2BlockNumber
		}

		// if s.lastKeystone does not exist we add it; if the incoming
		// keystone is more recent we replace lastKeystone.
		if s.lastKeystone == nil ||
			kh.L2BlockNumber > s.lastKeystone.L2BlockNumber {
			s.lastKeystone = &kh
			s.addL2Keystone(kh)
			work = true
			continue
		}

		// Potentially mine keystones that
		if lastL2BlockNumber-kh.L2BlockNumber <= s.retryThreshold {
			s.addL2Keystone(kh)
			work = true
			continue
		}
	}

	return work
}

func (s *Server) addL2Keystone(ks hemi.L2Keystone) {
	kspc := L2KeystoneProcessingContainer{
		l2Keystone:         ks,
		requiresProcessing: true,
	}
	s.mtx.Lock()
	defer s.mtx.Unlock()

	ksHash := hemi.L2KeystoneAbbreviate(ks).Hash()

	// keystone already exists, no-op
	if _, ok := s.l2Keystones[*ksHash]; ok {
		return
	}

	if len(s.l2Keystones) < l2KeystonesLen {
		// Insert key stone
		s.l2Keystones[*ksHash] = kspc
		return
	}

	// Find oldest keystone.
	var (
		l2Min  uint32
		keyMin chainhash.Hash
	)
	for k, v := range s.l2Keystones {
		if l2Min == 0 || v.l2Keystone.L2BlockNumber < l2Min {
			l2Min = v.l2Keystone.L2BlockNumber
			keyMin = k
		}
	}

	// Do not insert an L2Keystone that is older than all of the ones
	// already added.
	if ks.L2BlockNumber < l2Min {
		return
	}

	// Evict oldest
	delete(s.l2Keystones, keyMin)

	// Insert key stone
	s.l2Keystones[*ksHash] = kspc
}

func (s *Server) l2KeystonesForProcessing() []hemi.L2Keystone {
	copies := make([]hemi.L2Keystone, 0)

	s.mtx.Lock()

	for i, v := range s.l2Keystones {
		// if we're currently processing, or we've already processed
		// the keystone then don't process
		if !v.requiresProcessing {
			continue
		}

		// since we're about to process, mark this as false so others
		// don't process the same
		v.requiresProcessing = false
		s.l2Keystones[i] = v
		copies = append(copies, v.l2Keystone)
	}
	s.mtx.Unlock()

	slices.SortFunc(copies, func(a, b hemi.L2Keystone) int {
		return int(b.L2BlockNumber) - int(a.L2BlockNumber)
	})

	return copies
}

func (s *Server) createKeystoneTx(ctx context.Context, ks *hemi.L2Keystone) (*wire.MsgTx, error) {
	log.Tracef("createKeystoneTx")
	defer log.Tracef("createKeystoneTx exit")

	log.Infof("Mine L2 keystone height %v", ks.L2BlockNumber)

	if s.gozer == nil {
		// XXX happens during test
		return nil, fmt.Errorf("fuck off")
	}
	btcHeight, err := s.gozer.BtcHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("bitcoin height: %w", err)
	}

	payToScript, err := vinzclortho.ScriptFromPubKeyHash(s.address)
	if err != nil {
		return nil, fmt.Errorf("get pay to address script: %w", err)
	}
	if len(payToScript) != 25 {
		return nil, fmt.Errorf("invalid pay to public key script lenght (%d != 25)",
			len(payToScript))
	}
	scriptHash := vinzclortho.ScriptHashFromScript(payToScript)

	// Estimate BTC fees.
	feeEstimates, err := s.gozer.FeeEstimates(ctx)
	if err != nil {
		return nil, fmt.Errorf("fee estimates: %w", err)
	}
	feeAmount, err := gozer.FeeByConfirmations(6, feeEstimates) // XXX make 6 config
	if err != nil {
		return nil, fmt.Errorf("fee by confirmations: %w", err)
	}

	// Retrieve available UTXOs for the miner.
	utxos, err := s.gozer.UtxosByAddress(ctx, s.address, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("utxos by address: %w", err)
	}
	log.Debugf("utxos %d, script hash %v height %d",
		len(utxos), scriptHash, btcHeight)

	// Build transaction.
	popTx, prevOut, err := wallet.PoPTransactionCreate(ks, uint32(btcHeight),
		btcutil.Amount(feeAmount.SatsPerByte), utxos, payToScript)
	if err != nil {
		return nil, fmt.Errorf("create transaction: %w", err)
	}

	// Sign transaction.
	err = wallet.TransactionSign(s.params, s.mz, popTx, prevOut)
	if err != nil {
		return nil, fmt.Errorf("sign transaction: %w", err)
	}

	return popTx, nil
}

func (s *Server) broadcastKeystone(pctx context.Context, popTx *wire.MsgTx) error {
	log.Tracef("mineKeystone")
	defer log.Tracef("mineKeystone exit")

	log.Infof("Broadcast PoP tx %s %x", s.params.Name, popTx)

	ctx, cancel := context.WithTimeout(pctx, 5*time.Second)
	defer cancel()

	txHash, err := s.gozer.BroadcastTx(ctx, popTx)
	if err != nil {
		return fmt.Errorf("broadcast PoP transaction: %w", err)
	}
	log.Infof("Broadcast PoP tx %s %v", s.params.Name, txHash)

	return nil
}

func (s *Server) createAndBroadcastKeystone(ctx context.Context, ks *hemi.L2Keystone) error {
	popTx, err := s.createKeystoneTx(ctx, ks)
	if err != nil {
		return err
	}
	return s.broadcastKeystone(ctx, popTx)
}

func (s *Server) mineKnownKeystones(ctx context.Context) {
	copies := s.l2KeystonesForProcessing()

	for _, e := range copies {
		log.Debugf("mine keystone height %v", e.L2BlockNumber)

		// This is a little hard to read but there is a reason why we
		// recreated the pop tx. We may be waiting on change or funding
		// of the wallet, or a broadcast failed. Thus always recreate
		// the transaction and try to brodcast it.
		err := s.createAndBroadcastKeystone(ctx, &e)
		ksHash := hemi.L2KeystoneAbbreviate(e).Hash()

		s.mtx.Lock()
		if v, ok := s.l2Keystones[*ksHash]; ok {
			// if there is an error, mark keystone as "requires
			// processing" so potentially gets retried, otherwise
			// set this to false to nothing tries to process it
			v.requiresProcessing = err != nil
			s.l2Keystones[*ksHash] = v
		}
		s.mtx.Unlock()
	}
}

func (s *Server) mine(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(l2KeystoneRetryTimeout):
			s.mineKnownKeystones(ctx)
		}
	}
}

// XXX Test ONLY. Subscription should be handled
// in a smarter way.
func (s *Server) handleOpgethSubscription(ctx context.Context) error {
	log.Tracef("subscribeOpgeth")
	defer func() {
		log.Tracef("subscribeOpgeth exit")
		s.opgethWG.Done()
	}()

	headersCh := make(chan string, l2KeystonesLen) // XXX is l2KeystonesLen right
	sub, err := s.opgethClient.Client().Subscribe(ctx, "kss", headersCh)
	if err != nil {
		return err
	}

	for {
		select {
		case err := <-sub.Err():
			return err
		case <-ctx.Done():
			return ctx.Err()

		case n := <-headersCh:
			log.Tracef("kss notification received: %s", n)
			var kresp popapi.L2KeystoneResponse
			err := s.opgethClient.Client().Call(&kresp, "keystone_request",
				l2KeystonesLen)
			if err != nil {
				return err
			}
			if kresp.L2Keystones != nil && len(kresp.L2Keystones) > 0 {
				if s.processKeystones(ctx, kresp.L2Keystones) {
					s.mineKnownKeystones(ctx)
				}
			}
		}
	}
}

func (s *Server) connectOpgeth(pctx context.Context) error {
	log.Tracef("connectOpgeth")
	defer log.Tracef("connectOpgeth exit")

	// Allow the connection to timeout.
	connCtx, connCancel := context.WithTimeout(pctx, 5*time.Second)
	defer connCancel()

	var err error
	s.opgethClient, err = ethclient.DialContext(connCtx, s.cfg.OpgethURL)
	if err != nil {
		return err
	}
	defer s.opgethClient.Close()

	log.Debugf("connected to opgeth: %s", s.cfg.OpgethURL)

	// Create a context to exit function.
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	s.opgethWG.Add(1)
	go func() {
		err := s.handleOpgethSubscription(ctx)
		if err != nil {
			log.Errorf("opgeth connection: %v", err)
		}
		cancel()
	}()

	<-ctx.Done()
	s.opgethClient.Close()

	// Wait for exit
	s.opgethWG.Wait()

	return ctx.Err()
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
			if err := d.Run(ctx, s.Collectors(), nil); !errors.Is(err, context.Canceled) {
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

	var err error
	switch s.cfg.BitcoinSource {
	case bitcoinSourceTBC:
		s.gozer, err = tbcgozer.TBCGozerNew(ctx, s.cfg.BitcoinURL)
		if err != nil {
			return fmt.Errorf("could not setup %v tbc: %w",
				s.cfg.Network, err)
		}
	case bitcoinSourceBlockstream:
		s.gozer, err = blockstream.BlockstreamNew(s.params)
		if err != nil {
			return fmt.Errorf("could not setup %v blockstream: %w",
				s.cfg.Network, err)
		}
	default:
		return fmt.Errorf("invalid bitcoin source: %v", s.cfg.BitcoinSource)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.opgeth(ctx)
	}()

	s.wg.Add(1)
	go s.mine(ctx)

	log.Infof("bitcoin address   : %v", s.address)
	log.Infof("bitcoin public key: %v", s.public)

	<-ctx.Done()
	err = ctx.Err()

	log.Infof("pop miner shutting down")

	s.wg.Wait()
	log.Infof("pop miner has shutdown cleanly")

	return err
}
