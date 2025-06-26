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
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/api/gethapi"
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

	defaultPopAccount           = 1337
	defaultPopChild             = 0
	defaultBitcoinConfirmations = 6
	defaultOpgethURL            = "http://127.0.0.1:9999/v1/ws"

	defaultL2KeystonesCount = 12 // 1 hour

	bitcoinSourceBlockstream      = "blockstream"
	bitcoinSourceTBC              = "tbc"
	defaultOpgethReconnectTimeout = 5 * time.Second
	defaultL2KeystoneMaxAge       = 4 * time.Hour
	defaultL2KeystonePollTimeout  = 13 * time.Second
	defaultL2KeystoneRetryTimeout = 15 * time.Second
)

var log = loggo.GetLogger("popm")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	BitcoinConfirmations    uint
	BitcoinSecret           string
	BitcoinSource           string
	BitcoinURL              string
	LogLevel                string
	Network                 string
	OpgethURL               string
	PprofListenAddress      string
	PrometheusListenAddress string
	PrometheusNamespace     string
	RetryMineThreshold      uint

	// cooked settings, do not export
	opgethReconnectTimeout time.Duration
	l2KeystoneMaxAge       time.Duration
	l2KeystonePollTimeout  time.Duration
}

func NewDefaultConfig() *Config {
	return &Config{
		Network:                "testnet3",
		PrometheusNamespace:    appName,
		OpgethURL:              defaultOpgethURL,
		BitcoinConfirmations:   defaultBitcoinConfirmations,
		BitcoinSource:          bitcoinSourceTBC,
		BitcoinURL:             tbcgozer.DefaultURL,
		opgethReconnectTimeout: defaultOpgethReconnectTimeout,
		l2KeystoneMaxAge:       defaultL2KeystoneMaxAge,
		l2KeystonePollTimeout:  defaultL2KeystonePollTimeout,
	}
}

type keystoneState int

const (
	keystoneStateInvalid   keystoneState = 0
	keystoneStateNew       keystoneState = 1
	keystoneStateBroadcast keystoneState = 2
	keystoneStateError     keystoneState = 3
	keystoneStateMined     keystoneState = 4
)

type keystone struct {
	// comes from opgeth
	keystone *hemi.L2Keystone
	hash     *chainhash.Hash // map key

	// comes from gozer
	abbreviated *gozer.L2KeystoneBlockInfo

	expires *time.Time // Used to age out of cache

	// internal state                  /-----> 4
	state keystoneState // 0 -> 1 -> 2 -> 3 -> 4
	//                               2 <---/
}

func timestamp(d time.Duration) *time.Time {
	t := time.Now().Add(d)
	return &t
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
	opgethClient *ethclient.Client
	opgethWG     sync.WaitGroup

	// wallet
	gozer gozer.Gozer
	mz    zuul.Zuul
	vc    *vinzclortho.VinzClortho

	// mining
	retryThreshold uint32
	keystones      map[chainhash.Hash]*keystone
	workC          chan struct{}
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}

	s := &Server{
		cfg:            cfg,
		retryThreshold: uint32(cfg.RetryMineThreshold) * hemi.KeystoneHeaderPeriod,
		workC:          make(chan struct{}, 2),
	}

	switch strings.ToLower(cfg.Network) {
	case "mainnet":
		s.params = &chaincfg.MainNetParams
	case "testnet", "testnet3":
		s.params = &chaincfg.TestNet3Params
	case "localnet":
		s.params = &chaincfg.RegressionNetParams
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

func (s *Server) createKeystoneTx(ctx context.Context, ks *hemi.L2Keystone) (*wire.MsgTx, error) {
	log.Tracef("createKeystoneTx")
	defer log.Tracef("createKeystoneTx exit")

	log.Infof("Mine L2 keystone height %v", ks.L2BlockNumber)

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
	feeAmount, err := gozer.FeeByConfirmations(s.cfg.BitcoinConfirmations, feeEstimates)
	if err != nil {
		return nil, fmt.Errorf("fee by confirmations: %w", err)
	}

	// Retrieve available UTXOs for the miner.
	utxos, err := s.gozer.UtxosByAddress(ctx, true, s.address, 0, 100)
	if err != nil {
		return nil, fmt.Errorf("utxos by address: %w", err)
	}
	log.Infof("utxos %d, script hash %v height %d",
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

	log.Infof("Broadcasting PoP tx %s with hash %v", s.params.Name, popTx.TxHash())

	ctx, cancel := context.WithTimeout(pctx, 5*time.Second)
	defer cancel()

	txHash, err := s.gozer.BroadcastTx(ctx, popTx)
	if err != nil {
		return fmt.Errorf("broadcast PoP transaction: %w", err)
	}
	log.Infof("Broadcast PoP tx %s with TxID %v", s.params.Name, txHash)

	return nil
}

func (s *Server) createAndBroadcastKeystone(ctx context.Context, ks *hemi.L2Keystone) error {
	popTx, err := s.createKeystoneTx(ctx, ks)
	if err != nil {
		return err
	}
	return s.broadcastKeystone(ctx, popTx)
}

func (s *Server) latestKeystones(ctx context.Context, count int) (*gethapi.L2KeystoneLatestResponse, error) {
	log.Tracef("latestKeystones")
	defer log.Tracef("latestKeystones exit")

	var kr gethapi.L2KeystoneLatestResponse
	err := s.opgethClient.Client().CallContext(ctx, &kr, "kss_getLatestKeystones", count)
	if err != nil {
		return nil, fmt.Errorf("opgeth rpc: %w", err)
	}
	if len(kr.L2Keystones) <= 0 {
		return nil, fmt.Errorf("no keystones")
	}
	return &kr, nil
}

// reconcileKeystones generates a keystones map
func (s *Server) reconcileKeystones(ctx context.Context) (map[chainhash.Hash]*keystone, error) {
	log.Tracef("reconcileKeystones")
	defer log.Tracef("reconciletKeystones exit")

	kr, err := s.latestKeystones(ctx, defaultL2KeystonesCount)
	if err != nil {
		return nil, fmt.Errorf("reconcile: %w", err)
	}

	// Cross check with gozer to see what needs to be mined
	aksHashes := make([]chainhash.Hash, 0, len(kr.L2Keystones))
	keystones := make(map[chainhash.Hash]*keystone, defaultL2KeystonesCount)
	for k := range kr.L2Keystones {
		h := hemi.L2KeystoneAbbreviate(kr.L2Keystones[k]).Hash()

		// fill out hashes array for gozer
		aksHashes = append(aksHashes, *h)

		// while looping fill out keystones state cache
		keystones[*h] = &keystone{
			keystone: &kr.L2Keystones[k],
			hash:     h,
		}
	}

	gks := s.gozer.BlocksByL2AbrevHashes(ctx, aksHashes)
	if gks.Error != nil {
		return nil, fmt.Errorf("blocks by abrev hashes: %w", gks.Error)
	}
	if len(gks.L2KeystoneBlocks) != len(aksHashes) {
		// Shouldn't happen
		panic(fmt.Sprintf("len diagnostic %v != %v", len(gks.L2KeystoneBlocks), len(aksHashes)))
	}
	// log.Debugf("BlockKeystoneByL2KeystoneAbrevHash: %v", spew.Sdump(gks))
	for k := range gks.L2KeystoneBlocks {
		// Fixup keystone cache based on gozer response, note that gks
		// or is identical to aks order thus we can use the hash array
		// for identification in the keystone cache map.
		ks, ok := keystones[aksHashes[k]]
		if !ok {
			// Not found in keystones cache map so Error must be !nil
			if gks.L2KeystoneBlocks[k].Error == nil {
				panic("hash not found " + aksHashes[k].String())
			}
			ks.state = keystoneStateNew
		} else {
			// found, set state based on Error
			if gks.L2KeystoneBlocks[k].Error == nil {
				ks.state = keystoneStateMined
			} else {
				ks.state = keystoneStateNew
			}
		}
		ks.expires = timestamp(s.cfg.l2KeystoneMaxAge)

		// Always add the entry to cache and rely on Error being !nil
		// to retry later.
		ks.abbreviated = &gks.L2KeystoneBlocks[k]
	}

	return keystones, nil
}

// hydrateKeystones should be called once at start of day. It will build the
// keystone state cache. It returns an error if the cache is already hydrated.
// This is to prevent invalid successive calls to a function that may only be
// called once per connection. The caller should assert that the cache is empty
// prior to calling.
func (s *Server) hydrateKeystones(ctx context.Context) error {
	log.Tracef("hydrateKeystones")
	defer log.Tracef("hydrateKeystones exit")

	keystones, err := s.reconcileKeystones(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}

	// XXX this has a logic race with the test package
	s.mtx.Lock()
	if s.keystones != nil {
		s.mtx.Unlock()
		return errors.New("already hydrated")
	}
	s.keystones = keystones
	s.mtx.Unlock()

	return nil
}

func (s *Server) handleOpgethSubscription(ctx context.Context) error {
	log.Tracef("handleOpgethSubscription")
	defer log.Tracef("handleOpgethSubscription exit")

	headersCh := make(chan string, 10) // PNOOMA 10 notifications
	sub, err := s.opgethClient.Client().Subscribe(ctx, "kss", headersCh, "newKeystones")
	if err != nil {
		return fmt.Errorf("keystone subscription: %w", err)
	}

	// Note that notifications can be unreliable so additionally we rely on
	// a timeout to poll keystones.
	t := time.NewTimer(s.cfg.l2KeystonePollTimeout)
	for {
		t.Reset(s.cfg.l2KeystonePollTimeout)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-sub.Err():
			return err
		case <-headersCh:
			log.Tracef("keystone notification")
		case <-t.C:
			log.Tracef("keystone poll")
		}

		nkss, err := s.reconcileKeystones(ctx)
		if err != nil {
			// This only happens on non-recoverable errors so it is
			// ok to exit.
			return fmt.Errorf("keystone notification: %w", err)
		}

		// XXX this has a logic race with the test package
		// See if there are state changes
		var work bool
		s.mtx.Lock()
		for _, nks := range nkss {
			cks, ok := s.keystones[*nks.hash]
			if ok {
				switch nks.state {
				case keystoneStateNew:
					// Already in cache
					log.Tracef("skip %v: %v %v", nks.hash,
						nks.state, nks.keystone.L2BlockNumber)
					continue
				case keystoneStateMined:
					// Move to mined state
					log.Tracef("mined %v: %v %v", nks.hash,
						nks.state, nks.keystone.L2BlockNumber)
					cks.state = keystoneStateMined
				}
			} else {
				// Insert new keystone in cache
				log.Tracef("insert %v: %v %v", nks.hash, nks.state,
					nks.keystone.L2BlockNumber)
				s.keystones[*nks.hash] = nks
			}
			work = true
		}
		s.mtx.Unlock()

		// Signal miner to get to work
		if work {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case s.workC <- struct{}{}:
			default:
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

	// Rehydrate keystones state
	err = s.hydrateKeystones(ctx)
	if err != nil {
		return fmt.Errorf("hydrate: %w", err)
	}

	s.opgethWG.Add(1)
	go func() {
		defer s.opgethWG.Done()

		err := s.handleOpgethSubscription(ctx)
		if err != nil {
			log.Errorf("subscription: %v", err)
		}
		cancel()

		// Purge keystones on the way out.
		s.mtx.Lock()
		s.keystones = nil
		s.mtx.Unlock()
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
			// Do nothing, this is too loud so make it Tracef.
			log.Tracef("connectOpgeth: %v", err)
		} else {
			log.Infof("Connected to opgeth: %s", s.cfg.OpgethURL)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.opgethReconnectTimeout):
		}

		log.Debugf("reconnecting to: %v", s.cfg.OpgethURL)
	}
}

func (s *Server) mine(ctx context.Context) error {
	log.Tracef("mine")
	defer log.Tracef("mine exit")

	s.mtx.Lock()
	defer s.mtx.Unlock()
	// sks := sortKeystones(s.keystones)

	// log.Infof("mine: %v", spew.Sdump(sks))
	// This is crappy to do all in the mutex but let's make sure it works first.
	for _, ks := range s.keystones {
		switch ks.state {
		case keystoneStateNew, keystoneStateError:
			err := s.createAndBroadcastKeystone(ctx, ks.keystone)
			if err != nil {
				log.Errorf("new keystone: %v", err)
				ks.state = keystoneStateError
			} else {
				ks.state = keystoneStateBroadcast
			}
		case keystoneStateBroadcast:
			// Do nothing, wait for mined.
		case keystoneStateMined:
			// Remove if older than max age
			if time.Now().After(*ks.expires) {
				delete(s.keystones, *ks.hash)
			}
		}
	}

	return nil
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
		s.gozer, err = tbcgozer.Run(ctx, s.cfg.BitcoinURL)
		if err != nil {
			return fmt.Errorf("could not setup %v tbc: %w",
				s.cfg.Network, err)
		}
	case bitcoinSourceBlockstream:
		s.gozer, err = blockstream.Run(s.params)
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

	// Mining
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTimer(defaultL2KeystoneRetryTimeout)
		for {
			t.Reset(defaultL2KeystoneRetryTimeout)
			select {
			case <-ctx.Done():
				return
			case <-s.workC:
			case <-t.C:
			}

			err := s.mine(ctx)
			if err != nil {
				log.Errorf("mine: %v", err)
			}
		}
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
