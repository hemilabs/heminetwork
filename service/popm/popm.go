// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/v2/api/gethapi"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer/blockstream"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer/tbcgozer"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul/memory"
	"github.com/hemilabs/heminetwork/v2/ethereum"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/service/deucalion"
	"github.com/hemilabs/heminetwork/v2/service/pprof"
)

const (
	logLevel = "INFO"
	appName  = "popm"

	defaultBitcoinConfirmations = 6
	defaultOpgethURL            = "http://127.0.0.1:9999/v1/ws"

	defaultL2KeystonesCount = 12 // 1 hour

	bitcoinSourceBlockstream      = "blockstream"
	bitcoinSourceTBC              = "tbc"
	defaultOpgethReconnectTimeout = 5 * time.Second
	defaultL2KeystoneMaxAge       = 4 * time.Hour
	defaultL2KeystonePollTimeout  = 13 * time.Second
	defaultL2KeystoneRetryTimeout = 15 * time.Second

	minRelayFee = 1                // sats/byte
	maxBlockAge = 30 * time.Second // XXX make this configurable?
)

type health struct {
	BitcoinBestHeight  uint64    `json:"bitcoin_best_height"`
	BitcoinBestHash    string    `json:"bitcoin_best_hash"`
	BitcoinBestTime    time.Time `json:"bitcoin_best_time"`
	EthereumBestHeight uint64    `json:"ethereum_best_height"`
	EthereumBestHash   string    `json:"ethereum_best_hash"`
	EthereumBestTime   time.Time `json:"ethereum_best_time"`
	GozerConnected     bool      `json:"gozer_connected"`
	GethConnected      bool      `json:"geth_connected"`
}

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
	StaticFee               float64

	// cooked settings, do not export
	opgethReconnectTimeout time.Duration
	l2KeystoneMaxAge       time.Duration
	l2KeystonePollTimeout  time.Duration
}

func NewDefaultConfig() *Config {
	return &Config{
		Network:                "mainnet",
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
	params     *chaincfg.Params
	btcAddress btcutil.Address
	ethAddress common.Address

	// Prometheus
	isRunning       bool
	promPolling     bool
	promCollectors  []prometheus.Collector
	promHealth      health
	promPollVerbose bool // set to true to print stats during poll

	// opgeth
	opgethClient *ethclient.Client
	opgethWG     sync.WaitGroup

	// wallet
	gozer gozer.Gozer
	mz    zuul.Zuul
	// vc    *vinzclortho.VinzClortho

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

	if cfg.StaticFee != 0 && cfg.StaticFee < minRelayFee {
		return nil, fmt.Errorf("static fee set to %v, minimum is %v",
			cfg.StaticFee, minRelayFee)
	}

	switch strings.ToLower(cfg.Network) {
	case "mainnet":
		s.params = &chaincfg.MainNetParams
	case "testnet3":
		s.params = &chaincfg.TestNet3Params
	case "testnet4":
		s.params = &chaincfg.TestNet4Params
	case "localnet", "testnet":
		s.params = &chaincfg.RegressionNetParams
	default:
		return nil, fmt.Errorf("unknown bitcoin network %v", cfg.Network)
	}

	if cfg.BitcoinSecret == "" {
		return nil, errors.New("no bitcoin secret provided")
	}
	pk, err := hex.DecodeString(cfg.BitcoinSecret)
	if err != nil {
		return nil, err
	}
	privKey := dcrsecpk256k1.PrivKeyFromBytes(pk)
	pubBytes := privKey.PubKey().SerializeCompressed()

	btcAddress, err := btcutil.NewAddressPubKey(pubBytes, s.params)
	if err != nil {
		return nil, fmt.Errorf("new address: %w", err)
	}
	s.btcAddress = btcAddress.AddressPubKeyHash()
	s.ethAddress = ethereum.AddressFromPrivateKey(privKey)

	s.mz, err = memory.New(s.params)
	if err != nil {
		return nil, err
	}
	err = s.mz.PutKey(&zuul.NamedKey{
		Name:       "private",
		PrivateKey: privKey,
	})
	if err != nil {
		return nil, err
	}

	switch s.cfg.BitcoinSource {
	case bitcoinSourceTBC:
		if s.cfg.BitcoinURL == "" {
			return nil, fmt.Errorf("invalid bitcoin url")
		}
		s.gozer = tbcgozer.New(s.cfg.BitcoinURL)
	case bitcoinSourceBlockstream:
		s.gozer, err = blockstream.New(s.params)
		if err != nil {
			return nil, fmt.Errorf("could not setup %v blockstream: %w",
				s.cfg.Network, err)
		}
	default:
		return nil, fmt.Errorf("invalid bitcoin source: %v", s.cfg.BitcoinSource)
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

	btcHeight, _, _, err := s.gozer.BestHeightHashTime(ctx)
	if err != nil {
		return nil, fmt.Errorf("bitcoin height: %w", err)
	}

	payToScript, err := vinzclortho.ScriptFromPubKeyHash(s.btcAddress)
	if err != nil {
		return nil, fmt.Errorf("get pay to address script: %w", err)
	}
	if len(payToScript) != 25 {
		return nil, fmt.Errorf("invalid pay to public key script length (%d != 25)",
			len(payToScript))
	}
	scriptHash := vinzclortho.ScriptHashFromScript(payToScript)

	feeAmount, err := s.estimateFee(ctx)
	if err != nil {
		return nil, err
	}

	// Retrieve available UTXOs for the miner.
	utxos, err := s.gozer.UtxosByAddress(ctx, true, s.btcAddress, 0, 100)
	if err != nil {
		return nil, fmt.Errorf("utxos by address: %w", err)
	}
	log.Infof("utxos %d, script hash %v height %d",
		len(utxos), scriptHash, btcHeight)

	// Build transaction.
	popTx, prevOut, err := wallet.PoPTransactionCreate(ks, uint32(btcHeight),
		feeAmount.SatsPerByte, utxos, payToScript)
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
	err := s.opgethClient.Client().CallContext(ctx, &kr,
		"kss_getLatestKeystones", count)
	if err != nil {
		return nil, fmt.Errorf("opgeth rpc: %w", err)
	}
	if len(kr.L2Keystones) <= 0 {
		return nil, fmt.Errorf("no keystones")
	}
	return &kr, nil
}

func (s *Server) estimateFee(ctx context.Context) (*tbcapi.FeeEstimate, error) {
	log.Tracef("estimateFee")
	defer log.Tracef("estimateFee exit")

	if s.cfg.StaticFee != 0 {
		return &tbcapi.FeeEstimate{
			Blocks:      s.cfg.BitcoinConfirmations,
			SatsPerByte: s.cfg.StaticFee,
		}, nil
	}
	// Estimate BTC fees.
	feeEstimates, err := s.gozer.FeeEstimates(ctx)
	if err != nil {
		return nil, fmt.Errorf("fee estimates: %w", err)
	}
	feeAmount, err := gozer.FeeByConfirmations(s.cfg.BitcoinConfirmations, feeEstimates)
	if err != nil {
		return nil, fmt.Errorf("fee by confirmations: %w", err)
	}

	return feeAmount, nil
}

// reconcileKeystones generates a keystones map
func (s *Server) reconcileKeystones(ctx context.Context) (map[chainhash.Hash]*keystone, error) {
	log.Tracef("reconcileKeystones")
	defer log.Tracef("reconcileKeystones exit")

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

func (s *Server) updateKeystoneStates(ctx context.Context) (bool, error) {
	nkss, err := s.reconcileKeystones(ctx)
	if err != nil {
		return false, err
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

	return work, nil
}

func (s *Server) handleOpgethSubscription(ctx context.Context) error {
	log.Tracef("handleOpgethSubscription")
	defer log.Tracef("handleOpgethSubscription exit")

	headersCh := make(chan string, 10) // PNOOMA 10 notifications
	sub, err := s.opgethClient.Client().Subscribe(ctx, "kss", headersCh,
		"newKeystones")
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

		work, err := s.updateKeystoneStates(ctx)
		if err != nil {
			// This only happens on non-recoverable errors so it is
			// ok to exit.
			return fmt.Errorf("keystone notification: %w", err)
		}

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

	s.mtx.Lock()
	s.promHealth.GethConnected = true
	s.mtx.Unlock()
	defer func() {
		s.mtx.Lock()
		s.promHealth.GethConnected = false
		s.mtx.Unlock()
	}()

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

	const (
		maxBaseDelay = int64(15 * time.Second)
		minInc       = int64(1 * time.Second)
	)
	baseDelay := int64(s.cfg.opgethReconnectTimeout)
	for {
		log.Tracef("connecting to: %v", s.cfg.OpgethURL)
		if err := s.connectOpgeth(ctx); err != nil {
			// Do nothing, this is too loud so make it Tracef.
			log.Tracef("connectOpgeth: %v", err)
		} else {
			log.Infof("Connected to opgeth: %s", s.cfg.OpgethURL)
			// Reset attempt on success
			baseDelay = int64(s.cfg.opgethReconnectTimeout)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		default:
		}

		delay := baseDelay + rand.Int64N(baseDelay/2)
		log.Debugf("reconnecting to: %v in %v", s.cfg.OpgethURL, time.Duration(delay))

		select {
		case <-ctx.Done():
			return
		case <-time.Tick(time.Duration(delay)):
		}
		baseDelay += minInc + rand.Int64N(2*minInc)
		baseDelay = min(baseDelay, maxBaseDelay)
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

func (s *Server) promBitcoinTime(m *prometheus.GaugeVec) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	m.Reset()
	m.With(prometheus.Labels{
		"hash":      s.promHealth.BitcoinBestHash,
		"timestamp": strconv.Itoa(int(s.promHealth.BitcoinBestTime.Unix())),
	}).Set(deucalion.Uint64ToFloat(s.promHealth.BitcoinBestHeight))
}

func (s *Server) promEthereumTime(m *prometheus.GaugeVec) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	m.Reset()
	m.With(prometheus.Labels{
		"hash":      s.promHealth.EthereumBestHash,
		"timestamp": strconv.Itoa(int(s.promHealth.EthereumBestTime.Unix())),
	}).Set(deucalion.Uint64ToFloat(s.promHealth.EthereumBestHeight))
}

func (s *Server) gethBestHeightHash(ctx context.Context) (uint64, *chainhash.Hash, time.Time, error) {
	log.Tracef("gethBestHeightHash")
	defer log.Tracef("gethBestHeightHash exit")

	var t time.Time

	height := big.NewInt(int64(rpc.LatestBlockNumber))
	header, err := s.opgethClient.HeaderByNumber(ctx, height)
	if err != nil {
		return 0, nil, t, fmt.Errorf("error calling opgeth: %w", err)
	}
	commonHash := header.Hash()
	ch, err := chainhash.NewHash(commonHash[:])
	if err != nil {
		return 0, nil, t, err
	}
	h := header.Number.Uint64()
	t = time.Unix(int64(header.Time), 0)

	return h, ch, t, nil
}

func (s *Server) promGethConnected() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if s.promHealth.GethConnected {
		return 1
	}
	return 0
}

func (s *Server) promGozerConnected() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if s.promHealth.GozerConnected {
		return 1
	}
	return 0
}

func (s *Server) promPoll(pctx context.Context) error {
	promPollFrequency := 5 * time.Second
	ticker := time.NewTicker(promPollFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-pctx.Done():
			return pctx.Err()
		case <-ticker.C:
		}

		s.mtx.Lock()
		gozer := s.gozer
		if gozer == nil {
			// Not ready
			s.promHealth = health{}
			s.mtx.Unlock()
			continue
		}
		if s.promPolling {
			s.mtx.Unlock()
			continue
		}
		s.promPolling = true
		s.mtx.Unlock()

		ctx, cancel := context.WithTimeout(pctx, promPollFrequency-time.Second)

		var h health
		if height, hash, t, err := gozer.BestHeightHashTime(ctx); err == nil {
			h.BitcoinBestHeight = height
			h.BitcoinBestHash = hash.String()
			h.BitcoinBestTime = t
			h.GozerConnected = true
		} else {
			log.Debugf("btc height hash: %v", err)
			h.BitcoinBestHeight = 0
			h.BitcoinBestHash = ""
			h.BitcoinBestTime = time.Time{}
			h.GozerConnected = false
		}

		if height, hash, t, err := s.gethBestHeightHash(ctx); err == nil {
			h.EthereumBestHeight = height
			h.EthereumBestHash = hash.String()
			h.EthereumBestTime = t
			h.GethConnected = true
		} else {
			log.Debugf("geth height hash: %v", err)
			h.EthereumBestHeight = 0
			h.EthereumBestHash = ""
			h.EthereumBestTime = time.Time{}
			h.GethConnected = false
		}

		cancel()

		s.mtx.Lock()
		s.promHealth = h
		s.promPolling = false
		s.mtx.Unlock()

		if s.promPollVerbose {
			log.Infof("gozer connected: %v geth connected %v",
				h.GozerConnected, h.GethConnected)
		}
		ticker.Reset(promPollFrequency)
	}
}

func (s *Server) isHealthy(_ context.Context) bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if age := time.Since(s.promHealth.EthereumBestTime); age > maxBlockAge ||
		!s.promHealth.GozerConnected || !s.promHealth.GethConnected {
		return false
	}
	return true
}

func (s *Server) health(ctx context.Context) (bool, any, error) {
	log.Tracef("health")
	defer log.Tracef("health exit")

	s.mtx.RLock()
	h := s.promHealth
	s.mtx.RUnlock()

	return s.isHealthy(ctx), h, nil
}

// Collectors returns the Prometheus collectors available for the server.
func (s *Server) Collectors() []prometheus.Collector {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.promCollectors == nil {
		// Naming: https://prometheus.io/docs/practices/naming/
		s.promCollectors = []prometheus.Collector{
			newValueVecFunc(prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "bitcoin_block_height",
				Help:      "Best bitcoin block canonical height and hash",
			}, []string{"hash", "timestamp"}), s.promBitcoinTime),
			newValueVecFunc(prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "ethereum_block_height",
				Help:      "Best ethereum block canonical height and hash",
			}, []string{"hash", "timestamp"}), s.promEthereumTime),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "geth_connected",
				Help:      "Whether the pop miner is connected to geth",
			}, s.promGethConnected),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "gozer_connected",
				Help:      "Whether the pop miner is connected to gozer",
			}, s.promGozerConnected),
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

	err := s.gozer.Run(ctx, func() {
		utxos, err := s.gozer.UtxosByAddress(ctx, true, s.btcAddress, 0, 100)
		if err == nil {
			log.Infof("confirmed bitcoin balance %v: %v",
				s.btcAddress, gozer.BalanceFromUtxos(utxos))
		}
	})
	if err != nil {
		return fmt.Errorf("gozer run: %w", err)
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

	log.Infof("bitcoin address : %v", s.btcAddress)
	log.Infof("ethereum address: %v", s.ethAddress)

	<-ctx.Done()
	err = ctx.Err()

	log.Infof("pop miner shutting down")

	s.wg.Wait()
	log.Infof("pop miner has shutdown cleanly")

	return err
}
