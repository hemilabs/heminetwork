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
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	btcchaincfg "github.com/btcsuite/btcd/chaincfg"
	"github.com/davecgh/go-spew/spew"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin"
	"github.com/hemilabs/heminetwork/hemi"
)

// XXX we should debate if we can make pop miner fully transient. It feels like
// it should be.

const (
	logLevel = "INFO"

	promSubsystem = "popm_service" // Prometheus

	l2KeystonesMaxSize = 10
)

var log = loggo.GetLogger("popm")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	// TBCWSURL specifies the URL of the TBC private websocket endpoint
	TBCWSURL string

	// BTCChainName specifies the name of the Bitcoin chain that
	// this PoP miner is operating on.
	BTCChainName string // XXX are we brave enough to rename this BTCNetwork?

	// BTCPrivateKey provides a BTC private key as a string of
	// hexadecimal digits.
	BTCPrivateKey string

	TBCRequestTimeout time.Duration

	LogLevel string

	PrometheusListenAddress string

	PprofListenAddress string

	RetryMineThreshold uint

	StaticFee uint
}

const DefaultTBCRequestTimeout = 15 * time.Second

func NewDefaultConfig() *Config {
	return &Config{
		BFGWSURL:          "http://localhost:8383/v1/ws/public",
		BFGRequestTimeout: DefaultBFGRequestTimeout,
		BTCChainName:      "mainnet",
		TBCWSURL:          "http://localhost:8082/v1/ws",
		TBCRequestTimeout: DefaultTBCRequestTimeout,
		BTCChainName:      "testnet3",
	}
}

type Miner struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	holdoffTimeout time.Duration
	requestTimeout time.Duration

	cfg *Config

	btcChainParams *btcchaincfg.Params
	btcPrivateKey  *dcrsecp256k1.PrivateKey
	btcPublicKey   *dcrsecp256k1.PublicKey
	btcAddress     *btcutil.AddressPubKeyHash

	// Prometheus
	isRunning bool

	tbcCmdCh     chan tbcCmd // commands to send to tbc
	tbcWg        sync.WaitGroup
	tbcConnected atomic.Bool

	l2Keystones []*hemi.L2Keystone

	eventHandlersMtx sync.RWMutex
	eventHandlers    []EventHandler
}

// Wrap for calling tbc commands
type tbcCmd struct {
	msg any
	ch  chan any
}

func NewMiner(cfg *Config) (*Miner, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	if cfg.TBCRequestTimeout <= 0 {
		cfg.TBCRequestTimeout = DefaultTBCRequestTimeout
	}

	m := &Miner{
		cfg:            cfg,
		tbcCmdCh:       make(chan tbcCmd, 10),
		holdoffTimeout: 5 * time.Second,
		requestTimeout: cfg.TBCRequestTimeout,
		l2Keystones:    make([]*hemi.L2Keystone, l2KeystonesMaxSize),
	}

	switch strings.ToLower(cfg.BTCChainName) {
	case "mainnet":
		m.btcChainParams = &btcchaincfg.MainNetParams
	case "testnet", "testnet3":
		m.btcChainParams = &btcchaincfg.TestNet3Params
	default:
		return nil, fmt.Errorf("unknown BTC chain name %q", cfg.BTCChainName)
	}

	if cfg.BTCPrivateKey == "" {
		return nil, errors.New("no BTC private key provided")
	}
	var err error
	m.btcPrivateKey, m.btcPublicKey, m.btcAddress, err = bitcoin.KeysAndAddressFromHexString(cfg.BTCPrivateKey, m.btcChainParams)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Miner) Connected() bool {
	return m.tbcConnected.Load()
}

func (m *Miner) running() bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.isRunning
}

func (m *Miner) testAndSetRunning(b bool) bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	old := m.isRunning
	m.isRunning = b
	return old != m.isRunning
}

func (m *Miner) promRunning() float64 {
	r := m.running()
	if r {
		return 1
	}
	return 0
}

func (m *Miner) callTBC(pctx context.Context, timeout time.Duration, msg any) (any, error) {
	log.Tracef("callTBC %T", msg)
	defer log.Tracef("callTBC exit %T", msg)

	bc := tbcCmd{
		msg: msg,
		ch:  make(chan any),
	}

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	// attempt to send
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case m.tbcCmdCh <- bc:
	default:
		return nil, errors.New("tbc command queue full")
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

func (m *Miner) handleTBCWebsocketRead(ctx context.Context, conn *protocol.Conn) error {
	defer m.tbcWg.Done()

	log.Tracef("handleTBCWebsocketRead")
	defer log.Tracef("handleTBCWebsocketRead exit")
	for {
		_, _, _, err := tbcapi.ReadConn(ctx, conn)
		if err != nil {

			// See if we were terminated
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(m.holdoffTimeout):
			}

			log.Infof("Connection with TBC server was lost, reconnecting...")
			continue
		}
	}
}

func (m *Miner) handleTBCCallCompletion(pctx context.Context, conn *protocol.Conn, bc tbcCmd) {
	log.Tracef("handleTBCCallCompletion")
	defer log.Tracef("handleTBCCallCompletion exit")

	ctx, cancel := context.WithTimeout(pctx, m.requestTimeout)
	defer cancel()

	log.Tracef("handleTBCCallCompletion: %v", spew.Sdump(bc.msg))

	_, _, payload, err := tbcapi.Call(ctx, conn, bc.msg)
	if err != nil {
		log.Errorf("handleTBCCallCompletion %T: %v", bc.msg, err)
		select {
		case bc.ch <- err:
		default:
		}
	}
	select {
	case bc.ch <- payload:
		log.Tracef("handleTBCCallCompletion returned: %v", spew.Sdump(payload))
	default:
	}
}

func (m *Miner) handleTBCWebsocketCallUnauth(ctx context.Context, conn *protocol.Conn) {
	defer m.tbcWg.Done()

	log.Tracef("handleTBCWebsocketCallUnauth")
	defer log.Tracef("handleTBCWebsocketCallUnauth exit")
	for {
		select {
		case <-ctx.Done():
			return
		case bc := <-m.tbcCmdCh:
			go m.handleTBCCallCompletion(ctx, conn, bc)
		}
	}
}

func (m *Miner) connectTBC(pctx context.Context) error {
	log.Tracef("connectTBC")
	defer log.Tracef("connectTBC exit")

	conn, err := protocol.NewConn(m.cfg.TBCWSURL, &protocol.ConnOptions{
		ReadLimit: 6 * (1 << 20), // 6 MiB
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

	m.tbcWg.Add(1)
	go m.handleTBCWebsocketCallUnauth(ctx, conn)

	m.tbcWg.Add(1)
	m.handleTBCWebsocketRead(ctx, conn)

	log.Debugf("Connected to TBC: %s", m.cfg.TBCWSURL)
	m.tbcConnected.Store(true)

	// Wait for exit
	m.tbcWg.Wait()
	m.tbcConnected.Store(false)

	return nil
}

func (m *Miner) tbc(ctx context.Context) {
	defer m.wg.Done()

	log.Tracef("tbc")
	defer log.Tracef("tbc exit")

	for {
		if err := m.connectTBC(ctx); err != nil {
			// Do nothing
			log.Tracef("connectTBC: %v", err)
		} else {
			log.Infof("Connected to TBC: %s", m.cfg.TBCWSURL)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.After(m.holdoffTimeout):
		}

		log.Debugf("Reconnecting to: %v", m.cfg.TBCWSURL)
	}
}

func (m *Miner) Run(pctx context.Context) error {
	if !m.testAndSetRunning(true) {
		return errors.New("popmd already running")
	}
	defer m.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// Prometheus
	if m.cfg.PrometheusListenAddress != "" {
		if err := m.handlePrometheus(ctx); err != nil {
			return fmt.Errorf("handlePrometheus: %w", err)
		}
	}

	/* // pprof
	if m.cfg.PprofListenAddress != "" {
		p, err := pprof.NewServer(&pprof.Config{
			ListenAddress: m.cfg.PprofListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create pprof server: %w", err)
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			if err := p.Run(ctx); !errors.Is(err, context.Canceled) {
				log.Errorf("pprof server terminated with error: %v", err)
				return
			}
			log.Infof("pprof server clean shutdown")
		}()
	} */

	log.Infof("Starting PoP miner with BTC address %v (public key %x)",
		m.btcAddress.EncodeAddress(), m.btcPublicKey.SerializeCompressed())

	m.wg.Add(1)
	go m.tbc(ctx) // Attempt to talk to TBC

	<-ctx.Done()
	err := ctx.Err()

	log.Infof("PoP miner shutting down...")

	m.wg.Wait()
	log.Infof("PoP miner has shutdown cleanly")

	return err
}
