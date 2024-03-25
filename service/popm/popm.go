// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	btcchaincfg "github.com/btcsuite/btcd/chaincfg"
	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	btctxscript "github.com/btcsuite/btcd/txscript"
	btcwire "github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/auth"
	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/bitcoin"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/hemi/pop"
)

// XXX we should debate if we can make pop miner fully transient. It feels like
// it should be.

const (
	logLevel = "INFO"

	promSubsystem = "popm_service" // Prometheus

	l2KeystonesMaxSize = 10
)

var (
	log = loggo.GetLogger("popm")

	l2KeystoneRetryTimeout = 15 * time.Second
)

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type Config struct {
	// BFGWSURL specifies the URL of the BFG private websocket endpoint
	BFGWSURL string

	// BTCChainName specifies the name of the Bitcoin chain that
	// this PoP miner is operating on.
	BTCChainName string // XXX are we brave enough to rename this BTCNetwork?

	// BTCPrivateKey provides a BTC private key as a string of
	// hexadecimal digits.
	BTCPrivateKey string

	LogLevel string

	PrometheusListenAddress string
}

func NewDefaultConfig() *Config {
	return &Config{
		BFGWSURL:     "http://localhost:8383/v1/ws/public",
		BTCChainName: "testnet3",
	}
}

type bfgCmd struct {
	msg any
	ch  chan any
}

type L2KeystoneProcessingContainer struct {
	l2Keystone         hemi.L2Keystone
	requiresProcessing bool
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

	lastKeystone *hemi.L2Keystone

	// Prometheus
	isRunning bool

	bfgWg    sync.WaitGroup
	bfgCmdCh chan bfgCmd // commands to send to bfg

	mineNowCh chan struct{}

	l2Keystones map[string]L2KeystoneProcessingContainer
}

func NewMiner(cfg *Config) (*Miner, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}

	m := &Miner{
		cfg:            cfg,
		bfgCmdCh:       make(chan bfgCmd, 10),
		holdoffTimeout: 5 * time.Second,
		requestTimeout: 5 * time.Second,
		mineNowCh:      make(chan struct{}, 1),
		l2Keystones:    make(map[string]L2KeystoneProcessingContainer, l2KeystonesMaxSize),
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

func (m *Miner) bitcoinBalance(ctx context.Context, scriptHash []byte) (uint64, int64, error) {
	br := &bfgapi.BitcoinBalanceRequest{
		ScriptHash: scriptHash,
	}

	res, err := m.callBFG(ctx, m.requestTimeout, br)
	if err != nil {
		return 0, 0, err
	}

	bResp, ok := res.(*bfgapi.BitcoinBalanceResponse)
	if !ok {
		return 0, 0, fmt.Errorf("not a BitcoinBalanceResponse %T", res)
	}

	if bResp.Error != nil {
		return 0, 0, bResp.Error
	}

	return bResp.Confirmed, bResp.Unconfirmed, nil
}

func (m *Miner) bitcoinBroadcast(ctx context.Context, tx []byte) ([]byte, error) {
	bbr := &bfgapi.BitcoinBroadcastRequest{
		Transaction: tx,
	}
	res, err := m.callBFG(ctx, m.requestTimeout, bbr)
	if err != nil {
		return nil, err
	}

	bbResp, ok := res.(*bfgapi.BitcoinBroadcastResponse)
	if !ok {
		return nil, fmt.Errorf("not a bitcoin broadcast response %T", res)
	}

	if bbResp.Error != nil {
		return nil, bbResp.Error
	}

	return bbResp.TXID, nil
}

func (m *Miner) bitcoinHeight(ctx context.Context) (uint64, error) {
	bir := &bfgapi.BitcoinInfoRequest{}

	res, err := m.callBFG(ctx, m.requestTimeout, bir)
	if err != nil {
		return 0, err
	}

	biResp, ok := res.(*bfgapi.BitcoinInfoResponse)
	if !ok {
		return 0, fmt.Errorf("not a BitcoinIfnoResponse")
	}

	if biResp.Error != nil {
		return 0, biResp.Error
	}

	return biResp.Height, nil
}

func (m *Miner) bitcoinUTXOs(ctx context.Context, scriptHash []byte) ([]*bfgapi.BitcoinUTXO, error) {
	bur := &bfgapi.BitcoinUTXOsRequest{
		ScriptHash: scriptHash,
	}

	res, err := m.callBFG(ctx, m.requestTimeout, bur)
	if err != nil {
		return nil, err
	}

	buResp, ok := res.(*bfgapi.BitcoinUTXOsResponse)
	if !ok {
		return nil, fmt.Errorf("not a buResp %T", res)
	}

	if buResp.Error != nil {
		return nil, buResp.Error
	}

	return buResp.UTXOs, nil
}

func pickUTXOs(utxos []*bfgapi.BitcoinUTXO, amount int64) ([]*bfgapi.BitcoinUTXO, error) {
	um := make(map[int]*bfgapi.BitcoinUTXO)
	for i := range utxos {
		um[i] = utxos[i]
	}

	// First try to find a single UTXO that equal or exceed the given value.
	// XXX not random enough
	for _, utxo := range um {
		if utxo.Value >= amount {
			return []*bfgapi.BitcoinUTXO{utxo}, nil
		}
	}

	return nil, fmt.Errorf(
		"address does not have sufficient balance to PoP mine, please send additional funds to continue",
	)
}

func createTx(l2Keystone *hemi.L2Keystone, btcHeight uint64, utxo *bfgapi.BitcoinUTXO, payToScript []byte, feeAmount int64) (*btcwire.MsgTx, error) {
	btx := btcwire.MsgTx{
		Version:  2,
		LockTime: uint32(btcHeight),
	}

	// Add UTXO as input.
	outPoint := btcwire.OutPoint{
		Hash:  btcchainhash.Hash(utxo.Hash),
		Index: utxo.Index,
	}
	btx.TxIn = []*btcwire.TxIn{btcwire.NewTxIn(&outPoint, payToScript, nil)}

	// Add output for change as P2PKH.
	changeAmount := utxo.Value - feeAmount
	btx.TxOut = []*btcwire.TxOut{btcwire.NewTxOut(changeAmount, payToScript)}

	// Add PoP TX using OP_RETURN output.
	aks := hemi.L2KeystoneAbbreviate(*l2Keystone)
	popTx := pop.TransactionL2{L2Keystone: aks}
	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		return nil, fmt.Errorf("failed to encode PoP transaction: %w", err)
	}
	btx.TxOut = append(btx.TxOut, btcwire.NewTxOut(0, popTxOpReturn))

	return &btx, nil
}

// XXX this function is not right. Clean it up and ensure we make this in at
// least 2 functions. This needs to create and sign a tx, and then broadcast
// seperately. Also utxo picker needs to be fixed. Don't return a fake utxo
// etc. Fix fee estimation.
func (m *Miner) mineKeystone(ctx context.Context, ks *hemi.L2Keystone) error {
	log.Infof("Broadcasting PoP transaction to Bitcoin...")

	btcHeight, err := m.bitcoinHeight(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Bitcoin height: %w", err)
	}

	payToScript, err := btctxscript.PayToAddrScript(m.btcAddress)
	if err != nil {
		return fmt.Errorf("failed to get pay to address script: %w", err)
	}
	if len(payToScript) != 25 {
		return fmt.Errorf("incorrect length for pay to public key script (%d != 25)", len(payToScript))
	}
	scriptHash := btcchainhash.Hash(sha256.Sum256(payToScript))

	// Estimate BTC fees.
	txLen := 285 // XXX for now all transactions are the same size
	feePerKB := 1024
	feeAmount := (int64(txLen) * int64(feePerKB)) / 1024

	// Check balance.
	confirmed, unconfirmed, err := m.bitcoinBalance(ctx, scriptHash[:])
	if err != nil {
		return fmt.Errorf("failed to get Bitcoin balance: %w", err)
	}
	log.Tracef("Bitcoin balance for miner is: %v confirmed, %v unconfirmed", confirmed, unconfirmed)

	// Find UTXOs for inputs.
	log.Tracef("Looking for UTXOs for script hash %v", scriptHash)
	utxos, err := m.bitcoinUTXOs(ctx, scriptHash[:])
	if err != nil {
		return fmt.Errorf("failed to get Bitcoin UTXOs: %w", err)
	}

	log.Tracef("Found %d UTXOs at Bitcoin height %d", len(utxos), btcHeight)

	if len(utxos) == 0 {
		return errors.New("could not find any utxos")
	}

	utxos, err = pickUTXOs(utxos, feeAmount)
	if err != nil {
		return fmt.Errorf("failed to pick UTXOs: %w", err)
	}

	if len(utxos) != 1 {
		return errors.New("unable to create PoP transaction with a single UTXO")
	}

	// Build transaction.
	btx, err := createTx(ks, btcHeight, utxos[0], payToScript, feeAmount)
	if err != nil {
		return err
	}

	// Sign input.
	err = bitcoin.SignTx(btx, payToScript, m.btcPrivateKey, m.btcPublicKey)
	if err != nil {
		return err
	}

	// broadcast tx
	var buf bytes.Buffer
	if err := btx.Serialize(&buf); err != nil {
		return fmt.Errorf("failed to serialize Bitcoin transaction: %w", err)
	}
	txb := buf.Bytes()

	log.Tracef("Broadcasting Bitcoin transaction %x", txb)

	txh, err := m.bitcoinBroadcast(ctx, txb)
	if err != nil {
		return fmt.Errorf("failed to broadcast PoP transaction: %w", err)
	}
	txHash, err := btcchainhash.NewHash(txh)
	if err != nil {
		return fmt.Errorf("failed to create BTC hash from transaction hash: %w", err)
	}

	log.Infof("Successfully broadcast PoP transaction to Bitcoin with TX hash %v", txHash)

	return nil
}

func (m *Miner) Ping(ctx context.Context, timestamp int64) (*bfgapi.PingResponse, error) {
	res, err := m.callBFG(ctx, m.requestTimeout, &bfgapi.PingRequest{
		Timestamp: timestamp,
	})
	if err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}

	pr, ok := res.(*bfgapi.PingResponse)
	if !ok {
		return nil, fmt.Errorf("not a PingResponse: %T", res)
	}

	return pr, nil
}

func (m *Miner) L2Keystones(ctx context.Context, count uint64) (*bfgapi.L2KeystonesResponse, error) {
	res, err := m.callBFG(ctx, m.requestTimeout, &bfgapi.L2KeystonesRequest{
		NumL2Keystones: count,
	})
	if err != nil {
		return nil, fmt.Errorf("l2keystones: %w", err)
	}

	kr, ok := res.(*bfgapi.L2KeystonesResponse)
	if !ok {
		return nil, fmt.Errorf("not a L2KeystonesResponse: %T", res)
	}

	if kr.Error != nil {
		return nil, kr.Error
	}

	return kr, nil
}

func (m *Miner) BitcoinBalance(ctx context.Context, scriptHash string) (*bfgapi.BitcoinBalanceResponse, error) {
	if scriptHash[0:2] == "0x" || scriptHash[0:2] == "0X" {
		scriptHash = scriptHash[2:]
	}
	sh, err := hex.DecodeString(scriptHash)
	if err != nil {
		return nil, fmt.Errorf("bitcoinBalance: %w", err)
	}
	res, err := m.callBFG(ctx, m.requestTimeout, &bfgapi.BitcoinBalanceRequest{
		ScriptHash: sh,
	})
	if err != nil {
		return nil, fmt.Errorf("bitcoinBalance: %w", err)
	}

	br, ok := res.(*bfgapi.BitcoinBalanceResponse)
	if !ok {
		return nil, fmt.Errorf("not a BitcoinBalanceResponse: %T", res)
	}

	if br.Error != nil {
		return nil, br.Error
	}

	return br, nil
}

func (m *Miner) BitcoinInfo(ctx context.Context) (*bfgapi.BitcoinInfoResponse, error) {
	res, err := m.callBFG(ctx, m.requestTimeout, &bfgapi.BitcoinInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("bitcoinInfo: %w", err)
	}

	ir, ok := res.(*bfgapi.BitcoinInfoResponse)
	if !ok {
		return nil, fmt.Errorf("not a BitcoinInfoResponse: %T", res)
	}

	if ir.Error != nil {
		return nil, ir.Error
	}

	return ir, nil
}

func (m *Miner) BitcoinUTXOs(ctx context.Context, scriptHash string) (*bfgapi.BitcoinUTXOsResponse, error) {
	if scriptHash[0:2] == "0x" || scriptHash[0:2] == "0X" {
		scriptHash = scriptHash[2:]
	}
	sh, err := hex.DecodeString(scriptHash)
	if err != nil {
		return nil, fmt.Errorf("bitcoinBalance: %w", err)
	}
	res, err := m.callBFG(ctx, m.requestTimeout, &bfgapi.BitcoinUTXOsRequest{
		ScriptHash: sh,
	})
	if err != nil {
		return nil, fmt.Errorf("bitcoinUTXOs: %w", err)
	}

	ir, ok := res.(*bfgapi.BitcoinUTXOsResponse)
	if !ok {
		return nil, fmt.Errorf("not a BitcoinUTXOsResponse: %T", res)
	}

	if ir.Error != nil {
		return nil, ir.Error
	}

	return ir, nil
}

func (m *Miner) mineKnownKeystones(ctx context.Context) {
	copies := m.l2KeystonesForProcessing()

	for _, e := range copies {
		serialized := hemi.L2KeystoneAbbreviate(e).Serialize()
		key := hex.EncodeToString(serialized[:])

		log.Infof("Received keystone for mining with height %v...", e.L2BlockNumber)

		err := m.mineKeystone(ctx, &e)
		if err != nil {
			log.Errorf("Failed to mine keystone: %v", err)
		}

		m.mtx.Lock()

		if v, ok := m.l2Keystones[key]; ok {
			// if there is an error, mark keystone as "requires processing" so
			// potentially gets retried, otherwise set this to false to
			// nothing tries to process it
			v.requiresProcessing = err != nil
			m.l2Keystones[key] = v
		}

		m.mtx.Unlock()
	}
}

func (m *Miner) mine(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.mineNowCh:
			go m.mineKnownKeystones(ctx)
		case <-time.After(l2KeystoneRetryTimeout):
			go m.mineKnownKeystones(ctx)
		}
	}
}

func (m *Miner) queueKeystoneForMining(keystone *hemi.L2Keystone) {
	m.AddL2Keystone(*keystone)
	select {
	case m.mineNowCh <- struct{}{}:
	default:
	}
}

func sortL2KeystonesByL2BlockNumberAsc(a, b hemi.L2Keystone) int {
	return cmp.Compare(a.L2BlockNumber, b.L2BlockNumber)
}

func (m *Miner) processReceivedKeystones(ctx context.Context, l2Keystones []hemi.L2Keystone) {
	slices.SortFunc(l2Keystones, sortL2KeystonesByL2BlockNumberAsc)

	for _, kh := range l2Keystones {
		log.Infof(
			"checking keystone received with height %d against last keystone %s",
			kh.L2BlockNumber,
			func() string {
				if m.lastKeystone == nil {
					return "nil"
				}

				return fmt.Sprintf("%d", m.lastKeystone.L2BlockNumber)
			}(),
		)
		if m.lastKeystone == nil || kh.L2BlockNumber > m.lastKeystone.L2BlockNumber {
			log.Infof("Got new last keystone header with height %v", kh.L2BlockNumber)

			// copy L2Keystone to a tmp variable so the value doesn't get
			// ovewritten on next iteration. otherwise lastKeystone always
			// points to the latest kh
			tmp := kh
			m.lastKeystone = &tmp

			m.queueKeystoneForMining(&tmp)
		}
	}
}

func (m *Miner) callBFG(parrentCtx context.Context, timeout time.Duration, msg any) (any, error) {
	log.Tracef("callBFG %T", msg)
	defer log.Tracef("callBFG exit %T", msg)

	bc := bfgCmd{
		msg: msg,
		ch:  make(chan any),
	}

	ctx, cancel := context.WithTimeout(parrentCtx, timeout)
	defer cancel()

	// attempt to send
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case m.bfgCmdCh <- bc:
	default:
		return nil, fmt.Errorf("bfg command queue full")
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

func (m *Miner) checkForKeystones(ctx context.Context) error {
	log.Tracef("Checking for new keystone headers...")

	ghkr := &bfgapi.L2KeystonesRequest{
		NumL2Keystones: 3, // XXX this needs to be a bit smarter, do this based on some sort of time calculation. Do keep it simple, we don't need keystones that are older than let's say, 30 minbutes.
	}

	res, err := m.callBFG(ctx, m.requestTimeout, ghkr)
	if err != nil {
		return err
	}

	ghkrResp, ok := res.(*bfgapi.L2KeystonesResponse)
	if !ok {
		return fmt.Errorf("not an L2KeystonesResponse")
	}

	if ghkrResp.Error != nil {
		return ghkrResp.Error
	}

	log.Tracef("Got response with %v keystones", len(ghkrResp.L2Keystones))

	m.processReceivedKeystones(ctx, ghkrResp.L2Keystones)

	return nil
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

func handle(service string, mux *http.ServeMux, pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandleFunc(pattern, handler)
	log.Infof("handle (%v): %v", service, pattern)
}

func (m *Miner) handleBFGCallCompletion(parrentCtx context.Context, conn *protocol.Conn, bc bfgCmd) {
	log.Tracef("handleBFGCallCompletion")
	defer log.Tracef("handleBFGCallCompletion exit")

	ctx, cancel := context.WithTimeout(parrentCtx, m.requestTimeout)
	defer cancel()

	log.Tracef("handleBFGCallCompletion: %v", spew.Sdump(bc.msg))

	_, _, payload, err := bfgapi.Call(ctx, conn, bc.msg)
	if err != nil {
		log.Debugf("handleBFGCallCompletion %T: %v", bc.msg, err)
		select {
		case <-ctx.Done():
			bc.ch <- ctx.Err()
		case bc.ch <- err:
		default:
		}
	}
	select {
	case bc.ch <- payload:
		log.Tracef("handleBFGCallCompletion returned: %v", spew.Sdump(payload))
	default:
	}
}

func (m *Miner) handleBFGWebsocketRead(ctx context.Context, conn *protocol.Conn) error {
	defer m.bfgWg.Done()

	log.Tracef("handleBFGWebsocketRead")
	defer log.Tracef("handleBFGWebsocketRead exit")
	for {
		cmd, rid, payload, err := bfgapi.ReadConn(ctx, conn)
		if err != nil {
			// XXX kinda don't want to do thi here
			if errors.Is(err, protocol.PublicKeyAuthError) {
				return err
			}

			// See if we were terminated
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(m.holdoffTimeout):
			}
			// XXX this is too noisy
			log.Errorf("Retrying connecting to BFG")
			continue
		}
		switch cmd {
		case bfgapi.CmdPingRequest:
			p := payload.(*bfgapi.PingRequest)
			response := &bfgapi.PingResponse{
				OriginTimestamp: p.Timestamp,
				Timestamp:       time.Now().Unix(),
			}
			// XXX WriteConn ??
			if err := bfgapi.Write(ctx, conn, rid, response); err != nil {
				log.Errorf("handleBFGWebsocketRead write: %v",
					err)
			}
		case bfgapi.CmdL2KeystonesNotification:
			go func() {
				if err := m.checkForKeystones(ctx); err != nil {
					log.Errorf("error checking for keystones: %s", err)
				}
			}()
		default:
			return fmt.Errorf("unknown command: %v", cmd)
		}
	}
}

func (m *Miner) handleBFGWebsocketCall(ctx context.Context, conn *protocol.Conn) {
	defer m.bfgWg.Done()

	log.Tracef("handleBFGWebsocketCall")
	defer log.Tracef("handleBFGWebsocketCall exit")
	for {
		select {
		case <-ctx.Done():
			return
		case bc := <-m.bfgCmdCh:
			go m.handleBFGCallCompletion(ctx, conn, bc)
		}
	}
}

func (m *Miner) connectBFG(pctx context.Context) error {
	log.Tracef("connectBFG")
	defer log.Tracef("connectBFG exit")

	var (
		err           error
		authenticator protocol.Authenticator
		conn          *protocol.Conn
	)

	authenticator, err = auth.NewSecp256k1AuthClient(m.btcPrivateKey)
	if err != nil {
		return err
	}

	conn, err = protocol.NewConn(m.cfg.BFGWSURL, authenticator)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	err = conn.Connect(ctx)
	if err != nil {
		return err
	}

	m.bfgWg.Add(1)
	go m.handleBFGWebsocketCall(ctx, conn)

	// XXX ugh
	rWSCh := make(chan error)
	m.bfgWg.Add(1)
	go func() {
		rWSCh <- m.handleBFGWebsocketRead(ctx, conn)
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-rWSCh:
	}
	cancel()

	// Wait for exit
	log.Debugf("Connected to BFG: %s", m.cfg.BFGWSURL)
	m.bfgWg.Wait()

	return nil
}

func (m *Miner) bfg(ctx context.Context) error {
	defer m.wg.Done()

	log.Tracef("bfg")
	defer log.Tracef("bfg exit")

	for {
		if err := m.connectBFG(ctx); err != nil {
			log.Debugf("connectBFG: %v", err)

			if errors.Is(err, protocol.PublicKeyAuthError) {
				return err
			}
		}

		// See if we were terminated
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.holdoffTimeout):
		}

		log.Debugf("Reconnecting to: %v", m.cfg.BFGWSURL)
	}
}

func (m *Miner) Run(pctx context.Context) error {
	if !m.testAndSetRunning(true) {
		return fmt.Errorf("popmd already running")
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

	log.Infof("Starting PoP miner with BTC address %v (public key %x)",
		m.btcAddress.EncodeAddress(), m.btcPublicKey.SerializeCompressed())

	bfgErrCh := make(chan error)
	m.wg.Add(1)
	go func() {
		bfgErrCh <- m.bfg(ctx)
	}()

	m.wg.Add(1)
	go m.mine(ctx)

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-bfgErrCh:
	}
	cancel()

	log.Infof("pop miner service shutting down")

	m.wg.Wait()
	log.Infof("pop miner service clean shutdown")

	return err
}

func (m *Miner) AddL2Keystone(val hemi.L2Keystone) {
	serialized := hemi.L2KeystoneAbbreviate(val).Serialize()
	key := hex.EncodeToString(serialized[:])

	toInsert := L2KeystoneProcessingContainer{
		l2Keystone:         val,
		requiresProcessing: true,
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// keystone already exists, no-op
	if _, ok := m.l2Keystones[key]; ok {
		return
	}

	if len(m.l2Keystones) < l2KeystonesMaxSize {
		m.l2Keystones[key] = toInsert
		return
	}

	var smallestL2BlockNumber uint32
	var smallestKey string

	for k, v := range m.l2Keystones {
		if smallestL2BlockNumber == 0 || v.l2Keystone.L2BlockNumber < smallestL2BlockNumber {
			smallestL2BlockNumber = v.l2Keystone.L2BlockNumber
			smallestKey = k
		}
	}

	// do not insert an L2Keystone that is older than all of the ones already
	// added
	if val.L2BlockNumber < smallestL2BlockNumber {
		return
	}

	delete(m.l2Keystones, smallestKey)

	m.l2Keystones[key] = toInsert
}

// l2KeystonesForProcessing creates copies of the l2 keystones, set them to
// "processing", then returns the copies with the newest first
func (m *Miner) l2KeystonesForProcessing() []hemi.L2Keystone {
	copies := make([]hemi.L2Keystone, 0)

	m.mtx.Lock()

	for i, v := range m.l2Keystones {
		// if we're currently processing, or we've already processed the keystone
		// then don't process
		if !v.requiresProcessing {
			continue
		}

		// since we're about to process, mark this as false so others don't
		// process the same
		v.requiresProcessing = false
		m.l2Keystones[i] = v
		copies = append(copies, v.l2Keystone)
	}
	m.mtx.Unlock()

	slices.SortFunc(copies, func(a, b hemi.L2Keystone) int {
		return int(b.L2BlockNumber) - int(a.L2BlockNumber)
	})

	return copies
}
