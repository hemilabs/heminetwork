// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"syscall/js"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	btcchaincfg "github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/ethereum"
	"github.com/hemilabs/heminetwork/service/popm"
)

// handlers maps methods to the correct handler.
var handlers = map[Method]*Dispatch{
	MethodVersion: {
		Handler: wasmVersion,
	},
	MethodGenerateKey: {
		Handler: generateKey,
		Required: []DispatchArgs{
			{Name: "network", Type: js.TypeString},
		},
	},
	MethodParseKey: {
		Handler: parseKey,
		Required: []DispatchArgs{
			{Name: "network", Type: js.TypeString},
			{Name: "privateKey", Type: js.TypeString},
		},
	},
	MethodBitcoinAddressToScriptHash: {
		Handler: bitcoinAddressToScriptHash,
		Required: []DispatchArgs{
			{Name: "network", Type: js.TypeString},
			{Name: "address", Type: js.TypeString},
		},
	},
	MethodStartPoPMiner: {
		Handler: startPoPMiner,
		Required: []DispatchArgs{
			{Name: "logLevel", Type: js.TypeString},
			{Name: "network", Type: js.TypeString},
			{Name: "privateKey", Type: js.TypeString},
		},
	},
	MethodStopPoPMiner: {
		Handler: stopPopMiner,
	},
	MethodMinerStatus: {
		Handler: minerStatus,
	},

	// The following can only be dispatched after the PoP Miner is running.
	MethodPing: {
		Handler: ping,
	},
	MethodL2Keystones: {
		Handler: l2Keystones,
		Required: []DispatchArgs{
			{Name: "numL2Keystones", Type: js.TypeNumber},
		},
	},
	MethodBitcoinBalance: {
		Handler: bitcoinBalance,
		Required: []DispatchArgs{
			{Name: "scriptHash", Type: js.TypeString},
		},
	},
	MethodBitcoinInfo: {
		Handler: bitcoinInfo,
	},
	MethodBitcoinUTXOs: {
		Handler: bitcoinUTXOs,
		Required: []DispatchArgs{
			{Name: "scriptHash", Type: js.TypeString},
		},
	},

	// Events
	MethodEventListenerAdd: {
		Handler: addEventListener,
		Required: []DispatchArgs{
			{Name: "eventType", Type: js.TypeString},
			{Name: "handler", Type: js.TypeFunction},
		},
	},
	MethodEventListenerRemove: {
		Handler: removeEventListener,
		Required: []DispatchArgs{
			{Name: "eventType", Type: js.TypeString},
			{Name: "handler", Type: js.TypeFunction},
		},
	},
}

type DispatchArgs struct {
	Name string
	Type js.Type
}

type Dispatch struct {
	Handler  func(this js.Value, args []js.Value) (any, error)
	Required []DispatchArgs
}

func dispatch(this js.Value, args []js.Value) any {
	defer func() {
		if r := recover(); r != nil {
			log.Criticalf("recovered panic: %v", r)
			log.Criticalf(string(debug.Stack()))
		}
	}()

	log.Tracef("dispatch")
	defer log.Tracef("dispatch exit")

	// Create JS Promise handler
	handler := js.FuncOf(func(_ js.Value, handlerArgs []js.Value) any {
		resolve := handlerArgs[0]
		reject := handlerArgs[1]

		// Run dispatched call asynchronously
		go func() {
			// This function must always complete a promise.
			defer func() {
				if r := recover(); r != nil {
					log.Criticalf("recovered panic: %v", r)
					log.Criticalf(string(debug.Stack()))
					reject.Invoke(jsErrorWithCode(ErrorCodeInternal,
						fmt.Errorf("recovered panic: %v", r)))
				}
			}()

			// parse args
			d, err := parseArgs(args)
			if err != nil {
				reject.Invoke(jsError(err))
				return
			}

			// dispatch sanitized call
			rv, err := d.Handler(this, args)
			if err != nil {
				reject.Invoke(jsError(err))
				return
			}
			resolve.Invoke(jsValueOf(rv))
		}()

		// The handler of a Promise doesn't return any value
		return nil
	})
	defer handler.Release()

	// Create and return the Promise object
	return promiseConstructor.New(handler)
}

func parseArgs(args []js.Value) (*Dispatch, error) {
	// Verify we received data readable command
	if len(args) != 1 {
		return nil, fmt.Errorf("expected 1 argument, got %v", len(args))
	}
	data := args[0]
	if data.Type() != js.TypeObject {
		return nil, fmt.Errorf("expected an object, got: %v", data.Type())
	}

	m := data.Get("method")
	if m.Type() != js.TypeString {
		return nil, fmt.Errorf("expected method to be a string, got: %v", m.Type())
	}
	d, ok := handlers[Method(m.String())]
	if !ok {
		log.Warningf("method not found: %v", m.String())
		return nil, fmt.Errorf("method not found: %v", m.String())
	}

	// Verify required args
	for k := range d.Required {
		name := d.Required[k].Name
		typ := d.Required[k].Type
		arg := data.Get(name)
		if arg.Type() != typ {
			return nil, fmt.Errorf("%v: invalid type %v, want %v",
				name, arg.Type(), typ)
		}
	}

	return d, nil
}

func wasmVersion(_ js.Value, _ []js.Value) (any, error) {
	return VersionResult{
		Version:   version,
		GitCommit: gitCommit,
	}, nil
}

func generateKey(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("generatekey")
	defer log.Tracef("generatekey exit")

	net, btcChainParams, err := bitcoinNetwork(args[0].Get("network").String())
	if err != nil {
		return nil, err
	}

	privKey, err := dcrsecp256k1.GeneratePrivateKey()
	if err != nil {
		log.Errorf("failed to generate private key: %v", err)
		return nil, fmt.Errorf("generate secp256k1 private key: %w", err)
	}

	result, err := createKeyResult(privKey, net, btcChainParams)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func parseKey(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("parseKey")
	defer log.Tracef("parseKey exit")

	net, btcChainParams, err := bitcoinNetwork(args[0].Get("network").String())
	if err != nil {
		return nil, err
	}

	privateKey := args[0].Get("privateKey").String()
	b, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, errorWithCode(ErrorCodeInvalidValue,
			fmt.Errorf("invalid private key: %w", err))
	}

	if len(b) != dcrsecp256k1.PrivKeyBytesLen {
		return nil, errorWithCode(ErrorCodeInvalidValue,
			fmt.Errorf("invalid private key length: %d", len(b)))
	}

	privKey := dcrsecp256k1.PrivKeyFromBytes(b)
	result, err := createKeyResult(privKey, net, btcChainParams)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func createKeyResult(privKey *dcrsecp256k1.PrivateKey, net string, btcChainParams *btcchaincfg.Params) (*KeyResult, error) {
	compressedPubKey := privKey.PubKey().SerializeCompressed()
	uncompressedPubKey := privKey.PubKey().SerializeUncompressed()

	btcAddress, err := btcutil.NewAddressPubKey(compressedPubKey, btcChainParams)
	if err != nil {
		log.Errorf("failed to create bitcoin address: %v", err)
		return nil, fmt.Errorf("create bitcoin address from public key: %w", err)
	}
	btcPubKeyHash := btcAddress.AddressPubKeyHash()

	btcScript, err := txscript.PayToAddrScript(btcPubKeyHash)
	if err != nil {
		return nil, fmt.Errorf("convert address to script: %w", err)
	}
	btcScriptHash := sha256.Sum256(btcScript)

	return &KeyResult{
		HemiAddress:       ethereum.PublicKeyToAddress(uncompressedPubKey).String(),
		Network:           net,
		PrivateKey:        hex.EncodeToString(privKey.Serialize()),
		PublicKey:         hex.EncodeToString(compressedPubKey),
		BitcoinPubKeyHash: btcPubKeyHash.String(),
		BitcoinScriptHash: hex.EncodeToString(btcScriptHash[:]),
	}, nil
}

func bitcoinAddressToScriptHash(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("bitcoinAddressToScriptHash")
	defer log.Tracef("bitcoinAddressToScriptHash exit")

	net, btcChainParams, err := bitcoinNetwork(args[0].Get("network").String())
	if err != nil {
		return nil, err
	}

	address := args[0].Get("address").String()
	addr, err := btcutil.DecodeAddress(address, btcChainParams)
	if err != nil {
		return nil, errorWithCode(ErrorCodeInvalidValue,
			fmt.Errorf("invalid bitcoin address: %w", err))
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("convert address to script: %w", err)
	}

	scriptHash := sha256.Sum256(script)
	return BitcoinAddressToScriptHashResult{
		Network:    net,
		Address:    address,
		ScriptHash: hex.EncodeToString(scriptHash[:]),
	}, nil
}

func bitcoinNetwork(network string) (string, *btcchaincfg.Params, error) {
	switch network {
	case "devnet", "testnet3", "testnet":
		return "testnet3", &btcchaincfg.TestNet3Params, nil
	case "mainnet":
		return "mainnet", &btcchaincfg.MainNetParams, nil
	default:
		return "", nil, errorWithCode(ErrorCodeInvalidValue,
			fmt.Errorf("invalid network: %s", network))
	}
}

func startPoPMiner(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("startPoPMiner")
	defer log.Tracef("startPoPMiner exit")

	svc.minerMtx.Lock()
	defer svc.minerMtx.Unlock()
	if svc.miner != nil {
		return nil, errors.New("miner already started")
	}

	m, autoFees, err := newMiner(args[0])
	if err != nil {
		return nil, err
	}

	// Add WebAssembly miner event handler
	m.RegisterEventHandler(svc.handleMinerEvent)
	svc.miner = m

	// run in background
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		svc.dispatchEvent(EventTypeMinerStart, nil)
		if err := m.Run(m.ctx); !errors.Is(err, context.Canceled) {
			svc.dispatchEvent(EventTypeMinerStop, EventMinerStop{
				Error: &Error{
					Code:      ErrorCodeInternal,
					Message:   err.Error(),
					Stack:     string(debug.Stack()),
					Timestamp: time.Now().Unix(),
				},
			})

			// TODO: Fix, this doesn't work very well.
			//  We should remove the miner from svc here, and make stopPoPMiner
			//  no longer return the start error.
			m.errCh <- err
			return
		}

		// Exited without error.
		svc.dispatchEvent(EventTypeMinerStop, EventMinerStop{})
	}()

	if autoFees.enabled {
		// Automatic fees are enabled, run the goroutine to retrieve the fees
		// at the refresh interval.
		m.wg.Add(1)
		go m.automaticFees(
			autoFees.feeType,
			autoFees.multiplier,
			autoFees.refreshInterval,
		)
	}

	return js.Null(), nil
}

type automaticFeeOptions struct {
	enabled         bool
	feeType         RecommendedFeeType
	multiplier      float64
	refreshInterval time.Duration
}

// newMiner creates a [popm.Miner] using config options from the given
// JavaScript object.
func newMiner(config js.Value) (*Miner, *automaticFeeOptions, error) {
	cfg := popm.NewDefaultConfig()
	cfg.BTCPrivateKey = config.Get("privateKey").String()
	cfg.StaticFee = uint(config.Get("staticFee").Int())

	// Log level
	cfg.LogLevel = config.Get("logLevel").String()
	if cfg.LogLevel == "" {
		cfg.LogLevel = "popm=ERROR"
	}
	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		return nil, nil, errorWithCode(ErrorCodeInvalidValue,
			fmt.Errorf("configure logger: %w", err))
	}

	// Network
	network := config.Get("network").String()
	netOpts, ok := networks[network]
	if !ok {
		return nil, nil, errorWithCode(ErrorCodeInvalidValue,
			fmt.Errorf("unknown network: %s", network))
	}
	cfg.BFGWSURL = netOpts.bfgURL
	cfg.BTCChainName = netOpts.btcChainName

	// Automatic fee options
	autoFeeConfig := config.Get("automaticFees")
	autoFees := &automaticFeeOptions{
		enabled:         autoFeeConfig.IsUndefined() || autoFeeConfig.Truthy(),
		feeType:         RecommendedFeeTypeFastest,
		multiplier:      1.1,
		refreshInterval: 5 * time.Minute,
	}
	if autoFeeConfig.Type() == js.TypeString {
		// automaticFees is a string, parse the selected recommended fee type.
		feeType, err := ParseRecommendedFeeType(autoFeeConfig.String())
		if err != nil {
			return nil, nil, errorWithCode(ErrorCodeInvalidValue, err)
		}
		autoFees.feeType = feeType
	}
	if fm := config.Get("automaticFeeMultiplier"); fm.Truthy() {
		if fm.Float() <= 0 {
			return nil, nil, errorWithCode(ErrorCodeInvalidValue,
				errors.New("automaticFeeMultiplier must be greater than zero"))
		}
		autoFees.multiplier = fm.Float()
	}
	if rf := config.Get("automaticFeeRefreshSeconds"); rf.Truthy() {
		if rf.Int() < 1 {
			return nil, nil, errorWithCode(ErrorCodeInvalidValue,
				errors.New("automaticFeeRefreshSeconds must be greater than zero"))
		}
		autoFees.refreshInterval = time.Duration(rf.Int()) * time.Second
	}

	// Create new miner
	miner, err := popm.NewMiner(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create miner: %w", err)
	}

	m := &Miner{
		Miner: miner,
		errCh: make(chan error, 1),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		mempoolSpaceURL: netOpts.mempoolSpaceURL,
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	return m, autoFees, nil
}

func stopPopMiner(_ js.Value, _ []js.Value) (any, error) {
	log.Tracef("stopPopMiner")
	defer log.Tracef("stopPopMiner exit")

	svc.minerMtx.Lock()
	if svc.miner == nil {
		svc.minerMtx.Unlock()
		return nil, errors.New("miner not running")
	}

	// Copy the m and release the lock
	m := svc.miner
	svc.miner = nil
	svc.minerMtx.Unlock()

	if err := m.shutdown(); err != nil {
		return nil, err
	}

	return js.Null(), nil
}

func minerStatus(_ js.Value, _ []js.Value) (any, error) {
	log.Tracef("minerStatus")
	defer log.Tracef("minerStatus exit")

	var status MinerStatusResult
	miner, err := runningMiner()
	if err == nil {
		status.Running = true
		status.Connected = miner.Connected()
		status.Fee = miner.Fee()
	}

	return status, nil
}

func ping(_ js.Value, _ []js.Value) (any, error) {
	log.Tracef("ping")
	defer log.Tracef("ping exit")

	miner, err := runningMiner()
	if err != nil {
		return nil, err
	}
	pr, err := miner.Ping(miner.ctx, time.Now().Unix())
	if err != nil {
		return nil, err
	}

	// TODO(joshuasing): protocol.PingResponse should really use a more accurate
	//  time format instead of unix seconds.
	return PingResult{
		OriginTimestamp: time.Unix(pr.OriginTimestamp, 0).UnixNano(),
		Timestamp:       time.Unix(pr.Timestamp, 0).UnixNano(),
	}, nil
}

func l2Keystones(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("l2Keystones")
	defer log.Tracef("l2Keystones exit")

	c := args[0].Get("numL2Keystones").Int()
	if c < 0 || c > 10 {
		c = 2
	}
	count := uint64(c)

	miner, err := runningMiner()
	if err != nil {
		return nil, err
	}
	pr, err := miner.L2Keystones(miner.ctx, count)
	if err != nil {
		return nil, err
	}

	keystones := make([]L2Keystone, len(pr.L2Keystones))
	for i, ks := range pr.L2Keystones {
		keystones[i] = convertL2Keystone(&ks)
	}

	return L2KeystoneResult{
		L2Keystones: keystones,
	}, nil
}

func bitcoinBalance(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("bitcoinBalance")
	defer log.Tracef("bitcoinBalance exit")

	scriptHash := args[0].Get("scriptHash").String()

	miner, err := runningMiner()
	if err != nil {
		return nil, err
	}
	pr, err := miner.BitcoinBalance(miner.ctx, scriptHash)
	if err != nil {
		return nil, err
	}

	return BitcoinBalanceResult{
		Confirmed:   pr.Confirmed,
		Unconfirmed: pr.Unconfirmed,
	}, nil
}

func bitcoinInfo(_ js.Value, _ []js.Value) (any, error) {
	log.Tracef("bitcoinInfo")
	defer log.Tracef("bitcoinInfo exit")

	miner, err := runningMiner()
	if err != nil {
		return nil, err
	}
	pr, err := miner.BitcoinInfo(miner.ctx)
	if err != nil {
		return nil, err
	}

	return BitcoinInfoResult{
		Height: pr.Height,
	}, nil
}

func bitcoinUTXOs(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("bitcoinUTXOs")
	defer log.Tracef("bitcoinUTXOs exit")

	scriptHash := args[0].Get("scriptHash").String()

	miner, err := runningMiner()
	if err != nil {
		return nil, err
	}
	pr, err := miner.BitcoinUTXOs(miner.ctx, scriptHash)
	if err != nil {
		return nil, err
	}

	utxos := make([]BitcoinUTXO, len(pr.UTXOs))
	for i, u := range pr.UTXOs {
		utxos[i] = BitcoinUTXO{
			Hash:  u.Hash.String(),
			Index: u.Index,
			Value: u.Value,
		}
	}

	return BitcoinUTXOsResult{
		UTXOs: utxos,
	}, nil
}

func addEventListener(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("addEventListener")
	defer log.Tracef("addEventListener exit")

	eventType := args[0].Get("eventType").String()
	handler := args[0].Get("handler")

	event, ok := eventTypes[eventType]
	if !ok {
		return nil, errorWithCode(ErrorCodeInvalidValue,
			fmt.Errorf("invalid event type: %s", eventType))
	}

	svc.listenersMtx.Lock()
	svc.listeners[event] = append(svc.listeners[event], handler)
	svc.listenersMtx.Unlock()

	return js.Null(), nil
}

func removeEventListener(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("removeEventListener")
	defer log.Tracef("removeEventListener exit")

	eventType := args[0].Get("eventType").String()
	handler := args[0].Get("handler")

	event, ok := eventTypes[eventType]
	if !ok {
		return nil, errorWithCode(ErrorCodeInvalidValue,
			fmt.Errorf("invalid event type: %s", eventType))
	}

	svc.listenersMtx.Lock()
	eventHandlers := svc.listeners[event]
	for i, h := range eventHandlers {
		if handler.Equal(h) {
			// Remove handler from the slice.
			// We don't care about the order, so set the current index to the
			// value of the last index, then delete the last index.
			handlersLen := len(eventHandlers)
			eventHandlers[i] = eventHandlers[handlersLen-1]
			eventHandlers = eventHandlers[:handlersLen-1]
		}
	}
	svc.listeners[event] = eventHandlers
	svc.listenersMtx.Unlock()

	return js.Null(), nil
}
