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

	pmMtx.Lock()
	defer pmMtx.Unlock()
	if pm != nil {
		return nil, errors.New("pop miner already started")
	}

	pm = new(Miner)
	pm.ctx, pm.cancel = context.WithCancel(context.Background())

	cfg := popm.NewDefaultConfig()
	cfg.BTCPrivateKey = args[0].Get("privateKey").String()
	cfg.StaticFee = uint(args[0].Get("staticFee").Int())

	cfg.LogLevel = args[0].Get("logLevel").String()
	if cfg.LogLevel == "" {
		cfg.LogLevel = "popm=ERROR"
	}
	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		pm = nil
		return nil, fmt.Errorf("configure logger: %w", err)
	}

	network := args[0].Get("network").String()
	netOpts, ok := networks[network]
	if !ok {
		pm = nil
		return nil, fmt.Errorf("unknown network: %s", network)
	}
	cfg.BFGWSURL = netOpts.bfgURL
	cfg.BTCChainName = netOpts.btcChainName

	var err error
	pm.miner, err = popm.NewMiner(cfg)
	if err != nil {
		pm = nil
		return nil, fmt.Errorf("create PoP miner: %w", err)
	}

	// launch in background
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		if err := pm.miner.Run(pm.ctx); !errors.Is(err, context.Canceled) {
			// TODO(joshuasing): dispatch event on failure
			pmMtx.Lock()
			defer pmMtx.Unlock()
			pm.err = err // Theoretically this can logic race unless we unset pm
		}
	}()

	return js.Null(), nil
}

func stopPopMiner(_ js.Value, _ []js.Value) (any, error) {
	log.Tracef("stopPopMiner")
	defer log.Tracef("stopPopMiner exit")

	pmMtx.Lock()
	if pm == nil {
		pmMtx.Unlock()
		return nil, errors.New("pop miner not running")
	}

	oldPM := pm
	pm = nil
	pmMtx.Unlock()
	oldPM.cancel()
	oldPM.wg.Wait()

	if oldPM.err != nil {
		return nil, oldPM.err
	}

	return js.Null(), nil
}

func ping(_ js.Value, _ []js.Value) (any, error) {
	log.Tracef("ping")
	defer log.Tracef("ping exit")

	activePM, err := activeMiner()
	if err != nil {
		return nil, err
	}
	pr, err := activePM.miner.Ping(activePM.ctx, time.Now().Unix())
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

	activePM, err := activeMiner()
	if err != nil {
		return nil, err
	}
	pr, err := activePM.miner.L2Keystones(activePM.ctx, count)
	if err != nil {
		return nil, err
	}

	keystones := make([]L2Keystone, len(pr.L2Keystones))
	for i, ks := range pr.L2Keystones {
		keystones[i] = L2Keystone{
			Version:            ks.Version,
			L1BlockNumber:      ks.L1BlockNumber,
			L2BlockNumber:      ks.L2BlockNumber,
			ParentEPHash:       ks.ParentEPHash.String(),
			PrevKeystoneEPHash: ks.PrevKeystoneEPHash.String(),
			StateRoot:          ks.StateRoot.String(),
			EPHash:             ks.EPHash.String(),
		}
	}

	return L2KeystoneResult{
		L2Keystones: keystones,
	}, nil
}

func bitcoinBalance(_ js.Value, args []js.Value) (any, error) {
	log.Tracef("bitcoinBalance")
	defer log.Tracef("bitcoinBalance exit")

	scriptHash := args[0].Get("scriptHash").String()

	activePM, err := activeMiner()
	if err != nil {
		return nil, err
	}
	pr, err := activePM.miner.BitcoinBalance(activePM.ctx, scriptHash)
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

	activePM, err := activeMiner()
	if err != nil {
		return nil, err
	}
	pr, err := activePM.miner.BitcoinInfo(activePM.ctx)
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

	activePM, err := activeMiner()
	if err != nil {
		return nil, err
	}
	pr, err := activePM.miner.BitcoinUTXOs(activePM.ctx, scriptHash)
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
