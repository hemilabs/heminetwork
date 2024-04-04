// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall/js"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	btcchaincfg "github.com/btcsuite/btcd/chaincfg"
	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/ethereum"
	"github.com/hemilabs/heminetwork/service/popm"
)

const (
	logLevel = "INFO"
	version  = "1.0.0"
)

// This is used globally
type PopMiner struct {
	// Don't like adding these into the object but c'est la wasm
	ctx    context.Context
	cancel context.CancelFunc
	miner  *popm.Miner

	wg  sync.WaitGroup
	err error
}

type DispatchArgs struct {
	Name string
	Type js.Type
}

type Dispatch struct {
	Call     func(js.Value, []js.Value) (any, error)
	Required []DispatchArgs
}

func wasmPing(this js.Value, args []js.Value) (any, error) {
	log.Tracef("wasmPing")
	defer log.Tracef("wasmPing exit")

	message := args[0].Get("message").String()
	message += " response"

	return map[string]any{"response": message}, nil
}

func generateKey(this js.Value, args []js.Value) (any, error) {
	log.Tracef("generatekey")
	defer log.Tracef("generatekey exit")

	net := args[0].Get("network").String()
	var (
		btcChainParams *btcchaincfg.Params
		netNormalized  string
	)
	switch net {
	case "devnet", "testnet3", "testnet":
		btcChainParams = &btcchaincfg.TestNet3Params
		netNormalized = "testnet3"
	case "mainnet":
		btcChainParams = &btcchaincfg.MainNetParams
		netNormalized = "mainnet"
	default:
		return nil, fmt.Errorf("invalid network: %v", net)
	}
	privKey, err := dcrsecpk256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secp256k1 private key: %w", err)
	}
	btcAddress, err := btcutil.NewAddressPubKey(privKey.PubKey().SerializeCompressed(),
		btcChainParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create BTC address from public key: %v",
			err)
	}
	hash := btcAddress.AddressPubKeyHash().String()
	ethAddress := ethereum.AddressFromPrivateKey(privKey)

	return map[string]any{
		"ethereumAddress": ethAddress.String(),
		"network":         netNormalized,
		"privateKey":      hex.EncodeToString(privKey.Serialize()),
		"publicKey":       hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
		"publicKeyHash":   hash,
	}, nil
}

func runPopMiner(this js.Value, args []js.Value) (any, error) {
	log.Tracef("runPopMiner")
	defer log.Tracef("runPopMiner exit")

	globalMtx.Lock()
	if pm != nil {
		globalMtx.Unlock()
		return map[string]any{"error": "pop miner already running"}, nil
	}

	// Don't love doing this in mutex but other options are also costly
	pm = &PopMiner{}
	pm.ctx, pm.cancel = context.WithCancel(context.Background())
	cfg := popm.NewDefaultConfig()
	cfg.BTCChainName = args[0].Get("network").String()
	cfg.BTCPrivateKey = args[0].Get("privateKey").String()
	cfg.LogLevel = args[0].Get("logLevel").String() // "popm=TRACE:protocol=TRACE"
	if cfg.LogLevel == "" {
		cfg.LogLevel = "popm=INFO"
	}
	loggo.ConfigureLoggers(cfg.LogLevel)

	switch cfg.BTCChainName {
	case "testnet", "testnet3":
		cfg.BFGWSURL = "wss://testnet.rpc.hemi.network"
		cfg.BTCChainName = "testnet3"
	case "devnet":
		cfg.BFGWSURL = "wss://devnet.rpc.hemi.network"
		cfg.BTCChainName = "testnet3"
	case "local":
		// XXX this should only be enabled with a link flag
		cfg.BFGWSURL = "ws://localhost:8383"
		cfg.BTCChainName = "testnet3"
	case "mainnet":
		cfg.BFGWSURL = "wss://rpc.hemi.network"
	default:
		return map[string]any{"error": "invalid network for pop miner"}, nil
	}
	// We hardcode the route here because we do not want to include another
	// packge thus growing WASM.
	bfgRoute := "/v1/ws/public"
	cfg.BFGWSURL += bfgRoute

	var err error
	pm.miner, err = popm.NewMiner(cfg)
	if err != nil {
		globalMtx.Unlock()
		return nil, fmt.Errorf("failed to create POP miner: %w", err)
	}
	globalMtx.Unlock()

	// launch in background
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		if err := pm.miner.Run(pm.ctx); !errors.Is(err, context.Canceled) {
			globalMtx.Lock()
			defer globalMtx.Unlock()
			pm.err = err // Theoretically this can logic race unless we unset om
		}
	}()

	return map[string]any{"error": ""}, nil
}

func stopPopMiner(this js.Value, args []js.Value) (any, error) {
	log.Tracef("stopPopMiner")
	defer log.Tracef("stopPopMiner exit")

	globalMtx.Lock()
	if pm == nil {
		globalMtx.Unlock()
		return map[string]any{"error": "pop miner not running"}, nil
	}
	oldPM := pm
	pm = nil
	globalMtx.Unlock()
	oldPM.cancel()

	oldPM.wg.Wait()

	var exitError string
	if oldPM.err != nil {
		exitError = oldPM.err.Error()
	}

	return map[string]any{
		"error": exitError,
	}, nil
}

func activePopMiner() (*PopMiner, error) {
	globalMtx.Lock()
	defer globalMtx.Unlock()
	if pm == nil {
		return nil, fmt.Errorf("pop miner not running")
	}
	return pm, nil
}

// toMap converts a bfg response to a map. Errors are also encoded in a map.
func toMap(response any) map[string]any {
	jr, err := json.Marshal(response)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	mr := make(map[string]any, 10)
	err = json.Unmarshal(jr, &mr)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return mr
}

func ping(this js.Value, args []js.Value) (any, error) {
	log.Tracef("ping")
	defer log.Tracef("ping exit")

	activePM, err := activePopMiner()
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	pr, err := activePM.miner.Ping(activePM.ctx, time.Now().Unix())
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}

	return toMap(pr), nil
}

func l2Keystones(this js.Value, args []js.Value) (any, error) {
	log.Tracef("l2Keystones")
	defer log.Tracef("l2Keystones exit")

	c := args[0].Get("numL2Keystones").Int()
	if c < 0 || c > 10 {
		c = 2
	}
	count := uint64(c)

	activePM, err := activePopMiner()
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	pr, err := activePM.miner.L2Keystones(activePM.ctx, count)
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}

	return toMap(pr), nil
}

func bitcoinBalance(this js.Value, args []js.Value) (any, error) {
	log.Tracef("bitcoinBalance")
	defer log.Tracef("bitcoinBalance exit")

	scriptHash := args[0].Get("scriptHash").String()

	activePM, err := activePopMiner()
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	pr, err := activePM.miner.BitcoinBalance(activePM.ctx, scriptHash)
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}

	return toMap(pr), nil
}

func bitcoinInfo(this js.Value, args []js.Value) (any, error) {
	log.Tracef("bitcoinInfo")
	defer log.Tracef("bitcoinInfo exit")

	activePM, err := activePopMiner()
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	pr, err := activePM.miner.BitcoinInfo(activePM.ctx)
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}

	return toMap(pr), nil
}

func bitcoinUTXOs(this js.Value, args []js.Value) (any, error) {
	log.Tracef("bitcoinUTXOs")
	defer log.Tracef("bitcoinUTXOs exit")

	scriptHash := args[0].Get("scriptHash").String()

	activePM, err := activePopMiner()
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	pr, err := activePM.miner.BitcoinUTXOs(activePM.ctx, scriptHash)
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}

	return toMap(pr), nil
}

var (
	log        = loggo.GetLogger("hemiwasm")
	gitVersion = "not set yet"

	// pre connection and control
	CWASMPing     = "wasmping"     // WASM ping
	CGenerateKey  = "generatekey"  // Generate the various key
	CRunPopMiner  = "runpopminer"  // Run pop miner
	CStopPopMiner = "stoppopminer" // Stop pop miner

	// post connection
	CPing           = "ping"           // ping
	CL2Keystones    = "l2Keystones"    // Get L2 keystones
	CBitcoinBalance = "bitcoinBalance" // get balance
	CBitcoinInfo    = "bitcoinInfo"    // bitcoin information
	CBitcoinUTXOs   = "bitcoinUtxos"   // bitcoin UTXOs
	Dispatcher      = map[string]Dispatch{
		CWASMPing: {
			Call: wasmPing,
			Required: []DispatchArgs{
				{Name: "message", Type: js.TypeString},
			},
		},
		CGenerateKey: {
			Call: generateKey,
			Required: []DispatchArgs{
				{Name: "network", Type: js.TypeString},
			},
		},
		CRunPopMiner: {
			Call: runPopMiner,
			Required: []DispatchArgs{
				{Name: "logLevel", Type: js.TypeString},
				{Name: "network", Type: js.TypeString},
				{Name: "privateKey", Type: js.TypeString},
			},
		},
		CStopPopMiner: {
			Call:     stopPopMiner,
			Required: []DispatchArgs{{}},
		},

		// post connection
		CPing: {
			Call: ping,
			Required: []DispatchArgs{
				{Name: "timestamp", Type: js.TypeNumber},
			},
		},
		CL2Keystones: {
			Call: l2Keystones,
			Required: []DispatchArgs{
				{Name: "numL2Keystones", Type: js.TypeNumber},
			},
		},
		CBitcoinBalance: {
			Call: bitcoinBalance,
			Required: []DispatchArgs{
				{Name: "scriptHash", Type: js.TypeString},
			},
		},
		CBitcoinInfo: {
			Call:     bitcoinInfo,
			Required: []DispatchArgs{},
		},
		CBitcoinUTXOs: {
			Call: bitcoinUTXOs,
			Required: []DispatchArgs{
				{Name: "scriptHash", Type: js.TypeString},
			},
		},
	}

	globalMtx sync.Mutex // used to set and unset pm
	pm        *PopMiner
)

func init() {
	loggo.ConfigureLoggers(logLevel)
}

func validateArgs(args []js.Value) (Dispatch, error) {
	// Verify we received a readable command
	var ed Dispatch
	if len(args) != 1 {
		return ed, fmt.Errorf("1 argument expected, got %v", len(args))
	}
	a := args[0]
	if a.Type() != js.TypeObject {
		return ed, fmt.Errorf("expected an object, got: %v", a.Type())
	}
	m := a.Get("method")
	if m.Type() != js.TypeString {
		return ed, fmt.Errorf("expected a string, got: %v", m.Type())
	}
	d, ok := Dispatcher[m.String()]
	if !ok {
		return ed, fmt.Errorf("method not found: %v", m.String())
	}

	// Verify required args
	for k := range d.Required {
		name := d.Required[k].Name
		typ := d.Required[k].Type
		arg := a.Get(name)
		if arg.Type() != typ {
			return d, fmt.Errorf("invalid type %v: got %v want %v",
				name, arg.Type(), typ)
		}
	}
	return d, nil
}

func execute(this js.Value, args []js.Value) any {
	log.Tracef("execute")
	defer log.Tracef("execute exit")

	// Setup promise
	handler := js.FuncOf(func(this js.Value, handlerArgs []js.Value) any {
		resolve := handlerArgs[0]
		reject := handlerArgs[1]

		// Run dispatched call asynchronously
		go func() {
			// This function must always complete a promise.
			var err error
			defer func() {
				if r := recover(); r != nil {
					p := fmt.Sprintf("recovered panic: %v\n%v",
						r, string(debug.Stack()))
					log.Criticalf(p)
					reject.Invoke(js.Global().Get("Error").New(p))
				} else if err != nil {
					reject.Invoke(js.Global().Get("Error").New(err.Error()))
				}
			}()

			// verify args
			var d Dispatch
			d, err = validateArgs(args)
			if err != nil {
				return
			}

			// dispatch sanitized call
			var rv any
			rv, err = d.Call(this, args)
			if err != nil {
				return
			}

			// encode response
			var j []byte
			j, err = json.Marshal(rv)
			if err != nil {
				return
			}
			resolve.Invoke(string(j))
		}()

		// The handler of a Promise doesn't return any value
		return nil
	})
	// Create and return the Promise object
	return js.Global().Get("Promise").New(handler)
}

func dispatch(this js.Value, args []js.Value) any {
	defer func() {
		if r := recover(); r != nil {
			log.Criticalf("recovered panic: %v", r)
			log.Criticalf("%v", string(debug.Stack()))
		}
	}()

	log.Tracef("dispatch")
	defer log.Tracef("dispatch exit")

	rv := execute(this, args)
	if err, ok := rv.(error); ok && err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	return rv
}

func main() {
	log.Tracef("main")
	defer log.Tracef("main exit")

	// Enable function dispatcher
	log.Infof("=== Start of Day ===")
	// Don't use monitorclient.Runtime here because gitVersion is linked in.
	log.Infof("%v version %v compiled with go version %v %v/%v revision %v",
		filepath.Base(os.Args[0]), version, runtime.Version(),
		runtime.GOOS, runtime.GOARCH, gitVersion)
	log.Infof("Logging level : %v", logLevel)

	js.Global().Set("dispatch", js.FuncOf(dispatch))

	<-make(chan bool) // prevents the program from exiting
}
