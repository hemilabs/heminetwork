// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/v2/service/tbc/peer"
)

// p2pCommonArgs are shared by all p2p commands.
var p2pCommonArgs = map[string]argument{
	"addr":    {required: true, help: "remote node address (host:port)"},
	"net":     {defaultValue: "testnet3", help: "bitcoin network: mainnet|testnet|testnet3|testnet4"},
	"timeout": {defaultValue: "30s", help: "connection timeout (duration)"},
	"out":     {defaultValue: "spew", help: "output format: json|raw|spew"},
}

// mergeArgs returns a new map containing all entries from all provided maps.
func mergeArgs(sets ...map[string]argument) map[string]argument {
	result := make(map[string]argument)
	for _, s := range sets {
		maps.Copy(result, s)
	}
	return result
}

// p2pConnect creates and connects a peer using parsed args.
// The caller is responsible for calling cancel() and cp.Close().
func p2pConnect(ctx context.Context, args map[string]string) (*peer.Peer, context.CancelFunc, error) {
	var network wire.BitcoinNet
	switch args["net"] {
	case "mainnet":
		network = wire.MainNet
	case "testnet":
		network = wire.TestNet
	case "", "testnet3":
		network = wire.TestNet3
	case "testnet4":
		network = wire.TestNet4
	default:
		return nil, nil, fmt.Errorf("invalid net: %v", args["net"])
	}

	timeout, err := time.ParseDuration(args["timeout"])
	if err != nil {
		return nil, nil, fmt.Errorf("timeout: %w", err)
	}

	cp, err := peer.New(network, 0xc0ffee, args["addr"])
	if err != nil {
		return nil, nil, err
	}

	tctx, cancel := context.WithTimeout(ctx, timeout)
	if err = cp.Connect(tctx); err != nil {
		cancel()
		return nil, nil, err
	}
	return cp, cancel, nil
}

// p2pOutput writes a wire.Message in the requested format.
func p2pOutput(out string, msg wire.Message) error {
	switch out {
	case "json":
		j, err := json.MarshalIndent(msg, "", "  ")
		if err != nil {
			return fmt.Errorf("json: %w", err)
		}
		fmt.Printf("%v\n", string(j))
	case "", "spew":
		spew.Dump(msg)
	case "raw":
		if err := msg.BtcEncode(bufio.NewWriter(os.Stdout), wire.ProtocolVersion, wire.LatestEncoding); err != nil {
			return fmt.Errorf("raw: %w", err)
		}
	default:
		return fmt.Errorf("invalid out: %v", out)
	}
	return nil
}

func init() {
	registerCommand("p2p", "Bitcoin P2P commands", p2pHandler)
}

func p2pHandler(pctx context.Context, flags []string) error {
	grp := commandGroup{
		help: "Issue commands directly to a Bitcoin P2P peer.",
		commands: map[string]command{
			"feefilter": {
				help: "Return the fee filter advertised by the remote peer.",
				args: mergeArgs(p2pCommonArgs),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					var msg wire.Message
					for range 10 {
						time.Sleep(100 * time.Millisecond)
						msg, err = cp.FeeFilter()
						if err != nil {
							continue
						}
					}
					if msg == nil {
						return fmt.Errorf("fee filter: %w", err)
					}
					return p2pOutput(args["out"], msg)
				},
			},
			"getaddr": {
				help: "Retrieve address list from the remote peer.",
				args: mergeArgs(p2pCommonArgs),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					a, err := cp.GetAddr(ctx)
					if err != nil {
						return fmt.Errorf("get addr: %w", err)
					}
					var msg wire.Message
					switch m := a.(type) {
					case *wire.MsgAddr:
						msg = m
					case *wire.MsgAddrV2:
						msg = m
					default:
						return fmt.Errorf("invalid get addr type: %T", a)
					}
					return p2pOutput(args["out"], msg)
				},
			},
			"getblock": {
				help: "Retrieve a full block from the remote peer.",
				args: mergeArgs(p2pCommonArgs, map[string]argument{
					"hash": {required: true, help: "block hash (hex)"},
				}),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					ch, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					msg, err := cp.GetBlock(ctx, ch)
					if err != nil {
						return fmt.Errorf("get block: %w", err)
					}
					return p2pOutput(args["out"], msg)
				},
			},
			"getdata": {
				help: "Retrieve a transaction or block by inventory vector.",
				args: mergeArgs(p2pCommonArgs, map[string]argument{
					"hash": {required: true, help: "hash (hex)"},
					"type": {required: true, help: "inventory type: tx|block"},
				}),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					var typ wire.InvType
					switch args["type"] {
					case "tx":
						typ = wire.InvTypeTx
					case "block":
						typ = wire.InvTypeBlock
					default:
						return fmt.Errorf("invalid type: %v", args["type"])
					}
					ch, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					gd, err := cp.GetData(ctx, wire.NewInvVect(typ, ch))
					if err != nil {
						return fmt.Errorf("get data: %w", err)
					}
					var msg wire.Message
					switch m := gd.(type) {
					case *wire.MsgBlock:
						msg = m
					case *wire.MsgTx:
						msg = m
					case *wire.MsgNotFound:
						msg = m
					}
					return p2pOutput(args["out"], msg)
				},
			},
			"getheaders": {
				help: "Retrieve up to 2000 headers from the given hash.",
				args: mergeArgs(p2pCommonArgs, map[string]argument{
					"hash": {required: true, help: "starting block hash (hex)"},
				}),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					ch, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					msg, err := cp.GetHeaders(ctx, []*chainhash.Hash{ch}, nil)
					if err != nil {
						return fmt.Errorf("get headers: %w", err)
					}
					return p2pOutput(args["out"], msg)
				},
			},
			"gettx": {
				help: "Retrieve a mempool transaction from the remote peer.",
				args: mergeArgs(p2pCommonArgs, map[string]argument{
					"hash": {required: true, help: "transaction hash (hex)"},
				}),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					ch, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					msg, err := cp.GetTx(ctx, ch)
					if err != nil {
						return fmt.Errorf("get tx: %w", err)
					}
					return p2pOutput(args["out"], msg)
				},
			},
			"mempool": {
				help: "Retrieve the remote peer's mempool (slow; not always enabled).",
				args: mergeArgs(p2pCommonArgs),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					msg, err := cp.MemPool(ctx)
					if err != nil {
						return fmt.Errorf("mempool: %w", err)
					}
					return p2pOutput(args["out"], msg)
				},
			},
			"ping": {
				help: "Ping a remote node with a nonce and print the response.",
				args: mergeArgs(p2pCommonArgs, map[string]argument{
					"nonce": {defaultValue: "0", help: "ping nonce (uint64)"},
				}),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					n, err := strconv.ParseUint(args["nonce"], 10, 64)
					if err != nil {
						return fmt.Errorf("nonce: %w", err)
					}
					msg, err := cp.Ping(ctx, n)
					if err != nil {
						return fmt.Errorf("ping: %w", err)
					}
					return p2pOutput(args["out"], msg)
				},
			},
			"remote": {
				help: "Print the version message received from the remote peer.",
				args: mergeArgs(p2pCommonArgs),
				run: func(ctx context.Context, args map[string]string) error {
					cp, cancel, err := p2pConnect(ctx, args)
					if err != nil {
						return err
					}
					defer cancel()
					defer cp.Close()

					msg, err := cp.Remote()
					if err != nil {
						return fmt.Errorf("remote: %w", err)
					}
					return p2pOutput(args["out"], msg)
				},
			},
		},
	}

	fs := flag.NewFlagSet("p2p", flag.ExitOnError)
	helpShort := fs.Bool("h", false, "display help")
	helpLong := fs.Bool("help", false, "display help")
	fs.Usage = func() { printGroupHelp("p2p", grp) }
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(flags) == 0 || *helpShort || *helpLong {
		fs.Usage()
		return nil
	}

	return dispatchGroup(pctx, grp, "p2p", fs.Args())
}
