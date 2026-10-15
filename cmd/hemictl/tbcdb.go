// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
	"github.com/hemilabs/heminetwork/v2/service/tbc"
)

func init() {
	registerCommand("tbcdb", "direct database access (tbcd must not be running)", tbcdbHandler)
}

func tbcdbHandler(pctx context.Context, flags []string) error {
	var (
		s      *tbc.Server
		tbcCfg *tbc.Config
	)

	grp := commandGroup{
		help: "Manipulate the tbcd database directly (tbcd must not be running).",
		commands: map[string]command{
			"scripthashfromaddress": {
				help: "Derive a script hash from a Bitcoin address.",
				args: map[string]argument{
					"address": {required: true, help: "Bitcoin address"},
					"network": {defaultValue: "mainnet", help: "network: mainnet|testnet3|testnet4"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					address := args["address"]
					var (
						err error
						a   btcutil.Address
					)
					switch args["network"] {
					case "testnet3":
						a, err = btcutil.DecodeAddress(address, &chaincfg.TestNet3Params)
					case "testnet4":
						a, err = btcutil.DecodeAddress(address, &chaincfg.TestNet4Params)
					case "mainnet":
						a, err = btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
					default:
						return fmt.Errorf("invalid network: %v", args["network"])
					}
					if err != nil {
						return err
					}
					h, err := txscript.PayToAddrScript(a)
					if err != nil {
						return err
					}
					sh := tbcd.NewScriptHashFromScript(h)
					fmt.Printf("script     : %x\n", h)
					fmt.Printf("script hash: %v\n", sh)
					return nil
				},
			},

			// ---- block headers ----
			"blockheaderbyhash": {
				help: "Print block header for the given block hash.",
				args: map[string]argument{
					"hash": {required: true, help: "block hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					ch, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					bh, height, err := s.BlockHeaderByHash(ctx, *ch)
					if err != nil {
						return fmt.Errorf("block header by hash: %w", err)
					}
					fmt.Printf("hash  : %v\n", bh)
					fmt.Printf("height: %v\n", height)
					return nil
				},
			},
			"blockheaderbest": {
				help: "Print the best (tip) block header hash and height.",
				args: map[string]argument{},
				run: func(ctx context.Context, args map[string]string) error {
					height, bh, err := s.BlockHeaderBest(ctx)
					if err != nil {
						return fmt.Errorf("block header best: %w", err)
					}
					fmt.Printf("hash  : %v\n", bh.BlockHash())
					fmt.Printf("height: %v\n", height)
					return nil
				},
			},
			"blockheadersbyheight": {
				help: "Print all block headers at the given height.",
				args: map[string]argument{
					"height": {required: true, help: "block height (uint64)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					h, err := strconv.ParseUint(args["height"], 10, 64)
					if err != nil {
						return fmt.Errorf("parse height: %w", err)
					}
					bh, err := s.BlockHeadersByHeight(ctx, h)
					if err != nil {
						return fmt.Errorf("block headers by height: %w", err)
					}
					spew.Dump(bh)
					return nil
				},
			},
			"blockheaderbyutxoindex": {
				help: "Print the block header at the current UTXO index tip.",
				args: map[string]argument{},
				run: func(ctx context.Context, args map[string]string) error {
					bh, err := s.BlockHeaderByUtxoIndex(ctx)
					if err != nil {
						return err
					}
					spew.Dump(bh)
					return nil
				},
			},
			"blockheaderbytxindex": {
				help: "Print the block header at the current TX index tip.",
				args: map[string]argument{},
				run: func(ctx context.Context, args map[string]string) error {
					bh, err := s.BlockHeaderByTxIndex(ctx)
					if err != nil {
						return err
					}
					spew.Dump(bh)
					return nil
				},
			},
			"blockheaderbykeystoneindex": {
				help: "Print the block header at the current keystone index tip.",
				args: map[string]argument{},
				run: func(ctx context.Context, args map[string]string) error {
					bh, err := s.BlockHeaderByKeystoneIndex(ctx)
					if err != nil {
						return err
					}
					spew.Config.DisableMethods = true
					spew.Dump(bh)
					return nil
				},
			},

			// ---- blocks ----
			"blockbyhash": {
				help: "Print a full block for the given block hash.",
				args: map[string]argument{
					"hash": {required: true, help: "block hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					ch, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					b, err := s.BlockByHash(ctx, *ch)
					if err != nil {
						return fmt.Errorf("block by hash: %w", err)
					}
					spew.Dump(b)
					return nil
				},
			},
			"blocksmissing": {
				help: "List block hashes that are missing from the database.",
				args: map[string]argument{
					"count": {defaultValue: "0", help: "maximum number of results (0 = default)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					c, err := strconv.ParseInt(args["count"], 10, 32)
					if err != nil {
						return fmt.Errorf("parse uint: %w", err)
					}
					bi, err := s.BlocksMissing(ctx, int(c))
					if err != nil {
						return fmt.Errorf("blocks missing: %w", err)
					}
					for k := range bi {
						fmt.Printf("%v: %v\n", bi[k].Height, bi[k].Hash)
					}
					return nil
				},
			},
			"blockintxindex": {
				help: "Check whether a block is present in the TX index.",
				args: map[string]argument{
					"blkid": {required: true, help: "block hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					blkhash, err := chainhash.NewHashFromStr(args["blkid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					ok, err := s.BlockInTxIndex(ctx, *blkhash)
					if err != nil {
						return fmt.Errorf("block in transaction index: %w", err)
					}
					fmt.Printf("%v\n", ok)
					return nil
				},
			},
			"feesbyblockhash": {
				help: "Print fee information for the block with the given hash.",
				args: map[string]argument{
					"hash": {required: true, help: "block hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					ch, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					rf, err := s.FeesByBlockHash(ctx, *ch)
					if err != nil {
						return fmt.Errorf("fees by hash: %w", err)
					}
					spew.Dump(rf)
					return nil
				},
			},

			// ---- transactions ----
			"blockhashbytxid": {
				help: "Print the block hash that contains the given transaction.",
				args: map[string]argument{
					"txid": {required: true, help: "transaction ID (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chtxid, err := chainhash.NewHashFromStr(args["txid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					bh, _, err := s.BlockHashByTxId(ctx, *chtxid)
					if err != nil {
						return fmt.Errorf("block by txid: %w", err)
					}
					fmt.Printf("%v\n", bh)
					return nil
				},
			},
			"txbyid": {
				help: "Print the transaction with the given ID.",
				args: map[string]argument{
					"txid": {required: true, help: "transaction ID (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chtxid, err := chainhash.NewHashFromStr(args["txid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					tx, err := s.TxById(ctx, *chtxid)
					if err != nil {
						return fmt.Errorf("tx by id: %w", err)
					}
					fmt.Printf("%v\n", spew.Sdump(tx))
					return nil
				},
			},
			"spentoutputsbytxid": {
				help: "Print spent outputs for the given transaction.",
				args: map[string]argument{
					"txid": {required: true, help: "transaction ID (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chtxid, err := chainhash.NewHashFromStr(args["txid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					si, err := s.SpentOutputsByTxId(ctx, *chtxid)
					if err != nil {
						return fmt.Errorf("spent outputs by txid: %w", err)
					}
					for k := range si {
						fmt.Printf("%v\n", si[k])
					}
					return nil
				},
			},

			// ---- script hashes / outpoints ----
			"scripthashbyoutpoint": {
				help: "Print the script hash for the given outpoint (also dumps spent outputs).",
				args: map[string]argument{
					"txid":  {required: true, help: "transaction ID (hex)"},
					"index": {required: true, help: "output index (uint32)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chtxid, err := chainhash.NewHashFromStr(args["txid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					si, err := s.SpentOutputsByTxId(ctx, *chtxid)
					if err != nil {
						return fmt.Errorf("spent outputs by txid: %w", err)
					}
					for k := range si {
						fmt.Printf("%v\n", si[k])
					}
					idx, err := strconv.ParseUint(args["index"], 10, 32)
					if err != nil {
						return err
					}
					txIDBytes := [32]byte(chtxid.CloneBytes())
					op := tbcd.NewOutpoint(txIDBytes, uint32(idx))
					sh, err := s.ScriptHashByOutpoint(ctx, op)
					if err != nil {
						return err
					}
					fmt.Printf("%x\n", sh)
					return nil
				},
			},

			// ---- balances / UTXOs ----
			"balancebyscripthash": {
				help: "Print the confirmed balance for a script hash or address.",
				args: map[string]argument{
					"hash":    {required: true, order: 1, help: "script hash (hex)"},
					"address": {required: true, order: 1, help: "Bitcoin address (testnet3)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					var sh tbcd.ScriptHash
					var err error
					if h := args["hash"]; h != "" {
						sh, err = tbcd.NewScriptHashFromString(h)
						if err != nil {
							return fmt.Errorf("script hash: %w", err)
						}
					} else {
						a, err := btcutil.DecodeAddress(args["address"], &chaincfg.TestNet3Params)
						if err != nil {
							return err
						}
						h, err := txscript.PayToAddrScript(a)
						if err != nil {
							return err
						}
						sh = tbcd.NewScriptHashFromScript(h)
					}
					balance, err := s.BalanceByScriptHash(ctx, sh)
					if err != nil {
						return fmt.Errorf("balance by script hash: %w", err)
					}
					spew.Dump(balance)
					return nil
				},
			},
			"utxosbyscripthash": {
				help: "List UTXOs for a script hash or address.",
				args: map[string]argument{
					"hash":    {required: true, order: 1, help: "script hash (hex)"},
					"address": {required: true, order: 1, help: "Bitcoin address (testnet3)"},
					"count":   {defaultValue: "100", help: "maximum number of UTXOs to return"},
					"start":   {defaultValue: "0", help: "starting offset"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					countNum, err := strconv.ParseUint(args["count"], 10, 64)
					if err != nil {
						return err
					}
					startNum, err := strconv.ParseUint(args["start"], 10, 64)
					if err != nil {
						return err
					}
					var sh tbcd.ScriptHash
					if h := args["hash"]; h != "" {
						sh, err = tbcd.NewScriptHashFromString(h)
						if err != nil {
							return err
						}
					} else {
						a, err := btcutil.DecodeAddress(args["address"], &chaincfg.TestNet3Params)
						if err != nil {
							return err
						}
						script, err := txscript.PayToAddrScript(a)
						if err != nil {
							return err
						}
						sh = tbcd.NewScriptHashFromScript(script)
					}
					utxos, err := s.UtxosByScriptHash(ctx, sh, startNum, countNum)
					if err != nil {
						return fmt.Errorf("utxos by script hash: %w", err)
					}
					var balance uint64
					for k := range utxos {
						fmt.Printf("%v\n", utxos[k])
						balance += utxos[k].Value()
					}
					fmt.Printf("utxos: %v total: %v\n", len(utxos), balance)
					return nil
				},
			},
			"utxosbyscripthashcount": {
				help: "Print the number of UTXOs for the given script hash.",
				args: map[string]argument{
					"hash": {required: true, help: "script hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					sh, err := tbcd.NewScriptHashFromString(args["hash"])
					if err != nil {
						return err
					}
					count, err := s.UtxosByScriptHashCount(ctx, sh)
					if err != nil {
						return err
					}
					fmt.Printf("count: %v\n", count)
					return nil
				},
			},

			// ---- metadata ----
			"metadatadel": {
				help: "Delete a metadata entry by key.",
				args: map[string]argument{
					"key": {required: true, help: "metadata key"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					if err := s.DatabaseMetadataDel(ctx, []byte(args["key"])); err != nil {
						return err
					}
					fmt.Printf("key %v: deleted from metadata\n", args["key"])
					return nil
				},
			},
			"metadataput": {
				help: "Insert or update a metadata entry. Value may be a plain string or 0x-prefixed hex.",
				args: map[string]argument{
					"key":   {required: true, help: "metadata key"},
					"value": {required: true, help: "value (string or 0x-prefixed hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					key := []byte(args["key"])
					value := args["value"]
					if strings.HasPrefix(value, "0x") {
						v, err := hex.DecodeString(value[2:])
						if err != nil {
							return fmt.Errorf("value decode: %w", err)
						}
						if err := s.DatabaseMetadataPut(ctx, key, v); err != nil {
							return err
						}
					} else {
						if err := s.DatabaseMetadataPut(ctx, key, []byte(value)); err != nil {
							return err
						}
					}
					fmt.Printf("value (%v) with key (%v) added to metadata\n", value, args["key"])
					return nil
				},
			},
			"metadataget": {
				help: "Retrieve and print a metadata entry.",
				args: map[string]argument{
					"key": {required: true, help: "metadata key"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					value, err := s.DatabaseMetadataGet(ctx, []byte(args["key"]))
					if err != nil {
						return fmt.Errorf("metadata get: %w", err)
					}
					spew.Dump(value)
					return nil
				},
			},

			// ---- keystones ----
			"keystonesbyheight": {
				help: "Print keystones at the given height and depth.",
				args: map[string]argument{
					"height": {required: true, help: "block height (uint32)"},
					"depth":  {required: true, help: "depth (int)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					h, err := strconv.ParseUint(args["height"], 10, 32)
					if err != nil {
						return fmt.Errorf("parse height: %w", err)
					}
					d, err := strconv.ParseInt(args["depth"], 10, 0)
					if err != nil {
						return fmt.Errorf("parse depth: %w", err)
					}
					kssList, err := s.KeystonesByHeight(ctx, uint32(h), int(d))
					if err != nil {
						return fmt.Errorf("retrieve keystones: %w", err)
					}
					spew.Dump(kssList)
					return nil
				},
			},
			"blockkeystonebyl2keystoneabrevhash": {
				help: "Find the block keystone corresponding to an L2 keystone abbreviated hash.",
				args: map[string]argument{
					"abrevhash": {required: true, help: "L2 keystone abbreviated hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					ch, err := chainhash.NewHashFromStr(args["abrevhash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					keystone, err := s.BlockKeystoneByL2KeystoneAbrevHash(ctx, *ch)
					if err != nil {
						return err
					}
					spew.Dump(keystone)
					return nil
				},
			},
			"keystonesbyblockhash": {
				help: "Print PoP keystones contained in the block with the given hash.",
				args: map[string]argument{
					"blockhash": {required: true, help: "block hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					ch, err := chainhash.NewHashFromStr(args["blockhash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					block, err := s.BlockByHash(ctx, *ch)
					if err != nil {
						return err
					}
					keystones := tbc.BlockKeystones(block)
					for k, keystone := range keystones {
						aPoPTx, err := pop.ParseTransactionL2FromOpReturn(keystone.RawTx)
						if err != nil {
							return fmt.Errorf("tx %v: %w", k, err)
						}
						fmt.Printf("keystone hash %2v: %v\n", k, aPoPTx.L2Keystone.Hash())
					}
					return nil
				},
			},

			// ---- indexing ----
			"syncindexerstohash": {
				help: "Sync all indexers up to the block with the given hash.",
				args: map[string]argument{
					"hash":     {required: true, help: "target block hash (hex)"},
					"maxcache": {help: "override max cached TXs for this run"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					eh, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("parse hash: %w", err)
					}
					if mc := args["maxcache"]; mc != "" {
						v, err := strconv.ParseInt(mc, 10, 0)
						if err != nil {
							return fmt.Errorf("maxCache: %w", err)
						}
						tbcCfg.MaxCachedTxs = int(v)
					}
					if err := s.SyncIndexersToHash(ctx, *eh); err != nil {
						return fmt.Errorf("indexer: %w", err)
					}
					return nil
				},
			},

			// ---- ZK commands ----
			"zkbalancebyscripthash": {
				help: "Print the ZK balance for the given script hash.",
				args: map[string]argument{
					"scripthash": {required: true, help: "script hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					sh, err := tbcd.NewScriptHashFromString(args["scripthash"])
					if err != nil {
						return fmt.Errorf("scripthash: %w", err)
					}
					balance, err := s.ZKBalanceByScriptHash(ctx, sh)
					if err != nil {
						return err
					}
					fmt.Printf("balance: %v\n", balance)
					return nil
				},
			},
			"zkvalueandscriptbyoutpoint": {
				help: "Print value and script for the given outpoint (ZK index).",
				args: map[string]argument{
					"outpoint": {required: true, help: "outpoint in txhash:index format"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					op, err := tbcd.NewOutpointFromString(args["outpoint"])
					if err != nil {
						return fmt.Errorf("outpoint: %w", err)
					}
					value, script, err := s.ZKValueAndScriptByOutpoint(ctx, *op)
					if err != nil {
						return err
					}
					fmt.Printf("value    : %v\n", value)
					fmt.Printf("script   : %x\n", script)
					fmt.Printf("script hash: %v\n", tbcd.NewScriptHashFromScript(script))
					return nil
				},
			},
			"zkspentoutputs": {
				help: "List ZK spent outputs for the given script hash.",
				args: map[string]argument{
					"scripthash": {required: true, help: "script hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					sh, err := tbcd.NewScriptHashFromString(args["scripthash"])
					if err != nil {
						return fmt.Errorf("scripthash: %w", err)
					}
					sos, err := s.ZKSpentOutputs(ctx, sh)
					if err != nil {
						return err
					}
					for _, v := range sos {
						fmt.Printf("script hash            : %v\n", v.ScriptHash)
						fmt.Printf("block height           : %v\n", v.BlockHeight)
						fmt.Printf("block hash             : %v\n", v.BlockHash)
						fmt.Printf("tx id                  : %v\n", v.TxID)
						fmt.Printf("previous outpoint hash : %v\n", v.PrevOutpointHash)
						fmt.Printf("previous outpoint index: %v\n", v.PrevOutpointIndex)
						fmt.Printf("tx in index            : %v\n\n", v.TxInIndex)
					}
					return nil
				},
			},
			"zkspendingoutpoints": {
				help: "List ZK spending outpoints for the given transaction ID.",
				args: map[string]argument{
					"txid": {required: true, help: "transaction ID (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chtxid, err := chainhash.NewHashFromStr(args["txid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					sos, err := s.ZKSpendingOutpoints(ctx, *chtxid)
					if err != nil {
						return err
					}
					for _, v := range sos {
						fmt.Printf("tx id                  : %v\n", v.TxID)
						fmt.Printf("block height           : %v\n", v.BlockHeight)
						fmt.Printf("block hash             : %v\n", v.BlockHash)
						fmt.Printf("vout index             : %v\n", v.VOutIndex)
						if v.SpendingOutpoint != nil {
							fmt.Printf("spending outpoint      : %v:%v\n\n",
								v.SpendingOutpoint.TxID, v.SpendingOutpoint.Index)
						} else {
							fmt.Printf("spending outpoint      : N/A\n\n")
						}
					}
					return nil
				},
			},
			"zkspendableoutputs": {
				help: "List ZK spendable outputs for the given script hash.",
				args: map[string]argument{
					"scripthash": {required: true, help: "script hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					sh, err := tbcd.NewScriptHashFromString(args["scripthash"])
					if err != nil {
						return fmt.Errorf("scripthash: %w", err)
					}
					sos, err := s.ZKSpendableOutputs(ctx, sh)
					if err != nil {
						return err
					}
					for _, v := range sos {
						fmt.Printf("script hash            : %v\n", v.ScriptHash)
						fmt.Printf("block height           : %v\n", v.BlockHeight)
						fmt.Printf("block hash             : %v\n", v.BlockHash)
						fmt.Printf("tx id                  : %v\n", v.TxID)
						fmt.Printf("tx out index           : %v\n\n", v.TxOutIndex)
					}
					return nil
				},
			},

			// ---- ordinal index ----
			"ordinalrangesbyoutpoint": {
				help: "Print sat ranges for the given outpoint.",
				args: map[string]argument{
					"txid":  {required: true, help: "transaction ID (hex)"},
					"index": {required: true, help: "output index (uint32)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chtxid, err := chainhash.NewHashFromStr(args["txid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					idx, err := strconv.ParseUint(args["index"], 10, 32)
					if err != nil {
						return err
					}
					ranges, err := s.SatRangesByOutpoint(ctx, *chtxid, uint32(idx))
					if err != nil {
						return fmt.Errorf("sat ranges: %w", err)
					}
					for _, r := range ranges {
						fmt.Printf("start: %-20d count: %d\n", r.Start, r.Count)
					}
					return nil
				},
			},
			"ordinalinscriptionbyid": {
				help: "Print the inscription at the given transaction input.",
				args: map[string]argument{
					"txid":  {required: true, help: "transaction ID (hex)"},
					"index": {defaultValue: "0", help: "input index (uint32)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chtxid, err := chainhash.NewHashFromStr(args["txid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					idx, err := strconv.ParseUint(args["index"], 10, 32)
					if err != nil {
						return err
					}
					insc, err := s.InscriptionByID(ctx, *chtxid, uint32(idx), false)
					if err != nil {
						return fmt.Errorf("inscription: %w", err)
					}
					fmt.Printf("%v\n", spew.Sdump(insc))
					return nil
				},
			},
			"ordinalinscriptioncontent": {
				help: "Print the content type and content of an inscription.",
				args: map[string]argument{
					"txid":  {required: true, help: "transaction ID (hex)"},
					"index": {defaultValue: "0", help: "input index (uint32)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chtxid, err := chainhash.NewHashFromStr(args["txid"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					idx, err := strconv.ParseUint(args["index"], 10, 32)
					if err != nil {
						return err
					}
					contentType, content, err := s.InscriptionContent(ctx, *chtxid, uint32(idx))
					if err != nil {
						return fmt.Errorf("inscription content: %w", err)
					}
					fmt.Printf("content type: %s\n", contentType)
					fmt.Printf("content     : %x\n", content)
					return nil
				},
			},
			"ordinalinscriptionsbyblock": {
				help: "List inscriptions contained in the block with the given hash.",
				args: map[string]argument{
					"hash": {required: true, help: "block hash (hex)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					chhash, err := chainhash.NewHashFromStr(args["hash"])
					if err != nil {
						return fmt.Errorf("chainhash: %w", err)
					}
					inscriptions, err := s.InscriptionsByBlock(ctx, *chhash, false)
					if err != nil {
						return fmt.Errorf("inscriptions by block: %w", err)
					}
					for _, insc := range inscriptions {
						fmt.Printf("txid       : %v\n", insc.TxID)
						fmt.Printf("input index: %d\n", insc.InputIndex)
						fmt.Printf("sat number : %d\n", insc.SatNumber)
						fmt.Printf("cursed     : %v\n\n", insc.Cursed)
					}
					fmt.Printf("total: %d\n", len(inscriptions))
					return nil
				},
			},
			"ordinalinscriptionsbysat": {
				help: "List inscriptions on the given sat number.",
				args: map[string]argument{
					"sat": {required: true, help: "sat number (uint64)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					satNumber, err := strconv.ParseUint(args["sat"], 10, 64)
					if err != nil {
						return fmt.Errorf("sat: %w", err)
					}
					inscriptions, err := s.InscriptionsBySat(ctx, satNumber)
					if err != nil {
						return fmt.Errorf("inscriptions by sat: %w", err)
					}
					for _, insc := range inscriptions {
						fmt.Printf("txid       : %v\n", insc.TxID)
						fmt.Printf("input index: %d\n", insc.InputIndex)
						fmt.Printf("sat number : %d\n", insc.SatNumber)
						fmt.Printf("cursed     : %v\n\n", insc.Cursed)
					}
					fmt.Printf("total: %d\n", len(inscriptions))
					return nil
				},
			},
			"ordinalinscriptionsbyaddress": {
				help: "List inscriptions owned by the given address.",
				args: map[string]argument{
					"address": {required: true, help: "Bitcoin address"},
					"start":   {defaultValue: "0", help: "starting offset"},
					"count":   {defaultValue: "0", help: "maximum number of results (0 = default)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					start, err := strconv.ParseUint(args["start"], 10, 32)
					if err != nil {
						return fmt.Errorf("start: %w", err)
					}
					count, err := strconv.ParseUint(args["count"], 10, 32)
					if err != nil {
						return fmt.Errorf("count: %w", err)
					}
					inscriptions, err := s.InscriptionsByAddress(ctx, args["address"], uint32(start), uint32(count), false)
					if err != nil {
						return fmt.Errorf("inscriptions by address: %w", err)
					}
					for _, insc := range inscriptions {
						fmt.Printf("txid       : %v\n", insc.TxID)
						fmt.Printf("input index: %d\n", insc.InputIndex)
						fmt.Printf("sat number : %d\n", insc.SatNumber)
						fmt.Printf("cursed     : %v\n\n", insc.Cursed)
					}
					fmt.Printf("total: %d\n", len(inscriptions))
					return nil
				},
			},

			// ---- other ----
			"version": {
				help: "Print the database version.",
				args: map[string]argument{},
				run: func(ctx context.Context, args map[string]string) error {
					ver, err := s.DatabaseVersion(ctx)
					if err != nil {
						return fmt.Errorf("version: %w", err)
					}
					fmt.Printf("database version: %v\n", ver)
					return nil
				},
			},
			"dumpmetadata": {
				help: "Dump all metadata entries (not yet implemented).",
				args: map[string]argument{},
				run: func(ctx context.Context, args map[string]string) error {
					return errors.New("fixme dumpmetadata")
				},
			},
			"dumpoutputs": {
				help: "Dump raw output entries (not yet implemented).",
				args: map[string]argument{
					"prefix": {help: "single-byte prefix filter (h or u)"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					return errors.New("fixme dumpoutputs")
				},
			},
		},
	}

	fs := flag.NewFlagSet("tbcdb", flag.ExitOnError)
	debugFlag := fs.Bool("debug", false, "enable debug database access (required for certain actions)")
	helpShort := fs.Bool("h", false, "display help")
	helpLong := fs.Bool("help", false, "display help")
	fs.Usage = func() { printGroupHelp("tbcdb", grp) }
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(flags) == 0 || *helpShort || *helpLong {
		printGroupHelp("tbcdb", grp)
		return nil
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	level.Welcome = false
	tbc.Welcome = false
	tbcCfg = tbc.NewDefaultConfig()
	tbcCfg.LevelDBHome = leveldbHome
	tbcCfg.Network = network
	tbcCfg.DatabaseDebug = *debugFlag
	tbcCfg.PeersWanted = 0         // disable peer manager
	tbcCfg.ListenAddress = ""      // disable RPC
	tbcCfg.UtxoReadCacheSize = "0" // hemictl doesn't need read cache
	tbcCfg.BlockCacheSize = "64mb" // smaller for CLI
	tbcCfg.HeaderCacheSize = "1mb" // smaller for CLI
	if len(fs.Args()) > 0 && strings.HasPrefix(fs.Args()[0], "ordinal") {
		tbcCfg.OrdinalIndex = true
	}

	var err error
	s, err = tbc.NewServer(tbcCfg)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}
	go func() {
		if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Errorf("tbc server: %v", err)
		}
	}()
	for !s.Running() {
		time.Sleep(time.Millisecond)
	}

	return dispatchGroup(ctx, grp, "tbcdb", fs.Args())
}
