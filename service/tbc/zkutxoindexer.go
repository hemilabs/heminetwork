// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// Transactions to be looked up by txid.

type zkutxoIndexer struct {
	indexerCommon

	cacheCapacity int
}

var (
	_ Indexer = (*zkutxoIndexer)(nil)
	_ indexer = (*zkutxoIndexer)(nil)
)

func NewZKUtxoIndexer(g geometryParams, cacheLen int, enabled bool) Indexer {
	zi := &zkutxoIndexer{
		cacheCapacity: cacheLen,
	}
	zi.indexerCommon = indexerCommon{
		name:    "zkutxo",
		enabled: enabled,
		g:       g,
		p:       zi,
	}
	return zi
}

func (i *zkutxoIndexer) newCache() indexerCache {
	return NewCache[tbcd.ZKUtxoKey, []byte](i.cacheCapacity)
}

func (i *zkutxoIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByZKUtxoIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

func (i *zkutxoIndexer) runningBalance(ctx context.Context, ss tbcd.ScriptHash, c indexerCache) ([]byte, error) {
	cache := c.(*Cache[tbcd.ZKUtxoKey, []byte]).Map()
	if balance, ok := cache[tbcd.ZKUtxoKey(ss[:])]; ok {
		// log.Infof("balance %v %x", ss, balance)
		return balance, nil
	}

	// Not found in cache, fetch from db
	var balance [8]byte
	b, err := i.g.db.ZKBalanceByScriptHash(ctx, ss)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			// log.Infof("balance 0 %v %x", ss, balance)
			return balance[:], nil
		}
		return nil, err
	}
	binary.BigEndian.PutUint64(balance[:], b)
	// log.Infof("balance db %v %v", ss, balance)
	return balance[:], nil
}

func (i *zkutxoIndexer) script(ctx context.Context, pop tbcd.Outpoint, c indexerCache) ([]byte, error) {
	// XXX combine with i.value
	cache := c.(*Cache[tbcd.ZKUtxoKey, []byte]).Map()
	if utxoE, ok := cache[tbcd.ZKUtxoKey(pop[:])]; ok {
		txOut := tbcd.TxOutFromBytes(utxoE)
		return txOut.PkScript, nil
	}
	// Not found in cache, fetch from db
	script, err := i.g.db.ZKScriptByOutpoint(ctx, pop)
	if err != nil {
		return nil, err
	}
	return script[8:], err
}

func (i *zkutxoIndexer) value(ctx context.Context, pop tbcd.Outpoint, c indexerCache) (uint64, error) {
	// XXX combine with i.script
	cache := c.(*Cache[tbcd.ZKUtxoKey, []byte]).Map()
	if utxoE, ok := cache[tbcd.ZKUtxoKey(pop[:])]; ok {
		txOut := tbcd.TxOutFromBytes(utxoE)
		// log.Infof("value from pop %v", txOut.Value)
		return uint64(txOut.Value), nil
	}
	// XXX DONT DO THIS
	// LIFT THIS FROM THE "utxo bits" cache, see processing TxOut
	prevTxOut, err := txOutFromOutPoint(ctx, i.g.db, pop)
	if err != nil {
		// log.Infof("value from db new %v", pop)
		return 0, fmt.Errorf("fetch outpoint: %w", err)
	}
	// log.Infof("value from db no error %v", prevTxOut.Value)
	return uint64(prevTxOut.Value), nil
}

func (i *zkutxoIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	cache := c.(*Cache[tbcd.ZKUtxoKey, []byte]).Map()

	blockHash := block.Hash()
	blockHeight := uint32(block.Height())
	log.Infof("process: %v %v", blockHeight, blockHash)
	for _, tx := range block.Transactions() {
		// Every TxIn and TxOut journals three pieces of information.
		// 1. TxID to block height and hash mapping that stores spend info.
		// 2. SpendScript at block height hash and additional key
		//    material that stores TxOut.Value.
		// 3. Outpoint to PkScript mapping.
		//
		// In addition a running balance is kept for SpendScript.

		txId := tx.Hash()
		for txInIdx, txIn := range tx.MsgTx().TxIn {
			// Skip coinbase inputs
			if blockchain.IsCoinBase(tx) {
				continue
			}

			// Recreate Outpoint from TxIn.PreviousOutPoint
			pop := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			script, err := i.script(ctx, pop, c)
			if err != nil {
				panic(err)
			}
			ss := tbcd.NewScriptHashFromScript(script)
			balance, err := i.runningBalance(ctx, ss, c)
			if err != nil {
				panic(err)
			}
			// Fetch previous value
			value, err := i.value(ctx, pop, c) // XXX rename?
			if err != nil {
				panic(err)
			}
			cache[tbcd.ZKUtxoKey(ss[:])] = tbcd.BESubUint64(balance, value)

			// Insert spend
			ui := tbcd.NewZKUtxoIn(chainhash.Hash(ss), blockHeight,
				*blockHash, *txId, txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index, uint32(txInIdx))
			if _, ok := cache[tbcd.ZKUtxoKey(ui[:])]; ok {
				panic(fmt.Sprintf("diagnostic: %v", ui))
			}
			cache[tbcd.ZKUtxoKey(ui[:])] = tbcd.BEUint64(value)
		}

		for txOutIdx, txOut := range tx.MsgTx().TxOut {
			// Skip unspendables.
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}

			// utxo bits
			ss := tbcd.NewScriptHashFromScript(txOut.PkScript)
			o := tbcd.NewZKUtxoOut(chainhash.Hash(ss), blockHeight,
				*blockHash, *txId)
			if _, ok := cache[tbcd.ZKUtxoKey(o[:])]; ok {
				// XXX @max is this right?
				// panic: diagnostic: sh 4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260 height 25200 block 0000000000000067674a7a4b0787a9e54a21f05b1339f59e5a22af07e22ac7d6 tx 056aad3e8616785f6abc70cc8e0f089907126ac81634abde4399fdf7a69eb4c0
				// this can only work if we dont store value or make it cumulative? do we need to add txOutIdx?
				// panic(fmt.Sprintf("diagnostic: %v", o.Pretty()))
			}
			cache[tbcd.ZKUtxoKey(o[:])] = tbcd.BEUint64(uint64(txOut.Value))

			op := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
			txOutEncoded := tbcd.NewTxOut(txOut)
			if _, ok := cache[tbcd.ZKUtxoKey(op[:])]; ok {
				panic(fmt.Sprintf("diagnostic: %v", op))
			}
			txOutDecoded := tbcd.TxOutFromBytes(txOutEncoded)
			if !reflect.DeepEqual(txOutDecoded, *txOut) {
				spew.Dump(txOutDecoded)
				spew.Dump(*txOut)
				panic("x")
			}
			cache[tbcd.ZKUtxoKey(op[:])] = txOutEncoded

			// Fetch current balance of PkScript hash.
			balance, err := i.runningBalance(ctx, ss, c)
			if err != nil {
				log.Infof("op: %v", op)
				panic(err)
			}
			cache[tbcd.ZKUtxoKey(ss[:])] = tbcd.BEAddUint64(balance,
				uint64(txOut.Value))
		}
	}

	return nil
}

func (i *zkutxoIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[tbcd.ZKUtxoKey, []byte])
	return i.g.db.BlockZKUtxoUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *zkutxoIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk indexer.
	return nil
}
