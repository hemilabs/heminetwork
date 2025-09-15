// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

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
		return balance, nil
	}

	// Not found in cache, fetch from db
	var balance [8]byte
	b, err := i.g.db.ZKBalanceByScriptHash(ctx, ss)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return balance[:], nil
		}
		return nil, err
	}
	binary.BigEndian.PutUint64(balance[:], b)
	return balance[:], nil
}

func (i *zkutxoIndexer) script(ctx context.Context, pop tbcd.Outpoint, c indexerCache) ([]byte, error) {
	cache := c.(*Cache[tbcd.ZKUtxoKey, []byte]).Map()
	if script, ok := cache[tbcd.ZKUtxoKey(pop[:])]; ok {
		return script, nil
	}
	// Not found in cache, fetch from db
	script, err := i.g.db.ZKScriptByOutpoint(ctx, pop)
	if err != nil {
		return nil, err
	}
	return script, err
}

func (i *zkutxoIndexer) value(ctx context.Context, pop tbcd.Outpoint, c indexerCache) (uint64, error) {
	// XXX DONT DO THIS
	// LIFT THIS FROM THE "utxo bits" cache, see processing TxOut
	prevTxOut, err := txOutFromOutPoint(ctx, i.g.db, pop)
	if err != nil {
		return 0, fmt.Errorf("fetch outpoint: %w", err)
	}
	return uint64(prevTxOut.Value), nil
}

func (i *zkutxoIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	cache := c.(*Cache[tbcd.ZKUtxoKey, []byte]).Map()

	blockHash := block.Hash()
	log.Infof("process: %v", blockHash)
	blockHeight := uint32(block.Height())
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
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				continue
			}
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
			value, err := i.value(ctx, pop, c)
			if err != nil {
				panic(err)
			}
			cache[tbcd.ZKUtxoKey(ss[:])] = tbcd.BESubUint64(balance, value)

			// Insert spend
			ui := tbcd.NewZKUtxoIn(chainhash.Hash(ss), blockHeight,
				*blockHash, *txId, txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index, uint32(txInIdx))
			cache[tbcd.ZKUtxoKey(ui[:])] = tbcd.BEUint64(value)

			// 1 record spending outpoint
			// tsk := tbcd.NewTxSpendKey(txIn.PreviousOutPoint.Hash,
			//	blockHeight, *blockHash, txIn.PreviousOutPoint.Index)
			// cache[tbcd.ZKUtxoKey(tsk)] = tbcd.NewPointSlice(*txId,
			//	uint32(txInIdx))

			// 2 record SpendScript Value
			// 2.1 Fish out Value from map/db
			//pop := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
			//	txIn.PreviousOutPoint.Index)
			//if pkScript, ok := cache[tbcd.ZKUtxoKey(pop[:])]; ok {
			//} else {
			//	// 2.2 fix out of db
			//}

			// ZKUtxoKey sha256(txin.PreviousOutPoint->pkscript),
			// blockHeight, blockHash, txId,
			// txIn.PreviousOutPoint.Hash,
			// txIn.PreviousOutPoint.Index, txInIdx
			// balance -= outputvalue that txIn.PreviousOutPoint is pointing to

			// fetch prevPkScript
			//op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
			//	txIn.PreviousOutPoint.Index)
			//prevPkScript, err := i.g.db.ScriptHashByOutpoint(ctx, op)
			//if err != nil {
			//	// This happens when a transaction is created
			//	// and spent in the same block.
			//	log.Infof("db missing pkscript: %v", op)
			//	log.Infof("txid %v : %v", txInIdx, txId)
			//	log.Infof("%v", err)
			//	panic("this needs fixing")
			//}

			// the balance must come out of the map first, if it doesnt exist, get of disk
			// [sha256(pkscript)]->[running balance] // - txOut.Value
		}

		for txOutIdx, txOut := range tx.MsgTx().TxOut {
			// ZKUtxoKey = sha256(txOut.PkScript), blockHeight, blockHash,
			// txId, txOutIdx
			// balance = txOut.Value

			// utxo bits
			ss := tbcd.NewScriptHashFromScript(txOut.PkScript)
			o := tbcd.NewZKUtxoOut(chainhash.Hash(ss), blockHeight,
				*blockHash, *txId)
			cache[tbcd.ZKUtxoKey(o[:])] = tbcd.BEUint64(uint64(txOut.Value))

			// Add tx outpoint to script mapping. Doesn't matter if
			// we overwritte the same key.
			// If we need to compress PkScript use sha256 of
			// PkScript.
			// [txid:txOutIdx]->[pkscript]
			op := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
			cache[tbcd.ZKUtxoKey(op[:])] = txOut.PkScript
			// log.Infof("adding mapping %v -> %x", op, sha256.Sum256(txOut.PkScript))

			// Fetch current balance of PkScript hash.
			balance, err := i.runningBalance(ctx, ss, c)
			if err != nil {
				log.Infof("op: %v", op)
				panic(err)
			}
			cache[tbcd.ZKUtxoKey(ss[:])] = tbcd.BEAddUint64(balance,
				uint64(txOut.Value))

			//// the balance must come out of the map first, if it
			//// doesnt exist, get of disk
			////
			//// if nil then it's the very first balance update
			//// [sha256(pkscript)]->[running balance] // + txOut.Value
			//sh := tbcd.NewScriptHashFromScript(txOut.PkScript)
			//if _, ok := cache[tbcd.ZKUtxoKey(sh[:])]; ok {
			//	cache[tbcd.ZKUtxoKey(sh)] += txOut.Value
			//} else {
			//	panic("find in db")
			//	// if not in db -> new
			//}

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
