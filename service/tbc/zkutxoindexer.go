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
	"github.com/btcsuite/btcd/txscript"

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
	return NewCache[tbcd.ZKIndexKey, []byte](i.cacheCapacity)
}

func (i *zkutxoIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByZKUtxoIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

func (i *zkutxoIndexer) balance(ctx context.Context, ss tbcd.ScriptHash, c indexerCache) ([]byte, error) {
	cache := c.(*Cache[tbcd.ZKIndexKey, []byte]).Map()
	if balance, ok := cache[tbcd.ZKIndexKey(ss[:])]; ok {
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

func (i *zkutxoIndexer) txOut(ctx context.Context, pop tbcd.Outpoint, c indexerCache) (uint64, []byte, error) {
	cache := c.(*Cache[tbcd.ZKIndexKey, []byte]).Map()
	if utxoE, ok := cache[tbcd.ZKIndexKey(pop[:])]; ok {
		txOut := tbcd.TxOutFromBytes(utxoE)
		return uint64(txOut.Value), txOut.PkScript, nil
	}
	// Not found in cache, fetch from db
	txOut, err := i.g.db.ZKScriptByOutpoint(ctx, pop) // Rename
	if err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint64(txOut[0:]), txOut[8:], nil
}

func (i *zkutxoIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	cache := c.(*Cache[tbcd.ZKIndexKey, []byte]).Map()

	blockHash := block.Hash()
	blockHeight := uint32(block.Height())
	log.Tracef("processing: %v %v", blockHeight, blockHash)
	for _, tx := range block.Transactions() {
		txId := tx.Hash()
		for txInIdx, txIn := range tx.MsgTx().TxIn {
			// Skip coinbase inputs
			if blockchain.IsCoinBase(tx) {
				continue
			}

			// Recreate Outpoint from TxIn.PreviousOutPoint
			pop := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)

			// Retrieve TxOut from PreviousOutPoint
			value, script, err := i.txOut(ctx, pop, c)
			if err != nil {
				fmt.Errorf("tx out: %w", err)
			}

			// Retrieve balance
			sh := tbcd.NewScriptHashFromScript(script)
			balance, err := i.balance(ctx, sh, c)
			if err != nil {
				fmt.Errorf("balance in: %w", err)
			}

			// Handle balance
			switch direction {
			case 1:
				cache[tbcd.ZKIndexKey(sh[:])] = tbcd.BESubUint64(balance,
					value)
			case -1:
				cache[tbcd.ZKIndexKey(sh[:])] = tbcd.BEAddUint64(balance,
					value)
			default:
				panic("wtf")
			}

			// Insert SpentOutput
			spo := tbcd.NewSpentOutput(chainhash.Hash(sh), blockHeight,
				*blockHash, *txId, txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index, uint32(txInIdx))
			if _, ok := cache[tbcd.ZKIndexKey(spo[:])]; ok {
				panic(fmt.Sprintf("diagnostic: %v", spo))
			}
			cache[tbcd.ZKIndexKey(spo[:])] = nil

			// Mark UTxO spent and point where it was spent
			// XXX max what about this one?
			tsk := tbcd.NewTxSpendKey(txIn.PreviousOutPoint.Hash,
				blockHeight, *blockHash, txIn.PreviousOutPoint.Index)
			cache[tbcd.ZKIndexKey(tsk[:])] = tbcd.NewPointSlice(*txId,
				uint32(txInIdx))
		}

		for txOutIdx, txOut := range tx.MsgTx().TxOut {
			// Skip unspendables.
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}

			// SpendableOutput
			sh := tbcd.NewScriptHashFromScript(txOut.PkScript)
			so := tbcd.NewSpendableOutput(chainhash.Hash(sh), blockHeight,
				*blockHash, *txId)
			cache[tbcd.ZKIndexKey(so[:])] = nil

			// Outpoint to TxOut
			op := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
			if _, ok := cache[tbcd.ZKIndexKey(op[:])]; ok {
				panic(fmt.Sprintf("diagnostic: %v", op))
			}
			cache[tbcd.ZKIndexKey(op[:])] = tbcd.NewTxOut(txOut)

			// Fetch current balance of PkScript hash.
			balance, err := i.balance(ctx, sh, c)
			if err != nil {
				fmt.Errorf("balance out: %w", err)
			}
			switch direction {
			case 1:
				cache[tbcd.ZKIndexKey(sh[:])] = tbcd.BEAddUint64(balance,
					uint64(txOut.Value))
			case -1:
				cache[tbcd.ZKIndexKey(sh[:])] = tbcd.BESubUint64(balance,
					uint64(txOut.Value))
			default:
				panic("wtf")
			}

			// Spendable UTxO XXX max do we need this?
			tsk := tbcd.NewTxSpendKey(*txId, blockHeight, *blockHash,
				uint32(txOutIdx))
			cache[tbcd.ZKIndexKey(tsk[:])] = nil
		}
	}

	return nil
}

func (i *zkutxoIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[tbcd.ZKIndexKey, []byte])
	return i.g.db.BlockZKUtxoUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *zkutxoIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk indexer.
	return nil
}
