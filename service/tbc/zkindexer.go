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

type zkIndexer struct {
	indexerCommon

	cacheCapacity int
}

var (
	_ Indexer = (*zkIndexer)(nil)
	_ indexer = (*zkIndexer)(nil)
)

func NewZKIndexer(g geometryParams, cacheLen int, enabled bool) Indexer {
	zi := &zkIndexer{
		cacheCapacity: cacheLen,
	}
	zi.indexerCommon = indexerCommon{
		name:    "zkindexer",
		enabled: enabled,
		g:       g,
		p:       zi,
	}
	return zi
}

func (i *zkIndexer) newCache() indexerCache {
	return NewCache[tbcd.ZKIndexKey, []byte](i.cacheCapacity)
}

func (i *zkIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByZKIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

func (i *zkIndexer) balance(ctx context.Context, ss tbcd.ScriptHash, c indexerCache) ([]byte, error) {
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

func (i *zkIndexer) txOut(ctx context.Context, pop tbcd.Outpoint, c indexerCache) (uint64, []byte, error) {
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

func (i *zkIndexer) processTx(ctx context.Context, direction int, blockHeight uint32, blockHash *chainhash.Hash, tx *btcutil.Tx, c indexerCache) error {
	cache := c.(*Cache[tbcd.ZKIndexKey, []byte]).Map()
	txId := tx.Hash()
	log.Infof("tx %v", tx.Hash())
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
			return fmt.Errorf("tx out: %w", err)
		}

		// Retrieve balance
		sh := tbcd.NewScriptHashFromScript(script)
		balance, err := i.balance(ctx, sh, c)
		if err != nil {
			return fmt.Errorf("balance in: %w", err)
		}
		log.Infof("in pop %v value %v sh %v script %x", pop, value, sh, script)

		// Handle balance
		switch direction {
		case 1:
			// log.Infof("value %v balance %x", value, balance)
			// log.Infof("pop %v", pop)
			// log.Infof("sh %v", sh)
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

		// Spent UTxO lookup
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

		//// XXX not needed but diagnostic
		//pop := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
		//value, script, err := i.txOut(ctx, pop, c)
		//if err != nil {
		//	return fmt.Errorf("tx out: %w", err)
		//}
		//if int64(value) != txOut.Value {
		//	panic(fmt.Sprintf("op %v want %v got %v",
		//		pop, txOut.Value, value))
		//}
		//if !bytes.Equal(txOut.PkScript, script) {
		//	panic(fmt.Sprintf("op %v want %v got %v",
		//		pop, spew.Sdump(txOut.PkScript),
		//		spew.Sdump(script)))
		//}
		//sc, addrs, rs, err := txscript.ExtractPkScriptAddrs(script,
		//	i.g.chain)
		//if err != nil {
		//	panic(err)
		//}
		// log.Infof("pop %v pkscripthash %v sc %v addrs %v rs %v script %x", pop,
		//	tbcd.NewScriptHashFromScript(script), sc, addrs, rs,
		//	script)
		// Fetch current balance of PkScript hash.
		sh := tbcd.NewScriptHashFromScript(txOut.PkScript)
		balance, err := i.balance(ctx, sh, c)
		if err != nil {
			return fmt.Errorf("balance out: %w", err)
		}
		// log.Infof("sh %v balance %v", sh, binary.BigEndian.Uint64(balance))
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

		// SpendableOutput
		so := tbcd.NewSpendableOutput(chainhash.Hash(sh), blockHeight,
			*blockHash, *txId, uint32(txOutIdx))
		cache[tbcd.ZKIndexKey(so[:])] = nil

		// Outpoint to TxOut
		op := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
		if _, ok := cache[tbcd.ZKIndexKey(op[:])]; ok {
			panic(fmt.Sprintf("diagnostic: %v", op))
		}
		cache[tbcd.ZKIndexKey(op[:])] = tbcd.NewTxOut(txOut)

		// Spendable UTxO lookup
		tsk := tbcd.NewTxSpendKey(*txId, blockHeight, *blockHash,
			uint32(txOutIdx))
		cache[tbcd.ZKIndexKey(tsk[:])] = nil
	}

	return nil
}

func (i *zkIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	blockHash := block.Hash()
	blockHeight := uint32(block.Height())
	log.Tracef("processing: %v %v", blockHeight, blockHash)
	log.Infof("direction %v processing: %v %v", direction, blockHeight, blockHash)
	// log.Infof("block: %v", spew.Sdump(block))
	switch direction {
	case 1:
		for _, tx := range block.Transactions() {
			err := i.processTx(ctx, direction, blockHeight, blockHash, tx, c)
			if err != nil {
				return err
			}
		}
	case -1:
		txs := block.Transactions()
		for k := len(txs) - 1; k > 0; k-- {
			tx := txs[k]
			err := i.processTx(ctx, direction, blockHeight, blockHash, tx, c)
			if err != nil {
				return err
			}
		}
	default:
		panic("wtf")
	}

	return nil
}

func (i *zkIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[tbcd.ZKIndexKey, []byte])
	return i.g.db.BlockZKUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *zkIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk indexer.
	return nil
}
