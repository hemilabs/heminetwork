// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/x/zktrie"
)

type zkRollupIndexer struct {
	indexerCommon

	cacheCapacity int

	tr zktrie.ZKTrie
}

var (
	_ Indexer = (*zkRollupIndexer)(nil)
	_ indexer = (*zkRollupIndexer)(nil)
)

func NewZKRollupIndexer(g geometryParams, cacheLen int, enabled bool) Indexer {
	zi := &zkRollupIndexer{
		cacheCapacity: cacheLen,
	}
	zi.indexerCommon = indexerCommon{
		name:    "zkrollupindexer",
		enabled: enabled,
		g:       g,
		p:       zi,
	}
	var err error
	zi.tr, err = zktrie.NewZKTrie(context.TODO(), "")
	if err != nil {
		panic(err) // XXX return err
	}
	return zi
}

func (i *zkRollupIndexer) newCache() indexerCache {
	panic("newCache")
	// return NewCache[tbcd.ZKRollupKey, []byte](i.cacheCapacity)
}

func (i *zkRollupIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	panic("indexerAt")
	// bh, err := i.g.db.BlockHeaderByZKRollup(ctx)
	// return i.evaluateBlockHeaderIndex(bh, err)
}

//func (i *zkRollupIndexer) balance(ctx context.Context, ss tbcd.ScriptHash, c indexerCache) ([]byte, error) {
//	cache := c.(*Cache[tbcd.ZKRollupKey, []byte]).Map()
//	if balance, ok := cache[tbcd.ZKRollupKey(ss[:])]; ok {
//		return balance, nil
//	}
//
//	// Not found in cache, fetch from db
//	var balance [8]byte
//	b, err := i.g.db.ZKBalanceByScriptHash(ctx, ss)
//	if err != nil {
//		if errors.Is(err, database.ErrNotFound) {
//			return balance[:], nil
//		}
//		return nil, err
//	}
//	binary.BigEndian.PutUint64(balance[:], b)
//	return balance[:], nil
//}
//
//func (i *zkRollupIndexer) txOut(ctx context.Context, pop tbcd.Outpoint, c indexerCache) (uint64, []byte, error) {
//	cache := c.(*Cache[tbcd.ZKRollupKey, []byte]).Map()
//	if utxoE, ok := cache[tbcd.ZKRollupKey(pop[:])]; ok {
//		txOut := tbcd.TxOutFromBytes(utxoE)
//		return uint64(txOut.Value), txOut.PkScript, nil
//	}
//	// Not found in cache, fetch from db
//	value, txOut, err := i.g.db.ZKValueAndScriptByOutpoint(ctx, pop)
//	if err != nil {
//		return 0, nil, err
//	}
//	return value, txOut, nil
//}

//func (i *zkRollupIndexer) processTx(ctx context.Context, direction int, blockHeight uint32, blockHash *chainhash.Hash, tx *btcutil.Tx, c indexerCache) error {
//	cache := c.(*Cache[tbcd.ZKRollupKey, []byte]).Map()
//	txId := tx.Hash()
//	for txInIdx, txIn := range tx.MsgTx().TxIn {
//		// Skip coinbase inputs
//		if blockchain.IsCoinBase(tx) {
//			continue
//		}
//
//		// Recreate Outpoint from TxIn.PreviousOutPoint
//		pop := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
//			txIn.PreviousOutPoint.Index)
//
//		// Retrieve TxOut from PreviousOutPoint
//		value, script, err := i.txOut(ctx, pop, c)
//		if err != nil {
//			return fmt.Errorf("tx out: %w", err)
//		}
//
//		// Retrieve balance
//		sh := tbcd.NewScriptHashFromScript(script)
//		balance, err := i.balance(ctx, sh, c)
//		if err != nil {
//			return fmt.Errorf("balance in: %w", err)
//		}
//
//		// Handle balance
//		switch direction {
//		case 1:
//			cache[tbcd.ZKRollupKey(sh[:])] = tbcd.BESubUint64(balance,
//				value)
//		case -1:
//			cache[tbcd.ZKRollupKey(sh[:])] = tbcd.BEAddUint64(balance,
//				value)
//		default:
//			panic(fmt.Sprintf("diagnostic: invalid direction %v", direction))
//		}
//
//		// Insert SpentOutput
//		spo := tbcd.NewSpentOutput(chainhash.Hash(sh), blockHeight,
//			*blockHash, *txId, txIn.PreviousOutPoint.Hash,
//			txIn.PreviousOutPoint.Index, uint32(txInIdx))
//		if _, ok := cache[tbcd.ZKRollupKey(spo[:])]; ok {
//			panic(fmt.Sprintf("diagnostic: %v", spo))
//		}
//		cache[tbcd.ZKRollupKey(spo[:])] = nil
//
//		// Tx index, where spent
//		sok := tbcd.NewSpendingOutpointKey(txIn.PreviousOutPoint.Hash,
//			blockHeight, *blockHash, txIn.PreviousOutPoint.Index)
//		cache[tbcd.ZKRollupKey(sok[:])] = tbcd.NewSpendingOutpointValueSlice(*txId,
//			uint32(txInIdx))
//	}
//
//	for txOutIdx, txOut := range tx.MsgTx().TxOut {
//		// Skip unspendables.
//		if txscript.IsUnspendable(txOut.PkScript) {
//			continue
//		}
//
//		sh := tbcd.NewScriptHashFromScript(txOut.PkScript)
//		balance, err := i.balance(ctx, sh, c)
//		if err != nil {
//			return fmt.Errorf("balance out: %w", err)
//		}
//		// log.Infof("sh %v balance %v", sh, binary.BigEndian.Uint64(balance))
//		switch direction {
//		case 1:
//			cache[tbcd.ZKRollupKey(sh[:])] = tbcd.BEAddUint64(balance,
//				uint64(txOut.Value))
//		case -1:
//			cache[tbcd.ZKRollupKey(sh[:])] = tbcd.BESubUint64(balance,
//				uint64(txOut.Value))
//		default:
//			panic(fmt.Sprintf("diagnostic: invalid direction %v", direction))
//		}
//
//		// SpendableOutput
//		so := tbcd.NewSpendableOutput(chainhash.Hash(sh), blockHeight,
//			*blockHash, *txId, uint32(txOutIdx))
//		cache[tbcd.ZKRollupKey(so[:])] = nil
//
//		// Outpoint to TxOut
//		op := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
//		if _, ok := cache[tbcd.ZKRollupKey(op[:])]; ok {
//			// Work around two invalid txids on mainnet
//			switch op.String() {
//			case "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599:0":
//			case "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468:0":
//			default:
//				panic(fmt.Sprintf("diagnostic: %v", op))
//			}
//		}
//		cache[tbcd.ZKRollupKey(op[:])] = tbcd.NewTxOut(txOut)
//
//		// Tx index, available to spend
//		sok := tbcd.NewSpendingOutpointKey(*txId, blockHeight, *blockHash,
//			uint32(txOutIdx))
//		cache[tbcd.ZKRollupKey(sok[:])] = nil
//	}
//
//	return nil
//}

func (i *zkRollupIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	blockHash := block.Hash()
	blockHeight := uint32(block.Height())
	log.Tracef("processing: %v %v", blockHeight, blockHash)
	log.Infof("direction %v processing: %v %v", direction, blockHeight, blockHash)
	switch direction {
	case 1:
		panic("1")
		//for _, tx := range block.Transactions() {
		//	err := i.processTx(ctx, direction, blockHeight, blockHash, tx, c)
		//	if err != nil {
		//		return err
		//	}
		//}
	case -1:
		panic("-1")
		//txs := block.Transactions()
		//for k := len(txs) - 1; k >= 0; k-- {
		//	tx := txs[k]
		//	err := i.processTx(ctx, direction, blockHeight, blockHash, tx, c)
		//	if err != nil {
		//		return err
		//	}
		//}
	default:
		panic(fmt.Sprintf("diagnostic: %v", direction))
	}
}

func (i *zkRollupIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	panic("commit")
	// cache := c.(*Cache[tbcd.ZKRollupKey, []byte])
	// return i.g.db.BlockZKUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *zkRollupIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk indexer.
	return nil
}
