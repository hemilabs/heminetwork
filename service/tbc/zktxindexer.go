// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// Transactions to be looked up by txid.

type zktxIndexer struct {
	indexerCommon

	cacheCapacity int
}

var (
	_ Indexer = (*zktxIndexer)(nil)
	_ indexer = (*zktxIndexer)(nil)
)

func NewZKTXIndexer(g geometryParams, cacheLen int, enabled bool) Indexer {
	zi := &zktxIndexer{
		cacheCapacity: cacheLen,
	}
	zi.indexerCommon = indexerCommon{
		name:    "zktx",
		enabled: enabled,
		g:       g,
		p:       zi,
	}
	return zi
}

func (i *zktxIndexer) newCache() indexerCache {
	return NewCache[tbcd.TxSpendKey, []byte](i.cacheCapacity)
}

func (i *zktxIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByZKTXIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

func (i *zktxIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	cache := c.(*Cache[tbcd.TxSpendKey, []byte]).Map()

	blockHash := block.Hash()
	blockHeight := uint32(block.Height())
	for _, tx := range block.Transactions() {
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

		txId := tx.Hash()
		for txInIdx, txIn := range tx.MsgTx().TxIn {
			tsk := tbcd.NewTxSpendKey(txIn.PreviousOutPoint.Hash,
				blockHeight, *blockHash, txIn.PreviousOutPoint.Index)
			cache[tsk] = tbcd.NewPointSlice(*txId, uint32(txInIdx))
		}

		for txOutIdx := range tx.MsgTx().TxOut {
			tsk := tbcd.NewTxSpendKey(*txId, blockHeight, *blockHash,
				uint32(txOutIdx))
			cache[tsk] = nil
		}
	}

	return nil
}

func (i *zktxIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[tbcd.TxSpendKey, []byte])
	return i.g.db.BlockZKTXUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *zktxIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk indexer.
	return nil
}
