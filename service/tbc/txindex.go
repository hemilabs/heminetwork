// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type txIndexer struct {
	indexerCommon
	cache *Cache[tbcd.TxKey, *tbcd.TxValue]
}

var (
	_ Indexer = (*txIndexer)(nil)
	_ indexer = (*txIndexer)(nil)
)

func NewTxIndexer(chain *chaincfg.Params, cacheLen int, db tbcd.Database) Indexer {
	txi := &txIndexer{
		cache: NewCache[tbcd.TxKey, *tbcd.TxValue](cacheLen),
	}
	txi.indexerCommon = indexerCommon{
		name:    "tx",
		enabled: true,
		geometry: geometryParams{
			db:    db,
			chain: chain,
		},
		p:     txi,
		cache: txi.cache,
	}
	return txi
}

func (i *txIndexer) indexAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.geometry.db.BlockHeaderByTxIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

func (i *txIndexer) process(ctx context.Context, direction int, block *btcutil.Block) error {
	return processTxs(ctx, block, direction, i.cache.Map())
}

func (i *txIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash) error {
	return i.geometry.db.BlockTxUpdate(ctx, direction, i.cache.Map(), atHash)
}

func (i *txIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block) error {
	// Not needed for tx indexer.
	return nil
}

func processTxs(ctx context.Context, block *btcutil.Block, direction int, txsCache map[tbcd.TxKey]*tbcd.TxValue) error {
	blockHash := block.Hash()
	txs := block.Transactions()
	for _, tx := range txs {
		// cache txid <-> block
		txsCache[tbcd.NewTxMapping(tx.Hash(), blockHash)] = nil

		// Don't keep track of spent coinbase inputs
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

		for txInIdx, txIn := range tx.MsgTx().TxIn {
			txk, txv := tbcd.NewTxSpent(
				blockHash,
				tx.Hash(),
				&txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index,
				uint32(txInIdx))
			txsCache[txk] = &txv
		}
	}
	return nil
}
