// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"sync/atomic"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type txIndexer struct {
	// common
	indexing uint32 // Used as an atomic
	indexer  string
	enabled  bool
	c        *Cache[tbcd.TxKey, *tbcd.TxValue]

	// geometry
	g geometryParams

	// tx indexer only
}

var _ Indexer = (*txIndexer)(nil)

func NewTxIndexer(chain *chaincfg.Params, cacheLen int, db tbcd.Database) Indexer {
	return &txIndexer{
		indexer:  "tx",
		indexing: 0,
		enabled:  true,
		c:        NewCache[tbcd.TxKey, *tbcd.TxValue](cacheLen),
		g: geometryParams{
			db:    db,
			chain: chain,
		},
	}
}

func (i *txIndexer) geometry() geometryParams {
	return i.g
}

func (i *txIndexer) cacheStats() (int, int, int) {
	return i.c.Stats()
}

func (i *txIndexer) cacheFlush() {
	i.c.Clear()
}

func (i *txIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash) error {
	return i.g.db.BlockTxUpdate(ctx, direction, i.c.Map(), atHash)
}

func (i *txIndexer) genesis() *HashHeight {
	return nil
}

func (i *txIndexer) process(ctx context.Context, block *btcutil.Block, direction int) error {
	return processTxs(block, direction, i.c.Map())
}

func (i *txIndexer) fixupCacheHook(ctx context.Context, block *btcutil.Block) error {
	return nil
}

func (i *txIndexer) String() string {
	return i.indexer
}

func (i *txIndexer) ToBest(ctx context.Context) error {
	// XXX hate to do this here instead of inside the interface.
	if !atomic.CompareAndSwapUint32(&i.indexing, 0, 1) {
		return ErrAlreadyIndexing
	}
	defer atomic.StoreUint32(&i.indexing, 0)

	return toBest(ctx, i)
}

func (i *txIndexer) ToHash(ctx context.Context, hash chainhash.Hash) error {
	// XXX hate to do this here instead of inside the interface.
	if !atomic.CompareAndSwapUint32(&i.indexing, 0, 1) {
		return ErrAlreadyIndexing
	}
	defer atomic.StoreUint32(&i.indexing, 0)

	return windOrUnwind(ctx, i, hash)
}

func (i *txIndexer) At(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByTxIndex(ctx)
	return evaluateBlockHeaderIndex(i.g, bh, err)
}

func (i *txIndexer) Indexing() bool {
	return atomic.LoadUint32(&i.indexing) == 1
}

func (i *txIndexer) Enabled() bool {
	return i.enabled
}

func processTxs(block *btcutil.Block, direction int, txsCache map[tbcd.TxKey]*tbcd.TxValue) error {
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
