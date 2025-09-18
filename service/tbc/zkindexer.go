// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// Index block headers by hash and height to blockheader. This index is
// canonical only.

type zkIndexer struct {
	indexerCommon

	cacheCapacity int
}

var (
	_ Indexer = (*zkIndexer)(nil)
	_ indexer = (*zkIndexer)(nil)
)

func NewZKBlockHeaderIndexer(g geometryParams, cacheLen int, enabled bool) Indexer {
	zi := &zkIndexer{
		cacheCapacity: cacheLen,
	}
	zi.indexerCommon = indexerCommon{
		name:    "zkblockheader",
		enabled: enabled,
		g:       g,
		p:       zi,
	}
	return zi
}

func (i *zkIndexer) newCache() indexerCache {
	return NewCache[chainhash.Hash, tbcd.BlockHeader](i.cacheCapacity)
}

func (i *zkIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByZKBlockHeaderIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

var maxTxin, maxTxout, maxBs, maxTxs, totalTxs int

func (i *zkIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	cache := c.(*Cache[chainhash.Hash, tbcd.BlockHeader]).Map()
	bh, err := i.g.db.BlockHeaderByHash(ctx, *block.Hash())
	if err != nil {
		return err
	}
	cache[*block.Hash()] = *bh

	bs, err := block.Bytes()
	if err != nil {
		panic(err)
	}
	if len(bs) > maxBs {
		maxBs = len(bs)
		log.Infof("largest block %v: %v", block.Hash(), maxBs)
	}
	if len(block.Transactions()) > maxTxs {
		maxTxs = len(block.Transactions())
		log.Infof("largest block txs %v: %v", block.Hash(), maxTxs)
	}
	totalTxs += len(block.Transactions())
	for _, tx := range block.Transactions() {
		if len(tx.MsgTx().TxIn) > maxTxin {
			maxTxin = len(tx.MsgTx().TxIn)
			log.Infof("largest txin %v: %v", tx.Hash(), maxTxin)
		}
		if len(tx.MsgTx().TxOut) > maxTxout {
			maxTxout = len(tx.MsgTx().TxOut)
			log.Infof("largest txout %v: %v", tx.Hash(), maxTxout)
		}
		//if blockchain.IsCoinBase(tx) {
		//	// Skip coinbase inputs
		//	continue
		//}

		//for _, txOut := range tx.MsgTx().TxOut {
		//}
	}

	return nil
}

func (i *zkIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[chainhash.Hash, tbcd.BlockHeader])
	return i.g.db.BlockZKBlockHeaderUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *zkIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk indexer.
	return nil
}
