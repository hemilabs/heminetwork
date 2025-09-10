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
		name:    "zkblockheader",
		enabled: enabled,
		g:       g,
		p:       zi,
	}
	return zi
}

func (i *zkutxoIndexer) newCache() indexerCache {
	return NewCache[tbcd.TxSpendKey, []byte](i.cacheCapacity)
}

func (i *zkutxoIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByZKUtxoIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

func (i *zkutxoIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
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
			_ = txInIdx
			_ = txIn
			// since key size differs we can kill I and O
			// ZKUtxoKey sha256(txin.PreviousOutPoint->pkscript), blockHeight,
			// blockHash, txId, `I`, txIn.PreviousOutPoint.Hash,
			// txIn.PreviousOutPoint.Index, txInIdx
			// balance -= outputvalue that txIn.PreviousOutPoint is pointing to
		}

		for txOutIdx, txOut := range tx.MsgTx().TxOut {
			_ = txOutIdx
			_ = txOut
			// ZKUtxoKey = sha256(txOut.PkScript), blockHeight, blockHash, txId, `O`,
			// txOutIdx
			// balance += txOut.Value
		}
		_ = cache
		_ = blockHash
		_ = blockHeight
		_ = txId
	}

	return nil
}

func (i *zkutxoIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[tbcd.TxSpendKey, []byte])
	return i.g.db.BlockZKUtxoUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *zkutxoIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk indexer.
	return nil
}
