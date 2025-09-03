// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
)

type keystoneIndexer struct {
	indexerCommon

	cache       *Cache[chainhash.Hash, tbcd.Keystone]
	hemiGenesis *HashHeight
}

var (
	_ Indexer = (*keystoneIndexer)(nil)
	_ indexer = (*keystoneIndexer)(nil)
)

func NewKeystoneIndexer(g geometryParams, cacheLen int, enabled bool, hemiGenesis *HashHeight) Indexer {
	ki := &keystoneIndexer{
		cache:       NewCache[chainhash.Hash, tbcd.Keystone](cacheLen),
		hemiGenesis: hemiGenesis,
	}
	ki.indexerCommon = indexerCommon{
		name:    "keystone",
		enabled: enabled,
		g:       g,
		p:       ki,
		cache:   ki.cache,
	}
	return ki
}

func (i *keystoneIndexer) indexAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByKeystoneIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

func (i *keystoneIndexer) process(_ context.Context, direction int, block *btcutil.Block) error {
	return processKeystones(block, direction, i.cache.Map())
}

func (i *keystoneIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash) error {
	return i.g.db.BlockKeystoneUpdate(ctx, direction, i.cache.Map(), atHash)
}

func (i *keystoneIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block) error {
	// Not needed for keystone indexer.
	return nil
}

// BlockKeystonesByHash returns all keystones within a block. If hash is not
// nil then it returns *only* the keystone transactions where the L2
// abbreviated hash is equal to the provided hash.
func BlockKeystonesByHash(block *btcutil.Block, hash *chainhash.Hash) []tbcapi.KeystoneTx {
	blockHash := block.Hash()
	height := uint(block.Height())
	ktxs := make([]tbcapi.KeystoneTx, 0, 16)
	for txIndex, tx := range block.Transactions() {
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

		for _, txOut := range tx.MsgTx().TxOut {
			tl2, err := pop.ParseTransactionL2FromOpReturn(txOut.PkScript)
			if err != nil {
				continue
			}

			// Filter non matching keystones.
			if hash != nil && !hash.IsEqual(tl2.L2Keystone.Hash()) {
				continue
			}

			// XXX it is a travesty that we have to reserialize
			// this tx. We should add a change to btcutil.Tx to
			// return the internal rawBytes.
			var rawTx bytes.Buffer
			if err := tx.MsgTx().Serialize(&rawTx); err != nil {
				// We should always be able to serialize.
				panic(fmt.Sprintf("serialize tx: %s", err))
			}
			ktxs = append(ktxs, tbcapi.KeystoneTx{
				BlockHash:   *blockHash,
				TxIndex:     uint(txIndex),
				BlockHeight: height,
				RawTx:       rawTx.Bytes(),
			})
		}
	}

	return ktxs
}

func BlockKeystones(block *btcutil.Block) []tbcapi.KeystoneTx {
	return BlockKeystonesByHash(block, nil)
}

func processKeystones(block *btcutil.Block, direction int, kssCache map[chainhash.Hash]tbcd.Keystone) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	blockHash := *block.Hash()
	blockHeight := uint64(block.Height())
	txs := block.Transactions()
	for _, tx := range txs {
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

		for _, txOut := range tx.MsgTx().TxOut {
			aPoPTx, err := pop.ParseTransactionL2FromOpReturn(txOut.PkScript)
			if err != nil {
				// log.Tracef("error parsing tx l2: %s", err)
				continue
			}
			if _, ok := kssCache[*aPoPTx.L2Keystone.Hash()]; ok {
				// Multiple keystones may exist in block, only
				// store first or last based on direction. When
				// we move forward we only care about the first
				// one, when we move backwards we only car
				// about the last one thus overwrite the value
				// in the map.
				if direction == 1 {
					continue
				}
			}

			abvKss := aPoPTx.L2Keystone.Serialize()
			kssCache[*aPoPTx.L2Keystone.Hash()] = tbcd.Keystone{
				BlockHash:           blockHash,
				BlockHeight:         uint32(blockHeight),
				AbbreviatedKeystone: abvKss,
			}
		}
	}
	return nil
}
