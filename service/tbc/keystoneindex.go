// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
)

type keystoneIndexer struct {
	// common
	indexing uint32 // Used as an atomic
	indexer  string
	enabled  bool
	c        *Cache[chainhash.Hash, tbcd.Keystone]

	// geometry
	g geometryParams

	// keystone indexer only
	hemiGenesis *HashHeight
}

var _ Indexer = (*keystoneIndexer)(nil)

func NewKeystoneIndexer(chain *chaincfg.Params, cacheLen int, db tbcd.Database, enabled bool, hemiGenesis *HashHeight) Indexer {
	return &keystoneIndexer{
		indexer:  "keystone",
		indexing: 0,
		enabled:  enabled,
		c:        NewCache[chainhash.Hash, tbcd.Keystone](cacheLen),
		g: geometryParams{
			db:    db,
			chain: chain,
		},
		hemiGenesis: hemiGenesis,
	}
}

func (i *keystoneIndexer) geometry() geometryParams {
	return i.g
}

func (i *keystoneIndexer) cacheStats() (int, int, int) {
	return i.c.Stats()
}

func (i *keystoneIndexer) cacheFlush() {
	i.c.Clear()
}

func (i *keystoneIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash) error {
	return i.g.db.BlockKeystoneUpdate(ctx, direction, i.c.Map(), atHash)
}

func (i *keystoneIndexer) genesis() *HashHeight {
	return i.hemiGenesis
}

func (i *keystoneIndexer) process(ctx context.Context, block *btcutil.Block, direction int) error {
	return processKeystones(block, direction, i.c.Map())
}

func (i *keystoneIndexer) fixupCacheHook(ctx context.Context, block *btcutil.Block) error {
	return nil
}

func (i *keystoneIndexer) String() string {
	return i.indexer
}

func (i *keystoneIndexer) IndexToBest(ctx context.Context) error {
	// XXX hate to do this here instead of inside the interface.
	if !atomic.CompareAndSwapUint32(&i.indexing, 0, 1) {
		return ErrAlreadyIndexing
	}
	defer atomic.StoreUint32(&i.indexing, 0)

	return toBest(ctx, i)
}

func (i *keystoneIndexer) IndexToHash(ctx context.Context, hash chainhash.Hash) error {
	// XXX hate to do this here instead of inside the interface.
	if !atomic.CompareAndSwapUint32(&i.indexing, 0, 1) {
		return ErrAlreadyIndexing
	}
	defer atomic.StoreUint32(&i.indexing, 0)

	return windOrUnwind(ctx, i, hash)
}

func (i *keystoneIndexer) IndexAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByKeystoneIndex(ctx)
	return evaluateBlockHeaderIndex(i.g, bh, err)
}

func (i *keystoneIndexer) Indexing() bool {
	return atomic.LoadUint32(&i.indexing) == 1
}

func (i *keystoneIndexer) Enabled() bool {
	return i.enabled
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
