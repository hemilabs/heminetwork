// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// Need height lookup AND hash lookup

// height hash ->  h_uint32_[32]byte
type ZKHeightHash [37]byte

func encodeZKHeightHash(height uint32, hash chainhash.Hash) (zkhh ZKHeightHash) {
	zkhh[0] = 'h'
	binary.BigEndian.PutUint32(zkhh[1:5], height)
	copy(zkhh[5:], hash[:])
	return
}

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

func (i *zkIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	cache := c.(*Cache[chainhash.Hash, tbcd.BlockHeader]).Map()
	bh, err := i.g.db.BlockHeaderByHash(ctx, *block.Hash())
	if err != nil {
		return err
	}
	cache[*block.Hash()] = *bh
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
