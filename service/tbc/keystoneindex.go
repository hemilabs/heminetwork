// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type keystoneCache struct {
	maxCacheEntries int
	c               map[chainhash.Hash]tbcd.Keystone
}

func (c *keystoneCache) Clear() {
	clear(c.c)
}

func (c *keystoneCache) Length() int {
	return len(c.c)
}

func (c *keystoneCache) Capacity() int {
	return c.maxCacheEntries
}

func (c *keystoneCache) Generic() any {
	return c.c
}

func NewKeystoneCache(maxCacheEntries int) Cache {
	return &keystoneCache{
		maxCacheEntries: maxCacheEntries,
		c:               make(map[chainhash.Hash]tbcd.Keystone, maxCacheEntries),
	}
}

type keystoneIndexer struct {
	// common
	indexing uint32 // Used as an atomic
	indexer  string
	enabled  bool
	c        Cache

	// geometry
	g geometryParams

	// keystone indexer only
}

var (
	_ Cache   = (*keystoneCache)(nil)
	_ Indexer = (*keystoneIndexer)(nil)
)

func NewKeystoneIndexer(chain *chaincfg.Params, cacheLen int, db tbcd.Database, enabled bool) Indexer {
	return &keystoneIndexer{
		indexer:  "keystone",
		indexing: 0,
		enabled:  enabled,
		c:        NewKeystoneCache(cacheLen),
		g: geometryParams{
			db:    db,
			chain: chain,
		},
	}
}

func (i *keystoneIndexer) geometry() geometryParams {
	return i.g
}

func (i *keystoneIndexer) cache() Cache {
	return i.c
}

func (i *keystoneIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash) error {
	return i.g.db.BlockKeystoneUpdate(ctx, direction,
		i.cache().Generic().(map[chainhash.Hash]tbcd.Keystone), atHash)
}

func (i *keystoneIndexer) genesis() *HashHeight {
	return nil
}

func (i *keystoneIndexer) process(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	return processKeystones(block, direction,
		cache.(map[chainhash.Hash]tbcd.Keystone))
}

func (i *keystoneIndexer) fixupCacheHook(ctx context.Context, block *btcutil.Block, cache any) error {
	return nil
}

func (i *keystoneIndexer) String() string {
	return i.indexer
}

func (i *keystoneIndexer) ToBest(ctx context.Context) error {
	// XXX hate to do this here instead of inside the interface.
	if !atomic.CompareAndSwapUint32(&i.indexing, 0, 1) {
		return ErrAlreadyIndexing
	}
	defer atomic.StoreUint32(&i.indexing, 0)

	return toBest(ctx, i)
}

func (i *keystoneIndexer) ToHash(ctx context.Context, hash chainhash.Hash) error {
	// XXX hate to do this here instead of inside the interface.
	if !atomic.CompareAndSwapUint32(&i.indexing, 0, 1) {
		return ErrAlreadyIndexing
	}
	defer atomic.StoreUint32(&i.indexing, 0)

	return windOrUnwind(ctx, i, hash)
}

func (i *keystoneIndexer) At(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByKeystoneIndex(ctx)
	if err != nil {
		// XXX kind of don't want to copy/paste this everywhere
		if !errors.Is(err, database.ErrNotFound) {
			return nil, err
		}
		bh = &tbcd.BlockHeader{
			Hash:   *i.g.chain.GenesisHash,
			Height: 0,
			Header: h2b(&i.g.chain.GenesisBlock.Header),
		}
	}
	return bh, nil
}

func (i *keystoneIndexer) Indexing() bool {
	return atomic.LoadUint32(&i.indexing) == 1
}

func (i *keystoneIndexer) Enabled() bool {
	return i.enabled
}
