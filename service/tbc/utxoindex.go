// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type utxoCache struct {
	maxCacheEntries int
	c               map[tbcd.Outpoint]tbcd.CacheOutput
}

func (c *utxoCache) Clear() {
	clear(c.c)
}

func (c *utxoCache) Length() int {
	return len(c.c)
}

func (c *utxoCache) Capacity() int {
	return c.maxCacheEntries
}

func (c *utxoCache) Generic() any {
	return c.c
}

func NewUtxoCache(maxCacheEntries int) Cache {
	return &utxoCache{
		maxCacheEntries: maxCacheEntries,
		c:               make(map[tbcd.Outpoint]tbcd.CacheOutput, maxCacheEntries),
	}
}

type utxoIndexer struct {
	// common
	mtx      sync.RWMutex
	indexer  string
	indexing bool
	enabled  bool
	c        Cache

	// geometry
	g geometryParams

	// utxo indexer only
	fixupHook fixupCacheFunc
}

var (
	_ Cache   = (*utxoCache)(nil)
	_ Indexer = (*utxoIndexer)(nil)
)

type fixupCacheFunc func(context.Context, *btcutil.Block, map[tbcd.Outpoint]tbcd.CacheOutput) error

func NewUtxoIndexer(chain *chaincfg.Params, cacheLen int, db tbcd.Database, f fixupCacheFunc) Indexer {
	return &utxoIndexer{
		indexer:   "utxo",
		indexing:  false,
		enabled:   true,
		c:         NewUtxoCache(cacheLen),
		fixupHook: f,
		g: geometryParams{
			db:    db,
			chain: chain,
		},
	}
}

func (i *utxoIndexer) geometry() geometryParams {
	return i.g
}

func (i *utxoIndexer) cache() Cache {
	return i.c
}

func (i *utxoIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash) error {
	return i.g.db.BlockUtxoUpdate(ctx, direction,
		i.cache().Generic().(map[tbcd.Outpoint]tbcd.CacheOutput), atHash)
}

func (i *utxoIndexer) genesis() *HashHeight {
	return nil
}

func (i *utxoIndexer) process(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	if direction == -1 {
		return unprocessUtxos(ctx, i.g.db, block,
			cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
	}
	return processUtxos(block, cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

func (i *utxoIndexer) fixupCacheHook(ctx context.Context, block *btcutil.Block, cache any) error {
	return i.fixupHook(ctx, block, cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

func (i *utxoIndexer) String() string {
	return i.indexer
}

func (i *utxoIndexer) ToBest(ctx context.Context) error {
	// abstract locking away
	i.mtx.Lock()
	if i.indexing {
		i.mtx.Unlock()
		return fmt.Errorf("already indexing: %v", i)
	}
	i.indexing = true
	i.mtx.Unlock()
	return toBest(ctx, i)
}

func (i *utxoIndexer) ToHash(ctx context.Context, hash chainhash.Hash) error {
	// abstract locking away
	i.mtx.Lock()
	if i.indexing {
		i.mtx.Unlock()
		return fmt.Errorf("already indexing: %v", i)
	}
	i.indexing = true
	i.mtx.Unlock()
	return windOrUnwind(ctx, i, hash)
}

func (i *utxoIndexer) At(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByUtxoIndex(ctx)
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

func (i *utxoIndexer) Indexing() bool {
	i.mtx.RLock()
	defer i.mtx.RUnlock()
	return i.indexing
}

func (i *utxoIndexer) Enabled() bool {
	i.mtx.RLock()
	defer i.mtx.RUnlock()
	return i.enabled
}
