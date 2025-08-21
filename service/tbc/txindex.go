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

type txCache struct {
	maxCacheEntries int
	c               map[tbcd.TxKey]*tbcd.TxValue
}

func (c *txCache) Clear() {
	clear(c.c)
}

func (c *txCache) Length() int {
	return len(c.c)
}

func (c *txCache) Capacity() int {
	return c.maxCacheEntries
}

func (c *txCache) Generic() any {
	return c.c
}

func NewTxCache(maxCacheEntries int) Cache {
	return &txCache{
		maxCacheEntries: maxCacheEntries,
		c:               make(map[tbcd.TxKey]*tbcd.TxValue, maxCacheEntries),
	}
}

type txIndexer struct {
	// common
	mtx      sync.RWMutex
	indexer  string
	indexing bool
	enabled  bool
	c        Cache

	// geometry
	g geometryParams

	// tx indexer only
}

var (
	_ Cache   = (*txCache)(nil)
	_ Indexer = (*txIndexer)(nil)
)

func NewTxIndexer(chain *chaincfg.Params, cacheLen int, db tbcd.Database) Indexer {
	return &txIndexer{
		indexer:  "tx",
		indexing: false,
		enabled:  true,
		c:        NewTxCache(cacheLen),
		g: geometryParams{
			db:    db,
			chain: chain,
		},
	}
}

func (i *txIndexer) geometry() geometryParams {
	return i.g
}

func (i *txIndexer) cache() Cache {
	return i.c
}

func (i *txIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash) error {
	return i.g.db.BlockTxUpdate(ctx, direction,
		i.cache().Generic().(map[tbcd.TxKey]*tbcd.TxValue), atHash)
}

func (i *txIndexer) genesis() *HashHeight {
	return nil
}

func (i *txIndexer) process(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	return processTxs(block, direction, cache.(map[tbcd.TxKey]*tbcd.TxValue))
}

func (i *txIndexer) fixupCacheHook(ctx context.Context, block *btcutil.Block, cache any) error {
	return nil
}

func (i *txIndexer) String() string {
	return i.indexer
}

func (i *txIndexer) ToBest(ctx context.Context) error {
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

func (i *txIndexer) ToHash(ctx context.Context, hash chainhash.Hash) error {
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

func (i *txIndexer) At(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByTxIndex(ctx)
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

func (i *txIndexer) Indexing() bool {
	i.mtx.RLock()
	defer i.mtx.RUnlock()
	return i.indexing
}

func (i *txIndexer) Enabled() bool {
	i.mtx.RLock()
	defer i.mtx.RUnlock()
	return i.enabled
}
