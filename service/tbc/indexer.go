// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/dustin/go-humanize"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

var ErrAlreadyIndexing = errors.New("already indexing")

// Cache is an in-memory cache implementation.
type Cache[K comparable, V any] struct {
	capacity int
	m        map[K]V
}

// NewCache returns a new cache with a specified capacity.
func NewCache[K comparable, V any](capacity int) *Cache[K, V] {
	return &Cache[K, V]{capacity: capacity, m: make(map[K]V, capacity)}
}

// Clear clears the cache.
func (c *Cache[K, V]) Clear() {
	clear(c.m)
}

// Len returns the number of items stored in the cache.
func (c *Cache[K, V]) Len() int {
	return len(c.m)
}

// Cap returns the capacity of the cache.
func (c *Cache[K, V]) Cap() int {
	return c.capacity
}

func (c *Cache[K, V]) Stats() (length int, capacity int, pct int) {
	length = c.Len()
	return length, c.Cap(), length * 100 / c.Cap()
}

// Map returns the underlying map[K]V used in the cache.
func (c *Cache[K, V]) Map() map[K]V {
	return c.m
}

type Indexer interface {
	// Enabled returns whether the indexer is enabled.
	Enabled() bool

	// Indexing returns whether the indexer is currently indexing.
	Indexing() bool

	// IndexToBest moves the indexer to the best hash, and auto-resolves forks.
	IndexToBest(ctx context.Context) error

	// IndexToHash moves the indexer to the given hash.
	IndexToHash(ctx context.Context, hash chainhash.Hash) error

	// IndexerAt returns the point the indexer is currently at.
	IndexerAt(ctx context.Context) (*tbcd.BlockHeader, error)
}

// indexer does indexer-specific work.
type indexer interface {
	newCache() indexerCache // Creates new cache per run.

	indexerAt(ctx context.Context) (*tbcd.BlockHeader, error)                               // Returns where the indexer is.
	process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error // Process block
	commit(ctx context.Context, direction int, hash chainhash.Hash, c indexerCache) error   // Commit index cache to disk
	fixupCacheHook(ctx context.Context, block *btcutil.Block, c indexerCache) error         // Fixup cache
}

// indexerCache exposes Cache management functions.
type indexerCache interface {
	Clear()
	Stats() (length int, capacity int, pct int)
}

// geometryParams conveniently wraps all parameters required to perform
// geometry operations.
type geometryParams struct {
	db    tbcd.Database
	chain *chaincfg.Params
}

// indexerCommon is the common base for Indexer implementations.
type indexerCommon struct {
	name     string
	enabled  bool
	indexing atomic.Uint32

	p       indexer        // parent indexer
	g       geometryParams // geometry params
	genesis *HashHeight    // genesis block override
}

func (c *indexerCommon) Enabled() bool {
	return c.enabled
}

func (c *indexerCommon) Indexing() bool {
	return c.indexing.Load() == 1
}

func (c *indexerCommon) IndexToBest(ctx context.Context) error {
	if !c.Enabled() {
		return errors.New("indexer disabled")
	}

	// Ensure indexer is not already running.
	if !c.indexing.CompareAndSwap(0, 1) {
		return ErrAlreadyIndexing
	}
	defer c.indexing.Store(0)

	return c.toBest(ctx)
}

func (c *indexerCommon) IndexToHash(ctx context.Context, hash chainhash.Hash) error {
	if !c.Enabled() {
		return errors.New("indexer disabled")
	}

	// Ensure index is not already running.
	if !c.indexing.CompareAndSwap(0, 1) {
		return ErrAlreadyIndexing
	}
	defer c.indexing.Store(0)

	return c.windOrUnwind(ctx, hash)
}

func (c *indexerCommon) IndexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	if !c.Enabled() {
		return nil, errors.New("indexer disabled")
	}
	return c.p.indexerAt(ctx)
}

// String returns the indexer name.
func (c *indexerCommon) String() string {
	return c.name
}

// evaluateBlockHeaderIndex makes error handling of the various block header
// index calls generic.
func (c *indexerCommon) evaluateBlockHeaderIndex(bh *tbcd.BlockHeader, err error) (*tbcd.BlockHeader, error) {
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return nil, err
		}
		bh = &tbcd.BlockHeader{
			Hash:   *c.g.chain.GenesisHash,
			Height: 0,
			Header: h2b(&c.g.chain.GenesisBlock.Header),
		}
	}
	return bh, nil
}

// toBest moves the indexer to the best tip.
func (c *indexerCommon) toBest(ctx context.Context) error {
	log.Tracef("%vIndexersToBest", c)
	defer log.Tracef("%vIndexersToBest exit", c)

	bhb, err := c.g.db.BlockHeaderBest(ctx)
	if err != nil {
		return err
	}

	// Find out where the indexer is at.
	indexerAt, err := c.IndexerAt(ctx)
	if err != nil {
		return err
	}
	cp, err := findCanonicalParent(ctx, c.g, indexerAt)
	if err != nil {
		return err
	}
	if !cp.Hash.IsEqual(&indexerAt.Hash) {
		log.Infof("Syncing %v index to: %v from: %v via: %v",
			c, bhb.HH(), indexerAt.HH(), cp.HH())
		// indexerAt is NOT on canonical chain, unwind first
		if err := c.windOrUnwind(ctx, cp.Hash); err != nil {
			return fmt.Errorf("%v indexer unwind: %w", c, err)
		}
	}
	// Index to best block
	if err := c.windOrUnwind(ctx, bhb.Hash); err != nil {
		return fmt.Errorf("%v indexer: %w", c, err)
	}

	return nil
}

// headerAndBlock retrieves both the blockheader and the block. While the
// blockheader is part of the block we do this double database retrieval to
// ensure both exist.
func headerAndBlock(ctx context.Context, db tbcd.Database, hash chainhash.Hash) (*tbcd.BlockHeader, *btcutil.Block, error) {
	bh, err := db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("block header %v: %w", hash, err)
	}
	b, err := db.BlockByHash(ctx, bh.Hash)
	if err != nil {
		return nil, nil, fmt.Errorf("block by hash %v: %w", bh, err)
	}
	b.SetHeight(int32(bh.Height))

	return bh, b, nil
}

// windOrUnwind determines in which direction we are moving and kicks of the
// wind or unwind process.
func (c *indexerCommon) windOrUnwind(ctx context.Context, endHash chainhash.Hash) error {
	log.Tracef("%vIndexer", c)
	defer log.Tracef("%vIndexer exit", c)

	// XXX this is basically duplicate from modeIndexIsLinear

	if !c.Indexing() {
		panic("bug: indexing not true")
	}

	// Verify exit condition hash
	g := c.g
	endBH, err := g.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return fmt.Errorf("blockheader end hash: %w", err)
	}

	// Verify start point is not after the end point
	indexerAt, err := c.IndexerAt(ctx)
	if err != nil {
		return err
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := g.db.BlockHeaderByHash(ctx, indexerAt.Hash)
	if err != nil {
		return fmt.Errorf("blockheader %v hash: %w", c, err)
	}
	direction, err := indexIsLinear(ctx, g, indexerAt.Hash, endHash)
	if err != nil {
		return fmt.Errorf("%v index is linear: %w", c, err)
	}
	switch direction {
	case 1:
		return c.wind(ctx, startBH, endBH)
	case -1:
		return c.unwind(ctx, startBH, endBH)
	case 0:
		// Because we call modeIndexIsLinear we know it's the same block.
		return nil
	}

	return fmt.Errorf("invalid direction: %v", direction)
}

// wind moves the chain forward and process blocks to generate an index cache.
// When the cache is filled it flushes the cache to disk and repeats this
// process until it reaches endBH.
func (c *indexerCommon) wind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("%v wind", c)
	defer log.Tracef("%v wind exit", c)

	if !c.Indexing() {
		panic("bug: indexing not true")
	}

	// Allocate cache here. Once this function is done, the cache will be
	// cleared and its items will be collected by GC.
	cache := c.p.newCache()
	defer cache.Clear()

	log.Infof("Start indexing %vs at hash %v height %v", c, startBH, startBH.Height)
	log.Infof("End indexing %vs at hash %v height %v", c, endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := c.parseBlocks(ctx, endHash, cache)
		if err != nil {
			return fmt.Errorf("%v index blocks: %w", c, err)
		}
		if blocksProcessed == 0 {
			return nil
		}

		cached, _, pct := cache.Stats()
		log.Infof("%v indexer blocks processed %v in %v cached %v (%v%%) avg/blk %v",
			c, blocksProcessed, time.Since(start), cached, pct, cached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err := c.p.commit(ctx, 1, last.Hash, cache); err != nil {
			return fmt.Errorf("block %v update: %w", c, err)
		}
		cache.Clear() // Done in db but do it again here to be sure.

		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing %vs complete %v took %v",
			c, cached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}

	return nil
}

// unwind moves the chain backward and reverses the wind process on the found
// blocks. When the cache is filled it flushes the cache to disk and repeats
// this process until it reaches endBH.
func (c *indexerCommon) unwind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("%v Unwind", c)
	defer log.Tracef("%v Unwind exit", c)

	// XXX dedup with wind; it's basically the same code but with the direction, start anf endhas flipped

	if !c.Indexing() {
		panic("bug: indexing not true")
	}

	// Allocate cache here. Once this function is done, the cache will be
	// cleared and its items will be collected by GC.
	cache := c.p.newCache()
	defer cache.Clear()

	log.Infof("Start unwinding %v at hash %v height %v", c, startBH, startBH.Height)
	log.Infof("End unwinding %v at hash %v height %v", c, endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := c.parseBlocksReverse(ctx, endHash, cache)
		if err != nil {
			return fmt.Errorf("unindex %vs in blocks: %w", c, err)
		}
		if blocksProcessed == 0 {
			return nil
		}

		cached, _, pct := cache.Stats()
		log.Infof("%v unwinder blocks processed %v in %v cached %v cache (%v%%) avg/blk %v",
			c, blocksProcessed, time.Since(start), cached, pct, cached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = c.p.commit(ctx, -1, last.Hash, cache); err != nil {
			return fmt.Errorf("block %v update: %w", c, err)
		}
		cache.Clear() // Done in db but do it again here to be sure.

		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing unwind %vs complete %v took %v",
			c, cached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}
	return nil
}

// parseBlocks indexes the block from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it processed.
func (c *indexerCommon) parseBlocks(ctx context.Context, endHash *chainhash.Hash, cache indexerCache) (int, *HashHeight, error) {
	log.Tracef("%v parseBlocks", c)
	defer log.Tracef("%v parseBlocks exit", c)

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	at, err := c.IndexerAt(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("%v index hash: %w", c, err)
	}

	// If we have a real block move forward to the next block since we
	// already indexed the last block.
	hh := &HashHeight{Hash: at.Hash, Height: at.Height}
	if !hh.Hash.IsEqual(c.g.chain.GenesisHash) {
		hh, err = nextCanonicalBlockheader(ctx, c.g, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("%v next block %v: %w", c, hh, err)
		}
	} else {
		// Some indexers use a different genesis, e.g. keystones. Will
		// be nil if there is no override.
		if c.genesis != nil {
			hh = c.genesis
		}
	}

	const percentage = 95 // flush cache at >95% capacity
	var blocksProcessed int
	for {
		log.Debugf("indexing %vs: %v", c, hh)

		bh, b, err := headerAndBlock(ctx, c.g.db, hh.Hash)
		if err != nil {
			return 0, last, err
		}

		// Some indexers require a fixup of the cache, e.g. utxo indexer.
		if err = c.p.fixupCacheHook(ctx, b, cache); err != nil {
			return 0, last, fmt.Errorf("process %v fixup %v: %w",
				c, hh, err)
		}

		// Index block
		if err = c.p.process(ctx, 1, b, cache); err != nil {
			return 0, last, fmt.Errorf("process %vs %v: %w", c, hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		_, _, pct := cache.Stats()
		if bh.Height%10000 == 0 || pct > percentage || blocksProcessed == 1 {
			log.Infof("%v indexer: %v cache %v%%", c, hh, pct)
		}

		// Exit if we processed the provided end hash or hit 95% cache full.
		if pct > percentage || endHash.IsEqual(&hh.Hash) {
			// Flush cache to disk
			last = hh
			break
		}

		// Move to next block
		hh, err = nextCanonicalBlockheader(ctx, c.g, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("%v next block %v: %w", c, hh, err)
		}
	}

	return blocksProcessed, last, nil
}

// parseBlocksReverse unindexes whatever type from the last processed block
// until the provided end hash, inclusive. It returns the number of blocks
// processed and the last hash it processed.
func (c *indexerCommon) parseBlocksReverse(ctx context.Context, endHash *chainhash.Hash, cache indexerCache) (int, *HashHeight, error) {
	log.Tracef("%v parseBlocksReverse", c)
	defer log.Tracef("%v parseBlocksReverse exit", c)

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	at, err := c.IndexerAt(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("%v index hash: %w", c, err)
	}

	const percentage = 95 // flush cache at >95% capacity
	var blocksProcessed int
	hh := &HashHeight{Hash: at.Hash, Height: at.Height}
	for {
		log.Debugf("unindexing %vs: %v", c, hh)

		hash := hh.Hash

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		bh, b, err := headerAndBlock(ctx, c.g.db, hh.Hash)
		if err != nil {
			return 0, last, err
		}

		if err = c.p.process(ctx, -1, b, cache); err != nil {
			return 0, last, fmt.Errorf("process %vs %v: %w", c, hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		_, _, pct := cache.Stats()
		if bh.Height%10000 == 0 || pct > percentage || blocksProcessed == 1 {
			log.Infof("%v unindexer: %v cache %v%%", c, hh, pct)
		}

		// Move to previous block
		height := bh.Height - 1
		pbh, err := c.g.db.BlockHeaderByHash(ctx, *bh.ParentHash())
		if err != nil {
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}
		hh.Hash = *pbh.BlockHash()
		hh.Height = pbh.Height

		// We check overflow AFTER obtaining the previous hash so that
		// we can update the database with the LAST processed block.
		if pct > percentage {
			last = hh
			// Flush to disk
			break
		}
	}

	return blocksProcessed, last, nil
}

// logMemStats pretty prints memory stats during the lengthy index operations.
func logMemStats() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// Go memory statistics are hard to interpret but the following list is
	// an approximation:
	//	Alloc is currently allocated memory
	// 	TotalAlloc is all memory allocated over time
	// 	Sys is basically a peak memory use
	log.Infof("Alloc = %v, TotalAlloc = %v, Sys = %v, NumGC = %v\n",
		humanize.IBytes(mem.Alloc),
		humanize.IBytes(mem.TotalAlloc),
		humanize.IBytes(mem.Sys),
		mem.NumGC)
}
