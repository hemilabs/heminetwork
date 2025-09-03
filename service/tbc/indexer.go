// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/dustin/go-humanize"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type AlreadyIndexingError string

func (aie AlreadyIndexingError) Error() string {
	return string(aie)
}

func (aie AlreadyIndexingError) Is(target error) bool {
	_, ok := target.(AlreadyIndexingError)
	return ok
}

var ErrAlreadyIndexing = AlreadyIndexingError("already indexing")

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

	// IndexAt returns the point the indexer is currently at.
	IndexAt(ctx context.Context) (*tbcd.BlockHeader, error)

	// Cache control
	cacheStats() (l int, c int, pct int)
	cacheFlush()

	// XXX i would be tickled if we can get rid of these inside the interface
	geometry() geometryParams                          // Return geometry parameters
	commit(context.Context, int, chainhash.Hash) error // Commit index cache to disk
	genesis() *HashHeight                              // Genesis override, like hemi

	process(context.Context, *btcutil.Block, int) error   // Process block
	fixupCacheHook(context.Context, *btcutil.Block) error // Fixup cache
}

// geometryParams conveniently wraps all parameters required to perform
// geometry operations.
type geometryParams struct {
	db    tbcd.Database
	chain *chaincfg.Params
}

// evaluateBlockHeaderIndex makes error handling of the various block header
// index calls generic.
func evaluateBlockHeaderIndex(g geometryParams, bh *tbcd.BlockHeader, err error) (*tbcd.BlockHeader, error) {
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return nil, err
		}
		bh = &tbcd.BlockHeader{
			Hash:   *g.chain.GenesisHash,
			Height: 0,
			Header: h2b(&g.chain.GenesisBlock.Header),
		}
	}
	return bh, nil
}

// toBest moves the indexer to the best tip.
func toBest(ctx context.Context, i Indexer) error {
	log.Tracef("%vIndexersToBest", i)
	defer log.Tracef("%vIndexersToBest exit", i)

	bhb, err := i.geometry().db.BlockHeaderBest(ctx)
	if err != nil {
		return err
	}

	// Find out where the indexer is at.
	indexerAt, err := i.IndexAt(ctx)
	if err != nil {
		return err
	}
	cp, err := findCanonicalParent(ctx, i.geometry(), indexerAt)
	if err != nil {
		return err
	}
	if !cp.Hash.IsEqual(&indexerAt.Hash) {
		log.Infof("Syncing %v index to: %v from: %v via: %v",
			i, bhb.HH(), indexerAt.HH(), cp.HH())
		// indexerAt is NOT on canonical chain, unwind first
		if err := windOrUnwind(ctx, i, cp.Hash); err != nil {
			return fmt.Errorf("%v indexer unwind: %w", i, err)
		}
	}
	// Index to best block
	if err := windOrUnwind(ctx, i, bhb.Hash); err != nil {
		return fmt.Errorf("%v indexer: %w", i, err)
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
func windOrUnwind(ctx context.Context, i Indexer, endHash chainhash.Hash) error {
	log.Tracef("%vIndexer", i)
	defer log.Tracef("%vIndexer exit", i)

	// XXX this is basically duplicate from modeIndexIsLinear

	if !i.Enabled() {
		return errors.New("disabled")
	}
	if !i.Indexing() {
		panic("indexing not true")
	}

	// Verify exit condition hash
	g := i.geometry()
	endBH, err := g.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return fmt.Errorf("blockheader end hash: %w", err)
	}

	// Verify start point is not after the end point
	indexerAt, err := i.IndexAt(ctx)
	if err != nil {
		return err
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := g.db.BlockHeaderByHash(ctx, indexerAt.Hash)
	if err != nil {
		return fmt.Errorf("blockheader %v hash: %w", i, err)
	}
	direction, err := indexIsLinear(ctx, g, indexerAt.Hash, endHash)
	if err != nil {
		return fmt.Errorf("%v index is linear: %w", i, err)
	}
	switch direction {
	case 1:
		return wind(ctx, i, startBH, endBH)
	case -1:
		return unwind(ctx, i, startBH, endBH)
	case 0:
		// Because we call modeIndexIsLinear we know it's the same block.
		return nil
	}

	return fmt.Errorf("invalid direction: %v", direction)
}

// wind moves the chain forward and process blocks to generate an index cache.
// When the cache is filled it flushes the cache to disk and repeats this
// process until it reaches endBH.
func wind(ctx context.Context, i Indexer, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("%v wind", i)
	defer log.Tracef("%v wind exit", i)

	if !i.Indexing() {
		// XXX this prob should be an error but pusnish bad callers for now
		panic(fmt.Sprintf("%vIndexerWind not true", i))
	}

	// Allocate here so that we don't waste space when not indexing.
	// XXX the cache *really* should become a list methinks.
	defer i.cacheFlush()

	log.Infof("Start indexing %vs at hash %v height %v", i, startBH, startBH.Height)
	log.Infof("End indexing %vs at hash %v height %v", i, endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := parseBlocks(ctx, i, endHash)
		if err != nil {
			return fmt.Errorf("%v index blocks: %w", i, err)
		}
		if blocksProcessed == 0 {
			return nil
		}

		cached, _, pct := i.cacheStats()
		log.Infof("%v indexer blocks processed %v in %v cached %v (%v%%) avg/blk %v",
			i, blocksProcessed, time.Since(start), cached, pct, cached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err := i.commit(ctx, 1, last.Hash); err != nil {
			return fmt.Errorf("block %v update: %w", i, err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing %vs complete %v took %v",
			i, cached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}

	return nil
}

// unwind moves the chain backward and reverses the wind process on the found
// blocks. When the cache is filled it flushes the cache to disk and repeats
// this process until it reaches endBH.
func unwind(ctx context.Context, i Indexer, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("%v Unwind", i)
	defer log.Tracef("%v Unwind exit", i)

	// XXX dedup with modeIndexerWind; it's basically the same code but with the direction, start anf endhas flipped

	if !i.Indexing() {
		// XXX this prob should be an error but pusnish bad callers for now
		panic(fmt.Sprintf("%vIndexerUnwind indexing not true", i))
	}
	// Allocate here so that we don't waste space when not indexing.
	defer i.cacheFlush()

	log.Infof("Start unwinding %v at hash %v height %v", i, startBH, startBH.Height)
	log.Infof("End unwinding %v at hash %v height %v", i, endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := parseBlocksReverse(ctx, i, endHash)
		if err != nil {
			return fmt.Errorf("unindex %vs in blocks: %w", i, err)
		}
		if blocksProcessed == 0 {
			return nil
		}

		cached, _, pct := i.cacheStats()
		log.Infof("%v unwinder blocks processed %v in %v cached %v cache (%v%%) avg/blk %v",
			i, blocksProcessed, time.Since(start), cached, pct, cached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = i.commit(ctx, -1, last.Hash); err != nil {
			return fmt.Errorf("block %v update: %w", i, err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing unwind %vs complete %v took %v",
			i, cached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}
	return nil
}

// parseBlocks indexes the block from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it processed.
func parseBlocks(ctx context.Context, i Indexer, endHash *chainhash.Hash) (int, *HashHeight, error) {
	log.Tracef("%v parseBlocks", i)
	defer log.Tracef("%v parseBlocks exit", i)

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	g := i.geometry()

	// Find start hash
	at, err := i.IndexAt(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("%v index hash: %w", i, err)
	}

	// If we have a real block move forward to the next block since we
	// already indexed the last block.
	hh := &HashHeight{Hash: at.Hash, Height: at.Height}
	if !hh.Hash.IsEqual(g.chain.GenesisHash) {
		hh, err = nextCanonicalBlockheader(ctx, g, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("%v next block %v: %w", i, hh, err)
		}
	} else {
		// Some indexers use a different genesis, e.g. keystones. Will
		// be nil if there is no override.
		if override := i.genesis(); override != nil {
			hh = override
		}
	}

	const percentage = 95 // flush cache at >95% capacity
	var blocksProcessed int
	for {
		log.Debugf("indexing %vs: %v", i, hh)

		bh, b, err := headerAndBlock(ctx, g.db, hh.Hash)
		if err != nil {
			return 0, last, err
		}

		if err = i.fixupCacheHook(ctx, b); err != nil {
			return 0, last, fmt.Errorf("process %v fixup %v: %w",
				i, hh, err)
		}

		// Index block
		if err = i.process(ctx, b, 1); err != nil {
			return 0, last, fmt.Errorf("process %vs %v: %w", i, hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		_, _, pct := i.cacheStats()
		if bh.Height%10000 == 0 || pct > percentage || blocksProcessed == 1 {
			log.Infof("%v indexer: %v cache %v%%", i, hh, pct)
		}

		// Exit if we processed the provided end hash or hit 95% cache full.
		if pct > percentage || endHash.IsEqual(&hh.Hash) {
			// Flush cache to disk
			last = hh
			break
		}

		// Move to next block
		hh, err = nextCanonicalBlockheader(ctx, i.geometry(), endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("%v next block %v: %w", i, hh, err)
		}
	}

	return blocksProcessed, last, nil
}

// parseBlocksReverse unindexes whatever type from the last processed block
// until the provided end hash, inclusive. It returns the number of blocks
// processed and the last hash it processed.
func parseBlocksReverse(ctx context.Context, i Indexer, endHash *chainhash.Hash) (int, *HashHeight, error) {
	log.Tracef("%v parseBlocksReverse", i)
	defer log.Tracef("%v parseBlocksReverse exit", i)

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	g := i.geometry()

	// Find start hash
	at, err := i.IndexAt(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("%v index hash: %w", i, err)
	}

	const percentage = 95 // flush cache at >95% capacity
	var blocksProcessed int
	hh := &HashHeight{Hash: at.Hash, Height: at.Height}
	for {
		log.Debugf("unindexing %vs: %v", i, hh)

		hash := hh.Hash

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		bh, b, err := headerAndBlock(ctx, g.db, hh.Hash)
		if err != nil {
			return 0, last, err
		}

		err = i.process(ctx, b, -1)
		if err != nil {
			return 0, last, fmt.Errorf("process %vs %v: %w", i, hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		_, _, pct := i.cacheStats()
		if bh.Height%10000 == 0 || pct > percentage || blocksProcessed == 1 {
			log.Infof("%v unindexer: %v cache %v%%", i, hh, pct)
		}

		// Move to previous block
		height := bh.Height - 1
		pbh, err := g.db.BlockHeaderByHash(ctx, *bh.ParentHash())
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
