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
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

//type indexMode int
//
//const (
//	indexUtxos indexMode = iota
//	indexTxs
//	indexKeystones
//)

// indexer is a collection of function pointers and constants that abstract the
// nearly identical index functions.
//
// This is obviously shitty but we need an in-between version that shows us
// where the bodies are.
type indexer struct {
	indexer string // Name of indexer that is running

	s                *Server
	enabled          bool          // Index allowed to run, e.g. cfg.HemiIndex
	maxCachedEntries int           // Max index size, e.g. cfg.MaxCachedKeystones
	genesis          *HashHeight   // Genesis override
	allocateEntries  func(int) any // Allocate a cache
	lenEntries       func(any) int // Return actual used cache entries
	clearEntries     func(any)     // Delete all items in cache

	blockHeaderByModeIndex func(context.Context) (*tbcd.BlockHeader, error)
	blockModeUpdate        func(context.Context, int, any, chainhash.Hash) error
	processMode            func(context.Context, *btcutil.Block, int, any) error
	fixupCache             func(context.Context, *btcutil.Block, any) error
}

func (i *indexer) String() string {
	return i.indexer
}

//func (s *Server) indexToBest(ctx context.Context, mode indexMode) error {
//	var i *indexer
//	switch mode {
//	case indexKeystones:
//		i = s.newKeystoneIndexer()
//	default:
//		return fmt.Errorf("unsuported indexer: %v", mode)
//	}
//
//	return i.modeIndexersToBest(ctx, nil) // XXX
//}

func (s *Server) newUtxoIndexer() *indexer {
	i := &indexer{
		indexer:                "utxo",
		s:                      s,
		enabled:                true,
		maxCachedEntries:       s.cfg.MaxCachedTxs,
		allocateEntries:        allocateCacheUtxos,
		lenEntries:             lenCacheUtxos,
		clearEntries:           clearCacheUtxos,
		blockHeaderByModeIndex: s.db.BlockHeaderByUtxoIndex,
	}
	i.blockModeUpdate = i.blockUtxoUpdate // XXX double eew
	i.processMode = i.processUtxos        // XXX double eew
	i.fixupCache = i.fixupUtxos           // XXX double eew
	return i
}

// allocateCacheUtxos allocates cahe for the txs
func allocateCacheUtxos(maxCachedEntries int) any {
	return make(map[tbcd.Outpoint]tbcd.CacheOutput, maxCachedEntries)
}

// lenCacheUtxos returns the entry count in the tx cache.
func lenCacheUtxos(cache any) int {
	return len(cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

// clearCacheUtxos empties cached txs to lower memory pressure.
func clearCacheUtxos(cache any) {
	clear(cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

// blockUtxoUpdate calls the database update method
func (i *indexer) blockUtxoUpdate(ctx context.Context, direction int, cache any, modeIndexHash chainhash.Hash) error {
	return i.s.db.BlockUtxoUpdate(ctx, direction,
		cache.(map[tbcd.Outpoint]tbcd.CacheOutput), modeIndexHash)
}

func (i *indexer) unprocessUtxos(ctx context.Context, block *btcutil.Block, cache any) error {
	return i.s.unprocessUtxos(ctx, block, cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

// processUtxo walks a block and peels out the relevant keystones that
// will be stored in the database.
func (i *indexer) processUtxos(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	if direction == -1 {
		return i.unprocessUtxos(ctx, block, cache)
	}
	return processUtxos(block, direction, cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

func (i *indexer) fixupUtxos(ctx context.Context, block *btcutil.Block, cache any) error {
	return i.s.fixupCache(ctx, block, cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

func (s *Server) newTxIndexer() *indexer {
	i := &indexer{
		indexer:                "tx",
		s:                      s,
		enabled:                true,
		maxCachedEntries:       s.cfg.MaxCachedTxs,
		allocateEntries:        allocateCacheTxs,
		lenEntries:             lenCacheTxs,
		clearEntries:           clearCacheTxs,
		blockHeaderByModeIndex: s.db.BlockHeaderByTxIndex,
	}
	i.blockModeUpdate = i.blockTxUpdate // XXX double eew
	i.processMode = i.processTxs        // XXX double eew
	return i
}

// allocateCacheTxs allocates cahe for the txs
func allocateCacheTxs(maxCachedEntries int) any {
	return make(map[tbcd.TxKey]*tbcd.TxValue, maxCachedEntries)
}

// lenCacheTxs returns the entry count in the tx cache.
func lenCacheTxs(cache any) int {
	return len(cache.(map[tbcd.TxKey]*tbcd.TxValue))
}

// clearCacheTxs empties cached txs to lower memory pressure.
func clearCacheTxs(cache any) {
	clear(cache.(map[tbcd.TxKey]*tbcd.TxValue))
}

// blockTxUpdate calls the database update method
func (i *indexer) blockTxUpdate(ctx context.Context, direction int, cache any, modeIndexHash chainhash.Hash) error {
	return i.s.db.BlockTxUpdate(ctx, direction,
		cache.(map[tbcd.TxKey]*tbcd.TxValue), modeIndexHash)
}

// processTx walks a block and peels out the relevant keystones that
// will be stored in the database.
func (i *indexer) processTxs(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	return processTxs(block, direction, cache.(map[tbcd.TxKey]*tbcd.TxValue))
}

func (s *Server) newKeystoneIndexer() *indexer {
	i := &indexer{
		indexer:                "keystone",
		s:                      s,
		enabled:                s.cfg.HemiIndex,
		maxCachedEntries:       s.cfg.MaxCachedKeystones,
		genesis:                s.hemiGenesis,
		allocateEntries:        allocateCacheKeystones,
		lenEntries:             lenCacheKeystones,
		clearEntries:           clearCacheKeystones,
		blockHeaderByModeIndex: s.db.BlockHeaderByKeystoneIndex,
	}
	i.blockModeUpdate = i.blockKeystoneUpdate // XXX double eew
	i.processMode = i.processKeystones        // XXX double eew
	return i
}

// allocateCacheKeystones allocates cahe for the keystones
func allocateCacheKeystones(maxCachedEntries int) any {
	return make(map[chainhash.Hash]tbcd.Keystone, maxCachedEntries)
}

// lenCacheKeystones returns the entry count in the keystone cache.
func lenCacheKeystones(cache any) int {
	return len(cache.(map[chainhash.Hash]tbcd.Keystone))
}

// clearCacheKeystones empties cached keystones to lower memory pressure.
func clearCacheKeystones(cache any) {
	clear(cache.(map[chainhash.Hash]tbcd.Keystone))
}

// processKeystones walks a block and peels out the relevant keystones that
// will be stored in the database.
func (i *indexer) processKeystones(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	return processKeystones(block, direction, cache.(map[chainhash.Hash]tbcd.Keystone))
}

// blockKeystoneUpdate calls the database update method
func (i *indexer) blockKeystoneUpdate(ctx context.Context, direction int, cache any, modeIndexHash chainhash.Hash) error {
	return i.s.db.BlockKeystoneUpdate(ctx, direction,
		cache.(map[chainhash.Hash]tbcd.Keystone), modeIndexHash)
}

// modeIndexHash replaces (Utxo|Tx|Keystone)IndexHash
func (i *indexer) modeIndexHash(ctx context.Context) (*HashHeight, error) {
	bh, err := i.blockHeaderByModeIndex(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return nil, err
		}
		bh = &tbcd.BlockHeader{
			Hash:   *i.s.chainParams.GenesisHash,
			Height: 0,
			Header: h2b(&i.s.chainParams.GenesisBlock.Header),
		}
	}
	return HashHeightFromBlockHeader(bh), nil
}

// modeIndexersToBest replaces (Utxo|Tx|Keystone)IndexersToBest
func (i *indexer) modeIndexersToBest(ctx context.Context, bhb *tbcd.BlockHeader) error {
	log.Tracef("%vIndexersToBest", i)
	defer log.Tracef("%vIndexersToBest exit", i)

	// Find out where the indexer is at.
	modeHH, err := i.modeIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("%v index hash: %w", i, err)
	}
	modeBH, err := i.s.db.BlockHeaderByHash(ctx, modeHH.Hash)
	if err != nil {
		return err
	}
	cp, err := i.s.findCanonicalParent(ctx, modeBH)
	if err != nil {
		return err
	}
	if !cp.Hash.IsEqual(&modeBH.Hash) {
		log.Infof("Syncing %v index to: %v from: %v via: %v",
			i, bhb.HH(), modeBH.HH(), cp.HH())
		// modeBH is NOT on canonical chain, unwind first
		if err := i.modeIndexer(ctx, cp.Hash); err != nil {
			return fmt.Errorf("%v indexer unwind: %w", i, err)
		}
	}
	// Index to best block
	if err := i.modeIndexer(ctx, bhb.Hash); err != nil {
		return fmt.Errorf("%v indexer: %w", i, err)
	}

	return nil
}

// modeIndexer replaces (Utxo|Tx|Keystone)Indexer
func (i *indexer) modeIndexer(ctx context.Context, endHash chainhash.Hash) error {
	log.Tracef("%vIndexer", i)
	defer log.Tracef("%vIndexer exit", i)

	// XXX this is basically duplicate from modeIndexIsLinear

	if !i.enabled {
		return errors.New("disabled")
	}
	i.s.mtx.Lock()
	if !i.s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		i.s.mtx.Unlock()
		panic("indexing not true")
	}
	i.s.mtx.Unlock()

	// Verify exit condition hash
	endBH, err := i.s.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return fmt.Errorf("blockheader end hash: %w", err)
	}

	// Verify start point is not after the end point
	modeHH, err := i.modeIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("%v index hash: %w", i, err)
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := i.s.db.BlockHeaderByHash(ctx, modeHH.Hash)
	if err != nil {
		return fmt.Errorf("blockheader %v hash: %w", i, err)
	}
	direction, err := i.modeIndexIsLinear(ctx, endHash)
	if err != nil {
		return fmt.Errorf("%v index is linear: %w", i, err)
	}
	switch direction {
	case 1:
		return i.modeIndexerWind(ctx, startBH, endBH)
	case -1:
		return i.modeIndexerUnwind(ctx, startBH, endBH)
	case 0:
		// Because we call modeIndexIsLinear we know it's the same block.
		return nil
	}

	return fmt.Errorf("invalid direction: %v", direction)
}

// modeIndexIsLinear replaces (Utxo|Tx|Keystone)IndexIndexIsLinear
func (i *indexer) modeIndexIsLinear(ctx context.Context, endHash chainhash.Hash) (int, error) {
	log.Tracef("%vIndexIsLinear", i)
	defer log.Tracef("%vIndexIsLinear exit", i)

	// Verify start point is not after the end point
	modeHH, err := i.modeIndexHash(ctx)
	if err != nil {
		return 0, fmt.Errorf("%v index hash: %w", i, err)
	}

	return i.s.IndexIsLinear(ctx, modeHH.Hash, endHash)
}

// modeIndexerWind replaces (Utxo|Tx|Keystone)IndexerWind
func (i *indexer) modeIndexerWind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("%vIndexerWind", i)
	defer log.Tracef("%vkeystoneIndexerWind exit", i)

	i.s.mtx.Lock()
	if !i.s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		i.s.mtx.Unlock()
		panic(fmt.Sprintf("%vIndexerWind not true", i))
	}
	i.s.mtx.Unlock()

	// Allocate here so that we don't waste space when not indexing.
	// XXX the cache *really* should become a list methinks.
	es := i.allocateEntries(i.maxCachedEntries)
	defer i.clearEntries(es)

	log.Infof("Start indexing %vs at hash %v height %v", i, startBH, startBH.Height)
	log.Infof("End indexing %vs at hash %v height %v", i, endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := i.indexModeInBlocks(ctx, endHash, es)
		if err != nil {
			return fmt.Errorf("%v index blocks: %w", i, err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		esCached := i.lenEntries(es)
		log.Infof("%v indexer blocks processed %v in %v cached %v cache unused %v avg/blk %v",
			i, blocksProcessed, time.Since(start), esCached,
			i.maxCachedEntries-esCached, esCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = i.blockModeUpdate(ctx, 1, es, last.Hash); err != nil {
			return fmt.Errorf("block %v update: %w", i, err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing %vs complete %v took %v",
			i, esCached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}

	return nil
}

func (i *indexer) modeIndexerUnwind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("%vIndexerUnwind", i)
	defer log.Tracef("%vIndexerUnwind exit", i)

	// XXX dedup with modeIndexerWind; it's basically the same code but with the direction, start anf endhas flipped

	i.s.mtx.Lock()
	if !i.s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		i.s.mtx.Unlock()
		panic(fmt.Sprintf("%vIndexerUnwind indexing not true", i))
	}
	i.s.mtx.Unlock()
	// Allocate here so that we don't waste space when not indexing.
	es := i.allocateEntries(i.maxCachedEntries)
	defer i.clearEntries(es)

	log.Infof("Start unwinding %v at hash %v height %v", i, startBH, startBH.Height)
	log.Infof("End unwinding %v at hash %v height %v", i, endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := i.unindexModeInBlocks(ctx, endHash, es)
		if err != nil {
			return fmt.Errorf("unindex %vs in blocks: %w", i, err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		esCached := i.lenEntries(es)
		log.Infof("%v unwinder blocks processed %v in %v cached %v cache unused %v avg/blk %v",
			blocksProcessed, time.Since(start), esCached,
			i.maxCachedEntries-esCached, esCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = i.blockModeUpdate(ctx, -1, es, last.Hash); err != nil {
			return fmt.Errorf("block %v update: %w", i, err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing unwind %vs complete %v took %v",
			i, esCached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}
	return nil
}

// indexModeInBlocks indexes txs from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it processed.
// Replaces index(Utxos|Txs|Keystones)InBlocks
func (i *indexer) indexModeInBlocks(ctx context.Context, endHash *chainhash.Hash, cache any) (int, *HashHeight, error) {
	log.Tracef("%v indexModeInBlocks", i)
	defer log.Tracef("%v indexModeInBlocks exit", i)

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	modeHH, err := i.modeIndexHash(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("%v index hash: %w", i, err)
	}

	// If we have a real block move forward to the next block since we
	// already indexed the last block.
	hh := modeHH
	if !hh.Hash.IsEqual(i.s.chainParams.GenesisHash) {
		hh, err = i.s.nextCanonicalBlockheader(ctx, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("%v next block %v: %w", i, hh, err)
		}
	} else {
		// Some indexers use a different genesis, e.g. keystones
		if i.genesis != nil {
			hh = i.genesis
		}
	}

	percentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	for {
		log.Debugf("indexing %vs: %v", i, hh)

		bh, b, err := i.s.headerAndBlock(ctx, hh.Hash)
		if err != nil {
			return 0, last, err
		}

		if i.fixupCache != nil {
			err = i.fixupCache(ctx, b, cache)
			if err != nil {
				return 0, last, fmt.Errorf("process %v fixup %v: %w",
					i, hh, err)
			}
		}
		// Index block
		err = i.processMode(ctx, b, 1, cache)
		if err != nil {
			return 0, last, fmt.Errorf("process %vs %v: %w", i, hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := i.lenEntries(cache) * 100 / i.maxCachedEntries
		if bh.Height%10000 == 0 || cp > percentage || blocksProcessed == 1 {
			log.Infof("%v indexer: %v cache %v%%", i, hh, cp)
		}

		if cp > percentage {
			// Set cache to the largest capacity seen
			i.maxCachedEntries = max(i.lenEntries(cache), i.maxCachedEntries)
			last = hh
			// Flush
			break
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hh.Hash) {
			last = hh
			break
		}

		// Move to next block
		hh, err = i.s.nextCanonicalBlockheader(ctx, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("%v next block %v: %w", i, hh, err)
		}
	}

	return blocksProcessed, last, nil
}

// unindexModeInBlocks unindexes whatever type from the last processed block
// until the provided end hash, inclusive. It returns the number of blocks
// processed and the last hash it processed.
// Replaces index(Utxos|Txs|Keystones)InBlocks
func (i *indexer) unindexModeInBlocks(ctx context.Context, endHash *chainhash.Hash, cache any) (int, *HashHeight, error) {
	log.Tracef("%v unindexModeInBlocks", i)
	defer log.Tracef("%v unindexModeInBlocks exit", i)

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	ksHH, err := i.modeIndexHash(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("%v index hash: %w", i, err)
	}

	percentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	hh := ksHH
	for {
		log.Debugf("unindexing %vs: %v", i, hh)

		hash := hh.Hash

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		bh, b, err := i.s.headerAndBlock(ctx, hh.Hash)
		if err != nil {
			return 0, last, err
		}

		err = i.processMode(ctx, b, -1, cache)
		if err != nil {
			return 0, last, fmt.Errorf("process %vs %v: %w", i, hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := i.lenEntries(cache) * 100 / i.maxCachedEntries
		if bh.Height%10000 == 0 || cp > percentage || blocksProcessed == 1 {
			log.Infof("%v unindexer: %v cache %v%%", i, hh, cp)
		}

		// Move to previous block
		height := bh.Height - 1
		pbh, err := i.s.db.BlockHeaderByHash(ctx, *bh.ParentHash())
		if err != nil {
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}
		hh.Hash = *pbh.BlockHash()
		hh.Height = pbh.Height

		// We check overflow AFTER obtaining the previous hash so that
		// we can update the database with the LAST processed block.
		if cp > percentage {
			// Set cache to the largest mode capacity seen
			i.maxCachedEntries = max(i.lenEntries(cache), i.maxCachedEntries)
			last = hh
			// Flush
			break
		}
	}

	return blocksProcessed, last, nil
}
