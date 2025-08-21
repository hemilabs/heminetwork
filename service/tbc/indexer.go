// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/dustin/go-humanize"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type Cache interface {
	Clear()
	Length() int
	Capacity() int
	Generic() any
}

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

type Indexer interface {
	ToBest(context.Context, chainhash.Hash) error  // Move index to best hash, autoresolves forks
	ToHash(context.Context, chainhash.Hash) error  // Manually move index from current height hash
	At(context.Context) (*tbcd.BlockHeader, error) // Current index location
	Indexing() bool                                // Returns if indexing is active
	Enabled() bool                                 // Returns if index is enabled

	geometry() geometryParams // Return geometry parameters
	cache() Cache
}

// XXX implement cache interface?

// geometryParams conviniently wraps all parameters required to perform
// geometry operations.
type geometryParams struct {
	db    tbcd.Database
	chain *chaincfg.Params
}

type utxoIndexer struct {
	// common
	mtx             sync.RWMutex
	indexer         string
	indexing        bool
	enabled         bool
	maxCacheEntries int
	c               Cache

	// geometry
	g geometryParams

	// utxo indexer only
}

var _ Indexer = (*utxoIndexer)(nil)

func NewUtxoIndexer(chain *chaincfg.Params, cacheLen int, db tbcd.Database) (Indexer, error) {
	return &utxoIndexer{
		indexer:  "utxo",
		indexing: false,
		enabled:  true,
		c:        NewUtxoCache(cacheLen),
		g: geometryParams{
			db:    db,
			chain: chain,
		},
	}, nil
}

func (i *utxoIndexer) geometry() geometryParams {
	return i.g
}

func (i *utxoIndexer) cache() Cache {
	return i.c
}

func (i *utxoIndexer) String() string {
	return i.indexer
}

func (i *utxoIndexer) ToBest(context.Context, chainhash.Hash) error {
	return fmt.Errorf("ToBest not yet")
}

func (i *utxoIndexer) ToHash(context.Context, chainhash.Hash) error {
	return fmt.Errorf("ToHash not yet")
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

// indexersToBest replaces (Utxo|Tx|Keystone)IndexersToBest
func indexersToBest(ctx context.Context, i Indexer, bhb *tbcd.BlockHeader) error {
	log.Tracef("%vIndexersToBest", i)
	defer log.Tracef("%vIndexersToBest exit", i)

	// Find out where the indexer is at.
	indexerAt, err := i.At(ctx)
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

func findCanonicalParent(ctx context.Context, g geometryParams, bh *tbcd.BlockHeader) (*tbcd.BlockHeader, error) {
	log.Tracef("findCanonicalParent %v", bh)

	// Genesis is always canonical.
	if bh.Hash.IsEqual(g.chain.GenesisHash) {
		return bh, nil
	}

	bhb, err := g.db.BlockHeaderBest(ctx)
	if err != nil {
		return nil, err
	}
	log.Debugf("findCanonicalParent %v @ %v best %v @ %v",
		bh, bh.Height, bhb, bhb.Height)
	for {
		canonical, err := isCanonical(ctx, g, bh)
		if err != nil {
			return nil, err
		}
		if canonical {
			log.Tracef("findCanonicalParent exit %v", bh)
			return bh, nil
		}
		bh, err = findCommonParent(ctx, g, bhb, bh)
		if err != nil {
			return nil, err
		}
	}
}

// isCanonical uses checkpoints to determine if a block is on the canonical
// chain. This is a expensive call hence it tries to use checkpoints to short
// circuit the check.
func isCanonical(ctx context.Context, g geometryParams, bh *tbcd.BlockHeader) (bool, error) {
	var (
		bhb *tbcd.BlockHeader
		err error
	)
	ncp := nextCheckpoint(bh, g.chain.Checkpoints)
	if ncp == nil {
		// Use best since we do not have a best checkpoint
		bhb, err = g.db.BlockHeaderBest(ctx)
	} else {
		bhb, err = g.db.BlockHeaderByHash(ctx, *ncp.Hash)
	}
	if err != nil {
		return false, err
	}

	// Basic shortcircuit
	if bhb.Height < bh.Height {
		// We either hit a race or the caller did something wrong.
		// Either way, it cannot be canonical.
		log.Debugf("best height less than provided height: %v < %v",
			bhb.Height, bh.Height)
		return false, nil
	}
	if bhb.Hash.IsEqual(&bh.Hash) {
		// Self == best
		return true, nil
	}

	genesisHash := previousCheckpoint(bh, g.chain.Checkpoints).Hash // either genesis or a snapshot block

	// Move best block header backwards until we find bh.
	log.Debugf("isCanonical best %v bh %v genesis %v", bhb.HH(), bh.HH(), genesisHash)
	for {
		if bhb.Height <= bh.Height {
			return false, nil
		}
		bhb, err = g.db.BlockHeaderByHash(ctx, *bhb.ParentHash())
		if err != nil {
			return false, err
		}
		if bhb.Hash.IsEqual(genesisHash) {
			return false, nil
		}
		if bhb.Hash.IsEqual(&bh.Hash) {
			return true, nil
		}
	}
}

func findCommonParent(ctx context.Context, g geometryParams, bhX, bhY *tbcd.BlockHeader) (*tbcd.BlockHeader, error) {
	// This function has one odd corner case. If bhX and bhY are both on a
	// "long" chain without multiple blockheaders it will terminate on the
	// first height that has a single blockheader. This is to be expected!
	// This function "should" be called between forking blocks and then
	// it'll find the first common parent.

	// This function assumes that the highest block height connects to the
	// lowest block height.

	// 0. If bhX and bhY are the same return bhX.
	if bhX.Hash.IsEqual(&bhY.Hash) {
		return bhX, nil
	}

	// 1. Find lowest height between X and Y.
	h := min(bhX.Height, bhY.Height)

	// 2. Walk chain back until X and Y point to the same parent.
	for {
		bhs, err := g.db.BlockHeadersByHeight(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("block headers by height: %w", err)
		}
		if bhs[0].Hash.IsEqual(g.chain.GenesisHash) {
			if h != 0 {
				panic("height 0 not genesis")
			}
			return nil, fmt.Errorf("genesis")
		}

		// See if all blockheaders share a common parent.
		equals := 0
		var ph *chainhash.Hash
		for k := range bhs {
			if k == 0 {
				ph = bhs[k].ParentHash()
			}
			if !ph.IsEqual(bhs[k].ParentHash()) {
				break
			}
			equals++
		}
		if equals == len(bhs) {
			// All blockheaders point to the same parent.
			return g.db.BlockHeaderByHash(ctx, *ph)
		}

		// Decrease height
		h--
	}
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
		// XXX this prob should be an error but pusnish bad callers for now
		panic("indexing not true")
	}

	// Verify exit condition hash
	g := i.geometry()
	endBH, err := g.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return fmt.Errorf("blockheader end hash: %w", err)
	}

	// Verify start point is not after the end point
	indexerAt, err := i.At(ctx)
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
		return i.modeIndexerUnwind(ctx, startBH, endBH)
	case 0:
		// Because we call modeIndexIsLinear we know it's the same block.
		return nil
	}

	return fmt.Errorf("invalid direction: %v", direction)
}

func indexIsLinear(ctx context.Context, g geometryParams, startHash, endHash chainhash.Hash) (int, error) {
	log.Tracef("indexIsLinear")
	defer log.Tracef("indexIsLinear exit")

	// Verify exit condition hash
	endBH, err := g.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return 0, fmt.Errorf("blockheader hash: %w", err)
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := g.db.BlockHeaderByHash(ctx, startHash)
	if err != nil {
		return 0, fmt.Errorf("blockheader hash: %w", err)
	}
	// Short circuit if the block hash is the same.
	if startBH.BlockHash().IsEqual(endBH.BlockHash()) {
		return 0, nil
	}

	direction := endBH.Difficulty.Cmp(&startBH.Difficulty)
	log.Debugf("startBH %v %v", startBH.Height, startBH)
	log.Debugf("endBH %v %v", endBH.Height, endBH)
	log.Debugf("direction %v", direction)
	// Expensive linear test, this needs some performance love. We can
	// memoize it keep snapshot heights whereto we know the chain is
	// synced. For now just do the entire thing.

	// Always walk backwards because it's only a single lookup.
	var h, e *chainhash.Hash
	switch direction {
	case 1:
		h = endBH.BlockHash()
		e = startBH.BlockHash()
	case -1:
		h = startBH.BlockHash()
		e = endBH.BlockHash()
	default:
		// This is a fork and thus not linear.
		// XXX remove this once we determine if ErrNotLinear can happen here.
		log.Infof("startBH %v %v", startBH, startBH.Difficulty)
		log.Infof("endBH %v %v", endBH, endBH.Difficulty)
		log.Infof("direction %v", direction)
		return 0, NotLinearError(fmt.Sprintf("start %v end %v direction %v",
			startBH, endBH, direction))
	}
	for {
		bh, err := g.db.BlockHeaderByHash(ctx, *h)
		if err != nil {
			return -1, fmt.Errorf("block header by hash: %w", err)
		}
		h = bh.ParentHash()
		if h.IsEqual(e) {
			return direction, nil
		}
		if h.IsEqual(g.chain.GenesisHash) {
			return 0, NotLinearError(fmt.Sprintf("start %v end %v "+
				"direction %v: genesis", startBH, endBH, direction))
		}
	}
}

func wind(ctx context.Context, i Indexer, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("%v wind", i)
	defer log.Tracef("%v wind exit", i)

	if !i.Indexing() {
		// XXX this prob should be an error but pusnish bad callers for now
		panic(fmt.Sprintf("%vIndexerWind not true", i))
	}

	// Allocate here so that we don't waste space when not indexing.
	// XXX the cache *really* should become a list methinks.
	es := i.cache().Generic()
	defer i.cache().Clear()

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
		esCached := i.cache().Length()
		log.Infof("%v indexer blocks processed %v in %v cached %v cache unused %v avg/blk %v",
			i, blocksProcessed, time.Since(start), esCached,
			i.cache().Capacity()-esCached, esCached/blocksProcessed)

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

/////////////////////////////////////////////////////////////////
// DELETE BELOW THIS LINE
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
type _indexer struct {
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

func (i *_indexer) String() string {
	return i.indexer
}

//func (s *Server) indexToBest(ctx context.Context, mode indexMode) error {
//	var i *_indexer
//	switch mode {
//	case indexKeystones:
//		i = s.newKeystoneIndexer()
//	default:
//		return fmt.Errorf("unsuported indexer: %v", mode)
//	}
//
//	return i.modeIndexersToBest(ctx, nil) // XXX
//}

func (s *Server) newUtxoIndexer() *_indexer {
	i := &_indexer{
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
func (i *_indexer) blockUtxoUpdate(ctx context.Context, direction int, cache any, modeIndexHash chainhash.Hash) error {
	return i.s.db.BlockUtxoUpdate(ctx, direction,
		cache.(map[tbcd.Outpoint]tbcd.CacheOutput), modeIndexHash)
}

func (i *_indexer) unprocessUtxos(ctx context.Context, block *btcutil.Block, cache any) error {
	return i.s.unprocessUtxos(ctx, block, cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

// processUtxo walks a block and peels out the relevant keystones that
// will be stored in the database.
func (i *_indexer) processUtxos(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	if direction == -1 {
		return i.unprocessUtxos(ctx, block, cache)
	}
	return processUtxos(block, direction, cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

func (i *_indexer) fixupUtxos(ctx context.Context, block *btcutil.Block, cache any) error {
	return i.s.fixupCache(ctx, block, cache.(map[tbcd.Outpoint]tbcd.CacheOutput))
}

func (s *Server) newTxIndexer() *_indexer {
	i := &_indexer{
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
func (i *_indexer) blockTxUpdate(ctx context.Context, direction int, cache any, modeIndexHash chainhash.Hash) error {
	return i.s.db.BlockTxUpdate(ctx, direction,
		cache.(map[tbcd.TxKey]*tbcd.TxValue), modeIndexHash)
}

// processTx walks a block and peels out the relevant keystones that
// will be stored in the database.
func (i *_indexer) processTxs(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	return processTxs(block, direction, cache.(map[tbcd.TxKey]*tbcd.TxValue))
}

func (s *Server) newKeystoneIndexer() *_indexer {
	i := &_indexer{
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
func (i *_indexer) processKeystones(ctx context.Context, block *btcutil.Block, direction int, cache any) error {
	return processKeystones(block, direction, cache.(map[chainhash.Hash]tbcd.Keystone))
}

// blockKeystoneUpdate calls the database update method
func (i *_indexer) blockKeystoneUpdate(ctx context.Context, direction int, cache any, modeIndexHash chainhash.Hash) error {
	return i.s.db.BlockKeystoneUpdate(ctx, direction,
		cache.(map[chainhash.Hash]tbcd.Keystone), modeIndexHash)
}

// modeIndexHash replaces (Utxo|Tx|Keystone)IndexHash
func (i *_indexer) modeIndexHash(ctx context.Context) (*HashHeight, error) {
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
func (i *_indexer) modeIndexersToBest(ctx context.Context, bhb *tbcd.BlockHeader) error {
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
func (i *_indexer) modeIndexer(ctx context.Context, endHash chainhash.Hash) error {
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
func (i *_indexer) modeIndexIsLinear(ctx context.Context, endHash chainhash.Hash) (int, error) {
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
func (i *_indexer) modeIndexerWind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
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

func (i *_indexer) modeIndexerUnwind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
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
func (i *_indexer) indexModeInBlocks(ctx context.Context, endHash *chainhash.Hash, cache any) (int, *HashHeight, error) {
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
func (i *_indexer) unindexModeInBlocks(ctx context.Context, endHash *chainhash.Hash, cache any) (int, *HashHeight, error) {
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
