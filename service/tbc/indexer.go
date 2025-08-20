package tbc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type indexMode int

const (
	indexUtxos indexMode = iota
	indexTxs
	indexKeystones
)

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
	allocateEntries  func(int) any // allocate cache

	blockHeaderByModeIndex func(context.Context) (*tbcd.BlockHeader, error)
	blockModeUpdate        func(context.Context, int, any, chainhash.Hash) error
}

func (i *indexer) String() string {
	return i.indexer
}

func (s *Server) index(ctx context.Context, mode indexMode) error {
	var i *indexer
	switch mode {
	case indexKeystones:
		i = s.newKeystoneIndexer()
	default:
		return fmt.Errorf("unsuported indexer: %v", mode)
	}

	return i.modeIndexersToBest(ctx, nil) // XXX
}

func (s *Server) newKeystoneIndexer() *indexer {
	i := &indexer{
		indexer:                "keystone",
		s:                      s,
		enabled:                s.cfg.HemiIndex,
		maxCachedEntries:       s.cfg.MaxCachedKeystones,
		allocateEntries:        allocateCacheKeystones,
		blockHeaderByModeIndex: s.db.BlockHeaderByKeystoneIndex,
	}
	i.blockModeUpdate = i.blockKeystoneUpdate // XXX double eew
	return i
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

// allocateCacheKeystones allocates cahe for the keystones
func allocateCacheKeystones(maxCachedEntries int) any {
	return make(map[chainhash.Hash]tbcd.Keystone, maxCachedEntries)
}

// blockKeystoneUpdate calls the database update method
func (i *indexer) blockKeystoneUpdate(ctx context.Context, direction int, cache any, modeIndexHash chainhash.Hash) error {
	return i.s.db.BlockKeystoneUpdate(ctx, direction,
		cache.(map[chainhash.Hash]tbcd.Keystone), modeIndexHash)
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
	defer clear(es.(map[any]any))

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
		esCached := len(es.(map[any]any)) // XXX eew
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
	defer clear(es.(map[any]any))

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
		esCached := len(es.(map[any]any)) // XXX eew
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
