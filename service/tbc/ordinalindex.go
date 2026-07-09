// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/lru"
)

type ordinalIndexer struct {
	indexerCommon

	runCtx          context.Context
	cacheCapacity   int
	workCache       map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue
	computeInscSat  func(ctx context.Context, txid chainhash.Hash, inputIndex uint32) (uint64, error)
	watermarkGap    time.Duration
	populating      atomic.Uint32 // reentrancy guard for onSyncComplete
	verifyBigO      bool          // cross-check 'O' outputValue against the tx index
	cacheByteBudget int           // cache flush budget in bytes; 0 = default

	// cache is the live write cache created by newCache; retained so
	// readCacheInfo can report the byte dimension. Accessed only from
	// the indexer goroutine.
	cache *OrdinalCache

	// Watermark state. Loaded from DB on first access, written atomically
	// via the 'm' prefix OrdinalKey in the ordinal cache.
	watermark      *uint32 // nil = not loaded yet
	watermarkDirty bool

	// outputValueCache maps txid → output values for all outputs of that
	// tx. When inputOutputValue misses, it fetches the block, finds the
	// tx, and caches ALL output values. Subsequent inputs spending
	// different vouts from the same parent tx are O(1) cache hits.
	// LRU-evicted by byte cost; survives across blocks.
	outputValueCache *lru.Cache[chainhash.Hash, []uint64]
}

var (
	_ Indexer = (*ordinalIndexer)(nil)
	_ indexer = (*ordinalIndexer)(nil)
)

// defaultOrdinalCacheByteBudget caps the approximate bytes of key/value
// payload held in the ordinal cache between flushes. Sub-entry counts
// alone do not bound memory: 'i' values carry inscription bodies
// (multi-KB average, hundreds of KB max), so a count cap is anywhere
// from hundreds of MB to tens of GB depending on chain content. The
// flush decision triggers on whichever budget (count or bytes) fills
// first. Per-block overshoot is bounded by consensus (block size).
const defaultOrdinalCacheByteBudget = 1 << 30 // 1 GiB

// ordinalCacheEntryOverhead approximates the fixed heap cost of one
// OrdinalCacheEntry: three map headers plus buckets, the outpoint key
// and the entry pointer in the top-level map.
const ordinalCacheEntryOverhead = 400

// ordinalCacheSubEntryOverhead approximates the per-sub-entry map
// bookkeeping (key, value header, bucket share).
const ordinalCacheSubEntryOverhead = 64

// OrdinalCache wraps map[Outpoint]*OrdinalCacheEntry for the indexer
// framework. Len() returns a running count of sub-entry writes
// (inscriptions + predecessors + aux) — this drives the flush decision
// so the cache accurately reflects DB operation count, not outpoint count.
// Overwrites cause slight overcount; flush threshold is 95% so early
// flushing is harmless. A byte budget bounds memory independently of
// the count: Stats reports the fuller of the two dimensions.
type OrdinalCache struct {
	capacity   int
	byteBudget int
	entryCount int
	byteCount  int
	m          map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry
}

// ordinalCachePresize is the initial bucket reservation for the cache
// map. Deliberately modest: the map grows to what a window actually
// needs and Clear releases it again.
const ordinalCachePresize = 8192

// NewOrdinalCache returns a cache that flushes on whichever budget
// fills first: capacity sub-entries or byteBudget approximate bytes.
// byteBudget <= 0 selects the default.
func NewOrdinalCache(capacity, byteBudget int) *OrdinalCache {
	if capacity < 1 {
		// Enforce the divide-by-zero invariant at the single
		// construction point; NewServer validates the configured
		// value with a proper error.
		capacity = defaultMaxCachedOrdinals
	}
	if byteBudget <= 0 {
		byteBudget = defaultOrdinalCacheByteBudget
	}
	return &OrdinalCache{
		capacity:   capacity,
		byteBudget: byteBudget,
		m:          make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, ordinalCachePresize),
	}
}

func (c *OrdinalCache) Clear() {
	// Always drop the backing map. clear() would retain the bucket
	// array at its high-water size forever (Go maps never shrink), so
	// every overshooting window would ratchet memory up in perpetuity.
	// Dropping the map frees the previous window — buckets, entries
	// and inscription bodies — for collection before the next window
	// starts growing. (Pages return to the OS lazily via the runtime
	// scavenger; the guarantee here is heap reuse, not RSS.)
	//
	// No collection here: flush-path callers (the indexer framework)
	// run runtime.GC() immediately after Clear, and OOM safety is
	// carried by the byte budget bounding live growth plus the GC
	// pacer — not by eager collection.
	c.m = make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, ordinalCachePresize)
	c.entryCount = 0
	c.byteCount = 0
}

// Len returns the running count of sub-entry writes since the last Clear.
func (c *OrdinalCache) Len() int {
	return c.entryCount
}

func (c *OrdinalCache) Cap() int {
	return c.capacity
}

func (c *OrdinalCache) Stats() (length int, capacity int, pct int) {
	length = c.Len()
	pct = length * 100 / c.Cap()
	if bytePct := c.byteCount * 100 / c.byteBudget; bytePct > pct {
		pct = bytePct
	}
	return length, c.Cap(), pct
}

func (c *OrdinalCache) Map() map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry {
	return c.m
}

// PutInscription writes an 'o' sub-entry and increments the counters.
func (c *OrdinalCache) PutInscription(op tbcd.Outpoint, offset uint64, v []byte) {
	e := c.getEntry(op)
	e.Inscriptions[offset] = v
	c.entryCount++
	c.byteCount += ordinalCacheSubEntryOverhead + len(v)
}

// PutPredecessor writes a 'p' sub-entry and increments the counters.
func (c *OrdinalCache) PutPredecessor(op tbcd.Outpoint, offset uint64, v []byte) {
	e := c.getEntry(op)
	e.Predecessors[offset] = v
	c.entryCount++
	c.byteCount += ordinalCacheSubEntryOverhead + len(v)
}

// PutBigO writes the 'O' acceleration entry for an outpoint.
// v == nil signals deletion (tombstone).
func (c *OrdinalCache) PutBigO(op tbcd.Outpoint, v []byte) {
	e := c.getEntry(op)
	e.BigO = v
	e.BigOSet = true
	c.entryCount++
	c.byteCount += ordinalCacheSubEntryOverhead + len(v)
}

// PutAux writes a non-outpoint sub-entry ('i','n','a','m') and increments the counters.
func (c *OrdinalCache) PutAux(op tbcd.Outpoint, key tbcd.OrdinalKey, v tbcd.OrdinalValue) {
	e := c.getEntry(op)
	e.Aux[key] = v
	c.entryCount++
	c.byteCount += ordinalCacheSubEntryOverhead + len(key) + len(v.Bytes())
}

// getEntry returns the cache entry for op, creating and accounting it
// if absent.
func (c *OrdinalCache) getEntry(op tbcd.Outpoint) *tbcd.OrdinalCacheEntry {
	if e, ok := c.m[op]; ok {
		return e
	}
	c.byteCount += ordinalCacheEntryOverhead
	return rawGetEntry(c.m, op)
}

// rawGetEntry returns the entry for op in a raw cache map, creating it
// if absent. It performs NO byte accounting — use the OrdinalCache
// method on live caches; this exists for map construction outside the
// accounted cache (tests, fixtures).
func rawGetEntry(cache map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, op tbcd.Outpoint) *tbcd.OrdinalCacheEntry {
	e, ok := cache[op]
	if !ok {
		e = &tbcd.OrdinalCacheEntry{
			Inscriptions: make(map[uint64][]byte),
			Predecessors: make(map[uint64][]byte),
			Aux:          make(map[tbcd.OrdinalKey]tbcd.OrdinalValue),
		}
		cache[op] = e
	}
	return e
}

// OrdinalIndexerConfig carries the ordinal indexer construction
// parameters.
type OrdinalIndexerConfig struct {
	CacheLen             int // flush budget in cache sub-entries
	CacheByteBudget      int // flush budget in bytes; 0 = default
	Enabled              bool
	Genesis              *HashHeight // ordinal genesis override
	ComputeInscSat       func(ctx context.Context, txid chainhash.Hash, inputIndex uint32) (uint64, error)
	WatermarkGap         time.Duration
	OutputValueCacheSize int  // LRU for parent tx output values; 0 disables
	VerifyBigO           bool // debug: cross-check 'O' values against the tx index
}

func NewOrdinalIndexer(ctx context.Context, g geometryParams, cfg OrdinalIndexerConfig) Indexer {
	oi := &ordinalIndexer{
		runCtx:          ctx,
		cacheCapacity:   cfg.CacheLen,
		cacheByteBudget: cfg.CacheByteBudget,
		workCache:       make(map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue),
		computeInscSat:  cfg.ComputeInscSat,
		watermarkGap:    cfg.WatermarkGap,
		verifyBigO:      cfg.VerifyBigO,
	}
	oi.indexerCommon = indexerCommon{
		name:    "ordinal",
		enabled: cfg.Enabled,
		g:       g,
		p:       oi,
		genesis: cfg.Genesis,
		// Ordinal indexing is much slower than the other indexers,
		// log progress more often.
		logInterval: 1000,
	}
	if cfg.OutputValueCacheSize > 0 {
		var err error
		oi.outputValueCache, err = lru.New(
			cfg.OutputValueCacheSize,
			func(_ chainhash.Hash, v []uint64) int {
				// Key: 32 bytes (chainhash.Hash)
				// Value: 24 (slice header) + 8*len (backing array)
				return chainhash.HashSize + 24 + 8*len(v) + lru.EntryOverhead
			},
			0,
		)
		if err != nil {
			panic(fmt.Sprintf("ordinal output value cache: %v", err))
		}
	}
	return oi
}

func (i *ordinalIndexer) newCache() indexerCache {
	i.cache = NewOrdinalCache(i.cacheCapacity, i.cacheByteBudget)
	return i.cache
}

func (i *ordinalIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByOrdinalIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

// process dispatches a single block to windBlock or unwindBlock based on direction.
func (i *ordinalIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	cache := c.(*OrdinalCache)
	blockHash := block.Hash()
	blockHeight := uint32(block.Height())

	switch direction {
	case 1:
		return i.windBlock(ctx, blockHeight, blockHash, block, cache)
	case -1:
		return i.unwindBlock(ctx, blockHeight, blockHash, block, cache)
	default:
		panic(fmt.Sprintf("diagnostic: invalid direction %v", direction))
	}
}

// ordinalWorkKey builds a 'w' prefix key for the inscription work queue.
// Layout: 'w'(1) + block_height(4) + seq(2) = 7 bytes.
func ordinalWorkKey(blockHeight uint32, seq uint16) tbcd.OrdinalWorkKey {
	var key tbcd.OrdinalWorkKey
	key[0] = 'w'
	binary.BigEndian.PutUint32(key[1:5], blockHeight)
	binary.BigEndian.PutUint16(key[5:7], seq)
	return key
}

// encodeWorkValue encodes the inscription ID into the work queue value.
// The inscription ID (reveal_txid(32) + input_index(4)) is sufficient for
// the background populator to locate the reveal and compute the sat number.
// Layout: inscription_id(36), zero-padded to the fixed work-value width.
//
//nolint:unused // kept for revival with watermark/populator
func encodeWorkValue(inscID [36]byte) tbcd.OrdinalWorkValue {
	var v tbcd.OrdinalWorkValue
	copy(v[:36], inscID[:])
	return v
}

// watermarkOrdinalKey returns the 'm' prefix OrdinalKey used to store
// the watermark in the ordinal DB. Written atomically with ordinal data.
func watermarkOrdinalKey() tbcd.OrdinalKey {
	var key tbcd.OrdinalKey
	key[0] = 'm'
	return key
}

// watermarkSentinelOutpoint returns a reserved outpoint used to carry
// the watermark 'm' entry through the cache's aux mechanism. All-zero
// txid, vout 0xFFFFFFFE. Distinct from the lost sentinel (0xFFFFFFFF).
func watermarkSentinelOutpoint() tbcd.Outpoint {
	return tbcd.NewOutpoint(chainhash.Hash{}, 0xFFFFFFFE)
}

// getWatermark returns the cached watermark, loading from DB on first call.
// Returns (height, exists). A height equal to the ordinal genesis is the sentinel.
func (i *ordinalIndexer) getWatermark(ctx context.Context) (*uint32, error) {
	if i.watermark != nil {
		return i.watermark, nil
	}
	height, exists, err := i.g.db.OrdinalWatermarkGet(ctx)
	if err != nil {
		return nil, fmt.Errorf("watermark get: %w", err)
	}
	if !exists {
		return nil, nil
	}
	i.watermark = &height
	return i.watermark, nil
}

// setWatermark sets the watermark height. Written to DB on next commit.
func (i *ordinalIndexer) setWatermark(height uint32) {
	i.watermark = &height
	i.watermarkDirty = true
}

// genesisHeight returns the ordinal genesis height (where indexing starts).
// Returns 0 if no ordinal genesis is configured (e.g. testnet4).
func (i *ordinalIndexer) genesisHeight() uint32 {
	if i.genesis != nil {
		return uint32(i.genesis.Height)
	}
	return 0
}

// flotsam is an inscribed sat in flight through a transaction, identified
// by its FIFO position in the tx's input stream. Mirrors ord's Flotsam.
// A flotsam is either a reveal (new inscription) or a transfer (an
// existing inscription moving from a spent tracked outpoint).
type flotsam struct {
	inscID   [36]byte
	pos      uint64               // FIFO position in the tx input stream
	isReveal bool                 // true=reveal (needs 'i'/'n'/'a'/'w'), false=transfer
	cursed   bool                 // reveal only
	envelope *InscriptionEnvelope // reveal only
	// source location for a transfer, stored in the 'o' value so unwind
	// can restore the prior location without recomputing FIFO from input
	// amounts. srcInputIdx is the index, within THIS tx, of the input
	// that spent the tracked sat; the source outpoint is recovered for
	// free on unwind from tx.TxIn[srcInputIdx].PreviousOutPoint, so it is
	// not stored. srcOffset is the inscription's offset within the spent
	// output. A reveal sets srcInputIdx = ordinalRevealSentinel.
	srcInputIdx uint32
	srcOffset   uint64
	// prevValue is the raw 'o' value that was at the source outpoint
	// before this transfer moved it. Stored under the 'p' prefix at the
	// destination so unwind can restore it. Nil for reveals.
	prevValue []byte
	// srcBlockHash and srcOutputValue are carried from the 'O'
	// acceleration index during the cheap pass. If set, the expensive
	// pass can skip BlockHashByTxId + BlockRawByHash for this input.
	// Only populated for transfers with a committed 'O' entry.
	srcBlockHash   chainhash.Hash
	srcOutputValue uint64
	srcHasO        bool // true if srcBlockHash/srcOutputValue are valid
}

// flotsamMatchIdx returns the input index that positions a flotsam in
// the FIFO stream: the reveal input for reveals (from the inscription
// ID), the spending input for transfers.
func flotsamMatchIdx(f *flotsam) uint32 {
	if f.isReveal {
		return binary.LittleEndian.Uint32(f.inscID[32:36])
	}
	return f.srcInputIdx
}

// ordinalRevealSentinel marks an 'o' entry as a reveal (no prior location
// to restore on unwind). 0xFFFFFFFF cannot be a real input index in any
// consensus-valid transaction.
const ordinalRevealSentinel uint32 = 0xFFFFFFFF

// srcKind values for the 'o' entry. Describes how the inscribed sat
// arrived at its current holding outpoint.
const (
	srcKindReveal   byte = 0x00 // Inscription revealed here; no prior location.
	srcKindTransfer byte = 0x01 // Sat moved within the holding tx.
	srcKindFee      byte = 0x02 // Sat paid as fee, landed in coinbase output.
	srcKindLost     byte = 0x03 // Sat paid as fee, exceeded coinbase output value.
)

// windBlock scans a block for inscription envelopes and records reveals.
// Below watermark: fast path (sat=0, writes 'w' work queue entry).
// Above watermark: full computation (backward walk, writes 'a' and real sat).
func (i *ordinalIndexer) windBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache *OrdinalCache) error {
	txs := block.Transactions()
	var inscriptionSeq uint32

	// XXX(marco): watermark and backward-walk sat computation are
	// disabled for performance. The watermark detects the chain tip
	// and triggers full sat computation via backward walk; this is
	// too slow for bulk indexing (12+ seconds per inscription at
	// depth). Sat numbers will be computed on demand at query time.
	// These may be revived once stored sat ranges per outpoint make
	// the backward walk unnecessary.
	//
	// Original watermark code:
	//   wm, err := i.getWatermark(ctx)
	//   if err != nil { return err }
	//   if wm == nil {
	//       blockTime := block.MsgBlock().Header.Timestamp
	//       if time.Since(blockTime) < i.watermarkGap {
	//           i.setWatermark(blockHeight)
	//           wm = &blockHeight
	//       }
	//   }
	//   fullComputation := wm != nil
	fullComputation := false

	var feeList []feeCarry
	var blockFeeBase uint64

	blockStart := time.Now()
	var cheapTime, expensiveTime time.Duration
	var flotsamTxs, iovCalls, totalInputs int

	for txBlockIdx, tx := range txs {
		if blockchain.IsCoinBase(tx) {
			continue
		}
		txid := *tx.Hash()

		var fl []flotsam
		cheapStart := time.Now()
		for inputIdx, txIn := range tx.MsgTx().TxIn {
			prevOut := txIn.PreviousOutPoint

			spentOP := tbcd.NewOutpoint(prevOut.Hash, prevOut.Index)

			// Fast path: point Get 'O' with bloom filter.
			// Rejects 99.99% of inputs without creating an iterator.
			bigOVal, bigOErr := i.g.db.OrdinalBigOByOutpoint(ctx, spentOP)
			if bigOErr != nil {
				return fmt.Errorf("bigO lookup %v: %w", spentOP, bigOErr)
			}
			// Apply cache overlay for 'O' (same-block tombstone or update).
			if entry, ok := cache.m[spentOP]; ok && entry.BigOSet {
				bigOVal = entry.BigO
			}

			// Check cache for same-block inscription not yet committed.
			hasCacheInscription := false
			if entry, ok := cache.m[spentOP]; ok {
				for _, v := range entry.Inscriptions {
					if v != nil {
						hasCacheInscription = true
						break
					}
				}
			}

			// Inscription hit. Full 'o' scan for data (only ~200/block).
			if bigOVal != nil || hasCacheInscription {
				tracked, terr := i.g.db.OrdinalInscriptionsByOutpointWithOffset(ctx, spentOP)
				if terr != nil {
					return fmt.Errorf("tracked lookup %v: %w", spentOP, terr)
				}
				// Cache overlay for same-block inscriptions.
				if entry, ok := cache.m[spentOP]; ok {
					for offset, v := range entry.Inscriptions {
						if v == nil {
							continue // tombstoned
						}
						if len(v) < 36 {
							continue // malformed
						}
						var li tbcd.OrdinalLocatedInscription
						copy(li.InscID[:], v[:36])
						li.Offset = offset
						li.Value = append([]byte(nil), v...)
						tracked = append(tracked, li)
					}
				}
				for _, t := range tracked {
					f := flotsam{
						inscID:      t.InscID,
						srcInputIdx: uint32(inputIdx),
						srcOffset:   t.Offset,
						prevValue:   append([]byte(nil), t.Value...),
					}
					// Carry 'O' data for transfer fast path.
					if len(bigOVal) >= 40 {
						copy(f.srcBlockHash[:], bigOVal[:32])
						f.srcOutputValue = binary.BigEndian.Uint64(bigOVal[32:40])
						f.srcHasO = true
					}
					fl = append(fl, f)
					cache.PutInscription(spentOP, t.Offset, nil)
				}
				if len(tracked) > 0 && bigOVal != nil {
					cache.PutBigO(spentOP, nil)
				}
			}

			// Reveals: does this input carry an inscription envelope?
			envelope, perr := ParseInscriptionEnvelope(txIn.Witness)
			if perr == nil && envelope != nil {
				inscID := makeInscriptionID(tx.Hash(), uint32(inputIdx))
				fl = append(fl, flotsam{
					inscID:      inscID,
					isReveal:    true,
					cursed:      isInscriptionCursed(blockHeight, inputIdx, envelope),
					envelope:    envelope,
					srcInputIdx: ordinalRevealSentinel,
				})
			}
		}

		cheapTime += time.Since(cheapStart)
		totalInputs += len(tx.MsgTx().TxIn)

		if len(fl) == 0 {
			continue
		}
		flotsamTxs++

		// Expensive pass: only reached by txs with ordinal activity.
		// Compute input values for FIFO positioning via cross-block reads.
		//
		// Shortcircuit: only walk inputs up to the last one carrying
		// flotsam. For a 100-input tx with inscription on input 3,
		// this does 4 iov calls instead of 100.
		//
		// Reveal input index comes from inscID[32:36], NOT srcInputIdx
		// (which is ordinalRevealSentinel for reveals and must stay that
		// way in the stored 'o' value for unwind compatibility).
		expStart := time.Now()
		// Sort flotsam by their positioning input up front: the
		// FIFO walk below is then O(F + maxIdx) instead of the
		// quadratic O(F x maxIdx) scan an inscription-sweep tx
		// (thousands of inscribed inputs in one tx) could exploit.
		// fl is re-sorted by pos afterwards, so this order is free.
		sort.Slice(fl, func(a, b int) bool {
			return flotsamMatchIdx(&fl[a]) < flotsamMatchIdx(&fl[b])
		})
		maxIdx := flotsamMatchIdx(&fl[len(fl)-1])
		// Parallel fetch: pre-fetch input values 0..maxIdx-1
		// concurrently. Each goroutine writes to a disjoint slot
		// in the values slice — no mutex needed. Follows the UTXO
		// fixupCacheChannel pattern: bounded semaphore channel,
		// WaitGroup, token return on completion.
		//
		// A flotsam's FIFO position depends only on the values of
		// the inputs BEFORE it: the positioning loop below adds
		// values[idx] to the running sum after matching flotsam at
		// idx, so the value of the last flotsam-bearing input
		// (maxIdx) is never consumed. For the dominant 1-input
		// shape (mints, simple transfers) this means zero fetches.
		fetchCount := int(maxIdx)
		values := make([]uint64, fetchCount)
		errs := make([]error, fetchCount)
		txIns := tx.MsgTx().TxIn

		// Pre-fill values from 'O' fast path. Only transfers have
		// srcHasO (reveals' funding outputs are not inscriptions).
		filled := make([]bool, fetchCount)
		for fi := range fl {
			if !fl[fi].srcHasO {
				continue
			}
			idx := fl[fi].srcInputIdx
			if i.verifyBigO {
				// Debug cross-check: verify 'O' outputValue
				// against the tx index for every 'O'-carried
				// transfer, including ones whose value is never
				// consumed. Re-does the lookup the 'O' entry
				// exists to skip. A lookup failure is a normal
				// error (disk, shutdown) and is returned; only a
				// genuine value mismatch — a corrupt ordinal
				// index — panics.
				prevOut := txIns[idx].PreviousOutPoint
				iov, ioverr := i.inputOutputValue(ctx, prevOut.Hash, prevOut.Index)
				if ioverr != nil {
					return fmt.Errorf("bigO verify iov %v: %w", prevOut, ioverr)
				}
				if iov != fl[fi].srcOutputValue {
					panic(fmt.Sprintf("ordinal index corrupt: 'O' outputValue mismatch at %v: O=%d tx index=%d; delete the ordinals database and reindex, and report this",
						prevOut, fl[fi].srcOutputValue, iov))
				}
			}
			if int(idx) < fetchCount {
				values[idx] = fl[fi].srcOutputValue
				filled[idx] = true
			}
		}

		// Fetch remaining inputs not pre-filled by 'O'.
		if fetchCount == 1 && !filled[0] {
			values[0], errs[0] = i.inputOutputValue(ctx, txIns[0].PreviousOutPoint.Hash, txIns[0].PreviousOutPoint.Index)
			iovCalls++
		} else if fetchCount > 1 {
			slots := fetchCount
			if slots > 128 {
				slots = 128
			}
			sem := make(chan struct{}, slots)
			for range slots {
				sem <- struct{}{}
			}
			var wg sync.WaitGroup
			for idx := range fetchCount {
				if filled[idx] {
					continue // pre-filled from 'O'
				}
				select {
				case <-ctx.Done():
					wg.Wait()
					return ctx.Err()
				case <-sem:
				}
				wg.Add(1)
				go func(j int) {
					defer wg.Done()
					defer func() {
						select {
						case <-ctx.Done():
						case sem <- struct{}{}:
						}
					}()
					values[j], errs[j] = i.inputOutputValue(ctx, txIns[j].PreviousOutPoint.Hash, txIns[j].PreviousOutPoint.Index)
				}(idx)
				iovCalls++
			}
			wg.Wait()
		}

		// Check for errors from parallel fetch.
		for idx, ferr := range errs {
			if ferr != nil {
				return fmt.Errorf("input value %v: %w", txIns[idx].PreviousOutPoint, ferr)
			}
		}

		// Sequential FIFO positioning using fetched values: walk
		// inputs once with a running prefix sum, advancing through
		// the matchIdx-sorted flotsam. The last flotsam input's own
		// value was not fetched and is never added. O(F + maxIdx).
		var inputValue uint64
		idx := 0
		for fi := range fl {
			for m := int(flotsamMatchIdx(&fl[fi])); idx < m; idx++ {
				if idx < fetchCount {
					inputValue += values[idx]
				}
			}
			if fl[fi].isReveal {
				fl[fi].pos = inputValue
			} else {
				fl[fi].pos = inputValue + fl[fi].srcOffset
			}
		}
		expensiveTime += time.Since(expStart)

		sort.Slice(fl, func(a, b int) bool { return fl[a].pos < fl[b].pos })

		outTotal := txOutTotal(tx.MsgTx().TxOut)

		for _, f := range fl {
			f := f
			locVout, locOffset, landed := placeInOutputs(tx.MsgTx().TxOut, f.pos)

			if f.isReveal {
				// Aux entries ('i','n','a','w') are keyed by inscID, not
				// by the sat's landing location. Host them on the reveal
				// tx's vout 0 unconditionally — unwind derives the same
				// outpoint from inscID[:32] + vout 0 for tombstoning.
				auxOP := tbcd.NewOutpoint(txid, 0)

				if fullComputation {
					revealInput := binary.LittleEndian.Uint32(f.inscID[32:36])
					satStart := time.Now()
					satNumber, err := i.computeInscSat(ctx, txid, revealInput)
					if d := time.Since(satStart); d > 500*time.Millisecond {
						log.Infof("slow sat computation: height %d %v:%d took %v",
							blockHeight, txid, revealInput, d.Round(time.Millisecond))
					}
					if err != nil {
						return fmt.Errorf("compute inscribed sat at %v:%d: %w",
							txid, revealInput, err)
					}
					cache.PutAux(auxOP, ordinalInscriptionKey(f.inscID),
						encodeInscriptionValue(satNumber, blockHash, f.cursed, f.envelope))
					cache.PutAux(auxOP, ordinalBlockInscriptionKey(blockHash, inscriptionSeq),
						f.inscID[:])
					cache.PutAux(auxOP, ordinalSatInscriptionKey(satNumber, f.inscID),
						[]byte{})
				} else {
					cache.PutAux(auxOP, ordinalInscriptionKey(f.inscID),
						encodeInscriptionValue(0, blockHash, f.cursed, f.envelope))
					cache.PutAux(auxOP, ordinalBlockInscriptionKey(blockHash, inscriptionSeq),
						f.inscID[:])
					// 'w': work queue for background sat-number populator.
					// XXX(marco): disabled — populator is not active while
					// watermark is disabled. May be revived for deferred
					// sat computation once sat ranges are stored per outpoint.
					// Original:
					// i.workCache[ordinalWorkKey(blockHeight, uint16(inscriptionSeq))] = encodeWorkValue(f.inscID)
				}
				inscriptionSeq++
			}

			// 'o': ownership tracker.
			if landed {
				kind := srcKindTransfer
				if f.isReveal {
					kind = srcKindReveal
				}
				op := tbcd.NewOutpoint(txid, locVout)
				cache.PutInscription(op, locOffset, encodeOutpointValue(
					f.inscID, kind, uint32(txBlockIdx), f.srcInputIdx, f.srcOffset))
				// 'p': store predecessor value for correct unwind.
				// Reveals have no predecessor; only transfers write 'p'.
				if kind == srcKindTransfer {
					cache.PutPredecessor(op, locOffset, f.prevValue)
				}
				// 'O': point-Get acceleration index.
				// blockHash(32) + outputValue(8) = 40 bytes.
				var bigOVal [40]byte
				copy(bigOVal[:32], blockHash[:])
				binary.BigEndian.PutUint64(bigOVal[32:], uint64(tx.MsgTx().TxOut[locVout].Value))
				cache.PutBigO(op, bigOVal[:])
			} else {
				feeInternal := f.pos - outTotal
				feeList = append(feeList, feeCarry{
					inscID:      f.inscID,
					feePoolOff:  blockFeeBase + feeInternal,
					srcTxIdx:    uint32(txBlockIdx),
					srcInputIdx: f.srcInputIdx,
					srcOffset:   f.srcOffset,
					prevValue:   f.prevValue,
				})
			}
		}

		// NOTE: blockFeeBase is only accumulated from flotsam txs
		// (non-flotsam txs skip before reaching this line) and
		// inputValue only covers inputs 0..maxIdx-1 (shortcircuit;
		// the last flotsam input's value is not fetched at all).
		// This makes feePoolOff incorrect for fee-carried inscriptions,
		// which are practically nonexistent on mainnet. Guard the
		// subtraction so the undercounted inputValue cannot wrap.
		if inputValue > outTotal {
			blockFeeBase += inputValue - outTotal
		}
	}

	log.Infof("ordinal wind height %d: %d txs (%d inputs) %d flotsam_txs %d iov_calls cheap %v expensive %v total %v",
		blockHeight, len(txs)-1, totalInputs, flotsamTxs, iovCalls,
		cheapTime.Round(time.Millisecond),
		expensiveTime.Round(time.Millisecond),
		time.Since(blockStart).Round(time.Millisecond))

	// Coinbase phase.
	if len(feeList) > 0 {
		coinbaseTx := txs[0]
		cbTxid := *coinbaseTx.Hash()
		subsidyCount := SubsidyAtHeight(blockHeight)
		cbOutTotal := txOutTotal(coinbaseTx.MsgTx().TxOut)

		sort.Slice(feeList, func(a, b int) bool {
			return feeList[a].feePoolOff < feeList[b].feePoolOff
		})

		var lostSeq uint32
		for _, e := range feeList {
			posCB := subsidyCount + e.feePoolOff
			if posCB < cbOutTotal {
				vout, offset, _ := placeInOutputs(coinbaseTx.MsgTx().TxOut, posCB)
				op := tbcd.NewOutpoint(cbTxid, vout)
				cache.PutInscription(op, offset, encodeOutpointValue(
					e.inscID, srcKindFee, e.srcTxIdx, e.srcInputIdx, e.srcOffset))
				if len(e.prevValue) > 0 {
					cache.PutPredecessor(op, offset, e.prevValue)
				}
				// 'O' for fee-carried inscription in coinbase output.
				var feeOVal [40]byte
				copy(feeOVal[:32], blockHash[:])
				binary.BigEndian.PutUint64(feeOVal[32:], uint64(coinbaseTx.MsgTx().TxOut[vout].Value))
				cache.PutBigO(op, feeOVal[:])
			} else {
				op := lostSentinelOutpoint()
				lostOff := lostSatOffset(blockHeight, lostSeq)
				lostSeq++
				cache.PutInscription(op, lostOff, encodeOutpointValue(
					e.inscID, srcKindLost, e.srcTxIdx, e.srcInputIdx, e.srcOffset))
				if len(e.prevValue) > 0 {
					cache.PutPredecessor(op, lostOff, e.prevValue)
				}
			}
		}
	}

	return nil
}

// placeInOutputs locates FIFO position pos within a tx's outputs.
// Returns (vout, offset_within_output, true) if the sat lands in an
// output, or (0, 0, false) if pos falls beyond all outputs (the sat is
// in the fee — fee→coinbase placement handles it). Zero-value outputs
// (OP_RETURN etc.) hold no sats and are skipped.
func placeInOutputs(txOut []*wire.TxOut, pos uint64) (uint32, uint64, bool) {
	var cum uint64
	for vout, out := range txOut {
		if out.Value == 0 {
			continue
		}
		if pos < cum+uint64(out.Value) {
			return uint32(vout), pos - cum, true
		}
		cum += uint64(out.Value)
	}
	return 0, 0, false
}

// feeCarry is an inscribed sat that landed in fees during a non-coinbase tx.
// Accumulated per block, then placed into coinbase outputs (or lost sentinel)
// after all non-coinbase txs are processed.
type feeCarry struct {
	inscID      [36]byte
	feePoolOff  uint64 // position in the block-wide fee pool
	srcTxIdx    uint32 // block index of the paying tx
	srcInputIdx uint32
	srcOffset   uint64
	prevValue   []byte // predecessor 'o' value (nil for reveals)
}

// lostSentinelOutpoint returns the reserved outpoint for lost (unclaimed fee)
// sats. All-zero txid, vout 0xFFFFFFFF. Fixed-size, no nil.
func lostSentinelOutpoint() tbcd.Outpoint {
	return tbcd.NewOutpoint(chainhash.Hash{}, 0xFFFFFFFF)
}

// lostSatOffset encodes a unique offset for a lost sat. The block height is
// embedded so that unwind can identify which lost entries belong to a block.
func lostSatOffset(blockHeight uint32, seq uint32) uint64 {
	return (uint64(blockHeight) << 32) | uint64(seq)
}

// lostSatBlockHeight extracts the block height from a lost sat offset.
func lostSatBlockHeight(offset uint64) uint32 {
	return uint32(offset >> 32)
}

// txOutTotal returns the sum of all output values in a transaction.
func txOutTotal(txOut []*wire.TxOut) uint64 {
	var total uint64
	for _, out := range txOut {
		total += uint64(out.Value)
	}
	return total
}

// inputOutputValue returns the satoshi value of the output at txid:vout.
// Uses the outputValueCache: on miss, fetches the raw block bytes via
// BlockRawByHash and uses lazyBlock to find the tx and extract output
// values without deserializing the entire block.
func (i *ordinalIndexer) inputOutputValue(ctx context.Context, txid chainhash.Hash, vout uint32) (uint64, error) {
	// Cache hit path.
	if i.outputValueCache != nil {
		if vals, ok := i.outputValueCache.Get(txid); ok {
			if int(vout) >= len(vals) {
				return 0, fmt.Errorf("cached vout %d out of range (tx has %d outputs)", vout, len(vals))
			}
			return vals[vout], nil
		}
	}

	// Cache miss: find which block contains this tx.
	blockHash, loc, err := i.g.db.BlockHashByTxId(ctx, txid)
	if err != nil {
		return 0, fmt.Errorf("tx %v: %w", txid, err)
	}

	// Fetch raw block bytes — no deserialization.
	raw, err := i.g.db.BlockRawByHash(ctx, *blockHash)
	if err != nil {
		return 0, fmt.Errorf("block raw %v: %w", blockHash, err)
	}

	var vals []uint64
	if loc != nil && loc.TxLen > 0 {
		// Fast path: TxLoc available, extract output values directly.
		if loc.TxStart+loc.TxLen > len(raw) {
			return 0, fmt.Errorf("tx loc out of range: %d+%d > %d",
				loc.TxStart, loc.TxLen, len(raw))
		}
		var msgTx wire.MsgTx
		if err := msgTx.Deserialize(bytes.NewReader(raw[loc.TxStart : loc.TxStart+loc.TxLen])); err != nil {
			return 0, fmt.Errorf("deserialize tx at offset %d: %w", loc.TxStart, err)
		}
		vals = make([]uint64, len(msgTx.TxOut))
		for j, out := range msgTx.TxOut {
			vals[j] = uint64(out.Value)
		}
	} else {
		// Slow path: legacy entry, scan with lazyBlock.
		lb, err := newLazyBlock(raw)
		if err != nil {
			return 0, fmt.Errorf("lazy block %v: %w", blockHash, err)
		}
		idx, err := lb.FindTx(txid)
		if err != nil {
			return 0, fmt.Errorf("tx %v not in block %v: %w", txid, blockHash, err)
		}
		vals, err = lb.TxOutputValues(idx)
		if err != nil {
			return 0, fmt.Errorf("tx %v output values: %w", txid, err)
		}
	}

	if int(vout) >= len(vals) {
		return 0, fmt.Errorf("vout %d out of range (%d outputs)", vout, len(vals))
	}

	// Cache all output values for this tx.
	if i.outputValueCache != nil {
		i.outputValueCache.Put(txid, vals)
	}

	return vals[vout], nil
}

// unwindBlock reverses a single block. Panics if the unwind goes
// BELOW the watermark. Unwinding AT the watermark is safe.
//
// A reorg reaching below the watermark means a reorg deeper than
// OrdinalWatermarkGap (default 24h) — catastrophic for Bitcoin.
func (i *ordinalIndexer) unwindBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache *OrdinalCache) error {
	wm, err := i.getWatermark(ctx)
	if err != nil {
		return err
	}
	if wm != nil && blockHeight < *wm {
		// Invariant violation: blocks below the watermark are finalized
		// and must never be unwound. Continuing would corrupt the index.
		// Panic matches the indexer convention for unrecoverable bugs.
		panic(fmt.Sprintf("bug: ordinal unwind below watermark: height %d < watermark %d",
			blockHeight, *wm))
	}

	inscIDs, err := i.g.db.OrdinalInscriptionsByBlockHash(ctx, *blockHash)
	if err != nil {
		return fmt.Errorf("inscriptions by block %v: %w", blockHash, err)
	}
	for seq, inscID := range inscIDs {
		// Derive the reveal outpoint as host for aux tombstones.
		var revealTxid chainhash.Hash
		copy(revealTxid[:], inscID[:32])
		revealOP := tbcd.NewOutpoint(revealTxid, 0)

		// Read 'i' to recover the sat number (if computed) for 'a'
		// deletion. The inscID came from this block's 'n' index, so the
		// 'i' entry MUST exist; its absence (or any read error) means the
		// ordinal index is corrupt. Crash — a daemon that keeps unwinding
		// a corrupt index produces garbage. Fail fast, restart clean.
		iValue, err := i.g.db.OrdinalInscriptionByID(ctx, inscID)
		if err != nil {
			panic(fmt.Sprintf("bug: ordinal unwind: 'n' references inscription %x with no 'i' entry: %v",
				inscID, err))
		}
		if len(iValue) >= 8 {
			satNumber := binary.BigEndian.Uint64(iValue[:8])
			if satNumber != 0 {
				cache.PutAux(revealOP, ordinalSatInscriptionKey(satNumber, inscID), nil)
			}
		}

		cache.PutAux(revealOP, ordinalInscriptionKey(inscID), nil)
		cache.PutAux(revealOP, ordinalBlockInscriptionKey(blockHash, uint32(seq)), nil)
		// Harmless no-op if 'w' doesn't exist (above watermark).
		i.workCache[ordinalWorkKey(blockHeight, uint16(seq))] = tbcd.OrdinalWorkValueDelete
	}

	// Reverse the 'o' tracker for this block.
	return i.unwindOutpointTracker(ctx, block, cache)
}

// unwindOutpointTracker reverses the 'o' ownership entries windBlock placed
// for every tx in the block (including coinbase and lost sentinel). For each
// inscription at a tx output, it deletes the entry; if the entry is a
// transfer/fee/lost, it restores the prior 'o' entry from the 'p' prefix.
// Self-contained: reads only the ordinal index and the block in hand.
func (i *ordinalIndexer) unwindOutpointTracker(ctx context.Context, block *btcutil.Block, cache *OrdinalCache) error {
	txs := block.Transactions()

	// Process txs in reverse order. Coinbase is NOT skipped — fee sats
	// placed in coinbase outputs during wind must be reversed.
	for ti := len(txs) - 1; ti >= 0; ti-- {
		tx := txs[ti]

		for _, ob := range outpointsOf(tx) {
			if err := i.unwindOutpointEntries(ctx, block, cache, ob.op); err != nil {
				return err
			}
		}
	}

	// Scan the lost sentinel for entries created by this block.
	// unwindOutpointEntries filters by block height internally.
	sentinel := lostSentinelOutpoint()
	if err := i.unwindOutpointEntries(ctx, block, cache, sentinel); err != nil {
		return fmt.Errorf("unwind lost sentinel: %w", err)
	}

	return nil
}

// unwindOutpointEntries reverses all 'o' entries at the given outpoint.
func (i *ordinalIndexer) unwindOutpointEntries(ctx context.Context, block *btcutil.Block, cache *OrdinalCache, op tbcd.Outpoint) error {
	txs := block.Transactions()
	blockHeight := uint32(block.Height())
	isLostSentinel := op == lostSentinelOutpoint()

	located, lerr := i.locatedAtOutpoint(ctx, cache.m, op)
	if lerr != nil {
		return fmt.Errorf("unwind tracked lookup %v: %w", op, lerr)
	}
	for _, li := range located {
		// For lost sentinel: skip entries from other blocks.
		if isLostSentinel && lostSatBlockHeight(li.Offset) != blockHeight {
			continue
		}

		_, kind, srcTxIdx, srcInputIdx, srcOffset, isTransfer, derr := decodeOutpointValue(li.Value)
		if derr != nil {
			panic(fmt.Sprintf("bug: ordinal unwind: corrupt 'o' value at %v: %v", op, derr))
		}

		// Read the predecessor value BEFORE tombstoning.
		var prevValue []byte
		if isTransfer {
			var perr error
			prevValue, perr = i.predecessorValue(ctx, cache.m, op, li.Offset)
			if perr != nil {
				return fmt.Errorf("predecessor at %v: %w", op, perr)
			}
		}

		// Delete the 'o' and 'p' entries at the current location.
		cache.PutInscription(op, li.Offset, nil)
		cache.PutPredecessor(op, li.Offset, nil)
		cache.PutBigO(op, nil)

		// Reveal: nothing to restore.
		if !isTransfer {
			continue
		}

		// Determine the source tx.
		var srcTx *wire.MsgTx
		switch kind {
		case srcKindTransfer:
			if int(srcTxIdx) >= len(txs) {
				panic(fmt.Sprintf("bug: ordinal unwind: srcTxIdx %d out of range (%d txs)",
					srcTxIdx, len(txs)))
			}
			srcTx = txs[srcTxIdx].MsgTx()
		case srcKindFee, srcKindLost:
			// Source is a non-coinbase tx identified by srcTxIdx.
			if int(srcTxIdx) >= len(txs) {
				panic(fmt.Sprintf("bug: ordinal unwind: srcTxIdx %d out of range (%d txs)",
					srcTxIdx, len(txs)))
			}
			srcTx = txs[srcTxIdx].MsgTx()
		default:
			panic(fmt.Sprintf("bug: ordinal unwind: unhandled srcKind %d at %v", kind, op))
		}

		if int(srcInputIdx) >= len(srcTx.TxIn) {
			panic(fmt.Sprintf("bug: ordinal unwind: 'o' at %v src input %d out of range (%d inputs)",
				op, srcInputIdx, len(srcTx.TxIn)))
		}

		if len(prevValue) == 0 {
			// No predecessor (reveal that landed in fees). Nothing to restore.
			continue
		}

		prevOut := srcTx.TxIn[srcInputIdx].PreviousOutPoint
		srcOP := tbcd.NewOutpoint(prevOut.Hash, prevOut.Index)
		cache.PutInscription(srcOP, srcOffset, prevValue)

		// Restore O at the previous location. For cross-block
		// transfers, BlockHashByTxId works (the earlier block is
		// still wound). For same-block transfers, the tx index for
		// the current block is already gone — use the block hash
		// and find the output value from the block directly.
		var restoreBlockHash *chainhash.Hash
		var restoreOutValue uint64
		// NOTE: rbhErr catches all errors, not just "not found".
		// A real DB error falls through to the same-block scan.
		// The verify assert on the next wind will catch corruption.
		rbh, _, rbhErr := i.g.db.BlockHashByTxId(ctx, prevOut.Hash)
		if rbhErr == nil {
			// Cross-block: tx index has the earlier block.
			restoreBlockHash = rbh
			rov, rovErr := i.inputOutputValue(ctx, prevOut.Hash, prevOut.Index)
			if rovErr != nil {
				return fmt.Errorf("unwind O restore value %v: %w", prevOut, rovErr)
			}
			restoreOutValue = rov
		} else {
			// Same-block: tx is in the block being unwound.
			bh := block.MsgBlock().Header.BlockHash()
			restoreBlockHash = &bh
			for _, btx := range block.Transactions() {
				if *btx.Hash() == prevOut.Hash {
					if int(prevOut.Index) < len(btx.MsgTx().TxOut) {
						restoreOutValue = uint64(btx.MsgTx().TxOut[prevOut.Index].Value)
					}
					break
				}
			}
		}
		var bigORestore [40]byte
		copy(bigORestore[:32], restoreBlockHash[:])
		binary.BigEndian.PutUint64(bigORestore[32:], restoreOutValue)
		cache.PutBigO(srcOP, bigORestore[:])
	}
	return nil
}

// txOutpointBase pairs an output's outpoint with its base FIFO position
// (sum of prior output values) for unwind reversal.
type txOutpointBase struct {
	op   tbcd.Outpoint
	base uint64
}

// locatedAtOutpoint returns the inscriptions tracked at op as the unwind
// currently sees them: the committed DB entries with the pending cache
// overlaid. A cache tombstone (nil) removes a DB entry; a cache write adds
// or overrides one. Required for same-block multi-hop transfers, where a
// later tx's unwind restores an 'o' entry (into the cache) that an earlier
// tx's unwind must then observe — that entry was never committed to the
// DB, so a DB-only lookup would miss it and break the restore chain.
//
// Complexity: O(D + I) per call, where D is the DB entries at op (a keyed
// prefix scan, typically 0-1) and I is the number of inscriptions cached
// at this outpoint. Both are typically 0-1. This is O(1) in practice —
// the linear cache scan from the old design is eliminated.
func (i *ordinalIndexer) locatedAtOutpoint(ctx context.Context, cache map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, op tbcd.Outpoint) ([]tbcd.OrdinalLocatedInscription, error) {
	dbLocated, err := i.g.db.OrdinalInscriptionsByOutpointWithOffset(ctx, op)
	if err != nil {
		return nil, err
	}

	// Build a map keyed by offset for overlay merging.
	byOffset := make(map[uint64]tbcd.OrdinalLocatedInscription, len(dbLocated))
	var order []uint64
	for _, li := range dbLocated {
		if _, ok := byOffset[li.Offset]; !ok {
			order = append(order, li.Offset)
		}
		byOffset[li.Offset] = li
	}

	// O(1) cache overlay: check cache[op].inscriptions directly.
	if entry, ok := cache[op]; ok {
		for offset, v := range entry.Inscriptions {
			if len(v) < 36 {
				// Tombstone — remove from result.
				delete(byOffset, offset)
				continue
			}
			if _, ok := byOffset[offset]; !ok {
				order = append(order, offset)
			}
			var li tbcd.OrdinalLocatedInscription
			copy(li.InscID[:], v[:36])
			li.Offset = offset
			li.Value = append([]byte(nil), v...)
			byOffset[offset] = li
		}
	}

	result := make([]tbcd.OrdinalLocatedInscription, 0, len(byOffset))
	for _, offset := range order {
		if li, ok := byOffset[offset]; ok {
			result = append(result, li)
		}
	}
	return result, nil
}

// outpointsOf returns each non-zero output of tx with its base FIFO
// position in the output stream.
func outpointsOf(tx *btcutil.Tx) []txOutpointBase {
	txid := *tx.Hash()
	var result []txOutpointBase
	var base uint64
	for vout, out := range tx.MsgTx().TxOut {
		if out.Value == 0 {
			continue
		}
		result = append(result, txOutpointBase{
			op:   tbcd.NewOutpoint(txid, uint32(vout)),
			base: base,
		})
		base += uint64(out.Value)
	}
	return result
}

func (i *ordinalIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*OrdinalCache)

	// Write watermark into the cache's aux mechanism so it's committed
	// atomically with ordinal data. The DB layer will unpack it via the
	// aux map on the sentinel outpoint.
	if i.watermarkDirty && i.watermark != nil {
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], *i.watermark)
		cache.PutAux(watermarkSentinelOutpoint(), watermarkOrdinalKey(), tbcd.OrdinalValue(v[:]))
		i.watermarkDirty = false
	}

	if err := i.g.db.BlockOrdinalUpdate(ctx, direction, cache.Map(), i.workCache, atHash); err != nil {
		return err
	}
	return nil
}

// fixupCacheHook is unused by the ordinal indexer.
func (i *ordinalIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	return nil
}

// XXX(marco): onSyncComplete and populateWork are dormant. The populator
// fires on sync-complete and processes 'w' work queue entries (backward-
// walking each inscription to compute its sat number, then writing the
// real sat into 'i' and creating the 'a' entry). But the 'w' work queue
// writes in windBlock are commented out, so the populator finds zero
// entries and returns immediately.
//
// This is Path A for re-enabling InscriptionsBySat without stored sat
// ranges: un-comment the workCache write in windBlock's else branch,
// and the populator will grind through backward walks after sync
// completes. Downside: hours of background computation.
//

func (i *ordinalIndexer) onSyncComplete() {
	if !i.populating.CompareAndSwap(0, 1) {
		return
	}
	go i.populateWork()
}

func (i *ordinalIndexer) populateWork() {
	defer i.populating.Store(0)
	ctx := i.runCtx

	// Only run when synced — ordinal indexer at best block header.
	ordBH, err := i.indexerAt(ctx)
	if err != nil {
		return
	}
	bestBH, err := i.g.db.BlockHeaderBest(ctx)
	if err != nil {
		return
	}
	if ordBH.Height != bestBH.Height {
		return
	}

	wm, err := i.getWatermark(ctx)
	if err != nil || wm == nil {
		return
	}
	if *wm == i.genesisHeight() {
		return
	}

	bestHeight := bestBH.Height
	for {
		// Abort if a new block arrived.
		bh, err := i.g.db.BlockHeaderBest(ctx)
		if err != nil {
			return
		}
		if bh.Height != bestHeight {
			return
		}

		entries, err := i.g.db.ReadOrdinalWork(ctx, *wm, 10000)
		if err != nil {
			log.Errorf("ordinal populator read: %v", err)
			return
		}
		if len(entries) == 0 {
			// All done — set genesis sentinel.
			ordData := make(map[tbcd.OrdinalKey]tbcd.OrdinalValue)
			var v [4]byte
			binary.BigEndian.PutUint32(v[:], i.genesisHeight())
			ordData[watermarkOrdinalKey()] = tbcd.OrdinalValue(v[:])
			workData := make(map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue)
			if err := i.g.db.OrdinalPopulatorUpdate(ctx, ordData, workData); err != nil {
				log.Errorf("ordinal populator sentinel: %v", err)
				return
			}
			i.setWatermark(i.genesisHeight())
			i.watermarkDirty = false
			log.Infof("ordinal populator complete — watermark at genesis")
			return
		}

		// Process entries at the same height (one block).
		blockHeight := entries[0].Height
		start := time.Now()

		ordData := make(map[tbcd.OrdinalKey]tbcd.OrdinalValue)
		workData := make(map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue)
		var processed int

		for _, entry := range entries {
			if entry.Height != blockHeight {
				break
			}

			var revealTxid chainhash.Hash
			copy(revealTxid[:], entry.InscID[:32])
			inputIndex := binary.LittleEndian.Uint32(entry.InscID[32:36])

			satNumber, err := i.computeInscSat(ctx, revealTxid, inputIndex)
			if err != nil {
				log.Errorf("ordinal populator fatal: height %d %x: %v",
					blockHeight, entry.InscID, err)
				return
			}

			iValue, err := i.g.db.OrdinalInscriptionByID(ctx, entry.InscID)
			if err != nil {
				log.Errorf("ordinal populator fatal: read 'i' %x: %v",
					entry.InscID, err)
				return
			}
			if len(iValue) >= 8 {
				updated := make([]byte, len(iValue))
				copy(updated, iValue)
				binary.BigEndian.PutUint64(updated[:8], satNumber)
				ordData[ordinalInscriptionKey(entry.InscID)] = tbcd.OrdinalValue(updated)
			}

			ordData[ordinalSatInscriptionKey(satNumber, entry.InscID)] = []byte{}

			workData[ordinalWorkKey(entry.Height, entry.Seq)] = tbcd.OrdinalWorkValueDelete
			processed++
		}

		if processed == 0 {
			return
		}

		// Merge watermark into ordData, commit everything in one transaction.
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], blockHeight)
		ordData[watermarkOrdinalKey()] = tbcd.OrdinalValue(v[:])

		if err := i.g.db.OrdinalPopulatorUpdate(ctx, ordData, workData); err != nil {
			log.Errorf("ordinal populator update: %v", err)
			return
		}
		i.setWatermark(blockHeight)
		i.watermarkDirty = false
		wm = &blockHeight

		log.Infof("ordinal populator: height %d reveals=%d %v",
			blockHeight, processed, time.Since(start).Round(time.Millisecond))
	}
}

// readCacheInfo reports the byte dimension of the live cache so
// byte-triggered flushes are distinguishable from count-triggered
// ones in the indexer progress logs.
func (i *ordinalIndexer) readCacheInfo() string {
	if i.cache == nil {
		return ""
	}
	return fmt.Sprintf(" bytes %v/%v", i.cache.byteCount, i.cache.byteBudget)
}

// Key construction helpers. These match the SOW prefix scheme exactly.

func ordinalInscriptionKey(inscID [36]byte) tbcd.OrdinalKey {
	var key tbcd.OrdinalKey
	key[0] = 'i'
	copy(key[1:], inscID[:])
	return key
}

func ordinalSatInscriptionKey(satNumber uint64, inscID [36]byte) tbcd.OrdinalKey {
	var key tbcd.OrdinalKey
	key[0] = 'a'
	binary.BigEndian.PutUint64(key[1:], satNumber)
	copy(key[9:], inscID[:])
	return key
}

func ordinalBlockInscriptionKey(blockHash *chainhash.Hash, seq uint32) tbcd.OrdinalKey {
	var key tbcd.OrdinalKey
	key[0] = 'n'
	copy(key[1:], blockHash[:])
	binary.BigEndian.PutUint32(key[33:], seq)
	return key
}

// predecessorKey builds a 'p' prefix key for the predecessor value store.
// Layout mirrors 'o': 'p'(1) + txid(32) + vout(4) + offset(8) = 45 bytes.
// The value is the raw 'o' value that was at the source outpoint before the
// sat was moved here. Used by unwind to restore the correct predecessor.
func predecessorKey(op tbcd.Outpoint, offset uint64) tbcd.OrdinalKey {
	var key tbcd.OrdinalKey
	key[0] = 'p'
	copy(key[1:37], op[1:37])
	binary.BigEndian.PutUint64(key[37:], offset)
	return key
}

// predecessorValue retrieves a 'p' entry from the cache (with tombstone
// awareness) or falls back to the DB. Returns nil if no predecessor exists
// (reveals) or if the entry has been tombstoned.
func (i *ordinalIndexer) predecessorValue(ctx context.Context, cache map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, op tbcd.Outpoint, offset uint64) ([]byte, error) {
	if entry, ok := cache[op]; ok {
		if v, pok := entry.Predecessors[offset]; pok {
			if v == nil {
				return nil, nil // tombstoned
			}
			return v, nil
		}
	}
	pKey := predecessorKey(op, offset)
	v, err := i.g.db.OrdinalValueByKey(ctx, pKey)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("predecessor get: %w", err)
	}
	return v, nil
}

func makeInscriptionID(txHash *chainhash.Hash, inputIdx uint32) [36]byte {
	var id [36]byte
	copy(id[:32], txHash[:])
	binary.LittleEndian.PutUint32(id[32:], inputIdx)
	return id
}

// 'o' value layout: inscID(36) + srcKind(1) + srcTxIdx(4) + srcInputIdx(4) + srcOffset(8) = 53 bytes.
// srcKind describes how the sat arrived at this holding outpoint:
//
//	0x00 REVEAL   — no prior location to restore.
//	0x01 TRANSFER — sat moved within the holding tx.
//	0x02 FEE      — sat paid as fee, landed in coinbase. srcTxIdx names the paying tx.
//	0x03 LOST     — sat paid as fee, exceeded coinbase output. srcTxIdx names the paying tx.
//
// srcTxIdx is the block-relative index of the source tx. Only consulted
// for FEE/LOST; for TRANSFER, the holding tx IS the source tx.
// srcInputIdx is the input index within the source tx that spent the
// prior outpoint. srcOffset is the sat's byte offset within the spent output.
const ordinalOutpointValueLen = 36 + 1 + 4 + 4 + 8

func encodeOutpointValue(inscID [36]byte, kind byte, srcTxIdx uint32, srcInputIdx uint32, srcOffset uint64) tbcd.OrdinalValue {
	v := make([]byte, ordinalOutpointValueLen)
	copy(v[:36], inscID[:])
	v[36] = kind
	binary.BigEndian.PutUint32(v[37:41], srcTxIdx)
	binary.BigEndian.PutUint32(v[41:45], srcInputIdx)
	binary.BigEndian.PutUint64(v[45:53], srcOffset)
	return v
}

// decodeOutpointValue returns the inscription ID, the source kind, the
// source tx index, the source input index, the source offset, and whether
// the entry is a transfer/fee/lost (true) or reveal (false).
func decodeOutpointValue(v []byte) (inscID [36]byte, kind byte, srcTxIdx uint32, srcInputIdx uint32, srcOffset uint64, isTransfer bool, err error) {
	if len(v) != ordinalOutpointValueLen {
		return inscID, 0, 0, 0, 0, false, fmt.Errorf("invalid 'o' value length: %d", len(v))
	}
	copy(inscID[:], v[:36])
	kind = v[36]
	srcTxIdx = binary.BigEndian.Uint32(v[37:41])
	srcInputIdx = binary.BigEndian.Uint32(v[41:45])
	srcOffset = binary.BigEndian.Uint64(v[45:53])
	isTransfer = kind != srcKindReveal
	return inscID, kind, srcTxIdx, srcInputIdx, srcOffset, isTransfer, nil
}
