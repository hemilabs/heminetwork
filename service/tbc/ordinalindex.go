// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type ordinalIndexer struct {
	indexerCommon

	cacheCapacity int
	mtx           sync.Mutex // protects cache map during parallel fixup/unwind

	// Inscribed-sat tracking. inscribedSatSet tracks sat numbers with
	// 's' entries created in the current cache batch (not yet flushed
	// to DB). Cleared on commit.
	//
	// minInscribedSat / maxInscribedSat bound the range of all known
	// inscribed sats (DB + cache batch). The block-level pre-scan
	// skips the DB query when the block's input sat range falls
	// entirely outside [min, max].
	inscribedSatSet  map[uint64]struct{}
	minInscribedSat  uint64
	maxInscribedSat  uint64
	hasInscribedSats bool // true once any inscription exists
	inscCheckDone    bool // one-time DB boundary probe completed
}

var (
	_ Indexer = (*ordinalIndexer)(nil)
	_ indexer = (*ordinalIndexer)(nil)
)

func NewOrdinalIndexer(g geometryParams, cacheLen int, enabled bool) Indexer {
	oi := &ordinalIndexer{
		cacheCapacity:   cacheLen,
		inscribedSatSet: make(map[uint64]struct{}),
		minInscribedSat: math.MaxUint64,
	}
	oi.indexerCommon = indexerCommon{
		name:    "ordinal",
		enabled: enabled,
		g:       g,
		p:       oi,
	}
	return oi
}

func (i *ordinalIndexer) newCache() indexerCache {
	return NewCache[tbcd.OrdinalKey, tbcd.OrdinalValue](i.cacheCapacity)
}

func (i *ordinalIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByOrdinalIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

// satRanges retrieves sat ranges for an outpoint from cache or DB.
//
// Time: O(1) cache hit, O(log n) DB miss (LevelDB seek).
// Space: O(r) where r is ranges per outpoint (typically 1-3).
func (i *ordinalIndexer) satRanges(ctx context.Context, op tbcd.Outpoint, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) ([]SatRange, error) {
	k := ordinalRangeKey(op)
	if v, ok := cache[k]; ok {
		if v == nil {
			return nil, nil
		}
		return DecodeSatRanges(v), nil
	}
	v, err := i.g.db.OrdinalSatRangesByOutpoint(ctx, op)
	if err != nil {
		return nil, err
	}
	return DecodeSatRanges(v), nil
}

// trackInscribedSat records a newly inscribed sat in the batch set and
// updates the min/max boundaries.
func (i *ordinalIndexer) trackInscribedSat(sat uint64) {
	i.inscribedSatSet[sat] = struct{}{}
	i.hasInscribedSats = true
	if sat < i.minInscribedSat {
		i.minInscribedSat = sat
	}
	if sat > i.maxInscribedSat {
		i.maxInscribedSat = sat
	}
}

// updateInscribedSats checks if any inscribed sats moved during FIFO
// redistribution and updates their 's' entries. blockInscribedSats
// MUST be sorted. inputRanges MUST be sorted by Start (output of
// MergeSatRanges). Returns inscribed sats NOT found in any output
// (fee sats).
//
// Time: O(log(|blockInscribedSats|) + matches * log(|inputRanges|) * |outputRanges|)
// Two binary searches narrow 96K+ inscribed sats to the few that
// overlap with this tx's input range.
func (i *ordinalIndexer) updateInscribedSats(blockInscribedSats []uint64, inputRanges []SatRange, txHash *chainhash.Hash, outputRanges map[uint32][]SatRange, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) []uint64 {
	if len(inputRanges) == 0 || len(blockInscribedSats) == 0 {
		return nil
	}
	inputMin := inputRanges[0].Start
	inputMax := inputRanges[len(inputRanges)-1].Start + inputRanges[len(inputRanges)-1].Count

	// Binary search to find the sub-slice of inscribed sats in
	// [inputMin, inputMax). O(2*log N) instead of O(N).
	lo := sort.Search(len(blockInscribedSats), func(j int) bool {
		return blockInscribedSats[j] >= inputMin
	})
	hi := sort.Search(len(blockInscribedSats), func(j int) bool {
		return blockInscribedSats[j] >= inputMax
	})
	if lo >= hi {
		return nil
	}

	var feeSats []uint64
	for _, sat := range blockInscribedSats[lo:hi] {
		// Verify this sat is actually in one of the merged input
		// ranges (not in a gap between ranges).
		idx := sort.Search(len(inputRanges), func(j int) bool {
			return inputRanges[j].Start+inputRanges[j].Count > sat
		})
		if idx >= len(inputRanges) {
			continue
		}
		sr := inputRanges[idx]
		if sat < sr.Start || sat >= sr.Start+sr.Count {
			continue
		}

		found := false
		for txOutIdx, outRanges := range outputRanges {
			for _, outRange := range outRanges {
				if sat >= outRange.Start && sat < outRange.Start+outRange.Count {
					outpoint := tbcd.NewOutpoint(*txHash, txOutIdx)
					cache[ordinalSatKey(sat)] = outpoint[:]
					found = true
				}
			}
		}
		if !found {
			feeSats = append(feeSats, sat)
		}
	}
	return feeSats
}

// putRange writes a sat range to the cache, overwriting any existing value.
func (i *ordinalIndexer) putRange(cache map[tbcd.OrdinalKey]tbcd.OrdinalValue, op tbcd.Outpoint, encoded []byte) {
	k := ordinalRangeKey(op)
	cache[k] = encoded
}

func (i *ordinalIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	cache := c.(*Cache[tbcd.OrdinalKey, tbcd.OrdinalValue]).Map()
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

// windBlock processes a single block in the forward direction.
//
// Architecture:
//   - Pre-scan: O(block_inputs) cache reads + O(1) DB scan for the
//     merged input range. Builds blockInscribedSats set.
//   - Pass 1: process non-coinbase txs via windTx, collect fee ranges.
//   - Pass 2: process coinbase with subsidy + fee sats.
//
// Time: O(block_inputs + block_outputs + inscribed_sats_in_range)
// Space: O(cache_entries_per_block)
func (i *ordinalIndexer) windBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) error {
	// One-time check on first call: if resuming from a prior run, the
	// DB may contain inscribed sats. Two iterator seeks to get
	// min/max bounds — O(1), no full scan.
	if !i.inscCheckDone {
		i.inscCheckDone = true
		minSat, maxSat, err := i.g.db.OrdinalInscribedSatBounds(ctx)
		if err == nil {
			i.hasInscribedSats = true
			i.minInscribedSat = minSat
			i.maxInscribedSat = maxSat
		}
	}

	txs := block.Transactions()
	var inscriptionSeq uint32

	// Pre-scan: collect all input sat ranges for non-coinbase txs,
	// then do ONE DB scan for inscribed sats in the combined range.
	// This replaces per-input DB scans (O(inputs_per_block) → O(1)).
	var blockInscribedSats []uint64
	if i.hasInscribedSats {
		var minSat, maxSat uint64
		minSat = math.MaxUint64
		for _, tx := range txs {
			if blockchain.IsCoinBase(tx) {
				continue
			}
			for _, txIn := range tx.MsgTx().TxIn {
				op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
					txIn.PreviousOutPoint.Index)
				ranges, _ := i.satRanges(ctx, op, cache)
				for _, sr := range ranges {
					if sr.Start < minSat {
						minSat = sr.Start
					}
					end := sr.Start + sr.Count
					if end > maxSat {
						maxSat = end
					}
				}
			}
		}

		if minSat < maxSat &&
			minSat <= i.maxInscribedSat &&
			maxSat > i.minInscribedSat {
			dbSats, err := i.g.db.OrdinalInscribedSatsInRange(ctx, minSat, maxSat)
			if err != nil {
				return fmt.Errorf("block inscribed sats scan: %w", err)
			}
			if len(dbSats) > 0 || len(i.inscribedSatSet) > 0 {
				blockInscribedSats = make([]uint64, 0, len(dbSats)+len(i.inscribedSatSet))
				blockInscribedSats = append(blockInscribedSats, dbSats...)
				for sat := range i.inscribedSatSet {
					blockInscribedSats = append(blockInscribedSats, sat)
				}
				sort.Slice(blockInscribedSats, func(a, b int) bool {
					return blockInscribedSats[a] < blockInscribedSats[b]
				})
			}
		}
	}

	// Pass 1: process non-coinbase txs. Collect fee sat ranges and
	// inscribed sats that became fees (input sats not assigned to
	// any output). In ordinal theory fee sats go to the coinbase.
	var blockFeeRanges []SatRange
	var allInscribedFeeSats []uint64

	for _, tx := range txs {
		if blockchain.IsCoinBase(tx) {
			continue
		}
		feeRanges, inscFeeSats, err := i.windTx(ctx, blockHeight, blockHash, tx,
			cache, &inscriptionSeq, blockInscribedSats)
		if err != nil {
			return err
		}
		blockFeeRanges = append(blockFeeRanges, feeRanges...)
		allInscribedFeeSats = append(allInscribedFeeSats, inscFeeSats...)
	}

	// Pass 2: process the coinbase transaction with subsidy + fees.
	coinbaseTx := txs[0]
	subsStart, subsCount := CoinbaseSatRange(blockHeight)
	allInputRanges := make([]SatRange, 0, 1+len(blockFeeRanges))
	allInputRanges = append(allInputRanges, SatRange{Start: subsStart, Count: subsCount})
	allInputRanges = append(allInputRanges, blockFeeRanges...)
	mergedRanges := MergeSatRanges(allInputRanges)

	outputRanges := make(map[uint32][]SatRange)
	var rangeOffset int
	var satOffset uint64
	for txOutIdx, txOut := range coinbaseTx.MsgTx().TxOut {
		outpoint := tbcd.NewOutpoint(*coinbaseTx.Hash(), uint32(txOutIdx))
		if txOut.Value == 0 {
			i.putRange(cache, outpoint, EncodeSatRanges(nil))
			continue
		}
		outRanges, newRangeOffset, newSatOffset := SplitSatRanges(
			mergedRanges, rangeOffset, satOffset, uint64(txOut.Value))
		rangeOffset = newRangeOffset
		satOffset = newSatOffset
		outputRanges[uint32(txOutIdx)] = outRanges
		i.putRange(cache, outpoint, EncodeSatRanges(outRanges))
	}

	// Update 's' entries for inscribed sats that became fees.
	// Inscribed fee sats are rare on mainnet (~0 per typical block).
	// Triple-nested loop is justified: |allInscribedFeeSats| is
	// typically 0, |outputRanges| ≤ coinbase outputs (~1-2),
	// |ranges per output| is typically 1.
	for _, sat := range allInscribedFeeSats {
		for txOutIdx, outRanges := range outputRanges {
			for _, sr := range outRanges {
				if sat >= sr.Start && sat < sr.Start+sr.Count {
					outpoint := tbcd.NewOutpoint(*coinbaseTx.Hash(), txOutIdx)
					cache[ordinalSatKey(sat)] = outpoint[:]
				}
			}
		}
	}

	return nil
}

// windTx processes a single non-coinbase transaction: FIFO
// redistribution, inscribed sat tracking, and inscription detection.
// Returns fee sat ranges and inscribed sat numbers that became fees.
//
// Time: O(inputs + outputs + |blockInscribedSats|*log(mergedRanges))
// Space: O(inputs + outputs) for range slices.
func (i *ordinalIndexer) windTx(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, tx *btcutil.Tx, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue, inscriptionSeq *uint32, blockInscribedSats []uint64) (feeRanges []SatRange, inscribedFeeSats []uint64, err error) {
	txIns := tx.MsgTx().TxIn
	txOuts := tx.MsgTx().TxOut

	// Step 1: Collect per-input sat ranges.
	// O(inputs) cache lookups (all pre-fetched by fixupCacheHook).
	allInputRanges := make([]SatRange, 0, len(txIns))
	perInputStart := make([]uint64, 0, len(txIns))

	for _, txIn := range txIns {
		op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
			txIn.PreviousOutPoint.Index)
		ranges, err := i.satRanges(ctx, op, cache)
		if err != nil {
			return nil, nil, fmt.Errorf("sat ranges for %v: %w", op, err)
		}
		if len(ranges) > 0 {
			perInputStart = append(perInputStart, ranges[0].Start)
		} else {
			perInputStart = append(perInputStart, 0)
		}
		allInputRanges = append(allInputRanges, ranges...)

		// Mark spent input's sat ranges for deletion. Overwrite
		// with nil (never delete map keys). Mirrors the utxo
		// indexer's sentinel pattern: the value encodes intent,
		// the key set is stable across the batch.
		rk := ordinalRangeKey(op)
		cache[rk] = nil
	}

	// Step 2: Flatten contiguous ranges for FIFO split. O(inputs).
	mergedRanges := MergeSatRanges(allInputRanges)

	// Step 3: Split across outputs via FIFO. O(outputs).
	outputRanges := make(map[uint32][]SatRange, len(txOuts))
	var rangeOffset int
	var satOffset uint64
	for txOutIdx, txOut := range txOuts {
		outpoint := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
		if txOut.Value == 0 {
			i.putRange(cache, outpoint, EncodeSatRanges(nil))
			continue
		}
		outRanges, newRangeOffset, newSatOffset := SplitSatRanges(
			mergedRanges, rangeOffset, satOffset, uint64(txOut.Value))
		rangeOffset = newRangeOffset
		satOffset = newSatOffset
		outputRanges[uint32(txOutIdx)] = outRanges
		i.putRange(cache, outpoint, EncodeSatRanges(outRanges))
	}

	// Compute fee: remaining sats after all outputs consumed.
	for idx := rangeOffset; idx < len(mergedRanges); idx++ {
		r := mergedRanges[idx]
		if idx == rangeOffset && satOffset > 0 {
			remaining := r.Count - satOffset
			if remaining > 0 {
				feeRanges = append(feeRanges, SatRange{
					Start: r.Start + satOffset,
					Count: remaining,
				})
			}
		} else {
			feeRanges = append(feeRanges, r)
		}
	}

	// Step 4: Track inscribed sat movement.
	// O(|blockInscribedSats| * log(|mergedRanges|)) via binary search.
	if len(blockInscribedSats) > 0 {
		inscribedFeeSats = i.updateInscribedSats(blockInscribedSats, mergedRanges, tx.Hash(), outputRanges, cache)
	}

	// Step 5: Detect new inscriptions in witness data.
	// O(inputs) — ParseInscriptionEnvelope exits early on non-inscription inputs.
	for inputIdx, txIn := range txIns {
		envelope, err := ParseInscriptionEnvelope(txIn.Witness)
		if err != nil || envelope == nil {
			continue
		}

		var inscribedSat uint64
		if envelope.Pointer != nil {
			inscribedSat = satAtOutputOffset(
				outputRanges, txOuts,
				*envelope.Pointer)
		} else if inputIdx < len(perInputStart) {
			inscribedSat = perInputStart[inputIdx]
		}

		inscID := makeInscriptionID(tx.Hash(), uint32(inputIdx))
		cursed := isInscriptionCursed(blockHeight, inputIdx, envelope)

		cache[ordinalInscriptionKey(inscID)] = encodeInscriptionValue(
			inscribedSat, blockHash, cursed, envelope)

		for txOutIdx, outRanges := range outputRanges {
			for _, sr := range outRanges {
				if inscribedSat >= sr.Start && inscribedSat < sr.Start+sr.Count {
					outpoint := tbcd.NewOutpoint(*tx.Hash(), txOutIdx)
					cache[ordinalSatKey(inscribedSat)] = outpoint[:]
					i.trackInscribedSat(inscribedSat)
					goto satFound
				}
			}
		}
	satFound:

		cache[ordinalSatInscriptionKey(inscribedSat, inscID)] = []byte{}
		cache[ordinalBlockInscriptionKey(blockHash, *inscriptionSeq)] = inscID[:]

		*inscriptionSeq++
	}

	return feeRanges, inscribedFeeSats, nil
}

// unwindBlock reverses a single block. Deletes output ranges, restores
// input ranges, and removes inscriptions created in this block.
// Uses parallel DB reads for input range restoration.
//
// Time: O(block_txs * (outputs + inputs) + inscriptions_in_block)
// DB reads for input restoration are parallelized (128 concurrent).
func (i *ordinalIndexer) unwindBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) error {
	txs := block.Transactions()

	// Phase 1: Delete all output sat ranges (cache-only, fast).
	for k := len(txs) - 1; k >= 0; k-- {
		tx := txs[k]
		for txOutIdx := range tx.MsgTx().TxOut {
			outpoint := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
			cache[ordinalRangeKey(outpoint)] = nil
		}
	}

	// Phase 2: Restore input sat ranges from DB using parallel reads.
	slots := 128
	ch := make(chan struct{}, slots)
	defer close(ch)
	for range slots {
		select {
		case <-ctx.Done():
			return nil
		case ch <- struct{}{}:
		default:
			return errors.New("unwindBlock: semaphore init failed")
		}
	}

	w := new(sync.WaitGroup)
	defer w.Wait()

	for _, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ch:
			}

			w.Add(1)
			go i.fetchSatRangesParallel(ctx, ch, w, op, cache)
		}
	}
	w.Wait()

	cl := len(ch)
	if cl != slots {
		return fmt.Errorf("unwindBlock: channel not empty: %v", cl)
	}

	// Phase 3: Delete inscriptions created in this block.
	// OrdinalInscriptionsByBlockHash returns all inscription IDs for
	// the block. Then each inscription is read to get its sat number
	// for targeted cache deletions.
	// O(inscriptions_in_block) DB reads — sequential since these
	// are small point lookups and the count is typically < 100.
	inscIDs, err := i.g.db.OrdinalInscriptionsByBlockHash(ctx, *blockHash)
	if err != nil {
		return fmt.Errorf("inscriptions by block %v: %w", blockHash, err)
	}
	for seq, inscID := range inscIDs {
		iValue, err := i.g.db.OrdinalInscriptionByID(ctx, inscID)
		if err != nil {
			return fmt.Errorf("inscription %x: %w", inscID, err)
		}
		satNumber := binary.BigEndian.Uint64(iValue[:8])

		cache[ordinalInscriptionKey(inscID)] = nil
		cache[ordinalSatKey(satNumber)] = nil
		cache[ordinalSatInscriptionKey(satNumber, inscID)] = nil
		cache[ordinalBlockInscriptionKey(blockHash, uint32(seq))] = nil
	}

	return nil
}

func (i *ordinalIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[tbcd.OrdinalKey, tbcd.OrdinalValue])
	err := i.g.db.BlockOrdinalUpdate(ctx, direction, cache.Map(), atHash)
	if err != nil {
		return err
	}
	// Inscribed sats from this batch are now in DB; clear the set.
	// Min/max boundaries persist across batches (they only grow).
	clear(i.inscribedSatSet)
	return nil
}

// fetchSatRangesParallel fetches sat ranges for a single outpoint and
// writes them into the cache under the indexer mutex. Mirrors
// Server.fetchOPParallel from utxoindex.go.
func (i *ordinalIndexer) fetchSatRangesParallel(ctx context.Context, c chan struct{}, w *sync.WaitGroup, op tbcd.Outpoint, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) {
	defer w.Done()
	if c != nil {
		defer func() {
			select {
			case <-ctx.Done():
			case c <- struct{}{}:
			}
		}()
	}

	v, err := i.g.db.OrdinalSatRangesByOutpoint(ctx, op)
	if err != nil {
		// Created and spent in the same block.
		return
	}
	k := ordinalRangeKey(op)
	i.mtx.Lock()
	cache[k] = v
	i.mtx.Unlock()
}

// fixupCacheHook pre-fetches sat ranges for all input outpoints in the
// upcoming block using parallel DB reads. Mirrors
// Server.fixupCacheChannel from utxoindex.go.
//
// Time: O(cache_misses) DB reads, 128-way parallel.
func (i *ordinalIndexer) fixupCacheHook(ctx context.Context, block *btcutil.Block, c indexerCache) error {
	cache := c.(*Cache[tbcd.OrdinalKey, tbcd.OrdinalValue]).Map()

	slots := 128
	ch := make(chan struct{}, slots)
	defer close(ch)
	for range slots {
		select {
		case <-ctx.Done():
			return nil
		case ch <- struct{}{}:
		default:
			return errors.New("fixupCacheHook: shouldn't happen")
		}
	}

	w := new(sync.WaitGroup)
	defer w.Wait()

	for _, tx := range block.Transactions() {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			k := ordinalRangeKey(op)
			i.mtx.Lock()
			_, ok := cache[k]
			i.mtx.Unlock()
			if ok {
				continue
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ch:
			}

			w.Add(1)
			go i.fetchSatRangesParallel(ctx, ch, w, op, cache)
		}
	}

	return nil
}

func (i *ordinalIndexer) onSyncComplete() {}

func (i *ordinalIndexer) readCacheInfo() string { return "" }

// Key construction helpers. These match the SOW prefix scheme exactly.

func ordinalRangeKey(op tbcd.Outpoint) tbcd.OrdinalKey {
	var key tbcd.OrdinalKey
	key[0] = 'r'
	copy(key[1:], op[:])
	return key
}

func ordinalSatKey(satNumber uint64) tbcd.OrdinalKey {
	var key tbcd.OrdinalKey
	key[0] = 's'
	binary.BigEndian.PutUint64(key[1:], satNumber)
	return key
}

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

func makeInscriptionID(txHash *chainhash.Hash, inputIdx uint32) [36]byte {
	var id [36]byte
	copy(id[:32], txHash[:])
	binary.LittleEndian.PutUint32(id[32:], inputIdx)
	return id
}

// satAtOutputOffset finds the sat number at a given offset within the
// concatenated output sat ranges. Used for pointer tag (tag 2) handling.
//
// Time: O(outputs * ranges_per_output). Linear scan is justified
// because outputs are ordered and offset is a position in the
// concatenated sequence — binary search would require precomputing
// cumulative sums.
func satAtOutputOffset(outputRanges map[uint32][]SatRange, txOuts []*wire.TxOut, offset uint64) uint64 {
	var pos uint64
	for txOutIdx := range txOuts {
		ranges, ok := outputRanges[uint32(txOutIdx)]
		if !ok {
			continue
		}
		for _, sr := range ranges {
			if offset < pos+sr.Count {
				return sr.Start + (offset - pos)
			}
			pos += sr.Count
		}
	}
	if ranges, ok := outputRanges[0]; ok && len(ranges) > 0 {
		return ranges[0].Start
	}
	return 0
}
