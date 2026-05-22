// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type ordinalIndexer struct {
	indexerCommon

	runCtx         context.Context
	cacheCapacity  int
	workCache      map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue
	computeInscSat func(ctx context.Context, txid chainhash.Hash, inputIndex uint32) (uint64, error)
	watermarkGap   time.Duration
	populating     atomic.Uint32 // reentrancy guard for onSyncComplete

	// Watermark state. Loaded from DB on first access, written atomically
	// via the 'm' prefix OrdinalKey in the ordinal cache.
	watermark      *uint32 // nil = not loaded yet
	watermarkDirty bool
}

var (
	_ Indexer = (*ordinalIndexer)(nil)
	_ indexer = (*ordinalIndexer)(nil)
)

func NewOrdinalIndexer(ctx context.Context, g geometryParams, cacheLen int, enabled bool, ordinalGenesis *HashHeight, computeInscSat func(ctx context.Context, txid chainhash.Hash, inputIndex uint32) (uint64, error), watermarkGap time.Duration) Indexer {
	oi := &ordinalIndexer{
		runCtx:         ctx,
		cacheCapacity:  cacheLen,
		workCache:      make(map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue),
		computeInscSat: computeInscSat,
		watermarkGap:   watermarkGap,
	}
	oi.indexerCommon = indexerCommon{
		name:    "ordinal",
		enabled: enabled,
		g:       g,
		p:       oi,
		genesis: ordinalGenesis,
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
	srcInputIdx uint16
	srcOffset   uint64
}

// ordinalRevealSentinel marks an 'o' entry as a reveal (no prior location
// to restore on unwind). 0xFFFF cannot be a real input index in any
// consensus-valid transaction.
const ordinalRevealSentinel uint16 = 0xFFFF

// windBlock scans a block for inscription envelopes and records reveals.
// Below watermark: fast path (sat=0, writes 'w' work queue entry).
// Above watermark: full computation (backward walk, writes 'a' and real sat).
func (i *ordinalIndexer) windBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) error {
	txs := block.Transactions()
	var inscriptionSeq uint32

	wm, err := i.getWatermark(ctx)
	if err != nil {
		return err
	}

	// Check if this block crosses the watermark threshold.
	// Wall clock detection, block height storage.
	if wm == nil {
		blockTime := block.MsgBlock().Header.Timestamp
		if time.Since(blockTime) < i.watermarkGap {
			i.setWatermark(blockHeight)
			wm = &blockHeight
			log.Infof("ordinal watermark set at height %d", blockHeight)
		}
	}

	fullComputation := wm != nil

	for _, tx := range txs {
		if blockchain.IsCoinBase(tx) {
			continue
		}
		txid := *tx.Hash()

		// Gather flotsam (inscribed sats in flight) for this tx, walking
		// inputs once and accumulating the input-stream value. A reveal
		// sits at the running value (offset 0 of its input). A transfer
		// sits at running value + the inscription's offset in the spent
		// output.
		var fl []flotsam
		var inputValue uint64
		for inputIdx, txIn := range tx.MsgTx().TxIn {
			prevOut := txIn.PreviousOutPoint

			// Transfers: does this input spend a tracked outpoint?
			spentOP := tbcd.NewOutpoint(prevOut.Hash, prevOut.Index)
			tracked, terr := i.g.db.OrdinalInscriptionsByOutpointWithOffset(ctx, spentOP)
			if terr != nil {
				return fmt.Errorf("tracked lookup %v: %w", spentOP, terr)
			}
			// Also check the in-block cache: an outpoint created earlier
			// in THIS block won't be in the DB yet.
			tracked = append(tracked, trackedInBlock(cache, spentOP)...)
			for _, t := range tracked {
				fl = append(fl, flotsam{
					inscID:      t.InscID,
					pos:         inputValue + t.Offset,
					srcInputIdx: uint16(inputIdx),
					srcOffset:   t.Offset,
				})
				// Remove the old 'o' entry — the sat is moving.
				cache[ordinalOutpointKey(spentOP, t.Offset)] = nil
			}

			// Reveals: does this input carry an inscription envelope?
			envelope, perr := ParseInscriptionEnvelope(txIn.Witness)
			if perr == nil && envelope != nil {
				inscID := makeInscriptionID(tx.Hash(), uint32(inputIdx))
				fl = append(fl, flotsam{
					inscID:      inscID,
					pos:         inputValue,
					isReveal:    true,
					cursed:      isInscriptionCursed(blockHeight, inputIdx, envelope),
					envelope:    envelope,
					srcInputIdx: ordinalRevealSentinel,
				})
			}

			v, verr := inputOutputValue(ctx, i.g.db, prevOut.Hash, prevOut.Index)
			if verr != nil {
				return fmt.Errorf("input value %v: %w", prevOut, verr)
			}
			inputValue += v
		}

		if len(fl) == 0 {
			continue
		}

		// Place all flotsam in offset order (ord sorts before placing).
		sort.Slice(fl, func(a, b int) bool { return fl[a].pos < fl[b].pos })

		for _, f := range fl {
			f := f // local copy; f.inscID[:] is sliced into the cache below
			locVout, locOffset, landed := placeInOutputs(tx.MsgTx().TxOut, f.pos)

			if f.isReveal {
				if fullComputation {
					revealInput := binary.LittleEndian.Uint32(f.inscID[32:36])
					satNumber, err := i.computeInscSat(ctx, txid, revealInput)
					if err != nil {
						return fmt.Errorf("compute inscribed sat at %v:%d: %w",
							txid, revealInput, err)
					}
					cache[ordinalInscriptionKey(f.inscID)] = encodeInscriptionValue(
						satNumber, blockHash, f.cursed, f.envelope)
					cache[ordinalBlockInscriptionKey(blockHash, inscriptionSeq)] = f.inscID[:]
					cache[ordinalSatInscriptionKey(satNumber, f.inscID)] = []byte{}
				} else {
					cache[ordinalInscriptionKey(f.inscID)] = encodeInscriptionValue(
						0, blockHash, f.cursed, f.envelope)
					cache[ordinalBlockInscriptionKey(blockHash, inscriptionSeq)] = f.inscID[:]
					// 'w': work queue for background sat-number populator.
					i.workCache[ordinalWorkKey(blockHeight, uint16(inscriptionSeq))] = encodeWorkValue(f.inscID)
				}
				inscriptionSeq++
			}

			// 'o': ownership tracker. The !landed case (sat lands in
			// the fee) is handled in the fee/coinbase phase per
			// ordinals5-forward-tracker-proof.md "Operation D". Until
			// then a fee-bound inscribed sat is not re-tracked.
			if landed {
				op := tbcd.NewOutpoint(txid, locVout)
				cache[ordinalOutpointKey(op, locOffset)] = encodeOutpointValue(
					f.inscID, f.srcInputIdx, f.srcOffset)
			}
		}
	}

	return nil
}

// placeInOutputs locates FIFO position pos within a tx's outputs.
// Returns (vout, offset_within_output, true) if the sat lands in an
// output, or (0, 0, false) if pos falls beyond all outputs (the sat is
// in the fee — Phase D handles fee→coinbase placement). Zero-value
// outputs (OP_RETURN etc.) hold no sats and are skipped.
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

// trackedInBlock finds 'o' entries written earlier in the current block's
// cache that match the spent outpoint (create-and-spend within one block).
// The DB doesn't yet have these — they live only in the pending cache.
// Returns located inscriptions (inscID + offset); skips tombstoned (nil)
// entries.
// trackedInBlock resolves create-and-spend within a single block: an
// outpoint created earlier in this block is not yet in the DB, so scan
// the pending cache for 'o' entries matching the spent outpoint.
//
// Cost is O(cache) per call, O(inputs*cache) per block. Bounded by one
// block's pending writes; acceptable until measured. Revisit in Phase D
// if mass-inscription blocks make this quadratic scan a hot spot.
func trackedInBlock(cache map[tbcd.OrdinalKey]tbcd.OrdinalValue, op tbcd.Outpoint) []tbcd.OrdinalLocatedInscription {
	var prefix [37]byte
	prefix[0] = 'o'
	copy(prefix[1:], op[1:37])

	var result []tbcd.OrdinalLocatedInscription
	for k, v := range cache {
		if k[0] != 'o' {
			continue
		}
		if !bytes.Equal(k[1:37], prefix[1:37]) {
			continue
		}
		if len(v) < 36 {
			continue // tombstone or malformed
		}
		var li tbcd.OrdinalLocatedInscription
		copy(li.InscID[:], v[:36])
		li.Offset = binary.BigEndian.Uint64(k[37:45])
		li.Value = append([]byte(nil), v...)
		result = append(result, li)
	}
	return result
}

// inputOutputValue looks up the value of a specific outpoint.
func inputOutputValue(ctx context.Context, db tbcd.Database, txid chainhash.Hash, vout uint32) (uint64, error) {
	blockHash, err := db.BlockHashByTxId(ctx, txid)
	if err != nil {
		return 0, fmt.Errorf("tx %v: %w", txid, err)
	}
	block, err := db.BlockByHash(ctx, *blockHash)
	if err != nil {
		return 0, fmt.Errorf("block %v: %w", blockHash, err)
	}
	for _, tx := range block.Transactions() {
		if *tx.Hash() == txid {
			if int(vout) >= len(tx.MsgTx().TxOut) {
				return 0, fmt.Errorf("vout %d out of range", vout)
			}
			return uint64(tx.MsgTx().TxOut[vout].Value), nil
		}
	}
	return 0, fmt.Errorf("tx %v not in block", txid)
}

// unwindBlock reverses a single block. Panics if the unwind goes
// BELOW the watermark. Unwinding AT the watermark is safe.
//
// A reorg reaching below the watermark means a reorg deeper than
// OrdinalWatermarkGap (default 24h) — catastrophic for Bitcoin.
func (i *ordinalIndexer) unwindBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) error {
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
				cache[ordinalSatInscriptionKey(satNumber, inscID)] = nil
			}
		}

		cache[ordinalInscriptionKey(inscID)] = nil
		cache[ordinalBlockInscriptionKey(blockHash, uint32(seq))] = nil
		// Harmless no-op if 'w' doesn't exist (above watermark).
		i.workCache[ordinalWorkKey(blockHeight, uint16(seq))] = tbcd.OrdinalWorkValueDelete
	}

	// Reverse the 'o' tracker for this block.
	return i.unwindOutpointTracker(ctx, block, cache)
}

// unwindOutpointTracker reverses the 'o' ownership entries windBlock placed
// for every non-coinbase tx in the block. For each inscription now sitting
// in a tx output it deletes the entry; if the entry is a transfer it
// restores the prior 'o' entry at the spent outpoint, recovered from the
// block via the stored source input index, with the stored source offset.
// Self-contained: reads only the ordinal index and the block in hand — no
// input amounts, no tx/utxo index.
func (i *ordinalIndexer) unwindOutpointTracker(ctx context.Context, block *btcutil.Block, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) error {
	txs := block.Transactions()
	for ti := len(txs) - 1; ti >= 0; ti-- {
		tx := txs[ti]
		if blockchain.IsCoinBase(tx) {
			continue
		}
		txIns := tx.MsgTx().TxIn

		for _, ob := range outpointsOf(tx) {
			located, lerr := i.locatedAtOutpoint(ctx, cache, ob.op)
			if lerr != nil {
				return fmt.Errorf("unwind tracked lookup %v: %w", ob.op, lerr)
			}
			for _, li := range located {
				_, srcInputIdx, srcOffset, isTransfer, derr := decodeOutpointValue(li.Value)
				if derr != nil {
					// We wrote this 'o' value; a malformed read means the
					// ordinal index is corrupt. Crash, don't limp on.
					panic(fmt.Sprintf("bug: ordinal unwind: corrupt 'o' value at %v: %v", ob.op, derr))
				}

				// Delete the 'o' entry at the current location.
				cache[ordinalOutpointKey(ob.op, li.Offset)] = nil

				// Reveal: nothing to restore.
				if !isTransfer {
					continue
				}

				// Transfer: recover the source outpoint from the block
				// (the input this sat was spent through) and restore. A
				// srcInputIdx past the tx's inputs means the stored value
				// is corrupt — crash rather than index garbage.
				if int(srcInputIdx) >= len(txIns) {
					panic(fmt.Sprintf("bug: ordinal unwind: 'o' at %v src input %d out of range (%d inputs)",
						ob.op, srcInputIdx, len(txIns)))
				}
				prevOut := txIns[srcInputIdx].PreviousOutPoint
				srcOP := tbcd.NewOutpoint(prevOut.Hash, prevOut.Index)
				cache[ordinalOutpointKey(srcOP, srcOffset)] = li.Value
			}
		}
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
// Complexity: O(D + C) per call, where D is the DB entries at op (a keyed
// prefix scan, typically 0-1) and C is the pending cache size for the
// current unwind batch. The cache scan dominates: unwinding a batch of B
// blocks is O(outputs * C). C is bounded by the inscriptions in the batch,
// which are sparse (reorgs are shallow; inscriptions are rare per block),
// so this is not a steady-state hot path — unwind runs only on reorg and
// rebuild. If a deep reorg over inscription-dense blocks ever shows up in
// a profile, give the cache a prefix index; until then a scan is correct
// and simpler. See BenchmarkLocatedAtOutpoint:
//
//	cache=100    ~1.9µs/op   776 B/op   13 allocs/op
//	cache=1000   ~14µs/op    776 B/op   13 allocs/op
//	cache=10000  ~128µs/op   776 B/op   13 allocs/op
//
// Linear in cache size, flat allocations. A realistic reorg batch holds
// tens of 'o' entries, so this is microseconds per lookup.
func (i *ordinalIndexer) locatedAtOutpoint(ctx context.Context, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue, op tbcd.Outpoint) ([]tbcd.OrdinalLocatedInscription, error) {
	dbLocated, err := i.g.db.OrdinalInscriptionsByOutpointWithOffset(ctx, op)
	if err != nil {
		return nil, err
	}

	byKey := make(map[tbcd.OrdinalKey]tbcd.OrdinalLocatedInscription, len(dbLocated))
	var order []tbcd.OrdinalKey
	for _, li := range dbLocated {
		k := ordinalOutpointKey(op, li.Offset)
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = li
	}

	// Overlay the pending cache: tombstone removes, a value adds/overrides.
	var prefix [37]byte
	prefix[0] = 'o'
	copy(prefix[1:], op[1:37])
	for k, v := range cache {
		if k[0] != 'o' || !bytes.Equal(k[1:37], prefix[1:37]) {
			continue
		}
		if len(v) < 36 { // tombstone
			delete(byKey, k)
			continue
		}
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		var li tbcd.OrdinalLocatedInscription
		copy(li.InscID[:], v[:36])
		li.Offset = binary.BigEndian.Uint64(k[37:45])
		li.Value = append([]byte(nil), v...)
		byKey[k] = li
	}

	result := make([]tbcd.OrdinalLocatedInscription, 0, len(byKey))
	for _, k := range order {
		if li, ok := byKey[k]; ok {
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
	cache := c.(*Cache[tbcd.OrdinalKey, tbcd.OrdinalValue])

	// Write watermark into the ordinal cache so it's committed atomically.
	if i.watermarkDirty && i.watermark != nil {
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], *i.watermark)
		cache.Map()[watermarkOrdinalKey()] = tbcd.OrdinalValue(v[:])
		i.watermarkDirty = false
	}

	if err := i.g.db.BlockOrdinalUpdate(ctx, direction, cache.Map(), i.workCache, atHash); err != nil {
		return err
	}
	return nil
}

// fetchSatRangesParallel fetches sat ranges for a single outpoint and
// writes them into the cache under the indexer mutex. Mirrors
// Server.fetchOPParallel from utxoindex.go.
func (i *ordinalIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	return nil
}

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

// ordinalOutpointKey: 'o' + txid(32) + vout(4) + offset(8) = 45 bytes.
// Maps an inscribed sat's location (outpoint + byte offset within the
// output) to its inscription. Prefix-scannable by 'o'+txid+vout to list
// all inscriptions on an outpoint in offset order. The offset in the key
// guarantees uniqueness — no two inscribed sats share a location.
// Note: Outpoint is [u-prefix(1) + txid(32) + vout(4)] = 37 bytes; we copy
// only the txid+vout payload (op[1:37]).
func ordinalOutpointKey(op tbcd.Outpoint, offset uint64) tbcd.OrdinalKey {
	var key tbcd.OrdinalKey
	key[0] = 'o'
	copy(key[1:37], op[1:37]) // txid(32) + vout(4)
	binary.BigEndian.PutUint64(key[37:], offset)
	return key
}

func makeInscriptionID(txHash *chainhash.Hash, inputIdx uint32) [36]byte {
	var id [36]byte
	copy(id[:32], txHash[:])
	binary.LittleEndian.PutUint32(id[32:], inputIdx)
	return id
}

// 'o' value layout: inscID(36) + srcInputIdx(2) + srcOffset(8) = 46 bytes.
// srcInputIdx is the index, within the spending tx, of the input that
// consumed the inscribed sat on a transfer; the source outpoint is
// recovered on unwind from tx.TxIn[srcInputIdx].PreviousOutPoint (free
// from the block), so it is not stored. srcOffset is the inscription's
// offset within the spent output. A reveal stores srcInputIdx =
// ordinalRevealSentinel (no prior location to restore). This lets unwind
// reverse transfers from our own index alone — no input amounts, no
// tx/utxo index reads.
const ordinalOutpointValueLen = 36 + 2 + 8

func encodeOutpointValue(inscID [36]byte, srcInputIdx uint16, srcOffset uint64) tbcd.OrdinalValue {
	v := make([]byte, ordinalOutpointValueLen)
	copy(v[:36], inscID[:])
	binary.BigEndian.PutUint16(v[36:38], srcInputIdx)
	binary.BigEndian.PutUint64(v[38:46], srcOffset)
	return v
}

// decodeOutpointValue returns the inscription ID, the source input index,
// the source offset, and whether the entry is a transfer (true) or reveal
// (false, sentinel source).
func decodeOutpointValue(v []byte) (inscID [36]byte, srcInputIdx uint16, srcOffset uint64, isTransfer bool, err error) {
	if len(v) != ordinalOutpointValueLen {
		return inscID, 0, 0, false, fmt.Errorf("invalid 'o' value length: %d", len(v))
	}
	copy(inscID[:], v[:36])
	srcInputIdx = binary.BigEndian.Uint16(v[36:38])
	srcOffset = binary.BigEndian.Uint64(v[38:46])
	isTransfer = srcInputIdx != ordinalRevealSentinel
	return inscID, srcInputIdx, srcOffset, isTransfer, nil
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
