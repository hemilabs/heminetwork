// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"fmt"
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

func NewOrdinalIndexer(g geometryParams, cacheLen int, enabled bool, ordinalGenesis *HashHeight, computeInscSat func(ctx context.Context, txid chainhash.Hash, inputIndex uint32) (uint64, error), watermarkGap time.Duration) Indexer {
	oi := &ordinalIndexer{
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

// encodeWorkValue encodes the commit outpoint and inscription ID.
// Layout: commit_txid(32) + commit_vout(4) + inscription_id(36) = 72 bytes.
func encodeWorkValue(commitTxid chainhash.Hash, commitVout uint32, inscID [36]byte) tbcd.OrdinalWorkValue {
	var v tbcd.OrdinalWorkValue
	copy(v[:32], commitTxid[:])
	binary.BigEndian.PutUint32(v[32:36], commitVout)
	copy(v[36:72], inscID[:])
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
		for inputIdx, txIn := range tx.MsgTx().TxIn {
			envelope, err := ParseInscriptionEnvelope(txIn.Witness)
			if err != nil || envelope == nil {
				continue
			}

			inscID := makeInscriptionID(tx.Hash(), uint32(inputIdx))
			cursed := isInscriptionCursed(blockHeight, inputIdx, envelope)

			if fullComputation {
				// Above watermark: compute sat via backward walk.
				satNumber, err := i.computeInscSat(ctx, *tx.Hash(), uint32(inputIdx))
				if err != nil {
					return fmt.Errorf("compute inscribed sat at %v:%d: %w",
						tx.Hash(), inputIdx, err)
				}

				// 'i' with real sat number.
				cache[ordinalInscriptionKey(inscID)] = encodeInscriptionValue(
					satNumber, blockHash, cursed, envelope)

				// 'n': block→inscription index.
				cache[ordinalBlockInscriptionKey(blockHash, inscriptionSeq)] = inscID[:]

				// 'a': sat→inscription reverse index (immutable).
				cache[ordinalSatInscriptionKey(satNumber, inscID)] = []byte{}
			} else {
				// Below watermark: fast path (IBD speed).
				cache[ordinalInscriptionKey(inscID)] = encodeInscriptionValue(
					0, blockHash, cursed, envelope)

				cache[ordinalBlockInscriptionKey(blockHash, inscriptionSeq)] = inscID[:]

				// 'w': work queue for background populator.
				prevOut := txIn.PreviousOutPoint
				i.workCache[ordinalWorkKey(blockHeight, uint16(inscriptionSeq))] = encodeWorkValue(prevOut.Hash, prevOut.Index, inscID)
			}

			inscriptionSeq++
		}
	}

	return nil
}

// unwindBlock reverses a single block. Panics if the unwind reaches
// the watermark — the safety gap makes this a "Bitcoin is broken" event.
func (i *ordinalIndexer) unwindBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) error {
	wm, err := i.getWatermark(ctx)
	if err != nil {
		return err
	}
	if wm != nil && blockHeight < *wm {
		panic(fmt.Sprintf("ordinal unwind below watermark: height %d < watermark %d",
			blockHeight, *wm))
	}

	inscIDs, err := i.g.db.OrdinalInscriptionsByBlockHash(ctx, *blockHash)
	if err != nil {
		return fmt.Errorf("inscriptions by block %v: %w", blockHash, err)
	}
	for seq, inscID := range inscIDs {
		// Read 'i' to check if sat was computed (above watermark = real sat).
		iValue, err := i.g.db.OrdinalInscriptionByID(ctx, inscID)
		if err == nil && len(iValue) >= 8 {
			satNumber := binary.BigEndian.Uint64(iValue[:8])
			if satNumber != 0 {
				// Full computation was done — delete 'a'.
				cache[ordinalSatInscriptionKey(satNumber, inscID)] = nil
			}
		}

		cache[ordinalInscriptionKey(inscID)] = nil
		cache[ordinalBlockInscriptionKey(blockHash, uint32(seq))] = nil
		// Harmless no-op if 'w' doesn't exist (above watermark).
		i.workCache[ordinalWorkKey(blockHeight, uint16(seq))] = tbcd.OrdinalWorkValueDelete
	}

	return nil
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

	if err := i.g.db.BlockOrdinalUpdate(ctx, direction, cache.Map(), atHash); err != nil {
		return err
	}
	return i.g.db.BlockOrdinalWorkUpdate(ctx, i.workCache)
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
	ctx := context.Background()

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
