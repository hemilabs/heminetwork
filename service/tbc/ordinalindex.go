// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type ordinalIndexer struct {
	indexerCommon

	cacheCapacity int
}

var (
	_ Indexer = (*ordinalIndexer)(nil)
	_ indexer = (*ordinalIndexer)(nil)
)

func NewOrdinalIndexer(g geometryParams, cacheLen int, enabled bool) Indexer {
	oi := &ordinalIndexer{
		cacheCapacity: cacheLen,
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
	return NewCache[tbcd.OrdinalKey, []byte](i.cacheCapacity)
}

func (i *ordinalIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.g.db.BlockHeaderByOrdinalIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

// satRanges retrieves sat ranges for an outpoint from cache or DB.
func (i *ordinalIndexer) satRanges(ctx context.Context, op tbcd.Outpoint, cache map[tbcd.OrdinalKey][]byte) ([]SatRange, error) {
	k := ordinalRangeKey(op)
	if v, ok := cache[k]; ok {
		if v == nil {
			// Deleted in cache.
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

// updateInscribedSats checks if any inscribed sats moved during FIFO
// redistribution and updates their 's' entries. Uses a range scan on the
// DB's 's' prefix for each input sat range to find inscribed sats
// efficiently (inscribed sats are sparse relative to total sats).
func (i *ordinalIndexer) updateInscribedSats(ctx context.Context, inputRanges []SatRange, txHash *chainhash.Hash, outputRanges map[uint32][]SatRange, cache map[tbcd.OrdinalKey][]byte) error {
	for _, sr := range inputRanges {
		inscribedSats, err := i.g.db.OrdinalInscribedSatsInRange(ctx, sr.Start, sr.Start+sr.Count)
		if err != nil {
			return fmt.Errorf("inscribed sats in range: %w", err)
		}
		// Also check cache for 's' entries.
		inscribedSats = append(inscribedSats, inscribedSatsFromCache(cache, sr.Start, sr.Start+sr.Count)...)

		for _, sat := range inscribedSats {
			// Find which output this sat ended up in.
			for txOutIdx, outRanges := range outputRanges {
				for _, outRange := range outRanges {
					if sat >= outRange.Start && sat < outRange.Start+outRange.Count {
						outpoint := tbcd.NewOutpoint(*txHash, txOutIdx)
						cache[ordinalSatKey(sat)] = outpoint[:]
					}
				}
			}
		}
	}
	return nil
}

func (i *ordinalIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	cache := c.(*Cache[tbcd.OrdinalKey, []byte]).Map()
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

func (i *ordinalIndexer) windBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey][]byte) error {
	var inscriptionSeq uint32

	for _, tx := range block.Transactions() {
		// Step 1: Collect per-input sat ranges for FIFO and inscription
		// assignment. perInputRanges tracks boundaries per input so
		// we can determine which sat an inscription in input N lands on.
		var allInputRanges []SatRange
		var perInputStart []uint64 // start sat index per input

		if blockchain.IsCoinBase(tx) {
			start, count := CoinbaseSatRange(blockHeight)
			allInputRanges = []SatRange{{Start: start, Count: count}}
			perInputStart = []uint64{start}
		} else {
			for _, txIn := range tx.MsgTx().TxIn {
				op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
					txIn.PreviousOutPoint.Index)
				ranges, err := i.satRanges(ctx, op, cache)
				if err != nil {
					return fmt.Errorf("sat ranges for %v: %w", op, err)
				}
				// Always append for index alignment with input index.
				// A UTXO with value always has sat ranges; 0 is a
				// defensive sentinel.
				if len(ranges) > 0 {
					perInputStart = append(perInputStart, ranges[0].Start)
				} else {
					perInputStart = append(perInputStart, 0)
				}
				allInputRanges = append(allInputRanges, ranges...)

				// Mark spent input's sat ranges for deletion.
				cache[ordinalRangeKey(op)] = nil
			}
		}

		// Step 2: Flatten contiguous ranges for FIFO split.
		mergedRanges := MergeSatRanges(allInputRanges)

		// Step 3: Split across outputs via FIFO.
		outputRanges := make(map[uint32][]SatRange)
		var rangeOffset int
		var satOffset uint64
		for txOutIdx, txOut := range tx.MsgTx().TxOut {
			if txOut.Value == 0 {
				continue
			}
			outRanges, newRangeOffset, newSatOffset := SplitSatRanges(
				mergedRanges, rangeOffset, satOffset, uint64(txOut.Value))
			rangeOffset = newRangeOffset
			satOffset = newSatOffset
			outputRanges[uint32(txOutIdx)] = outRanges

			outpoint := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
			cache[ordinalRangeKey(outpoint)] = EncodeSatRanges(outRanges)
		}

		// Step 4: Track inscribed sat movement.
		if !blockchain.IsCoinBase(tx) {
			if err := i.updateInscribedSats(ctx, allInputRanges, tx.Hash(), outputRanges, cache); err != nil {
				return fmt.Errorf("update inscribed sats: %w", err)
			}
		}

		// Step 5: Detect new inscriptions in witness data.
		if !blockchain.IsCoinBase(tx) {
			for inputIdx, txIn := range tx.MsgTx().TxIn {
				envelope, err := ParseInscriptionEnvelope(txIn.Witness)
				if err != nil || envelope == nil {
					continue
				}

				// Determine which sat the inscription lands on.
				var inscribedSat uint64
				if envelope.Pointer != nil {
					// Pointer tag: sat offset within concatenated
					// output sat ranges.
					inscribedSat = satAtOutputOffset(
						outputRanges, tx.MsgTx().TxOut,
						*envelope.Pointer)
				} else if inputIdx < len(perInputStart) {
					// Default: first sat of this input.
					inscribedSat = perInputStart[inputIdx]
				}

				// Build inscription ID.
				inscID := makeInscriptionID(tx.Hash(), uint32(inputIdx))

				// Cursed status.
				cursed := isInscriptionCursed(blockHeight, inputIdx, envelope)

				// 'i' entry.
				cache[ordinalInscriptionKey(inscID)] = encodeInscriptionValue(
					inscribedSat, blockHash, cursed, envelope)

				// 's' entry: find which output holds this sat.
				for txOutIdx, outRanges := range outputRanges {
					for _, sr := range outRanges {
						if inscribedSat >= sr.Start && inscribedSat < sr.Start+sr.Count {
							outpoint := tbcd.NewOutpoint(*tx.Hash(), txOutIdx)
							cache[ordinalSatKey(inscribedSat)] = outpoint[:]
							goto satFound
						}
					}
				}
			satFound:

				// 'a' entry (reinscription index).
				cache[ordinalSatInscriptionKey(inscribedSat, inscID)] = nil

				// 'n' entry (inscriptions by block).
				cache[ordinalBlockInscriptionKey(blockHash, inscriptionSeq)] = inscID[:]

				inscriptionSeq++
			}
		}
	}

	return nil
}

func (i *ordinalIndexer) unwindBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey][]byte) error {
	txs := block.Transactions()

	// Walk transactions in reverse, same as zkIndexer.
	for k := len(txs) - 1; k >= 0; k-- {
		tx := txs[k]

		// Delete output sat ranges.
		for txOutIdx := range tx.MsgTx().TxOut {
			outpoint := tbcd.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
			cache[ordinalRangeKey(outpoint)] = nil
		}

		// Restore input sat ranges from DB.
		if !blockchain.IsCoinBase(tx) {
			for _, txIn := range tx.MsgTx().TxIn {
				op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
					txIn.PreviousOutPoint.Index)
				v, err := i.g.db.OrdinalSatRangesByOutpoint(ctx, op)
				if err != nil {
					return fmt.Errorf("unwind sat ranges for %v: %w", op, err)
				}
				cache[ordinalRangeKey(op)] = v
			}
		}
	}

	// Delete inscriptions created in this block.
	inscIDs, err := i.g.db.OrdinalInscriptionsByBlockHash(ctx, *blockHash)
	if err != nil {
		return fmt.Errorf("inscriptions by block %v: %w", blockHash, err)
	}
	for seq, inscID := range inscIDs {
		// Read inscription value to get sat number.
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
	cache := c.(*Cache[tbcd.OrdinalKey, []byte])
	return i.g.db.BlockOrdinalUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *ordinalIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	return nil
}

func (i *ordinalIndexer) onSyncComplete() {}

func (i *ordinalIndexer) readCacheInfo() string { return "" }

// Key construction helpers. These match the SOW prefix scheme exactly.

func ordinalRangeKey(op tbcd.Outpoint) tbcd.OrdinalKey {
	var key [1 + 37]byte
	key[0] = 'r'
	copy(key[1:], op[:])
	return tbcd.OrdinalKey(key[:])
}

func ordinalSatKey(satNumber uint64) tbcd.OrdinalKey {
	var key [9]byte
	key[0] = 's'
	binary.BigEndian.PutUint64(key[1:], satNumber)
	return tbcd.OrdinalKey(key[:])
}

func ordinalInscriptionKey(inscID [36]byte) tbcd.OrdinalKey {
	var key [1 + 36]byte
	key[0] = 'i'
	copy(key[1:], inscID[:])
	return tbcd.OrdinalKey(key[:])
}

func ordinalSatInscriptionKey(satNumber uint64, inscID [36]byte) tbcd.OrdinalKey {
	var key [1 + 8 + 36]byte
	key[0] = 'a'
	binary.BigEndian.PutUint64(key[1:], satNumber)
	copy(key[9:], inscID[:])
	return tbcd.OrdinalKey(key[:])
}

func ordinalBlockInscriptionKey(blockHash *chainhash.Hash, seq uint32) tbcd.OrdinalKey {
	var key [1 + 32 + 4]byte
	key[0] = 'n'
	copy(key[1:], blockHash[:])
	binary.BigEndian.PutUint32(key[33:], seq)
	return tbcd.OrdinalKey(key[:])
}

func makeInscriptionID(txHash *chainhash.Hash, inputIdx uint32) [36]byte {
	var id [36]byte
	copy(id[:32], txHash[:])
	binary.LittleEndian.PutUint32(id[32:], inputIdx)
	return id
}

// satAtOutputOffset finds the sat number at a given offset within the
// concatenated output sat ranges. Used for pointer tag (tag 2) handling.
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
	// Offset beyond total output sats. Fall back to first sat.
	if ranges, ok := outputRanges[0]; ok && len(ranges) > 0 {
		return ranges[0].Start
	}
	return 0
}

// inscribedSatsFromCache scans the cache for 's' prefixed keys whose sat
// numbers fall within [start, end).
func inscribedSatsFromCache(cache map[tbcd.OrdinalKey][]byte, start, end uint64) []uint64 {
	var sats []uint64
	for k, v := range cache {
		if len(k) != 9 || k[0] != 's' {
			continue
		}
		if v == nil {
			continue // deleted
		}
		sat := binary.BigEndian.Uint64([]byte(k[1:]))
		if sat >= start && sat < end {
			sats = append(sats, sat)
		}
	}
	return sats
}
