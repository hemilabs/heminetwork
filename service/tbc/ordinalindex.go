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
	workCache     map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue
}

var (
	_ Indexer = (*ordinalIndexer)(nil)
	_ indexer = (*ordinalIndexer)(nil)
)

func NewOrdinalIndexer(g geometryParams, cacheLen int, enabled bool, ordinalGenesis *HashHeight) Indexer {
	oi := &ordinalIndexer{
		cacheCapacity: cacheLen,
		workCache:     make(map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue),
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

// encodeWorkValue encodes the commit outpoint for the populator.
// Layout: commit_txid(32) + commit_vout(4) = 36 bytes.
func encodeWorkValue(commitTxid chainhash.Hash, commitVout uint32) tbcd.OrdinalWorkValue {
	v := make([]byte, 36)
	copy(v[:32], commitTxid[:])
	binary.BigEndian.PutUint32(v[32:], commitVout)
	return tbcd.OrdinalWorkValue(v)
}

// windBlock scans a block for inscription envelopes and records reveals.
// All transfer tracking and sat number derivation is deferred to query time.
func (i *ordinalIndexer) windBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) error {
	txs := block.Transactions()
	var inscriptionSeq uint32

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

			// 'i': inscription metadata (sat=0, computed later by populator).
			cache[ordinalInscriptionKey(inscID)] = encodeInscriptionValue(
				0, blockHash, cursed, envelope)

			// 'n': block→inscription index.
			cache[ordinalBlockInscriptionKey(blockHash, inscriptionSeq)] = inscID[:]

			// 'w': work queue entry for background sat computation.
			prevOut := txIn.PreviousOutPoint
			i.workCache[ordinalWorkKey(blockHeight, uint16(inscriptionSeq))] = encodeWorkValue(prevOut.Hash, prevOut.Index)

			inscriptionSeq++
		}
	}

	return nil
}

// unwindBlock reverses a single block. Deletes inscriptions created
// in this block. No sat ranges to restore.
func (i *ordinalIndexer) unwindBlock(ctx context.Context, blockHeight uint32, blockHash *chainhash.Hash, block *btcutil.Block, cache map[tbcd.OrdinalKey]tbcd.OrdinalValue) error {
	inscIDs, err := i.g.db.OrdinalInscriptionsByBlockHash(ctx, *blockHash)
	if err != nil {
		return fmt.Errorf("inscriptions by block %v: %w", blockHash, err)
	}
	for seq, inscID := range inscIDs {
		cache[ordinalInscriptionKey(inscID)] = nil
		cache[ordinalBlockInscriptionKey(blockHash, uint32(seq))] = nil
		i.workCache[ordinalWorkKey(blockHeight, uint16(seq))] = nil
	}

	return nil
}

func (i *ordinalIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[tbcd.OrdinalKey, tbcd.OrdinalValue])
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
