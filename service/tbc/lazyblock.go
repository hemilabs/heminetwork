// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// lazyBlock wraps raw block bytes from the block cache. Nothing is
// parsed until explicitly requested. Individual tx access parses only
// that tx from its raw byte range.
type lazyBlock struct {
	raw []byte // from block cache, never copied

	mu           sync.Mutex
	hash         chainhash.Hash // lazy, computed from raw[0:80]
	hashComputed bool
	txOffsets    []wire.TxLoc // lazy, populated on first tx access
	txWitness    []bool       // parallel to txOffsets: true if tx has witness
}

// newLazyBlock wraps raw block bytes for lazy access. The raw slice
// must be a complete serialized Bitcoin block (header + transactions).
// No data is parsed until a method is called.
//
// The caller must guarantee that raw is not mutated, reused, or recycled
// for the lifetime of the returned lazyBlock. raw bytes are referenced,
// not copied. If raw is a sub-slice of a larger allocation, holding the
// lazyBlock pins the entire backing array.
func newLazyBlock(raw []byte) (*lazyBlock, error) {
	if len(raw) < wire.MaxBlockHeaderPayload+1 {
		return nil, fmt.Errorf("lazyBlock: raw too short (%d bytes)", len(raw))
	}
	return &lazyBlock{raw: raw}, nil
}

// Hash returns the block hash (double-SHA256 of the 80-byte header).
// Computed once and cached.
func (lb *lazyBlock) Hash() (chainhash.Hash, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if !lb.hashComputed {
		lb.hash = chainhash.DoubleHashH(lb.raw[:wire.MaxBlockHeaderPayload])
		lb.hashComputed = true
	}
	return lb.hash, nil
}

// ensureTxOffsets populates txOffsets on first call. Must hold lb.mu.
func (lb *lazyBlock) ensureTxOffsets() error {
	if lb.txOffsets != nil {
		return nil
	}
	var err error
	lb.txOffsets, lb.txWitness, err = scanTxBoundaries(lb.raw)
	return err
}

// TxCount returns the number of transactions in the block.
func (lb *lazyBlock) TxCount() (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if err := lb.ensureTxOffsets(); err != nil {
		return 0, err
	}
	return len(lb.txOffsets), nil
}

// TxHash returns the non-witness txid for transaction i. The txid is
// the double-SHA256 of the non-witness serialization: version + inputs +
// outputs + locktime (excluding the segwit marker/flag and witness data).
func (lb *lazyBlock) TxHash(i int) (chainhash.Hash, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if err := lb.ensureTxOffsets(); err != nil {
		return chainhash.Hash{}, err
	}
	if i < 0 || i >= len(lb.txOffsets) {
		return chainhash.Hash{}, fmt.Errorf("lazyBlock: tx index %d out of range [0, %d)", i, len(lb.txOffsets))
	}
	loc := lb.txOffsets[i]
	txBytes := lb.raw[loc.TxStart : loc.TxStart+loc.TxLen]
	return computeTxID(txBytes, lb.txWitness[i])
}

// FindTx iterates transactions computing txids until a match is found.
// Returns the tx index or an error if not found.
func (lb *lazyBlock) FindTx(txid chainhash.Hash) (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if err := lb.ensureTxOffsets(); err != nil {
		return -1, err
	}
	for i := range lb.txOffsets {
		loc := lb.txOffsets[i]
		txBytes := lb.raw[loc.TxStart : loc.TxStart+loc.TxLen]
		h, err := computeTxID(txBytes, lb.txWitness[i])
		if err != nil {
			return -1, fmt.Errorf("lazyBlock: tx %d: %w", i, err)
		}
		if h == txid {
			return i, nil
		}
	}
	return -1, fmt.Errorf("lazyBlock: tx %v not found", txid)
}

// TxOutputValues parses only the output section of transaction i and
// returns the value (in satoshis) of each output. The only heap allocation
// is the result slice.
// FindTxOutputValues locates txid in the block and returns its output
// values in one step. The extraction shares the return with the lookup,
// so there is no separate error path for "found but unparseable" — the
// offsets that located the tx are the offsets extraction reads.
func (lb *lazyBlock) FindTxOutputValues(txid chainhash.Hash) ([]uint64, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if err := lb.ensureTxOffsets(); err != nil {
		return nil, err
	}
	for i := range lb.txOffsets {
		loc := lb.txOffsets[i]
		txBytes := lb.raw[loc.TxStart : loc.TxStart+loc.TxLen]
		h, err := computeTxID(txBytes, lb.txWitness[i])
		if err != nil {
			return nil, fmt.Errorf("lazyBlock: tx %d: %w", i, err)
		}
		if h == txid {
			return extractOutputValues(txBytes, lb.txWitness[i])
		}
	}
	return nil, fmt.Errorf("lazyBlock: tx %v not found", txid)
}

func (lb *lazyBlock) TxOutputValues(i int) ([]uint64, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if err := lb.ensureTxOffsets(); err != nil {
		return nil, err
	}
	if i < 0 || i >= len(lb.txOffsets) {
		return nil, fmt.Errorf("lazyBlock: tx index %d out of range [0, %d)", i, len(lb.txOffsets))
	}
	loc := lb.txOffsets[i]
	txBytes := lb.raw[loc.TxStart : loc.TxStart+loc.TxLen]
	return extractOutputValues(txBytes, lb.txWitness[i])
}

// FullBlock falls back to btcutil.NewBlockFromBytes for callers that
// need the full parsed block.
func (lb *lazyBlock) FullBlock() (*btcutil.Block, error) {
	return btcutil.NewBlockFromBytes(lb.raw)
}

// readVarInt reads a Bitcoin protocol variable-length integer from b
// starting at offset. Returns the decoded value and the number of bytes
// consumed. Returns an error if there are not enough bytes.
func readVarInt(b []byte, offset int) (uint64, int, error) {
	if offset >= len(b) {
		return 0, 0, errors.New("readVarInt: offset past end")
	}
	discriminant := b[offset]
	switch {
	case discriminant < 0xfd:
		return uint64(discriminant), 1, nil
	case discriminant == 0xfd:
		if offset+3 > len(b) {
			return 0, 0, errors.New("readVarInt: short 0xfd")
		}
		return uint64(binary.LittleEndian.Uint16(b[offset+1:])), 3, nil
	case discriminant == 0xfe:
		if offset+5 > len(b) {
			return 0, 0, errors.New("readVarInt: short 0xfe")
		}
		return uint64(binary.LittleEndian.Uint32(b[offset+1:])), 5, nil
	default: // 0xff
		if offset+9 > len(b) {
			return 0, 0, errors.New("readVarInt: short 0xff")
		}
		return binary.LittleEndian.Uint64(b[offset+1:]), 9, nil
	}
}

// maxBlockTxCount is a sanity cap for tx count parsed from untrusted
// bytes. A 4MB block with minimum-size txs (~60 bytes) fits ~66k txs.
const maxBlockTxCount = 100_000

// scanTxBoundaries walks the raw block bytes once to find the start
// offset and length of each transaction without deserializing any
// transaction data. Returns parallel slices of TxLoc and witness flags.
func scanTxBoundaries(raw []byte) ([]wire.TxLoc, []bool, error) {
	if len(raw) < wire.MaxBlockHeaderPayload+1 {
		return nil, nil, errors.New("scanTxBoundaries: block too short")
	}

	offset := wire.MaxBlockHeaderPayload

	// Read transaction count.
	txCount, n, err := readVarInt(raw, offset)
	if err != nil {
		return nil, nil, fmt.Errorf("scanTxBoundaries: tx count: %w", err)
	}
	offset += n

	if txCount > maxBlockTxCount {
		return nil, nil, fmt.Errorf("scanTxBoundaries: tx count %d exceeds max %d",
			txCount, maxBlockTxCount)
	}

	locs := make([]wire.TxLoc, 0, txCount)
	witness := make([]bool, 0, txCount)

	for t := range txCount {
		txStart := offset

		// Version: 4 bytes.
		if offset+4 > len(raw) {
			return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d: short version", t)
		}
		offset += 4

		// Check for segwit marker/flag (0x00, 0x01).
		hasWitness := false
		if offset+2 <= len(raw) && raw[offset] == 0x00 && raw[offset+1] == 0x01 {
			hasWitness = true
			offset += 2
		}

		// Input count.
		inputCount, n, err := readVarInt(raw, offset)
		if err != nil {
			return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d: input count: %w", t, err)
		}
		offset += n

		// Skip inputs.
		for i := range inputCount {
			// prevhash(32) + previndex(4) = 36.
			if offset+36 > len(raw) {
				return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d input %d: short prevout", t, i)
			}
			offset += 36

			// Script length + script.
			scriptLen, n, err := readVarInt(raw, offset)
			if err != nil {
				return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d input %d: script len: %w", t, i, err)
			}
			offset += n
			if scriptLen > uint64(len(raw)-offset) {
				return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d input %d: script len %d exceeds remaining %d",
					t, i, scriptLen, len(raw)-offset)
			}
			offset += int(scriptLen)

			// Sequence: 4 bytes.
			if offset+4 > len(raw) {
				return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d input %d: short sequence", t, i)
			}
			offset += 4
		}

		// Output count.
		outputCount, n, err := readVarInt(raw, offset)
		if err != nil {
			return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d: output count: %w", t, err)
		}
		offset += n

		if outputCount > uint64(len(raw)-offset) {
			return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d: output count %d exceeds remaining bytes",
				t, outputCount)
		}

		// Skip outputs.
		for o := range outputCount {
			// Value: 8 bytes.
			if offset+8 > len(raw) {
				return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d output %d: short value", t, o)
			}
			offset += 8

			// Script length + script.
			scriptLen, n, err := readVarInt(raw, offset)
			if err != nil {
				return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d output %d: script len: %w", t, o, err)
			}
			offset += n
			if scriptLen > uint64(len(raw)-offset) {
				return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d output %d: script len %d exceeds remaining %d",
					t, o, scriptLen, len(raw)-offset)
			}
			offset += int(scriptLen)
		}

		// Witness data (if present).
		if hasWitness {
			for i := range inputCount {
				stackCount, n, err := readVarInt(raw, offset)
				if err != nil {
					return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d witness %d: stack count: %w", t, i, err)
				}
				offset += n

				for s := range stackCount {
					itemLen, n, err := readVarInt(raw, offset)
					if err != nil {
						return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d witness %d item %d: len: %w", t, i, s, err)
					}
					offset += n
					if itemLen > uint64(len(raw)-offset) {
						return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d witness %d item %d: len %d exceeds remaining %d",
							t, i, s, itemLen, len(raw)-offset)
					}
					offset += int(itemLen)
				}
			}
		}

		// Locktime: 4 bytes.
		if offset+4 > len(raw) {
			return nil, nil, fmt.Errorf("scanTxBoundaries: tx %d: short locktime", t)
		}
		offset += 4

		locs = append(locs, wire.TxLoc{
			TxStart: txStart,
			TxLen:   offset - txStart,
		})
		witness = append(witness, hasWitness)
	}

	return locs, witness, nil
}

// computeTxID computes the non-witness txid from raw tx bytes.
// For non-witness transactions this is double-SHA256 of the entire
// serialization. For witness transactions it hashes
// version + inputs + outputs + locktime, skipping the marker/flag
// and witness data.
func computeTxID(txBytes []byte, hasWitness bool) (chainhash.Hash, error) {
	if !hasWitness {
		return chainhash.DoubleHashH(txBytes), nil
	}

	// Segwit tx: hash version(4) || inputs || outputs || locktime(4)
	// skipping marker/flag (bytes 4-5) and witness data.
	if len(txBytes) < 10 {
		return chainhash.Hash{}, errors.New("computeTxID: segwit tx too short")
	}

	// Walk the tx to find the boundaries we need.
	offset := 4 // skip version
	offset += 2 // skip marker/flag (0x00, 0x01)

	// Read input count and walk inputs.
	inputCount, n, err := readVarInt(txBytes, offset)
	if err != nil {
		return chainhash.Hash{}, fmt.Errorf("computeTxID: input count: %w", err)
	}
	inputsStart := offset
	offset += n

	for i := range inputCount {
		if offset+36 > len(txBytes) {
			return chainhash.Hash{}, fmt.Errorf("computeTxID: input %d: short prevout", i)
		}
		offset += 36 // prevout
		scriptLen, n, err := readVarInt(txBytes, offset)
		if err != nil {
			return chainhash.Hash{}, fmt.Errorf("computeTxID: input %d script len: %w", i, err)
		}
		offset += n
		if scriptLen > uint64(len(txBytes)-offset) {
			return chainhash.Hash{}, fmt.Errorf("computeTxID: input %d: script len %d exceeds remaining", i, scriptLen)
		}
		offset += int(scriptLen) + 4 // script + sequence
	}

	// Read output count and walk outputs.
	outputCount, n, err := readVarInt(txBytes, offset)
	if err != nil {
		return chainhash.Hash{}, fmt.Errorf("computeTxID: output count: %w", err)
	}
	offset += n

	for o := range outputCount {
		if offset+8 > len(txBytes) {
			return chainhash.Hash{}, fmt.Errorf("computeTxID: output %d: short value", o)
		}
		offset += 8 // value
		scriptLen, n, err := readVarInt(txBytes, offset)
		if err != nil {
			return chainhash.Hash{}, fmt.Errorf("computeTxID: output %d script len: %w", o, err)
		}
		offset += n
		if scriptLen > uint64(len(txBytes)-offset) {
			return chainhash.Hash{}, fmt.Errorf("computeTxID: output %d: script len %d exceeds remaining", o, scriptLen)
		}
		offset += int(scriptLen)
	}
	ioEnd := offset // end of inputs+outputs section

	// Locktime is last 4 bytes of the tx.
	locktime := txBytes[len(txBytes)-4:]

	// Hash: version(4) || inputs+outputs || locktime(4)
	h := sha256.New()
	h.Write(txBytes[:4])                // version
	h.Write(txBytes[inputsStart:ioEnd]) // input_count + inputs + output_count + outputs
	h.Write(locktime)                   // locktime
	first := h.Sum(nil)

	h.Reset()
	h.Write(first)
	var result chainhash.Hash
	copy(result[:], h.Sum(nil))
	return result, nil
}

// extractOutputValues parses only the outputs section of a raw tx and
// returns the satoshi value of each output.
func extractOutputValues(txBytes []byte, hasWitness bool) ([]uint64, error) {
	offset := 4 // skip version

	if hasWitness {
		offset += 2 // skip marker/flag
	}

	// Skip input count + inputs.
	inputCount, n, err := readVarInt(txBytes, offset)
	if err != nil {
		return nil, fmt.Errorf("extractOutputValues: input count: %w", err)
	}
	offset += n

	for i := range inputCount {
		if offset+36 > len(txBytes) {
			return nil, fmt.Errorf("extractOutputValues: input %d: short prevout", i)
		}
		offset += 36 // prevout
		scriptLen, n, err := readVarInt(txBytes, offset)
		if err != nil {
			return nil, fmt.Errorf("extractOutputValues: input %d script len: %w", i, err)
		}
		offset += n
		if scriptLen > uint64(len(txBytes)-offset) {
			return nil, fmt.Errorf("extractOutputValues: input %d: script len %d exceeds remaining", i, scriptLen)
		}
		offset += int(scriptLen) + 4 // script + sequence
	}

	// Read output count.
	outputCount, n, err := readVarInt(txBytes, offset)
	if err != nil {
		return nil, fmt.Errorf("extractOutputValues: output count: %w", err)
	}
	offset += n

	if outputCount > uint64(len(txBytes)-offset) {
		return nil, fmt.Errorf("extractOutputValues: output count %d exceeds remaining bytes",
			outputCount)
	}

	values := make([]uint64, outputCount)
	for o := range outputCount {
		if offset+8 > len(txBytes) {
			return nil, fmt.Errorf("extractOutputValues: output %d: short value", o)
		}
		values[o] = binary.LittleEndian.Uint64(txBytes[offset:])
		offset += 8

		// Skip script.
		scriptLen, n, err := readVarInt(txBytes, offset)
		if err != nil {
			return nil, fmt.Errorf("extractOutputValues: output %d script len: %w", o, err)
		}
		offset += n
		if scriptLen > uint64(len(txBytes)-offset) {
			return nil, fmt.Errorf("extractOutputValues: output %d: script len %d exceeds remaining", o, scriptLen)
		}
		offset += int(scriptLen)
	}

	return values, nil
}
