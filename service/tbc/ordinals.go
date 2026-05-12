// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// jubileeHeight is the block height at which cursed inscription rules were
// removed. At and above this height, all valid inscriptions are blessed.
const jubileeHeight = 824544

// SatRange represents a contiguous range of satoshi ordinal numbers.
type SatRange struct {
	Start uint64 // First sat number in range.
	Count uint64 // Number of contiguous sats.
}

// EncodeSatRanges encodes sat ranges as concatenated big-endian uint64 pairs.
func EncodeSatRanges(ranges []SatRange) []byte {
	buf := make([]byte, len(ranges)*16)
	for i, r := range ranges {
		binary.BigEndian.PutUint64(buf[i*16:], r.Start)
		binary.BigEndian.PutUint64(buf[i*16+8:], r.Count)
	}
	return buf
}

// DecodeSatRanges decodes sat ranges from concatenated big-endian uint64 pairs.
func DecodeSatRanges(data []byte) []SatRange {
	if len(data)%16 != 0 {
		panic(fmt.Sprintf("diagnostic: invalid sat range data length: %d", len(data)))
	}
	n := len(data) / 16
	ranges := make([]SatRange, n)
	for i := range n {
		ranges[i] = SatRange{
			Start: binary.BigEndian.Uint64(data[i*16:]),
			Count: binary.BigEndian.Uint64(data[i*16+8:]),
		}
	}
	return ranges
}

// MergeSatRanges merges adjacent contiguous sat ranges.
func MergeSatRanges(ranges []SatRange) []SatRange {
	if len(ranges) <= 1 {
		return ranges
	}
	merged := make([]SatRange, 0, len(ranges))
	current := ranges[0]
	for _, next := range ranges[1:] {
		if current.Start+current.Count == next.Start {
			current.Count += next.Count
		} else {
			merged = append(merged, current)
			current = next
		}
	}
	merged = append(merged, current)
	return merged
}

// SplitSatRanges consumes exactly `amount` sats from inputRanges starting at
// the given range offset and sat offset within that range. Returns the output
// ranges, the new range offset, and new sat offset for the next output.
func SplitSatRanges(inputRanges []SatRange, rangeOffset int, satOffset uint64, amount uint64) ([]SatRange, int, uint64) {
	var output []SatRange
	remaining := amount

	for remaining > 0 && rangeOffset < len(inputRanges) {
		r := inputRanges[rangeOffset]
		available := r.Count - satOffset
		if available <= remaining {
			// Consume the rest of this range.
			output = append(output, SatRange{
				Start: r.Start + satOffset,
				Count: available,
			})
			remaining -= available
			rangeOffset++
			satOffset = 0
		} else {
			// Partial consumption of this range.
			output = append(output, SatRange{
				Start: r.Start + satOffset,
				Count: remaining,
			})
			satOffset += remaining
			remaining = 0
		}
	}

	return output, rangeOffset, satOffset
}

// CoinbaseSatRange computes the sat range for a coinbase transaction at the
// given block height. Returns (start, count).
func CoinbaseSatRange(height uint32) (uint64, uint64) {
	subsidy := SubsidyAtHeight(height)
	start := TotalSubsidyBeforeHeight(height)
	return start, subsidy
}

// SubsidyAtHeight returns the block subsidy in sats at the given height.
func SubsidyAtHeight(height uint32) uint64 {
	halvings := height / 210000
	if halvings >= 64 {
		return 0
	}
	return 5000000000 >> halvings
}

// TotalSubsidyBeforeHeight returns the total sats mined before the given height.
func TotalSubsidyBeforeHeight(height uint32) uint64 {
	var total uint64
	h := uint32(0)
	for h < height {
		halvings := h / 210000
		if halvings >= 64 {
			break
		}
		subsidy := uint64(5000000000) >> halvings
		nextHalving := (halvings + 1) * 210000
		blocksAtThisSubsidy := nextHalving - h
		if h+blocksAtThisSubsidy > height {
			blocksAtThisSubsidy = height - h
		}
		total += subsidy * uint64(blocksAtThisSubsidy)
		h += blocksAtThisSubsidy
	}
	return total
}

// InscriptionEnvelope represents a parsed inscription from a taproot witness.
type InscriptionEnvelope struct {
	ContentType            []byte
	Content                []byte
	Pointer                *uint64   // tag 2: sat offset within outputs
	Parent                 *[36]byte // tag 3: parent inscription ID
	Metaprotocol           []byte    // tag 7: metaprotocol name
	Delegate               *[36]byte // tag 11: delegate inscription ID
	HasUnrecognizedEvenTag bool      // for cursed detection
	MultipleEnvelopes      bool      // set if >1 envelope found in same input
	NonTaprootWitness      bool      // set if found in non-taproot witness
}

// ParseInscriptionEnvelope parses an inscription envelope from witness data.
// Returns nil if no inscription is found.
func ParseInscriptionEnvelope(witness wire.TxWitness) (*InscriptionEnvelope, error) {
	if len(witness) == 0 {
		return nil, nil
	}

	// Inscriptions are in the tapscript (second-to-last witness element
	// in a taproot script-path spend). The last element is the control
	// block.
	if len(witness) < 2 {
		return nil, nil
	}

	script := witness[len(witness)-2]
	return parseEnvelopeFromScript(script)
}

// parseEnvelopeFromScript parses the ord envelope from a tapscript.
func parseEnvelopeFromScript(script []byte) (*InscriptionEnvelope, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	// Search for the OP_FALSE OP_IF OP_PUSH "ord" pattern.
	for tokenizer.Next() {
		if tokenizer.Opcode() != txscript.OP_FALSE {
			continue
		}
		if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_IF {
			continue
		}
		if !tokenizer.Next() {
			continue
		}
		data := tokenizer.Data()
		if !bytes.Equal(data, []byte("ord")) {
			continue
		}

		// Found envelope. Parse tags.
		return parseEnvelopeTags(&tokenizer)
	}

	if err := tokenizer.Err(); err != nil {
		return nil, fmt.Errorf("script tokenizer: %w", err)
	}

	return nil, nil
}

// parseEnvelopeTags parses tag-value pairs from an ord envelope.
func parseEnvelopeTags(tokenizer *txscript.ScriptTokenizer) (*InscriptionEnvelope, error) {
	env := &InscriptionEnvelope{}

	for tokenizer.Next() {
		op := tokenizer.Opcode()

		// OP_ENDIF terminates the envelope.
		if op == txscript.OP_ENDIF {
			return env, nil
		}

		// Tags are single-byte push opcodes (OP_1 through OP_16 or
		// OP_DATA_1 with the tag number).
		tag := envelopeTag(op, tokenizer.Data())
		if tag < 0 {
			continue
		}

		// Read the value (next push).
		if !tokenizer.Next() {
			break
		}
		value := tokenizer.Data()

		switch tag {
		case 1: // content_type
			env.ContentType = value
		case 2: // pointer
			if len(value) <= 8 {
				ptr := decodeVarUint(value)
				env.Pointer = &ptr
			}
		case 3: // parent inscription ID
			if len(value) == 36 {
				var parent [36]byte
				copy(parent[:], value)
				env.Parent = &parent
			}
		case 5: // content (body, may be split across multiple pushes)
			env.Content = append(env.Content, value...)
			// Content can span multiple pushes until next tag or OP_ENDIF.
			// Peek ahead for continuation.
			for tokenizer.Next() {
				nextOp := tokenizer.Opcode()
				if nextOp == txscript.OP_ENDIF {
					return env, nil
				}
				nextTag := envelopeTag(nextOp, tokenizer.Data())
				if nextTag >= 0 {
					// Hit next tag. We need to process it, but the
					// tokenizer already consumed it. Handle it in the
					// next iteration by breaking and letting the outer
					// loop re-check. But we already called Next(), so
					// we need to handle this tag here.
					// Process the tag we just consumed.
					if !tokenizer.Next() {
						break
					}
					nextValue := tokenizer.Data()
					applyTag(env, nextTag, nextValue)
					break
				}
				// Still content.
				env.Content = append(env.Content, tokenizer.Data()...)
			}
		case 7: // metaprotocol
			env.Metaprotocol = value
		case 11: // delegate
			if len(value) == 36 {
				var delegate [36]byte
				copy(delegate[:], value)
				env.Delegate = &delegate
			}
		default:
			// Unrecognized even tags make the inscription cursed
			// (pre-jubilee).
			if tag%2 == 0 {
				env.HasUnrecognizedEvenTag = true
			}
		}
	}

	if err := tokenizer.Err(); err != nil {
		return nil, fmt.Errorf("envelope tags: %w", err)
	}

	// Reached end of script without OP_ENDIF. Malformed but we still
	// return what we parsed.
	return env, nil
}

// applyTag applies a parsed tag to the envelope.
func applyTag(env *InscriptionEnvelope, tag int, value []byte) {
	switch tag {
	case 1:
		env.ContentType = value
	case 2:
		if len(value) <= 8 {
			ptr := decodeVarUint(value)
			env.Pointer = &ptr
		}
	case 3:
		if len(value) == 36 {
			var parent [36]byte
			copy(parent[:], value)
			env.Parent = &parent
		}
	case 7:
		env.Metaprotocol = value
	case 11:
		if len(value) == 36 {
			var delegate [36]byte
			copy(delegate[:], value)
			env.Delegate = &delegate
		}
	default:
		if tag%2 == 0 {
			env.HasUnrecognizedEvenTag = true
		}
	}
}

// envelopeTag extracts the tag number from an opcode. Returns -1 if the
// opcode is not a valid tag.
func envelopeTag(op byte, data []byte) int {
	// OP_1 through OP_16 map to tags 1-16.
	if op >= txscript.OP_1 && op <= txscript.OP_16 {
		return int(op - txscript.OP_1 + 1)
	}
	// Single-byte data push with the tag number.
	if len(data) == 1 {
		return int(data[0])
	}
	return -1
}

// decodeVarUint decodes a little-endian variable-length unsigned integer.
func decodeVarUint(data []byte) uint64 {
	var result uint64
	for i, b := range data {
		result |= uint64(b) << (uint(i) * 8)
	}
	return result
}

// isInscriptionCursed determines if an inscription is cursed based on
// pre-jubilee rules.
func isInscriptionCursed(blockHeight uint32, inputIdx int, env *InscriptionEnvelope) bool {
	if blockHeight >= jubileeHeight {
		return false
	}

	// Rule 1: inscription in non-zero input.
	if inputIdx != 0 {
		return true
	}
	// Rule 2: multiple inscriptions in same input.
	if env.MultipleEnvelopes {
		return true
	}
	// Rule 3: non-taproot witness (handled by caller setting the flag).
	if env.NonTaprootWitness {
		return true
	}
	// Rule 4: unrecognized even tags.
	if env.HasUnrecognizedEvenTag {
		return true
	}
	// Rule 5: pointer out of range (handled during pointer validation).
	// Not checked here — requires knowledge of output count.

	return false
}

// encodeInscriptionValue builds the 'i' value with flag-driven optional fields.
func encodeInscriptionValue(satNumber uint64, blockHash *chainhash.Hash, cursed bool, env *InscriptionEnvelope) []byte {
	var flags byte
	if cursed {
		flags |= 1 << 0
	}
	if env.Parent != nil {
		flags |= 1 << 1
	}
	if env.Delegate != nil {
		flags |= 1 << 2
	}
	if len(env.Metaprotocol) > 0 {
		flags |= 1 << 3
	}

	// Fixed part: sat_number(8) + block_hash(32) + flags(1) = 41
	size := 41
	if env.Parent != nil {
		size += 36
	}
	if env.Delegate != nil {
		size += 36
	}
	size += len(env.Metaprotocol)

	buf := make([]byte, size)
	binary.BigEndian.PutUint64(buf[0:8], satNumber)
	copy(buf[8:40], blockHash[:])
	buf[40] = flags

	offset := 41
	if env.Parent != nil {
		copy(buf[offset:offset+36], env.Parent[:])
		offset += 36
	}
	if env.Delegate != nil {
		copy(buf[offset:offset+36], env.Delegate[:])
		offset += 36
	}
	if len(env.Metaprotocol) > 0 {
		copy(buf[offset:], env.Metaprotocol)
	}

	return buf
}

// decodedInscription holds the fields parsed from the 'i' prefix value.
type decodedInscription struct {
	SatNumber    uint64
	BlockHash    chainhash.Hash
	Cursed       bool
	Parent       *[36]byte // inscription ID
	Delegate     *[36]byte // inscription ID
	Metaprotocol string
}

// decodeInscriptionValue decodes the value stored under the 'i' prefix.
// The encoding is produced by encodeInscriptionValue.
func decodeInscriptionValue(data []byte) (*decodedInscription, error) {
	if len(data) < 41 {
		return nil, fmt.Errorf("inscription value too short: %d", len(data))
	}

	d := &decodedInscription{
		SatNumber: binary.BigEndian.Uint64(data[0:8]),
		Cursed:    data[40]&(1<<0) != 0,
	}
	copy(d.BlockHash[:], data[8:40])

	flags := data[40]
	offset := 41

	if flags&(1<<1) != 0 {
		if offset+36 > len(data) {
			return nil, errors.New("inscription value truncated at parent")
		}
		var parent [36]byte
		copy(parent[:], data[offset:offset+36])
		d.Parent = &parent
		offset += 36
	}
	if flags&(1<<2) != 0 {
		if offset+36 > len(data) {
			return nil, errors.New("inscription value truncated at delegate")
		}
		var delegate [36]byte
		copy(delegate[:], data[offset:offset+36])
		d.Delegate = &delegate
		offset += 36
	}
	if flags&(1<<3) != 0 {
		d.Metaprotocol = string(data[offset:])
	}

	return d, nil
}
