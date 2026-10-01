// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
)

// Pre-decode allocation bounds for the tbcapi RAW handlers.
//
// handleTxBroadcastRawRequest and handleBlockInsertRawRequest hand caller-supplied bytes straight to
// btcd's Deserialize. btcd sizes its element slices from the *declared* count varint BEFORE reading a
// single element body, bounded only by maxTxInPerMessage = 818,401 and maxTxOutPerMessage = 3,728,271.
//
// The scan can only ever reject on a positive finding that the payload declared more elements than its
// own bytes have room for. Every other outcome -- a truncated field, a bad marker, a varint running
// off the end -- sets bailed and returns nil, i.e. ACCEPT, leaving the verdict to wire.
//
// THE SIZE CAP IS THE EXCEPTION, and it is deliberate. Both entry points reject a payload larger than
// wire.MaxBlockPayload, which is NOT a count proof and NOT a shape wire refuses -- btcd has no total
// size check. An earlier version of this header stated the invariant without the exception, so the
// text denied the line directly below it.

const (
	// minRawTxInPayload mirrors btcd's unexported wire.minTxInPayload: 32-byte prevout hash + 4-byte
	// index + 1-byte zero script-length varint + 4-byte sequence. btcd allocates BOTH a []TxIn and a
	// []*TxIn of the declared count, i.e. ~104 bytes per claimed input (sizeof(wire.TxIn)=96 plus 8
	// for the pointer slot).
	minRawTxInPayload = 41

	// minRawTxOutPayload is btcd's EXPORTED wire.MinTxOutPayload, taken rather than copied so a btcd
	// change to the output encoding moves this bound with it. The two siblings above and below are
	// unexported in btcd and must stay hand-written.
	minRawTxOutPayload = wire.MinTxOutPayload

	// minRawTxPayload mirrors btcd's unexported wire.minTxPayload: 4 version + 1 input count +
	// 1 output count + 4 lock time.
	minRawTxPayload = 10

	// minRawWitnessItem: a single length varint. A zero-length witness item is legal, so one byte
	// really is the floor; wire allocates a [][]byte of this count.
	minRawWitnessItem = 1
)

// rawScanner walks a payload reading only varints and skipping the bytes between them. It allocates
// nothing and retains no reference to the payload beyond the call.
type rawScanner struct {
	b   []byte
	off int
	// bailed records that the scan could not make sense of the structure and stopped early. It is
	// NOT a rejection: bail means ACCEPT.
	bailed bool
}

func (s *rawScanner) remaining() int { return len(s.b) - s.off }

func (s *rawScanner) bail() { s.bailed = true }

func (s *rawScanner) skip(n int) bool {
	if n < 0 || n > s.remaining() {
		return false
	}
	s.off += n
	return true
}

func (s *rawScanner) byteAt() (byte, bool) {
	if s.remaining() < 1 {
		return 0, false
	}
	c := s.b[s.off]
	s.off++
	return c, true
}

// varint reads a Bitcoin variable-length integer. It is deliberately more permissive than
// wire.ReadVarInt, which rejects non-canonical encodings: the encoded LENGTH is fixed by the prefix
// byte, so the cursor never diverges from wire's, and reading a large count from an overlong encoding
// and rejecting is safe because wire would reject too. Being *stricter* than wire is the only dangerous
// direction, and this is not that.
func (s *rawScanner) varint() (uint64, bool) {
	prefix, ok := s.byteAt()
	if !ok {
		return 0, false
	}
	var n int
	switch prefix {
	case 0xff:
		n = 8
	case 0xfe:
		n = 4
	case 0xfd:
		n = 2
	default:
		return uint64(prefix), true
	}
	if s.remaining() < n {
		return 0, false
	}
	var v uint64
	for i := 0; i < n; i++ { // little-endian
		v |= uint64(s.b[s.off+i]) << (8 * uint(i))
	}
	s.off += n
	return v, true
}

// skipVarBytes reads a length varint and skips that many bytes.
//
// This is not redundant with the count bounds. btcd's readScriptBuf slices a shared 4 MiB scriptSlab
// by the declared length and does io.ReadFull against what remains of it, so an over-declared script
// slices out of range and panics rather than erroring.
func (s *rawScanner) skipVarBytes(idx uint64, field string) error {
	n, ok := s.varint()
	if !ok {
		s.bail()
		return nil
	}
	if n > uint64(s.remaining()) {
		return fmt.Errorf("transaction %d declares a %d-byte %s, but only %d bytes remain",
			idx, n, field, s.remaining())
	}
	s.off += int(n) // safe: n <= remaining(), which is an int
	return nil
}

// scanTx walks one transaction, bounding each of its counts. The field order mirrors
// wire.MsgTx.BtcDecode under WitnessEncoding exactly, which is the encoding Deserialize uses.
func (s *rawScanner) scanTx(idx uint64) error {
	if !s.skip(4) { // version
		s.bail()
		return nil
	}

	// A zero input count is wire's segwit marker, not an empty input list: it is followed by a flag
	// byte that must be 0x01, then the real input count. Treating the zero as a count is exactly the
	// mistake that left the 12-byte / 149 MB bomb open in the prefix-bound version of this file.
	witness := false
	inCount, ok := s.varint()
	if !ok {
		s.bail()
		return nil
	}
	if inCount == 0 {
		flag, ok := s.byteAt()
		if !ok || flag != 0x01 {
			s.bail() // wire errors here too; let it produce the error
			return nil
		}
		witness = true
		if inCount, ok = s.varint(); !ok {
			s.bail()
			return nil
		}
	}

	if inCount > uint64(s.remaining())/minRawTxInPayload {
		return fmt.Errorf("transaction %d declares %d inputs, but the %d bytes that remain can hold at most %d",
			idx, inCount, s.remaining(), uint64(s.remaining())/minRawTxInPayload)
	}
	for j := uint64(0); j < inCount; j++ {
		if !s.skip(36) { // prevout hash + index
			s.bail()
			return nil
		}
		if err := s.skipVarBytes(idx, "signature script"); err != nil {
			return err
		}
		if s.bailed {
			return nil
		}
		if !s.skip(4) { // sequence
			s.bail()
			return nil
		}
	}

	outCount, ok := s.varint()
	if !ok {
		s.bail()
		return nil
	}
	if outCount > uint64(s.remaining())/minRawTxOutPayload {
		return fmt.Errorf("transaction %d declares %d outputs, but the %d bytes that remain can hold at most %d",
			idx, outCount, s.remaining(), uint64(s.remaining())/minRawTxOutPayload)
	}
	for j := uint64(0); j < outCount; j++ {
		if !s.skip(8) { // value
			s.bail()
			return nil
		}
		if err := s.skipVarBytes(idx, "pk script"); err != nil {
			return err
		}
		if s.bailed {
			return nil
		}
	}

	if witness {
		for j := uint64(0); j < inCount; j++ {
			witCount, ok := s.varint()
			if !ok {
				s.bail()
				return nil
			}
			if witCount > uint64(s.remaining())/minRawWitnessItem {
				return fmt.Errorf("transaction %d input %d declares %d witness items, but only %d bytes remain",
					idx, j, witCount, s.remaining())
			}
			for k := uint64(0); k < witCount; k++ {
				if err := s.skipVarBytes(idx, "witness item"); err != nil {
					return err
				}
				if s.bailed {
					return nil
				}
			}
		}
	}

	if !s.skip(4) { // lock time
		s.bail()
	}
	return nil
}

// boundRawTxCounts refuses a raw TRANSACTION payload whose declared counts cannot fit in its bytes.
func boundRawTxCounts(payload []byte) error {
	// SIZE CAP FIRST; this is the scriptSlab proof, see the header.
	//
	// MsgTx.BtcDecode borrows the SAME 4,194,304-byte slab as the block decoder, so a transaction
	// whose signature scripts are individually under the 4,000,000 per-script ceiling can still
	// exceed the slab collectively and panic.
	//
	// The block path carried this cap from the port; the transaction path did not, because it is
	// hemi-original with no upstream sibling to copy it from. That asymmetry is exactly how it was
	// missed. It is not reachable through the 32 KiB websocket default today -- and the block
	// handler's own comment says to add a size precondition BEFORE raising that limit, which is what
	// this is.
	if len(payload) > wire.MaxBlockPayload {
		return fmt.Errorf("transaction payload of %d bytes exceeds the %d-byte maximum block, so it "+
			"cannot be decoded without overrunning btcd's shared script slab",
			len(payload), wire.MaxBlockPayload)
	}

	// NO LENGTH *MINIMUM*.
	//
	// The scanner needs no such guard: skip() and varint() return false when the bytes are not
	// there, which sets bailed and ACCEPTS, leaving the verdict to wire. Short payloads are already
	// handled, correctly, by the same mechanism that handles every other malformed shape.
	s := &rawScanner{b: payload}
	return s.scanTx(0)
}

// boundRawBlockCounts refuses a raw BLOCK payload whose declared counts cannot fit in its bytes.
func boundRawBlockCounts(payload []byte) error {
	if len(payload) > wire.MaxBlockPayload {
		return fmt.Errorf("payload of %d bytes exceeds the %d-byte maximum block",
			len(payload), wire.MaxBlockPayload)
	}
	if len(payload) < wire.MaxBlockHeaderPayload {
		return nil // wire will reject; nothing to bound
	}
	s := &rawScanner{b: payload, off: wire.MaxBlockHeaderPayload}
	txCount, ok := s.varint()
	if !ok {
		return nil
	}
	// txCount == 0 is DELIBERATELY allowed: a zero-transaction block is a shape wire decodes without
	// error but should be handled upstream as an invalid block (must always have Coinbase).
	if txCount > uint64(s.remaining())/minRawTxPayload {
		return fmt.Errorf("declares %d transactions, but the %d bytes that remain can hold at most %d",
			txCount, s.remaining(), uint64(s.remaining())/minRawTxPayload)
	}
	for i := uint64(0); i < txCount; i++ {
		if err := s.scanTx(i); err != nil {
			return err
		}
		if s.bailed {
			return nil
		}
	}
	return nil
}
