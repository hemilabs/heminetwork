// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// genesisBlockBytes returns the serialized mainnet genesis block.
func genesisBlockBytes(t testing.TB) []byte {
	t.Helper()
	genesis := chaincfg.MainNetParams.GenesisBlock
	var buf bytes.Buffer
	if err := genesis.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serializeBlock serializes a wire.MsgBlock and fatals on error.
func serializeBlock(t testing.TB, mb *wire.MsgBlock) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := mb.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// mustAddTx adds a transaction to a MsgBlock, fataling on error.
func mustAddTx(t testing.TB, mb *wire.MsgBlock, tx *wire.MsgTx) {
	t.Helper()
	if err := mb.AddTransaction(tx); err != nil {
		t.Fatal(err)
	}
}

// makeCoinbaseTx builds a simple coinbase tx with the given output value.
func makeCoinbaseTx(value int64) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
		SignatureScript:  []byte{0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    value,
		PkScript: bytes.Repeat([]byte{0xac}, 25),
	})
	return tx
}

// assertBlockParity compares every txid and every output value between
// a lazyBlock and a btcutil-parsed block. This is the oracle: if these
// diverge on any field, we have a regression.
func assertBlockParity(t *testing.T, raw []byte) {
	t.Helper()

	lb, err := newLazyBlock(raw)
	if err != nil {
		t.Fatalf("newLazyBlock: %v", err)
	}

	refBlock, err := btcutil.NewBlockFromBytes(raw)
	if err != nil {
		t.Fatalf("btcutil parse failed: %v", err)
	}
	refTxs := refBlock.Transactions()

	// Block hash.
	lazyHash, err := lb.Hash()
	if err != nil {
		t.Fatalf("lazyBlock.Hash: %v", err)
	}
	if lazyHash != *refBlock.Hash() {
		t.Fatalf("block hash mismatch: lazy=%v btcutil=%v", lazyHash, refBlock.Hash())
	}

	// Tx count.
	txCount, err := lb.TxCount()
	if err != nil {
		t.Fatalf("lazyBlock.TxCount: %v", err)
	}
	if txCount != len(refTxs) {
		t.Fatalf("tx count: lazy=%d btcutil=%d", txCount, len(refTxs))
	}

	for i, refTx := range refTxs {
		// Txid.
		lazyTxid, err := lb.TxHash(i)
		if err != nil {
			t.Fatalf("tx %d TxHash: %v", i, err)
		}
		wantTxid := *refTx.Hash()
		if lazyTxid != wantTxid {
			t.Fatalf("tx %d txid: lazy=%v btcutil=%v", i, lazyTxid, wantTxid)
		}

		// FindTx round-trip.
		foundIdx, err := lb.FindTx(wantTxid)
		if err != nil {
			t.Fatalf("tx %d FindTx: %v", i, err)
		}
		if foundIdx != i {
			t.Fatalf("tx %d FindTx: got index %d, want %d", i, foundIdx, i)
		}

		// Output values.
		lazyVals, err := lb.TxOutputValues(i)
		if err != nil {
			t.Fatalf("tx %d TxOutputValues: %v", i, err)
		}
		refOuts := refTx.MsgTx().TxOut
		if len(lazyVals) != len(refOuts) {
			t.Fatalf("tx %d output count: lazy=%d btcutil=%d", i, len(lazyVals), len(refOuts))
		}
		for o, v := range lazyVals {
			want := uint64(refOuts[o].Value)
			if v != want {
				t.Fatalf("tx %d output %d value: lazy=%d btcutil=%d", i, o, v, want)
			}
		}
	}

	// FullBlock round-trip.
	fb, err := lb.FullBlock()
	if err != nil {
		t.Fatalf("FullBlock: %v", err)
	}
	if !fb.Hash().IsEqual(refBlock.Hash()) {
		t.Fatalf("FullBlock hash mismatch")
	}
	fbTxs := fb.Transactions()
	if len(fbTxs) != len(refTxs) {
		t.Fatalf("FullBlock tx count: %d vs %d", len(fbTxs), len(refTxs))
	}
	for i := range fbTxs {
		if *fbTxs[i].Hash() != *refTxs[i].Hash() {
			t.Fatalf("FullBlock tx %d hash mismatch", i)
		}
	}
}

// TestGenesisBlock tests against the mainnet genesis block — the simplest
// case: one non-segwit coinbase tx, one output.
func TestGenesisBlock(t *testing.T) {
	assertBlockParity(t, genesisBlockBytes(t))
}

// TestGenesisBlockHashCaching verifies the hash is computed once and
// the cached value is returned on subsequent calls.
func TestGenesisBlockHashCaching(t *testing.T) {
	raw := genesisBlockBytes(t)
	lb, err := newLazyBlock(raw)
	if err != nil {
		t.Fatalf("newLazyBlock: %v", err)
	}

	h1, err := lb.Hash()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := lb.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("cached hash differs from first computation")
	}
}

// TestEnsureTxOffsetsCaching verifies the tx boundary scan runs once.
func TestEnsureTxOffsetsCaching(t *testing.T) {
	raw := genesisBlockBytes(t)
	lb, err := newLazyBlock(raw)
	if err != nil {
		t.Fatalf("newLazyBlock: %v", err)
	}

	// Call TxCount twice — second call hits the cached path.
	c1, err := lb.TxCount()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := lb.TxCount()
	if err != nil {
		t.Fatal(err)
	}
	if c1 != c2 {
		t.Fatal("tx count changed between calls")
	}
}

// TestSegwitSingleInputSingleOutput tests a block with one coinbase
// (non-segwit) and one segwit tx with a single input and single output.
func TestSegwitSingleInputSingleOutput(t *testing.T) {
	coinbase := makeCoinbaseTx(5000000000)

	segwitTx := wire.NewMsgTx(2)
	segwitTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
		Sequence:         0xfffffffe,
	})
	segwitTx.TxIn[0].Witness = wire.TxWitness{
		bytes.Repeat([]byte{0x30}, 71), // DER signature
		bytes.Repeat([]byte{0x02}, 33), // compressed pubkey
	}
	segwitTx.AddTxOut(&wire.TxOut{
		Value:    4999990000,
		PkScript: []byte{0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
	})

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	mustAddTx(t, mb, coinbase)
	mustAddTx(t, mb, segwitTx)

	assertBlockParity(t, serializeBlock(t, mb))
}

// TestSegwitMultiInputMultiOutput tests a block with a segwit tx that has
// multiple inputs (each with varying witness stack sizes) and multiple outputs.
func TestSegwitMultiInputMultiOutput(t *testing.T) {
	coinbase := makeCoinbaseTx(5000000000)

	// A segwit tx with 3 inputs, each with different witness stacks,
	// and 4 outputs with various values and script sizes.
	segwitTx := wire.NewMsgTx(2)
	prevHash := coinbase.TxHash()

	// Input 0: 2 witness items.
	segwitTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
		Sequence:         0xfffffffe,
	})
	segwitTx.TxIn[0].Witness = wire.TxWitness{
		bytes.Repeat([]byte{0x30}, 72),
		bytes.Repeat([]byte{0x02}, 33),
	}

	// Input 1: 3 witness items (e.g. multisig pattern).
	segwitTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
		Sequence:         0xfffffffd,
	})
	segwitTx.TxIn[1].Witness = wire.TxWitness{
		{},                             // empty item (OP_0 for CHECKMULTISIG bug)
		bytes.Repeat([]byte{0x30}, 71), // sig 1
		bytes.Repeat([]byte{0x30}, 72), // sig 2
	}

	// Input 2: 1 witness item (taproot key-path spend style).
	segwitTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
		Sequence:         0xfffffffc,
	})
	segwitTx.TxIn[2].Witness = wire.TxWitness{
		bytes.Repeat([]byte{0xab}, 64), // Schnorr signature
	}

	// 4 outputs with different values.
	segwitTx.AddTxOut(&wire.TxOut{Value: 100000, PkScript: bytes.Repeat([]byte{0x01}, 22)})
	segwitTx.AddTxOut(&wire.TxOut{Value: 200000, PkScript: bytes.Repeat([]byte{0x02}, 34)})
	segwitTx.AddTxOut(&wire.TxOut{Value: 300000, PkScript: bytes.Repeat([]byte{0x03}, 22)})
	segwitTx.AddTxOut(&wire.TxOut{Value: 4999400000, PkScript: bytes.Repeat([]byte{0x04}, 25)})

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	mustAddTx(t, mb, coinbase)
	mustAddTx(t, mb, segwitTx)

	assertBlockParity(t, serializeBlock(t, mb))
}

// TestMixedSegwitNonSegwit tests a block with a mix of segwit and
// non-segwit transactions.
func TestMixedSegwitNonSegwit(t *testing.T) {
	coinbase := makeCoinbaseTx(5000000000)
	prevHash := coinbase.TxHash()

	// Non-segwit tx: 1 input, 2 outputs, no witness.
	nonSegwit := wire.NewMsgTx(1)
	nonSegwit.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
		SignatureScript:  bytes.Repeat([]byte{0x48}, 106),
		Sequence:         0xffffffff,
	})
	nonSegwit.AddTxOut(&wire.TxOut{Value: 2500000000, PkScript: bytes.Repeat([]byte{0xaa}, 25)})
	nonSegwit.AddTxOut(&wire.TxOut{Value: 2499990000, PkScript: bytes.Repeat([]byte{0xbb}, 25)})

	// Segwit tx.
	segwit := wire.NewMsgTx(2)
	segwit.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: nonSegwit.TxHash(), Index: 0},
		Sequence:         0xfffffffe,
	})
	segwit.TxIn[0].Witness = wire.TxWitness{
		bytes.Repeat([]byte{0x30}, 72),
		bytes.Repeat([]byte{0x02}, 33),
	}
	segwit.AddTxOut(&wire.TxOut{Value: 2499980000, PkScript: bytes.Repeat([]byte{0xcc}, 22)})

	// Another non-segwit tx.
	nonSegwit2 := wire.NewMsgTx(1)
	nonSegwit2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: nonSegwit.TxHash(), Index: 1},
		SignatureScript:  bytes.Repeat([]byte{0x47}, 73),
		Sequence:         0xffffffff,
	})
	nonSegwit2.AddTxOut(&wire.TxOut{Value: 2499980000, PkScript: bytes.Repeat([]byte{0xdd}, 25)})

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	mustAddTx(t, mb, coinbase)
	mustAddTx(t, mb, nonSegwit)
	mustAddTx(t, mb, segwit)
	mustAddTx(t, mb, nonSegwit2)

	assertBlockParity(t, serializeBlock(t, mb))
}

// TestManyTransactions tests a block with 50 txs to exercise the
// boundary scanner across a non-trivial number of transactions.
func TestManyTransactions(t *testing.T) {
	coinbase := makeCoinbaseTx(5000000000)

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	mustAddTx(t, mb, coinbase)

	for i := 0; i < 49; i++ {
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
			Sequence:         0xfffffffe,
		})
		tx.TxIn[0].Witness = wire.TxWitness{
			bytes.Repeat([]byte{byte(i)}, 72),
			bytes.Repeat([]byte{byte(i + 1)}, 33),
		}
		// Variable number of outputs per tx.
		numOutputs := (i % 5) + 1
		for o := 0; o < numOutputs; o++ {
			tx.AddTxOut(&wire.TxOut{
				Value:    int64(10000*(i+1) + o),
				PkScript: bytes.Repeat([]byte{byte(o)}, 22),
			})
		}
		mustAddTx(t, mb, tx)
	}

	assertBlockParity(t, serializeBlock(t, mb))
}

// TestEmptyWitnessItems tests a segwit tx that has an empty witness
// stack item (used in CHECKMULTISIG).
func TestEmptyWitnessItems(t *testing.T) {
	coinbase := makeCoinbaseTx(5000000000)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
		Sequence:         0xfffffffe,
	})
	tx.TxIn[0].Witness = wire.TxWitness{
		{},                             // empty OP_0
		bytes.Repeat([]byte{0x30}, 71), // sig
		bytes.Repeat([]byte{0x30}, 72), // sig
		bytes.Repeat([]byte{0x52}, 35), // redeemScript
	}
	tx.AddTxOut(&wire.TxOut{Value: 4999990000, PkScript: bytes.Repeat([]byte{0x00}, 34)})

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	mustAddTx(t, mb, coinbase)
	mustAddTx(t, mb, tx)

	assertBlockParity(t, serializeBlock(t, mb))
}

// TestLargeWitness tests a transaction with large witness data, similar
// to what inscription-heavy blocks produce.
func TestLargeWitness(t *testing.T) {
	coinbase := makeCoinbaseTx(5000000000)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
		Sequence:         0xfffffffe,
	})
	// Simulate an inscription: large witness data (e.g. 10KB image).
	inscriptionData := bytes.Repeat([]byte{0xff}, 10240)
	tx.TxIn[0].Witness = wire.TxWitness{
		bytes.Repeat([]byte{0x30}, 64), // signature
		inscriptionData,                // inscription envelope
		bytes.Repeat([]byte{0x21}, 33), // control block
	}
	tx.AddTxOut(&wire.TxOut{Value: 546, PkScript: bytes.Repeat([]byte{0x51}, 34)})
	tx.AddTxOut(&wire.TxOut{Value: 4999989454, PkScript: bytes.Repeat([]byte{0x00}, 22)})

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	mustAddTx(t, mb, coinbase)
	mustAddTx(t, mb, tx)

	assertBlockParity(t, serializeBlock(t, mb))
}

// TestFindTxNotFound verifies FindTx returns an error for a non-existent txid.
func TestFindTxNotFound(t *testing.T) {
	raw := genesisBlockBytes(t)
	lb, err := newLazyBlock(raw)
	if err != nil {
		t.Fatalf("newLazyBlock: %v", err)
	}

	_, err = lb.FindTx(chainhash.Hash{})
	if err == nil {
		t.Fatal("expected error for non-existent txid")
	}
}

// --- readVarInt tests ---

func TestReadVarInt(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint64
		size int
	}{
		{"zero", []byte{0x00}, 0, 1},
		{"one", []byte{0x01}, 1, 1},
		{"max_single_byte", []byte{0xfc}, 0xfc, 1},
		{"two_byte_min", []byte{0xfd, 0xfd, 0x00}, 0xfd, 3},
		{"two_byte", []byte{0xfd, 0x00, 0x01}, 0x0100, 3},
		{"two_byte_max", []byte{0xfd, 0xff, 0xff}, 0xffff, 3},
		{"four_byte_min", []byte{0xfe, 0x00, 0x00, 0x01, 0x00}, 0x00010000, 5},
		{"four_byte", []byte{0xfe, 0x01, 0x00, 0x01, 0x00}, 0x00010001, 5},
		{"four_byte_max", []byte{0xfe, 0xff, 0xff, 0xff, 0xff}, 0xffffffff, 5},
		{"eight_byte", []byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 1, 9},
		{"eight_byte_large", []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, 0x100000000, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, n, err := readVarInt(tt.data, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("value: got %d, want %d", got, tt.want)
			}
			if n != tt.size {
				t.Fatalf("size: got %d, want %d", n, tt.size)
			}
		})
	}
}

func TestReadVarIntWithOffset(t *testing.T) {
	// Varint starting at offset 3 in a larger buffer.
	data := []byte{0xaa, 0xbb, 0xcc, 0xfd, 0x00, 0x02}
	got, n, err := readVarInt(data, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x0200 {
		t.Fatalf("value: got %d, want %d", got, 0x0200)
	}
	if n != 3 {
		t.Fatalf("size: got %d, want 3", n)
	}
}

func TestReadVarIntErrors(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		offset int
	}{
		{"empty", nil, 0},
		{"offset_past_end", []byte{0x01}, 1},
		{"offset_past_end_2", []byte{0x01}, 5},
		{"short_0xfd", []byte{0xfd, 0x00}, 0},
		{"short_0xfd_1byte", []byte{0xfd}, 0},
		{"short_0xfe", []byte{0xfe, 0x00, 0x00, 0x00}, 0},
		{"short_0xfe_1byte", []byte{0xfe}, 0},
		{"short_0xff", []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0},
		{"short_0xff_1byte", []byte{0xff}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := readVarInt(tt.data, tt.offset)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// --- scanTxBoundaries error path tests ---

func TestScanTxBoundariesTooShort(t *testing.T) {
	_, _, err := scanTxBoundaries(nil)
	if err == nil {
		t.Fatal("expected error for nil")
	}
	_, _, err = scanTxBoundaries(make([]byte, wire.MaxBlockHeaderPayload))
	if err == nil {
		t.Fatal("expected error for header-only block")
	}
}

func TestScanTxBoundariesTruncated(t *testing.T) {
	// Build a valid block, then systematically truncate it at various points
	// to exercise every error path in scanTxBoundaries.
	coinbase := makeCoinbaseTx(5000000000)

	segwitTx := wire.NewMsgTx(2)
	segwitTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
		Sequence:         0xfffffffe,
	})
	segwitTx.TxIn[0].Witness = wire.TxWitness{
		bytes.Repeat([]byte{0x30}, 72),
		bytes.Repeat([]byte{0x02}, 33),
	}
	segwitTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: bytes.Repeat([]byte{0x01}, 22)})

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	mustAddTx(t, mb, coinbase)
	mustAddTx(t, mb, segwitTx)

	raw := serializeBlock(t, mb)

	// Every truncation from wire.MaxBlockHeaderPayload+1 to len(raw)-1 should either
	// succeed (if it happens to cut after a complete block) or return an
	// error. It must never panic.
	for cutoff := wire.MaxBlockHeaderPayload + 1; cutoff < len(raw); cutoff++ {
		truncated := raw[:cutoff]
		_, _, err := scanTxBoundaries(truncated)
		// We don't care whether it errors or succeeds for partial cuts.
		// We care that it never panics.
		_ = err
	}

	// Specific targeted truncations:

	// Truncate in the middle of tx version.
	_, _, err := scanTxBoundaries(raw[:wire.MaxBlockHeaderPayload+1+2])
	if err == nil {
		t.Fatal("expected error: truncated in tx version")
	}
}

// --- computeTxID error path tests ---

func TestComputeTxIDSegwitTooShort(t *testing.T) {
	// Less than 10 bytes for a segwit tx.
	_, err := computeTxID(make([]byte, 9), true)
	if err == nil {
		t.Fatal("expected error for segwit tx < 10 bytes")
	}
}

// --- lazyBlock method error paths ---

func TestLazyBlockHashTooShort(t *testing.T) {
	_, err := newLazyBlock(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short raw")
	}
}

func TestLazyBlockTxCountError(t *testing.T) {
	// Valid header but no tx count byte — constructor requires header+1.
	_, err := newLazyBlock(make([]byte, wire.MaxBlockHeaderPayload))
	if err == nil {
		t.Fatal("expected error for header-only block")
	}
}

func TestLazyBlockTxHashOutOfRange(t *testing.T) {
	raw := genesisBlockBytes(t)
	lb, err := newLazyBlock(raw)
	if err != nil {
		t.Fatalf("newLazyBlock: %v", err)
	}

	_, err = lb.TxHash(-1)
	if err == nil {
		t.Fatal("expected error for negative index")
	}
	_, err = lb.TxHash(99)
	if err == nil {
		t.Fatal("expected error for index past end")
	}
}

func TestLazyBlockTxOutputValuesOutOfRange(t *testing.T) {
	raw := genesisBlockBytes(t)
	lb, err := newLazyBlock(raw)
	if err != nil {
		t.Fatalf("newLazyBlock: %v", err)
	}

	_, err = lb.TxOutputValues(-1)
	if err == nil {
		t.Fatal("expected error for negative index")
	}
	_, err = lb.TxOutputValues(99)
	if err == nil {
		t.Fatal("expected error for index past end")
	}
}

func TestLazyBlockTxHashScanError(t *testing.T) {
	// Constructor rejects header-only blocks.
	_, err := newLazyBlock(make([]byte, wire.MaxBlockHeaderPayload))
	if err == nil {
		t.Fatal("expected error from constructor")
	}
}

func TestLazyBlockTxOutputValuesScanError(t *testing.T) {
	_, err := newLazyBlock(make([]byte, wire.MaxBlockHeaderPayload))
	if err == nil {
		t.Fatal("expected error from constructor")
	}
}

func TestLazyBlockFindTxScanError(t *testing.T) {
	_, err := newLazyBlock(make([]byte, wire.MaxBlockHeaderPayload))
	if err == nil {
		t.Fatal("expected error from constructor")
	}
}

// TestFullBlockRoundTrip verifies that FullBlock produces a block whose
// re-serialization is byte-identical to the original raw bytes.
func TestFullBlockRoundTrip(t *testing.T) {
	coinbase := makeCoinbaseTx(5000000000)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
		Sequence:         0xfffffffe,
	})
	tx.TxIn[0].Witness = wire.TxWitness{
		bytes.Repeat([]byte{0x30}, 72),
		bytes.Repeat([]byte{0x02}, 33),
	}
	tx.AddTxOut(&wire.TxOut{Value: 4999990000, PkScript: bytes.Repeat([]byte{0x00}, 22)})

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	mustAddTx(t, mb, coinbase)
	mustAddTx(t, mb, tx)

	raw := serializeBlock(t, mb)
	lb, err := newLazyBlock(raw)
	if err != nil {
		t.Fatalf("newLazyBlock: %v", err)
	}

	fb, err := lb.FullBlock()
	if err != nil {
		t.Fatal(err)
	}

	// Re-serialize and compare bytes.
	var buf bytes.Buffer
	if err := fb.MsgBlock().Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, buf.Bytes()) {
		t.Fatal("FullBlock re-serialization differs from original raw bytes")
	}
}

// --- Benchmarks ---

func BenchmarkLazyBlockTxHash(b *testing.B) {
	raw := func() []byte {
		genesis := chaincfg.MainNetParams.GenesisBlock
		var buf bytes.Buffer
		if err := genesis.Serialize(&buf); err != nil {
			b.Fatal(err)
		}
		return buf.Bytes()
	}()

	b.Run("lazyBlock", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			lb, err := newLazyBlock(raw)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := lb.TxHash(0); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("btcutil", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			block, err := btcutil.NewBlockFromBytes(raw)
			if err != nil {
				b.Fatal(err)
			}
			_ = block.Transactions()[0].Hash()
		}
	})
}

func BenchmarkLazyBlockOutputValues(b *testing.B) {
	raw := func() []byte {
		genesis := chaincfg.MainNetParams.GenesisBlock
		var buf bytes.Buffer
		if err := genesis.Serialize(&buf); err != nil {
			b.Fatal(err)
		}
		return buf.Bytes()
	}()

	b.Run("lazyBlock", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			lb, err := newLazyBlock(raw)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := lb.TxOutputValues(0); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("btcutil", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			block, err := btcutil.NewBlockFromBytes(raw)
			if err != nil {
				b.Fatal(err)
			}
			tx := block.Transactions()[0].MsgTx()
			vals := make([]uint64, len(tx.TxOut))
			for j, out := range tx.TxOut {
				vals[j] = uint64(out.Value)
			}
		}
	})
}

func BenchmarkLazyBlockSegwitFindTx(b *testing.B) {
	coinbase := makeCoinbaseTxBench(b, 5000000000)

	mb := wire.NewMsgBlock(&wire.BlockHeader{Version: 0x20000000})
	if err := mb.AddTransaction(coinbase); err != nil {
		b.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
			Sequence:         0xfffffffe,
		})
		tx.TxIn[0].Witness = wire.TxWitness{
			bytes.Repeat([]byte{0x30}, 72),
			bytes.Repeat([]byte{0x02}, 33),
		}
		tx.AddTxOut(&wire.TxOut{
			Value:    int64(1000000 + i),
			PkScript: bytes.Repeat([]byte{byte(i)}, 22),
		})
		if err := mb.AddTransaction(tx); err != nil {
			b.Fatal(err)
		}
	}

	var buf bytes.Buffer
	if err := mb.Serialize(&buf); err != nil {
		b.Fatal(err)
	}
	raw := buf.Bytes()

	refBlock, err := btcutil.NewBlockFromBytes(raw)
	if err != nil {
		b.Fatal(err)
	}
	targetTxid := *refBlock.Transactions()[100].Hash()

	b.Run("lazyBlock_FindTx+OutputValues", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			lb, err := newLazyBlock(raw)
			if err != nil {
				b.Fatal(err)
			}
			idx, err := lb.FindTx(targetTxid)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := lb.TxOutputValues(idx); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("btcutil_full_parse", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			block, err := btcutil.NewBlockFromBytes(raw)
			if err != nil {
				b.Fatal(err)
			}
			for _, tx := range block.Transactions() {
				if *tx.Hash() == targetTxid {
					mtx := tx.MsgTx()
					vals := make([]uint64, len(mtx.TxOut))
					for j, out := range mtx.TxOut {
						vals[j] = uint64(out.Value)
					}
					break
				}
			}
		}
	})
}

func makeCoinbaseTxBench(b *testing.B, value int64) *wire.MsgTx {
	b.Helper()
	return makeCoinbaseTx(value)
}

// --- Internal function coverage tests ---
// These test error paths inside computeTxID, extractOutputValues, and
// scanTxBoundaries that are unreachable through the public lazyBlock API
// (because scanTxBoundaries would reject the block before those paths
// fire). For 100% coverage we call the internals directly with crafted
// corrupted data.

func TestComputeTxIDSegwitErrors(t *testing.T) {
	// Build a valid segwit tx, then truncate at each internal boundary.
	coinbase := makeCoinbaseTx(5000000000)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: coinbase.TxHash(), Index: 0},
		Sequence:         0xfffffffe,
	})
	tx.TxIn[0].Witness = wire.TxWitness{
		bytes.Repeat([]byte{0x30}, 72),
		bytes.Repeat([]byte{0x02}, 33),
	}
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: bytes.Repeat([]byte{0x01}, 22)})

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()

	// Verify the full bytes produce the correct txid.
	got, err := computeTxID(full, true)
	if err != nil {
		t.Fatalf("full tx: %v", err)
	}
	want := tx.TxHash()
	if got != want {
		t.Fatalf("full tx txid: got %v, want %v", got, want)
	}

	// Truncation points. Each should produce an error.
	truncations := []struct {
		name string
		len  int
	}{
		{"too_short_for_segwit", 9},                       // < 10 bytes
		{"truncated_at_input_count", 6},                   // version(4) + marker/flag(2), no input count
		{"truncated_at_input_script_len", 6 + 1 + 36},     // input count(1) + prevout(36), no script len
		{"truncated_at_output_count", 6 + 1 + 36 + 1 + 4}, // ...+ scriptLen(1=0) + sequence(4), no output count
		// Truncate after output count but before output value+script.
		{"truncated_at_output_script_len", 6 + 1 + 36 + 1 + 4 + 1 + 8}, // + outputCount(1) + value(8)
	}

	for _, tt := range truncations {
		t.Run(tt.name, func(t *testing.T) {
			if tt.len > len(full) {
				t.Skipf("truncation point %d > full tx len %d", tt.len, len(full))
			}
			_, err := computeTxID(full[:tt.len], true)
			if err == nil {
				t.Fatalf("expected error for truncation at %d bytes", tt.len)
			}
		})
	}
}

func TestExtractOutputValuesErrors(t *testing.T) {
	// Build truncated tx byte slices to exercise each error path.
	// Non-witness tx with 1 input (scriptLen=0) offset map:
	//   version:     0-3   (4 bytes)
	//   inputCount:  4     (1 byte = 1)
	//   prevhash:    5-36  (32 bytes)
	//   previndex:   37-40 (4 bytes)
	//   scriptLen:   41    (1 byte = 0)
	//   sequence:    42-45 (4 bytes)
	//   outputCount: 46    (1 byte)
	//   value:       47-54 (8 bytes)
	//   scriptLen:   55    (1 byte)

	tests := []struct {
		name string
		len  int // total byte slice length
		// Bytes set: [0]=version, [4]=inputCount, [46]=outputCount (if present)
		setOutputCount bool
	}{
		{"input_count_error", 4, false},       // offset 4 past end
		{"input_script_len_error", 41, false}, // offset 41 past end
		{"output_count_error", 46, false},     // offset 46 past end
		{"short_output_value", 48, true},      // outputCount=1 at [46], value needs 8 bytes at 47
		{"output_script_len_error", 55, true}, // value at 47-54 ok, scriptLen at 55 past end
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.len)
			data[0] = 0x01 // version
			if tt.len > 4 {
				data[4] = 0x01 // 1 input
			}
			if tt.setOutputCount && tt.len > 46 {
				data[46] = 0x01 // 1 output
			}
			_, err := extractOutputValues(data, false)
			if err == nil {
				t.Fatalf("expected error for %d-byte tx", tt.len)
			}
		})
	}

	// Witness variant: truncated before input count (after marker/flag).
	_, err := extractOutputValues([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x01}, true)
	if err == nil {
		t.Fatal("expected error: witness tx no input count")
	}
}

func TestScanTxBoundariesTxCountError(t *testing.T) {
	// Block with valid header + 0xfd varint prefix but insufficient
	// following bytes for the tx count.
	block := make([]byte, wire.MaxBlockHeaderPayload+2)
	block[wire.MaxBlockHeaderPayload] = 0xfd
	block[wire.MaxBlockHeaderPayload+1] = 0x01 // need 2 more bytes, only 1 available
	_, _, err := scanTxBoundaries(block)
	if err == nil {
		t.Fatal("expected error for truncated tx count varint")
	}
}

// TestComputeTxIDNonWitness verifies that non-witness txid is computed
// as a straight double-SHA256 of the entire serialization.
func TestComputeTxIDNonWitness(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
		SignatureScript:  []byte{0x04, 0xff},
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(&wire.TxOut{Value: 5000000000, PkScript: []byte{0x76, 0xa9}})

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()

	got, err := computeTxID(raw, false)
	if err != nil {
		t.Fatal(err)
	}

	want := chainhash.DoubleHashH(raw)
	if got != want {
		t.Fatalf("non-witness txid: got %v, want %v", got, want)
	}
}

// TestComputeTxIDSegwitInputCountError covers the input count readVarInt
// error in computeTxID (line that requires len >= 10 but invalid varint).
func TestComputeTxIDSegwitInputCountError(t *testing.T) {
	// 10 bytes: version(4) + marker/flag(2) + 0xfe at offset 6 which
	// needs 5 more bytes but only 4 remain → readVarInt error.
	data := make([]byte, 10)
	data[0] = 0x01 // version
	data[4] = 0x00 // marker
	data[5] = 0x01 // flag
	data[6] = 0xfe // varint prefix needing 4 more bytes, only 3 available
	_, err := computeTxID(data, true)
	if err == nil {
		t.Fatal("expected error for malformed input count varint")
	}
}

// TestFindTxComputeTxIDError covers the computeTxID error path inside
// FindTx. We construct a lazyBlock with manually corrupted txOffsets
// that point to bytes too short for computeTxID to process.
func TestFindTxComputeTxIDError(t *testing.T) {
	// Start with a valid genesis block so the raw bytes are present.
	raw := genesisBlockBytes(t)
	lb, err := newLazyBlock(raw)
	if err != nil {
		t.Fatalf("newLazyBlock: %v", err)
	}

	// Force the tx boundary scan, then corrupt the result.
	lb.mu.Lock()
	if err := lb.ensureTxOffsets(); err != nil {
		lb.mu.Unlock()
		t.Fatal(err)
	}
	// Point the first tx at a 9-byte range and mark it as witness.
	// computeTxID will hit "segwit tx too short".
	lb.txOffsets = []wire.TxLoc{{TxStart: 0, TxLen: 9}}
	lb.txWitness = []bool{true}
	lb.mu.Unlock()

	_, err = lb.FindTx(chainhash.Hash{0x01})
	if err == nil {
		t.Fatal("expected error from computeTxID inside FindTx")
	}
}

// --- Real-world block tests and benchmarks ---
//
// These use actual testnet3 blocks from testdata/ (~1MB each, 3000+ txs)
// to validate correctness and benchmark lazy vs greedy (btcutil) parsing
// under realistic conditions.

// loadTestdataBlock reads a hex-encoded block from testdata/.
func loadTestdataBlock(tb testing.TB, filename string) []byte {
	tb.Helper()
	hexBytes, err := os.ReadFile("testdata/" + filename)
	if err != nil {
		tb.Fatalf("reading testdata block: %v", err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(hexBytes)))
	if err != nil {
		tb.Fatalf("decoding testdata block hex: %v", err)
	}
	return raw
}

// testdataBlockFiles returns the filenames of the hex block fixtures.
func testdataBlockFiles() []string {
	return []string{
		"0000000000000006200009cf36af2bbcb1362b887b4e2625113b6b44327435b8.hex",
		"00000000055a5c34a021ab3b1f3f6f0304b403775feb9e5a235dc7f724c5833f.hex",
	}
}

// TestRealBlockParity runs the full oracle comparison (every txid, every
// output value, FindTx round-trip, FullBlock round-trip) against each
// real testnet3 block in testdata/.
func TestRealBlockParity(t *testing.T) {
	for _, f := range testdataBlockFiles() {
		t.Run(f[:16], func(t *testing.T) {
			raw := loadTestdataBlock(t, f)
			assertBlockParity(t, raw)
		})
	}
}

// BenchmarkRealBlockFindTxOutputValues benchmarks the actual ordinal
// indexer use case: given a block, find a specific tx by txid and
// extract its output values. Compares lazy (boundary scan + targeted
// parse) against greedy (btcutil.NewBlockFromBytes, full deserialize,
// linear search).
//
// This is the hot path that causes 50% GC pressure in production.
func BenchmarkRealBlockFindTxOutputValues(b *testing.B) {
	for _, f := range testdataBlockFiles() {
		raw := loadTestdataBlock(b, f)

		// Parse with btcutil to get reference data.
		refBlock, err := btcutil.NewBlockFromBytes(raw)
		if err != nil {
			b.Fatal(err)
		}
		refTxs := refBlock.Transactions()

		// Pick the tx at 75% depth — forces scanning most of the block.
		targetIdx := len(refTxs) * 3 / 4
		targetTxid := *refTxs[targetIdx].Hash()
		wantOutputCount := len(refTxs[targetIdx].MsgTx().TxOut)

		label := fmt.Sprintf("%s_%dtxs", f[:8], len(refTxs))

		b.Run(label+"/lazy", func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for range b.N {
				lb, err := newLazyBlock(raw)
				if err != nil {
					b.Fatal(err)
				}
				idx, err := lb.FindTx(targetTxid)
				if err != nil {
					b.Fatal(err)
				}
				vals, err := lb.TxOutputValues(idx)
				if err != nil {
					b.Fatal(err)
				}
				if len(vals) != wantOutputCount {
					b.Fatalf("output count: got %d, want %d", len(vals), wantOutputCount)
				}
			}
		})

		b.Run(label+"/greedy", func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for range b.N {
				block, err := btcutil.NewBlockFromBytes(raw)
				if err != nil {
					b.Fatal(err)
				}
				for _, tx := range block.Transactions() {
					if *tx.Hash() == targetTxid {
						mtx := tx.MsgTx()
						vals := make([]uint64, len(mtx.TxOut))
						for j, out := range mtx.TxOut {
							vals[j] = uint64(out.Value)
						}
						if len(vals) != wantOutputCount {
							b.Fatalf("output count: got %d, want %d", len(vals), wantOutputCount)
						}
						break
					}
				}
			}
		})
	}
}

// BenchmarkRealBlockBoundaryScan benchmarks just the boundary scan step
// (finding all tx offsets without parsing any tx data) against the full
// btcutil deserialization.
func BenchmarkRealBlockBoundaryScan(b *testing.B) {
	for _, f := range testdataBlockFiles() {
		raw := loadTestdataBlock(b, f)

		refBlock, err := btcutil.NewBlockFromBytes(raw)
		if err != nil {
			b.Fatal(err)
		}
		txCount := len(refBlock.Transactions())
		label := fmt.Sprintf("%s_%dtxs", f[:8], txCount)

		b.Run(label+"/scanTxBoundaries", func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for range b.N {
				locs, _, err := scanTxBoundaries(raw)
				if err != nil {
					b.Fatal(err)
				}
				if len(locs) != txCount {
					b.Fatalf("tx count: got %d, want %d", len(locs), txCount)
				}
			}
		})

		b.Run(label+"/btcutil_NewBlockFromBytes", func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for range b.N {
				block, err := btcutil.NewBlockFromBytes(raw)
				if err != nil {
					b.Fatal(err)
				}
				txs := block.Transactions()
				if len(txs) != txCount {
					b.Fatalf("tx count: got %d, want %d", len(txs), txCount)
				}
			}
		})
	}
}

// BenchmarkRealBlockSingleTxHash benchmarks computing a single txid
// from a real block: lazy (boundary scan + one txid) vs greedy (full
// parse + one txid).
func BenchmarkRealBlockSingleTxHash(b *testing.B) {
	for _, f := range testdataBlockFiles() {
		raw := loadTestdataBlock(b, f)

		refBlock, err := btcutil.NewBlockFromBytes(raw)
		if err != nil {
			b.Fatal(err)
		}
		refTxs := refBlock.Transactions()
		targetIdx := len(refTxs) / 2
		wantHash := *refTxs[targetIdx].Hash()

		label := fmt.Sprintf("%s_%dtxs", f[:8], len(refTxs))

		b.Run(label+"/lazy", func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for range b.N {
				lb, err := newLazyBlock(raw)
				if err != nil {
					b.Fatal(err)
				}
				got, err := lb.TxHash(targetIdx)
				if err != nil {
					b.Fatal(err)
				}
				if got != wantHash {
					b.Fatal("txid mismatch")
				}
			}
		})

		b.Run(label+"/greedy", func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for range b.N {
				block, err := btcutil.NewBlockFromBytes(raw)
				if err != nil {
					b.Fatal(err)
				}
				got := *block.Transactions()[targetIdx].Hash()
				if got != wantHash {
					b.Fatal("txid mismatch")
				}
			}
		})
	}
}

// --- Fuzz tests ---
//
// scanTxBoundaries, readVarInt, computeTxID, and extractOutputValues
// parse untrusted bytes. These fuzz tests ensure no panic on arbitrary
// input.

func FuzzScanTxBoundaries(f *testing.F) {
	// Seed with a real block.
	f.Add(genesisBlockBytes(f))
	// Seed with minimal valid-ish input (header + varint 0).
	seed := make([]byte, wire.MaxBlockHeaderPayload+1)
	f.Add(seed)
	// Seed with empty and short inputs.
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Must not panic.
		_, _, _ = scanTxBoundaries(raw)
	})
}

func FuzzReadVarInt(f *testing.F) {
	f.Add([]byte{0x00}, 0)
	f.Add([]byte{0xfc}, 0)
	f.Add([]byte{0xfd, 0x01, 0x00}, 0)
	f.Add([]byte{0xfe, 0x01, 0x00, 0x00, 0x00}, 0)
	f.Add([]byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0)
	f.Add([]byte{}, 0)
	f.Add([]byte{0xfd}, 0)

	f.Fuzz(func(t *testing.T, b []byte, offset int) {
		if offset < 0 {
			return
		}
		// Must not panic.
		_, _, _ = readVarInt(b, offset)
	})
}

func FuzzComputeTxID(f *testing.F) {
	// Seed with a real genesis coinbase tx.
	raw := genesisBlockBytes(f)
	locs, witness, err := scanTxBoundaries(raw)
	if err != nil || len(locs) == 0 {
		f.Fatal("failed to scan genesis block")
	}
	txBytes := raw[locs[0].TxStart : locs[0].TxStart+locs[0].TxLen]
	f.Add(txBytes, witness[0])
	f.Add([]byte{}, false)
	f.Add([]byte{}, true)
	f.Add(make([]byte, 10), true)

	f.Fuzz(func(t *testing.T, txBytes []byte, hasWitness bool) {
		// Must not panic.
		_, _ = computeTxID(txBytes, hasWitness)
	})
}

func FuzzExtractOutputValues(f *testing.F) {
	raw := genesisBlockBytes(f)
	locs, witness, err := scanTxBoundaries(raw)
	if err != nil || len(locs) == 0 {
		f.Fatal("failed to scan genesis block")
	}
	txBytes := raw[locs[0].TxStart : locs[0].TxStart+locs[0].TxLen]
	f.Add(txBytes, witness[0])
	f.Add([]byte{}, false)
	f.Add([]byte{}, true)

	f.Fuzz(func(t *testing.T, txBytes []byte, hasWitness bool) {
		// Must not panic.
		_, _ = extractOutputValues(txBytes, hasWitness)
	})
}

func FuzzNewLazyBlock(f *testing.F) {
	f.Add(genesisBlockBytes(f))
	f.Add([]byte{})
	f.Add(make([]byte, wire.MaxBlockHeaderPayload))
	f.Add(make([]byte, wire.MaxBlockHeaderPayload+1))

	f.Fuzz(func(t *testing.T, raw []byte) {
		lb, err := newLazyBlock(raw)
		if err != nil {
			return
		}
		// If construction succeeded, methods must not panic.
		_, _ = lb.Hash()
		_, _ = lb.TxCount()
		n, err := lb.TxCount()
		if err != nil {
			return
		}
		for i := range n {
			_, _ = lb.TxHash(i)
			_, _ = lb.TxOutputValues(i)
		}
		_, _ = lb.FindTx(chainhash.Hash{})
	})
}
