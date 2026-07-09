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
	"maps"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// ordStubDB implements the subset of tbcd.Database that windBlock and
// inputOutputValue touch. Parent transactions are served as one-tx "raw
// blocks" keyed by their own txid. Calls to any other Database method
// panic (nil embedded interface), which is intentional: it flags an
// unexpected DB dependency in the code under test.
type ordStubDB struct {
	tbcd.Database

	bigO    map[tbcd.Outpoint][]byte
	located map[tbcd.Outpoint][]tbcd.OrdinalLocatedInscription
	parents map[chainhash.Hash]*wire.MsgTx
	// legacyBlocks serves parents whose tx-index entry predates v6:
	// BlockHashByTxId returns a nil TxLoc (as the real database does,
	// level.go BlockHashByTxId) and BlockRawByHash serves the full
	// serialized block for the lazyBlock slow path. A nil entry means
	// "legacy entry whose raw block is missing" and makes
	// BlockRawByHash report the block as not found.
	legacyBlocks map[chainhash.Hash][]byte

	mtx         sync.Mutex
	txIdLookups int // BlockHashByTxId call count == iov lookups
	inflight    int
	maxInflight int
	gateWaiters int
	// rawBlocks serves BlockRawByHash for entries that have a v6 loc
	// but need the whole-block path (zeroLoc scenarios).
	rawBlocks map[chainhash.Hash][]byte
	// overlapGate, when non-nil, blocks the first lookup until a
	// second concurrent lookup arrives, making observed overlap
	// deterministic without timing assumptions.
	overlapGate chan struct{}
	// badLocLen/badLocOff corrupt the TxLoc returned by
	// BlockHashByTxId to drive the ranged-read error paths; wrongTx
	// serves a DIFFERENT valid tx's bytes at the loc; zeroLoc returns
	// a non-nil TxLoc with TxLen 0 (corrupt/short v6 index value).
	badLocLen bool
	badLocOff bool
	wrongTx   bool
	zeroLoc   bool
}

// ordStubPrefix pads stub "blocks" so TxLocs carry a real nonzero
// TxStart, pinning the offset plumbing of the fast path (real locs
// are always >= 81: header + varint + coinbase).
const ordStubPrefix = 80

// stubBlockBytes returns the fake raw block for a parent tx: junk
// prefix followed by the serialized tx, with the tx's TxLoc.
func stubBlockBytes(tx *wire.MsgTx) ([]byte, wire.TxLoc, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, wire.TxLoc{}, err
	}
	raw := make([]byte, ordStubPrefix+buf.Len())
	for i := range ordStubPrefix {
		raw[i] = 0xa5 // junk: misuse of TxStart must not decode
	}
	copy(raw[ordStubPrefix:], buf.Bytes())
	return raw, wire.TxLoc{TxStart: ordStubPrefix, TxLen: buf.Len()}, nil
}

func (d *ordStubDB) OrdinalBigOByOutpoint(_ context.Context, op tbcd.Outpoint) ([]byte, error) {
	return d.bigO[op], nil
}

func (d *ordStubDB) OrdinalInscriptionsByOutpointWithOffset(_ context.Context, op tbcd.Outpoint) ([]tbcd.OrdinalLocatedInscription, error) {
	return d.located[op], nil
}

func (d *ordStubDB) BlockHashByTxId(_ context.Context, txId chainhash.Hash) (*chainhash.Hash, *wire.TxLoc, error) {
	d.mtx.Lock()
	d.txIdLookups++
	d.inflight++
	if d.inflight > d.maxInflight {
		d.maxInflight = d.inflight
	}
	gate := d.overlapGate
	if gate != nil {
		d.gateWaiters++
		if d.gateWaiters == 2 {
			close(gate)
			d.overlapGate = nil // subsequent lookups pass freely
		}
	}
	d.mtx.Unlock()
	if gate != nil {
		<-gate // released when a second lookup is concurrently inside
	}
	defer func() {
		d.mtx.Lock()
		d.inflight--
		d.mtx.Unlock()
	}()

	if _, ok := d.legacyBlocks[txId]; ok {
		bh := txId
		return &bh, nil, nil // legacy entry: no TxLoc
	}
	tx, ok := d.parents[txId]
	if !ok {
		return nil, nil, database.NotFoundError(fmt.Sprintf("tx not found: %v", txId))
	}
	if d.zeroLoc {
		bh := txId
		return &bh, &wire.TxLoc{}, nil // corrupt v6 entry: zero loc
	}
	_, loc, err := stubBlockBytes(tx)
	if err != nil {
		return nil, nil, err
	}
	if d.badLocLen {
		loc.TxLen++ // past the stored bytes: ranged read must fail
	}
	if d.badLocOff {
		loc.TxStart++ // misaligned: deserialize must fail
		loc.TxLen--
	}
	bh := txId // fake block hash: the parent txid itself
	return &bh, &loc, nil
}

func (d *ordStubDB) BlockTxRawByLoc(_ context.Context, hash chainhash.Hash, loc wire.TxLoc) ([]byte, error) {
	tx, ok := d.parents[hash] // fake block hash: the parent txid
	if !ok {
		return nil, database.BlockNotFoundError{Hash: hash}
	}
	if d.wrongTx {
		// Serve a different, valid transaction's bytes: in-range
		// wrong locs deserialize fine and must be caught by the
		// caller's txid verification.
		other, _ := ordTestParent(0xee, 31337)
		tx = other
	}
	raw, _, err := stubBlockBytes(tx)
	if err != nil {
		return nil, err
	}
	if loc.TxStart < 0 || loc.TxLen <= 0 || loc.TxStart+loc.TxLen > len(raw) {
		return nil, fmt.Errorf("range %v+%v exceeds value size %v",
			loc.TxStart, loc.TxLen, len(raw))
	}
	return raw[loc.TxStart : loc.TxStart+loc.TxLen], nil
}

func (d *ordStubDB) BlockRawByHash(_ context.Context, hash chainhash.Hash) ([]byte, error) {
	if raw, ok := d.legacyBlocks[hash]; ok && raw != nil {
		return raw, nil
	}
	if raw, ok := d.rawBlocks[hash]; ok {
		return raw, nil
	}
	tx, ok := d.parents[hash]
	if !ok {
		// Match the real implementation's error type (level.go
		// BlockRawByHash).
		return nil, database.BlockNotFoundError{Hash: hash}
	}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *ordStubDB) lookups() int {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return d.txIdLookups
}

func newOrdTestIndexer(t *testing.T, db *ordStubDB, verifyBigO bool) *ordinalIndexer {
	t.Helper()
	g := geometryParams{db: db, chain: &chaincfg.RegressionNetParams}
	return NewOrdinalIndexer(t.Context(), g, OrdinalIndexerConfig{
		CacheLen:             1000,
		Enabled:              true,
		WatermarkGap:         time.Hour,
		OutputValueCacheSize: 65536,
		VerifyBigO:           verifyBigO,
	}).(*ordinalIndexer)
}

// ordTestParent returns a parent tx with the given output values and a
// unique txid (seeded via the input prevout hash).
func ordTestParent(seed byte, vals ...int64) (*wire.MsgTx, chainhash.Hash) {
	tx := wire.NewMsgTx(wire.TxVersion)
	var h chainhash.Hash
	h[0] = seed
	h[1] = 0x5a
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&h, 0), nil, nil))
	for _, v := range vals {
		tx.AddTxOut(wire.NewTxOut(v, []byte{txscript.OP_TRUE}))
	}
	return tx, tx.TxHash()
}

// ordTestBlock wraps txs in a block with a coinbase paying cbValue.
func ordTestBlock(height int32, cbValue int64, txs ...*wire.MsgTx) *btcutil.Block {
	cb := wire.NewMsgTx(wire.TxVersion)
	cb.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex),
		SignatureScript:  []byte{txscript.OP_0, txscript.OP_0},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	cb.AddTxOut(wire.NewTxOut(cbValue, []byte{txscript.OP_TRUE}))

	msg := &wire.MsgBlock{
		Header: wire.BlockHeader{Timestamp: time.Unix(1700000000, 0)},
	}
	if err := msg.AddTransaction(cb); err != nil {
		panic(err)
	}
	for _, tx := range txs {
		if err := msg.AddTransaction(tx); err != nil {
			panic(err)
		}
	}
	b := btcutil.NewBlock(msg)
	b.SetHeight(height)
	return b
}

// ordTestTrackedOutpoint installs a tracked inscription ('o' + 'O') at
// op in the stub, holding an inscription at srcOffset within an output
// worth outputValue sats.
func ordTestTrackedOutpoint(db *ordStubDB, op tbcd.Outpoint, inscID [36]byte, srcOffset, outputValue uint64) {
	oVal := encodeOutpointValue(inscID, srcKindReveal, 0, ordinalRevealSentinel, 0)
	db.located[op] = []tbcd.OrdinalLocatedInscription{{
		InscID: inscID,
		Offset: srcOffset,
		Value:  oVal,
	}}
	bigO := make([]byte, 40)
	bigO[0] = 0xbb // fake holding block hash
	binary.BigEndian.PutUint64(bigO[32:], outputValue)
	db.bigO[op] = bigO
}

func newOrdStubDB() *ordStubDB {
	return &ordStubDB{
		bigO:         make(map[tbcd.Outpoint][]byte),
		located:      make(map[tbcd.Outpoint][]tbcd.OrdinalLocatedInscription),
		parents:      make(map[chainhash.Hash]*wire.MsgTx),
		legacyBlocks: make(map[chainhash.Hash][]byte),
	}
}

// TestWindBlockTransferZeroFetch verifies the maxIdx-1 shortcircuit: a
// single-input transfer with an 'O' entry winds with ZERO tx-index
// lookups — the last (only) input's value is never fetched.
func TestWindBlockTransferZeroFetch(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	parent, parentTxid := ordTestParent(1, 5000)
	_ = parent // never looked up; that is the point
	spentOP := tbcd.NewOutpoint(parentTxid, 0)
	inscID := makeInscriptionID(&parentTxid, 0)
	ordTestTrackedOutpoint(db, spentOP, inscID, 7, 5000)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentTxid, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(5000, []byte{txscript.OP_TRUE}))
	txid := tx.TxHash()

	b := ordTestBlock(800000, 625000000, tx)
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}

	if got := db.lookups(); got != 0 {
		t.Fatalf("expected 0 tx-index lookups for 1-in transfer, got %d", got)
	}

	m := cache.Map()
	src := m[spentOP]
	if src == nil {
		t.Fatal("no cache entry at source outpoint")
	}
	if v, ok := src.Inscriptions[7]; !ok || v != nil {
		t.Fatalf("source 'o' not tombstoned: ok=%v v=%x", ok, v)
	}
	if !src.BigOSet || src.BigO != nil {
		t.Fatalf("source 'O' not tombstoned: set=%v v=%x", src.BigOSet, src.BigO)
	}
	dst := m[tbcd.NewOutpoint(txid, 0)]
	if dst == nil {
		t.Fatal("no cache entry at destination outpoint")
	}
	if v, ok := dst.Inscriptions[7]; !ok || v == nil {
		t.Fatalf("transfer not placed at offset 7: ok=%v", ok)
	}
	if !dst.BigOSet || len(dst.BigO) != 40 {
		t.Fatalf("destination 'O' not written: set=%v len=%d", dst.BigOSet, len(dst.BigO))
	}
	if got := binary.BigEndian.Uint64(dst.BigO[32:]); got != 5000 {
		t.Fatalf("destination 'O' outputValue: got %d, want 5000", got)
	}
}

// TestWindBlockVerifyBigOPass runs the same transfer with the verify
// flag enabled and a matching parent output value: exactly one lookup
// (the cross-check) and a successful wind.
func TestWindBlockVerifyBigOPass(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, true)

	parent, parentTxid := ordTestParent(1, 5000)
	db.parents[parentTxid] = parent
	spentOP := tbcd.NewOutpoint(parentTxid, 0)
	inscID := makeInscriptionID(&parentTxid, 0)
	ordTestTrackedOutpoint(db, spentOP, inscID, 0, 5000)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentTxid, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(5000, []byte{txscript.OP_TRUE}))

	b := ordTestBlock(800000, 625000000, tx)
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	if got := db.lookups(); got != 1 {
		t.Fatalf("expected exactly 1 verify lookup, got %d", got)
	}
	dst := cache.Map()[tbcd.NewOutpoint(tx.TxHash(), 0)]
	if dst == nil || dst.Inscriptions[0] == nil {
		t.Fatal("transfer not placed with verify enabled")
	}
}

// TestWindBlockVerifyBigOMismatchPanic corrupts the 'O' outputValue and
// expects the verify cross-check to panic.
func TestWindBlockVerifyBigOMismatchPanic(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, true)

	parent, parentTxid := ordTestParent(1, 5000)
	db.parents[parentTxid] = parent
	spentOP := tbcd.NewOutpoint(parentTxid, 0)
	inscID := makeInscriptionID(&parentTxid, 0)
	ordTestTrackedOutpoint(db, spentOP, inscID, 0, 4999) // wrong: real is 5000

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentTxid, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(5000, []byte{txscript.OP_TRUE}))

	b := ordTestBlock(800000, 625000000, tx)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on 'O' outputValue mismatch")
		}
		if !strings.Contains(fmt.Sprint(r), "'O' outputValue mismatch") {
			t.Fatalf("wrong panic: %v", r)
		}
	}()
	_ = oi.windBlock(t.Context(), 800000, b.Hash(), b, NewOrdinalCache(1000, 0))
}

// TestWindBlockVerifyBigOLookupError makes the verify's authoritative
// lookup fail (parent tx missing from the tx index) and expects an
// ordinary error return: lookup failures are recoverable (disk error,
// shutdown) and must not crash the daemon; only genuine value
// mismatches panic.
func TestWindBlockVerifyBigOLookupError(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, true)

	_, parentTxid := ordTestParent(1, 5000) // NOT installed in db.parents
	spentOP := tbcd.NewOutpoint(parentTxid, 0)
	inscID := makeInscriptionID(&parentTxid, 0)
	ordTestTrackedOutpoint(db, spentOP, inscID, 0, 5000)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentTxid, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(5000, []byte{txscript.OP_TRUE}))

	b := ordTestBlock(800000, 625000000, tx)
	err := oi.windBlock(t.Context(), 800000, b.Hash(), b, NewOrdinalCache(1000, 0))
	if err == nil {
		t.Fatal("expected error on verify lookup failure")
	}
	if !strings.Contains(err.Error(), "bigO verify iov") {
		t.Fatalf("wrong error: %v", err)
	}
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("lookup failure must wrap the underlying error: %v", err)
	}
}

// TestWindBlockRevealSecondInput places a reveal on input 1 of a 2-in
// tx: exactly one value fetch (input 0, the sequential fetchCount==1
// path) and pos = value(input 0).
func TestWindBlockRevealSecondInput(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	parentA, parentATxid := ordTestParent(1, 10000)
	db.parents[parentATxid] = parentA
	_, parentBTxid := ordTestParent(2, 600)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentATxid, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentBTxid, 0), nil, nil))
	tx.TxIn[1].Witness = buildInscriptionWitness("text/plain", "second input")
	tx.AddTxOut(wire.NewTxOut(20000, []byte{txscript.OP_TRUE}))
	txid := tx.TxHash()

	b := ordTestBlock(800000, 625000000, tx)
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	if got := db.lookups(); got != 1 {
		t.Fatalf("expected 1 lookup (input 0 only), got %d", got)
	}
	dst := cache.Map()[tbcd.NewOutpoint(txid, 0)]
	if dst == nil {
		t.Fatal("no cache entry at reveal tx outpoint")
	}
	if v, ok := dst.Inscriptions[10000]; !ok || v == nil {
		t.Fatalf("reveal not placed at offset 10000 (value of input 0): %v", dst.Inscriptions)
	}
	if len(dst.Aux) != 2 { // 'i' + 'n'
		t.Fatalf("expected 2 aux entries, got %d", len(dst.Aux))
	}
}

// TestWindBlockPrefilledTransferPlusReveal mixes an 'O'-carried transfer
// on input 0 with a reveal on input 2: the transfer's value is prefilled
// from 'O' (no lookup), input 1 is fetched via the parallel path (which
// must skip the prefilled slot), and the reveal lands at the sum.
func TestWindBlockPrefilledTransferPlusReveal(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	_, parentPTxid := ordTestParent(1, 5000)
	spentOP := tbcd.NewOutpoint(parentPTxid, 0)
	inscID := makeInscriptionID(&parentPTxid, 0)
	ordTestTrackedOutpoint(db, spentOP, inscID, 0, 5000)

	parentA, parentATxid := ordTestParent(2, 7000)
	db.parents[parentATxid] = parentA
	_, parentBTxid := ordTestParent(3, 800)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentPTxid, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentATxid, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentBTxid, 0), nil, nil))
	tx.TxIn[2].Witness = buildInscriptionWitness("text/plain", "third input")
	tx.AddTxOut(wire.NewTxOut(20000, []byte{txscript.OP_TRUE}))
	txid := tx.TxHash()

	b := ordTestBlock(800000, 625000000, tx)
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	// Input 0 prefilled from 'O', input 2 is maxIdx (never fetched):
	// only input 1 hits the tx index.
	if got := db.lookups(); got != 1 {
		t.Fatalf("expected 1 lookup (input 1 only), got %d", got)
	}
	dst := cache.Map()[tbcd.NewOutpoint(txid, 0)]
	if dst == nil {
		t.Fatal("no cache entry at destination outpoint")
	}
	if v, ok := dst.Inscriptions[0]; !ok || v == nil {
		t.Fatal("transfer not placed at offset 0")
	}
	if v, ok := dst.Inscriptions[12000]; !ok || v == nil {
		t.Fatalf("reveal not placed at offset 12000 (5000+7000): %v", dst.Inscriptions)
	}
}

// TestWindBlockFeeCarryToCoinbase drives a transfer into the fee pool:
// pos exceeds the tx's outputs, so the sat lands in the coinbase. Also
// exercises the fee-base accumulation guard (inputValue > outTotal).
func TestWindBlockFeeCarryToCoinbase(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	parentA, parentATxid := ordTestParent(1, 10000)
	db.parents[parentATxid] = parentA
	_, parentPTxid := ordTestParent(2, 5000)
	spentOP := tbcd.NewOutpoint(parentPTxid, 0)
	inscID := makeInscriptionID(&parentPTxid, 0)
	ordTestTrackedOutpoint(db, spentOP, inscID, 3, 5000)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentATxid, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentPTxid, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(4000, []byte{txscript.OP_TRUE}))

	// Transfer at input 1: pos = 10000 + 3 = 10003 > outTotal 4000 →
	// fee pool. In the coinbase (subsidy 6.25e8 at height 800000):
	// posCB = 625000000 + (10003 - 4000) = 625006003.
	b := ordTestBlock(800000, 700000000, tx)
	cbTxid := b.Transactions()[0].MsgTx().TxHash()
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	cb := cache.Map()[tbcd.NewOutpoint(cbTxid, 0)]
	if cb == nil {
		t.Fatal("no cache entry at coinbase outpoint")
	}
	v, ok := cb.Inscriptions[625006003]
	if !ok || v == nil {
		t.Fatalf("fee-carried inscription not in coinbase at 625006003: %v", cb.Inscriptions)
	}
	if v[36] != srcKindFee {
		t.Fatalf("srcKind: got %#x, want srcKindFee", v[36])
	}
	if pv, ok := cb.Predecessors[625006003]; !ok || pv == nil {
		t.Fatal("predecessor not written for fee-carried transfer")
	}
	if !cb.BigOSet || len(cb.BigO) != 40 {
		t.Fatal("'O' not written at coinbase outpoint")
	}
}

// TestWindBlockManyInputsClampsSlots puts a reveal on input 129 of a
// 130-input tx, forcing the parallel fetch semaphore clamp (128) and a
// fetch of inputs 0..128.
func TestWindBlockManyInputsClampsSlots(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	tx := wire.NewMsgTx(wire.TxVersion)
	for i := range 129 {
		parent, parentTxid := ordTestParent(byte(i), 10)
		db.parents[parentTxid] = parent
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentTxid, 0), nil, nil))
	}
	_, parentRTxid := ordTestParent(0xf0, 900)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentRTxid, 0), nil, nil))
	tx.TxIn[129].Witness = buildInscriptionWitness("text/plain", "last input")
	tx.AddTxOut(wire.NewTxOut(2000, []byte{txscript.OP_TRUE}))
	txid := tx.TxHash()

	// The gate guarantees at least two lookups overlap, so the
	// in-flight bound is observable deterministically.
	db.overlapGate = make(chan struct{})
	b := ordTestBlock(800000, 625000000, tx)
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	if got := db.lookups(); got != 129 {
		t.Fatalf("expected 129 lookups (inputs 0..128), got %d", got)
	}
	// The semaphore clamps concurrency at 128; require genuine overlap
	// so the upper bound is meaningful, not vacuously true.
	if db.maxInflight > 128 {
		t.Fatalf("semaphore clamp exceeded: %d concurrent lookups", db.maxInflight)
	}
	if db.maxInflight < 2 {
		t.Fatalf("no concurrency observed (max in-flight %d); clamp untested", db.maxInflight)
	}
	dst := cache.Map()[tbcd.NewOutpoint(txid, 0)]
	if dst == nil {
		t.Fatal("no cache entry at reveal tx outpoint")
	}
	if v, ok := dst.Inscriptions[1290]; !ok || v == nil {
		t.Fatalf("reveal not placed at offset 1290 (129 x 10): %v", dst.Inscriptions)
	}
}

// TestWindBlockMissingParentError makes a required (non-last) input's
// parent unresolvable: the parallel fetch records the error and
// windBlock returns it.
func TestWindBlockMissingParentError(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	_, parentATxid := ordTestParent(1, 10000) // NOT installed: lookup fails
	parentB, parentBTxid := ordTestParent(2, 7000)
	db.parents[parentBTxid] = parentB
	_, parentCTxid := ordTestParent(3, 500)

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentATxid, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentBTxid, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentCTxid, 0), nil, nil))
	tx.TxIn[2].Witness = buildInscriptionWitness("text/plain", "third input")
	tx.AddTxOut(wire.NewTxOut(20000, []byte{txscript.OP_TRUE}))

	b := ordTestBlock(800000, 625000000, tx)
	err := oi.windBlock(t.Context(), 800000, b.Hash(), b, NewOrdinalCache(1000, 0))
	if err == nil {
		t.Fatal("expected error for missing parent tx")
	}
	if !strings.Contains(err.Error(), "input value") {
		t.Fatalf("wrong error: %v", err)
	}
}

// TestOrdinalCacheByteBudget verifies the byte dimension of the flush
// decision and that Clear drops the backing map instead of retaining
// high-water buckets.
func TestOrdinalCacheByteBudget(t *testing.T) {
	const budget = 64 * 1024
	c := NewOrdinalCache(1_000_000, budget) // count cap far away

	op := tbcd.NewOutpoint(chainhash.Hash{0x01}, 0)
	big := make([]byte, budget/2)
	c.PutInscription(op, 0, big)
	if _, _, pct := c.Stats(); pct < 50 || pct > 60 {
		t.Fatalf("byte pct after half-budget value: %d", pct)
	}
	c.PutInscription(op, 1, big)
	if _, _, pct := c.Stats(); pct < 100 {
		t.Fatalf("byte pct must reach 100 at budget: %d", pct)
	}

	// Count dimension still wins when it is the fuller one.
	c2 := NewOrdinalCache(10, 0)
	for i := range 11 {
		c2.PutAux(op, tbcd.OrdinalKey{byte(i)}, tbcd.OrdinalValue{0x01})
	}
	if _, _, pct := c2.Stats(); pct < 100 {
		t.Fatalf("count pct must reach 100: %d", pct)
	}

	// Clear resets both dimensions and replaces the map.
	before := c.Map()
	c.Clear()
	if len(c.Map()) != 0 || c.Len() != 0 {
		t.Fatal("Clear did not reset")
	}
	if _, _, pct := c.Stats(); pct != 0 {
		t.Fatalf("pct after Clear: %d", pct)
	}
	// The map object must be a fresh allocation, not the cleared old
	// one (bucket ratchet prevention). Insert into the old reference
	// and confirm the cache does not observe it.
	rawGetEntry(before, tbcd.NewOutpoint(chainhash.Hash{0x02}, 1))
	if len(c.Map()) != 0 {
		t.Fatal("Clear retained the old backing map")
	}
}

// TestOrdinalCacheClearReleasesMemory asserts the anti-ratchet claim
// with the runtime's own accounting: filling the cache with hundreds
// of MB of values plus bucket-heavy small entries, then Clear()ing,
// must return the heap to (near) its baseline. Under the previous
// clear()-based implementation the bucket arrays survived forever.
func TestOrdinalCacheClearReleasesMemory(t *testing.T) {
	var baseline, filled, cleared runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&baseline)

	c := NewOrdinalCache(100_000_000, 0)

	// 256 MiB of value payload across distinct outpoints.
	for i := range 256 {
		var h chainhash.Hash
		h[0], h[1], h[2] = byte(i), byte(i>>8), 0x33
		c.PutInscription(tbcd.NewOutpoint(h, 0), 0, make([]byte, 1<<20))
	}
	// Bucket-heavy load: 500k entries with tiny values. Under the old
	// clear()-based Clear this alone retained ~30-40MB of bucket
	// arrays forever, failing the threshold below.
	for i := range 500_000 {
		var h chainhash.Hash
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		c.PutBigO(tbcd.NewOutpoint(h, 1), nil)
	}
	runtime.ReadMemStats(&filled)
	grew := int64(filled.HeapAlloc) - int64(baseline.HeapAlloc)
	if grew < 200<<20 {
		t.Fatalf("test invalid: heap grew only %d MiB", grew>>20)
	}

	c.Clear() // must reallocate the map; gate fires (window is flush-sized)

	// Bounded retry: background allocation from the shared test binary
	// can inflate a single measurement; a real ratchet stays retained
	// no matter how often we collect.
	var retained int64
	for range 5 {
		runtime.GC()
		runtime.ReadMemStats(&cleared)
		retained = int64(cleared.HeapAlloc) - int64(baseline.HeapAlloc)
		if retained <= 16<<20 {
			break
		}
	}
	if retained > 16<<20 {
		t.Fatalf("Clear retained %d MiB of %d MiB grown; ratchet not fixed",
			retained>>20, grew>>20)
	}
	if len(c.Map()) != 0 || c.Len() != 0 {
		t.Fatal("Clear did not reset the cache")
	}
	runtime.KeepAlive(c)
}

// TestWindBlockByteBudgetSignalsFlush shrinks the byte budget and
// winds a block carrying a real inscription: the content bytes flowing
// into the cache must push Stats() past the flush threshold the
// indexer framework acts on.
func TestWindBlockByteBudgetSignalsFlush(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)
	oi.cacheByteBudget = 512

	_, parentTxid := ordTestParent(1, 600)
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentTxid, 0), nil, nil))
	tx.TxIn[0].Witness = buildInscriptionWitness("text/plain",
		strings.Repeat("x", 400))
	tx.AddTxOut(wire.NewTxOut(600, []byte{txscript.OP_TRUE}))

	b := ordTestBlock(800000, 625000000, tx)
	cache := oi.newCache().(*OrdinalCache) // through the production path
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	// The framework flushes on pct > flushThresholdPct; assert the
	// signal actually crosses it, not merely reaches it.
	if _, _, pct := cache.Stats(); pct <= flushThresholdPct {
		t.Fatalf("inscription bytes did not trip the flush signal: pct=%d", pct)
	}
}

// TestWindBlockFeeBaseWrapGuard proves the fee-pool wrap guard: tx1's
// undercounted inputValue (0, last-input skip) is less than its
// outTotal; without the guard blockFeeBase wraps and tx2's fee-carried
// inscription lands at the wrong coinbase offset (or in the lost
// sentinel). Fails when the guard is removed.
func TestWindBlockFeeBaseWrapGuard(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	// tx1: 1-input transfer landing in its output. fetchCount==0 so
	// inputValue==0 while outTotal==5000: the guarded subtraction
	// would wrap.
	_, parentPTxid := ordTestParent(1, 5000)
	spentP := tbcd.NewOutpoint(parentPTxid, 0)
	inscP := makeInscriptionID(&parentPTxid, 0)
	ordTestTrackedOutpoint(db, spentP, inscP, 0, 5000)
	tx1 := wire.NewMsgTx(wire.TxVersion)
	tx1.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentPTxid, 0), nil, nil))
	tx1.AddTxOut(wire.NewTxOut(5000, []byte{txscript.OP_TRUE}))

	// tx2: transfer at input 1 driven into the fee pool, exactly as in
	// TestWindBlockFeeCarryToCoinbase.
	parentA, parentATxid := ordTestParent(2, 10000)
	db.parents[parentATxid] = parentA
	_, parentQTxid := ordTestParent(3, 5000)
	spentQ := tbcd.NewOutpoint(parentQTxid, 0)
	inscQ := makeInscriptionID(&parentQTxid, 0)
	ordTestTrackedOutpoint(db, spentQ, inscQ, 3, 5000)
	tx2 := wire.NewMsgTx(wire.TxVersion)
	tx2.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentATxid, 0), nil, nil))
	tx2.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentQTxid, 0), nil, nil))
	tx2.AddTxOut(wire.NewTxOut(4000, []byte{txscript.OP_TRUE}))

	// With the guard, tx1 contributes nothing to blockFeeBase and
	// tx2's sat lands at subsidy + (10003-4000) = 625006003. With the
	// wrap, blockFeeBase ~= 2^64-5000 and the sat lands elsewhere.
	b := ordTestBlock(800000, 700000000, tx1, tx2)
	cbTxid := b.Transactions()[0].MsgTx().TxHash()
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	cb := cache.Map()[tbcd.NewOutpoint(cbTxid, 0)]
	if cb == nil {
		t.Fatal("no coinbase cache entry")
	}
	if v, ok := cb.Inscriptions[625006003]; !ok || v == nil {
		t.Fatalf("fee-carried inscription not at 625006003; fee base wrapped? placements: %v",
			maps.Keys(cb.Inscriptions))
	}
}

// TestOrdinalCacheAccountingAccuracy asserts the byte-accounting
// constants track real heap growth within a stated bound for realistic
// entry shapes; the constants gate a memory budget, so a 2x error means
// a 2x budget.
func TestOrdinalCacheAccountingAccuracy(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	c := NewOrdinalCache(10_000_000, 1<<40)
	for i := range 20_000 {
		var h chainhash.Hash
		h[0], h[1], h[2] = byte(i), byte(i>>8), 0x51
		op := tbcd.NewOutpoint(h, uint32(i))
		// Realistic mix: 'o' 53B, 'O' 40B, 'i' aux with a small body.
		c.PutInscription(op, uint64(i), make([]byte, 53))
		c.PutBigO(op, make([]byte, 40))
		c.PutAux(op, tbcd.OrdinalKey{byte(i), byte(i >> 8)}, make([]byte, 400))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)

	measured := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	accounted := int64(c.byteCount)
	if measured <= 0 {
		t.Skip("heap measurement invalid (background collection)")
	}
	ratio := float64(measured) / float64(accounted)
	if ratio < 0.5 || ratio > 2.0 {
		t.Fatalf("accounting off by %.2fx: accounted %d, measured %d",
			ratio, accounted, measured)
	}
	runtime.KeepAlive(c)
}

// TestWindBlockLegacyTxLocFallsBack serves a parent through a legacy
// (pre-v6) tx-index entry: BlockHashByTxId returns a nil TxLoc and
// inputOutputValue must fall back to the lazyBlock scan instead of
// dereferencing the nil location.
func TestWindBlockLegacyTxLocFallsBack(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	parentA, parentATxid := ordTestParent(1, 10000)
	rawBlock := func() []byte {
		blk := ordTestBlock(799999, 625000000, parentA)
		var buf bytes.Buffer
		if err := blk.MsgBlock().Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}()
	db.legacyBlocks[parentATxid] = rawBlock

	_, parentBTxid := ordTestParent(2, 600)
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentATxid, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentBTxid, 0), nil, nil))
	tx.TxIn[1].Witness = buildInscriptionWitness("text/plain", "legacy parent")
	tx.AddTxOut(wire.NewTxOut(20000, []byte{txscript.OP_TRUE}))
	txid := tx.TxHash()

	b := ordTestBlock(800000, 625000000, tx)
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	dst := cache.Map()[tbcd.NewOutpoint(txid, 0)]
	if dst == nil {
		t.Fatal("no cache entry at reveal tx outpoint")
	}
	if v, ok := dst.Inscriptions[10000]; !ok || v == nil {
		t.Fatalf("reveal not positioned via legacy lazyBlock path: %v", dst.Inscriptions)
	}
}

// TestServerWiresVerifyBigO proves the flag travels the production
// path: Config -> Server -> dbOpen -> ordinal indexer.
func TestServerWiresVerifyBigO(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg := NewDefaultConfig()
	cfg.Network = networkLocalnet
	cfg.LevelDBHome = t.TempDir()
	cfg.OrdinalIndex = true
	cfg.OrdinalVerifyBigO = true
	cfg.MempoolEnabled = false
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.dbOpen(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.dbClose(); err != nil {
			t.Logf("db close: %v", err)
		}
	}()
	oi, ok := s.oi.(*ordinalIndexer)
	if !ok {
		t.Fatalf("ordinal indexer type: %T", s.oi)
	}
	if !oi.verifyBigO {
		t.Fatal("OrdinalVerifyBigO did not reach the indexer")
	}
}

// BenchmarkWindBlock pins the wind hot path for the two dominant
// shapes. Expected (dev box): 1-in transfer ~2us/op, 0 lookups;
// sweep ~1ms/op dominated by placement writes.
func BenchmarkWindBlock(b *testing.B) {
	shapes := []struct {
		name string
		blk  func(db *ordStubDB) *btcutil.Block
	}{
		{"transfer1in", func(db *ordStubDB) *btcutil.Block {
			_, parentTxid := ordTestParent(1, 5000)
			op := tbcd.NewOutpoint(parentTxid, 0)
			ordTestTrackedOutpoint(db, op, makeInscriptionID(&parentTxid, 0), 0, 5000)
			tx := wire.NewMsgTx(wire.TxVersion)
			tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentTxid, 0), nil, nil))
			tx.AddTxOut(wire.NewTxOut(5000, []byte{txscript.OP_TRUE}))
			return ordTestBlock(800000, 625000000, tx)
		}},
		{"sweep1000", func(db *ordStubDB) *btcutil.Block {
			tx := wire.NewMsgTx(wire.TxVersion)
			for i := range 1000 {
				parent, parentTxid := ordTestParent(byte(i), 10)
				db.parents[parentTxid] = parent
				op := tbcd.NewOutpoint(parentTxid, 0)
				ordTestTrackedOutpoint(db, op,
					makeInscriptionID(&parentTxid, uint32(i)), 0, 10)
				tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentTxid, 0), nil, nil))
			}
			tx.AddTxOut(wire.NewTxOut(10000, []byte{txscript.OP_TRUE}))
			return ordTestBlock(800000, 625000000, tx)
		}},
	}
	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			db := newOrdStubDB()
			g := geometryParams{db: db, chain: &chaincfg.RegressionNetParams}
			oi := NewOrdinalIndexer(b.Context(), g, OrdinalIndexerConfig{
				CacheLen:             1_000_000,
				Enabled:              true,
				WatermarkGap:         time.Hour,
				OutputValueCacheSize: 65536,
			}).(*ordinalIndexer)
			blk := shape.blk(db)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				cache := NewOrdinalCache(1_000_000, 0)
				if err := oi.windBlock(b.Context(), 800000,
					blk.Hash(), blk, cache); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestReadCacheInfoBeforeWind covers the no-live-cache branch.
func TestReadCacheInfoBeforeWind(t *testing.T) {
	oi := newOrdTestIndexer(t, newOrdStubDB(), false)
	if got := oi.readCacheInfo(); got != "" {
		t.Fatalf("expected empty cache info before wind, got %q", got)
	}
	oi.newCache()
	if got := oi.readCacheInfo(); got == "" {
		t.Fatal("expected byte dimension after newCache")
	}
}

// TestNewServerRejectsZeroOrdinalCache pins the startup validation that
// prevents a divide-by-zero in the cache flush accounting.
func TestNewServerRejectsZeroOrdinalCache(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.Network = networkLocalnet
	cfg.LevelDBHome = t.TempDir()
	cfg.OrdinalIndex = true
	cfg.MaxCachedOrdinals = 0
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("NewServer accepted MaxCachedOrdinals=0 with ordinal index enabled")
	}
}

// TestWindBlockRangedReadErrors drives the three inputOutputValue error
// branches of the ranged-read fast path and the legacy fallback.
func TestWindBlockRangedReadErrors(t *testing.T) {
	build := func(db *ordStubDB) *btcutil.Block {
		parentA, parentATxid := ordTestParent(1, 10000)
		db.parents[parentATxid] = parentA
		_, parentBTxid := ordTestParent(2, 600)
		tx := wire.NewMsgTx(wire.TxVersion)
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentATxid, 0), nil, nil))
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentBTxid, 0), nil, nil))
		tx.TxIn[1].Witness = buildInscriptionWitness("text/plain", "boom")
		tx.AddTxOut(wire.NewTxOut(20000, []byte{txscript.OP_TRUE}))
		return ordTestBlock(800000, 625000000, tx)
	}

	tests := []struct {
		name    string
		mut     func(db *ordStubDB)
		wantErr string
	}{
		{"rangedReadFails", func(db *ordStubDB) { db.badLocLen = true }, "block tx raw"},
		{"deserializeFails", func(db *ordStubDB) { db.badLocOff = true }, "deserialize tx"},
		{"legacyBlockMissing", func(db *ordStubDB) {
			// Legacy tx-index entry (nil TxLoc) whose raw block is
			// absent: the whole-block fallback must surface the error.
			for txid := range db.parents {
				db.legacyBlocks[txid] = nil
				delete(db.parents, txid)
			}
		}, "block raw"},
		{"wrongTxAtLoc", func(db *ordStubDB) { db.wrongTx = true }, "tx loc corrupt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newOrdStubDB()
			oi := newOrdTestIndexer(t, db, false)
			b := build(db)
			tt.mut(db)
			err := oi.windBlock(t.Context(), 800000, b.Hash(), b, NewOrdinalCache(1000, 0))
			if err == nil {
				t.Fatal("expected wind error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want %q in error, got: %v", tt.wantErr, err)
			}
			if tt.name == "legacyBlockMissing" {
				// The typed error must survive the %w chain.
				var bnf database.BlockNotFoundError
				if !errors.As(err, &bnf) {
					t.Fatalf("want BlockNotFoundError, got %v", err)
				}
			}
		})
	}
}

// TestWindBlockZeroLocFallsBack: a non-nil TxLoc with TxLen 0 (corrupt
// or short v6 index value) must route to the whole-block fallback, not
// the ranged read.
func TestWindBlockZeroLocFallsBack(t *testing.T) {
	db := newOrdStubDB()
	oi := newOrdTestIndexer(t, db, false)

	parentA, parentATxid := ordTestParent(1, 10000)
	db.parents[parentATxid] = parentA
	db.zeroLoc = true
	// Serve the raw block for the fallback path.
	blk := ordTestBlock(799999, 625000000, parentA)
	var buf bytes.Buffer
	if err := blk.MsgBlock().Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	db.legacyBlocks[parentATxid] = buf.Bytes()
	// zeroLoc takes precedence over the legacy branch in the stub's
	// BlockHashByTxId only when the parent is still present; keep it.
	delete(db.legacyBlocks, parentATxid)
	db.rawBlocks = map[chainhash.Hash][]byte{parentATxid: buf.Bytes()}

	_, parentBTxid := ordTestParent(2, 600)
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentATxid, 0), nil, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentBTxid, 0), nil, nil))
	tx.TxIn[1].Witness = buildInscriptionWitness("text/plain", "zero loc")
	tx.AddTxOut(wire.NewTxOut(20000, []byte{txscript.OP_TRUE}))
	txid := tx.TxHash()

	b := ordTestBlock(800000, 625000000, tx)
	cache := NewOrdinalCache(1000, 0)
	if err := oi.windBlock(t.Context(), 800000, b.Hash(), b, cache); err != nil {
		t.Fatal(err)
	}
	dst := cache.Map()[tbcd.NewOutpoint(txid, 0)]
	if dst == nil || dst.Inscriptions[10000] == nil {
		t.Fatal("zero-loc entry did not resolve via whole-block fallback")
	}
}
