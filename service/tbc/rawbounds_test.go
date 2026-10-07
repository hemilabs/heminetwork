// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"runtime"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
)

// buildRawTxBomb returns a tiny payload declaring `count` inputs and supplying none of them.
func buildRawTxBomb(count uint64) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version
	_ = wire.WriteVarInt(&b, 0, count)      // input count
	return b.Bytes()
}

// TestRawTxBombIsRefusedBeforeAllocation pins the fix for the unauthenticated remote OOM.
//
// It asserts BOTH halves, because either alone is worthless:
//   - the PREMISE: btcd really does allocate from the declared count before reading bodies, so the
//     bound is guarding something real (if this stops being true, the guard can be reconsidered);
//   - the FIX: the bound refuses the payload, and does so without doing the allocation itself.
func TestRawTxBombIsRefusedBeforeAllocation(t *testing.T) {
	const claimed = 818401 // btcd's maxTxInPerMessage
	bomb := buildRawTxBomb(claimed)

	if len(bomb) > 64 {
		t.Fatalf("the payload must be tiny -- that asymmetry IS the vulnerability (got %d bytes)", len(bomb))
	}

	// PREMISE: measure what an unguarded decode costs for this payload.
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var victim wire.MsgTx
	err := victim.Deserialize(bytes.NewReader(bomb))
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("the bomb must not be a decodable transaction")
	}
	alloc := after.TotalAlloc - before.TotalAlloc
	if cap(victim.TxIn) != claimed {
		t.Fatalf("premise failed: btcd allocated capacity %d, expected %d -- if btcd stopped "+
			"pre-allocating from the declared count, re-derive whether this guard is still needed",
			cap(victim.TxIn), claimed)
	}
	t.Logf("PREMISE: a %d-byte payload drove %d bytes of allocation (%.0fx) through an unguarded decode",
		len(bomb), alloc, float64(alloc)/float64(len(bomb)))

	// FIX: the bound refuses it.
	if err := boundRawTxCounts(bomb); err == nil {
		t.Fatalf("boundRawTxCounts ACCEPTED a %d-byte payload declaring %d inputs. That is the "+
			"unauthenticated remote OOM: ~50 such messages hold ~4 GB live, on a listener that "+
			"defaults to localhost:8082 with no authentication and no recover().", len(bomb), claimed)
	}
}

// TestRawTxBoundAcceptsRealTransactions is the false-reject half. Refusing a legitimate embedder
// write is worse than the DoS, so the bound must never fire on a well-formed transaction.
func TestRawTxBoundAcceptsRealTransactions(t *testing.T) {
	blk := realBlock(t, realBlockA)
	checked := 0
	for i, tx := range blk.MsgBlock().Transactions {
		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err != nil {
			t.Fatalf("tx %d: serialize: %v", i, err)
		}
		if err := boundRawTxCounts(buf.Bytes()); err != nil {
			t.Fatalf("FALSE REJECT: real testnet3 transaction %d (%d bytes, %d inputs) was refused: %v",
				i, buf.Len(), len(tx.TxIn), err)
		}
		checked++
	}
	if checked < 1000 {
		t.Fatalf("only %d transactions checked; the control is too weak to prove no false rejects", checked)
	}
	t.Logf("no false rejects across %d real testnet3 transactions", checked)
}

// TestRawBlockBoundAcceptsRealBlocksAndRefusesBombs covers the block handler's half.
func TestRawBlockBoundAcceptsRealBlocksAndRefusesBombs(t *testing.T) {
	blk := realBlock(t, realBlockA)
	var buf bytes.Buffer
	if err := blk.MsgBlock().Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := boundRawBlockCounts(buf.Bytes()); err != nil {
		t.Fatalf("FALSE REJECT: a real testnet3 block (%d bytes, %d txs) was refused: %v",
			buf.Len(), len(blk.MsgBlock().Transactions), err)
	}
	t.Logf("real block accepted: %d bytes, %d transactions", buf.Len(), len(blk.MsgBlock().Transactions))

	// A header plus a transaction-count varint claiming more than the bytes can hold.
	var bomb bytes.Buffer
	bomb.Write(make([]byte, wire.MaxBlockHeaderPayload))
	_ = wire.WriteVarInt(&bomb, 0, 400000)
	if err := boundRawBlockCounts(bomb.Bytes()); err == nil {
		t.Fatalf("boundRawBlockCounts ACCEPTED a %d-byte payload declaring 400,000 transactions", bomb.Len())
	}

	// A one-transaction block whose single transaction declares 818,401 inputs -- the shape the
	// transaction-count bound alone does NOT catch, which is why the first tx is bounded too.
	var nested bytes.Buffer
	nested.Write(make([]byte, wire.MaxBlockHeaderPayload))
	_ = wire.WriteVarInt(&nested, 0, 1)
	nested.Write(buildRawTxBomb(818401))
	if err := boundRawBlockCounts(nested.Bytes()); err == nil {
		t.Fatalf("boundRawBlockCounts ACCEPTED a %d-byte block whose single transaction declares "+
			"818,401 inputs -- the transaction-count bound alone does not see this", nested.Len())
	}
}

// buildOutputBomb is O1/O2's 12-byte vector: segwit marker, input count ZERO, then a huge output
// count sitting at a FIXED offset 7. The prefix-bound version of rawbounds.go read the zero as the
// input count, was satisfied, and let btcd allocate 149 MB.
func buildOutputBomb(count uint64) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version
	b.WriteByte(0x00)                       // segwit marker
	b.WriteByte(0x01)                       // flag
	_ = wire.WriteVarInt(&b, 0, 0)          // input count 0
	_ = wire.WriteVarInt(&b, 0, count)      // OUTPUT count
	return b.Bytes()
}

// TestRawBoundsClosesEveryMeasuredVector pins the three bombs the prefix-bound version admitted.
// Each asserts the PREMISE (btcd really over-allocates) before asserting the fix.
func TestRawBoundsClosesEveryMeasuredVector(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		bound   func([]byte) error
	}{
		{"tx output count (12-byte / 149MB vector)", buildOutputBomb(3728271), boundRawTxCounts},
		{"tx input count (9-byte / 89MB vector)", buildRawTxBomb(818401), boundRawTxCounts},
		{
			name:  "block second transaction input bomb (150-byte / 85MB vector)",
			bound: boundRawBlockCounts,
			payload: func() []byte {
				var b bytes.Buffer
				b.Write(make([]byte, wire.MaxBlockHeaderPayload))
				_ = wire.WriteVarInt(&b, 0, 2) // two transactions
				// tx1: a minimal, entirely valid 1-in/1-out transaction.
				t1 := wire.NewMsgTx(1)
				t1.AddTxIn(&wire.TxIn{Sequence: 0xffffffff})
				t1.AddTxOut(&wire.TxOut{Value: 1})
				_ = t1.SerializeNoWitness(&b)
				// tx2: the amplifier, past the first transaction the old shortcut bounded.
				b.Write(buildRawTxBomb(818401))
				return b.Bytes()
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.payload) > 256 {
				t.Fatalf("the payload must be tiny -- that asymmetry IS the vulnerability (got %d)", len(tc.payload))
			}
			if err := tc.bound(tc.payload); err == nil {
				t.Fatalf("ACCEPTED a %d-byte payload. This is the unauthenticated remote OOM: "+
					"handleWebsocketRead spawns a goroutine per message without waiting, and there "+
					"is no recover() in service/tbc or api/.", len(tc.payload))
			}
		})
	}
}

// TestRawBlockBoundAcceptsZeroTransactionBlocks is the false-reject regression O2 found: the
// prefix-bound version applied the transaction bound to bytes AFTER a zero transaction count --
// bytes wire never reads -- producing 57 false rejects in a differential against btcd. op-geth's
// sibling guard documents this shape as DELIBERATELY allowed (a header-only relay).
func TestRawBlockBoundAcceptsZeroTransactionBlocks(t *testing.T) {
	var b bytes.Buffer
	b.Write(make([]byte, wire.MaxBlockHeaderPayload))
	b.WriteByte(0x00)                          // transaction count 0
	b.Write([]byte{0xfd, 0xff, 0x00, 1, 2, 3}) // trailing bytes wire never reads
	if err := boundRawBlockCounts(b.Bytes()); err != nil {
		t.Fatalf("FALSE REJECT on a zero-transaction block: %v.\nUnder Holocene a node that refuses "+
			"a body the fleet stored does not halt -- it permanently disagrees. op-geth's sibling "+
			"allows this shape explicitly.", err)
	}
}

// TestRawTxSlabOverrunIsRefused pins P1's finding: btcd borrows ONE shared scriptSlab and consumes it
// CUMULATIVELY, so scripts that are individually legal can collectively overrun it and PANIC. The
// block path carried op-geth's size cap; the transaction path did not.
//
// It asserts the PREMISE (btcd really panics) before asserting the fix, because a test that only
// checks the rejection would still pass if btcd stopped panicking and the cap became pointless.
func TestRawTxSlabOverrunIsRefused(t *testing.T) {
	// Two inputs, each declaring a 3,000,000-byte signature script and SUPPLYING every byte. Each is
	// under btcd's 4,000,000 per-script ceiling; together they exceed the 4,194,304-byte slab.
	const scriptLen = 3000000
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version
	_ = wire.WriteVarInt(&b, 0, 2)          // two inputs
	for i := 0; i < 2; i++ {
		b.Write(make([]byte, 36)) // prevout
		_ = wire.WriteVarInt(&b, 0, scriptLen)
		b.Write(make([]byte, scriptLen))
		b.Write([]byte{0xff, 0xff, 0xff, 0xff}) // sequence
	}
	_ = wire.WriteVarInt(&b, 0, 0)          // zero outputs
	b.Write([]byte{0x00, 0x00, 0x00, 0x00}) // lock time
	payload := b.Bytes()

	if len(payload) <= wire.MaxBlockPayload {
		t.Fatalf("fixture must exceed MaxBlockPayload to exercise the cap (got %d)", len(payload))
	}

	// PREMISE: btcd panics on this, it does not merely error.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("PREMISE FAILED: btcd did not panic on a %d-byte two-script transaction. If "+
					"btcd now bounds readScriptBuf, re-derive whether the size cap is still needed "+
					"-- do not simply delete it.", len(payload))
			} else {
				t.Logf("PREMISE: btcd panics as expected: %v", r)
			}
		}()
		var victim wire.MsgTx
		_ = victim.Deserialize(bytes.NewReader(payload))
	}()

	// FIX: the cap refuses it before any decode.
	if err := boundRawTxCounts(payload); err == nil {
		t.Fatalf("boundRawTxCounts ACCEPTED a %d-byte transaction that panics btcd's script slab. "+
			"A panic on the go s.handleRequest goroutine has no recover() and is process death.",
			len(payload))
	}
}

// TestRawBoundsArithmeticIsDivideNotMultiply is the mutation test that did NOT travel with the port.
//
// op-geth's scanner was mutation-hardened in its own test files; porting the implementation left that
// hardening behind, and a faithful `count * minSize` rewrite passed every test this file had. The
// discriminating value needs a count large enough that the product WRAPS uint64 -- which requires the
// 8-byte (0xff) varint encoding, a shape absent from all 314 real testnet3 blocks, so only an attacker
// produces it.
func TestRawBoundsArithmeticIsDivideNotMultiply(t *testing.T) {
	// 2^64/41 rounded up: count*41 wraps to a small number, so a multiplying guard would compute a
	// tiny requirement and ACCEPT. Dividing cannot overflow and rejects.
	// RUNTIME var, not a const: Go rejects `const * 41` at COMPILE time as a constant overflow, so a
	// const fixture cannot express the very wrap it exists to demonstrate. The same trap is documented
	// in core/vm's underflow test on the op-geth side.
	// ceil(2^64 / 41): count*41 = 2^64 + 25, so it wraps to exactly 25 -- a requirement any payload
	// satisfies. Derived, not guessed; an earlier value wrapped to ~3.26e15 and did not discriminate.
	wrapCount := uint64(449920587163647601)
	wrapped := wrapCount * uint64(minRawTxInPayload)
	if wrapped > 1<<20 {
		t.Fatalf("fixture no longer wraps: count*%d = %d; pick a count nearer 2^64/%d",
			minRawTxInPayload, wrapped, minRawTxInPayload)
	}
	t.Logf("wrap check: %d * %d overflows uint64 to %d, which a multiplying guard would treat as the requirement",
		wrapCount, minRawTxInPayload, wrapped)

	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00, 0x00, 0x00})
	_ = wire.WriteVarInt(&b, 0, wrapCount) // 0xff-encoded
	// EXACTLY `wrapped` trailing bytes, and this is what makes the test discriminate.
	//
	// With no trailing bytes remaining()==0, so even the wrapped product (25) exceeds it and BOTH
	// forms reject -- the test passed against the multiply mutant for the wrong reason. Measured: it
	// did, with the MUTANT_ACTIVE marker confirming the mutation was compiled in.
	//
	// With remaining()==25: MULTIPLY computes 25 > 25 == false and ACCEPTS; DIVIDE computes
	// count > 25/41 == 0 and REJECTS. That is the only window in which the two forms disagree.
	b.Write(make([]byte, wrapped))
	payload := b.Bytes()

	if err := boundRawTxCounts(payload); err == nil {
		t.Fatalf("boundRawTxCounts ACCEPTED a %d-byte payload declaring %d inputs. The bound is "+
			"MULTIPLYING: count*minRawTxInPayload wrapped uint64 to %d, which the payload trivially "+
			"satisfies. Divide the available length instead.", len(payload), wrapCount, wrapped)
	}
}

// TestRawBoundsWitnessItemCountIsBounded covers the witness-item bound, which had no regression test
// at all after the port -- the shape is only reachable through the segwit marker.
func TestRawBoundsWitnessItemCountIsBounded(t *testing.T) {
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version
	b.WriteByte(0x00)                       // segwit marker
	b.WriteByte(0x01)                       // flag
	_ = wire.WriteVarInt(&b, 0, 1)          // one input
	b.Write(make([]byte, 36))               // prevout
	_ = wire.WriteVarInt(&b, 0, 0)          // empty sigScript
	b.Write([]byte{0xff, 0xff, 0xff, 0xff}) // sequence
	_ = wire.WriteVarInt(&b, 0, 0)          // zero outputs
	_ = wire.WriteVarInt(&b, 0, 4000000)    // witness items for input 0 -- the bomb
	payload := b.Bytes()

	if len(payload) > 100 {
		t.Fatalf("the payload must be tiny -- that asymmetry IS the vulnerability (got %d)", len(payload))
	}
	if err := boundRawTxCounts(payload); err == nil {
		t.Fatalf("boundRawTxCounts ACCEPTED a %d-byte payload declaring 4,000,000 witness items on "+
			"one input. wire allocates a [][]byte of that count before reading any item.", len(payload))
	}
}

// TestDeterministicTimeSourceIsActuallyDeterministic asserts the BEHAVIOUR that op-geth's
// --tbc.blocksanity default depends on, in the repo where the behaviour lives.
//
// WHY IT IS HERE AND NOT IN op-geth. op-geth defaults --tbc.blocksanity TRUE, and that is only safe
// because handleBlock neutralises CheckBlockSanity's 2-hour wall-clock horizon. op-geth tried to assert
// that across the repo boundary by reading this package's source: first grepping for two strings (which
// turned out to live in different functions, so the one regression it existed to catch passed), then
// parsing the CheckBlockSanity call and checking its arguments.
//
// Both match a NAME, never a BEHAVIOUR. A mutation that keeps the type called deterministicTimeSource
// and changes AdjustedTime() to `return time.Now()` destroys the entire safety premise and leaves every
// cross-repo check green. Only a test in THIS package can see that, because only here is the method
// callable.
//
// So: if you change deterministicTimeSource, this test tells you what depends on it. If the horizon
// ever needs to become real, set TBCBlockSanity's Value back to false in op-geth in the same change.
func TestDeterministicTimeSourceIsActuallyDeterministic(t *testing.T) {
	got := deterministicTimeSource{}.AdjustedTime()

	// A Bitcoin header timestamp is a uint32, so it cannot exceed 2106. CheckBlockHeaderSanity rejects
	// a header more than 2h beyond AdjustedTime(), so the horizon is unreachable iff AdjustedTime()
	// exceeds any representable header time by a wide margin.
	maxHeaderTime := time.Unix(int64(^uint32(0)), 0) // 2106-02-07
	if !got.After(maxHeaderTime.Add(2 * time.Hour)) {
		t.Fatalf("deterministicTimeSource.AdjustedTime() returned %v, which is not beyond the maximum "+
			"representable Bitcoin header timestamp (%v) plus the 2h horizon.\n\n"+
			"CheckBlockSanity's ErrTimeTooNew rule is therefore LIVE, and two honest nodes with skewed "+
			"clocks will reach different verdicts on identical bytes. op-geth defaults "+
			"--tbc.blocksanity TRUE on the strength of this method being unreachable; if that is "+
			"changing deliberately, set that flag's Value back to false in the same change.",
			got, maxHeaderTime)
	}

	// It must also be CONSTANT: two calls a moment apart must agree, or it is a clock by another name.
	if second := (deterministicTimeSource{}).AdjustedTime(); !second.Equal(got) {
		t.Fatalf("AdjustedTime() is not constant: %v then %v. A varying source reintroduces exactly the "+
			"host-clock dependence this type exists to remove.", got, second)
	}

	// And the sibling methods must stay inert.
	if off := (deterministicTimeSource{}).Offset(); off != 0 {
		t.Fatalf("Offset() returned %v, want 0", off)
	}
}
