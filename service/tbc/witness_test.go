// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/api/tbcapi"
)

// witnessTx builds a transaction with witness on the MIDDLE input only.
//
// The middle position is deliberate: with witness on the first or last input, truncating the
// detection loop to TxIn[:1] or TxIn[len-1:] still finds it and the strip still runs, so those
// truncations survive. An undetected transaction is stored WITH its witness, which is the whole
// failure this guards against.
func witnessTx(tag byte, withWitness bool) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.LockTime = uint32(tag) << 8
	for i := 0; i < 3; i++ {
		in := &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{tag, byte(i)}, Index: uint32(i)},
			SignatureScript:  []byte{0x51},
			Sequence:         0xfffffffe,
		}
		if withWitness && i == 1 {
			in.Witness = wire.TxWitness{{0xaa, tag}, {0xbb}}
		}
		tx.AddTxIn(in)
	}
	tx.AddTxOut(&wire.TxOut{Value: int64(tag), PkScript: []byte{0x6a}})
	return tx
}

func witnessBearing(blk *wire.MsgBlock) int {
	n := 0
	for _, tx := range blk.Transactions {
		if tx.HasWitness() {
			n++
		}
	}
	return n
}

// TestStripBlockWitnessClearsEveryTransaction pins the count and the completeness of both loops.
func TestStripBlockWitnessClearsEveryTransaction(t *testing.T) {
	blk := &wire.MsgBlock{Transactions: []*wire.MsgTx{
		witnessTx(0x01, true), witnessTx(0x02, false), witnessTx(0x03, true),
	}}
	if got := witnessBearing(blk); got != 2 {
		t.Fatalf("fixture must have 2 witness-bearing txs, has %v", got)
	}

	if n := StripBlockWitness(blk); n != 2 {
		t.Fatalf("StripBlockWitness must count TRANSACTIONS that carried witness: got %v, want 2 "+
			"(1 would mean per-block counting, 2 inputs-worth would mean per-input)", n)
	}
	if got := witnessBearing(blk); got != 0 {
		t.Fatalf("%v transactions still carry witness after the strip", got)
	}
	// Non-witness content must survive: the body still has to match its header's merkle root.
	if blk.Transactions[1].TxIn[0].SignatureScript[0] != 0x51 ||
		blk.Transactions[1].TxOut[0].Value != 0x02 {
		t.Fatal("strip altered non-witness content")
	}
}

// TestStripBlockWitnessPreservesTxidsAndMerkleRoot is the property that makes stripping safe on every
// write path: witness is not committed by the txid-based merkle root, so a stripped body still
// matches the header it arrived under and still passes every check that accepted it.
func TestStripBlockWitnessPreservesTxidsAndMerkleRoot(t *testing.T) {
	blk := &wire.MsgBlock{Transactions: []*wire.MsgTx{
		witnessTx(0x11, true), witnessTx(0x12, true), witnessTx(0x13, false),
	}}
	before := make([]chainhash.Hash, len(blk.Transactions))
	for i, tx := range blk.Transactions {
		before[i] = tx.TxHash()
	}
	rootBefore := blockchain.CalcMerkleRoot(btcutil.NewBlock(blk).Transactions(), false)

	StripBlockWitness(blk)

	for i, tx := range blk.Transactions {
		if tx.TxHash() != before[i] {
			t.Fatalf("tx %v txid changed under the strip; the body would no longer match its header", i)
		}
	}
	if got := blockchain.CalcMerkleRoot(btcutil.NewBlock(blk).Transactions(), false); got != rootBefore {
		t.Fatal("merkle root changed under the strip")
	}
}

// TestStripBlockWitnessNonNilEmptyIsNotCounted pins the detection predicate.
//
// btcd decodes a witness field as make([][]byte, count), so under BIP144 EVERY input of a
// witness-serialized body has a non-nil slice -- including inputs carrying no witness bytes. Testing
// `in.Witness != nil` instead of `len(in.Witness) != 0` would report ordinary honest bodies as
// stripped and log an accusation against the peer that sent them.
func TestStripBlockWitnessNonNilEmptyIsNotCounted(t *testing.T) {
	tx := witnessTx(0x21, false)
	for _, in := range tx.TxIn {
		in.Witness = wire.TxWitness{} // non-nil, length 0
	}
	blk := &wire.MsgBlock{Transactions: []*wire.MsgTx{tx}}

	if n := StripBlockWitness(blk); n != 0 {
		t.Fatalf("non-nil EMPTY witness carries no witness bytes and must not be counted, got %v", n)
	}
}

// TestStripBlockWitnessSingleEmptyItemIsStripped is the other side of that predicate: a witness of
// LENGTH 1 whose single item is zero bytes IS witness -- HasWitness reports true and SerializeSize
// includes the framing -- so it must be stripped.
func TestStripBlockWitnessSingleEmptyItemIsStripped(t *testing.T) {
	tx := witnessTx(0x22, false)
	tx.TxIn[1].Witness = wire.TxWitness{[]byte{}}
	if !tx.HasWitness() {
		t.Fatal("precondition: btcd must consider this witness-bearing")
	}
	blk := &wire.MsgBlock{Transactions: []*wire.MsgTx{tx}}

	if n := StripBlockWitness(blk); n != 1 {
		t.Fatalf("a single zero-length witness item must be stripped, got %v", n)
	}
	if tx.HasWitness() {
		t.Fatal("witness survived the strip")
	}
}

// TestStripBlockWitnessNilSafe: defensive shapes must not panic.
func TestStripBlockWitnessNilSafe(t *testing.T) {
	if StripBlockWitness(nil) != 0 {
		t.Fatal("nil block")
	}
	if StripBlockWitness(&wire.MsgBlock{}) != 0 {
		t.Fatal("empty block")
	}
	// A nil at index >= 1, BEHIND a witness-bearing transaction. Every nil-transaction fixture used
	// to sit at index 0, so narrowing the guard to `i == 0 && tx == nil` survived the whole package.
	// The return value pins that the real transaction was still stripped past the nil.
	if n := StripBlockWitness(&wire.MsgBlock{Transactions: []*wire.MsgTx{
		{TxIn: []*wire.TxIn{{Witness: wire.TxWitness{{0x01}}}}},
		nil,
	}}); n != 1 {
		t.Fatalf("a nil transaction at index 1 must be skipped and the witness-bearing one at index "+
			"0 still stripped; got %v stripped", n)
	}
	if StripBlockWitness(&wire.MsgBlock{Transactions: []*wire.MsgTx{nil}}) != 0 {
		t.Fatal("nil transaction")
	}
	// A nil *TxIn, which is the case this function's own guard exists for and which the three above
	// do not reach. Measured: deleting that guard survived the whole package, because every fixture
	// here stopped at a nil TRANSACTION. op-geth's mirror of this function covers it; heminetwork's
	// did not, so the two repos' coverage had diverged even where the code agreed.
	//
	// The witness-bearing input is required: without one the strip returns before the loop that
	// dereferences, and the fixture proves nothing.
	nilIn := &wire.MsgBlock{Transactions: []*wire.MsgTx{{
		TxIn: []*wire.TxIn{nil, {Witness: wire.TxWitness{[]byte{0x01}}}},
	}}}
	if got := StripBlockWitness(nilIn); got != 1 {
		t.Fatalf("nil *TxIn beside a witness-bearing input: stripped %d, want 1", got)
	}
	if len(nilIn.Transactions[0].TxIn[1].Witness) != 0 {
		t.Fatal("nil *TxIn: the witness-bearing input was not stripped")
	}
	// Nil at index >= 1 as well, so a guard that only inspects TxIn[0] fails.
	nilLate := &wire.MsgBlock{Transactions: []*wire.MsgTx{{
		TxIn: []*wire.TxIn{{Witness: wire.TxWitness{[]byte{0x02}}}, nil},
	}}}
	if got := StripBlockWitness(nilLate); got != 1 {
		t.Fatalf("nil *TxIn at index 1: stripped %d, want 1", got)
	}
}

// TestEveryBlockWriteStripsWitness is a LINT-GRADE guard, and deliberately labelled as one.
//
// StripBlockWitness is only as good as its call sites, and the store has FIVE of them. Adding a
// sixth -- or removing a strip from an existing one -- compiles cleanly and every behavioural test
// stays green while unrequested witness becomes permanently stored again (BlocksDB is
// first-writer-wins with no delete).
//
// So this asserts the set of db.BlockInsert call sites directly. The genesis insert is exempt: its
// block comes from chainParams, not from the network.
func TestEveryBlockWriteStripsWitness(t *testing.T) {
	// function name -> must it strip first?
	want := map[string]bool{
		"BlockInsert":                 true,  // embedder path (op-geth's L2 gossip)
		"handleBlock":                 true,  // Bitcoin P2P
		"handleBlockInsertRequest":    true,  // tbcapi
		"handleBlockInsertRawRequest": true,  // tbcapi
		"insertGenesis":               false, // from chainParams, not the network
	}

	// Walk EVERY non-test file in the package, not a hardcoded list. An earlier version parsed only
	// tbc.go and rpc.go; a new write path in crawler.go, mempool.go, or any file added later was
	// invisible to it, and the "not in this guard's list" arm below -- the whole point of the guard --
	// could never fire for one. Demonstrated: a db.BlockInsert caller added to crawler.go passed.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			files = append(files, n)
		}
	}
	if len(files) < 2 {
		t.Fatalf("found only %d source files in the package; this guard is not looking at the code "+
			"it thinks it is (wrong working directory?)", len(files))
	}

	found := map[string]bool{}
	fset := token.NewFileSet()
	for _, file := range files {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %v: %v", file, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			var inserts, strips int
			firstInsert, firstStrip := -1, -1
			strippedNil := false
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				off := fset.Position(call.Pos()).Offset
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if fun.Sel.Name == "BlockInsert" {
						// Match any receiver, not just the literal `s.db`. The old version required
						// fun.X to be a SelectorExpr whose Sel was `db`, so the one-line evasion
						// `db := s.db; db.BlockInsert(...)` made inserts == 0 and the function was
						// skipped entirely.
						inserts++
						if firstInsert < 0 || off < firstInsert {
							firstInsert = off
						}
					}
				case *ast.Ident:
					if fun.Name == "StripBlockWitness" {
						strips++
						if firstStrip < 0 || off < firstStrip {
							firstStrip = off
						}
						// StripBlockWitness(nil) satisfies a presence check while stripping nothing.
						if len(call.Args) == 1 {
							if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "nil" {
								strippedNil = true
							}
						}
					}
				}
				return true
			})
			if inserts == 0 {
				continue
			}
			name := fn.Name.Name
			found[name] = true
			mustStrip, known := want[name]
			if !known {
				t.Errorf("%v writes to the block store but is not in this guard's list. Every write "+
					"path must strip witness before storing (see StripBlockWitness) unless the block "+
					"is trusted, e.g. from chainParams. Add it, with a reason.", name)
				continue
			}
			if mustStrip && strips == 0 {
				t.Errorf("%v calls db.BlockInsert without calling StripBlockWitness first. "+
					"Unrequested witness stored here is PERMANENT -- BlocksDB is first-writer-wins "+
					"with no delete -- and differs between nodes by arrival order.", name)
			}
			// The word "first" in the message above used to be unenforced: this guard counted calls
			// and nothing else, so moving the strip BELOW the write left it green while the witness
			// was stored permanently. That mutant is the exact bug the guard exists to catch.
			if mustStrip && strips > 0 && firstStrip > firstInsert {
				t.Errorf("%v calls StripBlockWitness AFTER db.BlockInsert. The stored body is what "+
					"gets written, so a strip that runs afterwards changes nothing and the witness "+
					"is persisted permanently. Move the strip above the write.", name)
			}
			if mustStrip && strippedNil {
				t.Errorf("%v calls StripBlockWitness(nil), which strips nothing and exists only to "+
					"satisfy this guard. Pass the block being written.", name)
			}
			if !mustStrip && strips != 0 {
				t.Errorf("%v is listed as not needing a strip but calls StripBlockWitness; "+
					"re-derive this guard.", name)
			}
		}
	}
	for name, mustStrip := range want {
		if mustStrip && !found[name] {
			t.Errorf("expected %v to write to the block store, but no db.BlockInsert call was found "+
				"in it. If the write moved, this guard has stopped guarding it.", name)
		}
	}
}

// TestMaxAddressLengthBoundsTheDecoder covers the O(n^2) base58 bound on the two address-taking
// Server methods.
//
// These are reached from the tbcapi websocket, which defaults to localhost:8082, is unauthenticated,
// has no rate limiting and spawns a goroutine per message -- so an unbounded address here is a
// local CPU-exhaustion DoS on a consensus node, not merely a slow query.
func TestMaxAddressLengthBoundsTheDecoder(t *testing.T) {
	s := &Server{cfg: &Config{}, chainParams: &chaincfg.RegressionNetParams}

	long := strings.Repeat("z", MaxAddressLength+1)
	if _, err := s.BalanceByAddress(t.Context(), long); err == nil {
		t.Fatal("BalanceByAddress accepted an over-length address")
	} else if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("BalanceByAddress rejected for the wrong reason: %v", err)
	}
	if _, err := s.UtxosByAddress(t.Context(), false, long, 0, 10); err == nil {
		t.Fatal("UtxosByAddress accepted an over-length address")
	} else if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("UtxosByAddress rejected for the wrong reason: %v", err)
	}
}

// TestMaxAddressLengthCannotRejectARealAddress is the false-reject control: the bound must sit far
// above every address form that exists, or it breaks ordinary queries.
func TestMaxAddressLengthCannotRejectARealAddress(t *testing.T) {
	for _, a := range []string{
		"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",                             // P2PKH
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",                             // P2SH
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",                     // P2WPKH
		"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", // P2WSH
		"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", // P2TR
		"mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",                             // testnet P2PKH
		strings.Repeat("0", 130),                                         // uncompressed pubkey hex
		strings.Repeat("0", 66),                                          // compressed pubkey hex
	} {
		if len(a) > MaxAddressLength {
			t.Fatalf("%q is %v characters, which the bound would reject", a, len(a))
		}
	}
}

// TestMaxAddressLengthIsAboveTheDecodableBound pins the arithmetic that makes the bound safe: a
// base58 string long enough to be rejected could never have decoded to a 25-byte payload anyway, so
// the bound cannot suppress a decode that would have succeeded.
func TestMaxAddressLengthIsAboveTheDecodableBound(t *testing.T) {
	// The minimising shape for a given length: one non-'1' digit, then all '1's.
	for _, n := range []int{201, 300, 1000} {
		s := "2" + strings.Repeat("1", n-1)
		if got := len(base58.Decode(s)); got <= 25 {
			t.Fatalf("a %v-character base58 string decoded to %v bytes; if 25 were reachable the "+
				"bound could suppress a successful decode", n, got)
		}
	}
	// And a real address decodes to exactly 25.
	if got := len(base58.Decode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")); got != 25 {
		t.Fatalf("expected a real P2PKH address to decode to 25 bytes, got %v", got)
	}
}

// TestBlockInsertRejectsNilElements pins the fix for a one-message remote process kill.
//
// tbcapi's BlockInsert takes a *wire.MsgBlock straight out of json.Unmarshal, so a caller can send
// shapes btcd's wire decoder can never produce: a null transaction, input, or output. btcd
// dereferences all three without a nil check (MsgBlock.SerializeSizeStripped, reached from
// blockchain.CheckBlockSanity, gets there first), and the handler runs in a bare goroutine with no
// recover, so a nil element terminated the process.
//
// The header only has to clear the difficulty test to reach the transaction walk -- free on
// localnet, where RegressionNetParams accepts nonce 0. the tbcapi listener that op-geth's EMBEDDED TBC node starts defaults to localhost:8082
// with no authentication.
//
// Note what this test does NOT rely on: StripBlockWitness's own nil guards. Those stop the strip
// from panicking and nothing more. An earlier version of this change claimed they made the handler
// safe; they did not, and the panic simply moved three lines down.
func TestBlockInsertRejectsNilElements(t *testing.T) {
	hdr := wire.BlockHeader{
		Version:   1,
		Timestamp: time.Unix(1700000000, 0),
		Bits:      0x207fffff, // regtest difficulty 1; nonce 0 clears it
	}
	good := &wire.TxOut{Value: 1, PkScript: []byte{0x51}}

	for _, tc := range []struct {
		name string
		blk  *wire.MsgBlock
		want string
	}{
		{
			name: "null transaction",
			blk:  &wire.MsgBlock{Header: hdr, Transactions: []*wire.MsgTx{nil}},
			want: "transaction 0 is null",
		},
		{
			// Index >= 1, behind a valid transaction. Without this a guard that inspects only
			// Transactions[0] passes -- measured, that mutant survived the whole package.
			name: "null transaction at index 1",
			blk: &wire.MsgBlock{Header: hdr, Transactions: []*wire.MsgTx{
				{TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{good}},
				nil,
			}},
			want: "transaction 1 is null",
		},
		{
			name: "null input",
			blk: &wire.MsgBlock{Header: hdr, Transactions: []*wire.MsgTx{{
				TxIn: []*wire.TxIn{nil}, TxOut: []*wire.TxOut{good},
			}}},
			want: "transaction 0 input 0 is null",
		},
		{
			name: "null output",
			blk: &wire.MsgBlock{Header: hdr, Transactions: []*wire.MsgTx{{
				TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{nil},
			}}},
			want: "transaction 0 output 0 is null",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// First: the payload really is lethal to the code path the handler runs. Without this the
			// test could pass against a fixture that was never dangerous.
			panicked := func() (p bool) {
				defer func() {
					if r := recover(); r != nil {
						p = true
					}
				}()
				_ = blockchain.CheckBlockSanity(btcutil.NewBlock(tc.blk),
					chaincfg.RegressionNetParams.PowLimit, deterministicTimeSource{})
				return false
			}()
			if !panicked {
				t.Skipf("btcd no longer panics on %s; this vector is closed upstream and the fixture "+
					"proves nothing. Re-derive rejectNilBlockElements before removing it.", tc.name)
			}

			err := rejectNilBlockElements(tc.blk)
			if err == nil {
				t.Fatalf("ACCEPTED a block with a %s. This payload panics blockchain.CheckBlockSanity, "+
					"which the insert handler calls from a goroutine with no recover -- an "+
					"unauthenticated caller kills the process with one message.", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rejected, but the message does not identify the offender: got %q, want it to "+
					"contain %q", err.Error(), tc.want)
			}
		})
	}

	// The TRANSACTION boundary, which the first version of this fix missed entirely.
	//
	// tbcapi.TxBroadcastRequest.Tx is a second *wire.MsgTx arriving from json.Unmarshal, reaching
	// Server.TxBroadcast, whose tx.TxHash() panics on a nil element exactly as CheckBlockSanity does
	// for blocks. The guard was originally placed in the block-insert handler with a comment calling
	// it "the one place" a wire type comes from JSON; that was false, and the missed half was the
	// one still killable.
	for _, tc := range []struct {
		name string
		tx   *wire.MsgTx
		want string
	}{
		{
			name: "null input",
			tx:   &wire.MsgTx{TxIn: []*wire.TxIn{nil}},
			want: "transaction 0 input 0 is null",
		},
		{
			name: "null output",
			tx:   &wire.MsgTx{TxOut: []*wire.TxOut{nil}},
			want: "transaction 0 output 0 is null",
		},
		{
			name: "null transaction",
			tx:   nil,
			want: "transaction 0 is null",
		},
		// Nils at index >= 1, behind a valid element. Every fixture above puts the nil at index 0
		// of a one-element slice, which a guard that inspects only TxIn[0]/TxOut[0] satisfies --
		// measured: that mutant survived the whole package. btcd walks every element, so index 2 is
		// exactly as lethal as index 0.
		{
			name: "null input at index 2",
			tx:   &wire.MsgTx{TxIn: []*wire.TxIn{{}, {}, nil}},
			want: "transaction 0 input 2 is null",
		},
		{
			name: "null output at index 1",
			tx: &wire.MsgTx{
				TxIn:  []*wire.TxIn{{}},
				TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}, nil},
			},
			want: "transaction 0 output 1 is null",
		},
	} {
		t.Run("tx/"+tc.name, func(t *testing.T) {
			if tc.tx != nil {
				panicked := func() (p bool) {
					defer func() {
						if r := recover(); r != nil {
							p = true
						}
					}()
					_ = tc.tx.TxHash()
					return false
				}()
				if !panicked {
					t.Skipf("btcd no longer panics on %s; re-derive rejectNilTxElements before "+
						"removing it", tc.name)
				}
			}
			err := rejectNilTxElements(tc.tx, 0)
			if err == nil {
				t.Fatalf("ACCEPTED a transaction with a %s. Server.TxBroadcast calls tx.TxHash() on "+
					"it from a goroutine with no recover -- one unauthenticated tbcapi message kills "+
					"the process.", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rejected, but the message does not identify the offender: got %q, want %q",
					err.Error(), tc.want)
			}
		})
	}

	// A well-formed transaction must still pass.
	if err := rejectNilTxElements(&wire.MsgTx{
		TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{good},
	}, 0); err != nil {
		t.Fatalf("rejected a well-formed transaction: %v", err)
	}

	// A well-formed block must still pass, or the guard is a denial of service of its own.
	ok := &wire.MsgBlock{Header: hdr, Transactions: []*wire.MsgTx{{
		TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{good},
	}}}
	if err := rejectNilBlockElements(ok); err != nil {
		t.Fatalf("rejected a well-formed block: %v", err)
	}
	if err := rejectNilBlockElements(&wire.MsgBlock{Header: hdr}); err != nil {
		t.Fatalf("rejected a zero-transaction block: %v", err)
	}
}

// TestNilGuardsRunAndAreActedOnAtTheServerBoundary replaces an AST lint that did not guard.
//
// The lint checked that Server.BlockInsert and Server.TxBroadcast CALL rejectNil*, and in what
// order. Its doc comment claimed it also caught "ignoring its error". It did not: replacing
//
//	if err := rejectNilBlockElements(blk); err != nil { return 0, err }
//
// with `_ = rejectNilBlockElements(blk)` left the lint AND the entire package green, while
// s.db.BlockInsert was still reached with a nil *TxIn and the process died. That is the one-message
// unauthenticated kill from localhost:8082 the guard exists to close.
//
// This test is behavioural and needs no database, which is the trick that makes it strictly stronger
// than the lint. Both methods run the nil check BEFORE they touch s.db, so a zero-value Server is
// enough: if the check is present and acted on, we get a clean error; if it is deleted, if its error
// is discarded, or if it is moved below the write, execution reaches a nil s.db (or btcd's nil
// deref) and the test panics instead. All three mutants die here; the lint killed only two.
func TestNilGuardsRunAndAreActedOnAtTheServerBoundary(t *testing.T) {
	good := &wire.TxOut{Value: 1, PkScript: []byte{0x51}}

	t.Run("BlockInsert", func(t *testing.T) {
		// Nil at index >= 1, behind a valid transaction, so a guard that only inspects element 0
		// fails here too.
		blk := &wire.MsgBlock{Transactions: []*wire.MsgTx{
			{TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{good}},
			{TxIn: []*wire.TxIn{{}, {}, nil}, TxOut: []*wire.TxOut{good}},
		}}

		// No db: reaching s.db.BlockInsert IS the failure this test detects.
		s := &Server{}
		var err error
		if p, v := didPanic(func() { _, err = s.BlockInsert(t.Context(), blk) }); p {
			t.Fatalf("Server.BlockInsert reached the store with a nil *TxIn (%v). The nil check is "+
				"missing, its error is being discarded, or it now runs after the write. An "+
				"unauthenticated tbcapi caller kills the process with one message.", v)
		}
		if err == nil {
			t.Fatal("a block with a nil input must be refused")
		}
		if !strings.Contains(err.Error(), "transaction 1 input 2 is null") {
			t.Fatalf("refused, but the error does not identify the offending element: %v", err)
		}
	})

	t.Run("TxBroadcast", func(t *testing.T) {
		tx := &wire.MsgTx{
			TxIn:  []*wire.TxIn{{}},
			TxOut: []*wire.TxOut{good, nil},
		}
		s := &Server{cfg: &Config{}}
		var err error
		if p, v := didPanic(func() { _, err = s.TxBroadcast(t.Context(), tx, false) }); p {
			t.Fatalf("Server.TxBroadcast reached tx.TxHash() with a nil *TxOut (%v). Same "+
				"one-message kill: the handler runs in a bare goroutine and there is no recover "+
				"anywhere in service/tbc.", v)
		}
		if err == nil {
			t.Fatal("a transaction with a nil output must be refused")
		}
		if !strings.Contains(err.Error(), "transaction 0 output 1 is null") {
			t.Fatalf("refused, but the error does not identify the offending element: %v", err)
		}
	})

	// The ACCEPT direction is deliberately not retested here. A zero-value Server has no broadcast
	// map and no db, so a well-formed input gets past the nil check and then panics inside the store
	// logic -- asserting on that panic would be asserting on an implementation detail of the stub,
	// not on the guard. TestBlockInsertRejectsNilElements covers the accept direction by calling
	// rejectNilTxElements/rejectNilBlockElements directly, which is where it belongs.
}

// TestBlockInsertHandlerRejectsNilElements covers the tbcapi block path, which does NOT go through
// Server.BlockInsert and therefore does not inherit its guard.
//
// This is the gap that made the "put the check on the exported Server method and no caller can miss
// it" reasoning wrong. It holds for transactions -- both tx handlers call s.TxBroadcast -- but
// handleBlockInsertRequest and handleBlockInsertRawRequest call s.db.BlockInsert DIRECTLY. So the
// tbcapi block path is protected only by its own separate rejectNilBlockElements call, and until this
// test existed, deleting that call left the entire package green while restoring a one-message
// unauthenticated process kill.
//
// A zero-value Server suffices: the guard runs before anything touches s.chainParams or s.db, so a
// clean error proves the guard ran, and a panic proves it did not.
func TestBlockInsertHandlerRejectsNilElements(t *testing.T) {
	good := &wire.TxOut{Value: 1, PkScript: []byte{0x51}}

	// The header must clear CheckBlockSanity's difficulty test, or sanity fails there and never
	// reaches the transaction walk -- which would make the lethality precondition below pass
	// vacuously. Regtest difficulty 1; nonce 0 clears it.
	hdr := wire.BlockHeader{
		Version:   1,
		Timestamp: time.Unix(1700000000, 0),
		Bits:      0x207fffff,
	}

	// Nil at index >= 1 behind a valid transaction, so a guard that inspects only element 0 fails.
	blk := &wire.MsgBlock{Header: hdr, Transactions: []*wire.MsgTx{
		{TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{good}},
		{TxIn: []*wire.TxIn{{}, nil}, TxOut: []*wire.TxOut{good}},
	}}

	// Confirm the payload really is lethal to what the handler runs, so this cannot pass vacuously.
	if p, _ := didPanic(func() {
		_ = blockchain.CheckBlockSanity(btcutil.NewBlock(blk),
			chaincfg.RegressionNetParams.PowLimit, deterministicTimeSource{})
	}); !p {
		t.Fatal("fixture is not lethal; this test would prove nothing")
	}

	s := &Server{}
	var resp any
	var err error
	if p, v := didPanic(func() {
		resp, err = s.handleBlockInsertRequest(t.Context(), &tbcapi.BlockInsertRequest{Block: blk})
	}); p {
		t.Fatalf("handleBlockInsertRequest panicked on a JSON block with a nil input (%v). Its own "+
			"rejectNilBlockElements call is missing or reordered -- and Server.BlockInsert's guard "+
			"does NOT cover this path, because this handler writes through s.db.BlockInsert "+
			"directly.", v)
	}
	if err != nil {
		t.Fatalf("a malformed request must be answered, not errored at the transport: %v", err)
	}
	ir, ok := resp.(*tbcapi.BlockInsertResponse)
	if !ok {
		t.Fatalf("handleBlockInsertRequest must answer with *tbcapi.BlockInsertResponse, got %T; "+
			"protocol.Write derives the wire command from the payload's Go type, so a different "+
			"type answers the client with the wrong command", resp)
	}
	if ir.Error == nil {
		t.Fatal("a block with a nil input must be refused")
	}
	if !strings.Contains(ir.Error.Message, "is null") {
		t.Fatalf("refused, but the error does not identify the offending element: %v", ir.Error.Message)
	}
}

// TestRawHandlerFailuresUseTheRawResponseType pins the response-type fix.
//
// protocol.Write derives the wire command from the payload's Go TYPE, so a *raw* handler that
// returns a non-raw response answers a "tbcapi-block-insert-raw-request" with
// "tbcapi-block-insert-response". The client correlates by id, receives a payload of the wrong type,
// and either panics on the assertion or silently drops the error under comma-ok.
//
// Every failure path in handleBlockInsertRawRequest did exactly that. It went unnoticed because
// wire.NewMsgBlock(nil) panicked on the handler's first statement, so no failure path had ever run.
func TestRawHandlerFailuresUseTheRawResponseType(t *testing.T) {
	s := &Server{}
	resp, err := s.handleBlockInsertRawRequest(t.Context(),
		&tbcapi.BlockInsertRawRequest{Block: []byte{0x00, 0x01, 0x02}}) // undecodable
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if _, ok := resp.(*tbcapi.BlockInsertRawResponse); !ok {
		t.Fatalf("a raw request's FAILURE path must return *tbcapi.BlockInsertRawResponse, got %T. "+
			"protocol.Write picks the wire command from this type, so the client is answered with "+
			"the wrong command and cannot type-assert the payload.", resp)
	}

	// The SANITY-failure path too. Measured: reverting only that return to the non-raw type left the
	// whole package green -- this test drove only the Deserialize-failure path while its doc claimed
	// "every failure path". A guard that pins one of three paths is a guard that will be half-reverted
	// without anyone noticing.
	//
	// A structurally decodable block with a zero header fails CheckBlockSanity on difficulty, which
	// is the second of the three returns.
	var sane bytes.Buffer
	if err := (&wire.MsgBlock{Header: wire.BlockHeader{Version: 1}}).Serialize(&sane); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	s3 := &Server{chainParams: &chaincfg.RegressionNetParams}
	resp3, err3 := s3.handleBlockInsertRawRequest(t.Context(),
		&tbcapi.BlockInsertRawRequest{Block: sane.Bytes()})
	if err3 != nil {
		t.Fatalf("unexpected transport error: %v", err3)
	}
	br3, ok := resp3.(*tbcapi.BlockInsertRawResponse)
	if !ok {
		t.Fatalf("the SANITY-failure path must also return *tbcapi.BlockInsertRawResponse, got %T",
			resp3)
	}
	if br3.Error == nil {
		t.Fatal("precondition: a zero-header block must fail CheckBlockSanity, else this case " +
			"exercises the wrong return")
	}

	// The same class in the raw TX handler. That one was LIVE -- nothing masked it, so every failure
	// answered with the wrong command in production. Covering only the block handler is what let it
	// survive being found and fixed one function away.
	s2 := &Server{cfg: &Config{}}
	resp2, err2 := s2.handleTxBroadcastRawRequest(t.Context(),
		&tbcapi.TxBroadcastRawRequest{Tx: []byte{0x00, 0x01, 0x02}}) // undecodable
	if err2 != nil {
		t.Fatalf("unexpected transport error: %v", err2)
	}
	if _, ok := resp2.(*tbcapi.TxBroadcastRawResponse); !ok {
		t.Fatalf("a raw tx request's FAILURE path must return *tbcapi.TxBroadcastRawResponse, got "+
			"%T -- the client is answered with command tbcapi-tx-broadcast-response and cannot "+
			"type-assert the payload.", resp2)
	}
}

// didPanic reports whether fn panicked. heminetwork's tests use plain t.Fatalf rather than a
// matcher library (testify is an indirect dependency here and no other test in this package pulls
// it in), so this is the local equivalent of require.Panics / require.NotPanics.
func didPanic(fn func()) (panicked bool, value any) {
	defer func() {
		if r := recover(); r != nil {
			panicked, value = true, r
		}
	}()
	fn()
	return false, nil
}

// TestMaxAddressLengthConsensusFloor asserts the floor DIRECTLY, rather than relying on it being an
// emergent property of a list of example addresses.
//
// MaxAddressLength is consensus-visible to hVM even though nothing in this repository can observe
// that. op-geth's 0x40 btcBalAddr and 0x41 btcUtxosAddrList do not decode addresses themselves --
// they hand the raw string to BalanceByAddress/UtxosByAddress, so THIS constant is their effective
// cap. Lower it below 130 and a valid uncompressed-pubkey address stops decoding; 0x40 maps that
// error to a SUCCESSFUL empty CALL, and Solidity reads balance zero for an address that holds funds.
// Nothing reverts and nothing logs.
//
// WHY A SEPARATE TEST. The floor was previously implied by one entry in
// TestMaxAddressLengthCannotRejectARealAddress's list -- a 130-character uncompressed-pubkey hex
// string. Nothing marked it load-bearing, and it does not decode on any network, so it reads like
// dead weight next to the real addresses around it. Measured: delete that entry and
// MaxAddressLength = 90 passes this entire package. A constant that guards consensus in another
// repository should not depend on a maintainer guessing which list entry is load-bearing.
//
// 90 is the specific trap: it is the bech32 limit, it is quoted a few lines above in
// MaxAddressLength's own doc comment, and "tighten to the bech32 maximum" looks locally correct to
// anyone who has never heard of hVM.
func TestMaxAddressLengthConsensusFloor(t *testing.T) {
	const consensusFloor = 130 // btcutil's acceptance ceiling: uncompressed-pubkey hex

	if MaxAddressLength < consensusFloor {
		t.Fatalf("MaxAddressLength is %d, BELOW the hVM consensus floor of %d.\n\n"+
			"This is not a local tightening. op-geth's 0x40/0x41 precompiles pass their raw address "+
			"string to BalanceByAddress/UtxosByAddress, so this constant is their effective cap. At "+
			"%d, a valid %d-character uncompressed-pubkey address stops decoding, 0x40 turns the "+
			"error into a successful empty CALL, and a contract reads BALANCE ZERO for an address "+
			"that holds funds -- with no revert and no log.\n\n"+
			"If you are tightening for DoS reasons: the decode is already bounded by the websocket "+
			"read limit, and op-geth caps at 200 on its own side. There is nothing to gain here and "+
			"a silent consensus break to lose.",
			MaxAddressLength, consensusFloor, MaxAddressLength, consensusFloor)
	}
}

// TestTxBroadcastHandlerAnswersNilElementAsAClientError pins the ERROR CLASS, not just the rejection.
//
// The block path already asserts this (`a malformed request must be answered, not errored at the
// transport`). The transaction path had no equivalent, and that asymmetry is exactly why the defect
// got through: the nil-element rejection fell past the errors.Is arm into
// protocol.NewInternalError, which handleRequest logs with an unthrottled log.Errorf per message.
//
// A ~60-byte unauthenticated tbcapi message carrying "TxIn":[null] therefore bought one Error line
// each -- no proof-of-work, no rate limit, on a listener that defaults to localhost:8082. That is a
// CHEAPER version of the log-amplification vector the strip logs were moved below CheckBlockSanity
// to close, introduced by the change that closed it. api/protocol's own contract says request errors
// "should not be logged server-side".
func TestTxBroadcastHandlerAnswersNilElementAsAClientError(t *testing.T) {
	s := &Server{cfg: &Config{}}
	tx := &wire.MsgTx{TxIn: []*wire.TxIn{nil}}

	resp, err := s.handleTxBroadcastRequest(t.Context(),
		&tbcapi.TxBroadcastRequest{Tx: tx})
	if err != nil {
		t.Fatalf("a malformed request must be ANSWERED, not errored at the transport. Returning a "+
			"non-nil error here makes handleRequest emit an unthrottled log.Errorf per message, so "+
			"an unauthenticated caller drives the log at will. got: %v", err)
	}
	br, ok := resp.(*tbcapi.TxBroadcastResponse)
	if !ok {
		t.Fatalf("want *tbcapi.TxBroadcastResponse, got %T", resp)
	}
	if br.Error == nil {
		t.Fatal("a transaction with a nil input must be refused")
	}
	if !strings.Contains(br.Error.Message, "is null") {
		t.Fatalf("refused, but the message does not identify the offender: %q", br.Error.Message)
	}
}

// TestHandleInvRejectsEmptyInventory pins a one-message remote node kill.
//
// btcd's MsgInv.BtcDecode accepts a vector count of zero, so a 25-byte `inv` message decodes cleanly
// into a zero-length InvList. handleInv's first statement indexed InvList[0] unconditionally, and
// handlePeer runs it on a bare goroutine with no recover anywhere in service/tbc or api/ -- so that
// index panic terminated the process.
//
// Reachability is the worst in this package: TBC dials 64 real Bitcoin peers (defaultPeersWanted --
// cfg.PeersWanted is never passed to NewPeerManager) and hands whatever they send straight to
// handleGeneric. Any one of them can send this. No authentication, no proof-of-work, no mining, 25
// bytes. It kills standalone tbcd AND the embedded full node inside every op-geth hVM node. TBC has
// no inbound Bitcoin listener, so the attacker must be dialed -- cheap on testnet3 (the default
// network) via a DNS seed, but it is not reachable from an arbitrary host.
//
// The test asserts the WIRE accepts it first, so it cannot pass vacuously if btcd ever starts
// rejecting a zero-count inv.
func TestHandleInvRejectsEmptyInventory(t *testing.T) {
	var buf bytes.Buffer
	if err := wire.WriteMessage(&buf, wire.NewMsgInv(), wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, m, _, err := wire.ReadMessageN(bytes.NewReader(buf.Bytes()), wire.ProtocolVersion, wire.MainNet)
	if err != nil {
		t.Skipf("btcd now rejects a zero-count inv on the wire (%v); the vector is closed upstream "+
			"and this test has nothing left to pin", err)
	}
	inv, ok := m.(*wire.MsgInv)
	if !ok {
		t.Fatalf("decoded %T, want *wire.MsgInv", m)
	}
	if len(inv.InvList) != 0 {
		t.Fatalf("precondition: want a zero-length InvList, got %d", len(inv.InvList))
	}

	// A zero-value Server suffices: the guard returns before anything touches s.db, s.mtx or a peer.
	s := &Server{}
	if p, v := didPanic(func() { _ = s.handleInv(t.Context(), nil, inv, nil) }); p {
		t.Fatalf("handleInv panicked on an empty inventory (%v). That is a 25-byte unauthenticated "+
			"remote process kill from any Bitcoin peer TBC dials -- handlePeer has no recover.", v)
	}
}

// TestNilRequestIsAnsweredNotErrored covers the CHEAPEST log-amplification shape, which the
// ErrNilElement work initially missed.
//
// handleRequest logs every non-nil transport error with an unthrottled log.Errorf, once per message.
// `{"block":null}` and `{"tx":null}` are strictly cheaper to send than any nil-ELEMENT shape, so
// while ErrNilElement closed the harder route these two arms kept the easy one wide open.
//
// The tests for the nil-element arms cannot catch this: they never send a nil request.
func TestNilRequestIsAnsweredNotErrored(t *testing.T) {
	s := &Server{cfg: &Config{}}

	if _, err := s.handleBlockInsertRequest(t.Context(),
		&tbcapi.BlockInsertRequest{Block: nil}); err != nil {
		t.Fatalf("a nil block must be ANSWERED, not errored at the transport -- a non-nil error here "+
			"makes handleRequest emit an unthrottled log.Errorf per message, and `{\"block\":null}` "+
			"is the cheapest message that reaches it. got: %v", err)
	}
	if _, err := s.handleTxBroadcastRequest(t.Context(),
		&tbcapi.TxBroadcastRequest{Tx: nil}); err != nil {
		t.Fatalf("a nil tx must be ANSWERED, not errored at the transport. got: %v", err)
	}
}

// TestMaxAddressLengthHasACeiling mirrors op-geth's TestMaxAddressLengthIsPlausible.
//
// The floor test stops MaxAddressLength being lowered into consensus-breaking territory. Nothing
// stopped it being RAISED: measured, MaxAddressLength = 1_000_000 passed this entire package, which
// re-opens the O(n^2) base58 decode on the unauthenticated, unthrottled, goroutine-per-message
// tbcapi surface. op-geth kills the identical mutation twice on its side; this closes the asymmetry.
//
// 200 is ~1.54x btcutil's real acceptance ceiling of 130 and ~3x the longest address form that
// exists, so anything far above it is a bound in name only.
func TestMaxAddressLengthHasACeiling(t *testing.T) {
	const ceiling = 1000 // generous: still bounds the quadratic decode to microseconds
	if MaxAddressLength > ceiling {
		t.Fatalf("MaxAddressLength is %d, above the plausibility ceiling of %d.\n\n"+
			"base58.CheckDecode is O(n^2) and this constant is the only bound on the address string "+
			"reaching it from tbcapi -- an unauthenticated, unrate-limited, goroutine-per-message "+
			"surface. btcutil cannot accept anything longer than 130 characters, so a cap far above "+
			"that bounds nothing while costing quadratic CPU per request.", MaxAddressLength, ceiling)
	}
}
