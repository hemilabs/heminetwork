// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

// M1: behavioural coverage for handleBlock's witness-strip arm -- the Bitcoin-P2P write path.
//
// WHAT WAS MISSING. handleBlock is the only free, un-mined channel through which a malicious Bitcoin
// peer can put forged witness into BlocksDB (rawpeer reads with wire.LatestEncoding, so a peer can
// answer an InvTypeBlock getdata with a witness-serialized body, and CheckBlockSanity is
// witness-blind). Its strip arm had exactly one guard: TestEveryBlockWriteStripsWitness, which is an
// AST walk over source read FROM DISK. That guard proves the call is written down in the right
// ORDER; it cannot observe what the code does, it cannot be exercised under `go test -overlay`, and
// it would stay green if StripBlockWitness itself were broken.
//
// READ THIS BEFORE TRUSTING THE TEST BELOW. TestM1HandleBlockStripArmOnRealBlocks does NOT bind
// handleBlock. It calls StripBlockWitness, btcutil.NewBlock and checkBlockMerkleRoot itself, in
// handleBlock's order, so it exercises the FUNCTIONS and never the CALLER. Measured: deleting
// `stripped := StripBlockWitness(msg)` from handleBlock leaves it, and the whole package, GREEN --
// which is precisely the flaw this header criticises the AST guard for two paragraphs up. Its value is
// real but narrower than "behavioural coverage": it validates the sequence and the ordering hazard
// against 314 real bodies.
//
// The call site itself is bound by TestN1HandleBlockCallSiteActuallyStrips at the bottom of this file,
// which drives the real s.handleBlock and inspects WHAT THE STORE WAS HANDED. That one does fail when
// the call site is deleted.
//
// This test drives the exact statement sequence handleBlock executes, on 314 real mainnet block
// bodies, and pins BOTH directions:
//
//   - the strip runs and removes every witness byte, while the block still binds to its header;
//   - the ORDER (strip, then btcutil.NewBlock, then checkBlockMerkleRoot) is load-bearing, and the
//     one-line change handleBlock's comment warns against -- NewBlockFromBlockAndBytes -- REJECTS
//     real mainnet blocks. The comment cites 481824, 500000 and 800000 as measured; nothing in the
//     tree checked that, so the claim could rot silently and the "DO NOT MAKE THAT CHANGE" warning
//     would be the only thing standing between the fleet and a liveness break.
//
// A false reject here disconnects the honest peer that served the body and leaves the node unable to
// obtain that block from anyone, which under Holocene is a silent fork rather than a halt.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
)

// m1Stamp reports whether a MUTATED service/tbc source is compiled in. A mutant sets M1_MUTANT in
// an init(); the real tree sets nothing. It is how a mutation run proves the mutation applied.
func m1Stamp(t *testing.T) {
	t.Helper()
	if v := os.Getenv("M1_MUTANT"); v != "" {
		t.Logf("M1 STAMP: MUTATED BUILD -> %s", v)
	} else {
		t.Logf("M1 STAMP: none (unmutated build)")
	}
}

func m1Corpus(t *testing.T) []string {
	t.Helper()
	// Corpus resolution: explicit override, legacy override, then the COMMITTED corpus.
	var dir string
	switch {
	case os.Getenv("HVM_BTC_CORPUS") != "":
		dir = os.Getenv("HVM_BTC_CORPUS")
	case os.Getenv("M1_CORPUS") != "":
		dir = os.Getenv("M1_CORPUS")
	default:
		// Committed corpus: SIX real mainnet blocks (~1.2 MB) -- heights 1 and 100000
		// (pre-segwit), 509388, 603436 and 608000 (which carry witness), and 481824, which ships
		// so the ordering-hazard citation is verified in CI. The count is stated PER REPO on
		// purpose: op-geth ships a different set (five blocks, ~162 KB, no 481824), and an earlier
		// version of this paragraph was copied verbatim between the two, making it false on arrival. This used to t.Skip when the env var was
		// unset, so it never ran in ANY CI lane; it was one of seven such tests across six variable
		// names. A corpus test that silently does nothing reads as coverage and provides none.
		// Set HVM_BTC_CORPUS to a directory of *.bin bodies for the full sweep.
		dir = filepath.Join("testdata", "btccorpus")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".bin" {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	floor := 4
	if os.Getenv("HVM_BTC_CORPUS") != "" || os.Getenv("M1_CORPUS") != "" {
		floor = 300
	}
	if len(out) < floor {
		t.Fatalf("corpus has only %d blocks; this control is not reading what it thinks it is", len(out))
	}
	return out
}

func m1Decode(t *testing.T, path string) (*wire.MsgBlock, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var blk wire.MsgBlock
	if err := blk.BtcDecode(bytes.NewReader(raw), wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return &blk, raw
}

// TestM1HandleBlockStripArmOnRealBlocks reproduces handleBlock's sequence verbatim.
func TestM1HandleBlockStripArmOnRealBlocks(t *testing.T) {
	m1Stamp(t)
	files := m1Corpus(t)
	stripped, clean := 0, 0

	for _, f := range files {
		msg, _ := m1Decode(t, f)
		wantHash := msg.BlockHash()

		hadWitness := false
		for _, tx := range msg.Transactions {
			for _, in := range tx.TxIn {
				if len(in.Witness) != 0 {
					hadWitness = true
				}
			}
		}

		// --- handleBlock's sequence ---
		n := StripBlockWitness(msg)
		block := btcutil.NewBlock(msg)
		bhs := block.Hash().String()
		if err := checkBlockMerkleRoot(block); err != nil {
			t.Fatalf("%s: a REAL mainnet block was REJECTED by handleBlock's merkle gate after the "+
				"witness strip. This disconnects the honest peer that served it and the node can "+
				"never obtain the block: %v", f, err)
		}
		// --- end sequence ---

		if bhs != wantHash.String() {
			t.Fatalf("%s: the strip moved the block hash (%s -> %s)", f, wantHash, bhs)
		}
		if hadWitness {
			stripped++
			if n == 0 {
				t.Fatalf("%s: block carried witness but StripBlockWitness reported 0", f)
			}
		} else {
			clean++
			if n != 0 {
				t.Fatalf("%s: witness-free block reported %d stripped", f, n)
			}
		}
		for i, tx := range msg.Transactions {
			for j, in := range tx.TxIn {
				if len(in.Witness) != 0 {
					t.Fatalf("%s tx %d in %d: witness survived handleBlock's strip", f, i, j)
				}
			}
		}
		// The tx set btcutil hands the rest of the pipeline must be the stripped one, and every txid
		// must be unchanged -- that is what binds the body to the (unchanged) merkle root.
		for i, tx := range block.Transactions() {
			for j, in := range tx.MsgTx().TxIn {
				if len(in.Witness) != 0 {
					t.Fatalf("%s tx %d in %d: btcutil.Block still exposes witness", f, i, j)
				}
			}
			_ = tx.Hash()
		}
	}
	t.Logf("M1 handleBlock arm: %d real blocks (%d carried witness, %d were already clean) all "+
		"passed strip -> NewBlock -> checkBlockMerkleRoot", len(files), stripped, clean)
	// Richness floor scales with WHICH corpus is in use, like the size floor above: the committed
	// testdata set is five real blocks (three witness-bearing), an override is a full sweep. What
	// this tripwire protects is that the control actually EXERCISES the behaviour -- not that the
	// corpus is large. A hard 50 is what kept this test out of every CI lane.
	floorW := 3
	if os.Getenv("HVM_BTC_CORPUS") != "" || os.Getenv("M1_CORPUS") != "" {
		floorW = 50
	}
	if stripped < floorW {
		t.Fatalf("only %d corpus blocks carried witness (floor %d); this control is near-vacuous", stripped, floorW)
	}
}

// TestM1HandleBlockOrderingHazardIsReal pins the measurement handleBlock's comment rests on: if the
// block were built with NewBlockFromBlockAndBytes (which caches the UNSTRIPPED raw bytes) after the
// strip, Transactions() slices each tx out of the raw bytes using offsets computed from the STRIPPED
// sizes, so every tx after the first witness-bearing one is parsed from misaligned bytes and the
// merkle check rejects a genuine block.
//
// This is a REGRESSION GUARD ON A COMMENT: if a future refactor makes that change safe, this test
// fails and the "DO NOT MAKE THAT CHANGE" warning can be revisited with evidence. If the change is
// made unsafely, the sibling test above catches it. Neither existed before.
func TestM1HandleBlockOrderingHazardIsReal(t *testing.T) {
	m1Stamp(t)
	files := m1Corpus(t)
	cited := map[string]bool{"481824.bin": false, "500000.bin": false, "800000.bin": false}
	// present records which corpus files exist, so an ABSENT cited block is reported as
	// "not verified" rather than as "accepted" -- two very different claims.
	present := map[string]struct{}{}
	for _, f := range files {
		present[filepath.Base(f)] = struct{}{}
	}

	rejected, accepted := 0, 0
	for _, f := range files {
		msg, raw := m1Decode(t, f)
		hadWitness := false
		for _, tx := range msg.Transactions {
			for _, in := range tx.TxIn {
				if len(in.Witness) != 0 {
					hadWitness = true
				}
			}
		}
		StripBlockWitness(msg)
		bad := btcutil.NewBlockFromBlockAndBytes(msg, raw)
		merr := func() (e error) {
			// Transactions() can panic on misaligned bytes; a panic is as much a rejection as an
			// error for the purposes of this claim.
			defer func() {
				if r := recover(); r != nil {
					e = errPanic
				}
			}()
			return checkBlockMerkleRoot(bad)
		}()
		if merr != nil {
			rejected++
			if _, ok := cited[filepath.Base(f)]; ok {
				cited[filepath.Base(f)] = true
			}
		} else {
			accepted++
			if hadWitness {
				t.Errorf("%s carries witness yet survived the NewBlockFromBlockAndBytes ordering "+
					"hazard; handleBlock's comment claims this shape is broken", f)
			}
		}
	}
	// Only assert on cited blocks the corpus ACTUALLY CONTAINS.
	//
	// This used to fail every cited name that was merely ABSENT, reporting it as "ACCEPTED here" --
	// which is a different and much more alarming claim than "not present to check". The committed
	// testdata corpus carries 481824 precisely so at least one citation is verified in CI; point
	// HVM_BTC_CORPUS at a full sweep to verify all three.
	verified := 0
	for name, hit := range cited {
		if _, ok := present[name]; !ok {
			t.Logf("cited block %s is not in this corpus; not verified here", name)
			continue
		}
		verified++
		if !hit {
			t.Errorf("handleBlock's comment cites %s as a measured rejection under "+
				"NewBlockFromBlockAndBytes, but it was ACCEPTED here. Re-derive the comment.", name)
		}
	}
	if verified == 0 {
		t.Fatal("no cited block was present in the corpus, so the comment's measured claim was not " +
			"checked at all. testdata/btccorpus ships 481824 for exactly this reason.")
	}
	t.Logf("M1 ordering hazard: NewBlockFromBlockAndBytes after the strip rejects %d of %d real "+
		"mainnet blocks (%d still accepted -- the witness-free ones)", rejected, len(files), accepted)
	floorR := 3
	if os.Getenv("HVM_BTC_CORPUS") != "" || os.Getenv("M1_CORPUS") != "" {
		floorR = 50
	}
	if rejected < floorR {
		t.Fatalf("only %d rejections; the documented hazard did not reproduce", rejected)
	}
}

var errPanic = panicError{}

type panicError struct{}

func (panicError) Error() string { return "panic while parsing misaligned transactions" }

// TestN1HandleBlockCallSiteActuallyStrips binds handleBlock's witness-strip CALL SITE.
//
// WHY THIS EXISTS, AND WHAT IT REPLACES. TestM1HandleBlockStripArmOnRealBlocks claims to give this arm
// behavioural coverage. It does not. It calls StripBlockWitness, btcutil.NewBlock and
// checkBlockMerkleRoot itself, in handleBlock's order -- so it exercises the FUNCTIONS but never the
// CALLER. Measured: deleting `stripped := StripBlockWitness(msg)` from handleBlock leaves that test,
// and the entire package, GREEN. It has precisely the flaw its own header criticises the AST guard for
// ("it would stay green if StripBlockWitness itself were broken").
//
// The distinction is not academic. The vulnerability is a witness-bearing body reaching BlocksDB, and
// BlocksDB is first-writer-wins with no delete, so one admitted body is permanent. What has to be
// proven is that THE STORE RECEIVES STRIPPED BYTES -- a property of the call site, observable only by
// looking at what BlockInsert was handed.
//
// So: drive the real s.handleBlock with a witness-bearing body and assert the STORED block carries no
// witness. A nil peer is fine (p is only formatted into a log line), and recordingDB stands in for the
// store, the same harness TestHandleBlockRefusesForgedBodyBehaviourally uses.
func TestN1HandleBlockCallSiteActuallyStrips(t *testing.T) {
	genuine := realBlock(t, realBlockA)

	// Precondition: the body must carry witness, or "no witness in the store" is trivially true and
	// this test proves nothing whether or not the strip runs.
	probe := &wire.MsgBlock{Header: genuine.MsgBlock().Header}
	probe.Transactions = make([]*wire.MsgTx, 0, len(genuine.MsgBlock().Transactions))
	for _, tx := range genuine.MsgBlock().Transactions {
		probe.Transactions = append(probe.Transactions, tx.Copy())
	}
	witnessTxs := StripBlockWitness(probe)
	if witnessTxs == 0 {
		t.Fatal("precondition failed: the fixture must carry witness, else a deleted strip is " +
			"indistinguishable from a working one")
	}
	t.Logf("fixture carries witness in %d transaction(s)", witnessTxs)

	// A DEEP copy. slices.Clone is SHALLOW -- it copies the []*wire.MsgTx pointer slice, not the
	// transactions -- so the probe above and this body would share every *wire.MsgTx, and the probe's
	// in-place strip would have already cleaned the body handleBlock is about to see. Measured: with
	// slices.Clone here this test PASSED against a build whose strip call site was deleted, i.e. it
	// reproduced exactly the defect it was written to catch. tx.Copy() is what makes it real.
	body := &wire.MsgBlock{Header: genuine.MsgBlock().Header}
	body.Transactions = make([]*wire.MsgTx, 0, len(genuine.MsgBlock().Transactions))
	for _, tx := range genuine.MsgBlock().Transactions {
		body.Transactions = append(body.Transactions, tx.Copy())
	}
	// Prove the deep copy really is witness-bearing, so a green result cannot come from a clean input.
	live := 0
	for _, tx := range body.Transactions {
		if tx.HasWitness() {
			live++
		}
	}
	if live == 0 {
		t.Fatal("precondition failed: the deep-copied body lost its witness; the copy is not independent")
	}
	t.Logf("body handed to handleBlock carries witness in %d transaction(s)", live)

	cfg := NewDefaultConfig()
	cfg.Network = "localnet"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	db := &recordingDB{}
	s.db = db

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := s.handleBlock(ctx, nil, body, nil); err != nil {
		t.Fatalf("handleBlock REJECTED a real mainnet block: %v", err)
	}
	if db.inserts != 1 {
		t.Fatalf("expected exactly one store write, got %d", db.inserts)
	}
	if db.last == nil {
		t.Fatal("handleBlock reported a write but the store captured no block")
	}

	for i, tx := range db.last.MsgBlock().Transactions {
		for j, in := range tx.TxIn {
			if len(in.Witness) != 0 {
				t.Fatalf("THE STORE RECEIVED WITNESS: tx %d input %d carries %d witness element(s). "+
					"handleBlock's StripBlockWitness call site is not running. BlocksDB is "+
					"first-writer-wins with no delete, so this body would be permanent and every hVM "+
					"precompile would answer from it.", i, j, len(in.Witness))
			}
		}
	}
}
