// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// M4 test-robustness round: properties derived from the ISSUE and Bitcoin merkle
// semantics, independently of the existing suite. Package-local names are all
// m4-prefixed to avoid colliding with merkle_test.go's helpers.

package tbc

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// m4Mutation stamps the active mutation into every test's output, so a PASS/FAIL line
// in a mutation matrix is self-describing and cannot be misfiled.
func m4Mutation(t *testing.T) {
	t.Helper()
	m := os.Getenv("M4_MUTATION")
	if m == "" {
		m = "none (pristine production code)"
	}
	t.Logf("### M4 MUTATION IN EFFECT: %s", m)
}

func m4Ser(tx *wire.MsgTx) []byte {
	var b bytes.Buffer
	if err := tx.SerializeNoWitness(&b); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// ---------------------------------------------------------------------------
// CVE-2017-12842 / BIP-54: the 64-byte leaf/node ambiguity, built for real.
//
// A transaction T of exactly 64 bytes whose serialization equals txid(P)||txid(Q)
// has txid(T) = dSHA256(txid(P)||txid(Q)) = HashMerkleBranches(P, Q) -- it IS an
// interior merkle node. So block[P,Q] and block[T] share a merkle root, share a
// block hash, and contain NO duplicate txid, which is precisely the collision
// family the duplicate-transaction guard cannot see.
//
// A 1-in/1-out transaction serializes to 60+s+p bytes (s = scriptSig len,
// p = pkScript len), so s+p = 4 for a 64-byte transaction. With s=4, p=0 the
// bytes T's parser must find at fixed offsets are:
//
//	offset  4 = 0x01  input count   -> lands in txid(P)[4]
//	offset 41 = 0x04  scriptSig len -> lands in txid(Q)[9]
//	offset 50 = 0x01  output count  -> lands in txid(Q)[18]
//	offset 59 = 0x00  pkScript len  -> lands in txid(Q)[27]
//
// so P costs ~2^8 grinding and Q ~2^24. Both were ground once (~41s) and the
// winning nonces are pinned below so this test is instant and deterministic.
// If btcd's serialization ever changes, the preconditions below fail loudly.
const (
	m4PNonce    = 643      // coinbase extraNonce giving txid(P)[4] == 0x01
	m4QLockTime = 25594653 // locktime giving txid(Q)[9,18,27] == 0x04,0x01,0x00
)

// m4ImpostorP is the honest coinbase that becomes the LEFT half of the impostor.
func m4ImpostorP() *wire.MsgTx {
	n := uint32(m4PNonce)
	m := wire.NewMsgTx(1)
	m.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0xffffffff},
		SignatureScript:  []byte{0x51, byte(n), byte(n >> 8), byte(n >> 16)},
		Sequence:         0xffffffff,
	})
	m.AddTxOut(&wire.TxOut{Value: 5000000000, PkScript: []byte{0x51}})
	return m
}

// m4ImpostorQ is the honest second transaction, the RIGHT half of the impostor.
func m4ImpostorQ() *wire.MsgTx {
	m := wire.NewMsgTx(1)
	m.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 7},
		SignatureScript:  []byte{0x51},
		Sequence:         0xfffffffe,
	})
	m.AddTxOut(&wire.TxOut{Value: 1234, PkScript: []byte{0x51, 0x52}})
	m.LockTime = m4QLockTime
	return m
}

// TestM4CVE201712842RealImpostorRejected is the test the existing
// TestMerkleRootRejectsNonCoinbaseFirst stands in for but does not perform.
//
// That test builds blockOf(tx(1), tx(2)) -- a body whose header root was computed
// FROM the forged body. No such header exists on the Bitcoin chain, so that shape
// is not independently exploitable: an attacker must match a REAL header's root.
// The only known way to do that without a duplicate txid is this 64-byte
// ambiguity. This test builds it.
func TestM4CVE201712842RealImpostorRejected(t *testing.T) {
	m4Mutation(t)

	P, Q := m4ImpostorP(), m4ImpostorQ()
	ph, qh := P.TxHash(), Q.TxHash()

	// --- Precondition 1: the ground bytes still land where the parser needs them.
	if ph[4] != 0x01 {
		t.Fatalf("precondition failed: txid(P)[4] = %#x, want 0x01 (T's input-count byte). "+
			"btcd's transaction serialization changed; re-grind m4PNonce.", ph[4])
	}
	if qh[9] != 0x04 || qh[18] != 0x01 || qh[27] != 0x00 {
		t.Fatalf("precondition failed: txid(Q)[9,18,27] = %#x,%#x,%#x, want 0x04,0x01,0x00. "+
			"btcd's transaction serialization changed; re-grind m4QLockTime.", qh[9], qh[18], qh[27])
	}
	if !blockchain.IsCoinBaseTx(P) {
		t.Fatal("precondition failed: P must be a coinbase so the HONEST block is well-formed")
	}

	// --- Precondition 2: T parses as a real 64-byte transaction.
	tb := append(append([]byte{}, ph[:]...), qh[:]...)
	if len(tb) != 64 {
		t.Fatalf("precondition failed: impostor is %d bytes, want 64", len(tb))
	}
	T := wire.NewMsgTx(1)
	if err := T.DeserializeNoWitness(bytes.NewReader(tb)); err != nil {
		t.Fatalf("precondition failed: the impostor does not parse as a transaction: %v", err)
	}
	if got := m4Ser(T); !bytes.Equal(got, tb) {
		t.Fatalf("precondition failed: impostor is not canonically serialized:\n got %x\nwant %x", got, tb)
	}

	// --- THE COLLISION, DEMONSTRATED. This is the assertion that makes the rest mean
	// anything: txid(T) is bit-for-bit the interior merkle node over (P, Q).
	th := T.TxHash()
	node := blockchain.HashMerkleBranches(&ph, &qh)
	if !th.IsEqual(&node) {
		t.Fatalf("precondition failed: the 64-byte leaf/node ambiguity did not reproduce.\n"+
			"txid(T)      = %v\nnode(P,Q)    = %v\n"+
			"If this ever fails the CVE-2017-12842 shape has changed and the coinbase guard "+
			"must be re-derived rather than deleted.", th, node)
	}
	// Independent restatement, not via btcd, so a btcd bug cannot make the collision
	// look real when it is not.
	s1 := sha256.Sum256(tb)
	s2 := sha256.Sum256(s1[:])
	if !bytes.Equal(s2[:], th[:]) {
		t.Fatalf("precondition failed: txid(T) is not dSHA256 of its own 64 bytes")
	}
	t.Logf("collision CONFIRMED: txid(T) = node(P,Q) = %v", th)

	// --- The two blocks: same header, same block hash, different bodies.
	root := blockchain.CalcMerkleRoot(btcutil.NewBlock(&wire.MsgBlock{
		Transactions: []*wire.MsgTx{P, Q},
	}).Transactions(), false)
	hdr := wire.BlockHeader{Version: 1, Bits: 0x207fffff, MerkleRoot: root}

	honest := btcutil.NewBlock(&wire.MsgBlock{Header: hdr, Transactions: []*wire.MsgTx{P, Q}})
	forged := btcutil.NewBlock(&wire.MsgBlock{Header: hdr, Transactions: []*wire.MsgTx{T}})

	fr := blockchain.CalcMerkleRoot(forged.Transactions(), false)
	if !fr.IsEqual(&root) {
		t.Fatalf("precondition failed: forged body roots to %v, honest header commits to %v; "+
			"they must collide or this test is not exercising the CVE", fr, root)
	}
	if !forged.Hash().IsEqual(honest.Hash()) {
		t.Fatalf("precondition failed: the forged body must carry the GENUINE block hash " +
			"(that is why the store cannot tell them apart)")
	}
	// The duplicate guard is structurally blind here: there is only one transaction.
	if len(forged.Transactions()) != 1 {
		t.Fatal("precondition failed: forged body must be a single transaction")
	}
	if blockchain.IsCoinBase(forged.Transactions()[0]) {
		t.Fatal("precondition failed: the impostor must NOT be a coinbase, or it proves nothing")
	}

	// --- The honest block must pass (no false reject).
	if err := checkBlockMerkleRoot(honest); err != nil {
		t.Fatalf("REGRESSION: the honest 2-transaction block was REFUSED: %v", err)
	}

	// --- The forged block must be rejected, and ONLY the coinbase guard can do it:
	// the root matches and there is no duplicate.
	err := checkBlockMerkleRoot(forged)
	if !errors.Is(err, ErrBlockMerkleMismatch) {
		t.Fatalf("A REAL CVE-2017-12842 64-BYTE IMPOSTOR WAS ACCEPTED (err=%v).\n"+
			"Its merkle root and block hash are identical to the honest block's and it contains "+
			"no duplicate transaction, so neither the root comparison nor the duplicate guard can "+
			"see it. Only the coinbase-first guard closes this. A body admitted here is stored "+
			"permanently under a real consensus-chain header hash (BlocksDB is first-writer-wins, "+
			"no delete) and every hVM precompile then answers from it.", err)
	}
	t.Logf("forged impostor correctly rejected: %v", err)
}

// TestM4SixtyFourByteCoinbaseIsAccepted is the false-reject control for the coinbase
// guard, and the one that stops the guard from being "fixed" the wrong way.
//
// 64-byte transactions are STILL consensus-valid on Bitcoin (BIP-54 would change
// that; they have merely been non-standard since 2019). Closing the ambiguity by
// banning 64-byte transactions would be a consensus DIVERGENCE from Bitcoin and a
// false reject on historical blocks. This pins that a 64-byte transaction that IS a
// valid coinbase is accepted.
func TestM4SixtyFourByteCoinbaseIsAccepted(t *testing.T) {
	m4Mutation(t)

	// 60 + s + p = 64 with s=4, p=0.
	cb := wire.NewMsgTx(1)
	cb.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0xffffffff},
		SignatureScript:  []byte{0x03, 0x01, 0x02, 0x03},
		Sequence:         0xffffffff,
	})
	cb.AddTxOut(&wire.TxOut{Value: 5000000000, PkScript: nil})
	if n := len(m4Ser(cb)); n != 64 {
		t.Fatalf("precondition failed: fixture coinbase is %d bytes, want exactly 64", n)
	}
	if !blockchain.IsCoinBaseTx(cb) {
		t.Fatal("precondition failed: fixture must be a valid coinbase")
	}

	b := btcutil.NewBlock(&wire.MsgBlock{Transactions: []*wire.MsgTx{cb}})
	root := blockchain.CalcMerkleRoot(b.Transactions(), false)
	blk := btcutil.NewBlock(&wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, MerkleRoot: root},
		Transactions: []*wire.MsgTx{cb},
	})
	if err := checkBlockMerkleRoot(blk); err != nil {
		t.Fatalf("a block whose coinbase is exactly 64 bytes was REFUSED: %v.\n"+
			"64-byte transactions are consensus-valid on Bitcoin today. Rejecting them is a "+
			"consensus divergence and, on a consensus path, a permanent silent fork.", err)
	}
}

// TestM4MerkleCollisionShapeModel pins the SHAPE MODEL the duplicate guard is
// derived from, including the negative controls. Without these, a reader cannot
// tell a real collision family from a coincidence, and the two collision tests in
// merkle_test.go look like arbitrary fixtures.
//
// Derivation: btcd duplicates the last element of any ODD row. A forged list
// reproduces the padded row at level L by repeating the trailing 2^L transactions.
// Therefore a collision exists iff SOME row is odd -- which is false exactly when
// the transaction count is a power of two.
func TestM4MerkleCollisionShapeModel(t *testing.T) {
	m4Mutation(t)

	mk := func(txs ...*wire.MsgTx) chainhash.Hash {
		return blockchain.CalcMerkleRoot(
			btcutil.NewBlock(&wire.MsgBlock{Transactions: txs}).Transactions(), false)
	}
	// distinct transactions; only txids matter
	n := func(i uint32) *wire.MsgTx {
		m := wire.NewMsgTx(1)
		m.LockTime = 1000 + i
		m.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{byte(i)}, Index: i},
			SignatureScript:  []byte{0x51}, Sequence: 0xffffffff,
		})
		m.AddTxOut(&wire.TxOut{Value: int64(i) + 1, PkScript: []byte{0x51}})
		return m
	}
	a, b, c, d, e, f := n(1), n(2), n(3), n(4), n(5), n(6)

	type shape struct {
		name          string
		honest, forge []*wire.MsgTx
		wantCollide   bool
		why           string
	}
	for _, s := range []shape{
		{
			"n=1 (power of two): [A] vs [A A]",
			[]*wire.MsgTx{a},
			[]*wire.MsgTx{a, a},
			false,
			"a single leaf IS the root; duplicating it introduces a level that did not exist",
		},
		{
			"n=2 (power of two): [A B] vs [A B B]",
			[]*wire.MsgTx{a, b},
			[]*wire.MsgTx{a, b, b},
			false,
			"row of 2 is even, nothing is duplicated, so there is no padded row to reproduce",
		},
		{
			"n=3: [A B C] vs [A B C C]",
			[]*wire.MsgTx{a, b, c},
			[]*wire.MsgTx{a, b, c, c},
			true,
			"level-0 row of 3 is odd: btcd duplicates C, which the forged list supplies explicitly",
		},
		{
			"n=4 (power of two): [A B C D] vs [A B C D D]",
			[]*wire.MsgTx{a, b, c, d},
			[]*wire.MsgTx{a, b, c, d, d},
			false,
			"every row (4 then 2) is even, so no duplication happens anywhere",
		},
		{
			"n=4 (power of two): [A B C D] vs [A B C D C D]",
			[]*wire.MsgTx{a, b, c, d},
			[]*wire.MsgTx{a, b, c, d, c, d},
			false,
			"power-of-two counts are immune to tail duplication at EVERY level",
		},
		{
			"n=5: [A B C D E] vs [A B C D E E]",
			[]*wire.MsgTx{a, b, c, d, e},
			[]*wire.MsgTx{a, b, c, d, e, e},
			true,
			"level-0 row of 5 is odd: duplicate the trailing 2^0 = 1 transaction",
		},
		{
			"n=6: [A..F] vs [A..F E F]",
			[]*wire.MsgTx{a, b, c, d, e, f},
			[]*wire.MsgTx{a, b, c, d, e, f, e, f},
			true,
			"level-0 row of 6 is even but level-1 row of 3 is odd: duplicate the trailing 2^1 = 2 transactions. NON-ADJACENT.",
		},
	} {
		hr, fr := mk(s.honest...), mk(s.forge...)
		got := hr.IsEqual(&fr)
		if got != s.wantCollide {
			t.Errorf("SHAPE MODEL WRONG for %s\n  honest root = %v\n  forged root = %v\n"+
				"  collide: got %v want %v\n  model says: %s\n"+
				"The duplicate guard is derived from this model. If the model is wrong the guard "+
				"may be guarding the wrong shapes -- re-derive it, do not adjust this table.",
				s.name, hr, fr, got, s.wantCollide, s.why)
			continue
		}
		t.Logf("ok  collide=%-5v  %s", got, s.name)
	}
}

// TestM4ServerBlockInsertAppliesNoMerkleCheck is a CHARACTERIZATION test of a real
// residual gap, not a proof of safety.
//
// The ISSUE names Server.BlockInsert specifically ("a bare store pass-through that
// applies NO validation"). The fix binds the Bitcoin P2P path (handleBlock), but
// Server.BlockInsert -- the EXPORTED embedder API -- still applies no merkle check;
// it is bound only at its caller. op-geth is the in-tree caller and does check, but
// with vm.CheckBTCBlockMerkleRoot, which has NO coinbase guard (see the op-geth
// half of this round). So the composed embedder path is strictly weaker than the
// Bitcoin P2P path against the 64-byte impostor.
//
// This test asserts the CURRENT behaviour so that if someone later adds the check
// here it fails and gets updated deliberately, rather than the gap being forgotten.
func TestM4ServerBlockInsertAppliesNoMerkleCheck(t *testing.T) {
	m4Mutation(t)

	P, Q := m4ImpostorP(), m4ImpostorQ()
	ph, qh := P.TxHash(), Q.TxHash()
	tb := append(append([]byte{}, ph[:]...), qh[:]...)
	T := wire.NewMsgTx(1)
	if err := T.DeserializeNoWitness(bytes.NewReader(tb)); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	root := blockchain.CalcMerkleRoot(btcutil.NewBlock(&wire.MsgBlock{
		Transactions: []*wire.MsgTx{P, Q},
	}).Transactions(), false)
	forged := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Bits: 0x207fffff, MerkleRoot: root},
		Transactions: []*wire.MsgTx{T},
	}

	// The forged body is exactly the one checkBlockMerkleRoot refuses.
	if err := checkBlockMerkleRoot(btcutil.NewBlock(forged)); err == nil {
		t.Fatal("precondition failed: the P2P path must refuse this body")
	}

	cfg := NewDefaultConfig()
	cfg.Network = "localnet"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	db := &recordingDB{}
	s.db = db

	// PIN the current behaviour in BOTH directions. An earlier version logged-and-returned when
	// BlockInsert rejected, so the test passed whether the gap was open OR closed -- it could not
	// fail on the property it names, which is the whole point of a characterization test. Measured:
	// adding a real merkle check to BlockInsert left it green.
	//
	// If this now fires, that is GOOD NEWS and a deliberate change: Server.BlockInsert has gained
	// validation. Delete this test and the "bound at its CALLER" language it documents, in the same
	// change.
	_, err = s.BlockInsert(t.Context(), forged)
	if err != nil {
		t.Fatalf("Server.BlockInsert REJECTED the impostor (%v). The exported embedder API used to "+
			"be a bare pass-through bound only at its caller, and this test pinned that. If the "+
			"validation was added deliberately, delete this test and update the surrounding docs.", err)
	}
	if db.inserts != 1 {
		t.Fatalf("expected the pass-through to store the body once, got %v", db.inserts)
	}
	t.Logf("CHARACTERIZED GAP: Server.BlockInsert stored a CVE-2017-12842 impostor body " +
		"that handleBlock refuses. The exported embedder API is bound only at its caller.")
}

// TestM4MainnetCorpusFalseReject is the false-reject control AT SCALE.
//
// A gate that refuses an honest block is worse than no gate: under Holocene an hVM
// INVALID does not halt the node, op-node builds a deposits-only replacement and the
// node forks SILENTLY. The existing control uses two testnet3 blocks. This runs every
// real mainnet body in the corpus through the production check, and separately
// asserts the coinbase-first premise holds on all of them.
func TestM4MainnetCorpusFalseReject(t *testing.T) {
	m4Mutation(t)

	// Corpus resolution: explicit override, legacy override, then the COMMITTED corpus.
	var dir string
	switch {
	case os.Getenv("HVM_BTC_CORPUS") != "":
		dir = os.Getenv("HVM_BTC_CORPUS")
	case os.Getenv("M4_CORPUS") != "":
		dir = os.Getenv("M4_CORPUS")
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
	ents, err := filepath.Glob(filepath.Join(dir, "*.bin"))
	if err != nil || len(ents) == 0 {
		t.Fatalf("no corpus bodies in %v (err=%v)", dir, err)
	}
	sort.Slice(ents, func(i, j int) bool {
		ai, _ := strconv.Atoi(strings.TrimSuffix(filepath.Base(ents[i]), ".bin"))
		aj, _ := strconv.Atoi(strings.TrimSuffix(filepath.Base(ents[j]), ".bin"))
		return ai < aj
	})

	var txCount, witnessBlocks, maxTx int
	for _, p := range ents {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %v: %v", p, err)
		}
		blk, err := btcutil.NewBlockFromBytes(raw)
		if err != nil {
			t.Fatalf("parse %v: %v", p, err)
		}
		txs := blk.Transactions()
		txCount += len(txs)
		if len(txs) > maxTx {
			maxTx = len(txs)
		}
		// The coinbase-first premise, measured rather than assumed.
		if !blockchain.IsCoinBase(txs[0]) {
			t.Fatalf("PREMISE VIOLATED: real mainnet body %v opens with a NON-coinbase. "+
				"The coinbase-first guard would false-reject it.", filepath.Base(p))
		}
		if err := checkBlockMerkleRoot(blk); err != nil {
			t.Fatalf("FALSE REJECT: real mainnet body %v (%d txs) was REFUSED: %v.\n"+
				"On a consensus path this is a PERMANENT SILENT FORK.", filepath.Base(p), len(txs), err)
		}
		// And again after the witness strip, which must not move the verdict.
		msg := blk.MsgBlock()
		if StripBlockWitness(msg) != 0 {
			witnessBlocks++
		}
		if err := checkBlockMerkleRoot(btcutil.NewBlock(msg)); err != nil {
			t.Fatalf("FALSE REJECT AFTER STRIP: %v: %v", filepath.Base(p), err)
		}
	}
	t.Logf("false-reject control: %d real mainnet bodies, %d transactions total, "+
		"largest %d txs, %d carried witness -- all ACCEPTED before and after stripping",
		len(ents), txCount, maxTx, witnessBlocks)
}
