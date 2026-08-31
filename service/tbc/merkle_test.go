// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

// realBlock loads one of the two real testnet3 blocks in testdata.
func realBlock(t *testing.T, name string) *btcutil.Block {
	t.Helper()
	h, err := os.ReadFile("testdata/" + name + ".hex")
	if err != nil {
		t.Fatalf("read %v: %v", name, err)
	}
	raw, err := hex.DecodeString(string(h))
	if err != nil {
		t.Fatalf("decode %v: %v", name, err)
	}
	b, err := btcutil.NewBlockFromBytes(raw)
	if err != nil {
		t.Fatalf("parse %v: %v", name, err)
	}
	return b
}

const (
	realBlockA = "0000000000000006200009cf36af2bbcb1362b887b4e2625113b6b44327435b8" // testnet3 3802508
	realBlockB = "00000000055a5c34a021ab3b1f3f6f0304b403775feb9e5a235dc7f724c5833f" // testnet3 3802509
)

// tx returns a minimal transaction whose txid is a function of nonce, so callers can build lists of
// distinct transactions without caring what is in them. Merkle binding is over txids only.
func tx(nonce uint32) *wire.MsgTx {
	m := wire.NewMsgTx(1)
	m.LockTime = nonce
	m.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{byte(nonce)}, Index: nonce},
		SignatureScript:  []byte{0x51},
		Sequence:         0xffffffff,
	})
	m.AddTxOut(&wire.TxOut{Value: int64(nonce) + 1, PkScript: []byte{0x51}})
	return m
}

// coinbase returns a transaction blockchain.IsCoinBase accepts: exactly one input spending the null
// outpoint. Every block must open with one, so every fixture that is meant to REACH the merkle
// comparison has to lead with this.
func coinbase(nonce uint32) *wire.MsgTx {
	m := wire.NewMsgTx(1)
	m.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0xffffffff},
		SignatureScript:  []byte{0x51, byte(nonce)},
		Sequence:         0xffffffff,
	})
	m.AddTxOut(&wire.TxOut{Value: int64(nonce) + 1, PkScript: []byte{0x51}})
	return m
}

// blockOf builds a block whose header commits to the merkle root of txs.
func blockOf(txs ...*wire.MsgTx) *btcutil.Block {
	mb := &wire.MsgBlock{Header: wire.BlockHeader{Version: 1, Bits: 0x207fffff}}
	mb.Transactions = append(mb.Transactions, txs...)
	b := btcutil.NewBlock(mb)
	mb.Header.MerkleRoot = blockchain.CalcMerkleRoot(b.Transactions(), false)
	return btcutil.NewBlock(mb)
}

// TestMerkleRootAcceptsRealBlocks is the false-reject control. A check on a consensus path that can
// refuse an honest block is worse than no check at all: under Holocene the refusing node does not
// halt, it forks silently. Both real blocks must pass, before AND after witness stripping.
func TestMerkleRootAcceptsRealBlocks(t *testing.T) {
	for _, name := range []string{realBlockA, realBlockB} {
		b := realBlock(t, name)
		n := len(b.Transactions())
		if n < 1000 {
			t.Fatalf("precondition failed: %v has only %v transactions; this control is meant to "+
				"exercise a real multi-thousand-transaction merkle tree", name, n)
		}
		if err := checkBlockMerkleRoot(b); err != nil {
			t.Fatalf("REGRESSION: real testnet3 block %v (%v txs) was REFUSED: %v", name, n, err)
		}

		// Stripping witness must not move the verdict. The header commits to the TXID tree, and
		// txids are witness-invariant -- that orthogonality is the reason both fixes can ship
		// together without either needing to know about the other. If this ever fails, one of the
		// two is wrong.
		msg := b.MsgBlock()
		stripped := StripBlockWitness(msg)
		// Without this the arm is shape (d): `stripped` would appear only in a format string, so a
		// StripBlockWitness that did nothing at all would leave the test green while the comment
		// still claimed it proved the before-and-after property. Measured: 30 and 4.
		if stripped == 0 {
			t.Fatalf("fixture %v carries no witness, so the strip arm below proves nothing", name)
		}
		after := btcutil.NewBlock(msg)
		if err := checkBlockMerkleRoot(after); err != nil {
			t.Fatalf("REGRESSION: %v was accepted with witness and REFUSED after stripping %v "+
				"transaction(s): %v. Witness is not committed to by Header.MerkleRoot, so this "+
				"must be impossible.", name, stripped, err)
		}
	}
}

// TestMerkleRootRejectsSubstitutedBody is the attack this check exists for.
//
// It asserts the premise first: a forged body under a genuine header produces the GENUINE BLOCK HASH,
// because the hash is over the 80-byte header alone. That is why ldb.BlockInsert -- which looks the
// header up by that hash and then writes first-writer-wins with no delete -- cannot tell the two
// apart, and why nothing downstream can repair it.
func TestMerkleRootRejectsSubstitutedBody(t *testing.T) {
	genuine := realBlock(t, realBlockA)

	forgedMsg := &wire.MsgBlock{Header: genuine.MsgBlock().Header} // genuine header, verbatim
	// Leads with a coinbase so the body reaches the MERKLE comparison rather than being turned away
	// by the coinbase guard -- otherwise this test would stop proving what it is named for.
	forgedMsg.Transactions = []*wire.MsgTx{coinbase(1), tx(2), tx(3)}
	forged := btcutil.NewBlock(forgedMsg)

	if !forged.Hash().IsEqual(genuine.Hash()) {
		t.Fatalf("precondition failed: forged body hashed to %v, genuine is %v. If these differ the "+
			"store would key them separately and this test proves nothing.",
			forged.Hash(), genuine.Hash())
	}
	if err := checkBlockMerkleRoot(genuine); err != nil {
		t.Fatalf("precondition failed: the genuine block must pass: %v", err)
	}

	err := checkBlockMerkleRoot(forged)
	if !errors.Is(err, ErrBlockMerkleMismatch) {
		t.Fatalf("a wholly substituted transaction list under a genuine header was ACCEPTED "+
			"(err=%v). This is the free, zero-proof-of-work forgery: every hVM precompile and the "+
			"PoP payout indexer would answer from it, permanently.", err)
	}
}

// TestMerkleRootRejectsDuplicatedTransactions covers CVE-2012-2459, and proves the fixture is
// dangerous before asserting that it is refused.
//
// btcd's tree duplicates the last hash when a level holds an odd number of nodes, so [A B C] and
// [A B C C] hash to the SAME root. A check that compared roots and nothing else would accept the
// second one. The first assertion below IS that danger, stated as an equality: if btcd ever stops
// duplicating, this test must fail loudly rather than quietly guarding nothing.
func TestMerkleRootRejectsDuplicatedTransactions(t *testing.T) {
	a, b, c := coinbase(1), tx(2), tx(3)

	honest := blockOf(a, b, c)
	dupMsg := &wire.MsgBlock{Header: honest.MsgBlock().Header} // same header, same committed root
	dupMsg.Transactions = []*wire.MsgTx{a, b, c, c}
	dup := btcutil.NewBlock(dupMsg)

	honestRoot := blockchain.CalcMerkleRoot(honest.Transactions(), false)
	dupRoot := blockchain.CalcMerkleRoot(dup.Transactions(), false)
	if !honestRoot.IsEqual(&dupRoot) {
		t.Fatalf("precondition failed: [A B C] roots to %v but [A B C C] roots to %v. They are "+
			"supposed to collide (CVE-2012-2459) -- that collision is the whole reason the "+
			"duplicate-transaction guard exists. If btcd changed, re-derive the guard rather than "+
			"deleting it.", honestRoot, dupRoot)
	}
	if !dup.Hash().IsEqual(honest.Hash()) {
		t.Fatalf("precondition failed: the duplicated body must carry the same block hash")
	}
	if err := checkBlockMerkleRoot(honest); err != nil {
		t.Fatalf("precondition failed: the honest 3-transaction block must pass: %v", err)
	}

	err := checkBlockMerkleRoot(dup)
	if !errors.Is(err, ErrBlockDuplicateTx) {
		t.Fatalf("a body with a duplicated transaction was ACCEPTED (err=%v). Its merkle root is "+
			"identical to the honest one, so the root comparison CANNOT catch it -- only the "+
			"duplicate guard can. The extended body would then be stored in place of the honest "+
			"one under the same block hash, permanently.", err)
	}
}

// TestMerkleRootRejectsReordering pins that ordering is part of the commitment. Reordering changes no
// txid, so a set-based check would miss it entirely.
func TestMerkleRootRejectsReordering(t *testing.T) {
	a, b, c, d := coinbase(1), tx(2), tx(3), tx(4)
	honest := blockOf(a, b, c, d)

	swapped := &wire.MsgBlock{Header: honest.MsgBlock().Header}
	swapped.Transactions = []*wire.MsgTx{a, c, b, d} // same set, coinbase still first, order changed
	if err := checkBlockMerkleRoot(btcutil.NewBlock(swapped)); !errors.Is(err, ErrBlockMerkleMismatch) {
		t.Fatalf("a reordered transaction list was ACCEPTED (err=%v)", err)
	}
}

// TestMerkleRootRejectsDegenerateBodies covers the shapes that have no transactions to bind.
func TestMerkleRootRejectsDegenerateBodies(t *testing.T) {
	if err := checkBlockMerkleRoot(nil); !errors.Is(err, ErrNilElement) {
		t.Fatalf("nil block: want ErrNilElement, got %v", err)
	}
	empty := btcutil.NewBlock(&wire.MsgBlock{Header: wire.BlockHeader{Version: 1}})
	if err := checkBlockMerkleRoot(empty); !errors.Is(err, ErrBlockMerkleMismatch) {
		t.Fatalf("zero-transaction block: want ErrBlockMerkleMismatch, got %v", err)
	}
}

// TestMerkleRootIsCheckedBeforeBlockInsert is a LINT-GRADE guard and is deliberately labelled as one.
//
// The behavioural tests above prove checkBlockMerkleRoot is correct; they do not prove handleBlock
// still calls it, or still calls it BEFORE the write. Deleting the call, or moving it below
// s.db.BlockInsert, leaves every test above green while the forgery path is fully reopened -- and
// BlocksDB has no delete, so anything admitted in that window is permanent.
//
// It parses the AST rather than searching text, because a text search is defeated by a comment
// mentioning the identifier. It also refuses to pass if it cannot find what it is guarding.
func TestMerkleRootIsCheckedBeforeBlockInsert(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tbc.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fd.Name.Name == "handleBlock" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("cannot find handleBlock in tbc.go -- this guard has silently stopped guarding " +
			"anything. If the Bitcoin P2P ingest path was renamed or moved, re-derive it.")
	}

	checkAt, insertAt := -1, -1
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == "checkBlockMerkleRoot" && checkAt < 0 {
				checkAt = fset.Position(call.Pos()).Offset
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == "BlockInsert" && insertAt < 0 {
				insertAt = fset.Position(call.Pos()).Offset
			}
		}
		return true
	})

	if checkAt < 0 {
		t.Fatal("handleBlock no longer calls checkBlockMerkleRoot. Nothing else on the Bitcoin P2P " +
			"path binds a block body to the header it arrived under: ldb.BlockInsert keys by the " +
			"HEADER hash and never looks at the transaction list, and CheckBlockSanity is gated " +
			"behind cfg.BlockSanity, which op-geth's embedded full node leaves false. Removing " +
			"this readmits a free, zero-proof-of-work whole-body forgery.")
	}
	if insertAt < 0 {
		t.Fatal("handleBlock no longer calls BlockInsert directly; this guard cannot check an " +
			"order it cannot see. If the write moved behind a wrapper, re-derive it.")
	}
	if checkAt > insertAt {
		t.Fatal("handleBlock calls checkBlockMerkleRoot AFTER BlockInsert. The forged body is " +
			"already in the store by then, and BlocksDB is first-writer-wins with no delete.")
	}

	// The check must not be GATED. A conditional would restore exactly the cfg.BlockSanity hole this
	// closes, and no behavioural test in the package can see the difference.
	//
	// Look only at each if statement's BODY and ELSE. The call's own idiomatic form --
	// `if err := checkBlockMerkleRoot(block); err != nil` -- puts it in the if's INIT, which executes
	// unconditionally; an earlier version of this guard did not make that distinction and failed on
	// correct code.
	// SHAPE, not just position. The positional checks above prove the call is present, unconditional
	// and ahead of the write; they cannot prove the error is ACTED ON. Measured: `_ = check(block)`,
	// `if err := check(block); err != nil && s.cfg.BlockSanity {`, and an `if` body that logs without
	// returning all pass every positional assertion while reopening the forgery. So require the
	// enclosing statement to be exactly `if err := checkBlockMerkleRoot(...); err != nil { ... return`.
	var enclosing *ast.IfStmt
	ast.Inspect(fn, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if ifs.Init != nil {
			a := fset.Position(ifs.Init.Pos()).Offset
			b := fset.Position(ifs.Init.End()).Offset
			if a <= checkAt && checkAt < b {
				enclosing = ifs
			}
		}
		return true
	})
	if enclosing == nil {
		t.Fatal("checkBlockMerkleRoot's result is not bound by an `if err := ...; err != nil` " +
			"statement. `_ = checkBlockMerkleRoot(block)` and a bare call both land here: the check " +
			"runs, its verdict is discarded, and the forged body is written anyway.")
	}
	bin, ok := enclosing.Cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		t.Fatalf("the guarding condition is %T, not `err != nil`. A conjunct such as "+
			"`err != nil && s.cfg.BlockSanity` moves the gate into the CONDITION, where the "+
			"body/else scan below cannot see it -- which reintroduces exactly the cfg.BlockSanity "+
			"hole this check closes.", enclosing.Cond)
	}
	if id, ok := bin.Y.(*ast.Ident); !ok || id.Name != "nil" {
		t.Fatalf("the guarding condition does not compare against nil: %v", enclosing.Cond)
	}
	returns := false
	ast.Inspect(enclosing.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.ReturnStmt); ok {
			returns = true
		}
		return true
	})
	if !returns {
		t.Fatal("the error branch does not return. Logging the mismatch and falling through leaves " +
			"the forged body to be written by s.db.BlockInsert a few lines later, and BlocksDB has " +
			"no delete.")
	}

	//
	// Scan EVERY branching construct, not just if. A `switch { case s.cfg.Network == …: <call> }`
	// gates the check exactly as an if does and was invisible to an if-only scan.
	var gatedAt int
	in := func(node ast.Node) bool {
		if node == nil {
			return false
		}
		return fset.Position(node.Pos()).Offset <= checkAt && checkAt < fset.Position(node.End()).Offset
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		var body, els ast.Node
		switch g := n.(type) {
		case *ast.IfStmt:
			body, els = g.Body, g.Else
		case *ast.SwitchStmt:
			body = g.Body
		case *ast.TypeSwitchStmt:
			body = g.Body
		case *ast.SelectStmt:
			body = g.Body
		case *ast.ForStmt:
			body = g.Body
		case *ast.RangeStmt:
			body = g.Body
		default:
			return true
		}
		if in(body) || in(els) {
			gatedAt = fset.Position(n.Pos()).Line
		}
		return true
	})
	if gatedAt != 0 {
		t.Fatalf("the checkBlockMerkleRoot call is inside the body of a branching statement at "+
			"tbc.go:%v. "+
			"It must be unconditional: gating it reintroduces the cfg.BlockSanity hole, where a "+
			"default-configured op-geth full node performs no body validation at all on the Bitcoin "+
			"P2P path.", gatedAt)
	}
}

// recordingDB is a tbcd.Database that records block writes and nothing else. The embedded interface is
// nil, so any method this test does not implement panics loudly rather than silently succeeding.
type recordingDB struct {
	tbcd.Database
	inserts int
	// last is the block handed to BlockInsert, kept so a test can inspect WHAT WAS STORED rather
	// than only whether a write happened. That distinction is what binds handleBlock's witness-strip
	// CALL SITE: a test that calls StripBlockWitness itself stays green when the call is deleted from
	// handleBlock, because it exercises the function and not the caller.
	last *btcutil.Block
}

func (r *recordingDB) BlockInsert(_ context.Context, b *btcutil.Block) (int64, error) {
	r.inserts++
	r.last = b
	return 0, nil
}

// BlocksMissing is reached by the `defer go s.syncBlocks(ctx)` that handleBlock runs on every path,
// including the error path. Returning an error makes syncBlocks log and return instead of walking
// further into the nil embedded interface.
func (r *recordingDB) BlocksMissing(_ context.Context, _ int) ([]tbcd.BlockIdentifier, error) {
	return nil, errors.New("recordingDB: no blocks missing")
}

// TestHandleBlockRefusesForgedBodyBehaviourally is the test the AST guard cannot be.
//
// TestMerkleRootIsCheckedBeforeBlockInsert proves the call is PRESENT, UNCONDITIONAL and TEXTUALLY
// AHEAD of the write. It cannot prove the error STOPS the write, because that is a data-flow property
// and the guard only reads positions. Three independent review passes found the same hole: replacing
// `return fmt.Errorf(...)` with `log.Errorf(...)`, or writing `_ = checkBlockMerkleRoot(block)`, leaves
// the entire package green while the forgery path is fully reopened. So does moving the gate into the
// if's CONDITION (`err != nil && s.cfg.BlockSanity`), which the guard deliberately cannot see because
// the call legitimately lives in the if's Init.
//
// This test closes all of those at once by asserting the OUTCOME rather than the shape: a forged body
// must produce an error AND must not reach the store. It is also the only test in the package that
// calls handleBlock at all.
func TestHandleBlockRefusesForgedBodyBehaviourally(t *testing.T) {
	genuine := realBlock(t, realBlockA)

	// REALISTIC, deliberately. An earlier version drove a 3-transaction witness-free body on localnet
	// with a nil peer and nil raw bytes -- and any gate whose predicate happened to be true for that
	// one configuration survived. Measured survivors included "skip the check when the body carried
	// witness" (which would disable the defence for essentially every post-2017 block) and "enforce
	// only on localnet". So the forged body is now the REAL block with one transaction replaced: 3,478
	// transactions, coinbase intact, duplicate-free, and carrying witness.
	forged := &wire.MsgBlock{Header: genuine.MsgBlock().Header} // genuine header, verbatim
	forged.Transactions = slices.Clone(genuine.MsgBlock().Transactions)
	forged.Transactions[1] = tx(0xbad)
	if n := len(forged.Transactions); n < 1000 {
		t.Fatalf("precondition failed: the forged body must be realistically sized, got %v txs", n)
	}
	if StripBlockWitness(&wire.MsgBlock{
		Header:       forged.Header,
		Transactions: slices.Clone(forged.Transactions),
	}) == 0 {
		t.Fatal("precondition failed: the forged body must carry witness, or a gate conditioned on " +
			"witness would survive this test")
	}
	if !btcutil.NewBlock(forged).Hash().IsEqual(genuine.Hash()) {
		t.Fatal("precondition failed: the forged body must carry the genuine block hash")
	}

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

	err = s.handleBlock(ctx, nil, forged, nil)
	if !errors.Is(err, ErrBlockMerkleMismatch) {
		t.Fatalf("handleBlock accepted a forged body under a genuine header (err=%v). Every hVM "+
			"precompile and the PoP payout indexer would answer from it, permanently: BlocksDB is "+
			"first-writer-wins with no delete.", err)
	}
	if db.inserts != 0 {
		t.Fatalf("handleBlock REPORTED an error but still wrote the forged body to the store "+
			"(%v insert(s)). The merkle verdict is being computed and discarded.", db.inserts)
	}

	// The genuine body under the same header must still be written, or the check is a liveness break.
	if err := s.handleBlock(ctx, nil, genuine.MsgBlock(), nil); err != nil {
		t.Fatalf("handleBlock REFUSED the genuine body: %v", err)
	}
	if db.inserts != 1 {
		t.Fatalf("the genuine body must be stored exactly once; got %v insert(s)", db.inserts)
	}
}

// TestMerkleRootRejectsOneTransactionForgery covers the CHEAPEST forgery shape.
//
// A one-transaction body needs no tree at all: the merkle root IS the single txid. A `len(txs) == 1`
// short-circuit therefore looks like a harmless optimisation and passes every other test in this file,
// because all the other forged fixtures carry three or four transactions.
func TestMerkleRootRejectsOneTransactionForgery(t *testing.T) {
	genuine := realBlock(t, realBlockA)
	forged := &wire.MsgBlock{Header: genuine.MsgBlock().Header}
	forged.Transactions = []*wire.MsgTx{coinbase(7)}
	if err := checkBlockMerkleRoot(btcutil.NewBlock(forged)); !errors.Is(err, ErrBlockMerkleMismatch) {
		t.Fatalf("a single-transaction substituted body was ACCEPTED (err=%v)", err)
	}
}

// TestMerkleRootRejectsNonAdjacentDuplicates pins that the duplicate scan is set-based, not
// pairwise-adjacent.
//
// The exhaustive shape enumeration over every equality pattern of length <= 13 shows the collision
// family is not limited to a duplicated tail: [A B C D E F] and [A B C D E F E F] share a root, and
// its duplicates are NOT adjacent. A guard that only compared neighbours would pass the [A B C]/
// [A B C C] case this file already covers and still admit this one.
func TestMerkleRootRejectsNonAdjacentDuplicates(t *testing.T) {
	a, b, c, d, e, f := coinbase(1), tx(2), tx(3), tx(4), tx(5), tx(6)
	honest := blockOf(a, b, c, d, e, f)

	dupMsg := &wire.MsgBlock{Header: honest.MsgBlock().Header}
	dupMsg.Transactions = []*wire.MsgTx{a, b, c, d, e, f, e, f}
	dup := btcutil.NewBlock(dupMsg)

	honestRoot := blockchain.CalcMerkleRoot(honest.Transactions(), false)
	dupRoot := blockchain.CalcMerkleRoot(dup.Transactions(), false)
	if !honestRoot.IsEqual(&dupRoot) {
		t.Fatalf("precondition failed: [A B C D E F] roots to %v but [A B C D E F E F] roots to %v; "+
			"they are supposed to collide, and that collision is what this test guards", honestRoot, dupRoot)
	}
	if err := checkBlockMerkleRoot(dup); !errors.Is(err, ErrBlockDuplicateTx) {
		t.Fatalf("a body with NON-ADJACENT duplicated transactions was ACCEPTED (err=%v)", err)
	}
}

// TestMerkleRootRejectsNonCoinbaseFirst pins the guard that closes the 64-byte leaf/node confusion.
//
// A 64-byte transaction whose serialization is exactly txid(P)||txid(Q) is indistinguishable from an
// interior tree node, so [P Q] and [T] share a root with NO duplicate txid -- the one collision family
// the duplicate scan cannot see. The impostor is always at index 0 and can never be a valid coinbase,
// so requiring a coinbase first closes it. Bitcoin requires one anyway.
func TestMerkleRootRejectsNonCoinbaseFirst(t *testing.T) {
	honest := blockOf(coinbase(1), tx(2))
	if err := checkBlockMerkleRoot(honest); err != nil {
		t.Fatalf("precondition failed: a coinbase-led block must pass: %v", err)
	}

	noCB := blockOf(tx(1), tx(2)) // merkle-consistent, but opens with a non-coinbase
	if err := checkBlockMerkleRoot(noCB); !errors.Is(err, ErrBlockMerkleMismatch) {
		t.Fatalf("a merkle-consistent body whose first transaction is NOT a coinbase was ACCEPTED "+
			"(err=%v); this is the shape a 64-byte node impostor takes", err)
	}
}
