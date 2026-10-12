// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/level"
)

// TestTornHeaderWriteIsRepairedOnReannounce verifies that a header whose
// record exists but whose height-index entry does not is repaired when the
// header is announced again. BlockHeadersInsert commits the header records
// before the height index, so a crash between the two leaves this state, and
// a dedupe on the record alone would make it permanent.
func TestTornHeaderWriteIsRepairedOnReannounce(t *testing.T) {
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer db.Close()

	gen := chaincfg.TestNet3Params.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(ctx, gen, 0, nil); err != nil {
		t.Fatalf("genesis insert: %v", err)
	}
	best, err := db.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatalf("best: %v", err)
	}

	// One header extending genesis.
	wbh := &wire.BlockHeader{
		Version:   1,
		PrevBlock: best.Hash,
		Bits:      0x1d00ffff,
		Nonce:     42,
	}
	msg := wire.NewMsgHeaders()
	if err := msg.AddBlockHeader(wbh); err != nil {
		t.Fatalf("add header: %v", err)
	}
	hash := wbh.BlockHash()

	if _, _, _, _, err := db.BlockHeadersInsert(ctx, msg, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	bhs, err := db.BlockHeadersByHeight(ctx, best.Height+1)
	if err != nil || len(bhs) != 1 {
		t.Fatalf("precondition: header not at height %v: %v", best.Height+1, err)
	}

	// Simulate the torn write: delete only the height-index entry, as a
	// crash between bhsCommit and hhCommit would.
	hhDB := db.pool[level.HeightHashDB]
	hhKey := heightHashToKey(best.Height+1, hash[:])
	if err := hhDB.Delete(hhKey, nil); err != nil {
		t.Fatalf("delete height hash: %v", err)
	}
	if _, err := db.BlockHeadersByHeight(ctx, best.Height+1); err == nil {
		t.Fatal("precondition: the torn state was not created")
	}

	// Re-announce, exactly as a peer would.
	msg2 := wire.NewMsgHeaders()
	if err := msg2.AddBlockHeader(wbh); err != nil {
		t.Fatalf("add header: %v", err)
	}
	_, _, _, _, err = db.BlockHeadersInsert(ctx, msg2, nil)
	if err != nil {
		t.Logf("re-insert returned %v (an error is acceptable; repair is what matters)", err)
	}

	// The repair is the assertion.
	got, err := db.BlockHeadersByHeight(ctx, best.Height+1)
	if err != nil {
		t.Fatalf("the torn write was NOT repaired by re-announcing the header: "+
			"BlockHeadersByHeight(%v) = %v. The dedupe skipped on the header "+
			"record alone, so the height index is never rewritten and this node "+
			"reports the header missing for the life of the store.",
			best.Height+1, err)
	}
	if len(got) != 1 || got[0].Hash != hash {
		t.Fatalf("repaired to the wrong header: %v", got)
	}
}

// TestDuplicateHeaderStillDeduplicates verifies that a fully stored header is
// still reported as a duplicate rather than reinserted on every announcement.
func TestDuplicateHeaderStillDeduplicates(t *testing.T) {
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer db.Close()

	gen := chaincfg.TestNet3Params.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(ctx, gen, 0, nil); err != nil {
		t.Fatalf("genesis insert: %v", err)
	}
	best, err := db.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatalf("best: %v", err)
	}
	wbh := &wire.BlockHeader{
		Version:   1,
		PrevBlock: best.Hash,
		Bits:      0x1d00ffff,
		Nonce:     7,
	}
	mk := func() *wire.MsgHeaders {
		m := wire.NewMsgHeaders()
		if err := m.AddBlockHeader(wbh); err != nil {
			t.Fatalf("add header: %v", err)
		}
		return m
	}
	if _, _, _, _, err := db.BlockHeadersInsert(ctx, mk(), nil); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// The record and its height entry are both present, so this must dedupe.
	_, _, _, _, err = db.BlockHeadersInsert(ctx, mk(), nil)
	if err == nil {
		t.Fatal("a fully-present header was reinserted instead of deduplicated; " +
			"the dedupe is now a no-op and every re-announcement rewrites the store")
	}

	// And the height entry must be intact and unduplicated.
	got, err := db.BlockHeadersByHeight(ctx, best.Height+1)
	if err != nil {
		t.Fatalf("headers by height: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("height %v holds %v headers, want 1: the repair path is "+
			"writing a duplicate index entry", best.Height+1, len(got))
	}
}

// tornFixture inserts one header on top of genesis and returns the pieces a
// torn-write simulation needs.
func tornFixture(t *testing.T) (*ldb, context.Context, *wire.BlockHeader, chainhash.Hash, uint64) {
	t.Helper()
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	gen := chaincfg.TestNet3Params.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(ctx, gen, 0, nil); err != nil {
		t.Fatalf("genesis insert: %v", err)
	}
	best, err := db.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatalf("best: %v", err)
	}
	wbh := &wire.BlockHeader{
		Version: 1, PrevBlock: best.Hash, Bits: 0x1d00ffff, Nonce: 99,
	}
	m := wire.NewMsgHeaders()
	if err := m.AddBlockHeader(wbh); err != nil {
		t.Fatalf("add header: %v", err)
	}
	if _, _, _, _, err := db.BlockHeadersInsert(ctx, m, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return db, ctx, wbh, best.Hash, best.Height + 1
}

func reannounce(t *testing.T, db *ldb, ctx context.Context, wbh *wire.BlockHeader) {
	t.Helper()
	m := wire.NewMsgHeaders()
	if err := m.AddBlockHeader(wbh); err != nil {
		t.Fatalf("add header: %v", err)
	}
	// An error is fine; repair is what matters.
	_, _, _, _, _ = db.BlockHeadersInsert(ctx, m, nil)
}

// TestTornTipWriteIsRepairedOnReannounce verifies that a header stored in
// full except for the canonical tip is repaired when announced again. The tip
// is written last, so a crash or I/O error after the height-index commit
// leaves this state, and a presence-only dedupe would return DuplicateError
// forever.
func TestTornTipWriteIsRepairedOnReannounce(t *testing.T) {
	db, ctx, wbh, prevHash, height := tornFixture(t)
	hash := wbh.BlockHash()

	// Simulate the tip write never landing: roll the canonical tip back to
	// the parent, leaving the record and the height index in place.
	prevRec, err := db.pool[level.BlockHeadersDB].Get(prevHash[:], nil)
	if err != nil {
		t.Fatalf("get parent record: %v", err)
	}
	if err := db.pool[level.BlockHeadersDB].Put(
		[]byte(bhsCanonicalTipKey), prevRec, nil); err != nil {
		t.Fatalf("roll back tip: %v", err)
	}
	if b, err := db.BlockHeaderBest(ctx); err != nil || b.Height != height-1 {
		t.Fatalf("precondition: tip is %v, want %v", b.Height, height-1)
	}

	reannounce(t, db, ctx, wbh)

	best, err := db.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatalf("best after reannounce: %v", err)
	}
	if best.Height != height || best.Hash != hash {
		t.Fatalf("the tip was NOT repaired by re-announcing the header: still "+
			"at %v (%v), want %v (%v). The dedupe treats the header record "+
			"alone as proof the whole insert landed, so this state is "+
			"permanent.", best.Height, best.Hash, height, hash)
	}
}

// TestTornTipCdiffDistinctionRepairsHigherWorkShorterChain verifies that the
// torn-tip check compares cumulative work, not height. Chain A (two easy
// headers) is taller and chain B (one hard header) has more work. B is fully
// stored but the tip is rolled back to A; re-announcing B must make it the
// best header. A height comparison would treat B as known and dedupe it.
func TestTornTipCdiffDistinctionRepairsHigherWorkShorterChain(t *testing.T) {
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	gen := chaincfg.TestNet3Params.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(ctx, gen, 0, nil); err != nil {
		t.Fatalf("genesis insert: %v", err)
	}
	genHash := gen.BlockHash()

	insert := func(hdrs ...*wire.BlockHeader) {
		t.Helper()
		m := wire.NewMsgHeaders()
		for _, h := range hdrs {
			if err := m.AddBlockHeader(h); err != nil {
				t.Fatalf("add header: %v", err)
			}
		}
		if _, _, _, _, err := db.BlockHeadersInsert(ctx, m, nil); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// Chain A: two easy headers off genesis, taller (height 2) but low
	// work. It becomes the canonical tip.
	a1 := &wire.BlockHeader{Version: 1, PrevBlock: genHash, Bits: 0x1f00ffff, Nonce: 1}
	a1h := a1.BlockHash()
	a2 := &wire.BlockHeader{Version: 1, PrevBlock: a1h, Bits: 0x1f00ffff, Nonce: 2}
	a2h := a2.BlockHash()
	insert(a1, a2)

	// Chain B: one hard header off genesis, shorter (height 1) but far more
	// cumulative work. It forks and wins, so the tip moves to B.
	b1 := &wire.BlockHeader{Version: 1, PrevBlock: genHash, Bits: 0x1b00ffff, Nonce: 3}
	b1h := b1.BlockHash()
	insert(b1)

	if best, err := db.BlockHeaderBest(ctx); err != nil {
		t.Fatalf("best: %v", err)
	} else if !best.Hash.IsEqual(&b1h) {
		t.Fatalf("premise: higher-work B should be canonical after insert, got %v", best.Hash)
	}

	// Simulate a torn ITChainFork insert: B's records and height index
	// landed but the tip did not, so it stays on the taller, lower-work A.
	a2Rec, err := db.pool[level.BlockHeadersDB].Get(a2h[:], nil)
	if err != nil {
		t.Fatalf("get A tip record: %v", err)
	}
	if err := db.pool[level.BlockHeadersDB].Put([]byte(bhsCanonicalTipKey), a2Rec, nil); err != nil {
		t.Fatalf("roll tip to A: %v", err)
	}
	if best, err := db.BlockHeaderBest(ctx); err != nil {
		t.Fatalf("best: %v", err)
	} else if !best.Hash.IsEqual(&a2h) {
		t.Fatalf("premise: tip should be rolled back to A, got %v", best.Hash)
	}

	// Re-announce B. The dedupe must see that the stored tip carries less
	// work than B and redo the insert, republishing the tip.
	reannounce(t, db, ctx, b1)

	best, err := db.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatalf("best after reannounce: %v", err)
	}
	if !best.Hash.IsEqual(&b1h) {
		t.Fatalf("torn tip not repaired to the higher-work chain: best=%v, want B %v "+
			"(a height gate would leave the lower-work taller A canonical)", best.Hash, b1h)
	}
}

type tornDB struct {
	*ldb
	ctx context.Context
	t   *testing.T
	gen chainhash.Hash
}

func newTornDB(t *testing.T) *tornDB {
	t.Helper()
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	gen := chaincfg.TestNet3Params.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(ctx, gen, 0, nil); err != nil {
		t.Fatalf("genesis insert: %v", err)
	}
	return &tornDB{ldb: db, ctx: ctx, t: t, gen: gen.BlockHash()}
}

// tornChain returns n linked headers off prev with the given bits. tag keeps
// nonces, and therefore hashes, distinct across chains.
func tornChain(prev chainhash.Hash, n int, bits uint32, tag uint32) []*wire.BlockHeader {
	out := make([]*wire.BlockHeader, 0, n)
	for i := range n {
		h := &wire.BlockHeader{Version: 1, PrevBlock: prev, Bits: bits, Nonce: tag*1000 + uint32(i)}
		out = append(out, h)
		prev = h.BlockHash()
	}
	return out
}

func (f *tornDB) insert(hdrs ...*wire.BlockHeader) error {
	m := wire.NewMsgHeaders()
	for _, h := range hdrs {
		if err := m.AddBlockHeader(h); err != nil {
			f.t.Fatal(err)
		}
	}
	_, _, _, _, err := f.BlockHeadersInsert(f.ctx, m, nil)
	return err
}

func (f *tornDB) mustInsert(hdrs ...*wire.BlockHeader) {
	f.t.Helper()
	if err := f.insert(hdrs...); err != nil {
		f.t.Fatalf("insert: %v", err)
	}
}

func (f *tornDB) height(h *wire.BlockHeader) uint64 {
	f.t.Helper()
	bh, err := f.BlockHeaderByHash(f.ctx, h.BlockHash())
	if err != nil {
		f.t.Fatalf("lookup: %v", err)
	}
	return bh.Height
}

func (f *tornDB) hhKey(h *wire.BlockHeader) []byte {
	hash := h.BlockHash()
	return heightHashToKey(f.height(h), hash[:])
}

func (f *tornDB) inMissing(h *wire.BlockHeader) bool {
	f.t.Helper()
	ok, err := f.pool[level.BlocksMissingDB].Has(f.hhKey(h), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return ok
}

func (f *tornDB) best() chainhash.Hash {
	f.t.Helper()
	b, err := f.BlockHeaderBest(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return b.Hash
}

// TestTornParentIsNotExtended verifies that a batch starting one past a
// parent with no height-index entry is refused with NotFound instead of
// burying the damage under a new tip. Re-sending the parent then heals it.
func TestTornParentIsNotExtended(t *testing.T) {
	t.Run("parent missing its height-index entry", func(t *testing.T) {
		f := newTornDB(t)
		c := tornChain(f.gen, 2, 0x1d00ffff, 1) // [P, C]
		f.mustInsert(c[0])
		// Simulate a tear after the records commit: P keeps its record but
		// loses its height-index entry.
		if err := f.pool[level.HeightHashDB].Delete(f.hhKey(c[0]), nil); err != nil {
			t.Fatal(err)
		}
		err := f.insert(c[1])
		if !errors.Is(err, database.ErrNotFound) {
			t.Fatalf("extending a parent with no height-index entry = %v, want NotFound", err)
		}
		// The caller's re-request includes the parent; that heals it.
		f.mustInsert(c[0], c[1])
		if ok, _ := f.pool[level.HeightHashDB].Has(f.hhKey(c[0]), nil); !ok {
			t.Fatal("re-request did not heal the parent's height-index entry")
		}
		if b, want := f.best(), c[1].BlockHash(); !b.IsEqual(&want) {
			t.Fatalf("tip %v, want %v", b, want)
		}
	})
}

// TestForkParentAfterRemoveIsExtended verifies that the parent check does not
// refuse a complete fork. After BlockHeadersRemove rolls the tip back, a
// stored fork can be heavier than the new tip; extending it must succeed,
// since a NotFound here would send op-geth into a header-store rebuild.
func TestForkParentAfterRemoveIsExtended(t *testing.T) {
	f := newTornDB(t)
	a := tornChain(f.gen, 4, 0x1d00ffff, 3) // canonical, 4 x w
	f.mustInsert(a...)
	fk := tornChain(f.gen, 1, 0x1c7fff80, 4) // one header, ~2w: fork, lighter than a[3]
	f.mustInsert(fk...)
	if b, want := f.best(), a[3].BlockHash(); !b.IsEqual(&want) {
		t.Fatalf("premise: tip %v, want a[3]", b)
	}

	// Remove a[1..3]; tip falls back to a[0] (~1w), lighter than the fork.
	rm := wire.NewMsgHeaders()
	for _, h := range a[1:] {
		if err := rm.AddBlockHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.BlockHeadersRemove(f.ctx, rm, a[0], nil); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !f.inMissing(fk[0]) {
		t.Fatal("premise: the fork kept its blocks-missing entry")
	}

	child := tornChain(fk[0].BlockHash(), 1, 0x1d00ffff, 5)
	if err := f.insert(child...); err != nil {
		t.Fatalf("extending a complete fork heavier than the rolled-back tip = %v, want success", err)
	}
	if b, want := f.best(), child[0].BlockHash(); !b.IsEqual(&want) {
		t.Fatalf("tip %v, want the extended fork %v", b, want)
	}
}

var errInjectedCrash = errors.New("injected crash")

// injectCommitFault makes the next BlockHeadersInsert fail right after the
// named commit lands, then disarms itself.
func injectCommitFault(t *testing.T, after string) {
	t.Helper()
	prev := testInsertCommitFault
	armed := true
	testInsertCommitFault = func(stage string) error {
		if armed && stage == after {
			armed = false
			return errInjectedCrash
		}
		return nil
	}
	t.Cleanup(func() { testInsertCommitFault = prev })
}

// TestTornForkExtendLaterWinsQueuesBodies checks that a lighter (ForkExtend)
// batch whose insert dies after any of its commits still has every header in
// blocks-missing once the fork wins, by a child-only batch or by one that
// re-sends the prefix. Otherwise the winning fork's blocks are never
// downloaded.
//
// This fails if the height index commits before blocks-missing: a fault
// between the two leaves the first header deduping as complete with no
// blocks-missing entry.
func TestTornForkExtendLaterWinsQueuesBodies(t *testing.T) {
	for _, stage := range []string{"bhs", "bm", "hh"} {
		for _, childOnly := range []bool{true, false} {
			name := stage + "/prefix"
			if childOnly {
				name = stage + "/child-only"
			}
			t.Run(name, func(t *testing.T) {
				f := newTornDB(t)
				a := tornChain(f.gen, 2, 0x1d00ffff, 11) // canonical, tip = 2w
				f.mustInsert(a...)
				fk := tornChain(f.gen, 3, 0x1d00ffff, 12) // 1w, 2w, 3w

				// ForkExtend of the lighter first header, dying after `stage`.
				injectCommitFault(t, stage)
				if err := f.insert(fk[0]); !errors.Is(err, errInjectedCrash) {
					t.Fatalf("premise: injected fault not hit (%v)", err)
				}

				if childOnly {
					err := f.insert(fk[1], fk[2])
					if err != nil {
						if !errors.Is(err, database.ErrNotFound) {
							t.Fatalf("child-only batch = %v", err)
						}
						// The caller re-requests from our tip: the answer
						// now carries the prefix.
						f.mustInsert(fk...)
					}
				} else {
					f.mustInsert(fk...)
				}

				if b, want := f.best(), fk[2].BlockHash(); !b.IsEqual(&want) {
					t.Fatalf("tip %v, want the winning fork %v", b, want)
				}
				for i, h := range fk {
					if !f.inMissing(h) {
						t.Fatalf("fork header %d is a canonical ancestor with no "+
							"blocks-missing entry and no body: never downloaded", i)
					}
					hash := h.BlockHash()
					if ok, _ := f.pool[level.HeightHashDB].Has(heightHashToKey(f.height(h), hash[:]), nil); !ok {
						t.Fatalf("fork header %d has no height-index entry", i)
					}
				}
			})
		}
	}
}

// TestTornTipOnlyParentIsExtended: a crash after a batch's records,
// blocks-missing and height index land but before its tip Put leaves the tip
// one batch behind headers that descend from it. A child-only batch extending
// them must succeed, move the tip, and leave the parent in blocks-missing.
//
// This fails if the parent gate also requires the stored tip to carry the
// parent's work.
func TestTornTipOnlyParentIsExtended(t *testing.T) {
	f := newTornDB(t)
	c := tornChain(f.gen, 2, 0x1d00ffff, 13) // [P, C]

	injectCommitFault(t, "hh") // P complete except the tip Put
	if err := f.insert(c[0]); !errors.Is(err, errInjectedCrash) {
		t.Fatalf("premise: injected fault not hit (%v)", err)
	}
	if b := f.best(); !b.IsEqual(&f.gen) {
		t.Fatalf("premise: tip should still be genesis, got %v", b)
	}

	m := wire.NewMsgHeaders()
	if err := m.AddBlockHeader(c[1]); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := f.BlockHeadersInsert(f.ctx, m, nil); err != nil {
		t.Fatalf("child-only batch over a tip-torn parent: %v", err)
	}
	if b, want := f.best(), c[1].BlockHash(); !b.IsEqual(&want) {
		t.Fatalf("tip %v, want %v", b, want)
	}
	if !f.inMissing(c[0]) {
		t.Fatal("the tip-torn parent lost its blocks-missing entry")
	}
}

// TestForkParentWithBodyAfterRemoveIsExtended checks that after
// BlockHeadersRemove rolls the tip back below a heavier fork whose block was
// downloaded (so it has no blocks-missing entry), extending that fork
// succeeds, as op-geth reorgs require. This fails if the parent check refuses
// a heavier parent with no blocks-missing entry.
func TestForkParentWithBodyAfterRemoveIsExtended(t *testing.T) {
	f := newTornDB(t)
	a := tornChain(f.gen, 4, 0x1d00ffff, 14)
	f.mustInsert(a...)
	fk := tornChain(f.gen, 1, 0x1c7fff80, 15) // ~2w, lighter than a[3]
	f.mustInsert(fk...)

	if _, err := f.BlockInsert(f.ctx, btcutil.NewBlock(&wire.MsgBlock{Header: *fk[0]})); err != nil {
		t.Fatalf("block insert: %v", err)
	}
	if f.inMissing(fk[0]) {
		t.Fatal("premise: a downloaded block leaves blocks-missing")
	}

	rm := wire.NewMsgHeaders()
	for _, h := range a[1:] {
		if err := rm.AddBlockHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.BlockHeadersRemove(f.ctx, rm, a[0], nil); err != nil {
		t.Fatalf("remove: %v", err)
	}

	child := tornChain(fk[0].BlockHash(), 1, 0x1d00ffff, 16)
	if err := f.insert(child...); err != nil {
		t.Fatalf("extending a downloaded fork heavier than the rolled-back tip = %v, "+
			"want success", err)
	}
	if b, want := f.best(), child[0].BlockHash(); !b.IsEqual(&want) {
		t.Fatalf("tip %v, want %v", b, want)
	}
}

func genesisOnlyDB(t *testing.T, gen wire.BlockHeader, height uint64, diff *big.Int) (*ldb, context.Context) {
	t.Helper()
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	// Header only: no block body, and genesis insert writes no blocks-missing
	// entry. This is the ExternalHeaderMode effective-genesis shape.
	if err := db.BlockHeaderGenesisInsert(ctx, gen, height, diff); err != nil {
		t.Fatalf("genesis insert: %v", err)
	}
	return db, ctx
}

// TestGenesisTipReinsertIsDuplicate checks that re-announcing the (effective)
// genesis while it is the canonical tip returns DuplicateError and that
// [genesis, child] extends normally; op-geth reaches this through
// AddExternalHeaders with an effective genesis. The genesis has no
// blocks-missing entry or body,
// so it must dedupe on its height-index entry and the tip's cdiff; a redo
// would look up its never-stored parent and fail with NotFound.
func TestGenesisTipReinsertIsDuplicate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gen    wire.BlockHeader
		height uint64
		diff   *big.Int
	}{
		{"real genesis", chaincfg.TestNet3Params.GenesisBlock.Header, 0, nil},
		{"effective genesis", wire.BlockHeader{
			Version: 0x20000000, PrevBlock: [32]byte{0x42},
			Bits: 0x1d00ffff, Nonce: 7,
		}, 800000, new(big.Int).Lsh(big.NewInt(1), 80)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx := genesisOnlyDB(t, tc.gen, tc.height, tc.diff)

			// Re-announce the genesis alone: must dedupe.
			m := wire.NewMsgHeaders()
			g := tc.gen
			if err := m.AddBlockHeader(&g); err != nil {
				t.Fatal(err)
			}
			_, _, _, _, err := db.BlockHeadersInsert(ctx, m, nil)
			if !errors.Is(err, database.ErrDuplicate) {
				t.Fatalf("re-inserting the genesis tip = %v, want DuplicateError", err)
			}

			// A batch that starts at the genesis and extends it must insert.
			gh := tc.gen.BlockHash()
			child := &wire.BlockHeader{Version: 1, PrevBlock: gh, Bits: 0x1d00ffff, Nonce: 99}
			m2 := wire.NewMsgHeaders()
			for _, h := range []*wire.BlockHeader{&g, child} {
				if err := m2.AddBlockHeader(h); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, _, _, err := db.BlockHeadersInsert(ctx, m2, nil); err != nil {
				t.Fatalf("batch [genesis, child] = %v, want a normal extend", err)
			}
			best, err := db.BlockHeaderBest(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if ch := child.BlockHash(); !best.Hash.IsEqual(&ch) {
				t.Fatalf("tip = %v, want child %v", best.Hash, ch)
			}
		})
	}
}

// TestNoTornWindowOnExtend checks that a reader which can see the canonical
// tip can always resolve that tip's height.
//
// BlockHeadersInsert commits several independent leveldb transactions in
// sequence, so a concurrent reader can observe a half-written store. If the
// tip were published before the height index, a reader could hit this on any
// extend, and nextCanonicalBlockheader would turn it into syncBlocks' default
// panic.
func TestNoTornWindowOnExtend(t *testing.T) {
	cfg, _ := NewConfig("testnet3", t.TempDir(), "", "")
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	gen := chaincfg.TestNet3Params.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(ctx, gen, 0, nil); err != nil {
		t.Fatal(err)
	}
	best, _ := db.BlockHeaderBest(ctx)
	prev := best.Hash

	var fail, total atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				b, err := db.BlockHeaderBest(ctx)
				if err != nil {
					continue
				}
				total.Add(1)
				// Any error is a failure here: we just read this tip, so its
				// height must resolve. An empty height means the tip was
				// published before the index named it; a dangling index entry
				// means the index was committed before the records.
				if _, err := db.BlockHeadersByHeight(ctx, b.Height); err != nil {
					fail.Add(1)
				}
			}
		}()
	}
	deadline := time.Now().Add(4 * time.Second)
	n := uint32(0)
	for time.Now().Before(deadline) {
		m := wire.NewMsgHeaders()
		h := &wire.BlockHeader{Version: 1, PrevBlock: prev, Bits: 0x1d00ffff, Nonce: n}
		n++
		_ = m.AddBlockHeader(h)
		if _, _, _, _, err := db.BlockHeadersInsert(ctx, m, nil); err == nil {
			prev = h.BlockHash()
		}
	}
	close(stop)
	wg.Wait()
	tt, ff := total.Load(), fail.Load()
	pct := 0.0
	if tt > 0 {
		pct = 100 * float64(ff) / float64(tt)
	}
	t.Logf("extend: %d/%d reads failed = %.2f%%", ff, tt, pct)
	if ff != 0 {
		t.Fatalf("%d of %d reads (%.2f%%) could see the canonical tip but not "+
			"resolve its height. The tip is being published before the height "+
			"index names it, and nextCanonicalBlockheader turns that into "+
			"syncBlocks' default panic.", ff, tt, pct)
	}
	// Checked AFTER the torn-read assertion, so a torn read always fails. A
	// host too starved to interleave enough reads proves nothing either way.
	if tt < 1000 {
		t.Skipf("only %d reads observed; host too loaded to exercise the window", tt)
	}
}

// TestNoTornWindowOnFork checks that a hash reachable through the height index
// always has its header record; it fails if the index commits before the
// records.
//
// The writer adds sibling headers at the height the readers query, so every
// insert lands a new hash in the index the readers are walking. It moves one
// height up every siblingsPerHeight inserts because a reader resolves every
// sibling at its height, and an unbounded sibling set slows reads until too
// few are observed.
func TestNoTornWindowOnFork(t *testing.T) {
	const siblingsPerHeight = 128

	cfg, _ := NewConfig("testnet3", t.TempDir(), "", "")
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	gen := chaincfg.TestNet3Params.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(ctx, gen, 0, nil); err != nil {
		t.Fatal(err)
	}
	best, _ := db.BlockHeaderBest(ctx)

	var readHeight atomic.Uint64
	readHeight.Store(best.Height + 1)
	var fail, total atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				total.Add(1)
				if _, err := db.BlockHeadersByHeight(ctx, readHeight.Load()); err != nil &&
					strings.Contains(err.Error(), "headers by height") {
					fail.Add(1) // dangling index entry, not an empty height
				}
			}
		}()
	}
	deadline := time.Now().Add(4 * time.Second)
	parent := best.Hash
	n := uint32(0)
	for i := 0; time.Now().Before(deadline); i++ {
		m := wire.NewMsgHeaders()
		h := &wire.BlockHeader{Version: 1, PrevBlock: parent, Bits: 0x1d00ffff, Nonce: n}
		n++
		_ = m.AddBlockHeader(h)
		if _, _, _, _, err := db.BlockHeadersInsert(ctx, m, nil); err != nil {
			continue
		}
		if (i+1)%siblingsPerHeight == 0 {
			// Move up: new siblings hang off one of this height's headers.
			parent = h.BlockHash()
			readHeight.Add(1)
		}
	}
	close(stop)
	wg.Wait()
	tt, ff := total.Load(), fail.Load()
	pct := 0.0
	if tt > 0 {
		pct = 100 * float64(ff) / float64(tt)
	}
	t.Logf("fork: %d/%d reads failed = %.2f%%, %d inserts", ff, tt, pct, n)
	if ff != 0 {
		t.Fatalf("%d of %d reads (%.2f%%) found a hash in the height index "+
			"whose header record was absent. The index is being committed "+
			"before the records it names.", ff, tt, pct)
	}
	// Checked AFTER the torn-read assertion, so a torn read always fails.
	if tt < 1000 {
		t.Skipf("only %d reads observed; host too loaded to exercise the window", tt)
	}
}

// raceDB opens a fresh store seeded with the testnet3 genesis.
func raceDB(t *testing.T) (*ldb, context.Context) {
	t.Helper()
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	gen := chaincfg.TestNet3Params.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(ctx, gen, 0, nil); err != nil {
		t.Fatalf("genesis insert: %v", err)
	}
	return db, ctx
}

// TestBlockHeadersInsertConcurrentTipIsMaxWork: BlockHeadersInsert reads the
// canonical tip to classify fork vs extend and later Puts the new tip. The
// MetadataDB transaction, opened before the read and committed after the Put,
// holds goleveldb's per-DB write lock and serializes that, so a stale tip read
// cannot make a lower-work chain canonical.
//
// Each round inserts several competing tips off the current tip concurrently,
// one with strictly more work than the rest, and requires the max-work header
// to end up canonical. This is a -race smoke test; it does not reliably catch
// a tip access moved outside the transaction.
func TestBlockHeadersInsertConcurrentTipIsMaxWork(t *testing.T) {
	// Work decreases as the compact exponent grows, so index 0 is the unique
	// highest-work chain.
	tipBits := []uint32{0x1b00ffff, 0x1c00ffff, 0x1d00ffff, 0x1e00ffff, 0x1f00ffff}

	// Determine (and sanity-check the uniqueness of) the max-work tip.
	winner := 0
	bestWork := blockchain.CalcWork(tipBits[0])
	for i := 1; i < len(tipBits); i++ {
		w := blockchain.CalcWork(tipBits[i])
		if w.Cmp(bestWork) == 0 {
			t.Fatalf("test bug: tips %d and %d have equal work", winner, i)
		}
		if w.Cmp(bestWork) > 0 {
			bestWork, winner = w, i
		}
	}

	db, ctx := raceDB(t)

	best, err := db.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatalf("genesis best: %v", err)
	}
	parentHash := best.Hash

	const rounds = 50
	for round := 0; round < rounds; round++ {
		// Distinct nonce per round keeps every round's headers unique.
		nonceBase := uint32(round * 100)
		hashes := make([]chainhash.Hash, len(tipBits))
		hdrs := make([]*wire.BlockHeader, len(tipBits))
		for i, bits := range tipBits {
			h := &wire.BlockHeader{
				Version:   1,
				PrevBlock: parentHash,
				Bits:      bits,
				Nonce:     nonceBase + uint32(i),
			}
			hdrs[i] = h
			hashes[i] = h.BlockHash()
		}

		// Release all inserters together to maximise the interleaving of the
		// read-classify-write of the canonical tip.
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range hdrs {
			wg.Add(1)
			go func(h *wire.BlockHeader) {
				defer wg.Done()
				m := wire.NewMsgHeaders()
				if err := m.AddBlockHeader(h); err != nil {
					return
				}
				<-start
				// Only the resulting canonical tip matters.
				_, _, _, _, _ = db.BlockHeadersInsert(ctx, m, nil)
			}(hdrs[i])
		}
		close(start)
		wg.Wait()

		bhb, err := db.BlockHeaderBest(ctx)
		if err != nil {
			t.Fatalf("round %d: best: %v", round, err)
		}
		if !bhb.Hash.IsEqual(&hashes[winner]) {
			t.Fatalf("round %d: canonical tip = %v, want the max-work tip %v (bits %08x); "+
				"concurrent inserts raced the read-classify-write of the canonical tip",
				round, bhb.Hash, hashes[winner], tipBits[winner])
		}
		// The winner extends into the next round, so winners form a chain and
		// each round's max-work tip is the new global best.
		parentHash = hashes[winner]
	}
}
