// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/level"
)

// Re-announcing the header of an already downloaded block must not put it back
// into blocks-missing. The re-announce dedupes before the main insert loop;
// TestMainLoopDoesNotRequeueDownloaded covers the loop itself.
func TestDownloadedBlockNotRequeuedOnReannounce(t *testing.T) {
	db, ctx, wbh, _, _ := tornFixture(t)

	// The fixture leaves wbh (height 1) in blocks-missing with no body.
	inMissing := func() bool {
		bm, err := db.BlocksMissing(ctx, 16)
		if err != nil {
			t.Fatalf("blocks missing: %v", err)
		}
		h := wbh.BlockHash()
		for _, b := range bm {
			if b.Hash != nil && *b.Hash == h {
				return true
			}
		}
		return false
	}

	if !inMissing() {
		t.Fatal("premise: wbh should be in blocks-missing before its body is downloaded")
	}

	// Download the block body: this clears wbh from blocks-missing and makes
	// blocksDB.Has(wbh.Hash) true.
	blk := btcutil.NewBlock(&wire.MsgBlock{Header: *wbh})
	if _, err := db.BlockInsert(ctx, blk); err != nil {
		t.Fatalf("block insert: %v", err)
	}
	if inMissing() {
		t.Fatal("wbh should be cleared from blocks-missing after its body is downloaded")
	}

	// Re-announce the header: it is fully known, so the batch dedupes out.
	m := wire.NewMsgHeaders()
	if err := m.AddBlockHeader(wbh); err != nil {
		t.Fatalf("add header: %v", err)
	}
	_, _, _, _, err := db.BlockHeadersInsert(ctx, m, nil)
	if !errors.Is(err, database.ErrDuplicate) {
		t.Fatalf("re-announce of a fully-known downloaded header must "+
			"return DuplicateError, got %v", err)
	}

	// End state: the block must not be back in blocks-missing.
	if inMissing() {
		t.Fatal("a downloaded block was re-queued into blocks-missing " +
			"on header re-announce")
	}
}

// The main insert loop must check block presence by the 32-byte block hash,
// not the height/hash key, or a downloaded block is re-queued into
// blocks-missing. Rolling the tip back to the parent defeats the dedupe so the
// known header reaches the main loop.
func TestMainLoopDoesNotRequeueDownloaded(t *testing.T) {
	db, ctx, wbh, prevHash, _ := tornFixture(t)

	inMissing := func() bool {
		bm, err := db.BlocksMissing(ctx, 16)
		if err != nil {
			t.Fatalf("blocks missing: %v", err)
		}
		h := wbh.BlockHash()
		for _, b := range bm {
			if b.Hash != nil && *b.Hash == h {
				return true
			}
		}
		return false
	}

	// Download the body: clears wbh from blocks-missing and makes
	// blocksDB.Has(wbh.Hash) true.
	blk := btcutil.NewBlock(&wire.MsgBlock{Header: *wbh})
	if _, err := db.BlockInsert(ctx, blk); err != nil {
		t.Fatalf("block insert: %v", err)
	}
	if inMissing() {
		t.Fatal("premise: wbh should be cleared from blocks-missing after download")
	}

	// Roll the canonical tip back to the parent so the dedupe treats wbh as
	// incomplete and it goes through the main insert loop.
	prevRec, err := db.pool[level.BlockHeadersDB].Get(prevHash[:], nil)
	if err != nil {
		t.Fatalf("get parent record: %v", err)
	}
	if err := db.pool[level.BlockHeadersDB].Put([]byte(bhsCanonicalTipKey), prevRec, nil); err != nil {
		t.Fatalf("roll tip to parent: %v", err)
	}

	// Re-announce: the main loop's blocks-missing decision must see the body is
	// present and NOT re-queue it.
	reannounce(t, db, ctx, wbh)

	if inMissing() {
		t.Fatal("main-loop site: a downloaded block was re-queued into blocks-missing " +
			"when re-processed through the main insert loop (blocksDB.Has used the wrong key)")
	}
}

// Re-announcing a non-canonical fork header that handleBlockExpired removed
// from blocks-missing must dedupe, must not re-arm blocks-missing and must
// leave the canonical tip unchanged.
func TestForkAbandonNotResurrected(t *testing.T) {
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

	insert := func(h *wire.BlockHeader) {
		t.Helper()
		m := wire.NewMsgHeaders()
		if err := m.AddBlockHeader(h); err != nil {
			t.Fatalf("add header: %v", err)
		}
		if _, _, _, _, err := db.BlockHeadersInsert(ctx, m, nil); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// Canonical A and an equal-work fork F, both off genesis. A is inserted
	// first, so F does not overcome it and stays non-canonical (ITForkExtend).
	a := &wire.BlockHeader{Version: 1, PrevBlock: genHash, Bits: 0x1d00ffff, Nonce: 1}
	f := &wire.BlockHeader{Version: 1, PrevBlock: genHash, Bits: 0x1d00ffff, Nonce: 2}
	insert(a)
	insert(f)
	ah := a.BlockHash()
	fh := f.BlockHash()

	if best, err := db.BlockHeaderBest(ctx); err != nil {
		t.Fatalf("best: %v", err)
	} else if !best.Hash.IsEqual(&ah) {
		t.Fatalf("premise: A must be canonical, got %v", best.Hash)
	}

	inMissing := func(h chainhash.Hash) bool {
		bm, err := db.BlocksMissing(ctx, 64)
		if err != nil {
			t.Fatalf("blocks missing: %v", err)
		}
		for _, b := range bm {
			if b.Hash != nil && *b.Hash == h {
				return true
			}
		}
		return false
	}
	if !inMissing(fh) {
		t.Fatal("premise: F should be in blocks-missing after insert")
	}

	// Simulate handleBlockExpired abandoning the non-canonical fork.
	if err := db.BlockMissingDelete(ctx, 1, fh); err != nil {
		t.Fatalf("block missing delete: %v", err)
	}
	if inMissing(fh) {
		t.Fatal("premise: F should be cleared from blocks-missing after abandonment")
	}

	// Re-announce F: must dedupe and must NOT re-arm blocks-missing.
	m := wire.NewMsgHeaders()
	if err := m.AddBlockHeader(f); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, err = db.BlockHeadersInsert(ctx, m, nil)
	if !errors.Is(err, database.ErrDuplicate) {
		t.Fatalf("re-announcing an abandoned fork must dedupe (DuplicateError), got %v", err)
	}
	if inMissing(fh) {
		t.Fatal("an abandoned non-canonical fork was resurrected into " +
			"blocks-missing on re-announce")
	}
	// The canonical tip must be untouched.
	if best, err := db.BlockHeaderBest(ctx); err != nil {
		t.Fatalf("best: %v", err)
	} else if !best.Hash.IsEqual(&ah) {
		t.Fatalf("canonical tip moved to %v", best.Hash)
	}
}
