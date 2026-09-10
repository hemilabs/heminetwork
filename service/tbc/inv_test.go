// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"net"
	"slices"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
)

// TestHandleInvKeepsScanningPastKnownBlock is the regression test for
// the wedge where an inv listing several blocks was abandoned at the
// first one already known.
//
// A peer announced two blocks found seconds apart in one inv.  We
// already had the first, so handleInv returned instead of continuing,
// and the second -- which we still needed -- was never queued.  The
// node then had no way to learn about that block and stalled at its
// current tip.
func TestHandleInvKeepsScanningPastKnownBlock(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	// One real header in the DB, so its hash is "known".
	genesis := chaincfg.MainNetParams.GenesisBlock.Header
	chain := makeChain(1, genesis, chaincfg.MainNetParams.PowLimitBits,
		10*time.Minute)
	insertHeaders(t, s, chain)
	known := chain[0].BlockHash()

	// A second header that was never inserted, so its hash is
	// "unknown" -- the block we still need.
	unknownHdr := makeChain(1, *chain[0], chaincfg.MainNetParams.PowLimitBits,
		10*time.Minute)[0]
	unknown := unknownHdr.BlockHash()

	// Sanity: the DB agrees on what is and isn't known.
	if _, _, err := s.BlockHeaderByHash(t.Context(), known); err != nil {
		t.Fatalf("known header should be in the db: %v", err)
	}
	if _, _, err := s.BlockHeaderByHash(t.Context(), unknown); err == nil {
		t.Fatal("unknown header should not be in the db")
	}

	// inv order matters: the known block comes first, exactly the
	// case that used to abort the scan.
	msg := wire.NewMsgInv()
	for _, h := range []chainhash.Hash{known, unknown} {
		if err := msg.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &h)); err != nil {
			t.Fatal(err)
		}
	}

	// p is only touched for logging on a block-only inv with the
	// mempool disabled (cfg is empty), so nil is safe here.
	if err := s.handleInv(t.Context(), nil, msg, nil); err != nil {
		t.Fatalf("handleInv: %v", err)
	}

	// The block we lacked must be queued for download; the one we
	// already had must not.
	s.mtx.Lock()
	queued := slices.ContainsFunc(s.invBlocks, func(h *chainhash.Hash) bool {
		return h.IsEqual(&unknown)
	})
	knownQueued := slices.ContainsFunc(s.invBlocks, func(h *chainhash.Hash) bool {
		return h.IsEqual(&known)
	})
	s.mtx.Unlock()

	if !queued {
		t.Fatal("block announced after a known block was dropped from the inv scan")
	}
	if knownQueued {
		t.Fatal("already-known block should not have been queued")
	}
}

// TestHandleInvEmpty covers the empty-inv guard.
func TestHandleInvEmpty(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)
	if err := s.handleInv(t.Context(), nil, wire.NewMsgInv(), nil); err != nil {
		t.Fatalf("handleInv empty: %v", err)
	}
}

// TestHeadersRecoveryUsesHaveLocator guards the fix for the second half
// of the wedge.
//
// After indexing, syncBlocks recovers missed headers with
// s.pm.All(ctx, s.headersPeer).  It must NOT build the getheaders from
// the hashes it is missing.  A getheaders locator is a list of blocks
// the sender already has, and the peer replies with the headers that
// follow the first one it recognizes -- so a missing hash makes the
// peer start after the block we need, which is never delivered.  This
// checks that headersPeer, the function recovery uses, locates from our
// best (owned) header.
func TestHeadersRecoveryUsesHaveLocator(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	// Advance the tip a few blocks so best != genesis.
	chain := makeChain(3, chaincfg.MainNetParams.GenesisBlock.Header,
		chaincfg.MainNetParams.PowLimitBits, 10*time.Minute)
	insertHeaders(t, s, chain)
	best := chain[len(chain)-1].BlockHash()

	// A real peer over a pipe; we read what headersPeer sends.
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	p, err := rawpeer.NewFromConn(c1, wire.MainNet, wire.AddrV2Version, 1)
	if err != nil {
		t.Fatal(err)
	}

	go s.headersPeer(t.Context(), p)

	if err := c2.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, msg, _, err := wire.ReadMessageWithEncodingN(c2, wire.AddrV2Version,
		wire.MainNet, wire.LatestEncoding)
	if err != nil {
		t.Fatalf("read getheaders: %v", err)
	}
	gh, ok := msg.(*wire.MsgGetHeaders)
	if !ok {
		t.Fatalf("got %T, want *wire.MsgGetHeaders", msg)
	}

	if len(gh.BlockLocatorHashes) == 0 {
		t.Fatal("getheaders has no block locator")
	}
	// The locator must be a header we own (best), never a hash we are
	// missing.
	if !gh.BlockLocatorHashes[0].IsEqual(&best) {
		t.Fatalf("locator = %v, want best owned header %v",
			gh.BlockLocatorHashes[0], best)
	}
	for _, h := range gh.BlockLocatorHashes {
		if _, _, err := s.BlockHeaderByHash(t.Context(), *h); err != nil {
			t.Fatalf("locator hash %v is not in our db; a getheaders "+
				"locator must list blocks we already have", h)
		}
	}
}
