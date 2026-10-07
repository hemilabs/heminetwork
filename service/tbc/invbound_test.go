// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// hashN builds a distinct deterministic hash for index n.
func hashN(n int) chainhash.Hash {
	var h chainhash.Hash
	h[0] = byte(n)
	h[1] = byte(n >> 8)
	h[2] = byte(n >> 16)
	h[3] = byte(n >> 24)
	return h
}

// TestInvBlocksIsBounded verifies the cap on s.invBlocks. Nothing drains it
// during IBD or with AutoIndex off, so without the cap it only grows.
func TestInvBlocksIsBounded(t *testing.T) {
	s := &Server{}

	for i := range maxInvBlocks + 5000 {
		s.invInsertUnlocked(hashN(i))
	}

	if len(s.invBlocks) > maxInvBlocks {
		t.Fatalf("expected at most %d invBlocks, got %d",
			maxInvBlocks, len(s.invBlocks))
	}
}

// TestInvBlocksAdmitsNewEvictsOld verifies that at the cap a new hash is
// admitted and an old one evicted. If the map is full of hashes we already
// have, refusing the new one would leave the syncBlocks drain nothing to do.
func TestInvBlocksAdmitsNewEvictsOld(t *testing.T) {
	s := &Server{}

	for i := range maxInvBlocks {
		s.invInsertUnlocked(hashN(i))
	}
	if len(s.invBlocks) != maxInvBlocks {
		t.Fatalf("expected a full map of %d, got %d", maxInvBlocks, len(s.invBlocks))
	}

	fresh := hashN(999999)
	if !s.invInsertUnlocked(fresh) {
		t.Fatal("a new hash was reported as already present at the cap")
	}
	if _, ok := s.invBlocks[fresh]; !ok {
		t.Fatal("expected new hash in invBlocks at the cap")
	}
	if len(s.invBlocks) > maxInvBlocks {
		t.Fatalf("admitting the new hash grew the map to %d, past %d",
			len(s.invBlocks), maxInvBlocks)
	}
}

// TestInvInsertRejectsDuplicates verifies invInsertUnlocked returns false for
// a hash already recorded and true on insert; callers log off this return.
func TestInvInsertRejectsDuplicates(t *testing.T) {
	s := &Server{}
	h := hashN(1)

	if !s.invInsertUnlocked(h) {
		t.Fatal("first insert returned false, want true")
	}
	if s.invInsertUnlocked(h) {
		t.Fatal("duplicate insert returned true, want false")
	}
	if len(s.invBlocks) != 1 {
		t.Fatalf("duplicate was stored: len %d, want 1", len(s.invBlocks))
	}
}

// TestInvInsertOnNilMapDoesNotPanic verifies the nil-map guard for a Server
// built as a struct literal rather than by NewServer.
func TestInvInsertOnNilMapDoesNotPanic(t *testing.T) {
	s := &Server{}                // invBlocks is nil, not made by NewServer
	s.invInsertUnlocked(hashN(1)) // must not panic
	if len(s.invBlocks) != 1 {
		t.Fatalf("insert on a nil map stored %d entries, want 1", len(s.invBlocks))
	}
}

// TestInvInsertLargeBatchIsFast guards against a quadratic insert for a
// maximum-size inv. The limit is loose so it checks the complexity class,
// not the machine.
func TestInvInsertLargeBatchIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	s := &Server{}

	start := time.Now()
	for i := range wire.MaxInvPerMsg {
		s.invInsertUnlocked(hashN(i))
	}
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("inserting %d hashes took %v, expected under 2s",
			wire.MaxInvPerMsg, elapsed)
	}
	t.Logf("%d inserts in %v, final len %d", wire.MaxInvPerMsg, elapsed, len(s.invBlocks))
}
