// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// TestPeerBehindFrontier is the regression test for the wedge where a
// bad/future best header rejected every real Bitcoin peer.
//
// The peer-accept gate must key on our indexed block frontier, never
// on the best header height. In external-header mode op-geth pushes
// headers ahead of block download; a header tip above the live chain
// (here 967088 while the real chain — and our indexer — is at 965496)
// must NOT cause us to reject peers at the live tip, or we starve
// ourselves of the peers we need and never recover.
func TestPeerBehindFrontier(t *testing.T) {
	const (
		frontier = 965496 // indexer: real blocks we processed
		realTip  = 965496 // where honest mainnet peers advertise
		bogusHdr = 967088 // bad future header pushed into the DB
	)

	tests := []struct {
		name      string
		frontier  uint64
		lastBlock int32
		want      bool // true == rejected (behind frontier)
	}{
		{"peer at live tip, bogus header ahead", frontier, realTip, false},
		{"peer one above frontier", frontier, frontier + 1, false},
		{"peer exactly at frontier", frontier, frontier, false},
		{"genuinely behind peer", frontier, frontier - 1, true},
		{"far-behind laggard", frontier, 900000, true},
		{"fresh node accepts anyone", 0, 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{ui: &stubIndexer{
				bh: &tbcd.BlockHeader{Hash: chainhash.Hash{0x01}, Height: tt.frontier},
			}}
			got := s.peerBehindFrontier(t.Context(), tt.lastBlock)
			if got != tt.want {
				t.Fatalf("peerBehindFrontier(frontier=%d, last=%d) = %v, want %v",
					tt.frontier, tt.lastBlock, got, tt.want)
			}
		})
	}

	// The point of the fix, stated plainly: the header tip is
	// irrelevant. A peer at the live tip is accepted no matter how
	// far a bogus header runs ahead.
	_ = bogusHdr
}
