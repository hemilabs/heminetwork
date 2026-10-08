// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
	"github.com/hemilabs/heminetwork/v2/ttl"
)

// newSyncServer returns a server with n canonical headers and no
// blocks, so every header has a blocks missing entry.
func newSyncServer(t *testing.T, n int) (*Server, []*wire.BlockHeader) {
	t.Helper()

	params := checkpointParams()
	s := newDifficultyTestServer(t, params)
	chain := makeChain(n, params.GenesisBlock.Header, params.PowLimitBits,
		10*time.Minute)
	insertHeaders(t, s, chain)

	var err error
	s.blocks, err = ttl.New(defaultPendingBlocks, true)
	if err != nil {
		t.Fatal(err)
	}
	s.pm, err = NewPeerManager(wire.TestNet, []string{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	return s, chain
}

// addPipePeer adds a connected peer to the peer manager and returns it
// with a channel that receives every block hash it is asked for.
func addPipePeer(t *testing.T, s *Server, name string, getData chan<- chainhash.Hash) *rawpeer.RawPeer {
	t.Helper()

	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	p, err := rawpeer.NewFromConn(c1, wire.TestNet, wire.AddrV2Version, 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			_, msg, _, err := wire.ReadMessageWithEncodingN(c2,
				wire.AddrV2Version, wire.TestNet, wire.LatestEncoding)
			if err != nil {
				return
			}
			if gd, ok := msg.(*wire.MsgGetData); ok {
				for _, iv := range gd.InvList {
					getData <- iv.Hash
				}
			}
		}
	}()

	s.pm.mtx.Lock()
	s.pm.peers[name] = p
	s.pm.mtx.Unlock()
	return p
}

// collect reads block requests until want arrive or quiet passes
// without one.
func collect(getData <-chan chainhash.Hash, want int, quiet time.Duration) map[chainhash.Hash]struct{} {
	got := make(map[chainhash.Hash]struct{})
	for {
		if want >= 0 && len(got) >= want {
			// Give stray extra requests a moment to show up.
			quiet = 200 * time.Millisecond
			want = -1
		}
		select {
		case h := <-getData:
			got[h] = struct{}{}
		case <-time.After(quiet):
			return got
		}
	}
}

// TestSyncBlocksRefill checks that syncBlocks fills every free download
// slot, reading past the blocks already in flight.
func TestSyncBlocksRefill(t *testing.T) {
	tests := []struct {
		name     string
		headers  int // canonical headers, all missing
		inFlight int // lowest missing blocks already being downloaded
		want     int // new requests
	}{
		{"nothing in flight", 200, 0, defaultPendingBlocks},
		{"half the window in flight", 200, defaultPendingBlocks / 2, defaultPendingBlocks / 2},
		{"most of the window in flight", 200, defaultPendingBlocks - 1, 1},
		{"window full", 200, defaultPendingBlocks, 0},
		{"fewer missing than free slots", 10, 0, 10},
		{"all missing in flight", 10, 10, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, chain := newSyncServer(t, tt.headers)
			getData := make(chan chainhash.Hash, 2*defaultPendingBlocks)
			p := addPipePeer(t, s, "peer", getData)

			inFlight := make(map[chainhash.Hash]struct{}, tt.inFlight)
			for _, h := range chain[:tt.inFlight] {
				hash := h.BlockHash()
				inFlight[hash] = struct{}{}
				s.blocks.Put(t.Context(), time.Hour, hash.String(), p,
					nil, nil)
			}

			s.syncBlocks(t.Context())

			got := collect(getData, tt.want, 2*time.Second)
			if len(got) != tt.want {
				t.Fatalf("requests %v, want %v", len(got), tt.want)
			}
			// The new requests are the lowest blocks not in flight.
			for _, h := range chain[tt.inFlight : tt.inFlight+tt.want] {
				if _, ok := got[h.BlockHash()]; !ok {
					t.Fatalf("block %v not requested", h.BlockHash())
				}
			}
			for h := range inFlight {
				if _, ok := got[h]; ok {
					t.Fatalf("block %v requested while in flight", h)
				}
			}
			if l := s.blocks.Len(); l != tt.inFlight+tt.want {
				t.Fatalf("pending %v, want %v", l, tt.inFlight+tt.want)
			}
		})
	}
}

// TestBlockExpiredRefill checks that an expired block request refills
// the download window, whether the expired block was dropped as a fork
// or retried as canonical, and that nothing is sent on shutdown.
func TestBlockExpiredRefill(t *testing.T) {
	tests := []struct {
		name      string
		fork      bool // expire a fork block instead of a canonical one
		cancelled bool // expire during shutdown
	}{
		{name: "fork block expired", fork: true},
		{name: "canonical block expired"},
		{name: "fork block expired during shutdown", fork: true, cancelled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, chain := newSyncServer(t, 10)

			// A one block fork off genesis: less work, not canonical,
			// but it has a blocks missing entry like any header.
			fork := makeChain(1, chaincfg.RegressionNetParams.GenesisBlock.Header,
				chaincfg.RegressionNetParams.PowLimitBits, 11*time.Minute)
			insertHeaders(t, s, fork)
			forkHash := fork[0].BlockHash()

			getData := make(chan chainhash.Hash, 2*defaultPendingBlocks)
			a := addPipePeer(t, s, "a", getData)
			addPipePeer(t, s, "b", getData)

			expired := chain[0].BlockHash()
			if tt.fork {
				expired = forkHash
			}

			ctx := t.Context()
			if tt.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			s.blockExpired(ctx, expired.String(), a)

			if tt.cancelled {
				if got := collect(getData, 0, 500*time.Millisecond); len(got) != 0 {
					t.Fatalf("requests sent during shutdown: %v", len(got))
				}
				return
			}

			// Every missing block is requested again: 10 canonical
			// blocks, plus the fork block unless it was dropped.
			want := len(chain) + 1
			if tt.fork {
				want = len(chain)
			}
			got := collect(getData, want, 5*time.Second)
			if len(got) != want {
				t.Fatalf("requests %v, want %v", len(got), want)
			}
			if _, ok := got[expired]; ok == tt.fork {
				t.Fatalf("expired block %v requested %v, want %v",
					expired, ok, !tt.fork)
			}
			if tt.fork && !a.IsConnected() {
				t.Fatal("peer closed for a fork block")
			}
			if !tt.fork && a.IsConnected() {
				t.Fatal("peer kept after a canonical block expired")
			}
		})
	}
}

// TestSyncBlocksCancelled checks that syncBlocks sends no request once
// its context is cancelled.
func TestSyncBlocksCancelled(t *testing.T) {
	s, _ := newSyncServer(t, 10)
	getData := make(chan chainhash.Hash, 2*defaultPendingBlocks)
	addPipePeer(t, s, "peer", getData)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s.syncBlocks(ctx)

	if got := collect(getData, 0, 500*time.Millisecond); len(got) != 0 {
		t.Fatalf("requests sent after cancel: %v", len(got))
	}
	if l := s.blocks.Len(); l != 0 {
		t.Fatalf("pending %v, want 0", l)
	}
}
