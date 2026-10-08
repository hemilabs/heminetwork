// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
)

// checkpointParams returns regtest params with tbc style checkpoints:
// highest first, ending at genesis.
func checkpointParams(cps ...chaincfg.Checkpoint) *chaincfg.Params {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = append(cps, chaincfg.Checkpoint{
		Height: 0,
		Hash:   chaincfg.RegressionNetParams.GenesisHash,
	})
	return &params
}

// newCheckpointServer returns a server whose canonical chain is 30
// mined regtest headers on top of genesis, with checkpoints at heights
// 20, 10 and 0.  The best header is at height 30, so the most recent
// checkpoint passed is 20.
func newCheckpointServer(t *testing.T) (*Server, []*wire.BlockHeader) {
	t.Helper()

	genesis := chaincfg.RegressionNetParams.GenesisBlock.Header
	chain := makeMinedChain(30, genesis,
		chaincfg.RegressionNetParams.PowLimitBits, 10*time.Minute)

	params := checkpointParams(
		chaincfg.Checkpoint{Height: 20, Hash: new(chain[19].BlockHash())},
		chaincfg.Checkpoint{Height: 10, Hash: new(chain[9].BlockHash())},
	)
	s := newDifficultyTestServer(t, params)
	s.timeSource = blockchain.NewMedianTime()
	s.notifier = NewNotifier(false)
	insertHeaders(t, s, chain)
	return s, chain
}

// forkFrom returns count mined headers that fork off parent.  The
// spacing differs from the canonical chain so the hashes differ.
func forkFrom(count int, parent *wire.BlockHeader) []*wire.BlockHeader {
	return makeMinedChain(count, *parent,
		chaincfg.RegressionNetParams.PowLimitBits, 11*time.Minute)
}

func TestVerifyHeaderCheckpoints(t *testing.T) {
	s, chain := newCheckpointServer(t)

	// chain[i] is at height i+1.
	tests := []struct {
		name    string
		headers []*wire.BlockHeader
		wantErr bool
	}{
		{
			name:    "known headers below checkpoint",
			headers: chain[4:7], // heights 5-7
		},
		{
			name:    "known header at checkpoint height",
			headers: chain[9:10], // height 10
		},
		{
			name:    "new fork below checkpoint",
			headers: forkFrom(1, chain[4]), // height 6
			wantErr: true,
		},
		{
			name:    "new fork at checkpoint height",
			headers: forkFrom(1, chain[18]), // height 20
			wantErr: true,
		},
		{
			name:    "new fork from genesis",
			headers: forkFrom(3, &chaincfg.RegressionNetParams.GenesisBlock.Header),
			wantErr: true,
		},
		{
			name:    "new fork above checkpoint",
			headers: forkFrom(2, chain[24]), // heights 26-27
		},
		{
			name:    "extend tip",
			headers: forkFrom(2, chain[29]), // heights 31-32
		},
		{
			name:    "empty batch",
			headers: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.verifyHeaderCheckpoints(t.Context(), tt.headers)
			if tt.wantErr {
				if !errors.Is(err, ErrCheckpoint) {
					t.Fatalf("got %v, want %v", err, ErrCheckpoint)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyHeaderCheckpointsHash checks the checkpoint hash rule
// above the best header, where the fork rule does not apply.
func TestVerifyHeaderCheckpointsHash(t *testing.T) {
	genesis := chaincfg.RegressionNetParams.GenesisBlock.Header
	chain := makeMinedChain(15, genesis,
		chaincfg.RegressionNetParams.PowLimitBits, 10*time.Minute)
	other := forkFrom(15, &genesis)

	tests := []struct {
		name    string
		cp      *chainhash.Hash // checkpoint hash at height 10
		wantErr bool
	}{
		{"header matches checkpoint", new(chain[9].BlockHash()), false},
		{"header contradicts checkpoint", new(other[9].BlockHash()), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Best header is genesis: no checkpoint passed yet.
			s := newDifficultyTestServer(t, checkpointParams(
				chaincfg.Checkpoint{Height: 10, Hash: tt.cp}))
			err := s.verifyHeaderCheckpoints(t.Context(), chain)
			if tt.wantErr {
				if !errors.Is(err, ErrCheckpoint) {
					t.Fatalf("got %v, want %v", err, ErrCheckpoint)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyHeaderCheckpointsNone checks that a network without
// checkpoints accepts a fork at any height.
func TestVerifyHeaderCheckpointsNone(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	s := newDifficultyTestServer(t, &params)

	genesis := chaincfg.RegressionNetParams.GenesisBlock.Header
	chain := makeMinedChain(30, genesis, params.PowLimitBits, 10*time.Minute)
	insertHeaders(t, s, chain)

	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(1, chain[4])); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyHeaderCheckpointsUnknownParent checks that a batch that
// does not connect is an error, not a checkpoint violation.
func TestVerifyHeaderCheckpointsUnknownParent(t *testing.T) {
	s, _ := newCheckpointServer(t)

	orphan := forkFrom(1, &wire.BlockHeader{Timestamp: time.Unix(1, 0)})
	err := s.verifyHeaderCheckpoints(t.Context(), orphan)
	if err == nil || errors.Is(err, ErrCheckpoint) {
		t.Fatalf("got %v, want parent lookup error", err)
	}
}

// blocksMissingCount returns the number of blocks missing entries.
func blocksMissingCount(t *testing.T, s *Server) int {
	t.Helper()
	bm, err := s.g.db.BlocksMissing(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return len(bm)
}

func headersMsg(t *testing.T, headers []*wire.BlockHeader) *wire.MsgHeaders {
	t.Helper()
	msg := wire.NewMsgHeaders()
	for _, h := range headers {
		if err := msg.AddBlockHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	return msg
}

// TestHandleHeadersCheckpoint runs header batches through handleHeaders
// and checks that a fork below the checkpoint is rejected before it
// adds blocks missing entries, while known and new headers above the
// checkpoint are handled as before.
func TestHandleHeadersCheckpoint(t *testing.T) {
	tests := []struct {
		name        string
		headers     func(chain []*wire.BlockHeader) []*wire.BlockHeader
		wantErr     bool
		wantMissing int // blocks missing entries added
	}{
		{
			name: "fork from genesis rejected",
			headers: func([]*wire.BlockHeader) []*wire.BlockHeader {
				return forkFrom(5, &chaincfg.RegressionNetParams.GenesisBlock.Header)
			},
			wantErr: true,
		},
		{
			name: "fork below checkpoint rejected",
			headers: func(chain []*wire.BlockHeader) []*wire.BlockHeader {
				return forkFrom(3, chain[4])
			},
			wantErr: true,
		},
		{
			name: "known headers accepted",
			headers: func(chain []*wire.BlockHeader) []*wire.BlockHeader {
				return chain[0:5]
			},
		},
		{
			name: "fork above checkpoint accepted",
			headers: func(chain []*wire.BlockHeader) []*wire.BlockHeader {
				return forkFrom(2, chain[24])
			},
			wantMissing: 2,
		},
		{
			name: "tip extension accepted",
			headers: func(chain []*wire.BlockHeader) []*wire.BlockHeader {
				return forkFrom(2, chain[29])
			},
			wantMissing: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, chain := newCheckpointServer(t)

			// An accepted batch asks the peer for more headers.
			c1, c2 := net.Pipe()
			t.Cleanup(func() { c1.Close(); c2.Close() })
			p, err := rawpeer.NewFromConn(c1, wire.TestNet, wire.AddrV2Version, 0)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				for {
					_, _, _, err := wire.ReadMessageWithEncodingN(c2,
						wire.AddrV2Version, wire.TestNet, wire.LatestEncoding)
					if err != nil {
						return
					}
				}
			}()

			before := blocksMissingCount(t, s)
			err = s.handleHeaders(t.Context(), p, headersMsg(t, tt.headers(chain)))
			if tt.wantErr {
				if !errors.Is(err, ErrCheckpoint) {
					t.Fatalf("got %v, want %v", err, ErrCheckpoint)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := blocksMissingCount(t, s) - before; got != tt.wantMissing {
				t.Fatalf("blocks missing added %v, want %v", got, tt.wantMissing)
			}
		})
	}
}
