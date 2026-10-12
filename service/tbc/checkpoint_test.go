// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
)

// newCheckpointServer returns a localnet server on a real store whose
// canonical chain is 30 mined headers on top of genesis, with checkpoints at
// heights 20, 10 and 0. Checkpoints 20 and 10 are stored at their heights, so
// the floor is 20. chain[i] is at height i+1.
func newCheckpointServer(t *testing.T) (*Server, []*wire.BlockHeader) {
	t.Helper()
	s, chain := newCheckpointStore(t)
	insertChain(t, s, chain)
	return s, chain
}

// newCheckpointStore is newCheckpointServer with only genesis stored.
func newCheckpointStore(t *testing.T) (*Server, []*wire.BlockHeader) {
	t.Helper()
	s := deferServer(t)
	cfg, err := level.NewConfig(networkLocalnet, t.TempDir(), "0", "0")
	if err != nil {
		t.Fatal(err)
	}
	db, err := level.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	gen := chaincfg.RegressionNetParams.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(t.Context(), gen, 0, nil); err != nil {
		t.Fatal(err)
	}
	chain := minedChain(t, s, gen.BlockHash(), 30, 1)
	s.db = db
	s.checkpoints = []checkpoint{
		{20, chain[19].BlockHash()},
		{10, chain[9].BlockHash()},
		{0, gen.BlockHash()},
	}
	return s, chain
}

// insertChain stores headers directly, without the P2P checks.
func insertChain(t *testing.T, s *Server, headers []*wire.BlockHeader) {
	t.Helper()
	if _, _, _, _, err := s.db.BlockHeadersInsert(t.Context(), headersMsg(t, headers...), nil); err != nil {
		t.Fatal(err)
	}
}

// forkFrom returns count mined headers that fork off parent. The tag keeps
// their hashes distinct from the canonical chain.
func forkFrom(t *testing.T, s *Server, parent *wire.BlockHeader, count int) []*wire.BlockHeader {
	t.Helper()
	return minedChain(t, s, parent.BlockHash(), count, 0x80)
}

func TestVerifyHeaderCheckpoints(t *testing.T) {
	s, chain := newCheckpointServer(t)
	gen := chaincfg.RegressionNetParams.GenesisBlock.Header

	tests := []struct {
		name    string
		headers []*wire.BlockHeader
		wantErr bool
	}{
		{"known headers below checkpoint", chain[4:7], false},
		{"known header at checkpoint height", chain[9:10], false},
		{"new fork below checkpoint", forkFrom(t, s, chain[4], 1), true},
		{"new fork at checkpoint height", forkFrom(t, s, chain[18], 1), true},
		{"new fork from genesis", forkFrom(t, s, &gen, 3), true},
		{"new fork above checkpoint", forkFrom(t, s, chain[24], 2), false},
		{
			"known prefix then fork below checkpoint",
			append([]*wire.BlockHeader{chain[15], chain[16]}, forkFrom(t, s, chain[16], 1)...),
			true,
		},
		{
			"known prefix across checkpoint then new above",
			append([]*wire.BlockHeader{chain[18], chain[19], chain[20]}, forkFrom(t, s, chain[20], 2)...),
			false,
		},
		{"extend tip", forkFrom(t, s, chain[29], 2), false},
		{"empty batch", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.verifyHeaderCheckpoints(t.Context(), tt.headers)
			if tt.wantErr {
				if !errors.Is(err, ErrCheckpoint) {
					t.Fatalf("expected %v, got %v", ErrCheckpoint, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyHeaderCheckpointsHash checks the checkpoint hash rule above the
// floor, where the fork rule does not apply.
func TestVerifyHeaderCheckpointsHash(t *testing.T) {
	s, chain := newCheckpointServer(t)
	other := forkFrom(t, s, chain[29], 15) // heights 31-45

	for _, tc := range []struct {
		name    string
		cp      chainhash.Hash // checkpoint hash at height 40
		wantErr bool
	}{
		{"header matches checkpoint", other[9].BlockHash(), false},
		{"header contradicts checkpoint", chainhash.Hash{0x40}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.checkpoints = []checkpoint{
				{40, tc.cp},
				{20, chain[19].BlockHash()},
				{0, chaincfg.RegressionNetParams.GenesisBlock.Header.BlockHash()},
			}
			err := s.verifyHeaderCheckpoints(t.Context(), other)
			if tc.wantErr {
				if !errors.Is(err, ErrCheckpoint) {
					t.Fatalf("expected %v, got %v", ErrCheckpoint, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyHeaderCheckpointsGenesisOnly checks that a network whose only
// checkpoint is genesis, such as localnet, accepts any batch without a store
// lookup. The server has no store, so a lookup would panic.
func TestVerifyHeaderCheckpointsGenesisOnly(t *testing.T) {
	s := deferServer(t)
	if len(s.checkpoints) != 1 || s.checkpoints[0].height != 0 {
		t.Fatalf("premise: expected localnet to have only the genesis checkpoint, got %v", s.checkpoints)
	}
	batch := minedChain(t, s, chainhash.Hash{0x77}, 2, 0x70)
	if err := s.verifyHeaderCheckpoints(t.Context(), batch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyHeaderCheckpointsUnknownParent checks that a batch that does not
// connect is an error, but not a checkpoint violation.
func TestVerifyHeaderCheckpointsUnknownParent(t *testing.T) {
	s, _ := newCheckpointServer(t)
	orphan := minedChain(t, s, chainhash.Hash{0x99}, 1, 0x90)
	err := s.verifyHeaderCheckpoints(t.Context(), orphan)
	if err == nil || errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected a parent lookup error, got %v", err)
	}
}

// pipePeer returns a peer whose writes are read and discarded, so that
// handleHeaders can send getheaders after an insert.
func pipePeer(t *testing.T) *rawpeer.RawPeer {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	p, err := rawpeer.NewFromConn(c1, wire.TestNet, wire.AddrV2Version, 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			if _, _, _, err := wire.ReadMessageWithEncodingN(c2,
				wire.AddrV2Version, wire.TestNet, wire.LatestEncoding); err != nil {
				return
			}
		}
	}()
	return p
}

// TestHandleHeadersCheckpoint runs batches through handleHeaders: a fork below
// the floor is rejected before it adds blocks-missing entries, while known
// headers and new headers above it are accepted as usual.
func TestHandleHeadersCheckpoint(t *testing.T) {
	gen := chaincfg.RegressionNetParams.GenesisBlock.Header
	tests := []struct {
		name        string
		headers     func(s *Server, chain []*wire.BlockHeader) []*wire.BlockHeader
		wantErr     bool
		wantMissing int // blocks-missing entries added
	}{
		{
			name: "fork from genesis rejected",
			headers: func(s *Server, _ []*wire.BlockHeader) []*wire.BlockHeader {
				return forkFrom(t, s, &gen, 5)
			},
			wantErr: true,
		},
		{
			name: "fork below checkpoint rejected",
			headers: func(s *Server, chain []*wire.BlockHeader) []*wire.BlockHeader {
				return forkFrom(t, s, chain[4], 3)
			},
			wantErr: true,
		},
		{
			name: "known prefix then fork below checkpoint rejected",
			headers: func(s *Server, chain []*wire.BlockHeader) []*wire.BlockHeader {
				return append([]*wire.BlockHeader{chain[15], chain[16]}, forkFrom(t, s, chain[16], 1)...)
			},
			wantErr: true,
		},
		{
			name: "known headers accepted",
			headers: func(_ *Server, chain []*wire.BlockHeader) []*wire.BlockHeader {
				return chain[0:5]
			},
		},
		{
			name: "fork above checkpoint accepted",
			headers: func(s *Server, chain []*wire.BlockHeader) []*wire.BlockHeader {
				return forkFrom(t, s, chain[24], 2)
			},
			wantMissing: 2,
		},
		{
			name: "tip extension accepted",
			headers: func(s *Server, chain []*wire.BlockHeader) []*wire.BlockHeader {
				return forkFrom(t, s, chain[29], 2)
			},
			wantMissing: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, chain := newCheckpointServer(t)
			missing := func() int {
				bm, err := s.db.BlocksMissing(t.Context(), 1000)
				if err != nil {
					t.Fatal(err)
				}
				return len(bm)
			}
			before := missing()
			err := s.handleHeaders(t.Context(), pipePeer(t), headersMsg(t, tt.headers(s, chain)...))
			if tt.wantErr {
				if !errors.Is(err, ErrCheckpoint) {
					t.Fatalf("expected %v, got %v", ErrCheckpoint, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := missing() - before; got != tt.wantMissing {
				t.Fatalf("expected %v blocks-missing entries added, got %v", tt.wantMissing, got)
			}
		})
	}
}

// TestHandleHeadersCheckpointForkOvertakesTip checks that a fork above the
// floor may overtake the tip.
func TestHandleHeadersCheckpointForkOvertakesTip(t *testing.T) {
	s, chain := newCheckpointServer(t)
	fork := forkFrom(t, s, chain[24], 8) // heights 26-33
	if err := s.handleHeaders(t.Context(), pipePeer(t), headersMsg(t, fork...)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	best, err := s.db.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if want := fork[7].BlockHash(); best.Height != 33 || !best.Hash.IsEqual(&want) {
		t.Fatalf("expected best %v at 33, got %v at %v", want, best.Hash, best.Height)
	}
}

// TestHandleHeadersCheckpointJunkBest checks that a best header on a junk
// fork past a checkpoint height does not raise the floor: the floor is a
// checkpoint we store, so the canonical chain can still replace the junk.
func TestHandleHeadersCheckpointJunkBest(t *testing.T) {
	s, chain := newCheckpointStore(t)
	gen := chaincfg.RegressionNetParams.GenesisBlock.Header
	insertChain(t, s, chain[:5])
	insertChain(t, s, forkFrom(t, s, &gen, 25)) // junk best at 25, past 20
	if best, err := s.db.BlockHeaderBest(t.Context()); err != nil || best.Height != 25 {
		t.Fatalf("premise: expected the junk fork as best at 25, got %v, %v", best, err)
	}

	if err := s.handleHeaders(t.Context(), pipePeer(t), headersMsg(t, chain...)); err != nil {
		t.Fatalf("expected the canonical chain to be accepted, got %v", err)
	}
	best, err := s.db.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if want := chain[29].BlockHash(); !best.Hash.IsEqual(&want) {
		t.Fatalf("expected the canonical tip %v, got %v at %v", want, best.Hash, best.Height)
	}
}

// TestEnforcedCheckpoints checks the merged list for each network: sorted
// high to low, genesis last, btcd's low checkpoints included, and no height
// where tbc's and btcd's lists disagree.
func TestEnforcedCheckpoints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params *chaincfg.Params
		cps    []checkpoint
	}{
		{"mainnet", &chaincfg.MainNetParams, mainnetCheckpoints},
		{"testnet3", &chaincfg.TestNet3Params, testnet3Checkpoints},
		{"localnet", &chaincfg.RegressionNetParams, localnetCheckpoints},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{chainParams: tc.params, checkpoints: tc.cps}
			got := s.enforcedCheckpoints()
			for i := 1; i < len(got); i++ {
				if got[i].height >= got[i-1].height {
					t.Fatalf("expected strictly decreasing heights, got %v then %v",
						got[i-1].height, got[i].height)
				}
			}
			if last := got[len(got)-1]; last.height != 0 || !last.hash.IsEqual(tc.params.GenesisHash) {
				t.Fatalf("expected genesis last, got %v at %v", last.hash, last.height)
			}
			for _, c := range tc.params.Checkpoints {
				cp := checkpointAt(uint64(c.Height), got)
				if cp == nil || !cp.hash.IsEqual(c.Hash) {
					t.Fatalf("expected btcd checkpoint %v at %v, got %v", c.Hash, c.Height, cp)
				}
			}
			for _, cp := range tc.cps {
				if c := checkpointAt(cp.height, got); c == nil || c.hash != cp.hash {
					t.Fatalf("expected tbc checkpoint %v at %v", cp.hash, cp.height)
				}
			}
			if s.hasEnforcedCheckpoints() != (got[0].height > 0) {
				t.Fatalf("hasEnforcedCheckpoints disagrees with the merged list")
			}
		})
	}
}

// TestVerifyHeaderCheckpointsBestAtCheckpoint checks the floor when the best
// header is exactly a checkpoint, including the next header, which is where
// an honest IBD batch usually starts.
func TestVerifyHeaderCheckpointsBestAtCheckpoint(t *testing.T) {
	s, chain := newCheckpointStore(t)
	insertChain(t, s, chain[:20]) // best is checkpoint 20
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, chain[14], 2)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v for a fork below the floor, got %v", ErrCheckpoint, err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, chain[18], 1)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v at the checkpoint height, got %v", ErrCheckpoint, err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), chain[20:]); err != nil {
		t.Fatalf("expected the canonical continuation at floor + 1 to pass, got %v", err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, chain[19], 1)); err != nil {
		t.Fatalf("expected a fork branching at the floor to pass, got %v", err)
	}
}

// TestVerifyHeaderCheckpointsAdjacent checks two checkpoints one height apart,
// as on testnet3 (tbc 300000, btcd 300001): with the lower one stored, the
// header at the upper one is the next one an honest batch sends.
func TestVerifyHeaderCheckpointsAdjacent(t *testing.T) {
	s, chain := newCheckpointStore(t)
	s.checkpoints = append([]checkpoint{{21, chain[20].BlockHash()}}, s.checkpoints...)
	insertChain(t, s, chain[:20])
	if err := s.verifyHeaderCheckpoints(t.Context(), chain[20:]); err != nil {
		t.Fatalf("expected the canonical continuation to pass, got %v", err)
	}
}

// lookupCountDB counts the header lookups the checks make.
type lookupCountDB struct {
	tbcd.Database
	byHash, best atomic.Int32
}

func (d *lookupCountDB) BlockHeaderByHash(ctx context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	d.byHash.Add(1)
	return d.Database.BlockHeaderByHash(ctx, h)
}

func (d *lookupCountDB) BlockHeaderBest(ctx context.Context) (*tbcd.BlockHeader, error) {
	d.best.Add(1)
	return d.Database.BlockHeaderBest(ctx)
}

// TestHandleHeadersCheckpointSkippedForKnownBatch checks that a batch whose
// headers are all stored skips the checkpoint check: only the per-header
// lookups run, and the floor is never computed.
func TestHandleHeadersCheckpointSkippedForKnownBatch(t *testing.T) {
	s, chain := newCheckpointServer(t)
	db := &lookupCountDB{Database: s.db}
	s.db = db
	if err := s.handleHeaders(t.Context(), pipePeer(t), headersMsg(t, chain[0:5]...)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n, b := db.byHash.Load(), db.best.Load(); n != 5 || b != 0 {
		t.Fatalf("expected 5 header lookups and no best lookup, got %v and %v", n, b)
	}
}

// TestVerifyHeaderCheckpointsUsesBtcdList checks that the verifier enforces
// btcd's checkpoints for the network, not only tbc's.
func TestVerifyHeaderCheckpointsUsesBtcdList(t *testing.T) {
	s, chain := newCheckpointStore(t)
	s.checkpoints = s.checkpoints[2:] // tbc: genesis only
	params := *s.chainParams
	h15 := chain[14].BlockHash()
	params.Checkpoints = []chaincfg.Checkpoint{{Height: 15, Hash: &h15}}
	s.chainParams = &params

	// Hash rule: checkpoint 15 is not stored yet, so the floor is 0 and only
	// the hash rule can refuse a different header at height 15.
	insertChain(t, s, chain[:14])
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, chain[13], 1)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v at btcd checkpoint 15, got %v", ErrCheckpoint, err)
	}
	// Floor rule: once checkpoint 15 is stored, a new fork below it is refused.
	insertChain(t, s, chain[14:])
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, chain[9], 1)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v below btcd checkpoint 15, got %v", ErrCheckpoint, err)
	}
}

// TestHandleHeadersCheckpointAfterFutureCut checks that dropping a trailing
// future header does not skip the checks: the fork before it is still
// refused.
func TestHandleHeadersCheckpointAfterFutureCut(t *testing.T) {
	s, chain := newCheckpointServer(t)
	fork := forkFrom(t, s, chain[16], 1)[0] // height 18, below floor 20
	future := mineHeaderAt(t, fork.BlockHash(), s.chainParams.PowLimitBits, time.Now().Add(3*time.Hour))
	before, err := s.db.BlocksMissing(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	msg := headersMsg(t, chain[15], chain[16], fork, future)
	if err := s.handleHeaders(t.Context(), pipePeer(t), msg); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v, got %v", ErrCheckpoint, err)
	}
	after, err := s.db.BlocksMissing(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("expected no new blocks-missing entries, got %v", len(after)-len(before))
	}
}

// TestHandleHeadersCheckpointHeavierJunkBest checks that a shorter but
// heavier junk best below the stored checkpoints does not hold the floor down:
// a fork from genesis is still refused once the canonical checkpoints are
// stored.
func TestHandleHeadersCheckpointHeavierJunkBest(t *testing.T) {
	s, chain := newCheckpointStore(t)
	gen := chaincfg.RegressionNetParams.GenesisBlock.Header
	p := pipePeer(t)
	if err := s.handleHeaders(t.Context(), p, headersMsg(t, chain[:5]...)); err != nil {
		t.Fatal(err)
	}
	// Eight headers at harder bits outweigh the whole canonical chain.
	junk := make([]*wire.BlockHeader, 0, 8)
	prev := gen.BlockHash()
	for i := range 8 {
		h := mineHeader(t, &prev, 0x1f7fffff, 0xa0+byte(i))
		junk = append(junk, h)
		prev = h.BlockHash()
	}
	if err := s.handleHeaders(t.Context(), p, headersMsg(t, junk...)); err != nil {
		t.Fatal(err)
	}
	if err := s.handleHeaders(t.Context(), p, headersMsg(t, chain[5:]...)); err != nil {
		t.Fatal(err)
	}
	if best, err := s.db.BlockHeaderBest(t.Context()); err != nil || best.Height != 8 {
		t.Fatalf("premise: expected the heavier junk fork as best at 8, got %v, %v", best, err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, &gen, 9)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v below stored checkpoint 20, got %v", ErrCheckpoint, err)
	}
}

// TestVerifyHeaderCheckpointsFloorFallsBack checks that when the higher
// checkpoint is not stored, the floor is the next lower one that is.
func TestVerifyHeaderCheckpointsFloorFallsBack(t *testing.T) {
	s, chain := newCheckpointStore(t)
	insertChain(t, s, chain[:12]) // checkpoint 10 stored, 20 not
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, chain[4], 1)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v below stored checkpoint 10, got %v", ErrCheckpoint, err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), chain[12:]); err != nil {
		t.Fatalf("expected the canonical continuation to pass, got %v", err)
	}
}

// TestHandleHeadersCheckpointLegacyOrphan checks that a header stored without
// its parent, as a store written by an older version can hold, does not let a batch
// ending at it skip the checks.
func TestHandleHeadersCheckpointLegacyOrphan(t *testing.T) {
	s, chain := newCheckpointServer(t)
	fork := forkFrom(t, s, chain[4], 4) // heights 6-9, below floor 20
	// Store the last fork header at its height without its parent, as an
	// older binary could: the store assigns heights by position and only
	// looks up the first header's parent, so [x, orphan] on chain[6] puts the
	// orphan at height 9 on top of x.
	x := minedChain(t, s, chain[6].BlockHash(), 1, 0x90)[0]
	if _, _, _, _, err := s.db.BlockHeadersInsert(t.Context(), headersMsg(t, x, fork[3]), nil); err != nil {
		t.Fatalf("premise: plant: %v", err)
	}
	if bh, err := s.db.BlockHeaderByHash(t.Context(), fork[3].BlockHash()); err != nil || bh.Height != 9 {
		t.Fatalf("premise: expected the orphan stored at 9, got %v, %v", bh, err)
	}
	before, err := s.db.BlocksMissing(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	err = s.handleHeaders(t.Context(), pipePeer(t), headersMsg(t, fork...))
	if !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v, got %v", ErrCheckpoint, err)
	}
	after, err := s.db.BlocksMissing(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("expected no new blocks-missing entries, got %v", len(after)-len(before))
	}
}

// newMissingBelow returns the new blocks-missing heights at or below floor.
func newMissingBelow(t *testing.T, s *Server, before map[chainhash.Hash]bool, floor uint64) []uint64 {
	t.Helper()
	bm, err := s.db.BlocksMissing(t.Context(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	var out []uint64
	for _, e := range bm {
		if !before[*e.Hash] && e.Height <= floor {
			out = append(out, e.Height)
		}
	}
	return out
}

func missingSet(t *testing.T, s *Server) map[chainhash.Hash]bool {
	t.Helper()
	bm, err := s.db.BlocksMissing(t.Context(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[chainhash.Hash]bool, len(bm))
	for _, e := range bm {
		out[*e.Hash] = true
	}
	return out
}

// TestHandleHeadersCheckpointLegacyHeights checks headers that a store written
// by an older version holds at the wrong height. The insert would re-home them and
// their successors below the floor, so the batch must be refused instead.
func TestHandleHeadersCheckpointLegacyHeights(t *testing.T) {
	t.Run("stored run at the wrong heights", func(t *testing.T) {
		s, chain := newCheckpointServer(t) // floor 20
		b := forkFrom(t, s, chain[4], 3)   // real heights 6-8
		// An older binary stores [x, b...] by position: b at 12-14.
		x := minedChain(t, s, chain[9].BlockHash(), 1, 0x90)[0]
		insertChain(t, s, append([]*wire.BlockHeader{x}, b...))
		before := missingSet(t, s)
		err := s.handleHeaders(t.Context(), pipePeer(t), headersMsg(t, append([]*wire.BlockHeader{chain[4]}, b...)...))
		if !errors.Is(err, ErrCheckpoint) {
			t.Fatalf("expected %v, got %v", ErrCheckpoint, err)
		}
		if got := newMissingBelow(t, s, before, 20); len(got) != 0 {
			t.Fatalf("expected no new blocks-missing entries below the floor, got %v", got)
		}
	})
	t.Run("stored header too low, new headers after it", func(t *testing.T) {
		s, chain := newCheckpointServer(t)   // floor 20
		k := forkFrom(t, s, chain[24], 1)[0] // real height 26
		// An older binary stores [x, k] by position: k at 7.
		x := minedChain(t, s, chain[4].BlockHash(), 1, 0x90)[0]
		insertChain(t, s, []*wire.BlockHeader{x, k})
		n := minedChain(t, s, k.BlockHash(), 5, 0xb0)
		before := missingSet(t, s)
		err := s.handleHeaders(t.Context(), pipePeer(t), headersMsg(t, append([]*wire.BlockHeader{k}, n...)...))
		if !errors.Is(err, ErrCheckpoint) {
			t.Fatalf("expected %v, got %v", ErrCheckpoint, err)
		}
		if got := newMissingBelow(t, s, before, 20); len(got) != 0 {
			t.Fatalf("expected no new blocks-missing entries below the floor, got %v", got)
		}
	})
}

// TestVerifyHeaderCheckpointsLegacyForkAcrossFloor checks that a low-work fork
// an older binary stored across the floor cannot be extended: a parent at or
// above the floor must carry at least the checkpoint's work plus the minimum
// per height.
func TestVerifyHeaderCheckpointsLegacyForkAcrossFloor(t *testing.T) {
	s, _ := newCheckpointStore(t)
	gen := chaincfg.RegressionNetParams.GenesisBlock.Header
	// Canonical chain at harder bits than the PowLimit junk, so it carries
	// more work per header.
	canon := make([]*wire.BlockHeader, 0, 30)
	prev := gen.BlockHash()
	for i := range 30 {
		h := mineHeader(t, &prev, 0x1f7fffff, 0x40+byte(i))
		canon = append(canon, h)
		prev = h.BlockHash()
	}
	insertChain(t, s, canon)
	s.checkpoints = []checkpoint{
		{20, canon[19].BlockHash()},
		{10, canon[9].BlockHash()},
		{0, gen.BlockHash()},
	}
	junk := forkFrom(t, s, &gen, 25) // PowLimit fork stored by an older binary
	insertChain(t, s, junk)

	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, junk[24], 1)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v extending the legacy fork, got %v", ErrCheckpoint, err)
	}
	// junk[19] sits at the floor height itself, not on the checkpoint.
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, junk[19], 1)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v extending the legacy fork at the floor height, got %v", ErrCheckpoint, err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, canon[29], 2)); err != nil {
		t.Fatalf("expected the canonical extension to pass, got %v", err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, canon[24], 1)); err != nil {
		t.Fatalf("expected an honest fork above the floor to pass, got %v", err)
	}
}

// TestVerifyHeaderCheckpointsLegacyForkPerHeightWork checks the per-height term
// of the work bound: a legacy PowLimit fork whose work is at least the floor
// checkpoint's, but less than that plus PowLimit work per height above it,
// must not be extended.
func TestVerifyHeaderCheckpointsLegacyForkPerHeightWork(t *testing.T) {
	s, _ := newCheckpointStore(t)
	gen := chaincfg.RegressionNetParams.GenesisBlock.Header
	// canon[0] at harder bits, the rest at PowLimit.
	canon := make([]*wire.BlockHeader, 0, 30)
	prev := gen.BlockHash()
	for i := range 30 {
		bits := s.chainParams.PowLimitBits
		if i == 0 {
			bits = 0x1f7fffff
		}
		h := mineHeader(t, &prev, bits, 0x40+byte(i))
		canon = append(canon, h)
		prev = h.BlockHash()
	}
	insertChain(t, s, canon)
	s.checkpoints = []checkpoint{
		{20, canon[19].BlockHash()},
		{10, canon[9].BlockHash()},
		{0, gen.BlockHash()},
	}
	junk := forkFrom(t, s, &gen, 600) // legacy PowLimit fork, heights 1-600
	insertChain(t, s, junk)

	cp, err := s.db.BlockHeaderByHash(t.Context(), canon[19].BlockHash())
	if err != nil {
		t.Fatal(err)
	}
	jt, err := s.db.BlockHeaderByHash(t.Context(), junk[599].BlockHash())
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Mul(big.NewInt(600-20), blockchain.CalcWork(s.chainParams.PowLimitBits))
	want.Add(want, &cp.Difficulty)
	if jt.Difficulty.Cmp(&cp.Difficulty) < 0 || jt.Difficulty.Cmp(want) >= 0 {
		t.Fatalf("premise: junk work %v must be between %v and %v", &jt.Difficulty, &cp.Difficulty, want)
	}

	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, junk[599], 1)); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("expected %v extending the legacy fork, got %v", ErrCheckpoint, err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, canon[29], 2)); err != nil {
		t.Fatalf("expected the canonical extension to pass, got %v", err)
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), forkFrom(t, s, canon[24], 1)); err != nil {
		t.Fatalf("expected an honest fork above the floor to pass, got %v", err)
	}
}

// TestVerifyHeaderCheckpointsStoredJunkAtFloorPrefix checks that a batch whose
// parent is below the floor cannot re-enter a low-work fork stored across the
// floor by resending its stored headers. The descent guard does not run for
// such a parent; the hash rule on the stored header at the checkpoint height
// is what refuses it.
func TestVerifyHeaderCheckpointsStoredJunkAtFloorPrefix(t *testing.T) {
	s, _ := newCheckpointStore(t)
	gen := chaincfg.RegressionNetParams.GenesisBlock.Header
	canon := make([]*wire.BlockHeader, 0, 30)
	prev := gen.BlockHash()
	for i := range 30 {
		h := mineHeader(t, &prev, 0x1f7fffff, 0x40+byte(i))
		canon = append(canon, h)
		prev = h.BlockHash()
	}
	insertChain(t, s, canon)
	s.checkpoints = []checkpoint{
		{20, canon[19].BlockHash()},
		{10, canon[9].BlockHash()},
		{0, gen.BlockHash()},
	}
	junk := forkFrom(t, s, &gen, 25) // stored by an older binary
	insertChain(t, s, junk)

	cat := func(parts ...[]*wire.BlockHeader) []*wire.BlockHeader {
		var out []*wire.BlockHeader
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		headers []*wire.BlockHeader
	}{
		{"stored junk 20-25 + new", cat(junk[19:25], forkFrom(t, s, junk[24], 2))},
		{"stored junk 16-25 + new", cat(junk[15:25], forkFrom(t, s, junk[24], 2))},
		{"stored junk 11-21 + new sibling", cat(junk[10:21], minedChain(t, s, junk[20].BlockHash(), 1, 0xd8))},
	} {
		before := missingSet(t, s)
		err := s.handleHeaders(t.Context(), pipePeer(t), headersMsg(t, tc.headers...))
		if !errors.Is(err, ErrCheckpoint) {
			t.Fatalf("%v: expected %v, got %v", tc.name, ErrCheckpoint, err)
		}
		if got := newMissingBelow(t, s, before, 1000); len(got) != 0 {
			t.Fatalf("%v: expected no new blocks-missing entries, got %v", tc.name, got)
		}
	}
	if err := s.verifyHeaderCheckpoints(t.Context(), cat(canon[15:30], forkFrom(t, s, canon[29], 1))); err != nil {
		t.Fatalf("expected stored canonical headers plus an extension to pass, got %v", err)
	}
}
