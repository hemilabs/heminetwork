// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
)

// invStubDB answers the store lookups handleInv can reach. BlockHeaderByHash
// is called for each block entry up to maxInvBlockScan; the other methods are
// reached through s.Synced when the inv also carries a tx entry. Anything else
// hits the embedded nil tbcd.Database and panics.
type invStubDB struct {
	tbcd.Database

	known map[chainhash.Hash]struct{}
	best  *tbcd.BlockHeader
}

func (d *invStubDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	if _, ok := d.known[h]; ok {
		// An all-zero header deserializes cleanly (see
		// TestZeroValueBlockHeaderDeserializes); handleInv only checks
		// that the lookup succeeded.
		return &tbcd.BlockHeader{Hash: h}, nil
	}
	// Same error type the leveldb store returns (see
	// TestStubNotFoundMatchesLevelDB).
	return nil, database.NotFoundError("block header not found: " + h.String())
}

func (d *invStubDB) BlockHeaderBest(context.Context) (*tbcd.BlockHeader, error) {
	if d.best == nil {
		return nil, database.NotFoundError("no best block header")
	}
	return d.best, nil
}

func (d *invStubDB) BlockHeaderByUtxoIndex(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

func (d *invStubDB) BlockHeaderByTxIndex(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

func (d *invStubDB) BlockHeaderByKeystoneIndex(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

func (d *invStubDB) BlocksMissing(context.Context, int) ([]tbcd.BlockIdentifier, error) {
	return nil, nil
}

func newInvServer(t *testing.T, known ...chainhash.Hash) *Server {
	t.Helper()

	cfg := NewDefaultConfig()
	cfg.Network = networkLocalnet
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	km := make(map[chainhash.Hash]struct{}, len(known))
	for _, h := range known {
		km[h] = struct{}{}
	}
	s.db = &invStubDB{known: km}
	return s
}

func blockInv(t *testing.T, hashes ...chainhash.Hash) *wire.MsgInv {
	t.Helper()

	m := wire.NewMsgInv()
	for i := range hashes {
		h := hashes[i]
		if err := m.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &h)); err != nil {
			t.Fatalf("add inv vect: %v", err)
		}
	}
	return m
}

// TestHandleInvQueuesEveryUnknownHashInOrder verifies that a known block hash
// skips only its own entry. Known hashes are placed at several positions since
// a handler that stops early can still pass a single ordering.
func TestHandleInvQueuesEveryUnknownHashInOrder(t *testing.T) {
	h := func(b byte) chainhash.Hash { return chainhash.Hash{b} }

	tests := []struct {
		name  string
		known []chainhash.Hash
		inv   []chainhash.Hash
		want  []chainhash.Hash
	}{
		{
			name:  "known first, the production case",
			known: []chainhash.Hash{h(1)},
			inv:   []chainhash.Hash{h(1), h(2), h(3)},
			want:  []chainhash.Hash{h(2), h(3)},
		},
		{
			name:  "two adjacent known hashes first",
			known: []chainhash.Hash{h(1), h(2)},
			inv:   []chainhash.Hash{h(1), h(2), h(3), h(4)},
			want:  []chainhash.Hash{h(3), h(4)},
		},
		{
			name:  "known in the middle",
			known: []chainhash.Hash{h(2)},
			inv:   []chainhash.Hash{h(1), h(2), h(3)},
			want:  []chainhash.Hash{h(1), h(3)},
		},
		{
			name:  "known interleaved",
			known: []chainhash.Hash{h(2), h(4), h(6)},
			inv:   []chainhash.Hash{h(1), h(2), h(3), h(4), h(5), h(6), h(7)},
			want:  []chainhash.Hash{h(1), h(3), h(5), h(7)},
		},
		{
			name:  "known last",
			known: []chainhash.Hash{h(3)},
			inv:   []chainhash.Hash{h(1), h(2), h(3)},
			want:  []chainhash.Hash{h(1), h(2)},
		},
		{
			name:  "nothing known",
			known: nil,
			inv:   []chainhash.Hash{h(1), h(2), h(3)},
			want:  []chainhash.Hash{h(1), h(2), h(3)},
		},
		{
			name:  "everything known",
			known: []chainhash.Hash{h(1), h(2), h(3)},
			inv:   []chainhash.Hash{h(1), h(2), h(3)},
			want:  nil,
		},
		{
			name:  "duplicate announcement is deduped, first-seen order kept",
			known: nil,
			inv:   []chainhash.Hash{h(1), h(2), h(1), h(3)},
			want:  []chainhash.Hash{h(1), h(2), h(3)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newInvServer(t, tc.known...)

			if err := s.handleInv(t.Context(), nil, blockInv(t, tc.inv...), nil); err != nil {
				t.Fatalf("handleInv: %v", err)
			}

			// invBlocks is a set, so check the exact count and
			// membership rather than order.
			got := make([]chainhash.Hash, 0, len(s.invBlocks))
			for h := range s.invBlocks {
				got = append(got, h)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("queued %v hashes, want %v.\n got: %v\nwant: %v\n"+
					"handleInv dropped or duplicated announcements; nothing "+
					"re-announces an old block, so a dropped one is lost "+
					"permanently and the node stalls at the gap.",
					len(got), len(tc.want), got, tc.want)
			}
			for _, w := range tc.want {
				if _, ok := s.invBlocks[w]; !ok {
					t.Fatalf("announcement %v missing from the queue.\n got: %v\nwant: %v",
						w, got, tc.want)
				}
			}
		})
	}
}

// TestHandleInvBlockAndTxInSameMessage verifies that a block announcement
// survives a mixed block/tx inv. The tx entry takes handleInv through s.Synced
// and, when invTxsInsert sees a new tx, into downloadMissingTx, which writes
// to the peer, so this test needs a real peer rather than nil.
func TestHandleInvBlockAndTxInSameMessage(t *testing.T) {
	s := newInvServer(t, chainhash.Hash{1})
	s.db.(*invStubDB).best = &tbcd.BlockHeader{Hash: chainhash.Hash{0xaa}, Height: 100}

	local, remote := net.Pipe()
	t.Cleanup(func() {
		local.Close()
		remote.Close()
	})
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := remote.Read(buf); err != nil {
				return
			}
		}
	}()
	p, err := rawpeer.NewFromConn(local, s.wireNet, wire.ProtocolVersion, 0)
	if err != nil {
		t.Fatalf("new from conn: %v", err)
	}

	blk := chainhash.Hash{2}
	tx := chainhash.Hash{0x77}
	m := wire.NewMsgInv()
	if err := m.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &blk)); err != nil {
		t.Fatal(err)
	}
	if err := m.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &tx)); err != nil {
		t.Fatal(err)
	}

	if err := s.handleInv(t.Context(), p, m, nil); err != nil {
		t.Fatalf("handleInv: %v", err)
	}
	if _, ok := s.invBlocks[blk]; len(s.invBlocks) != 1 || !ok {
		t.Fatalf("block announcement lost in a mixed inv: %v", s.invBlocks)
	}
}

// TestZeroValueBlockHeaderDeserializes verifies that a tbcd.BlockHeader with
// zeroed Header bytes survives bh.Wire(), which Server.BlockHeaderByHash
// calls, so invStubDB's known hashes read as known to handleInv.
func TestZeroValueBlockHeaderDeserializes(t *testing.T) {
	bh := tbcd.BlockHeader{Hash: chainhash.Hash{1}}
	if _, err := bh.Wire(); err != nil {
		t.Fatalf("zero-value tbcd.BlockHeader does not deserialize: %v", err)
	}
}

// TestStubNotFoundMatchesLevelDB verifies that invStubDB returns the same
// not-found error type as the leveldb store for a missing header.
func TestStubNotFoundMatchesLevelDB(t *testing.T) {
	ctx := t.Context()

	cfg, err := level.NewConfig(networkLocalnet, t.TempDir(), "0", "0")
	if err != nil {
		t.Fatalf("level config: %v", err)
	}
	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatalf("level new: %v", err)
	}
	defer db.Close()

	missing := chainhash.Hash{9, 9, 9}
	_, realErr := tbcd.Database(db).BlockHeaderByHash(ctx, missing)
	_, stubErr := (&invStubDB{}).BlockHeaderByHash(ctx, missing)

	var nfe database.NotFoundError
	if !errors.As(realErr, &nfe) {
		t.Fatalf("leveldb returned %T (%v), want database.NotFoundError", realErr, realErr)
	}
	if !errors.As(stubErr, &nfe) {
		t.Fatalf("stub returned %T (%v), want database.NotFoundError", stubErr, stubErr)
	}
	if !errors.Is(realErr, database.ErrNotFound) || !errors.Is(stubErr, database.ErrNotFound) {
		t.Fatalf("errors.Is(ErrNotFound) mismatch: real=%v stub=%v",
			errors.Is(realErr, database.ErrNotFound), errors.Is(stubErr, database.ErrNotFound))
	}
}

// TestHandleInvTxAfterBlockCapStillMempools verifies that a tx entry trailing
// more than maxInvBlockScan block entries still reaches the mempool. Past the
// cap handleInv must skip block entries, not break out of the loop.
func TestHandleInvTxAfterBlockCapStillMempools(t *testing.T) {
	// MempoolEnabled defaults to true and a best header makes Synced report
	// true; handleInv needs both to take the mempool path.
	s := newInvServer(t)
	s.db.(*invStubDB).best = &tbcd.BlockHeader{Hash: chainhash.Hash{0xaa}, Height: 100}

	// invTxsInsert returns an error for a new tx, so handleInv starts
	// downloadMissingTx, which writes to the peer; a nil peer would panic.
	local, remote := net.Pipe()
	t.Cleanup(func() {
		local.Close()
		remote.Close()
	})
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := remote.Read(buf); err != nil {
				return
			}
		}
	}()
	p, err := rawpeer.NewFromConn(local, s.wireNet, wire.ProtocolVersion, 0)
	if err != nil {
		t.Fatalf("new from conn: %v", err)
	}

	// One block entry past the cap, then a tx entry.
	m := wire.NewMsgInv()
	for i := range maxInvBlockScan + 1 {
		var b chainhash.Hash
		b[0], b[1], b[2] = byte(i), byte(i>>8), byte(i>>16)
		if err := m.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &b)); err != nil {
			t.Fatalf("add block inv: %v", err)
		}
	}
	tx := chainhash.Hash{0x77}
	if err := m.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &tx)); err != nil {
		t.Fatalf("add tx inv: %v", err)
	}

	if err := s.handleInv(t.Context(), p, m, nil); err != nil {
		t.Fatalf("handleInv: %v", err)
	}

	// The trailing tx must have reached the mempool (recorded as wanted).
	s.mempool.mtx.RLock()
	_, wanted := s.mempool.txs[tx]
	s.mempool.mtx.RUnlock()
	if !wanted {
		t.Fatal("a tx inv trailing an oversized block prefix was dropped: the cap " +
			"broke out of the loop instead of continuing, so the tx/mempool path never ran")
	}
}
