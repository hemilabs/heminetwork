// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
	"github.com/hemilabs/heminetwork/v2/ttl"
)

// slowInsertDB holds BlockInsert until release is closed.
type slowInsertDB struct {
	tbcd.Database
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (d *slowInsertDB) BlockInsert(ctx context.Context, b *btcutil.Block) (int64, error) {
	d.once.Do(func() { close(d.entered) })
	<-d.release
	return d.Database.BlockInsert(ctx, b)
}

// inflightServer returns a server with one mined regtest block whose
// header is known and whose body is missing, a pipe peer that reports
// every block it is asked for, and a database whose BlockInsert waits
// for release.
func inflightServer(t *testing.T) (*Server, *wire.MsgBlock, *rawpeer.RawPeer, *slowInsertDB, <-chan chainhash.Hash) {
	t.Helper()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = []chaincfg.Checkpoint{{Height: 0, Hash: params.GenesisHash}}
	payTo, err := btcutil.NewAddressPubKeyHash(make([]byte, 20), &params)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := newBlockTemplate(t, &params, payTo, 1, params.GenesisHash, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Block timestamps have a precision of one second.
	msg := blk.MsgBlock()
	msg.Header.Timestamp = time.Unix(msg.Header.Timestamp.Unix(), 0)
	mineHeader(&msg.Header)

	s := newDifficultyTestServer(t, &params)
	s.timeSource = blockchain.NewMedianTime()
	s.notifier = NewNotifier(false)
	insertHeaders(t, s, []*wire.BlockHeader{&msg.Header})
	db := &slowInsertDB{
		Database: s.g.db,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	s.g.db = db

	s.blocks, err = ttl.New(defaultPendingBlocks, true)
	if err != nil {
		t.Fatal(err)
	}
	s.pm, err = NewPeerManager(wire.TestNet, []string{}, 1)
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	p, err := rawpeer.NewFromConn(c1, wire.TestNet, wire.AddrV2Version, 0)
	if err != nil {
		t.Fatal(err)
	}
	asked := make(chan chainhash.Hash, 16)
	go func() {
		for {
			_, m, _, err := wire.ReadMessageWithEncodingN(c2,
				wire.AddrV2Version, wire.TestNet, wire.LatestEncoding)
			if err != nil {
				return
			}
			if gd, ok := m.(*wire.MsgGetData); ok {
				for _, iv := range gd.InvList {
					asked <- iv.Hash
				}
			}
		}
	}()
	s.pm.mtx.Lock()
	s.pm.peers["peer"] = p
	s.pm.mtx.Unlock()

	return s, msg, p, db, asked
}

// TestHandleBlockInFlightUntilInserted is the regression test for
// blocks downloaded more than once during IBD.
//
// handleBlock removed the block from the in-flight map before the
// insert removed it from blocks missing.  A syncBlocks run in between
// requested the block again from another peer.
func TestHandleBlockInFlightUntilInserted(t *testing.T) {
	s, msg, p, db, asked := inflightServer(t)
	hash := msg.BlockHash()

	// The block was requested and has arrived.
	s.blocks.Put(t.Context(), time.Hour, hash.String(), p, nil, nil)
	done := make(chan error, 1)
	go func() { done <- s.handleBlock(t.Context(), p, msg, nil) }()

	// While the insert runs, a syncBlocks run must not ask again.
	<-db.entered
	if _, _, err := s.blocks.Get(hash.String()); err != nil {
		t.Fatalf("block not in flight during insert: %v", err)
	}
	s.syncBlocks(t.Context())
	select {
	case h := <-asked:
		t.Fatalf("block %v requested again during its insert", h)
	case <-time.After(500 * time.Millisecond):
	}

	close(db.release)
	if err := <-done; err != nil {
		t.Fatalf("handleBlock: %v", err)
	}
	if _, _, err := s.blocks.Get(hash.String()); err == nil {
		t.Fatal("block still in flight after insert")
	}
	bm, err := s.g.db.BlocksMissing(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(bm) != 0 {
		t.Fatalf("blocks missing %v after insert, want 0", len(bm))
	}
}

// TestHandleBlockInFlightRemovedOnError checks that a block whose insert
// fails is no longer in flight, so that it can be requested again.
func TestHandleBlockInFlightRemovedOnError(t *testing.T) {
	s, _, p, db, _ := inflightServer(t)
	close(db.release)

	bad := wire.NewMsgBlock(&wire.BlockHeader{})
	hash := bad.BlockHash()
	s.blocks.Put(t.Context(), time.Hour, hash.String(), p, nil, nil)

	if err := s.handleBlock(t.Context(), p, bad, nil); err == nil {
		t.Fatal("expected insert error")
	}
	if _, _, err := s.blocks.Get(hash.String()); err == nil {
		t.Fatal("failed block still in flight")
	}
}

// TestHandleBlockSlowInsertKeepsPeer checks that a request expiring
// while its block is being inserted does not run the expiry callback,
// which would close the peer that delivered the block.
func TestHandleBlockSlowInsertKeepsPeer(t *testing.T) {
	s, msg, p, db, _ := inflightServer(t)
	hash := msg.BlockHash()

	var expired atomic.Bool
	s.blocks.Put(t.Context(), 100*time.Millisecond, hash.String(), p,
		func(context.Context, any, any) { expired.Store(true) }, nil)
	done := make(chan error, 1)
	go func() { done <- s.handleBlock(t.Context(), p, msg, nil) }()

	// Hold the insert past the original request deadline.
	<-db.entered
	time.Sleep(300 * time.Millisecond)
	close(db.release)
	if err := <-done; err != nil {
		t.Fatalf("handleBlock: %v", err)
	}
	if expired.Load() {
		t.Fatal("expiry callback ran during the insert")
	}
}
