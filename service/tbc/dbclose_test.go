// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
	"github.com/hemilabs/heminetwork/v2/ttl"
)

// parkDB parks a background goroutine inside a database call and
// records whether Close ran while that goroutine was still in the
// database.
type parkDB struct {
	tbcd.Database

	entered chan struct{}
	release chan struct{}
	inside  atomic.Bool
	closed  atomic.Bool
	early   atomic.Bool // Close ran with a goroutine inside
}

func newParkDB() *parkDB {
	return &parkDB{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (d *parkDB) park() {
	d.inside.Store(true)
	close(d.entered)
	<-d.release
	d.inside.Store(false)
}

func (d *parkDB) Close() error {
	if d.inside.Load() {
		d.early.Store(true)
	}
	d.closed.Store(true)
	return nil
}

// populatorParkDB parks the ordinal populator in its first call.
type populatorParkDB struct {
	*parkDB
}

func (d populatorParkDB) BlockHeaderByOrdinalIndex(_ context.Context) (*tbcd.BlockHeader, error) {
	d.park()
	return nil, errors.New("populator stub")
}

// bestParkDB parks the first goroutine that asks for the best header.
type bestParkDB struct {
	*parkDB
}

func (d bestParkDB) BlockHeaderBest(_ context.Context) (*tbcd.BlockHeader, error) {
	d.park()
	return nil, context.Canceled
}

// autoIndexParkDB reports that no blocks are missing, so syncBlocks
// starts auto indexing, and parks the indexing goroutine.
type autoIndexParkDB struct {
	bestParkDB
}

func (d autoIndexParkDB) BlocksMissing(_ context.Context, _ int) ([]tbcd.BlockIdentifier, error) {
	return nil, nil
}

// hashParkDB parks the first goroutine that asks for a header by hash.
type hashParkDB struct {
	*parkDB
}

func (d hashParkDB) BlockHeaderByHash(_ context.Context, _ chainhash.Hash) (*tbcd.BlockHeader, error) {
	d.park()
	return nil, errors.New("hash park stub")
}

// newPipePeer returns a connected peer and the remote end of its
// connection.
func newPipePeer(t *testing.T) (*rawpeer.RawPeer, net.Conn) {
	t.Helper()

	local, remote := net.Pipe()
	t.Cleanup(func() {
		local.Close()
		remote.Close()
	})
	p, err := rawpeer.NewFromConn(local, wire.MainNet, wire.AddrV2Version, 1)
	if err != nil {
		t.Fatal(err)
	}
	return p, remote
}

// newPeerTestServer returns a server with the peer state that the peer
// goroutines use.
func newPeerTestServer(t *testing.T, db tbcd.Database) *Server {
	t.Helper()

	blocks, err := ttl.New(defaultPendingBlocks, true)
	if err != nil {
		t.Fatal(err)
	}
	pings, err := ttl.New(1, true)
	if err != nil {
		t.Fatal(err)
	}
	pm, err := NewPeerManager(wire.MainNet, []string{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		cfg:    &Config{},
		g:      geometryParams{db: db, chain: &chaincfg.MainNetParams},
		blocks: blocks,
		pings:  pings,
		pm:     pm,
	}
}

// assertCloseJoins starts dbClose while a goroutine is parked in db,
// verifies that dbClose blocks, releases the goroutine and verifies
// that dbClose then closes the database.  Call it in a synctest bubble.
func assertCloseJoins(t *testing.T, s *Server, db *parkDB) {
	t.Helper()

	<-db.entered

	closeErr := make(chan error, 1)
	go func() { closeErr <- s.dbClose() }()

	// All goroutines in the bubble are now durably blocked: the parked
	// one on release and dbClose on the join.
	synctest.Wait()
	select {
	case err := <-closeErr:
		t.Fatalf("dbClose returned while database in use: %v", err)
	default:
	}
	if db.closed.Load() {
		t.Fatal("database closed while in use")
	}

	close(db.release)
	if err := <-closeErr; err != nil {
		t.Fatal(err)
	}
	if !db.closed.Load() {
		t.Fatal("database not closed")
	}
	if db.early.Load() {
		t.Fatal("database closed while in use")
	}
}

// TestDBCloseJoinsOrdinalPopulator verifies that the server does not
// close the database while the ordinal populator goroutine still uses
// it.
func TestDBCloseJoinsOrdinalPopulator(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := newParkDB()
		g := geometryParams{
			db:    populatorParkDB{db},
			chain: &chaincfg.RegressionNetParams,
		}
		oi := NewOrdinalIndexer(t.Context(), g, OrdinalIndexerConfig{
			Enabled: true,
		}).(*ordinalIndexer)
		s := &Server{g: g, oi: oi}

		oi.onSyncComplete()
		assertCloseJoins(t, s, db)
	})
}

// TestOrdinalPopulatorNoStartAfterWait verifies that the ordinal
// populator does not start once its owner waited for it.
func TestOrdinalPopulatorNoStartAfterWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := newParkDB()
		g := geometryParams{
			db:    populatorParkDB{db},
			chain: &chaincfg.RegressionNetParams,
		}
		oi := NewOrdinalIndexer(t.Context(), g, OrdinalIndexerConfig{
			Enabled: true,
		}).(*ordinalIndexer)

		oi.wait()
		oi.onSyncComplete()
		synctest.Wait()
		select {
		case <-db.entered:
			t.Fatal("populator started after wait")
		default:
		}
	})
}

// TestDBCloseJoinsAutoIndex verifies that the server does not close
// the database while the auto index goroutine that syncBlocks starts
// still uses it.
func TestDBCloseJoinsAutoIndex(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		blocks, err := ttl.New(defaultPendingBlocks, true)
		if err != nil {
			t.Fatal(err)
		}
		db := newParkDB()
		s := &Server{
			cfg:    &Config{AutoIndex: true},
			g:      geometryParams{db: autoIndexParkDB{bestParkDB{db}}},
			blocks: blocks,
		}

		s.syncBlocks(t.Context())
		assertCloseJoins(t, s, db)
	})
}

// TestDBCloseJoinsPeerHandler verifies that a canceled context closes
// the peer of a running peer handler, and that the server does not
// close the database while that handler still uses it.
func TestDBCloseJoinsPeerHandler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := newParkDB()
		s := newPeerTestServer(t, bestParkDB{db})
		p, remote := newPipePeer(t)

		ctx, cancel := context.WithCancel(t.Context())
		connectDone := make(chan struct{})
		go func() {
			s.connectPeers(ctx)
			close(connectDone)
		}()
		s.pm.peersC <- p
		<-db.entered

		// The handler is parked in the database; cancel must close
		// its peer, so that a handler in the read loop returns.
		readErr := make(chan error, 1)
		go func() {
			_, err := remote.Read(make([]byte, 1))
			readErr <- err
		}()
		cancel()
		<-connectDone
		synctest.Wait()
		select {
		case err := <-readErr:
			if !errors.Is(err, io.EOF) {
				t.Fatalf("remote read: %v", err)
			}
		default:
			t.Fatal("peer not closed on cancel")
		}

		assertCloseJoins(t, s, db)
	})
}

// TestDBCloseJoinsHeadersRequest verifies that the server does not
// close the database while a headers request to a peer still uses it.
func TestDBCloseJoinsHeadersRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := newParkDB()
		s := newPeerTestServer(t, bestParkDB{db})
		p, _ := newPipePeer(t)
		s.pm.peers[p.String()] = p

		s.headersAll(t.Context())
		assertCloseJoins(t, s, db)
	})
}

// TestDBCloseJoinsBlockExpiry verifies that the server does not close
// the database while the expiry of a block request still uses it.
func TestDBCloseJoinsBlockExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := newParkDB()
		s := newPeerTestServer(t, hashParkDB{db})
		p, remote := newPipePeer(t)
		s.pm.peers[p.String()] = p

		// Drain the getdata the request writes to the peer.
		go func() { _, _ = io.Copy(io.Discard, remote) }()

		err := s.downloadBlockFromRandomPeer(t.Context(),
			*chaincfg.MainNetParams.GenesisHash)
		if err != nil {
			t.Fatal(err)
		}
		// Time in the bubble is fake: this expires the request at
		// once and deterministically.
		time.Sleep(defaultBlockPendingTimeout)
		assertCloseJoins(t, s, db)
	})
}

// TestConnectPeersClosesPeerAfterClose verifies that a peer connected
// after dbClose started is closed and not handled.
func TestConnectPeersClosesPeerAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := newParkDB()
		s := newPeerTestServer(t, bestParkDB{db})
		if err := s.dbClose(); err != nil {
			t.Fatal(err)
		}
		p, remote := newPipePeer(t)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go s.connectPeers(ctx)
		s.pm.peersC <- p

		if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("remote read: %v", err)
		}
		synctest.Wait()
		select {
		case <-db.entered:
			t.Fatal("peer handled after dbClose")
		default:
		}
	})
}

// TestGoDBNoStartAfterClose verifies that no database user starts once
// dbClose has started.
func TestGoDBNoStartAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Server{g: geometryParams{db: newParkDB()}}
		if err := s.dbClose(); err != nil {
			t.Fatal(err)
		}

		var ran atomic.Bool
		if s.goDB(func() { ran.Store(true) }) {
			t.Fatal("goDB reported a start after dbClose")
		}
		synctest.Wait()
		if ran.Load() {
			t.Fatal("database user started after dbClose")
		}
	})
}

// populateCancelDB puts the ordinal indexer at the best height with a
// pending watermark, so populateWork enters its work loop.
type populateCancelDB struct {
	tbcd.Database

	bestCalls atomic.Int32
	readWork  atomic.Bool
}

func (d *populateCancelDB) BlockHeaderByOrdinalIndex(_ context.Context) (*tbcd.BlockHeader, error) {
	return &tbcd.BlockHeader{Height: 5}, nil
}

func (d *populateCancelDB) BlockHeaderBest(_ context.Context) (*tbcd.BlockHeader, error) {
	d.bestCalls.Add(1)
	return &tbcd.BlockHeader{Height: 5}, nil
}

func (d *populateCancelDB) OrdinalWatermarkGet(_ context.Context) (uint32, bool, error) {
	return 10, true, nil
}

func (d *populateCancelDB) ReadOrdinalWork(_ context.Context, _ uint32, _ int) ([]tbcd.OrdinalWorkEntry, error) {
	d.readWork.Store(true)
	return nil, errors.New("populate cancel stub")
}

// TestPopulateWorkStopsOnCancel verifies that populateWork does no work
// once its run context is canceled.
func TestPopulateWorkStopsOnCancel(t *testing.T) {
	db := &populateCancelDB{}
	g := geometryParams{db: db, chain: &chaincfg.RegressionNetParams}
	ctx, cancel := context.WithCancel(t.Context())
	oi := NewOrdinalIndexer(ctx, g, OrdinalIndexerConfig{
		Enabled: true,
	}).(*ordinalIndexer)
	cancel()

	oi.populating.Store(1)
	oi.populateWork()

	if db.readWork.Load() {
		t.Fatal("populateWork read work after cancel")
	}
	if got := db.bestCalls.Load(); got != 1 {
		t.Fatalf("best header calls: got %v, want 1", got)
	}
	if oi.populating.Load() != 0 {
		t.Fatal("populating not cleared")
	}
}

// fetchParkDB parks every outpoint lookup until release is closed and
// counts the lookups that are in the database.
type fetchParkDB struct {
	tbcd.Database

	release chan struct{}
	inside  atomic.Int32
}

func (d *fetchParkDB) ScriptHashByOutpoint(_ context.Context, _ tbcd.Outpoint) (*tbcd.ScriptHash, error) {
	d.inside.Add(1)
	defer d.inside.Add(-1)
	<-d.release
	return nil, errors.New("fetch park stub")
}

// TestFixupCacheChannelJoinsFetchesOnCancel verifies that the channel
// fixup does not return on cancel while its fetches still use the
// database.
func TestFixupCacheChannelJoinsFetchesOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// One input more than the fixup has slots, so that the last
		// input waits for a slot.
		const inputs = 129
		spend := wire.NewMsgTx(wire.TxVersion)
		for i := range inputs {
			op := wire.NewOutPoint(&chainhash.Hash{1}, uint32(i))
			spend.AddTxIn(wire.NewTxIn(op, nil, nil))
		}
		coinbase := wire.NewMsgTx(wire.TxVersion)
		coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex), nil, nil))
		mb := wire.NewMsgBlock(&wire.BlockHeader{})
		for _, tx := range []*wire.MsgTx{coinbase, spend} {
			if err := mb.AddTransaction(tx); err != nil {
				t.Fatal(err)
			}
		}

		db := &fetchParkDB{release: make(chan struct{})}
		s := &Server{g: geometryParams{db: db}}

		ctx, cancel := context.WithCancel(t.Context())
		type result struct {
			err    error
			inside int32
		}
		done := make(chan result, 1)
		go func() {
			utxos := make(map[tbcd.Outpoint]tbcd.CacheOutput)
			err := s.fixupCacheChannel(ctx, btcutil.NewBlock(mb), utxos)
			done <- result{err: err, inside: db.inside.Load()}
		}()

		// Every slot holds a parked fetch; the fixup waits for a
		// slot.
		synctest.Wait()
		if got := db.inside.Load(); got != inputs-1 {
			t.Fatalf("fetches in database: got %v, want %v", got,
				inputs-1)
		}

		cancel()
		synctest.Wait()
		select {
		case r := <-done:
			t.Fatalf("fixup returned with %v fetches in database: %v",
				r.inside, r.err)
		default:
		}

		close(db.release)
		r := <-done
		if !errors.Is(r.err, context.Canceled) {
			t.Fatalf("fixup: got %v, want %v", r.err, context.Canceled)
		}
		if r.inside != 0 {
			t.Fatalf("fixup returned with %v fetches in database",
				r.inside)
		}
	})
}

// TestDifficultyTestServerClosesThroughDBClose verifies that the test
// server closes its database through dbClose, so that the goroutines a
// test starts through the server are joined before the database
// closes.
func TestDifficultyTestServerClosesThroughDBClose(t *testing.T) {
	var s *Server
	t.Run("server", func(t *testing.T) {
		s = newDifficultyTestServer(t, &chaincfg.MainNetParams)
	})
	if s.goDB(func() {}) {
		t.Fatal("database user started after the test server closed")
	}
}
