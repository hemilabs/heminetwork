// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
)

// trimStubDB mimics the one side effect of BlockHeadersInsert that matters
// here: it trims bhs.Headers in place, as the real store does when it skips
// the already-known prefix. It takes no lock; the real store trims inside a
// leveldb transaction, which does not cover another replay reading the message.
type trimStubDB struct {
	tbcd.Database
}

func (trimStubDB) BlockHeadersInsert(_ context.Context, bhs *wire.MsgHeaders, _ tbcd.BatchHook) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	bhs.Headers = bhs.Headers[len(bhs.Headers):]
	return tbcd.ITInvalid, nil, nil, 0, database.DuplicateError("duplicate")
}

// Two replays can own the same *wire.MsgHeaders and BlockHeadersInsert trims
// msg.Headers in place, so each replay must hand handleHeaders a private copy.
// Two servers stand in for the two replays so the message is the only thing
// they share. Passing dh[k].msg directly empties x and fails this test even
// without -race.
func TestReplayHandsHandleHeadersAPrivateCopy(t *testing.T) {
	a := deferServer(t)
	b := deferServer(t)
	a.db, b.db = trimStubDB{}, trimStubDB{}

	for round := range 20 {
		x := headersMsg(t, minedChain(t, a, chainhash.Hash{0x51, byte(round)}, 3, byte(round))...)
		last := x.Headers[len(x.Headers)-1].BlockHash()
		for _, s := range []*Server{a, b} {
			s.mtx.Lock()
			s.deferredHeaders = []deferredHeaderMsg{{p: fakePeer(t, 1), msg: x, last: last}}
			s.mtx.Unlock()
		}
		var wg sync.WaitGroup
		for _, s := range []*Server{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.replayDeferredHeaders(t.Context())
			}()
		}
		wg.Wait()
		if len(x.Headers) != 3 {
			t.Fatalf("round %d: the buffered message was trimmed in place (%d headers left); "+
				"its other owner would see a truncated batch", round, len(x.Headers))
		}
	}
}

// A longer message that prepends garbage to the public tip header must not
// displace the honest answer ending at that tip. The quiesce branch only
// buffers a message that passed the contiguity check.
func TestDeferHeadersRejectsGarbagePrefix(t *testing.T) {
	s := deferServer(t)
	s.mtx.Lock()
	s.indexing = true // the quiesce branch is what buffers
	s.mtx.Unlock()

	honest := headersMsg(t, chainOf(chainhash.Hash{0x61}, 3, 1)...)
	tip := honest.Headers[2]
	junk := chainOf(chainhash.Hash{0x62}, 4, 2) // unrelated to the tip
	garbage := headersMsg(t, append(junk, tip)...)

	for i, m := range []*wire.MsgHeaders{honest, garbage} {
		if err := s.handleHeaders(t.Context(), fakePeer(t, 1+i), m); !errors.Is(err, ErrAlreadyIndexing) {
			t.Fatalf("handleHeaders = %v, want ErrAlreadyIndexing", err)
		}
	}

	s.mtx.Lock()
	n := len(s.deferredHeaders)
	held := s.deferredHeaders[0].msg
	s.mtx.Unlock()
	if n != 1 || held != honest {
		t.Fatalf("buffer holds %d messages, slot 0 = %p; want only the honest "+
			"answer %p -- a garbage-prefixed message displaced it", n, held, honest)
	}
}

// The dedupe replace re-attributes a slot to the newcomer, so a host already
// at maxDeferredPerPeer must not gain another slot that way. The longer data
// must still replace the stub; only the attribution respects the cap.
func TestDeferHeadersDedupeReplaceRespectsHostCap(t *testing.T) {
	s := deferServer(t)
	greedy := fakePeer(t, 7)
	other := fakePeer(t, 8)

	target := chainOf(chainhash.Hash{0x71}, 3, 1) // [A, B, T]
	s.mtx.Lock()
	// greedy fills its quota with unrelated answers.
	for i := range maxDeferredPerPeer {
		s.deferHeadersUnlocked(greedy, headersMsg(t, chainOf(chainhash.Hash{0x72, byte(i)}, 2, uint32(10+i))...))
	}
	// other holds the short answer ending at T.
	s.deferHeadersUnlocked(other, headersMsg(t, target[2]))
	// greedy tries to take other's slot with the longer answer ending at T.
	s.deferHeadersUnlocked(greedy, headersMsg(t, target...))

	mine := 0
	for k := range s.deferredHeaders {
		if peerHost(s.deferredHeaders[k].p) == peerHost(greedy) {
			mine++
		}
	}
	s.mtx.Unlock()

	if mine > maxDeferredPerPeer {
		t.Fatalf("host holds %d slots, cap is %d: the dedupe replace bypassed the "+
			"per-host cap", mine, maxDeferredPerPeer)
	}

	// The longer data must still replace the stub, but the slot stays with
	// other.
	tHash := target[2].BlockHash()
	for _, l := range deferredLasts(s) {
		if l.IsEqual(&tHash) {
			s.mtx.Lock()
			for k := range s.deferredHeaders {
				if s.deferredHeaders[k].last.IsEqual(&tHash) {
					if n := len(s.deferredHeaders[k].msg.Headers); n != len(target) {
						s.mtx.Unlock()
						t.Fatalf("slot ending at the tip holds %d headers, want the "+
							"longer %d-header answer", n, len(target))
					}
					if peerHost(s.deferredHeaders[k].p) != peerHost(other) {
						s.mtx.Unlock()
						t.Fatal("a capped host was attributed the slot")
					}
				}
			}
			s.mtx.Unlock()
			return
		}
	}
	t.Fatal("the answer ending at the tip is gone from the buffer")
}

// If the indexing pass has already ended when the unreplayed remainder is
// seated, that pass's replay may already have run, so the requeue must start a
// replay itself. While indexing is still running it must not; the pass-end
// replay picks the remainder up.
func TestRequeueWhenIdleReplaysTheRemainder(t *testing.T) {
	t.Run("idle: remainder is replayed", func(t *testing.T) {
		s, db := replayServer(t)
		rem := []deferredHeaderMsg{}
		for i := range 2 {
			m := headersMsg(t, minedChain(t, s, chainhash.Hash{0x81, byte(i)}, 2, byte(20+i))...)
			rem = append(rem, deferredHeaderMsg{p: fakePeer(t, 1), msg: m, last: m.Headers[1].BlockHash()})
		}
		s.requeueDeferredHeadersUnreplayed(t.Context(), rem) // s.indexing is false

		deadline := time.Now().Add(5 * time.Second)
		for db.applied() < len(rem) {
			if time.Now().After(deadline) {
				t.Fatalf("remainder requeued on an idle node was never replayed "+
					"(%d of %d applied); it would sit until some later pass",
					db.applied(), len(rem))
			}
			time.Sleep(5 * time.Millisecond)
		}
	})

	t.Run("indexing: no replay is spawned", func(t *testing.T) {
		s, db := replayServer(t)
		m := headersMsg(t, minedChain(t, s, chainhash.Hash{0x82}, 2, 30)...)
		requeueWhileIndexing(t, s, []deferredHeaderMsg{{p: fakePeer(t, 1), msg: m, last: m.Headers[1].BlockHash()}})
		time.Sleep(200 * time.Millisecond)
		if n := db.applied(); n != 0 {
			t.Fatalf("%d messages applied while indexing was running", n)
		}
		if got := deferredLasts(s); len(got) != 1 {
			t.Fatalf("remainder not held for the pass-end replay: %v", got)
		}
	})
}

// A rate-limited drain sends nothing inside the window and does not put the
// hashes back into invBlocks, but its deferred fan-out must go out once the
// window reopens. Otherwise a real announcement waits for an unrelated
// syncBlocks kick or the periodic refresh.
func TestRateLimitedDrainDefersTheFanout(t *testing.T) {
	const junk = 500
	missed := make([]chainhash.Hash, junk)
	for i := range missed {
		missed[i][0], missed[i][1], missed[i][31] = byte(i), byte(i>>8), 0xd7
	}
	s, _ := drainServer(t, missed...)
	peers := addPeers(t, s, 1)
	s.mtx.Lock()
	s.drainFanout = time.Now() // a fan-out just happened: rate limited
	s.mtx.Unlock()

	s.syncBlocks(t.Context())
	peers[0].silent(t, drainFanoutInterval/2)

	s.mtx.Lock()
	n := len(s.invBlocks)
	s.mtx.Unlock()
	if n != 0 {
		t.Fatalf("rate-limited drain re-seated %d of %d unsolicited hashes", n, junk)
	}
	if _, ok := peers[0].next(t, 5*drainFanoutInterval).(*wire.MsgGetHeaders); !ok {
		t.Fatal("the deferred fan-out never went out")
	}
}

// contextSpyDB counts BlockHeaderByHash reads, to catch the context walk, and
// reports every insert as a duplicate.
type contextSpyDB struct {
	tbcd.Database
	headers     map[chainhash.Hash]*tbcd.BlockHeader
	byHashCalls int
	insertCalls int
}

func (d *contextSpyDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	d.byHashCalls++
	if bh, ok := d.headers[h]; ok {
		return bh, nil
	}
	return nil, database.NotFoundError("block header not found")
}

func (d *contextSpyDB) BlockHeadersInsert(_ context.Context, _ *wire.MsgHeaders, _ tbcd.BatchHook) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	d.insertCalls++
	return tbcd.ITInvalid, nil, nil, 0, database.ErrDuplicate
}

// contextWindow builds a mainnet (retargeting) chain with an easy PoW limit so
// headers can be mined in a test: unmined ancestors at heights 0..2015, whose
// PoW is never rechecked, plus a mined tip at the retarget boundary 2016. All
// of them are stored in the spy.
func contextWindow(t *testing.T) (*chaincfg.Params, *contextSpyDB, *wire.BlockHeader) {
	t.Helper()
	p := chaincfg.MainNetParams
	p.PowLimit = chaincfg.RegressionNetParams.PowLimit
	p.PowLimitBits = chaincfg.RegressionNetParams.PowLimitBits

	spy := &contextSpyDB{headers: make(map[chainhash.Hash]*tbcd.BlockHeader, 2018)}
	base := time.Unix(1600000000, 0)
	var prevHash chainhash.Hash
	for h := 0; h <= 2015; h++ {
		wh := &wire.BlockHeader{
			Version:   1,
			PrevBlock: prevHash,
			Bits:      p.PowLimitBits,
			Timestamp: base.Add(time.Duration(int64(h)*600) * time.Second),
			Nonce:     uint32(h),
		}
		hh := wh.BlockHash()
		spy.headers[hh] = &tbcd.BlockHeader{Hash: hh, Height: uint64(h), Header: h2b(wh)}
		prevHash = hh
	}
	// Genuinely mine the boundary tip so it clears verifyHeadersPoW on replay.
	tip := mineHeader(t, &prevHash, p.PowLimitBits, 0xaa)
	th := tip.BlockHash()
	spy.headers[th] = &tbcd.BlockHeader{Hash: th, Height: 2016, Header: h2b(tip)}
	return &p, spy, tip
}

// Replaying an already-stored contiguous batch whose tip is a retarget
// boundary must not trigger the ~2015-hop context walk: a stored tip plus
// contiguity means the whole batch is already stored.
func TestHandleHeadersReplaySkipsContextWalk(t *testing.T) {
	params, spy, tip := contextWindow(t)
	s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: params, db: spy}

	msg := wire.NewMsgHeaders()
	if err := msg.AddBlockHeader(tip); err != nil {
		t.Fatal(err)
	}
	if err := s.handleHeaders(t.Context(), fakePeer(t, 0), msg); err != nil {
		t.Fatalf("replayed known boundary tip must be accepted (deduped), got %v", err)
	}

	// With the gate, only the tip lookup happens (1). The unbounded walk would
	// be ~2016. A threshold of 2 leaves headroom while staying far below it.
	if spy.byHashCalls > 2 {
		t.Fatalf("replayed known boundary tip triggered %v BlockHeaderByHash reads; "+
			"the context walk must be skipped when the tip is already stored", spy.byHashCalls)
	}
	if spy.insertCalls != 1 {
		t.Fatalf("expected exactly one BlockHeadersInsert (the dedup), got %v", spy.insertCalls)
	}
}

// A stored tip must never let a crafted batch through. Contiguity and PoW run
// on every batch before the context skip, so a non-contiguous or bad-PoW
// batch is rejected and never inserted.
func TestHandleHeadersNonContiguousKnownTipStillRejected(t *testing.T) {
	t.Run("contiguous batch with a bad-PoW header is rejected by verifyHeadersPoW", func(t *testing.T) {
		params, spy, tip := contextWindow(t)
		s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: params, db: spy}

		// Connects to the known tip, so only PoW can reject it. Claims a
		// hard target but is not mined.
		garbage := &wire.BlockHeader{
			Version:   1,
			PrevBlock: tip.BlockHash(),
			Bits:      0x1b0404cb, // far harder than the easy PoW limit; unmined
			Timestamp: time.Unix(1700000000, 0),
		}
		msg := wire.NewMsgHeaders()
		for _, h := range []*wire.BlockHeader{tip, garbage} {
			if err := msg.AddBlockHeader(h); err != nil {
				t.Fatal(err)
			}
		}
		err := s.handleHeaders(t.Context(), fakePeer(t, 0), msg)
		if err == nil || !strings.Contains(err.Error(), "proof-of-work") {
			t.Fatalf("bad-PoW header must be rejected by PoW, got %v", err)
		}
		if spy.insertCalls != 0 {
			t.Fatalf("a rejected batch reached the store (%v inserts)", spy.insertCalls)
		}
	})

	t.Run("mined-but-non-contiguous first header is rejected by shape", func(t *testing.T) {
		params, spy, tip := contextWindow(t)
		s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: params, db: spy}

		// Genuinely mined (clears PoW) but does not connect to the tip.
		orphan := chainhash.Hash{0xbe, 0xef}
		garbage := mineHeader(t, &orphan, params.PowLimitBits, 0xbb)
		msg := wire.NewMsgHeaders()
		for _, h := range []*wire.BlockHeader{garbage, tip} {
			if err := msg.AddBlockHeader(h); err != nil {
				t.Fatal(err)
			}
		}
		// The batch must be rejected and never stored. Which check
		// rejects it does not matter, only that a stored tip does not
		// let a non-contiguous first header through.
		err := s.handleHeaders(t.Context(), fakePeer(t, 0), msg)
		if err == nil {
			t.Fatal("non-contiguous batch with a known tip must be rejected")
		}
		if spy.insertCalls != 0 {
			t.Fatalf("a rejected batch reached the store (%v inserts)", spy.insertCalls)
		}
	})
}

// handleHeaders' empty branch fans out once per reply but costs one mempool
// message per peer, so one getheaders round to N peers yields N^2 mempool
// messages. btcd charges 33 ban score per mempool message against a threshold
// of 100, so with four or more peers every btcd peer bans us.
func TestMempoolFanoutIsRateLimited(t *testing.T) {
	s := deferServer(t)

	if !s.mempoolFanoutDue() {
		t.Fatal("the first fan out was refused; the mempool would never be built")
	}
	if s.mempoolFanoutDue() {
		t.Fatalf("a second fan out was allowed immediately. The empty-headers "+
			"branch fires once per reply and costs one mempool message per "+
			"peer, so an unlimited fan out is N^2 messages; btcd bans at the "+
			"fourth in a burst (33 ban score each against a threshold of 100). "+
			"mempoolFanoutInterval = %v", mempoolFanoutInterval)
	}

	// ...and it must not latch off permanently: once the interval has
	// elapsed the mempool has to be rebuildable.
	s.mtx.Lock()
	s.mempoolFanout = time.Now().Add(-2 * mempoolFanoutInterval)
	s.mtx.Unlock()
	if !s.mempoolFanoutDue() {
		t.Fatal("no fan out was allowed a full interval later; the limiter " +
			"latched off and the mempool can never be refreshed")
	}
}

// A correct mempoolFanoutDue that nothing calls is still an unlimited fan out.
// The limiter records when it last allowed one, so an empty headers message
// that reached the mempool arm must leave s.mempoolFanout non-zero.
func TestHandleHeadersEmptyBranchConsultsTheRateLimiter(t *testing.T) {
	s, _ := newRecoveryServer(t)
	s.cfg.MempoolEnabled = true
	peers := addPeers(t, s, 1)

	// Sanity: this fixture really does take the mempool arm, i.e. we are
	// synced with nothing missing. Otherwise the assertion below is vacuous.
	if !s.Synced(t.Context()).Synced {
		t.Fatal("fixture is not synced, so the empty branch never reaches the mempool arm")
	}
	if s.blksMissing(t.Context()) {
		t.Fatal("fixture reports blocks missing, so the empty branch takes the other arm")
	}

	if err := s.handleHeaders(t.Context(), peers[0].rp, wire.NewMsgHeaders()); err != nil {
		t.Fatalf("handleHeaders: %v", err)
	}

	s.mtx.Lock()
	fanout := s.mempoolFanout
	s.mtx.Unlock()
	if fanout.IsZero() {
		t.Fatal("an empty headers message reached the mempool fan out without " +
			"going through mempoolFanoutDue. The fan out is per reply and costs " +
			"one mempool message per peer, so unlimited it is N^2 and btcd bans " +
			"us at the fourth message in a burst.")
	}
}

// btcd halves transient ban score every 60s and charges 33 per mempool message
// against a threshold of 100, so one message per minute settles at 66 and one
// every ~35s or faster converges on a ban. Too long an interval leaves a
// synced node with a stale mempool, since this fan out is how it gets built.
func TestMempoolFanoutIntervalIsSane(t *testing.T) {
	if mempoolFanoutInterval < time.Minute {
		t.Fatalf("mempoolFanoutInterval = %v: btcd charges 33 ban score per "+
			"mempool message against a threshold of 100 and halves it every "+
			"60s, so this converges on a ban from every btcd peer",
			mempoolFanoutInterval)
	}
	if mempoolFanoutInterval > time.Hour {
		t.Fatalf("mempoolFanoutInterval = %v: the empty-headers branch is how "+
			"the mempool is built, so this leaves a synced node serving a stale "+
			"mempool for that long", mempoolFanoutInterval)
	}
}

// The unreplayed remainder must survive and go back in order, ahead of
// whatever arrived during the replay. A headers batch only inserts if its
// parent is stored, so replaying a later segment first orphans it, and
// re-admitting the remainder through deferHeadersUnlocked lets new arrivals
// take its per-peer slots and drop it.
func TestRequeueDeferredHeadersSeatsTheRemainderAtTheFront(t *testing.T) {
	g := chainhash.Hash{0xd1}

	t.Run("ordering", func(t *testing.T) {
		s := deferServer(t)

		// Two unreplayed messages from one peer, in buffer order.
		rp := fakePeer(t, 1)
		rem := make([]deferredHeaderMsg, 0, 2)
		for i := range 2 {
			m := headersMsg(t, chainOf(g, 3, uint32(10+i))...)
			rem = append(rem, deferredHeaderMsg{
				p: rp, msg: m, last: m.Headers[len(m.Headers)-1].BlockHash(),
			})
		}

		// Something a peer buffered while the replay was in flight.
		arrived := headersMsg(t, chainOf(g, 3, 99)...)
		s.mtx.Lock()
		s.deferHeadersUnlocked(fakePeer(t, 2), arrived)
		s.mtx.Unlock()

		requeueWhileIndexing(t, s, rem)

		got := deferredLasts(s)
		if len(got) != 3 {
			t.Fatalf("buffer holds %v messages, want 3 (2 requeued + 1 arrived): %v",
				len(got), got)
		}
		if got[0] != rem[0].last || got[1] != rem[1].last {
			t.Fatalf("the unreplayed remainder is not at the FRONT, in order.\n"+
				" got: %v\nwant: [%v %v ...]\n"+
				"A headers batch only inserts if its parent is already in the "+
				"store, so replaying a later segment before an earlier one "+
				"orphans it.", got, rem[0].last, rem[1].last)
		}
	})

	t.Run("remainder survives a full buffer", func(t *testing.T) {
		s := deferServer(t)

		// The buffer filled up while the replay was running.
		s.mtx.Lock()
		for i := range 4 * maxDeferredHeaderMsgs {
			p := fakePeer(t, 100+i)
			for j := range maxDeferredPerPeer {
				s.deferHeadersUnlocked(p,
					headersMsg(t, chainOf(g, 2, uint32(2000+i*10+j))...))
			}
		}
		full := len(s.deferredHeaders)
		s.mtx.Unlock()
		if full != maxDeferredHeaderMsgs {
			t.Fatalf("fixture: buffer holds %v, want it full at %v",
				full, maxDeferredHeaderMsgs)
		}

		rp := fakePeer(t, 1)
		m := headersMsg(t, chainOf(g, 3, 4242)...)
		rem := []deferredHeaderMsg{{
			p: rp, msg: m, last: m.Headers[len(m.Headers)-1].BlockHash(),
		}}

		requeueWhileIndexing(t, s, rem)

		got := deferredLasts(s)
		if len(got) == 0 || got[0] != rem[0].last {
			t.Fatalf("the unreplayed remainder was DROPPED by a full buffer.\n"+
				" got: %v\nwant it seated first at %v\n"+
				"rem came out of this same buffer, so it is already deduped and "+
				"already within the per-peer cap; re-running admission on it is "+
				"exactly what turned a reordering bug into data loss.",
				got, rem[0].last)
		}
	})
}

// kickStubDB is newRecoveryServer's stub plus a record of which store calls the
// replay makes and in what order, so the kick can be located relative to the
// buffered data it must follow.
type kickStubDB struct {
	recoveryStubDB

	mtx      sync.Mutex
	calls    []string
	entered  chan struct{}
	release  chan struct{}
	inserted int
}

func (d *kickStubDB) note(what string) {
	d.mtx.Lock()
	d.calls = append(d.calls, what)
	d.mtx.Unlock()
}

func (d *kickStubDB) seen() []string {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return append([]string(nil), d.calls...)
}

func (d *kickStubDB) BlocksMissing(ctx context.Context, count int) ([]tbcd.BlockIdentifier, error) {
	// syncBlocks asks for a budget-sized batch; blksMissing asks for 1. Only
	// the first is evidence that syncBlocks itself ran.
	if count >= defaultPendingBlocks {
		d.note("syncBlocks")
	}
	return d.recoveryStubDB.BlocksMissing(ctx, count)
}

func (d *kickStubDB) BlockHeadersInsert(_ context.Context, _ *wire.MsgHeaders, _ tbcd.BatchHook) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	d.note("replay")
	d.mtx.Lock()
	d.inserted++
	d.mtx.Unlock()
	if d.entered != nil {
		select {
		case d.entered <- struct{}{}:
		default:
		}
		<-d.release
	}
	return tbcd.ITInvalid, nil, nil, 0, database.DuplicateError("duplicate")
}

// kickServer is newRecoveryServer wired to the recording stub.
func kickServer(t *testing.T) (*Server, *kickStubDB) {
	t.Helper()
	s, db := newRecoveryServer(t)
	k := &kickStubDB{recoveryStubDB: *db}
	s.db = k
	return s, k
}

// swallowEmpty drives the quiesce branch with an EMPTY headers message, which
// is what sets s.deferredEmpty.
func swallowEmpty(t *testing.T, s *Server, p *rawpeer.RawPeer) {
	t.Helper()
	s.mtx.Lock()
	s.indexing = true
	s.mtx.Unlock()
	if err := s.handleHeaders(t.Context(), p, wire.NewMsgHeaders()); !errors.Is(err, ErrAlreadyIndexing) {
		t.Fatalf("handleHeaders(empty) = %v, want ErrAlreadyIndexing", err)
	}
	s.mtx.Lock()
	s.indexing = false
	if !s.deferredEmpty {
		s.mtx.Unlock()
		t.Fatal("the quiesce branch did not record the swallowed empty headers " +
			"message, so there is nothing for the replay to re-issue")
	}
	s.mtx.Unlock()
}

// An empty headers message normally ends in a syncBlocks kick, which is what
// turns BlocksMissing into getdata. The quiesce branch cannot buffer it, so
// the replay must re-issue the kick or a node with blocks missing goes quiet.
func TestReplayReissuesTheSwallowedEmptyHeadersKick(t *testing.T) {
	s, db := kickServer(t)
	peers := addPeers(t, s, 1)

	missing := chainhash.Hash{0xf1}
	db.missing = []tbcd.BlockIdentifier{{Height: 1, Hash: &missing}}

	swallowEmpty(t, s, peers[0].rp)
	s.replayDeferredHeaders(t.Context())

	gd, ok := peers[0].next(t, 10*time.Second).(*wire.MsgGetData)
	if !ok {
		t.Fatal("the replay issued no getdata for a block we are missing")
	}
	if len(gd.InvList) != 1 || gd.InvList[0].Hash != missing {
		t.Fatalf("getdata = %v, want a single entry for %v", gd.InvList, missing)
	}
}

// The re-issued kick is for getdata, which needs blocks to be missing. An
// ungated kick would start a pointless SyncIndexersToBest on an idle synced
// node after every indexing pass.
func TestReplayKickIsGatedOnBlocksMissing(t *testing.T) {
	s, db := kickServer(t)
	s.cfg.AutoIndex = true // so an ungated kick has somewhere to go
	db.missing = nil       // nothing missing: the gate must hold

	// A missed announcement, so an ungated kick reaches the drain and is
	// observable on the wire.
	missed := chainhash.Hash{0xe1}
	s.mtx.Lock()
	s.invBlocks[missed] = struct{}{}
	s.mtx.Unlock()

	peers := addPeers(t, s, 1)
	swallowEmpty(t, s, peers[0].rp)
	s.replayDeferredHeaders(t.Context())

	time.Sleep(1500 * time.Millisecond)
	if calls := db.seen(); len(calls) != 0 {
		t.Fatalf("the replay started syncBlocks on a node with nothing missing "+
			"(store calls: %v). The gate on blksMissing is what keeps the "+
			"re-issued kick from spawning a pointless SyncIndexersToBest every "+
			"time an indexing pass ends.", calls)
	}
	peers[0].silent(t, 250*time.Millisecond)
}

// The kick spawns syncBlocks, which can start SyncIndexersToBest and set
// s.indexing again. Fired first, it makes the rest of the replay return
// ErrAlreadyIndexing and re-buffer the data instead of applying it. The kick
// runs in a goroutine, so the replay is parked in its first insert and we
// check that syncBlocks has not run yet.
func TestReplayFiresTheKickAfterTheBufferedData(t *testing.T) {
	s, db := kickServer(t)
	db.entered = make(chan struct{}, 1)
	db.release = make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(db.release) }) }
	t.Cleanup(release)

	missing := chainhash.Hash{0xf2}
	db.missing = []tbcd.BlockIdentifier{{Height: 1, Hash: &missing}}

	p := fakePeer(t, 0)
	msg := headersMsg(t, minedChain(t, s, chainhash.Hash{0xd9}, 2, 4)...)
	s.mtx.Lock()
	s.indexing = true
	s.mtx.Unlock()
	if err := s.handleHeaders(t.Context(), p, msg); !errors.Is(err, ErrAlreadyIndexing) {
		t.Fatalf("handleHeaders = %v", err)
	}
	swallowEmpty(t, s, p)

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.replayDeferredHeaders(t.Context())
	}()

	select {
	case <-db.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the buffered headers message never reached the store")
	}

	// The replay is parked inside BlockHeadersInsert. Give a kick that was
	// fired first ample time to have reached syncBlocks.
	time.Sleep(500 * time.Millisecond)
	calls := db.seen()
	for _, c := range calls {
		if c == "syncBlocks" {
			t.Fatalf("syncBlocks ran while the replay was still applying "+
				"buffered headers (calls: %v). The kick must be fired LAST: "+
				"syncBlocks spawns SyncIndexersToBest, which sets s.indexing "+
				"again and makes the rest of the replay return "+
				"ErrAlreadyIndexing, so the buffered data is re-buffered "+
				"instead of applied.", calls)
		}
	}

	release()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("replay did not finish")
	}
	// Not vacuous: the data really was applied, and the kick really did fire
	// afterwards.
	db.mtx.Lock()
	n := db.inserted
	db.mtx.Unlock()
	if n == 0 {
		t.Fatal("no buffered headers message was applied at all")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range db.seen() {
			if c == "syncBlocks" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the kick never fired after the replay finished: %v", db.seen())
}

// TestInvBlocksIsBounded is satisfied by any positive maxInvBlocks, so this
// bounds the value itself. With AutoIndex off, as op-geth's embedded node
// runs, nothing drains invBlocks, so the cap sizes a permanent allocation. It
// must still span an indexing pass with room to spare.
func TestInvBlocksCapIsSane(t *testing.T) {
	const bytesPerEntry = 64 // 32-byte key plus map overhead, rounded up
	if maxInvBlocks > (128<<20)/bytesPerEntry {
		t.Fatalf("maxInvBlocks = %v: at ~%v bytes per entry that is %v MiB of "+
			"permanently retained announcements inside a validator process, and "+
			"nothing removes them when AutoIndex is off",
			maxInvBlocks, bytesPerEntry, maxInvBlocks*bytesPerEntry>>20)
	}
	if maxInvBlocks < 1024 {
		t.Fatalf("maxInvBlocks = %v: that is smaller than the announcements a "+
			"single mainnet indexing pass can see, so the map is a bound in "+
			"name only", maxInvBlocks)
	}
}

// TestDeferHeadersRespectsTheGlobalBound is satisfied by any non-zero value of
// maxDeferredHeaderMsgs, so this bounds the constants themselves. Each slot
// holds up to 2000 decoded headers of 104 bytes (~208KB), and peers can fill
// the buffer during every indexing pass.
func TestDeferredBufferBoundIsSane(t *testing.T) {
	const perSlot = wire.MaxBlockHeadersPerMsg * 104 // ~208KB
	if maxDeferredHeaderMsgs*perSlot > 32<<20 {
		t.Fatalf("maxDeferredHeaderMsgs = %v: %v MiB of peer-fillable retention "+
			"during every indexing pass", maxDeferredHeaderMsgs,
			maxDeferredHeaderMsgs*perSlot>>20)
	}
	if maxDeferredHeaderMsgs < 4 {
		t.Fatalf("maxDeferredHeaderMsgs = %v: too few slots to hold one answer "+
			"from more than a couple of peers, so honest replies are dropped "+
			"and the quiesce branch is back to discarding header data",
			maxDeferredHeaderMsgs)
	}
	if maxDeferredPerPeer >= maxDeferredHeaderMsgs {
		t.Fatalf("maxDeferredPerPeer = %v of %v slots: one peer can own the "+
			"whole buffer, which is the starvation the per-peer cap exists to "+
			"prevent", maxDeferredPerPeer, maxDeferredHeaderMsgs)
	}
}
