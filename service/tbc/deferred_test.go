// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// chainOf returns n unmined headers that form a contiguous chain descending
// from prev. The admission paths tested here run before verifyHeadersPoW, so
// PoW is not needed. tag makes sibling chains distinct, so chainOf(g, 3, 1)
// and chainOf(g, 3, 2) are two forks off the same parent.
func chainOf(prev chainhash.Hash, n int, tag uint32) []*wire.BlockHeader {
	out := make([]*wire.BlockHeader, 0, n)
	p := prev
	for i := range n {
		h := &wire.BlockHeader{
			Version:   1,
			PrevBlock: p,
			Timestamp: time.Unix(1700000000, 0),
			Bits:      0x207fffff,
			Nonce:     tag*1e6 + uint32(i),
		}
		out = append(out, h)
		p = h.BlockHash()
	}
	return out
}

func headersMsg(t *testing.T, hdrs ...*wire.BlockHeader) *wire.MsgHeaders {
	t.Helper()
	m := wire.NewMsgHeaders()
	for _, h := range hdrs {
		if err := m.AddBlockHeader(h); err != nil {
			t.Fatalf("add block header: %v", err)
		}
	}
	return m
}

// fakePeer returns an unconnected *rawpeer.RawPeer with a distinct host per
// id. deferHeadersUnlocked only looks at the peer's address, so no connection
// is needed.
func fakePeer(t *testing.T, id int) *rawpeer.RawPeer {
	t.Helper()
	// Vary the host, not the port: the per-peer cap is keyed on the host (see
	// peerHost), so ids differing only by port would all be one peer.
	p, err := rawpeer.New(wire.TestNet, id,
		fmt.Sprintf("10.%d.%d.%d:8333", (id>>16)&0xff, (id>>8)&0xff, id&0xff))
	if err != nil {
		t.Fatalf("rawpeer new: %v", err)
	}
	return p
}

// deferServer is a bare server; the buffer tests never reach the store.
func deferServer(t *testing.T) *Server {
	t.Helper()
	cfg := NewDefaultConfig()
	cfg.Network = networkLocalnet
	cfg.MempoolEnabled = false
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s
}

func deferredLasts(s *Server) []chainhash.Hash {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	out := make([]chainhash.Hash, 0, len(s.deferredHeaders))
	for k := range s.deferredHeaders {
		out = append(out, s.deferredHeaders[k].last)
	}
	return out
}

// ===========================================================================
// deferHeadersUnlocked: buffer admission
// ===========================================================================

// TestDeferHeadersDedupesOnTheLastHeader checks that identical answers from
// several peers take one slot, and that the key is the last header: two
// answers that start at the same header and then diverge are a fork, which a
// first-header key would drop as a duplicate.
func TestDeferHeadersDedupesOnTheLastHeader(t *testing.T) {
	g := chainhash.Hash{0x01}
	main := chainOf(g, 5, 1)
	fork := chainOf(g, 5, 2) // same parent, different chain

	p0 := fakePeer(t, 0)
	p1 := fakePeer(t, 1)

	tests := []struct {
		name string
		msgs []struct {
			p *rawpeer.RawPeer
			h []*wire.BlockHeader
		}
		want int
		why  string
	}{
		{
			name: "identical answers from two peers are deduped",
			msgs: []struct {
				p *rawpeer.RawPeer
				h []*wire.BlockHeader
			}{{p0, main}, {p1, main}},
			want: 1,
			why:  "one refresh tick makes every peer answer the same question",
		},
		{
			name: "a shorter answer ending at the same header is deduped",
			msgs: []struct {
				p *rawpeer.RawPeer
				h []*wire.BlockHeader
			}{{p0, main}, {p1, main[2:]}},
			want: 1,
			why:  "same tip, same information",
		},
		{
			name: "a FORK sharing our first header must NOT be deduped",
			msgs: []struct {
				p *rawpeer.RawPeer
				h []*wire.BlockHeader
			}{{p0, main[:1]}, {p1, append([]*wire.BlockHeader{main[0]}, chainOf(main[0].BlockHash(), 4, 3)...)}},
			want: 2,
			why: "these two answers start at the same header and diverge; keying " +
				"the dedupe on the FIRST header throws the fork away, which is " +
				"precisely the message the buffer exists to carry",
		},
		{
			name: "two genuinely different answers are both kept",
			msgs: []struct {
				p *rawpeer.RawPeer
				h []*wire.BlockHeader
			}{{p0, main}, {p1, fork}},
			want: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := deferServer(t)
			s.mtx.Lock()
			for _, m := range tc.msgs {
				s.deferHeadersUnlocked(m.p, headersMsg(t, m.h...))
			}
			n := len(s.deferredHeaders)
			s.mtx.Unlock()
			if n != tc.want {
				t.Fatalf("buffered %v messages, want %v. %v\nlasts: %v",
					n, tc.want, tc.why, deferredLasts(s))
			}
		})
	}
}

// TestDeferHeadersCapsSlotsPerPeer checks that one flooding peer cannot take
// more than maxDeferredPerPeer slots and starve honest replies. The cap must
// also be at least 2 so a peer can hold its answer plus a following fork.
func TestDeferHeadersCapsSlotsPerPeer(t *testing.T) {
	g := chainhash.Hash{0x02}
	flooder := fakePeer(t, 0)
	honest := fakePeer(t, 1)

	s := deferServer(t)

	// The flooder offers far more distinct answers than the cap.
	s.mtx.Lock()
	for i := range 8 {
		s.deferHeadersUnlocked(flooder, headersMsg(t, chainOf(g, 3, uint32(100+i))...))
	}
	got := len(s.deferredHeaders)
	s.mtx.Unlock()

	if got != maxDeferredPerPeer {
		t.Fatalf("one peer took %v of %v slots with 8 distinct answers, want at "+
			"most maxDeferredPerPeer=%v; without this cap a single peer starves "+
			"every honest reply out of the buffer",
			got, maxDeferredHeaderMsgs, maxDeferredPerPeer)
	}
	if maxDeferredPerPeer < 2 {
		t.Fatalf("maxDeferredPerPeer = %v: a peer cannot hold both its answer "+
			"and the fork it announces immediately afterwards", maxDeferredPerPeer)
	}

	// An honest peer must still be admitted after the flooder hit its cap.
	s.mtx.Lock()
	s.deferHeadersUnlocked(honest, headersMsg(t, chainOf(g, 3, 999)...))
	got = len(s.deferredHeaders)
	s.mtx.Unlock()
	if got != maxDeferredPerPeer+1 {
		t.Fatalf("an honest peer's answer was refused after a flooder filled "+
			"its own quota: buffer holds %v, want %v", got, maxDeferredPerPeer+1)
	}
}

// TestDeferHeadersCapIsKeyedOnAddressNotPointer checks that reconnecting does
// not reset the per-peer cap. Every reconnection yields a new *RawPeer for the
// same remote, so a pointer-keyed cap would let one address fill the buffer.
func TestDeferHeadersCapIsKeyedOnAddressNotPointer(t *testing.T) {
	g := chainhash.Hash{0x0c}
	s := deferServer(t)

	// Eight DIFFERENT *RawPeer values that all share one remote address, as a
	// reconnecting peer produces.
	s.mtx.Lock()
	for i := range 8 {
		p, err := rawpeer.New(wire.TestNet, i, "203.0.113.9:8333")
		if err != nil {
			t.Fatalf("rawpeer new: %v", err)
		}
		s.deferHeadersUnlocked(p, headersMsg(t, chainOf(g, 2, uint32(500+i))...))
	}
	got := len(s.deferredHeaders)
	s.mtx.Unlock()

	if got != maxDeferredPerPeer {
		t.Fatalf("one address took %v of %v slots across 8 reconnections, want "+
			"maxDeferredPerPeer=%v. The cap is keyed on the *RawPeer pointer, so "+
			"reconnecting resets the tally and one remote can still own the "+
			"whole buffer.", got, maxDeferredHeaderMsgs, maxDeferredPerPeer)
	}
}

// TestDeferHeadersCapIgnoresThePort checks that the per-peer cap is keyed on
// the remote host, not host:port. Ports cost an attacker nothing, so one host
// under many ports must still count as one peer.
func TestDeferHeadersCapIgnoresThePort(t *testing.T) {
	g := chainhash.Hash{0x0d}
	s := deferServer(t)

	// One host, eight ports.
	s.mtx.Lock()
	for i := range 8 {
		p, err := rawpeer.New(wire.TestNet, i,
			fmt.Sprintf("198.51.100.7:%d", 8333+i))
		if err != nil {
			t.Fatalf("rawpeer new: %v", err)
		}
		s.deferHeadersUnlocked(p, headersMsg(t, chainOf(g, 2, uint32(700+i))...))
	}
	got := len(s.deferredHeaders)
	s.mtx.Unlock()

	if got != maxDeferredPerPeer {
		t.Fatalf("one host took %v of %v slots across 8 source ports, want "+
			"maxDeferredPerPeer=%v. The tally is keyed on host:port, so a "+
			"single attacker host varies its port and owns the whole buffer.",
			got, maxDeferredHeaderMsgs, maxDeferredPerPeer)
	}

	// A genuinely different host must still get in.
	s.mtx.Lock()
	other, err := rawpeer.New(wire.TestNet, 99, "203.0.113.4:8333")
	if err != nil {
		t.Fatalf("rawpeer new: %v", err)
	}
	s.deferHeadersUnlocked(other, headersMsg(t, chainOf(g, 2, 799)...))
	got = len(s.deferredHeaders)
	s.mtx.Unlock()
	if got != maxDeferredPerPeer+1 {
		t.Fatalf("a different host was refused: buffer holds %v, want %v",
			got, maxDeferredPerPeer+1)
	}
}

// TestDeferHeadersRespectsTheGlobalBound checks that many distinct peers
// cannot grow the buffer past maxDeferredHeaderMsgs, and that the bound is
// non-zero, since zero would disable the buffer entirely.
func TestDeferHeadersRespectsTheGlobalBound(t *testing.T) {
	g := chainhash.Hash{0x03}
	s := deferServer(t)

	// Enough distinct peers, each within its own per-peer quota, to overrun
	// the global bound several times over.
	s.mtx.Lock()
	for i := range 4 * maxDeferredHeaderMsgs {
		p := fakePeer(t, i)
		for j := range maxDeferredPerPeer {
			s.deferHeadersUnlocked(p,
				headersMsg(t, chainOf(g, 2, uint32(1000+i*10+j))...))
		}
	}
	got := len(s.deferredHeaders)
	s.mtx.Unlock()

	if got != maxDeferredHeaderMsgs {
		t.Fatalf("buffer holds %v messages, want exactly maxDeferredHeaderMsgs=%v; "+
			"unbounded retention is %v full messages of 2000 headers",
			got, maxDeferredHeaderMsgs, got)
	}
	if maxDeferredHeaderMsgs == 0 {
		t.Fatal("maxDeferredHeaderMsgs is 0: nothing is ever buffered and the " +
			"quiesce branch has silently reverted to discarding header data")
	}
}

// TestDeferHeadersPrefersTheLongerAnswer checks that a longer message with a
// held last hash replaces the shorter one instead of being refused. The last
// header of an honest answer is the public network tip, so otherwise a peer
// could send just that header and have every real answer bounce as a
// duplicate.
func TestDeferHeadersPrefersTheLongerAnswer(t *testing.T) {
	g := chainhash.Hash{0x0e}
	full := chainOf(g, 20, 3)
	stub := full[len(full)-1:] // just the tip header, as an attacker sends

	s := deferServer(t)
	attacker := fakePeer(t, 1)
	honest := fakePeer(t, 2)

	// Attacker claims the key first.
	s.mtx.Lock()
	s.deferHeadersUnlocked(attacker, headersMsg(t, stub...))
	s.mtx.Unlock()

	// The honest peer's real answer ends at the same header.
	s.mtx.Lock()
	s.deferHeadersUnlocked(honest, headersMsg(t, full...))
	held := 0
	if len(s.deferredHeaders) == 1 {
		held = len(s.deferredHeaders[0].msg.Headers)
	}
	nslots := len(s.deferredHeaders)
	s.mtx.Unlock()

	if nslots != 1 {
		t.Fatalf("buffer holds %v messages, want 1 (same last hash)", nslots)
	}
	if held != len(full) {
		t.Fatalf("buffer kept %v headers, want %v. A one-header stub ending at "+
			"the public network tip is claiming the dedupe key and bouncing "+
			"every real answer.", held, len(full))
	}
}

// TestDeferHeadersEvictsForAPeerHoldingNothing checks fair-share eviction: a
// peer holding no slots must get into a full buffer, otherwise a few hosts
// each at their per-peer cap can lock everyone else out for the whole pass.
func TestDeferHeadersEvictsForAPeerHoldingNothing(t *testing.T) {
	g := chainhash.Hash{0x0f}
	s := deferServer(t)

	// Fill every slot using the permitted per-peer quota.
	s.mtx.Lock()
	for i := range maxDeferredHeaderMsgs / maxDeferredPerPeer {
		p := fakePeer(t, 200+i)
		for j := range maxDeferredPerPeer {
			s.deferHeadersUnlocked(p, headersMsg(t, chainOf(g, 2, uint32(900+i*10+j))...))
		}
	}
	full := len(s.deferredHeaders)
	s.mtx.Unlock()
	if full != maxDeferredHeaderMsgs {
		t.Fatalf("precondition: buffer holds %v, want %v", full, maxDeferredHeaderMsgs)
	}

	honest := fakePeer(t, 999)
	honestLast := chainOf(g, 2, 4242)
	s.mtx.Lock()
	s.deferHeadersUnlocked(honest, headersMsg(t, honestLast...))
	n := len(s.deferredHeaders)
	got := 0
	for k := range s.deferredHeaders {
		if s.deferredHeaders[k].p != nil &&
			peerHost(s.deferredHeaders[k].p) == peerHost(honest) {
			got++
		}
	}
	s.mtx.Unlock()

	if got == 0 {
		t.Fatal("a peer holding no slots was refused by a full buffer; a few " +
			"flooders can then deny the buffer to every honest peer for the " +
			"whole indexing pass")
	}
	if n > maxDeferredHeaderMsgs {
		t.Fatalf("eviction grew the buffer to %v, past the %v bound",
			n, maxDeferredHeaderMsgs)
	}
}

// TestDeferHeadersIgnoresEmptyMessages pins that an empty headers message is
// never buffered. It carries no header data, and buffering it would consume a
// slot and, on replay, re-enter handleHeaders' empty branch.
func TestDeferHeadersIgnoresEmptyMessages(t *testing.T) {
	s := deferServer(t)
	s.mtx.Lock()
	s.deferHeadersUnlocked(fakePeer(t, 0), wire.NewMsgHeaders())
	n := len(s.deferredHeaders)
	s.mtx.Unlock()
	if n != 0 {
		t.Fatalf("an empty headers message consumed %v buffer slots", n)
	}
}

// ===========================================================================
// handleHeaders' quiesce branch
// ===========================================================================

// quiesceStubDB implements no store methods, so the embedded nil interface
// panics if the quiesce branch ever touches the store while holding s.mtx.
type quiesceStubDB struct {
	tbcd.Database
}

// TestHandleHeadersWhileIndexingQueuesOnlyTheTipHash checks that the quiesce
// branch buffers the message and queues only its last hash, which is all the
// drain needs to know we are behind. It must be the last hash, since the
// drain drops hashes we already have and the earlier ones may well be known.
func TestHandleHeadersWhileIndexingQueuesOnlyTheTipHash(t *testing.T) {
	s := deferServer(t)
	s.db = &quiesceStubDB{}

	hdrs := chainOf(chainhash.Hash{0x04}, 4, 7)
	msg := headersMsg(t, hdrs...)
	tip := hdrs[len(hdrs)-1].BlockHash()

	s.mtx.Lock()
	s.indexing = true
	s.mtx.Unlock()

	err := s.handleHeaders(t.Context(), fakePeer(t, 0), msg)
	if !errors.Is(err, ErrAlreadyIndexing) {
		t.Fatalf("handleHeaders = %v, want ErrAlreadyIndexing", err)
	}

	s.mtx.Lock()
	ib := make([]chainhash.Hash, 0, len(s.invBlocks))
	for h := range s.invBlocks {
		ib = append(ib, h)
	}
	nd := len(s.deferredHeaders)
	s.mtx.Unlock()

	if len(ib) != 1 {
		t.Fatalf("a %v-header message queued %v inventory hashes, want exactly 1 "+
			"(the tip): %v. Every hash here is inserted with the GLOBAL mutex "+
			"held, so inserting the whole batch stops the server for the whole "+
			"batch.", len(hdrs), len(ib), ib)
	}
	if ib[0] != tip {
		t.Fatalf("queued %v, want the LAST header of the batch %v. The drain "+
			"filters out hashes we already have; every header but the last is "+
			"one we plausibly already have, so queueing the first can leave the "+
			"drain with nothing to do and the gap open.", ib[0], tip)
	}
	if nd != 1 {
		t.Fatalf("the headers message was not buffered (%v deferred); the "+
			"quiesce branch has reverted to keeping only the hash, which makes "+
			"recovery depend on a later round trip landing in an idle window",
			nd)
	}
}

// ===========================================================================
// replayDeferredHeaders
// ===========================================================================

// replayStubDB records every headers message that reaches the store. Returning
// ErrDuplicate keeps handleHeaders on its short path (it returns nil) so the
// recorder is the only thing under test.
type replayStubDB struct {
	tbcd.Database

	mtx  chanMutex
	seen []*wire.MsgHeaders
}

// chanMutex is a channel-based mutex; copies share the same lock.
type chanMutex struct{ c chan struct{} }

func newChanMutex() chanMutex {
	m := chanMutex{c: make(chan struct{}, 1)}
	m.c <- struct{}{}
	return m
}
func (m chanMutex) Lock()   { <-m.c }
func (m chanMutex) Unlock() { m.c <- struct{}{} }

func (d *replayStubDB) BlockHeadersInsert(_ context.Context, bhs *wire.MsgHeaders, _ tbcd.BatchHook) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	d.mtx.Lock()
	d.seen = append(d.seen, bhs)
	d.mtx.Unlock()
	return tbcd.ITInvalid, nil, nil, 0, database.DuplicateError("duplicate")
}

func (d *replayStubDB) applied() int {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return len(d.seen)
}

// minedChain returns n mined headers descending from prev, so they survive
// verifyHeadersPoW and verifyHeaderBatchShape and actually reach the store.
func minedChain(t *testing.T, s *Server, prev chainhash.Hash, n int, tag byte) []*wire.BlockHeader {
	t.Helper()
	out := make([]*wire.BlockHeader, 0, n)
	p := prev
	for i := range n {
		h := mineHeader(t, &p, s.chainParams.PowLimitBits, tag+byte(i))
		out = append(out, h)
		p = h.BlockHash()
	}
	return out
}

func replayServer(t *testing.T) (*Server, *replayStubDB) {
	t.Helper()
	s := deferServer(t)
	db := &replayStubDB{mtx: newChanMutex()}
	s.db = db
	return s, db
}

// TestReplayDeferredHeadersAppliesBufferedMessages checks that headers
// buffered during an indexing pass are applied when the pass ends.
func TestReplayDeferredHeadersAppliesBufferedMessages(t *testing.T) {
	s, db := replayServer(t)

	a := headersMsg(t, minedChain(t, s, chainhash.Hash{0x11}, 2, 1)...)
	b := headersMsg(t, minedChain(t, s, chainhash.Hash{0x22}, 2, 9)...)

	s.mtx.Lock()
	s.indexing = true
	s.mtx.Unlock()
	if err := s.handleHeaders(t.Context(), fakePeer(t, 0), a); !errors.Is(err, ErrAlreadyIndexing) {
		t.Fatalf("handleHeaders(a) = %v", err)
	}
	if err := s.handleHeaders(t.Context(), fakePeer(t, 1), b); !errors.Is(err, ErrAlreadyIndexing) {
		t.Fatalf("handleHeaders(b) = %v", err)
	}
	if n := db.applied(); n != 0 {
		t.Fatalf("%v headers messages reached the store while indexing", n)
	}

	s.mtx.Lock()
	s.indexing = false
	s.mtx.Unlock()
	s.replayDeferredHeaders(t.Context())

	if n := db.applied(); n != 2 {
		t.Fatalf("%v of 2 buffered headers messages were applied; the buffered "+
			"header DATA is being dropped, so the node can only recover if a "+
			"later round trip happens to land between indexing passes", n)
	}
	s.mtx.Lock()
	left := len(s.deferredHeaders)
	s.mtx.Unlock()
	if left != 0 {
		t.Fatalf("%v messages left in the buffer after a replay", left)
	}
}

// TestReplayDeferredHeadersDoesNotApplyTwice checks that a replay takes the
// buffer rather than copying it, so stale messages are not re-applied after
// every later indexing pass.
func TestReplayDeferredHeadersDoesNotApplyTwice(t *testing.T) {
	s, db := replayServer(t)

	msg := headersMsg(t, minedChain(t, s, chainhash.Hash{0x33}, 2, 3)...)
	s.mtx.Lock()
	s.indexing = true
	s.mtx.Unlock()
	if err := s.handleHeaders(t.Context(), fakePeer(t, 0), msg); !errors.Is(err, ErrAlreadyIndexing) {
		t.Fatalf("handleHeaders = %v", err)
	}
	s.mtx.Lock()
	s.indexing = false
	s.mtx.Unlock()

	s.replayDeferredHeaders(t.Context())
	first := db.applied()
	s.replayDeferredHeaders(t.Context())
	second := db.applied()

	if first != 1 {
		t.Fatalf("first replay applied %v messages, want 1", first)
	}
	if second != first {
		t.Fatalf("a second replay re-applied the same messages (%v -> %v); "+
			"replayDeferredHeaders must take the buffer, not copy it",
			first, second)
	}
}

// TestReplayDeferredHeadersStopsOnCancelledContext checks that a replay stops
// once ctx is cancelled. The replay is not tracked in s.wg and on shutdown the
// aborted indexing pass fires it, so it can race the store being closed.
func TestReplayDeferredHeadersStopsOnCancelledContext(t *testing.T) {
	s, db := replayServer(t)

	msg := headersMsg(t, minedChain(t, s, chainhash.Hash{0x44}, 2, 5)...)
	s.mtx.Lock()
	s.indexing = true
	s.mtx.Unlock()
	if err := s.handleHeaders(t.Context(), fakePeer(t, 0), msg); !errors.Is(err, ErrAlreadyIndexing) {
		t.Fatalf("handleHeaders = %v", err)
	}
	s.mtx.Lock()
	s.indexing = false
	s.mtx.Unlock()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s.replayDeferredHeaders(ctx)

	if n := db.applied(); n != 0 {
		t.Fatalf("%v headers messages were pushed into the store after the "+
			"context was cancelled; shutdown closes the store underneath this "+
			"goroutine and a post-close insert kills the process", n)
	}
	// The buffer is taken before the loop, so a cancelled replay leaves it
	// empty.
	s.mtx.Lock()
	left := len(s.deferredHeaders)
	s.mtx.Unlock()
	if left != 0 {
		t.Fatalf("a cancelled replay stranded %v messages in the buffer", left)
	}
}

// ---------------------------------------------------------------------------
// crawler wiring: BOTH indexing defers must fire a replay
// ---------------------------------------------------------------------------

// indexFailStubDB makes both indexer entry points fail on their first store
// call, so the wiring tests exercise the defer without running an indexer.
type indexFailStubDB struct {
	tbcd.Database
}

func (d *indexFailStubDB) BlockHeaderBest(context.Context) (*tbcd.BlockHeader, error) {
	return nil, database.NotFoundError("no best block header")
}

func (d *indexFailStubDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	return nil, database.NotFoundError("block header not found: " + h.String())
}

func waitBufferDrained(t *testing.T, s *Server, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		s.mtx.Lock()
		n := len(s.deferredHeaders)
		s.mtx.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	s.mtx.Lock()
	n := len(s.deferredHeaders)
	s.mtx.Unlock()
	t.Fatalf("the indexing pass finished but %v buffered headers messages were "+
		"never replayed. Every exit from an indexing pass must fire "+
		"replayDeferredHeaders; a pass that does not is a pass during which all "+
		"header data is silently discarded.", n)
}

// TestSyncIndexersToBestReplaysDeferredHeaders pins the defer in
// SyncIndexersToBest, the entry point syncBlocks uses.
func TestSyncIndexersToBestReplaysDeferredHeaders(t *testing.T) {
	s := deferServer(t)
	s.db = &indexFailStubDB{}

	s.mtx.Lock()
	s.deferHeadersUnlocked(fakePeer(t, 0),
		headersMsg(t, chainOf(chainhash.Hash{0x55}, 2, 4)...))
	s.mtx.Unlock()

	// Errors are expected: the stub fails the indexer's first store call. The
	// defer runs regardless, which is the point.
	_ = s.SyncIndexersToBest(t.Context())
	waitBufferDrained(t, s, 5*time.Second)
}

// TestSyncIndexersToHashReplaysDeferredHeaders pins the defer in
// SyncIndexersToHash, the entry point hemictl uses.
func TestSyncIndexersToHashReplaysDeferredHeaders(t *testing.T) {
	s := deferServer(t)
	s.db = &indexFailStubDB{}

	s.mtx.Lock()
	s.deferHeadersUnlocked(fakePeer(t, 0),
		headersMsg(t, chainOf(chainhash.Hash{0x66}, 2, 6)...))
	s.mtx.Unlock()

	_ = s.SyncIndexersToHash(t.Context(), chainhash.Hash{0x66})
	waitBufferDrained(t, s, 5*time.Second)
}

// TestReplayDeferredHeadersIsRaceFree runs a replay concurrently with peers
// that keep buffering. It pins the "fresh slice, not dh[:0]" choice: reusing
// the backing array aliases the appends made by peer goroutines onto the slice
// the replay is walking.
//
// Run with -race.
func TestReplayDeferredHeadersIsRaceFree(t *testing.T) {
	s, _ := replayServer(t)

	// Pre-build the messages so the appender spends its time appending, not
	// hashing.
	msgs := make([]*wire.MsgHeaders, 0, 256)
	for i := range 256 {
		msgs = append(msgs, headersMsg(t, chainOf(chainhash.Hash{0x77}, 2, uint32(i))...))
	}
	peers := make([]*rawpeer.RawPeer, 0, 8)
	for i := range 8 {
		peers = append(peers, fakePeer(t, i))
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			s.mtx.Lock()
			s.deferHeadersUnlocked(peers[i%len(peers)], msgs[i%len(msgs)])
			s.mtx.Unlock()
		}
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.replayDeferredHeaders(t.Context())
	}
	close(stop)
	<-done
}

// ===========================================================================
// the periodic header refresh
// ===========================================================================

// initialHeaderRefreshInterval captures the shipped value at package init, so
// the assertion below is not affected by tests that shorten the interval.
var initialHeaderRefreshInterval = headerRefreshInterval

// TestHeaderRefreshIntervalIsSane pins the shipped cadence. The refresh is the
// only backstop for a node idle behind a header gap, so too long means a long
// stall; too short sends unsolicited getheaders to every peer, and zero spins.
func TestHeaderRefreshIntervalIsSane(t *testing.T) {
	if initialHeaderRefreshInterval < 10*time.Second {
		t.Fatalf("headerRefreshInterval = %v: this fires getheaders at every "+
			"connected peer that often and, at 0, spins",
			initialHeaderRefreshInterval)
	}
	if initialHeaderRefreshInterval > 10*time.Minute {
		t.Fatalf("headerRefreshInterval = %v: this is the ONLY backstop for a "+
			"node idle behind a header gap, so it bounds how long such a node "+
			"stays stalled", initialHeaderRefreshInterval)
	}
}

// timedPeer is a peer that timestamps each message on arrival, so a test can
// tell which messages belong to the same refresh tick regardless of the order
// in which it reads them.
type timedPeer struct {
	rp   *rawpeer.RawPeer
	msgs chan timedMsg
}

type timedMsg struct {
	at  time.Time
	msg wire.Message
}

func addTimedPeers(t *testing.T, s *Server, n int) []*timedPeer {
	t.Helper()

	out := make([]*timedPeer, 0, n)
	s.pm.mtx.Lock()
	defer s.pm.mtx.Unlock()
	for i := range n {
		local, remote := net.Pipe()
		t.Cleanup(func() {
			local.Close()
			remote.Close()
		})
		rp, err := rawpeer.NewFromConn(local, s.wireNet, wire.ProtocolVersion, i)
		if err != nil {
			t.Fatalf("new from conn: %v", err)
		}
		tp := &timedPeer{rp: rp, msgs: make(chan timedMsg, 256)}
		go func() {
			for {
				_, msg, _, err := wire.ReadMessageWithEncodingN(remote,
					wire.AddrV2Version, s.wireNet, wire.LatestEncoding)
				if err != nil {
					return
				}
				select {
				case tp.msgs <- timedMsg{at: time.Now(), msg: msg}:
				default:
				}
			}
		}()
		s.pm.peers[fmt.Sprintf("timed%d", i)] = rp
		out = append(out, tp)
	}
	return out
}

// firstGetHeaders returns when this peer receives its first getheaders.
func (tp *timedPeer) firstGetHeaders(t *testing.T, within time.Duration) timedMsg {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case m := <-tp.msgs:
			if _, ok := m.msg.(*wire.MsgGetHeaders); ok {
				return m
			}
		case <-deadline:
			t.Fatalf("no getheaders within %v", within)
		}
	}
}

// TestRunRefreshesHeadersFromEveryPeer runs the real Run and checks that it
// starts the periodic header refresh, that one tick asks every peer, and that
// the loop stops on cancel.
//
// "Every peer" is asserted by arrival time rather than by count: a refresh
// that picks one peer per tick still reaches every peer eventually, but spread
// over as many ticks as there are peers, which can leave the one peer that can
// answer unasked for minutes.
func TestRunRefreshesHeadersFromEveryPeer(t *testing.T) {
	// Generous on purpose. pm.All reaches every peer within microseconds,
	// but a loaded box can delay goroutines a lot. A one-peer-per-tick
	// refresh would spread arrivals over whole intervals, so a long
	// interval keeps the test discriminating and far above scheduler noise.
	const interval = 2 * time.Second
	restore := headerRefreshInterval
	headerRefreshInterval = interval
	t.Cleanup(func() { headerRefreshInterval = restore })

	cfg := NewDefaultConfig()
	cfg.Network = networkLocalnet
	cfg.MempoolEnabled = false
	cfg.LevelDBHome = t.TempDir()
	cfg.ListenAddress = ""
	cfg.PprofListenAddress = ""
	cfg.PrometheusListenAddress = ""
	cfg.Seeds = nil // no seeds: the peer manager parks in its seeder hold-off
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()

	// Attach peers straight away. The refresh loop is started only after Run
	// has opened the store, so the first tick that finds these peers already
	// has a usable database.
	const nPeers = 4
	peers := addTimedPeers(t, s, nPeers)

	var first, last time.Time
	for i, tp := range peers {
		m := tp.firstGetHeaders(t, 30*time.Second)
		gh := m.msg.(*wire.MsgGetHeaders)
		if len(gh.BlockLocatorHashes) == 0 {
			cancel()
			t.Fatalf("peer %v got a getheaders with an empty locator", i)
		}
		if first.IsZero() || m.at.Before(first) {
			first = m.at
		}
		if m.at.After(last) {
			last = m.at
		}
	}
	if spread := last.Sub(first); spread > interval/2 {
		cancel()
		t.Fatalf("the %v peers were first asked %v apart, which is more than "+
			"half the %v refresh interval: they were served on different ticks, "+
			"so one tick does not ask every peer. A refresh that picks a single "+
			"peer leaves the peer that can actually answer unasked for "+
			"peers*interval, and pm.Random is biased towards whichever peer the "+
			"map iterates first.", nPeers, spread, interval)
	}

	// ...and the loop must stop on cancel: Run ends with s.wg.Wait(), so a
	// loop with no ctx.Done case wedges shutdown forever.
	cancel()
	select {
	case <-runErr:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return within 30s of cancel; a refresh loop that " +
			"does not select on ctx.Done() wedges s.wg.Wait() forever")
	}
}

// ===========================================================================
// the syncBlocks drain

// reindexStubDB answers the first after BlockHeadersInsert calls with a
// duplicate error and fails the rest with ErrAlreadyIndexing, which is what a
// fresh indexing pass starting mid-replay looks like from inside
// replayDeferredHeaders.
type reindexStubDB struct {
	tbcd.Database

	mtx   chanMutex
	calls int
	after int

	s *Server // set indexing when reporting ErrAlreadyIndexing
}

func (d *reindexStubDB) BlockHeadersInsert(_ context.Context, bhs *wire.MsgHeaders, _ tbcd.BatchHook) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	d.mtx.Lock()
	d.calls++
	n := d.calls
	d.mtx.Unlock()
	if n > d.after {
		// ErrAlreadyIndexing means an indexing pass has (re)started; model
		// that state too, or the requeue sees an idle node and re-arms a
		// replay that races this test's inspection of the buffer.
		if d.s != nil {
			d.s.mtx.Lock()
			d.s.indexing = true
			d.s.mtx.Unlock()
		}
		return tbcd.ITInvalid, nil, nil, 0, ErrAlreadyIndexing
	}
	return tbcd.ITInvalid, nil, nil, 0, database.DuplicateError("duplicate")
}

// TestReplayRequeuesTheUnreplayedRemainder pins
// requeueDeferredHeadersUnreplayed.
//
// An indexing pass can restart while a replay is still walking the buffer.
// The remainder must go back unconditionally: it already passed admission, and
// re-running admission makes it compete with newer arrivals for the per-peer
// slots and lose.
func TestReplayRequeuesTheUnreplayedRemainder(t *testing.T) {
	s := deferServer(t)
	db := &reindexStubDB{mtx: newChanMutex(), after: 1, s: s}
	s.db = db

	// Three buffered answers from three hosts.
	lasts := make([]chainhash.Hash, 0, 3)
	s.mtx.Lock()
	for i := range 3 {
		hdrs := minedChain(t, s, chainhash.Hash{byte(0xd0 + i)}, 2, byte(0x60+i))
		s.deferHeadersUnlocked(fakePeer(t, 300+i), headersMsg(t, hdrs...))
		lasts = append(lasts, hdrs[len(hdrs)-1].BlockHash())
	}
	if len(s.deferredHeaders) != 3 {
		n := len(s.deferredHeaders)
		s.mtx.Unlock()
		t.Fatalf("precondition: buffered %v, want 3", n)
	}
	s.mtx.Unlock()

	// The first insert reports a duplicate, which handleHeaders treats as
	// success; the rest report a restarted indexing pass.
	s.replayDeferredHeaders(t.Context())

	s.mtx.Lock()
	got := make(map[chainhash.Hash]bool, len(s.deferredHeaders))
	for k := range s.deferredHeaders {
		got[s.deferredHeaders[k].last] = true
	}
	n := len(s.deferredHeaders)
	s.mtx.Unlock()

	if n == 0 {
		t.Fatal("the replay was interrupted by a restarted indexing pass and " +
			"the unreplayed remainder was DISCARDED. Those headers are gone: " +
			"nothing re-derives them, because BlocksMissing is built from " +
			"header inserts.")
	}
	for _, l := range lasts[1:] {
		if !got[l] {
			t.Fatalf("the remainder lost the answer ending at %v; buffer now "+
				"holds %v messages", l, n)
		}
	}
}

// emptyKickStubDB stubs the calls the empty-headers kick path can make.
// missing controls whether the kick has anything to do.
type emptyKickStubDB struct {
	tbcd.Database

	missing int
	best    *tbcd.BlockHeader
}

func (d *emptyKickStubDB) BlocksMissing(_ context.Context, count int) ([]tbcd.BlockIdentifier, error) {
	n := min(d.missing, count)
	return make([]tbcd.BlockIdentifier, n), nil
}

func (d *emptyKickStubDB) BlockHeaderBest(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

func (d *emptyKickStubDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	return nil, database.NotFoundError("block header not found: " + h.String())
}

// TestReplayReissuesTheEmptyHeadersKick pins deferredEmpty.
//
// An empty headers message has nothing to buffer, but handleHeaders' empty
// branch kicks syncBlocks, which is what turns BlocksMissing into getdata.
// Buffering must not swallow that kick. The replay re-issues it once, and only
// when blocks are actually missing, so the empty branch cannot feed itself.
func TestReplayReissuesTheEmptyHeadersKick(t *testing.T) {
	s := deferServer(t)
	// missing:0 so the replay's gate is false and no syncBlocks goroutine is
	// spawned. This part checks the flag lifecycle (set by the quiesce
	// branch, consumed by the replay); the gate itself is checked below.
	s.db = &emptyKickStubDB{missing: 0, best: stubHeader(t, s, 1, 0x71)}

	s.mtx.Lock()
	s.indexing = true
	s.mtx.Unlock()

	// An empty headers message during indexing.
	err := s.handleHeaders(t.Context(), fakePeer(t, 400), wire.NewMsgHeaders())
	if !errors.Is(err, ErrAlreadyIndexing) {
		t.Fatalf("handleHeaders = %v, want ErrAlreadyIndexing", err)
	}

	s.mtx.Lock()
	empty := s.deferredEmpty
	buffered := len(s.deferredHeaders)
	s.mtx.Unlock()

	if buffered != 0 {
		t.Fatalf("an empty headers message consumed %v buffer slots", buffered)
	}
	if !empty {
		t.Fatal("the empty headers message was swallowed without recording " +
			"that it happened, so the replay cannot re-issue the syncBlocks " +
			"kick and blocks announced before the indexing pass are never " +
			"requested")
	}

	// The replay must consume the flag, so the kick fires once and not once
	// per subsequent pass.
	s.mtx.Lock()
	s.indexing = false
	s.mtx.Unlock()
	s.replayDeferredHeaders(t.Context())

	s.mtx.Lock()
	still := s.deferredEmpty
	s.mtx.Unlock()
	if still {
		t.Fatal("deferredEmpty was not cleared by the replay; the kick " +
			"would re-fire on every later indexing pass")
	}

	// The gate the kick is conditioned on must actually discriminate.
	// Ungated, the replay would start a pointless indexing pass on an idle
	// synced node.
	if s.blksMissing(t.Context()) {
		t.Fatal("blksMissing reported work with nothing missing; the kick " +
			"would fire on every replay regardless of need")
	}
	s.db = &emptyKickStubDB{missing: 3, best: stubHeader(t, s, 1, 0x71)}
	if !s.blksMissing(t.Context()) {
		t.Fatal("blksMissing reported no work with 3 blocks missing; the kick " +
			"is gated off exactly when it is needed")
	}
}

// TestDrainFanoutIsRateLimited pins the bound on the syncBlocks drain's
// getheaders fan-out.
//
// Outside indexing, every empty headers message, which a peer can send for
// free, spawns syncBlocks, whose drain can end in one getheaders per connected
// peer.
//
// The bound is on the fan-out, not on the kick: syncBlocks also starts block
// download, and handleBlock cannot take over until a first block has arrived,
// so rate limiting the kick can stop downloads from ever beginning.
func TestDrainFanoutIsRateLimited(t *testing.T) {
	s := deferServer(t)

	if !s.drainFanoutDue() {
		t.Fatal("the first fan-out was refused; a node must be able to act on " +
			"the first empty headers message it sees")
	}
	allowed := 0
	for range 500 {
		if s.drainFanoutDue() {
			allowed++
		}
	}
	if allowed != 0 {
		t.Fatalf("%v of 500 back-to-back fan-outs were allowed inside the %v "+
			"window; a peer can drive one getheaders per connected peer as "+
			"fast as it can write empty headers messages",
			allowed, drainFanoutInterval)
	}

	// The window must reopen, or the drain could never recover
	// announcements seen during indexing.
	s.mtx.Lock()
	s.drainFanout = time.Now().Add(-2 * drainFanoutInterval)
	s.mtx.Unlock()
	if !s.drainFanoutDue() {
		t.Fatalf("the gate did not reopen after %v", drainFanoutInterval)
	}
}

// TestDownloadBlockDoesNotHoldTheGlobalMutexAcrossTheWrite pins that one peer
// which stops reading its socket cannot freeze the whole server.
//
// p.Write blocks for up to defaultCmdTimeout against a peer whose receive
// window is full. Holding s.mtx across it would stall every other user of the
// mutex for that long, and the lock guards nothing: the getdata is local and
// rawpeer.Write serialises on its own mutex.
func TestDownloadBlockDoesNotHoldTheGlobalMutexAcrossTheWrite(t *testing.T) {
	s := deferServer(t)

	// A peer whose remote end is never read. net.Pipe is unbuffered, so the
	// write blocks until its deadline, just like a full socket.
	wedged := addWedgedPeers(t, s, 1)[0]

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.downloadBlock(t.Context(), wedged, chainhash.Hash{0xab})
	}()

	// Give the download goroutine time to reach the write.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	s.mtx.Lock()
	waited := time.Since(start)
	s.mtx.Unlock()

	if waited > 2*time.Second {
		t.Fatalf("an unrelated s.mtx acquisition waited %v while ONE peer "+
			"refused to read its socket. downloadBlock is holding the global "+
			"mutex across a %v network write, so any peer can freeze the "+
			"entire server for that long, repeatedly, for free.",
			waited, defaultCmdTimeout)
	}
	t.Logf("s.mtx acquired in %v with a wedged peer mid-write", waited)

	select {
	case <-done:
	case <-time.After(defaultCmdTimeout + 3*time.Second):
		t.Fatal("downloadBlock never returned")
	}
}

// TestDrainRateLimitDoesNotSuppressTheDrainThatMatters pins where the drain
// fan-out limiter sits.
//
// Gated before the have-filter, a drain with nothing to do burns the token and
// the next drain, which carries a real announcement, is delayed by up to
// drainFanoutInterval. Gating after the filter keeps the DoS bound, since an
// empty-headers flood has missed == 0 and returns before the gate.
func TestDrainRateLimitDoesNotSuppressTheDrainThatMatters(t *testing.T) {
	announced := chainhash.Hash{0xd1}
	s, _ := drainServer(t) // nothing missed yet
	peers := addPeers(t, s, 1)

	// A no-op drain. It must not consume the rate-limit token.
	//
	// The wait has to stay inside drainFanoutInterval, or the second drain
	// gets a fresh token anyway and the test proves nothing.
	s.syncBlocks(t.Context())
	peers[0].silent(t, drainFanoutInterval/5)

	// Still well inside the rate-limit window, an announcement arrives and
	// the drain runs again. It must reach the wire.
	s.mtx.Lock()
	s.invBlocks[announced] = struct{}{}
	s.mtx.Unlock()
	s.syncBlocks(t.Context())

	// Wait less than the rest of the window: the deferred fan-out a wrongly
	// suppressed drain arms would otherwise arrive in time and mask the bug.
	if _, ok := peers[0].next(t, drainFanoutInterval/2).(*wire.MsgGetHeaders); !ok {
		t.Fatal("the drain carrying a real announcement was rate limited " +
			"by a token the preceding EMPTY drain had already spent")
	}
}

// TestEvictionTakesFromTheGreediestHost pins the fair-share property itself.
//
// A host over-represented in the buffer must lose a slot before a host holding
// fewer does. Without that, a flooder that has reached its per-peer cap keeps
// both slots while honest single-slot peers are evicted around it, which is
// the starvation the fair-share rule was added to prevent.
func TestEvictionTakesFromTheGreediestHost(t *testing.T) {
	g := chainhash.Hash{0x3b}
	s := deferServer(t)

	greedy := fakePeer(t, 900)
	s.mtx.Lock()
	for i := range maxDeferredPerPeer {
		s.deferHeadersUnlocked(greedy, headersMsg(t, chainOf(g, 2, uint32(5000+i))...))
	}
	// Fill the rest with one slot per distinct host.
	for i := len(s.deferredHeaders); i < maxDeferredHeaderMsgs; i++ {
		s.deferHeadersUnlocked(fakePeer(t, 901+i),
			headersMsg(t, chainOf(g, 2, uint32(6000+i))...))
	}
	before := 0
	for k := range s.deferredHeaders {
		if peerHost(s.deferredHeaders[k].p) == peerHost(greedy) {
			before++
		}
	}
	s.mtx.Unlock()
	if before != maxDeferredPerPeer {
		t.Fatalf("precondition: greedy host holds %v slots, want %v",
			before, maxDeferredPerPeer)
	}

	// One newcomer holding nothing. The eviction must come out of the
	// greedy host, not out of a single-slot honest peer.
	s.mtx.Lock()
	s.deferHeadersUnlocked(fakePeer(t, 9999), headersMsg(t, chainOf(g, 2, 7777)...))
	after := 0
	for k := range s.deferredHeaders {
		if peerHost(s.deferredHeaders[k].p) == peerHost(greedy) {
			after++
		}
	}
	s.mtx.Unlock()

	if after >= before {
		t.Fatalf("the host holding %v slots still holds %v after a newcomer "+
			"was admitted; the eviction took from someone else. A peer at its "+
			"per-peer cap must give up a slot before a single-slot honest peer "+
			"does, or the cap is the only thing limiting a flooder and honest "+
			"peers rotate out around it.", before, after)
	}
}

// ===========================================================================

// addWedgedPeers registers peers whose remote end is never read, so every write
// to them blocks for the full defaultCmdTimeout.
func addWedgedPeers(t *testing.T, s *Server, n int) []*rawpeer.RawPeer {
	t.Helper()

	out := make([]*rawpeer.RawPeer, 0, n)
	s.pm.mtx.Lock()
	defer s.pm.mtx.Unlock()
	for i := range n {
		local, remote := net.Pipe()
		t.Cleanup(func() {
			local.Close()
			remote.Close()
		})
		rp, err := rawpeer.NewFromConn(local, s.wireNet, wire.ProtocolVersion, i)
		if err != nil {
			t.Fatalf("new from conn: %v", err)
		}
		s.pm.peers[fmt.Sprintf("wedged%d", i)] = rp
		out = append(out, rp)
	}
	return out
}

// TestSyncBlocksDrainDoesNotWaitOnWedgedPeers pins pm.All over pm.AllBlock.
//
// AllBlock waits on every peer write, so one peer that does not read its
// socket stalls the drain for defaultCmdTimeout, and it logs at INFO on every
// drain. The drain fires and forgets; the periodic refresh in Run covers the
// case where nothing got out.
//
// Nothing exposes the drain goroutine, so this checks the goroutine dump:
// with pm.All nothing stays parked inside syncBlocks.
func TestSyncBlocksDrainDoesNotWaitOnWedgedPeers(t *testing.T) {
	missed := chainhash.Hash{0xa1}
	s, _ := drainServer(t, missed)
	wedged := addWedgedPeers(t, s, 3)

	go s.syncBlocks(t.Context())

	// Wait for the drain to take s.invBlocks; it swaps in an empty map just
	// before counting what was missed and fanning out, so an empty queue means
	// the drain really ran.
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mtx.Lock()
		n := len(s.invBlocks)
		s.mtx.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the drain never ran")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Well past when a fire-and-forget drain has finished, and well inside
	// defaultCmdTimeout, which is how long each of these writes blocks for.
	time.Sleep(2 * time.Second)
	// This is a negative match on a symbol name, so a rename can only make
	// it pass. Match the method name alone so that inlining or renaming the
	// closure inside it does not silently disarm the test.
	if stackContains("(*Server).syncBlocks") {
		t.Fatalf("the drain goroutine is still parked inside syncBlocks with %v "+
			"peers whose sockets are not being read. It is waiting on the peer "+
			"writes (pm.AllBlock), so one wedged peer stalls recovery for "+
			"defaultCmdTimeout=%v -- and AllBlock logs at INFO once per drain.",
			len(wedged), defaultCmdTimeout)
	}
}

func stackContains(needle string) bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Contains(string(buf[:n]), needle)
		}
		buf = make([]byte, 2*len(buf))
	}
}

// blockingStubDB fails the indexers immediately and then parks inside
// BlockHeadersInsert, so a replay can be held mid-flight.
type blockingStubDB struct {
	indexFailStubDB

	entered chan struct{}
	release chan struct{}
}

func (d *blockingStubDB) BlockHeadersInsert(_ context.Context, _ *wire.MsgHeaders, _ tbcd.BatchHook) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	<-d.release
	return tbcd.ITInvalid, nil, nil, 0, database.DuplicateError("duplicate")
}

// TestIndexingDefersDoNotBlockOnTheReplay pins the `go` in front of
// replayDeferredHeaders in SyncIndexersToBest's defer. The same `go` in
// SyncIndexersToHash's defer is not exercised here.
//
// The replay re-enters handleHeaders for up to maxDeferredHeaderMsgs messages.
// Running it inline would hold up the indexer's return and, in
// SyncIndexersToHash, delay the pm.All(headersPeer) that follows it in the
// same defer.
func TestIndexingDefersDoNotBlockOnTheReplay(t *testing.T) {
	s := deferServer(t)
	db := &blockingStubDB{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	s.db = db
	t.Cleanup(func() { close(db.release) })

	msg := headersMsg(t, minedChain(t, s, chainhash.Hash{0x88}, 2, 2)...)
	s.mtx.Lock()
	s.deferHeadersUnlocked(fakePeer(t, 0), msg)
	s.mtx.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.SyncIndexersToBest(t.Context())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SyncIndexersToBest did not return while a replayed headers " +
			"message was still inside the store. The replay must be spawned " +
			"(go s.replayDeferredHeaders), not run inline in the defer: it " +
			"re-enters handleHeaders for up to maxDeferredHeaderMsgs messages " +
			"of up to 2000 headers each.")
	}

	// The replay really did start, i.e. the test is not passing because
	// nothing was replayed at all.
	select {
	case <-db.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the buffered headers message never reached the store")
	}
}

// requeueWhileIndexing calls requeueDeferredHeadersUnreplayed under its real
// precondition: a replay requeues only after handleHeaders returned
// ErrAlreadyIndexing, i.e. while an indexing pass is running. It seats the
// remainder without spawning a replay that the test would then race.
func requeueWhileIndexing(t *testing.T, s *Server, rem []deferredHeaderMsg) {
	t.Helper()
	s.mtx.Lock()
	s.indexing = true
	s.mtx.Unlock()
	s.requeueDeferredHeadersUnreplayed(t.Context(), rem)
}
