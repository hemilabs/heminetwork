// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression suite for the peer-table unbounded-growth (memory-exhaustion)
// vulnerability: an attacker can make s.peers grow without bound, or pin
// attacker-sized memory per entry, until the node runs out of memory. Three
// independent root causes feed it:
//
//   A. Leak: the pong handler re-arms peersTTL on the per-session context
//      (handlePingResponse passes dc.sessionCtx). When the session ends, the ttl
//      cancel path drops the entry without running peerExpired, which is the only
//      code that deletes from s.peers, so a peer that pongs then disconnects is
//      never removed.
//   B. Per-entry memory: sanitizeSessions bounds the length of a gossiped session
//      list but allocates the output with cap = len(input) (route.go:184), so one
//      record still pins an attacker-sized backing array.
//   C. Count-cap bypass: addPeer rejects new entries at MaxPeers, but bindPeerKey
//      inserts a new entry with no such check.
//
// Invariants a correct fix must satisfy (each pinned by a test below):
//   1. a departed peer that is not self is removed from s.peers within peerTTL.
//   2. the memory a stored record retains is bounded, up to the largest list a
//      gossip message can carry.
//   3. s.peers and peersTTL stay within MaxPeers under a flood of fresh identities,
//      and the measured cap paths (bindPeerKey and addPeer reject, admit-then-expire)
//      retain no per-id memory. Other per-identity maps (limiters), routing CPU and
//      transient allocation are out of scope and tracked separately.
//   4. a correct cap evicts only gossip-only rows (never a key-bound incumbent or
//      self), every admitted row stays reapable (expires within peerTTL), and gossip
//      refresh of an existing row does not make it immortal.
//
// The tests are deterministic: shape A uses a synctest virtual clock so the
// peerTTL expiry is instant, and shapes B and C measure retained heap after GC
// rather than slice capacity (a capacity-only check is fooled by a fix that keeps
// the big backing array alive, whether by reslicing without copying or by over-
// allocating the copy). Identities and keys are fabricated directly; the peer-table
// paths under test do not verify them. A runnable PoC is in the build-tagged
// peer_table_poc_demo_test.go.
//
// A session-exempt C fix must place its teardown trim in deleteSession (continuum.go:634)
// or a callee: that is the only path handle()'s non-admin defer uses (:944), and the only
// teardown these tests drive.
//
// Scope: B and C inject through addPeer/bindPeerKey directly, so those are the
// required sanitize/cap points; a fix placed only at the gossip handler is out of
// scope here. The retention check (C) resolves side stores of >=4 B/id; a store of
// 1-2 bytes per id, or one preallocated before the test, is a documented blind spot
// that the structural count/Len/untimed/incumbent checks cover instead. The liveness
// phase (A) refreshes on an unsolicited pong, matching the current handler.

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

// peerTableServer builds a Server through the production constructor (so s.peers,
// s.sessions, s.ponged and the routing counters that peerExpired/addPeer touch are
// wired), with a chosen MaxPeers (0 keeps the default) and the background timers
// pushed out of range. NewServer defers peersTTL/pings to Run(), so create them here.
func peerTableServer(t *testing.T, maxPeers int) *Server {
	t.Helper()
	cfg := testConfig()
	cfg.MaxPeers = maxPeers
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	s.secret = mustSecret(t)
	peersTTL, err := ttl.New(16, true)
	if err != nil {
		t.Fatalf("peers ttl: %v", err)
	}
	pings, err := ttl.New(16, true)
	if err != nil {
		t.Fatalf("pings ttl: %v", err)
	}
	seen, err := ttl.New(16, true)
	if err != nil {
		t.Fatalf("seen ttl: %v", err)
	}
	s.peersTTL, s.pings, s.seen = peersTTL, pings, seen
	if s.ponged == nil {
		s.ponged = make(map[Identity]struct{})
	}
	s.cfg.InitialPingTimeout = time.Hour
	s.cfg.PingInterval = time.Hour
	s.cfg.MaintainInterval = time.Hour
	return s
}

// fakeID returns a distinct, non-zero Identity for n. The peer table only compares
// and stores identities, so no real key is needed.
func fakeID(n int) Identity {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	sum := sha256.Sum256(buf[:]) // spread across all prefixes so a per-bucket cap is visible
	var id Identity
	copy(id[:], sum[:])
	if id == (Identity{}) {
		id[0] = 1 // sha256 is never zero for distinct inputs; guard the impossible case without biasing any byte
	}
	return id
}

// fakeNaClPub returns a distinct, non-zero 32-byte key. bindPeerKey checks only the
// length and that it is not all-zeros; it does not verify the key.
func fakeNaClPub(n int) []byte {
	b := make([]byte, NaClPubSize)
	b[0], b[1], b[2], b[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	b[NaClPubSize-1] = 1
	return b
}

// bindSeq hands each TestPeerTableBindFloodBounded run a fresh identity range (stride
// above warm-up+window so runs never overlap), so a package-level side store keeps
// growing under -count>1. The retention measurement is only authoritative on run 1: a
// store pre-grown by an earlier run reads as no delta on later runs.
var bindSeq atomic.Int64

func peerCount(s *Server) int {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return len(s.peers)
}

func peerPresent(s *Server, id Identity) bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	_, ok := s.peers[id]
	return ok
}

// ttlTracks reports whether peersTTL still holds a row for id. Diagnostic only: a
// row can exist yet be a dead timer, so this does not prove the peer will expire.
func ttlTracks(s *Server, id Identity) bool {
	_, _, err := s.peersTTL.Get(id)
	return err == nil
}

// untimedPeers counts non-self peers with no live expiry row. A fix that caps the
// table but never arms peersTTL leaves rows that can never expire — a silent lockout.
func untimedPeers(s *Server) int {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	n := 0
	for id := range s.peers {
		if id == s.secret.Identity {
			continue
		}
		if !ttlTracks(s, id) {
			n++
		}
	}
	return n
}

// installSelf adds the production self row: key-bound, untimed (no peersTTL), stale
// LastSeen — exactly what registerSelfAsPeer (continuum.go:2894) creates at startup. A cap
// that evicts untimed or stale rows would delete it and break knownPeerList and routing.
func installSelf(t *testing.T, s *Server) {
	t.Helper()
	naclPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatalf("self nacl key: %v", err)
	}
	s.mtx.Lock()
	s.peers[s.secret.Identity] = &PeerRecord{
		Identity: s.secret.Identity,
		NaClPub:  naclPub,
		Version:  ProtocolVersion,
		LastSeen: time.Now().Unix() - 2*int64(peerTTL/time.Second),
	}
	s.mtx.Unlock()
}

// heapLive forces GC and returns live heap bytes, for measuring what a path retains.
func heapLive() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// bigSessions builds an n-long session list drawn from `distinct` identities (so a
// small distinct count never reaches sanitizeSessions' truncation branch).
func bigSessions(base, n, distinct int) []Identity {
	out := make([]Identity, n)
	for i := range out {
		out[i] = fakeID(base + i%distinct)
	}
	return out
}

// TestPeerTableDepartedPeerRemovedWithinTTL pins invariant 1 (the leak). A peer connects
// over a real transport, pongs to stay alive, then ends the session through handle()'s
// real teardown via each exit a peer can trigger: a transport close, a busy response, a
// routed cleartext TSS, a rate-limit disconnect, and a failed ping response. Inside a
// synctest bubble the virtual clock is then advanced past peerTTL, and the peer must be
// gone from s.peers. The buggy pong path re-arms peersTTL on the session context and the
// cancel drops the row without running peerExpired, so the peer is never removed. The
// liveness phase checks the lower bound: a peer that keeps ponging must NOT be removed.
// Fails while buggy.
func TestPeerTableDepartedPeerRemovedWithinTTL(t *testing.T) {
	exits := []struct {
		name string
		end  func(t *testing.T, cli *Transport, id, self Identity)
	}{
		{"transport-close", func(t *testing.T, cli *Transport, _, _ Identity) { cli.Close() }},
		{"busy-response", func(t *testing.T, cli *Transport, id, _ Identity) {
			if err := cli.Write(id, BusyResponse{}); err != nil {
				t.Fatal(err)
			}
		}},
		{"routed-cleartext-tss", func(t *testing.T, cli *Transport, id, self Identity) {
			if err := cli.WriteTo(id, self, defaultTTL, TSSMessage{}); err != nil {
				t.Fatal(err)
			}
		}},
		{"rate-limit-disconnect", func(t *testing.T, cli *Transport, id, _ Identity) {
			// Flood past the message and refusal budgets so the server hits the sustained-
			// abuse disconnect (continuum.go:1026). Count 0 so the server never asks for a
			// peer list back, which would block on the unbuffered pipe.
			for i := 0; i < messageBurst+messageDropBurst+200; i++ {
				if err := cli.Write(id, PeerNotify{Count: 0}); err != nil {
					return // server disconnected; its transport is closed
				}
			}
			t.Fatal("server did not rate-limit-disconnect under a sustained flood")
		}},
		{"ping-write-fail", func(t *testing.T, cli *Transport, id, _ Identity) {
			// Make the server's ping-response write fail (dispatch.go:104): send a ping,
			// then close so the response has nowhere to go.
			if err := cli.Write(id, PingRequest{OriginTimestamp: 1}); err != nil {
				t.Fatal(err)
			}
			cli.Close()
		}},
	}
	for _, ex := range exits {
		t.Run(ex.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := peerTableServer(t, 256)
				id := mustSecret(t).Identity
				srvCtx, srvCancel := context.WithCancel(context.Background())
				sp, cp := net.Pipe()
				cli := new(Transport)
				defer func() { // drain on every path, including t.Fatal
					srvCancel()
					sp.Close()
					cp.Close()
					time.Sleep(10000 * time.Hour)
					synctest.Wait()
				}()

				srv, err := NewTransportFromCurve(ecdh.X25519())
				if err != nil {
					t.Fatal(err)
				}
				errCh := make(chan error, 2)
				go func() { errCh <- srv.KeyExchange(srvCtx, sp) }()
				go func() { errCh <- cli.KeyExchange(srvCtx, cp) }()
				for i := 0; i < 2; i++ {
					if err := <-errCh; err != nil {
						t.Fatal(err)
					}
				}
				// Production handshake order: session, addPeer, bindPeerKey, handle.
				if err := s.newSession(&id, srv); err != nil {
					t.Fatal(err)
				}
				if !s.addPeer(srvCtx, PeerRecord{Identity: id, Version: ProtocolVersion, LastSeen: time.Now().Unix()}) {
					t.Fatal("addPeer rejected a fresh peer")
				}
				if err := s.bindPeerKey(srvCtx, id, fakeNaClPub(7)); err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				s.wg.Add(1)
				go func() { defer close(done); s.handle(srvCtx, &id, srv, false) }()
				for i := 0; i < 3; i++ {
					if _, _, _, err := cli.read(0); err != nil {
						t.Fatal(err)
					}
				}

				// Liveness (lower bound): a connected peer that keeps ponging must keep
				// its record and its bound key well past peerTTL.
				const step = 20 * time.Second
				for elapsed := time.Duration(0); elapsed < 3*peerTTL; elapsed += step {
					if err := cli.Write(id, PingResponse{}); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					time.Sleep(step)
					synctest.Wait()
					if _, ok := s.peerNaClPub(id); !ok || !peerPresent(s, id) {
						t.Fatalf("a connected, ponging peer lost its record/key at +%v: the pong must "+
							"refresh the peer TTL while the session is live.", elapsed+step)
					}
				}
				s.mtx.RLock()
				_, ponged := s.ponged[id]
				s.mtx.RUnlock()
				if !ponged {
					t.Fatal("pong never processed")
				}

				ex.end(t, cli, id, s.secret.Identity) // the peer picks how the session ends
				<-done
				synctest.Wait()
				if ex.name == "rate-limit-disconnect" && s.rateDisconnects.Load() != 1 {
					t.Errorf("rate-limit exit: rateDisconnects=%d want 1: the session did not end via "+
						"the sustained-abuse disconnect (continuum.go:1026).", s.rateDisconnects.Load())
				}

				// Lower bound: a peer must NOT be forgotten the instant its session ends — it
				// stays in s.peers with its key until peerTTL. A fix that deletes at disconnect
				// would strand the bootstrap/maintain redial handoff.
				if _, ok := s.peerNaClPub(id); !ok || !peerPresent(s, id) {
					t.Errorf("exit=%s: the departed peer was removed at disconnect, before peerTTL; a correct "+
						"fix reaps it via the TTL, not synchronously on session end.", ex.name)
				}

				time.Sleep(peerTTL + time.Second) // virtual clock: past the expiry
				synctest.Wait()
				if peerPresent(s, id) {
					t.Errorf("exit=%s: a departed peer is still in s.peers after peerTTL (peersTTL row "+
						"present=%v): the pong path re-arms peersTTL on the session context, and the cancel "+
						"on disconnect drops the row without running peerExpired.", ex.name, ttlTracks(s, id))
				}
				// s.ponged must be cleaned at teardown (deleteSession), or it grows one entry per
				// identity without bound beside s.peers.
				s.mtx.RLock()
				_, stillPonged := s.ponged[id]
				s.mtx.RUnlock()
				if stillPonged {
					t.Errorf("exit=%s: s.ponged still holds the departed peer; the session teardown must clean "+
						"it, or it leaks one entry per identity.", ex.name)
				}
			})
		})
	}
}

// TestPeerTableStoredRecordMemoryBounded pins invariant 2 (per-entry memory),
// mechanism-agnostically: it measures retained heap after GC rather than slice capacity,
// so a fix that reslices without copying (leaving the big array alive) does not pass. It
// covers a fresh insert, a re-gossip of the identical record, an update of an existing
// entry, and a duplicate-padded list that never reaches sanitizeSessions' truncation
// branch. LastSeen is set so a fix that drops stale records cannot pass vacuously, and a
// presence check confirms the records were actually stored. Fails while buggy.
func TestPeerTableStoredRecordMemoryBounded(t *testing.T) {
	ctx := context.Background()
	const per = 8
	now := time.Now().Unix()
	// Cover a range of advertised list sizes. 24000 is about the largest list that fits
	// one gossip message (TransportMaxSize / ~43 bytes per id), so a fix that only copies
	// lists above some fixed threshold still pins the array for a smaller but still-huge
	// list that can actually arrive on the wire.
	for _, huge := range []int{512, 1700, 4096, 24000, 50000} {
		s := peerTableServer(t, 256)
		before := heapLive()
		for i := 0; i < per; i++ { // fresh insert, advertised twice (identical) to exercise re-gossip
			for r := 0; r < 2; r++ {
				s.addPeer(ctx, PeerRecord{Identity: fakeID(i), Version: ProtocolVersion, LastSeen: now, Sessions: bigSessions(10_000_000*(i+1), huge, huge)})
			}
		}
		for i := per; i < 2*per; i++ { // update path: add plain, then re-add with a huge list
			s.addPeer(ctx, PeerRecord{Identity: fakeID(i), Version: ProtocolVersion, LastSeen: now})
			s.addPeer(ctx, PeerRecord{Identity: fakeID(i), Version: ProtocolVersion, LastSeen: now, Sessions: bigSessions(10_000_000*(i+1), huge, huge)})
		}
		for i := 2 * per; i < 3*per; i++ { // duplicate-padded: never hits truncation
			s.addPeer(ctx, PeerRecord{Identity: fakeID(i), Version: ProtocolVersion, LastSeen: now, Sessions: bigSessions(10_000_000*(i+1), huge, 4)})
		}
		after := heapLive()

		// Non-vacuity: every record must actually be stored. A fix that drops records
		// (e.g. on a stale LastSeen) would otherwise meet the memory bound by storing nothing.
		if n := peerCount(s); n != 3*per {
			t.Fatalf("huge=%d: %d of %d records stored: the bound must be met by storing, not dropping", huge, n, 3*per)
		}
		s.mtx.RLock()
		for id, pr := range s.peers {
			if len(pr.Sessions) > maxPeerSessions {
				t.Errorf("peer %v stores %d sessions (> %d)", id, len(pr.Sessions), maxPeerSessions)
			}
		}
		s.mtx.RUnlock()

		var grew uint64
		if after > before {
			grew = after - before
		}
		limit := uint64(3*per) * (32 << 10) // 32 KiB per record is generous for <=256 ids
		t.Logf("huge=%d records=%d retained=%d bytes limit=%d", huge, 3*per, grew, limit)
		if grew > limit {
			t.Fatalf("huge=%d: %d gossiped records retain %d bytes (> %d): a stored record pins an attacker-sized "+
				"session backing array (sanitizeSessions allocates the output with cap=len(input)).", huge, 3*per, grew, limit)
		}
		runtime.KeepAlive(s)
	}
}

// TestPeerTableBindFloodBounded pins invariant 3 (count cap) for bindPeerKey, the path
// that bypasses it. Each binder has a live session, as on every real handshake path.
// After the flood: s.peers and peersTTL must both be within MaxPeers, further binds must
// retain ~no memory (so a fix cannot just relocate overflow into a side map), and the
// cap must reject only NEW peers (a known peer must still be able to bind when full).
// Fails while buggy.
func TestPeerTableBindFloodBounded(t *testing.T) {
	const maxPeers = 4
	s := peerTableServer(t, maxPeers)
	installSelf(t, s) // production always holds a key-bound, untimed self row
	ctx := context.Background()

	bind := func(n int) {
		id := fakeID(n)
		s.mtx.Lock()
		s.sessions[id] = &Transport{}
		s.mtx.Unlock()
		_ = s.bindPeerKey(ctx, id, fakeNaClPub(n))
		_ = s.deleteSession(&id)
	}

	for i := 0; i < maxPeers*10; i++ {
		bind(i)
	}
	if n := peerCount(s); n < maxPeers {
		t.Fatalf("only %d of %d slots filled by fresh binds: the cap rejects new peers before the table is full", n, maxPeers)
	} else if n > maxPeers {
		t.Fatalf("s.peers grew to %d with MaxPeers=%d: bindPeerKey inserts a new peer with no cap check, or a "+
			"session-exempt cap whose teardown trim is not reached through deleteSession.", n, maxPeers)
	}
	if u := untimedPeers(s); u != 0 {
		t.Fatalf("%d peers have no expiry row: a cap that never arms peersTTL leaves rows that can never expire (permanent lockout).", u)
	}
	if l := s.peersTTL.Len(); l > maxPeers {
		t.Fatalf("peersTTL holds %d rows with MaxPeers=%d: evicted or rejected peers are still retained by the ttl map.", l, maxPeers)
	}

	// Retention: once the table is full, further fresh-identity binds must retain ~no
	// memory, wherever a fix puts the state. A side map or an entry left in peersTTL is
	// still a leak. Warm up first to absorb one-time runtime/map growth.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1)) // pin P=1: per-P dead-g caches otherwise read as retained heap
	g0 := runtime.NumGoroutine()
	settle := func() int {
		d := 0
		for i := 0; i < 300; i++ {
			if d = runtime.NumGoroutine() - g0; d <= 16 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		return d
	}
	// Bound the goroutine high-water mark: a correct fix that does Put then Delete spawns a
	// short-lived ttl goroutine per bind whose g struct is cached per P and never freed, so
	// without this drain the P=1 pin makes such a fix fail the retention check every run.
	drain := func() {
		for i := 0; i < 10000 && runtime.NumGoroutine()-g0 > 16; i++ {
			runtime.Gosched()
		}
	}
	next := int(bindSeq.Add(2_000_000)) // fresh ids per run; stride > warm-up(20k)+window(100k)
	for end := next + 20000; next < end; next++ {
		bind(next)
		if next%64 == 0 {
			drain()
		}
	}
	if d := settle(); d > 16 {
		t.Fatalf("warm-up flood left %d extra goroutines", d)
	}
	h0 := heapLive()
	const measured = 100000
	for end := next + measured; next < end; next++ {
		bind(next)
		if next%64 == 0 {
			drain()
		}
	}
	if d := settle(); d > 16 {
		t.Fatalf("flood left %d extra goroutines", d)
	}
	h1 := heapLive()
	per := float64(int64(h1)-int64(h0)) / measured
	t.Logf("retained %.2f bytes per fresh identity past a full table", per)
	// Correct fixes read 0.00 B/id here (the P=1 pin + drain leave no per-P garbage).
	// This catches any side store of >=4 B/id — the realistic overflow shapes (a map or
	// slice of rejected identities measure >=9 here). A store of only 1-2 bytes per id is
	// below the resolution of a 100k-bind heap delta, and a store preallocated before the
	// test reads as no delta; both are acknowledged blind spots that the structural count,
	// peersTTL.Len, untimedPeers and incumbent checks bound regardless of size.
	if per > 4 {
		t.Fatalf("binding fresh identities past a full table retains %.1f bytes each: the overflow is being "+
			"stored somewhere (a side map, or peersTTL rows) rather than rejected.", per)
	}
	// keyBound reports whether id is present with its e2e key stored.
	keyBound := func(id Identity) bool {
		s.mtx.RLock()
		defer s.mtx.RUnlock()
		pr := s.peers[id]
		return pr != nil && len(pr.NaClPub) == NaClPubSize
	}

	// Self is never evicted (untimed, stale, key-bound); an evictor that drops
	// self breaks gossip/routing.
	if !keyBound(s.secret.Identity) {
		t.Fatal("self was evicted by the flood: a cap must never evict the untimed self row.")
	}
	runtime.KeepAlive(s)

	// Live-session protection + no lockout. The correct cap, at a full table,
	// evicts a SESSIONLESS row to admit a new key binding — locking a currently
	// connected peer out of e2e is a worse DoS than the overflow, and a departed
	// peer's deterministic key is re-derived on reconnect. But it must NEVER
	// evict a peer that currently HAS a live session, nor self, even when gossip
	// has staled that peer's LastSeen (an evictor keyed on gossip-controlled
	// LastSeen would wrongly target it). Set up a protected live peer, gossip-
	// stale it, flood with sessionless binds, and confirm it (and self) survive.
	live := fakeID(20_000_000)
	s.mtx.Lock()
	s.sessions[live] = &Transport{}
	s.mtx.Unlock()
	if err := s.bindPeerKey(ctx, live, fakeNaClPub(20_000_000)); err != nil {
		t.Fatalf("binding a live peer's key failed: %v", err)
	}
	s.addPeer(ctx, PeerRecord{Identity: live, Version: ProtocolVersion, LastSeen: 1}) // gossip-stale it
	for i := 0; i < maxPeers*10; i++ {
		bind(30_000_000 + i) // sessionless binds; each evicts a sessionless row
	}
	if !keyBound(live) {
		t.Fatal("a peer with a LIVE session was evicted by the flood: eviction must spare live sessions regardless of gossiped LastSeen.")
	}
	if !keyBound(s.secret.Identity) {
		t.Fatal("self was evicted by the flood.")
	}

	// No lockout: a brand-new peer WITH a live session must bind at the full
	// table (by evicting a sessionless row), or a real connected peer is locked
	// out of e2e and TSS ceremonies stall. This is what a reject-when-full cap
	// gets wrong.
	newLive := fakeID(21_000_000)
	s.mtx.Lock()
	s.sessions[newLive] = &Transport{}
	s.mtx.Unlock()
	if err := s.bindPeerKey(ctx, newLive, fakeNaClPub(21_000_000)); err != nil {
		t.Fatalf("a new live peer could not bind at a full table (%v): a cap must evict a sessionless row, not lock out a connected peer.", err)
	}
	if !keyBound(newLive) {
		t.Fatal("a new live peer's binding was not stored at a full table.")
	}
	if n := peerCount(s); n > maxPeers {
		t.Fatalf("table grew to %d past the live-bind flood with MaxPeers=%d", n, maxPeers)
	}
	s.mtx.Lock()
	delete(s.sessions, live)
	delete(s.sessions, newLive)
	s.mtx.Unlock()

	// Positive control: the cap must reject only NEW peers. A known peer must still be
	// able to bind its key when the table is full, or an over-broad reject breaks real
	// key binding.
	ctrl := peerTableServer(t, 2)
	known := fakeID(1)
	ctrl.addPeer(ctx, PeerRecord{Identity: known, Version: ProtocolVersion, LastSeen: time.Now().Unix()})
	ctrl.addPeer(ctx, PeerRecord{Identity: fakeID(2), Version: ProtocolVersion, LastSeen: time.Now().Unix()}) // table now full
	if err := ctrl.bindPeerKey(ctx, known, fakeNaClPub(1)); err != nil {
		t.Fatalf("binding an already-known peer's key failed when the table was full (%v): the cap must "+
			"reject only new peers.", err)
	}
	ctrl.mtx.RLock()
	kr := ctrl.peers[known]
	ctrl.mtx.RUnlock()
	if kr == nil || len(kr.NaClPub) != NaClPubSize {
		t.Fatalf("a known peer's key was not stored when the table was full")
	}

	// Handshake order over a gossip-filled table: the real attack fills s.peers through
	// addPeer first, then every handshake does addPeer (rejected when full) then bindPeerKey.
	// A cap that counts a sub-population (key-bound rows, or max(bound,gossip)) passes the
	// empty-table flood above but overshoots here; a prefill smaller than the cap exposes
	// max(bound,gossip). The prefill rows carry a stale LastSeen, so a cap that only counts
	// recently-seen rows treats them as free and overshoots too.
	for pi, prefill := range []int{maxPeers, maxPeers / 2} {
		g := peerTableServer(t, maxPeers)
		installSelf(t, g)
		base := 900_000 * (pi + 1)
		for i := 0; i < prefill; i++ {
			g.addPeer(ctx, PeerRecord{Identity: fakeID(base + i), Version: ProtocolVersion, LastSeen: 1})
		}
		for i := 0; i < maxPeers*10; i++ {
			id := fakeID(base + 1000 + i)
			g.mtx.Lock()
			g.sessions[id] = &Transport{}
			g.mtx.Unlock()
			g.addPeer(ctx, PeerRecord{Identity: id, Version: ProtocolVersion, LastSeen: time.Now().Unix()})
			_ = g.bindPeerKey(ctx, id, fakeNaClPub(i))
			_ = g.deleteSession(&id)
		}
		if n, l, u := peerCount(g), g.peersTTL.Len(), untimedPeers(g); n > maxPeers || l > maxPeers || u != 0 {
			t.Fatalf("prefill=%d: handshake-order binds over a gossip-filled table grew s.peers to %d (peersTTL %d, untimed %d) with MaxPeers=%d", prefill, n, l, u, maxPeers)
		}
		if !peerPresent(g, g.secret.Identity) {
			t.Fatalf("prefill=%d: self evicted by the gossip-path flood", prefill)
		}
	}

	// No-session bind flood: bindPeerKey (the NaClKeyResponse path) binds a key with no
	// live session, so a cap that only counts session-holding ids skips it entirely.
	ns := peerTableServer(t, maxPeers)
	installSelf(t, ns)
	for i := 0; i < maxPeers*10; i++ {
		_ = ns.bindPeerKey(ctx, fakeID(7_000_000+i), fakeNaClPub(i))
	}
	if n, l, u := peerCount(ns), ns.peersTTL.Len(), untimedPeers(ns); n > maxPeers || l > maxPeers || u != 0 {
		t.Fatalf("no-session binds grew s.peers to %d (peersTTL %d, untimed %d) with MaxPeers=%d", n, l, u, maxPeers)
	}
	if !peerPresent(ns, ns.secret.Identity) {
		t.Fatal("self evicted by the no-session bind flood")
	}

	// Pong sub-flood at a full table: a pong for an UNKNOWN id must not create a row.
	// refreshPeerLastSeen that upserts is a 4th uncapped s.peers writer that reopens root C.
	pf := peerTableServer(t, maxPeers)
	for i := 0; i < maxPeers; i++ {
		id := fakeID(950_000 + i)
		pf.mtx.Lock()
		pf.sessions[id] = &Transport{}
		pf.mtx.Unlock()
		pf.addPeer(ctx, PeerRecord{Identity: id, Version: ProtocolVersion, LastSeen: time.Now().Unix()})
		_ = pf.bindPeerKey(ctx, id, fakeNaClPub(950_000+i))
		_ = pf.deleteSession(&id)
	}
	for i := 0; i < maxPeers*10; i++ {
		pf.refreshPeerLastSeen(ctx, fakeID(960_000+i))
	}
	if n, l, u := peerCount(pf), pf.peersTTL.Len(), untimedPeers(pf); n > maxPeers || l > maxPeers || u != 0 {
		t.Fatalf("pong for unknown ids at a full table grew s.peers to %d (peersTTL %d, untimed %d): refreshPeerLastSeen must not insert a new row.", n, l, u)
	}

	// addPeer reject retention: once the table is full, a REJECTED gossip record must retain
	// nothing. A fix that stashes rejected records on addPeer's full-table branch leaks per
	// record even though s.peers stays capped. Rejects do not arm peersTTL, so no drain/pin.
	ar := peerTableServer(t, maxPeers)
	installSelf(t, ar)
	for i := 0; i < maxPeers; i++ {
		ar.addPeer(ctx, PeerRecord{Identity: fakeID(40_000_000 + i), Version: ProtocolVersion, LastSeen: time.Now().Unix()})
	}
	for i := 0; i < 500; i++ { // warm up one-time growth
		ar.addPeer(ctx, PeerRecord{Identity: fakeID(41_000_000 + i), Version: ProtocolVersion, Sessions: bigSessions(50_000_000+i*1000, 512, 512)})
	}
	arh0 := heapLive()
	const arN = 20000
	for i := 0; i < arN; i++ {
		ar.addPeer(ctx, PeerRecord{Identity: fakeID(42_000_000 + i), Version: ProtocolVersion, Sessions: bigSessions(60_000_000+i*1000, 512, 512)})
	}
	arh1 := heapLive()
	if n := peerCount(ar); n > maxPeers {
		t.Fatalf("addPeer admitted past the cap: %d > %d", n, maxPeers)
	}
	arper := float64(int64(arh1)-int64(arh0)) / arN
	t.Logf("addPeer-reject retained %.2f bytes per rejected record", arper)
	if arper > 8 {
		t.Fatalf("addPeer retains %.1f bytes per REJECTED record: a fix is stashing rejected gossip records in a side store.", arper)
	}
	if ap := ar.peers[ar.secret.Identity]; ap == nil || len(ap.NaClPub) != NaClPubSize {
		t.Fatal("self evicted by the addPeer-reject flood: a full-table addPeer evictor must not drop self.")
	}
}

// TestPeerTableBindFloodSparesCeremonyKeys pins the committee-member protection:
// a key bound for a RUNNING ceremony's committee member we hold NO session with
// (ensureCommitteeKeys reaches members multi-hop and binds them via the
// NaClKeyResponse path) must survive a fresh-identity bind flood -- otherwise
// SendEncrypted to that member fails mid-ceremony and keygen/sign/reshare
// aborts. Eviction may take such a row only as a last resort (no other
// sessionless row exists), which MaxPeers >> committee size prevents. Once the
// ceremony ends the member is unpinned, so the pin cannot bloat the table.
func TestPeerTableBindFloodSparesCeremonyKeys(t *testing.T) {
	const maxPeers = 4
	s := peerTableServer(t, maxPeers)
	installSelf(t, s)
	ctx := context.Background()

	// Two committee members (as a reshare's Old union New) reached multi-hop:
	// keys bound via the NaClKeyResponse path, no live session.
	memberA, memberB := fakeID(500), fakeID(501)
	if err := s.bindPeerKey(ctx, memberA, fakeNaClPub(500)); err != nil {
		t.Fatalf("binding committee member A failed: %v", err)
	}
	if err := s.bindPeerKey(ctx, memberB, fakeNaClPub(501)); err != nil {
		t.Fatalf("binding committee member B failed: %v", err)
	}
	var cid CeremonyID
	cid[0] = 0xC1
	s.mtx.Lock()
	s.ceremonies[cid] = &CeremonyInfo{Status: CeremonyRunning, Committee: []Identity{memberA, memberB}}
	s.mtx.Unlock()

	flood := func(base int) {
		for i := 0; i < maxPeers*20; i++ {
			id := fakeID(base + i)
			s.mtx.Lock()
			s.sessions[id] = &Transport{}
			s.mtx.Unlock()
			_ = s.bindPeerKey(ctx, id, fakeNaClPub(base+i))
			_ = s.deleteSession(&id)
		}
	}
	keyBound := func(id Identity) bool {
		s.mtx.RLock()
		defer s.mtx.RUnlock()
		pr := s.peers[id]
		return pr != nil && len(pr.NaClPub) == NaClPubSize
	}

	flood(50_000_000)
	if !keyBound(memberA) || !keyBound(memberB) {
		t.Fatal("a running-ceremony committee member's e2e key was evicted by a bind flood: SendEncrypted would fail mid-ceremony and abort keygen/sign/reshare (both Old and New reshare members must be spared).")
	}
	if n := peerCount(s); n > maxPeers {
		t.Fatalf("table grew to %d with MaxPeers=%d", n, maxPeers)
	}

	// When the ceremony leaves Running its members must be UNPINNED -- a pin that
	// never lapses bloats the table and lets a stale committee shield itself
	// while a currently-running ceremony's member is forced out instead.
	s.mtx.Lock()
	s.ceremonies[cid].Status = CeremonyComplete
	stillPinned := s.runningCeremonyMembersLocked()
	s.mtx.Unlock()
	if _, ok := stillPinned[memberA]; ok {
		t.Fatal("a completed ceremony's member is still pinned: the pin must lapse when Status leaves CeremonyRunning.")
	}
	// A subsequent flood reclaims their now-unpinned rows; the table stays capped.
	flood(51_000_000)
	if n := peerCount(s); n > maxPeers {
		t.Fatalf("table grew to %d after ceremony completion with MaxPeers=%d", n, maxPeers)
	}
}

// TestPeerTableSessionlessBindAtFullTableStores pins that a NEW bind with no
// live session (the NaClKeyResponse / ensureCommitteeKeys path, which reaches
// committee peers multi-hop) is actually STORED at a full table, not silently
// dropped. A cap that inserts-then-evicts (evicting the just-inserted row) or
// rejects the no-session binder reopens the lockout Part C exists to prevent.
func TestPeerTableSessionlessBindAtFullTableStores(t *testing.T) {
	const maxPeers = 4
	s := peerTableServer(t, maxPeers)
	installSelf(t, s)
	ctx := context.Background()

	// Fill with sessionless key-bound rows (session held only during the bind).
	for i := 0; i < maxPeers*5; i++ {
		id := fakeID(70_000_000 + i)
		s.mtx.Lock()
		s.sessions[id] = &Transport{}
		s.mtx.Unlock()
		_ = s.bindPeerKey(ctx, id, fakeNaClPub(70_000_000+i))
		_ = s.deleteSession(&id)
	}

	// A NEW bind with NO session at the full table must be stored.
	newID := fakeID(71_000_000)
	if err := s.bindPeerKey(ctx, newID, fakeNaClPub(71_000_000)); err != nil {
		t.Fatalf("sessionless bind at a full table errored: %v", err)
	}
	if _, ok := s.peerNaClPub(newID); !ok {
		t.Fatal("a sessionless bind at a full table was not stored: an insert-then-evict or reject-no-session cap reopens the lockout (a multi-hop committee key is lost).")
	}
	if n := peerCount(s); n > maxPeers {
		t.Fatalf("table grew to %d with MaxPeers=%d", n, maxPeers)
	}
}

// TestPeerTableEvictPrefersGossipOnly pins that bind-time eviction drops a
// gossip-only row (no bound key) before a sessionless key-bound one: forgetting
// a discovery row is cheaper than forgetting an authenticated e2e key. Repeated
// over many trials because s.peers iteration order is randomized.
func TestPeerTableEvictPrefersGossipOnly(t *testing.T) {
	const maxPeers = 3
	ctx := context.Background()
	kb := func(s *Server, id Identity) bool {
		s.mtx.RLock()
		defer s.mtx.RUnlock()
		pr := s.peers[id]
		return pr != nil && len(pr.NaClPub) == NaClPubSize
	}
	for trial := 0; trial < 64; trial++ {
		s := peerTableServer(t, maxPeers)
		installSelf(t, s) // self occupies one slot
		gossipOnly := fakeID(90_000_000 + trial)
		s.addPeer(ctx, PeerRecord{Identity: gossipOnly, Version: ProtocolVersion, LastSeen: time.Now().Unix()})
		keyID := fakeID(91_000_000 + trial)
		s.mtx.Lock()
		s.sessions[keyID] = &Transport{}
		s.mtx.Unlock()
		_ = s.bindPeerKey(ctx, keyID, fakeNaClPub(91_000_000+trial))
		_ = s.deleteSession(&keyID) // table now full: self + gossipOnly + keyID

		// A new sessionless bind must evict the gossip-only row and keep the key.
		_ = s.bindPeerKey(ctx, fakeID(92_000_000+trial), fakeNaClPub(92_000_000+trial))
		if peerPresent(s, gossipOnly) {
			t.Fatalf("trial %d: eviction kept the gossip-only row at a full table", trial)
		}
		if !kb(s, keyID) {
			t.Fatalf("trial %d: eviction dropped the key-bound row instead of the gossip-only one", trial)
		}
	}
}

// TestPeerTableChurnConserved pins that admit-then-expire conserves memory: a fix that

// TestPeerTableChurnConserved pins that admit-then-expire conserves memory: a fix that
// records each admitted identity in a side store never cleaned on expiry bounds s.peers
// yet leaks per admission under sustained churn. Runs at the production default MaxPeers.
func TestPeerTableChurnConserved(t *testing.T) {
	const maxPeers = 256
	s := peerTableServer(t, maxPeers)
	installSelf(t, s)
	ctx := context.Background()
	expire := func(id Identity) {
		_ = s.deleteSession(&id)
		_, _ = s.peersTTL.Delete(id)
		s.peerExpired(ctx, id, nil) // the sole production s.peers deleter (+ its route/side-index hooks)
	}
	// Each cycle admits via BOTH production admission paths — a handshake (addPeer creates
	// the row at 2491, then bindPeerKey) and a bind-only (bindPeerKey creates it at 2646) —
	// so a side store on either admit path is seen.
	cycle := func(n int) {
		h := fakeID(80_000_000 + n)
		s.mtx.Lock()
		s.sessions[h] = &Transport{}
		s.mtx.Unlock()
		s.addPeer(ctx, PeerRecord{Identity: h, Version: ProtocolVersion, LastSeen: time.Now().Unix()})
		_ = s.bindPeerKey(ctx, h, fakeNaClPub(n))
		expire(h)
		b := fakeID(90_000_000 + n)
		s.mtx.Lock()
		s.sessions[b] = &Transport{}
		s.mtx.Unlock()
		_ = s.bindPeerKey(ctx, b, fakeNaClPub(n))
		expire(b)
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	g0 := runtime.NumGoroutine()
	drain := func() {
		for i := 0; i < 10000 && runtime.NumGoroutine()-g0 > 16; i++ {
			runtime.Gosched()
		}
	}
	settle := func() int {
		d := 0
		for i := 0; i < 300; i++ {
			if d = runtime.NumGoroutine() - g0; d <= 16 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		return d
	}
	n := 0
	for ; n < 20000; n++ { // warm up
		cycle(n)
		if n%64 == 0 {
			drain()
		}
	}
	if d := settle(); d > 16 {
		t.Fatalf("warm-up left %d extra goroutines", d)
	}
	h0 := heapLive()
	const measured = 100000
	for end := n + measured; n < end; n++ {
		cycle(n)
		if n%64 == 0 {
			drain()
		}
	}
	if d := settle(); d > 16 {
		t.Fatalf("flood left %d extra goroutines", d)
	}
	h1 := heapLive()
	if c := peerCount(s); c > 2 {
		t.Fatalf("admit-then-expire left %d peers; each cycle must fully remove its peer", c)
	}
	per := float64(int64(h1)-int64(h0)) / measured
	t.Logf("admit-then-expire retained %.2f bytes per admission", per)
	if per > 8 {
		t.Fatalf("admit-then-expire retains %.1f bytes per admission: a fix records admitted identities in a side store never cleaned on expiry.", per)
	}
}

// TestPeerTableLiveSessionKeptAlive runs the REAL ping machinery (pingLoop + pings TTL +
// cancel) under production timers with a client that answers every PingRequest, and
// requires the session to stay alive well past several ping cycles. It catches a fix that
// drops the pong's pings.Cancel (dispatch.go:112): the ping timeout then fires and
// pingExpired kills an honest, responsive session. peerTableServer suppresses the ping
// cadence (1h); this test restores it. Passes on base and a correct fix.
func TestPeerTableLiveSessionKeptAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := peerTableServer(t, 256)
		s.cfg.InitialPingTimeout = initialPingTimeout // restore production ping cadence
		s.cfg.PingInterval = pingInterval
		s.cfg.PingTimeout = pingTimeout
		id := mustSecret(t).Identity
		srvCtx, srvCancel := context.WithCancel(context.Background())
		sp, cp := net.Pipe()
		cli := new(Transport)
		defer func() {
			srvCancel()
			sp.Close()
			cp.Close()
			time.Sleep(10000 * time.Hour)
			synctest.Wait()
		}()
		srv, err := NewTransportFromCurve(ecdh.X25519())
		if err != nil {
			t.Fatal(err)
		}
		errCh := make(chan error, 2)
		go func() { errCh <- srv.KeyExchange(srvCtx, sp) }()
		go func() { errCh <- cli.KeyExchange(srvCtx, cp) }()
		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		}
		if err := s.newSession(&id, srv); err != nil {
			t.Fatal(err)
		}
		if !s.addPeer(srvCtx, PeerRecord{Identity: id, Version: ProtocolVersion, LastSeen: time.Now().Unix()}) {
			t.Fatal("addPeer rejected a fresh peer")
		}
		if err := s.bindPeerKey(srvCtx, id, fakeNaClPub(7)); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		s.wg.Add(1)
		go func() { defer close(done); s.handle(srvCtx, &id, srv, false) }()

		// The peer answers every PingRequest, so a correct node keeps the session.
		go func() {
			for {
				_, cmd, _, err := cli.read(0)
				if err != nil {
					return
				}
				if req, ok := cmd.(*PingRequest); ok {
					// Answer instantly: the production pingLoop arms its timeout BEFORE the
					// write, so an instant pong cannot race ahead of the arm.
					if err := cli.Write(id, PingResponse{OriginTimestamp: req.OriginTimestamp}); err != nil {
						return
					}
				}
			}
		}()

		for elapsed := time.Duration(0); elapsed < 5*time.Minute; elapsed += pingInterval {
			time.Sleep(pingInterval)
			synctest.Wait()
			select {
			case <-done:
				t.Fatalf("handle() returned at +%v while the peer was answering pings: a fix must not kill a "+
					"live, responsive session (e.g. dropping the pong's pings.Cancel).", elapsed+pingInterval)
			default:
			}
			if _, ok := s.peerNaClPub(id); !ok || !peerPresent(s, id) {
				t.Fatalf("a live, ping-answering peer was dropped at +%v.", elapsed+pingInterval)
			}
		}
	})
}

// TestPeerTableCappedRowsExpire guards against a count-cap fix that admits a peer but
// arms a non-reaping expiry: a nil peerExpired callback (the ttl row auto-deletes without
// touching s.peers) or an unbounded TTL. untimedPeers cannot see these — the row exists —
// so this advances the virtual clock and requires the rows to actually be gone. It passes
// on the unpatched tree (bindPeerKey already arms a correct timer) and on a correct fix;
// it fails a fix that caps the count but leaves a row that never reaps the peer.
func TestPeerTableCappedRowsExpire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxPeers = 4
		s := peerTableServer(t, maxPeers)
		installSelf(t, s) // the untimed self row must survive the reap
		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			cancel()
			time.Sleep(10000 * time.Hour)
			synctest.Wait()
		}()
		for i := 0; i < maxPeers+1; i++ { // self holds one slot, so tolerate rejects past it
			id := fakeID(i)
			s.mtx.Lock()
			s.sessions[id] = &Transport{}
			s.mtx.Unlock()
			if err := s.bindPeerKey(ctx, id, fakeNaClPub(i)); err != nil && i < maxPeers-1 {
				t.Fatal(err)
			}
			_ = s.deleteSession(&id)
		}
		synctest.Wait()
		if n := peerCount(s); n < maxPeers {
			t.Fatalf("setup: want >=%d rows incl self, got %d", maxPeers, n)
		}
		time.Sleep(peerTTL + time.Second) // no further pong: every TIMED row must reap
		synctest.Wait()
		if !peerPresent(s, s.secret.Identity) {
			t.Fatal("self (untimed) was reaped: a cap must not arm an expiry timer on the untimed self row")
		}
		if n, l := peerCount(s), s.peersTTL.Len(); n != 1 || l != 0 {
			t.Fatalf("after peerTTL want only self left (n=1,l=0), got n=%d l=%d — a cap that arms a nil "+
				"callback or an unbounded TTL leaves a row that never removes the peer.", n, l)
		}
	})
}
