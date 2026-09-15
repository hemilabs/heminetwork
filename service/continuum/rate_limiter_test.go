// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Coverage for the three inbound-abuse controls:
//
//   - a per-identity message bucket that survives reconnects and
//     expires on idleness, so it neither refills for free nor grows
//     without bound;
//   - a per-source cap on IN-FLIGHT handshakes, so one address cannot
//     occupy every handshakeSem slot;
//   - a budget on REFUSED messages, so a peer that ignores the message
//     limit is disconnected rather than being paid for forever.
//
// Time is supplied explicitly wherever a token bucket is asserted on.
// rate.Limiter refills on the wall clock, so `drain(); if l.Allow()`
// is only correct when both statements run inside one refill interval
// (10.3ms at messageRate) — a flake that hides on an idle machine.
// AllowN with a fixed instant removes the clock from the assertion.

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

// limiterServer builds a Server through the production constructor so
// the limiter table exists, and pushes the session timers out of range
// so they cannot fire during a test. handle() arms an initial-ping
// timeout; at the default 7s it races the negative waits below and
// would close the session for a reason the test then misattributes.
func limiterServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(testConfig())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("server secret: %v", err)
	}
	peersTTL, err := ttl.New(16, true)
	if err != nil {
		t.Fatalf("peers ttl: %v", err)
	}
	pings, err := ttl.New(16, true)
	if err != nil {
		t.Fatalf("pings ttl: %v", err)
	}
	s.secret, s.peersTTL, s.pings = secret, peersTTL, pings
	s.cfg.InitialPingTimeout = time.Hour
	s.cfg.PingInterval = time.Hour
	s.cfg.MaintainInterval = time.Hour
	return s
}

// drainAt empties a limiter at a fixed instant and returns how many
// tokens it granted. The instant is fixed so no refill can occur
// mid-drain.
func drainAt(t *testing.T, l *rate.Limiter, now time.Time) int {
	t.Helper()
	const bound = messageBurst * 10
	for i := range bound {
		if !l.AllowN(now, 1) {
			return i
		}
	}
	t.Fatalf("limiter granted %d tokens without refusing", bound)
	return 0
}

// --- per-identity message bucket ---

func TestPeerLimiterSurvivesReconnect(t *testing.T) {
	s := limiterServer(t)
	peer := mustSecret(t).Identity
	now := time.Now()

	if got := drainAt(t, s.peerLimiter(peer), now); got == 0 {
		t.Fatal("limiter refused the very first message")
	}

	// Reconnect: handle() looks the limiter up again for the same
	// identity and must get the exhausted one, not a fresh bucket.
	if s.peerLimiter(peer).AllowN(now, 1) {
		t.Fatal("reconnecting refilled the burst budget: a peer can " +
			"spend its burst, drop the connection, and immediately " +
			"reconnect for another one")
	}
}

func TestPeerLimiterIsPerIdentity(t *testing.T) {
	s := limiterServer(t)
	noisy := mustSecret(t).Identity
	quiet := mustSecret(t).Identity
	now := time.Now()

	drainAt(t, s.peerLimiter(noisy), now)

	if !s.peerLimiter(quiet).AllowN(now, 1) {
		t.Fatal("a different identity was throttled by the noisy peer")
	}
	if s.peerLimiter(noisy).AllowN(now, 1) {
		t.Fatal("the exhausted identity was refilled")
	}
}

func TestPeerLimiterStableIdentity(t *testing.T) {
	s := limiterServer(t)
	peer := mustSecret(t).Identity

	first := s.peerLimiter(peer)
	if second := s.peerLimiter(peer); first != second {
		t.Fatal("peerLimiter returned a new limiter for a known identity")
	}
	if got := first.Burst(); got != messageBurst {
		t.Fatalf("burst = %d, want %d", got, messageBurst)
	}
	if got := first.Limit(); got != rate.Limit(messageRate) {
		t.Fatalf("rate = %v, want %v", got, rate.Limit(messageRate))
	}
}

// TestPeerLimiterTableSelfBounds proves the table does not depend on
// the peer record for eviction.
//
// Identities are free to mint and addPeer REJECTS a peer whose NaClPub
// is absent, while the handshake permits it — so an attacker can hold
// a session, and therefore a limiter, for an identity that never
// becomes a tracked peer. Keying eviction off the peer record leaked
// one entry per such connection, permanently. The table must expire on
// its own instead.
func TestPeerLimiterTableSelfBounds(t *testing.T) {
	s := limiterServer(t)

	// None of these identities is ever added to s.peers.
	for range 64 {
		s.peerLimiter(mustSecret(t).Identity)
	}
	s.mtx.RLock()
	tracked := len(s.peers)
	s.mtx.RUnlock()
	if tracked != 0 {
		t.Fatalf("test setup: %d peers tracked, want 0", tracked)
	}
	if got := s.limiters.Len(); got != 64 {
		t.Fatalf("limiters = %d, want 64", got)
	}

	// Entries carry their own expiry rather than waiting on a peer
	// record that will never exist.
	id := mustSecret(t).Identity
	s.peerLimiter(id)
	if _, _, err := s.limiters.Get(id); err != nil {
		t.Fatalf("entry not stored: %v", err)
	}
	if _, err := s.limiters.Delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := s.limiters.Get(id); err == nil {
		t.Fatal("entry survived deletion")
	}
}

// --- per-source in-flight handshake cap ---

func tcpAddr(t *testing.T, ip string, port int) *net.TCPAddr {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("bad test ip %q", ip)
	}
	return &net.TCPAddr{IP: parsed, Port: port}
}

func TestHandshakeInFlightCap(t *testing.T) {
	s := limiterServer(t)
	addr := tcpAddr(t, "10.0.0.1", 40000)

	keys := make([]string, 0, maxHandshakesPerIP)
	for i := range maxHandshakesPerIP {
		k, ok := s.acquireHandshake(addr)
		if !ok {
			t.Fatalf("attempt %d refused below the cap", i)
		}
		keys = append(keys, k)
	}

	// Past the cap: refused, so the source cannot occupy more than
	// maxHandshakesPerIP semaphore slots no matter how fast it
	// connects. This is what an arrival-rate limit could not do —
	// occupancy is rate x hold-time, so any permitted rate holds
	// rate*handshakeTimeout slots in steady state.
	if _, ok := s.acquireHandshake(addr); ok {
		t.Fatalf("a source held more than %d handshakes in flight: "+
			"it can occupy every semaphore slot and starve "+
			"legitimate peers", maxHandshakesPerIP)
	}

	// Finishing one frees exactly one.
	s.releaseHandshake(keys[0])
	if _, ok := s.acquireHandshake(addr); !ok {
		t.Fatal("releasing a handshake did not free a slot")
	}
}

// TestHandshakeInFlightNeverLocksOut proves the cap cannot be used to
// exclude an honest peer. Unlike an arrival-rate limit, a source with
// fewer than the cap in flight is ALWAYS admitted, so a peer behind a
// shared NAT egress is never refused because of a co-located flooder.
func TestHandshakeInFlightNeverLocksOut(t *testing.T) {
	s := limiterServer(t)
	shared := tcpAddr(t, "10.0.0.1", 40000)

	// A flooder saturates the shared address, then goes away.
	var keys []string
	for range maxHandshakesPerIP {
		k, _ := s.acquireHandshake(shared)
		keys = append(keys, k)
	}
	for _, k := range keys {
		s.releaseHandshake(k)
	}

	// The honest peer behind the same address connects and is
	// admitted immediately — no residual penalty, unlike a token
	// bucket which would still be empty.
	if _, ok := s.acquireHandshake(shared); !ok {
		t.Fatal("an honest peer was refused after a co-located " +
			"flooder finished: the cap must not carry a penalty " +
			"forward or NAT'd peers get locked out")
	}
}

// TestHandshakeIPv6PrefixKeyed proves addresses in one /64 share a
// budget. A routed /64 is the standard host allocation, so keying on
// the full /128 would let one machine mint unlimited distinct keys and
// bypass the cap entirely.
func TestHandshakeIPv6PrefixKeyed(t *testing.T) {
	s := limiterServer(t)

	first, ok := handshakeIP(tcpAddr(t, "2001:db8::1", 40000))
	if !ok {
		t.Fatal("no key derived for an IPv6 address")
	}
	second, _ := handshakeIP(tcpAddr(t, "2001:db8::dead:beef", 40001))
	if first != second {
		t.Fatalf("addresses in one /64 keyed separately (%q vs %q): "+
			"a single host can rotate addresses to bypass the cap",
			first, second)
	}

	// A different /64 is a different source.
	other, _ := handshakeIP(tcpAddr(t, "2001:db8:0:1::1", 40000))
	if other == first {
		t.Fatal("distinct /64s shared a key")
	}

	// Saturating one /64 does not refuse another.
	for range maxHandshakesPerIP {
		s.acquireHandshake(tcpAddr(t, "2001:db8::1", 40000))
	}
	if _, ok := s.acquireHandshake(tcpAddr(t, "2001:db8::2", 40002)); ok {
		t.Fatal("a second address in the saturated /64 was admitted")
	}
	if _, ok := s.acquireHandshake(tcpAddr(t, "2001:db8:0:1::1", 40000)); !ok {
		t.Fatal("an unrelated /64 was refused")
	}
}

func TestHandshakeIPv4KeyedWhole(t *testing.T) {
	s := limiterServer(t)

	a, ok := handshakeIP(tcpAddr(t, "10.0.0.1", 40000))
	if !ok {
		t.Fatal("no key derived for an IPv4 address")
	}
	// Source port must not matter: an attacker gets a fresh one per
	// connection for free.
	b, _ := handshakeIP(tcpAddr(t, "10.0.0.1", 40001))
	if a != b {
		t.Fatal("source port changed the key")
	}
	// Neighbouring addresses are distinct sources.
	c, _ := handshakeIP(tcpAddr(t, "10.0.0.2", 40000))
	if c == a {
		t.Fatal("distinct IPv4 addresses shared a key")
	}
	for range maxHandshakesPerIP {
		s.acquireHandshake(tcpAddr(t, "10.0.0.1", 40000))
	}
	if _, ok := s.acquireHandshake(tcpAddr(t, "10.0.0.2", 40000)); !ok {
		t.Fatal("an unrelated IPv4 source was refused")
	}
}

// TestHandshakeTableBoundedByInFlight proves the tracking map holds
// only work actually in progress, so it cannot be grown by connection
// churn from many sources.
func TestHandshakeTableBoundedByInFlight(t *testing.T) {
	s := limiterServer(t)

	for i := range 4096 {
		//nolint:gosec // deterministic test octets
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		k, ok := s.acquireHandshake(&net.TCPAddr{IP: ip, Port: 40000})
		if !ok {
			t.Fatalf("source %d refused on its first handshake", i)
		}
		s.releaseHandshake(k)
	}

	s.handshakeIPMtx.Lock()
	n := len(s.handshakesInFlight)
	s.handshakeIPMtx.Unlock()
	if n != 0 {
		t.Fatalf("in-flight table = %d entries after every handshake "+
			"finished, want 0", n)
	}
}

// TestHandshakeNonTCPAddr covers the guard for addresses with no IP to
// key on; handshakeSem still bounds total concurrency.
func TestHandshakeNonTCPAddr(t *testing.T) {
	s := limiterServer(t)
	addr := &net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"}

	for range maxHandshakesPerIP * 2 {
		k, ok := s.acquireHandshake(addr)
		if !ok {
			t.Fatal("non-TCP address was capped")
		}
		if k != "" {
			t.Fatalf("non-TCP address produced key %q", k)
		}
	}
	// Releasing an empty key is a no-op, not a corruption.
	s.releaseHandshake("")
	s.handshakeIPMtx.Lock()
	n := len(s.handshakesInFlight)
	s.handshakeIPMtx.Unlock()
	if n != 0 {
		t.Fatalf("in-flight table = %d, want 0", n)
	}
}

// TestAcceptLoopEnforcesHandshakeCap drives the REAL listener: the
// unit tests above exercise the helper directly and would pass even if
// nothing called it.
func TestAcceptLoopEnforcesHandshakeCap(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()
	addr := waitForListenAddress(t, s, 5*time.Second)

	// Open connections that never speak the protocol. Each would
	// otherwise hold a semaphore slot for the whole handshake
	// timeout — the starvation this cap exists to stop.
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			c.Close()
		}
	})
	for range maxHandshakesPerIP * 8 {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			break // refused at the OS level is also a rejection
		}
		conns = append(conns, c)
	}

	waitForCondition(t, "accept loop never refused a flood of "+
		"unauthenticated connections from one source",
		15*time.Second, func() bool {
			return s.hsRateDrops.Load() > 0
		})

	cancel()
	exitCtx, exitCancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer exitCancel()
	select {
	case <-errCh:
	case <-exitCtx.Done():
		t.Fatal("server did not shut down")
	}
}

// --- refused-message budget ---

// blockedSession drives handle() with a peer whose message limiter
// refuses everything, writes msgs messages, and reports whether
// handle() closed the session.
//
// The limiter is pinned to refuse rather than being outrun in real
// time: a test that floods and hopes to beat the refill rate is a race
// against machine speed and fails under load.
func blockedSession(t *testing.T, s *Server, peer *Secret, msgs int) bool {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// rate 0, burst 0: AllowN is always false.
	s.limiterMtx.Lock()
	s.limiters.Put(context.Background(), limiterTTL, peer.Identity,
		rate.NewLimiter(0, 0), nil, nil)
	s.limiterMtx.Unlock()

	// Real TCP, not net.Pipe: the pipe is unbuffered, so every write
	// blocks for a reader and nothing can be staged.
	srv, cli := localhostTransports(t)
	if err := s.newSession(&peer.Identity, srv); err != nil {
		t.Fatalf("new session: %v", err)
	}

	done := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer close(done)
		s.handle(ctx, &peer.Identity, srv, false)
	}()

	// Drain whatever handle() sends so its writes cannot block the
	// read loop under test. Deadline cleared so the drain lives as
	// long as the session it protects.
	go func() {
		for {
			if _, _, _, err := cli.read(0); err != nil {
				return
			}
		}
	}()

	for range msgs {
		select {
		case <-done:
			return true
		default:
		}
		if err := cli.Write(peer.Identity, PingResponse{}); err != nil {
			// A closed transport IS the disconnect under test.
			// handle() closes the transport before this goroutine
			// observes done, so give it a moment to land rather
			// than racing it.
			closeCtx, closeCancel := context.WithTimeout(t.Context(),
				5*time.Second)
			defer closeCancel()
			select {
			case <-done:
				return true
			case <-closeCtx.Done():
				t.Fatalf("write failed but the session stayed open: %v", err)
			}
		}
	}

	waitCtx, waitCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer waitCancel()
	select {
	case <-done:
		return true
	case <-waitCtx.Done():
		cancel()
		<-done
		return false
	}
}

func TestSustainedRefusalDisconnects(t *testing.T) {
	s := limiterServer(t)

	if !blockedSession(t, s, mustSecret(t), messageDropBurst*2) {
		t.Fatal("a peer that ignored the message limit was never " +
			"disconnected: every message it sends costs a transport " +
			"decrypt, so refusing alone lets it waste resources forever")
	}
	if s.rateDisconnects.Load() == 0 {
		t.Fatal("disconnect was not counted")
	}
}

// TestBriefOvershootSurvives proves the budget tolerates a burst.
// The assertion is positive: it waits for the refusals to actually be
// counted before concluding the session survived them, so it cannot
// pass by the writer stalling and no refusals happening at all.
func TestBriefOvershootSurvives(t *testing.T) {
	s := limiterServer(t)
	peer := mustSecret(t)

	const msgs = messageDropBurst / 2
	done := make(chan bool, 1)
	go func() { done <- blockedSession(t, s, peer, msgs) }()

	waitForCondition(t, "the refused messages were never counted",
		10*time.Second, func() bool {
			return s.rateDropped.Load() >= msgs
		})

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	select {
	case closed := <-done:
		if closed {
			t.Fatalf("session closed after %d refusals; the budget is "+
				"%d, so a brief overshoot must be tolerated",
				msgs, messageDropBurst)
		}
	case <-ctx.Done():
		t.Fatal("blockedSession did not return")
	}
	if got := s.rateDisconnects.Load(); got != 0 {
		t.Fatalf("rate disconnects = %d, want 0", got)
	}
}

// TestRefusalBudgetIgnoresPacing is the regression for the defect
// this control replaced.
//
// The previous version counted CONSECUTIVE refusals and reset the
// count to zero on any accepted message. Because the message bucket
// admits messageRate messages per second regardless of how fast they
// arrive, one accepted message lands every 1/messageRate and cleared
// the run — so reaching N consecutive refusals required more than
// (N+1)*messageRate msgs/sec, and any rate below that sustained the
// full decrypt cost indefinitely without ever disconnecting.
//
// A budget over time closes that hole because accepted messages never
// touch it: only refusals spend tokens, and nothing refunds them. This
// drives the exact interleaving that defeated the counter — runs of
// refusals separated by accepted messages — and requires the budget to
// still run out. Driven at a fixed instant so no refill occurs.
func TestRefusalBudgetIgnoresPacing(t *testing.T) {
	drops := rate.NewLimiter(messageDropRate, messageDropBurst)
	now := time.Now()

	const run = 16
	spent := 0
	disconnected := false
	for range messageDropBurst {
		for range run {
			// A refusal spends budget.
			if !drops.AllowN(now, 1) {
				disconnected = true
				break
			}
			spent++
		}
		if disconnected {
			break
		}
		// An accepted message. Under the old scheme this reset the
		// consecutive count to zero and the peer never tripped the
		// threshold. Here it touches nothing, so the budget spent
		// so far is not refunded.
		if got := drops.TokensAt(now); got > float64(messageDropBurst-spent) {
			t.Fatalf("an accepted message refunded budget: tokens %v, "+
				"want at most %d", got, messageDropBurst-spent)
		}
	}
	if !disconnected {
		t.Fatal("a peer interleaving accepted messages between runs of " +
			"refusals never exhausted the budget: pacing defeats the " +
			"control")
	}
}

// --- metrics ---

func TestPromHandshakeRateDrops(t *testing.T) {
	s := limiterServer(t)
	if got := s.promHSRateDrops(); got != 0 {
		t.Fatalf("initial = %v, want 0", got)
	}
	s.hsRateDrops.Add(3)
	if got := s.promHSRateDrops(); got != 3 {
		t.Fatalf("= %v, want 3", got)
	}
}

func TestPromRateDisconnects(t *testing.T) {
	s := limiterServer(t)
	if got := s.promRateDisconnects(); got != 0 {
		t.Fatalf("initial = %v, want 0", got)
	}
	s.rateDisconnects.Add(2)
	if got := s.promRateDisconnects(); got != 2 {
		t.Fatalf("= %v, want 2", got)
	}
}
