// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Coverage for the per-identity message rate limiter.
//
// The limiter is keyed on peer Identity and outlives any single
// session.  A per-session limiter let a peer spend its whole burst,
// drop the connection, reconnect, and get a fresh one, which makes the
// sustained rate unbounded no matter how the per-session numbers are
// tuned.  Identity is proven by the handshake before handle() runs, so
// it cannot be spoofed to dodge an exhausted bucket.

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

// limiterServer builds a Server through the production constructor so
// the limiter map exists, without starting listeners or loops.
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
	s.secret = secret
	return s
}

// drain consumes tokens until the limiter refuses, returning how many
// it allowed.  Bounded so a broken limiter cannot spin forever.
func drain(t *testing.T, l *rate.Limiter) int {
	t.Helper()
	const bound = messageBurst * 10
	for i := range bound {
		if !l.Allow() {
			return i
		}
	}
	t.Fatalf("limiter allowed %d messages without refusing", bound)
	return 0
}

func TestPeerLimiterSurvivesReconnect(t *testing.T) {
	s := limiterServer(t)
	peer := mustSecret(t).Identity

	// First session: spend the whole burst.
	if got := drain(t, s.peerLimiter(peer)); got == 0 {
		t.Fatal("limiter refused the very first message")
	}

	// Reconnect: handle() asks for the limiter again for the same
	// identity.  It must be the exhausted one, not a fresh bucket.
	if s.peerLimiter(peer).Allow() {
		t.Fatal("reconnecting refilled the burst budget: a peer can " +
			"spend its burst, drop the connection, and immediately " +
			"reconnect for another one")
	}
}

func TestPeerLimiterIsPerIdentity(t *testing.T) {
	s := limiterServer(t)
	noisy := mustSecret(t).Identity
	quiet := mustSecret(t).Identity

	drain(t, s.peerLimiter(noisy))

	// One peer exhausting its bucket must not throttle another.
	if !s.peerLimiter(quiet).Allow() {
		t.Fatal("a different identity was throttled by the noisy peer")
	}
	// ...and the noisy one stays exhausted.
	if s.peerLimiter(noisy).Allow() {
		t.Fatal("the exhausted identity was refilled")
	}
}

func TestPeerLimiterStableIdentity(t *testing.T) {
	s := limiterServer(t)
	peer := mustSecret(t).Identity

	// Repeated lookups return the same limiter rather than
	// replacing it, which is what makes the budget cumulative.
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

// TestPeerLimiterEvictedOnPeerExpiry proves the map is bounded by the
// peer table rather than by connection attempts: when a peer record
// expires the limiter goes with it.
func TestPeerLimiterEvictedOnPeerExpiry(t *testing.T) {
	s := limiterServer(t)
	peer := mustSecret(t).Identity

	drain(t, s.peerLimiter(peer))
	s.limiterMtx.Lock()
	n := len(s.limiters)
	s.limiterMtx.Unlock()
	if n != 1 {
		t.Fatalf("limiters = %d, want 1", n)
	}

	// peerExpired fires after the peer has been silent for peerTTL,
	// far longer than the bucket needs to refill, so dropping it
	// forgives nothing time had not already restored.
	s.peerExpired(t.Context(), peer, nil)

	s.limiterMtx.Lock()
	n = len(s.limiters)
	s.limiterMtx.Unlock()
	if n != 0 {
		t.Fatalf("limiters = %d after expiry, want 0", n)
	}
	if !s.peerLimiter(peer).Allow() {
		t.Fatal("limiter was not recreated after expiry")
	}
}

// TestPeerExpiredBadKeyType covers the type guard on the TTL callback.
func TestPeerExpiredBadKeyType(t *testing.T) {
	s := limiterServer(t)
	s.peerExpired(t.Context(), "not-an-identity", nil)

	s.limiterMtx.Lock()
	n := len(s.limiters)
	s.limiterMtx.Unlock()
	if n != 0 {
		t.Fatalf("limiters = %d, want 0", n)
	}
}

// --- per-IP handshake attempt limiting ---
//
// handshakeSem caps how many handshakes run CONCURRENTLY but says
// nothing about how fast they may be started, and a slot is held for
// up to handshakeTimeout while KX runs.  One IP opening connections it
// never completes could therefore keep every slot occupied and starve
// legitimate peers.  handshakeAllowed refuses that flood in the accept
// loop, before a slot is ever taken.

// tcpAddr builds a *net.TCPAddr for an IP literal.
func tcpAddr(t *testing.T, ip string, port int) *net.TCPAddr {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("bad test ip %q", ip)
	}
	return &net.TCPAddr{IP: parsed, Port: port}
}

func TestHandshakeAllowedThrottlesOneIP(t *testing.T) {
	s := limiterServer(t)
	addr := tcpAddr(t, "10.0.0.1", 40000)

	// The burst is what a legitimate peer may use for reconnects.
	for i := range handshakeBurst {
		if !s.handshakeAllowed(addr) {
			t.Fatalf("attempt %d refused inside the burst", i)
		}
	}
	// Past it the flood is refused, without ever taking a
	// handshakeSem slot.
	if s.handshakeAllowed(addr) {
		t.Fatal("an IP exceeded its handshake burst without being " +
			"refused: it can hold every semaphore slot and starve " +
			"legitimate peers")
	}
}

func TestHandshakeAllowedIsPerIP(t *testing.T) {
	s := limiterServer(t)
	flooder := tcpAddr(t, "10.0.0.1", 40000)
	honest := tcpAddr(t, "10.0.0.2", 40000)

	for range handshakeBurst {
		s.handshakeAllowed(flooder)
	}
	if s.handshakeAllowed(flooder) {
		t.Fatal("flooder was not throttled")
	}

	// A different IP is unaffected: this is the starvation the fix
	// exists to prevent.
	if !s.handshakeAllowed(honest) {
		t.Fatal("an unrelated IP was starved by the flooder")
	}

	// Source port must not matter — an attacker gets a new one per
	// connection for free.
	if s.handshakeAllowed(tcpAddr(t, "10.0.0.1", 40001)) {
		t.Fatal("changing source port reset the limit")
	}
}

// TestHandshakeAllowedNonTCPAddr covers the guard for listeners that
// do not yield TCP addresses (test injection): there is no IP to key
// on, and handshakeSem still bounds concurrency.
func TestHandshakeAllowedNonTCPAddr(t *testing.T) {
	s := limiterServer(t)
	addr := &net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"}
	for range handshakeBurst * 2 {
		if !s.handshakeAllowed(addr) {
			t.Fatal("non-TCP address was rate limited")
		}
	}
}

// TestHandshakeRateTableBounded proves the limiter table cannot itself
// be grown without bound by connections from fresh IPs.
func TestHandshakeRateTableBounded(t *testing.T) {
	s := limiterServer(t)

	// Walk past the cap using distinct IPs.
	for i := range handshakeRateCap + 16 {
		//nolint:gosec // deterministic test octets, no overflow concern
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		s.handshakeAllowed(&net.TCPAddr{IP: ip, Port: 40000})
	}

	s.handshakeRateMtx.Lock()
	n := len(s.handshakeRates)
	s.handshakeRateMtx.Unlock()
	if n > handshakeRateCap {
		t.Fatalf("handshake limiter table = %d entries, cap is %d",
			n, handshakeRateCap)
	}
}

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

// TestAcceptLoopEnforcesHandshakeRate proves the accept loop actually
// applies handshakeAllowed.  The unit tests above exercise the helper
// directly and pass even if nothing calls it, so this drives the real
// listener: a burst of raw TCP connections from one IP that never
// complete KX must start being refused.
func TestAcceptLoopEnforcesHandshakeRate(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()
	addr := waitForListenAddress(t, s, 5*time.Second)

	// Open well past the burst without ever speaking the protocol,
	// which is exactly the starvation attack: every one of these
	// would otherwise hold a handshakeSem slot for handshakeTimeout.
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			c.Close()
		}
	})
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	for range handshakeBurst * 3 {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			break // refused at the OS level is also a rejection
		}
		conns = append(conns, c)
	}

	waitForCondition(t, "accept loop never rate limited a flood of "+
		"unauthenticated connections from one IP",
		10*time.Second, func() bool {
			return s.hsRateDrops.Load() > 0
		})

	cancel()
	select {
	case <-errCh:
	case <-time.After(30 * time.Second):
		t.Fatal("server did not shut down")
	}
}

// --- disconnect on sustained rate abuse ---
//
// Dropping a rate-limited message is not by itself a defence: by the
// time the limiter sees it, ReadEnvelope has already paid the
// transport decrypt.  A peer that ignores the limit imposes that cost
// on every message, forever, for free.  handle() therefore closes the
// session after messageDropLimit CONSECUTIVE drops, which also forces
// the peer back through the per-IP handshake limiter.

// blockedSession drives handle() against a peer whose limiter refuses
// everything, then writes msgs messages.  It reports whether handle()
// closed the session.
//
// The limiter is pinned to refuse rather than being outrun in real
// time: a test that floods and hopes to beat the refill rate is a race
// against machine speed and fails under load.  Pinning it makes the
// drop count exactly the message count, so the threshold behaviour is
// deterministic.
func blockedSession(t *testing.T, s *Server, peer *Secret, msgs int) bool {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// rate 0, burst 0: Allow() is always false.
	s.limiterMtx.Lock()
	if s.limiters == nil {
		s.limiters = make(map[Identity]*rate.Limiter)
	}
	s.limiters[peer.Identity] = rate.NewLimiter(0, 0)
	s.limiterMtx.Unlock()

	// Real TCP, not net.Pipe: the pipe is unbuffered, so every
	// write blocks for a reader and nothing can be staged.
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

	// Drain whatever handle() sends (initial gossip, pings) so its
	// writes cannot block and stall the read loop under test.
	go func() {
		for {
			if _, _, _, err := cli.read(readTimeout); err != nil {
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
			break
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

// rateTestServer is a limiterServer with the TTLs handle() touches.
func rateTestServer(t *testing.T) *Server {
	t.Helper()
	s := limiterServer(t)
	peersTTL, err := ttl.New(16, true)
	if err != nil {
		t.Fatal(err)
	}
	pings, err := ttl.New(16, true)
	if err != nil {
		t.Fatal(err)
	}
	s.peersTTL, s.pings = peersTTL, pings
	return s
}

func TestSustainedRateAbuseDisconnects(t *testing.T) {
	s := rateTestServer(t)

	// Every message is refused, so this is comfortably past the
	// consecutive-drop threshold.
	if !blockedSession(t, s, mustSecret(t), messageDropLimit*2) {
		t.Fatal("a peer that ignored the rate limit was never " +
			"disconnected: every message it sends costs a transport " +
			"decrypt, so dropping alone lets it waste resources forever")
	}
	if s.rateDisconnects.Load() == 0 {
		t.Fatal("disconnect was not counted")
	}
}

// TestDisconnectRespectsThreshold proves a session is not closed on the
// first refusal: a peer must sustain more than messageDropLimit
// consecutive drops, so a brief overshoot is tolerated.
func TestDisconnectRespectsThreshold(t *testing.T) {
	s := rateTestServer(t)

	// Exactly at the limit, never past it: the session must survive.
	if blockedSession(t, s, mustSecret(t), messageDropLimit) {
		t.Fatalf("session closed after %d drops; the threshold is "+
			"more than %d, so a brief overshoot must be tolerated",
			messageDropLimit, messageDropLimit)
	}
	if got := s.rateDisconnects.Load(); got != 0 {
		t.Fatalf("rate disconnects = %d, want 0", got)
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

// TestLimitersLazyInit covers servers built by hand rather than
// through NewServer, which have no limiter maps.  handle() calls
// peerLimiter on every session, so a nil map there is a panic in the
// hot path.
func TestLimitersLazyInit(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{secret: secret}

	if l := s.peerLimiter(mustSecret(t).Identity); l == nil {
		t.Fatal("peerLimiter returned nil on a hand-built server")
	}
	if !s.handshakeAllowed(tcpAddr(t, "10.0.0.9", 40000)) {
		t.Fatal("handshakeAllowed refused the first attempt on a " +
			"hand-built server")
	}
}
