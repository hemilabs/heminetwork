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
	"testing"

	"golang.org/x/time/rate"
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
