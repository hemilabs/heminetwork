// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Coverage for the authenticated e2e key exchange: the binding hash,
// bindPeerKey's immutability rule, both dispatch handlers, and the
// gossip strip in each direction.
//
// The exchange exists because a node's X25519 key is derived from its
// PRIVATE secp256k1 key (NaClPrivateKey), so no recipient can compute
// or check it from a public identity.  Gossip therefore has nothing
// truthful to say about key material and never carries it; a key is
// learned only from its holder, either by handshake or by the routed
// NaClKeyRequest/NaClKeyResponse challenge-response verified here.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

// keyXchgServer builds a Server through the production constructor
// (so the exchange TTLs exist) and supplies only what Run() would
// otherwise add: an identity and the peers TTL that bindPeerKey and
// addPeer write to.  No listeners, no background loops.
func keyXchgServer(t *testing.T) *Server {
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
	s.secret, s.peersTTL = secret, peersTTL
	return s
}

// capturingTransport records payloads written through the dispatch
// context instead of sending them.  Handlers under test route their
// replies via sendTo, which needs a session; tests that only care
// about verification logic use dispatchCtx with no transport at all.
type keyXchgCtx struct {
	dc *dispatchCtx
}

// newKeyXchgCtx returns a dispatch context for s with from as the
// session peer.  ctx doubles as sessionCtx: no handler under test
// distinguishes them.
func newKeyXchgCtx(t *testing.T, s *Server, from Identity) *keyXchgCtx {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // reap TTL goroutines the handlers arm
	id := from
	return &keyXchgCtx{dc: &dispatchCtx{
		ctx:        ctx,
		sessionCtx: ctx,
		s:          s,
		id:         &id,
	}}
}

// mustNaClPub returns the X25519 public key for a secret.
func mustNaClPub(t *testing.T, s *Secret) []byte {
	t.Helper()
	pub, err := s.NaClPublicKey()
	if err != nil {
		t.Fatalf("nacl pub: %v", err)
	}
	return pub
}

// pendingChallenge registers a challenge for id exactly as
// sendNaClKeyRequest does, so response-handler tests can run without
// a live mesh.
func pendingChallenge(t *testing.T, s *Server, id Identity, challenge []byte) {
	t.Helper()
	s.naclXchg.Put(context.Background(), naclXchgTTL, string(challenge),
		id, nil, nil)
}

// signedKeyResponse builds the response the holder of secret would
// send for challenge.
func signedKeyResponse(t *testing.T, secret *Secret, challenge []byte) *NaClKeyResponse {
	t.Helper()
	naclPub := mustNaClPub(t, secret)
	return &NaClKeyResponse{
		Challenge: challenge,
		NaClPub:   naclPub,
		Signature: secret.Sign(hashNaClKeyBinding(challenge, naclPub)),
	}
}

// freshChallenge returns a distinct non-zero challenge per call.
func freshChallenge(i byte) []byte {
	c := make([]byte, ChallengeSize)
	for j := range c {
		c[j] = i + byte(j) + 1
	}
	return c
}

func TestHashNaClKeyBindingDomainSeparated(t *testing.T) {
	challenge := freshChallenge(1)
	naclPub := make([]byte, NaClPubSize)
	naclPub[0] = 0x42

	base := hashNaClKeyBinding(challenge, naclPub)
	if len(base) != 32 {
		t.Fatalf("hash length %d, want 32", len(base))
	}
	// Deterministic.
	if !bytes.Equal(base, hashNaClKeyBinding(challenge, naclPub)) {
		t.Fatal("hash is not deterministic")
	}
	// Both inputs are covered.
	other := freshChallenge(2)
	if bytes.Equal(base, hashNaClKeyBinding(other, naclPub)) {
		t.Fatal("hash ignores the challenge")
	}
	altPub := make([]byte, NaClPubSize)
	altPub[0] = 0x43
	if bytes.Equal(base, hashNaClKeyBinding(challenge, altPub)) {
		t.Fatal("hash ignores the nacl public key")
	}
	// Distinct from the handshake binding over the same material,
	// so neither signature can be replayed as the other.
	if bytes.Equal(base, Hash256([]byte("continuum-challenge-v2"), challenge, naclPub)) {
		t.Fatal("key binding collides with the handshake binding")
	}
}

func TestBindPeerKey(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()
	victim := mustSecret(t)
	victimPub := mustNaClPub(t, victim)

	t.Run("rejects self", func(t *testing.T) {
		if err := s.bindPeerKey(ctx, s.secret.Identity,
			mustNaClPub(t, s.secret)); err == nil {
			t.Fatal("bound a key for our own identity")
		}
	})

	t.Run("rejects malformed", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			key  []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", make([]byte, NaClPubSize-1)},
			{"long", make([]byte, NaClPubSize+1)},
			{"all zeros", make([]byte, NaClPubSize)},
		} {
			t.Run(tt.name, func(t *testing.T) {
				id := mustSecret(t).Identity
				if err := s.bindPeerKey(ctx, id, tt.key); err == nil {
					t.Fatal("accepted a malformed e2e key")
				}
				if _, ok := s.peerNaClPub(id); ok {
					t.Fatal("malformed key was stored")
				}
			})
		}
	})

	t.Run("binds and creates a record", func(t *testing.T) {
		if err := s.bindPeerKey(ctx, victim.Identity, victimPub); err != nil {
			t.Fatalf("bindPeerKey: %v", err)
		}
		got, ok := s.peerNaClPub(victim.Identity)
		if !ok {
			t.Fatal("no key bound")
		}
		if !bytes.Equal(got, victimPub) {
			t.Fatalf("bound %x, want %x", got, victimPub)
		}
	})

	t.Run("stores a copy", func(t *testing.T) {
		mutable := append([]byte(nil), victimPub...)
		id := mustSecret(t).Identity
		if err := s.bindPeerKey(ctx, id, mutable); err != nil {
			t.Fatalf("bindPeerKey: %v", err)
		}
		mutable[0] ^= 0xFF
		got, _ := s.peerNaClPub(id)
		if bytes.Equal(got, mutable) {
			t.Fatal("bindPeerKey aliased the caller's buffer")
		}
	})

	t.Run("idempotent for the same key", func(t *testing.T) {
		before := s.keyConflicts.Load()
		if err := s.bindPeerKey(ctx, victim.Identity, victimPub); err != nil {
			t.Fatalf("re-binding the same key failed: %v", err)
		}
		if got := s.keyConflicts.Load(); got != before {
			t.Fatalf("same-key re-bind counted as a conflict: %d -> %d",
				before, got)
		}
	})

	t.Run("immutable against a conflicting key", func(t *testing.T) {
		attackerPub := mustNaClPub(t, mustSecret(t))
		before := s.keyConflicts.Load()
		if err := s.bindPeerKey(ctx, victim.Identity, attackerPub); err == nil {
			t.Fatal("accepted a conflicting e2e key for a bound identity")
		}
		got, _ := s.peerNaClPub(victim.Identity)
		if !bytes.Equal(got, victimPub) {
			t.Fatalf("conflicting bind mutated the stored key: %x", got)
		}
		// The derivation is deterministic, so a conflict is
		// always an attack or a broken peer: it must be counted.
		if got := s.keyConflicts.Load(); got != before+1 {
			t.Fatalf("conflict counter %d, want %d", got, before+1)
		}
	})
}

func TestHandleNaClKeyRequestRejects(t *testing.T) {
	valid := freshChallenge(7)
	tests := []struct {
		name string
		req  *NaClKeyRequest
		self bool // set Requester to the server's own identity
	}{
		{name: "short challenge", req: &NaClKeyRequest{
			Challenge: make([]byte, ChallengeSize-1),
		}},
		{name: "long challenge", req: &NaClKeyRequest{
			Challenge: make([]byte, ChallengeSize+1),
		}},
		{name: "nil challenge", req: &NaClKeyRequest{}},
		{name: "zero challenge", req: &NaClKeyRequest{
			Challenge: make([]byte, ChallengeSize),
		}},
		{name: "self requester", req: &NaClKeyRequest{
			Challenge: valid,
		}, self: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := keyXchgServer(t)
			req := *tt.req
			if tt.self {
				req.Requester = s.secret.Identity
			} else {
				req.Requester = mustSecret(t).Identity
			}
			k := newKeyXchgCtx(t, s, req.Requester)

			before := s.naclXchgDrops.Load()
			if handleNaClKeyRequest(k.dc, &req) {
				t.Fatal("handler asked to close the session")
			}
			if got := s.naclXchgDrops.Load(); got != before+1 {
				t.Fatalf("drop counter %d, want %d", got, before+1)
			}
		})
	}
}

// TestHandleNaClKeyRequestRateLimited proves the responder signs at
// most once per requester per window, bounding the signing work an
// unauthenticated flood can extract.
func TestHandleNaClKeyRequestRateLimited(t *testing.T) {
	s := keyXchgServer(t)
	requester := mustSecret(t).Identity
	k := newKeyXchgCtx(t, s, requester)

	// First request is answered.  sendTo fails (no session) but
	// that is after the rate window is claimed, which is what we
	// are asserting on.
	handleNaClKeyRequest(k.dc, &NaClKeyRequest{
		Requester: requester,
		Challenge: freshChallenge(1),
	})
	before := s.naclXchgDrops.Load()

	// Second request inside the window is dropped.
	handleNaClKeyRequest(k.dc, &NaClKeyRequest{
		Requester: requester,
		Challenge: freshChallenge(2),
	})
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("second request was not rate limited: drops %d, want %d",
			got, before+1)
	}

	// A different requester is unaffected — the limit is per
	// requester, not global.
	other := mustSecret(t).Identity
	ok := newKeyXchgCtx(t, s, other)
	before = s.naclXchgDrops.Load()
	handleNaClKeyRequest(ok.dc, &NaClKeyRequest{
		Requester: other,
		Challenge: freshChallenge(3),
	})
	if got := s.naclXchgDrops.Load(); got != before {
		t.Fatalf("a distinct requester was rate limited: drops %d, want %d",
			got, before)
	}
}

// TestHandleNaClKeyResponseBinds is the happy path: a response that
// verifies against the identity the challenge was issued for binds the
// key and consumes the challenge.
func TestHandleNaClKeyResponseBinds(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	challenge := freshChallenge(11)
	pendingChallenge(t, s, peer.Identity, challenge)
	k := newKeyXchgCtx(t, s, peer.Identity)

	if handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, challenge)) {
		t.Fatal("handler asked to close the session")
	}
	got, ok := s.peerNaClPub(peer.Identity)
	if !ok {
		t.Fatal("verified response did not bind a key")
	}
	if !bytes.Equal(got, mustNaClPub(t, peer)) {
		t.Fatalf("bound %x, want %x", got, mustNaClPub(t, peer))
	}
	// The challenge is single-use: replaying the same response
	// finds no pending exchange.
	before := s.naclXchgDrops.Load()
	handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, challenge))
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("challenge was not consumed: drops %d, want %d",
			got, before+1)
	}
}

func TestHandleNaClKeyResponseRejects(t *testing.T) {
	peer := mustSecret(t)
	attacker := mustSecret(t)
	challenge := freshChallenge(21)

	tests := []struct {
		name string
		// build returns the response to feed and whether to
		// register challenge as pending for peer first.
		build   func(t *testing.T, s *Server) *NaClKeyResponse
		pending bool
	}{
		{
			name:    "short challenge",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.Challenge = challenge[:ChallengeSize-1]
				return r
			},
		},
		{
			name:    "short nacl pub",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.NaClPub = r.NaClPub[:NaClPubSize-1]
				return r
			},
		},
		{
			// Unsolicited: nothing pending for this challenge.
			name:    "no pending challenge",
			pending: false,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				return signedKeyResponse(t, peer, challenge)
			},
		},
		{
			// Right challenge, but signed by someone else: the
			// recovered identity does not match the identity the
			// challenge was issued for.
			name:    "signed by another identity",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				return signedKeyResponse(t, attacker, challenge)
			},
		},
		{
			// The core substitution attack: keep the victim's
			// signature but swap in the attacker's key.  The hash
			// is recomputed from the received key, so recovery
			// yields a different identity and fails.
			name:    "attacker key with victim signature",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.NaClPub = mustNaClPub(t, attacker)
				return r
			},
		},
		{
			name:    "garbage signature",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.Signature = make([]byte, len(r.Signature))
				return r
			},
		},
		{
			name:    "empty signature",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.Signature = nil
				return r
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := keyXchgServer(t)
			if tt.pending {
				pendingChallenge(t, s, peer.Identity, challenge)
			}
			k := newKeyXchgCtx(t, s, peer.Identity)

			before := s.naclXchgDrops.Load()
			if handleNaClKeyResponse(k.dc, tt.build(t, s)) {
				t.Fatal("handler asked to close the session")
			}
			if _, ok := s.peerNaClPub(peer.Identity); ok {
				t.Fatal("a rejected response bound a key")
			}
			if _, ok := s.peerNaClPub(attacker.Identity); ok {
				t.Fatal("a rejected response bound a key for the attacker")
			}
			if got := s.naclXchgDrops.Load(); got != before+1 {
				t.Fatalf("drop counter %d, want %d", got, before+1)
			}
		})
	}
}

// TestNaClKeyResponseDoesNotBurnPendingOnFailure proves a forged
// response cannot deny service by consuming the pending challenge: the
// legitimate response still binds afterwards.
func TestNaClKeyResponseDoesNotBurnPendingOnFailure(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	attacker := mustSecret(t)
	challenge := freshChallenge(31)
	pendingChallenge(t, s, peer.Identity, challenge)
	k := newKeyXchgCtx(t, s, peer.Identity)

	// Forged response for the outstanding challenge.
	handleNaClKeyResponse(k.dc, signedKeyResponse(t, attacker, challenge))
	if _, ok := s.peerNaClPub(peer.Identity); ok {
		t.Fatal("forged response bound a key")
	}

	// The real one still works.
	handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, challenge))
	got, ok := s.peerNaClPub(peer.Identity)
	if !ok {
		t.Fatal("a forged response burned the pending challenge")
	}
	if !bytes.Equal(got, mustNaClPub(t, peer)) {
		t.Fatalf("bound %x, want %x", got, mustNaClPub(t, peer))
	}
}

// TestNaClKeyResponseCannotRebind proves the exchange cannot be used
// to overwrite a key already established by a handshake — the
// vulnerability's overwrite case, now closed at the binding layer.
func TestNaClKeyResponseCannotRebind(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	peerPub := mustNaClPub(t, peer)

	// A completed handshake bound the real key.
	if err := s.bindPeerKey(t.Context(), peer.Identity, peerPub); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}

	// An attacker who somehow answers a pending challenge for that
	// identity still cannot replace the key: only the identity
	// holder can produce a verifying response, and even that is a
	// no-op re-bind of the same key.
	challenge := freshChallenge(41)
	pendingChallenge(t, s, peer.Identity, challenge)
	k := newKeyXchgCtx(t, s, peer.Identity)
	handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, challenge))

	got, _ := s.peerNaClPub(peer.Identity)
	if !bytes.Equal(got, peerPub) {
		t.Fatalf("key changed after re-exchange: got %x want %x", got, peerPub)
	}
}

// TestGossipCarriesNoKeyMaterial proves the strip in both directions:
// keys never leave in knownPeerList and never enter through the real
// gossip dispatch handler.
func TestGossipCarriesNoKeyMaterial(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()
	peer := mustSecret(t)
	peerPub := mustNaClPub(t, peer)
	selfPub := mustNaClPub(t, s.secret)

	// Self record, as registerSelfAsPeer writes it, plus a peer
	// with an authenticated binding.
	s.mtx.Lock()
	s.peers[s.secret.Identity] = &PeerRecord{
		Identity: s.secret.Identity,
		Address:  "10.0.0.1:9000",
		NaClPub:  selfPub,
		Version:  ProtocolVersion,
	}
	s.mtx.Unlock()
	if err := s.bindPeerKey(ctx, peer.Identity, peerPub); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}

	t.Run("outbound", func(t *testing.T) {
		for _, rec := range s.knownPeerList(Identity{}) {
			if len(rec.NaClPub) != 0 {
				t.Fatalf("gossip record for %v carries key material %x",
					rec.Identity, rec.NaClPub)
			}
		}
	})

	t.Run("inbound", func(t *testing.T) {
		// An attacker gossips a poisoned binding for a victim
		// it has no key for, and for one it does.
		victim := mustSecret(t).Identity
		attackerPub := mustNaClPub(t, mustSecret(t))
		attacker := mustSecret(t).Identity
		k := newKeyXchgCtx(t, s, attacker)

		handlePeerListResponse(k.dc, &PeerListResponse{Peers: []PeerRecord{
			{
				Identity: victim,
				Address:  "10.0.0.2:9000",
				NaClPub:  attackerPub,
				Version:  ProtocolVersion,
			},
			{
				Identity: peer.Identity,
				Address:  "10.0.0.3:9000",
				NaClPub:  attackerPub,
				Version:  ProtocolVersion,
			},
		}})

		// First binding: discovery landed, key did not.
		if _, ok := s.peerNaClPub(victim); ok {
			t.Fatal("gossip installed a first e2e key binding")
		}
		s.mtx.RLock()
		vr, known := s.peers[victim]
		s.mtx.RUnlock()
		if !known || vr.Address != "10.0.0.2:9000" {
			t.Fatal("gossip failed to record discovery metadata")
		}

		// Overwrite: the authenticated binding survived intact.
		got, ok := s.peerNaClPub(peer.Identity)
		if !ok {
			t.Fatal("gossip dropped an authenticated binding")
		}
		if !bytes.Equal(got, peerPub) {
			t.Fatalf("gossip overwrote an authenticated binding: %x", got)
		}
	})
}

// TestEnsurePeerKeyShortCircuits covers the paths that return without
// any mesh traffic: self, and an identity whose key is already bound.
func TestEnsurePeerKeyShortCircuits(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()

	if err := s.ensurePeerKey(ctx, s.secret.Identity); err != nil {
		t.Fatalf("ensurePeerKey(self): %v", err)
	}
	peer := mustSecret(t)
	if err := s.bindPeerKey(ctx, peer.Identity, mustNaClPub(t, peer)); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}
	if err := s.ensurePeerKey(ctx, peer.Identity); err != nil {
		t.Fatalf("ensurePeerKey(bound): %v", err)
	}
	// Both short circuits also satisfy the plural form.
	if err := s.ensurePeerKeys(ctx, []Identity{s.secret.Identity, peer.Identity}); err != nil {
		t.Fatalf("ensurePeerKeys: %v", err)
	}
}

// TestEnsurePeerKeyTimesOut proves the wait is bounded when no peer
// ever answers, and that ensurePeerKeys propagates the failure.
func TestEnsurePeerKeyTimesOut(t *testing.T) {
	s := keyXchgServer(t)
	unreachable := mustSecret(t).Identity

	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	if err := s.ensurePeerKey(ctx, unreachable); err == nil {
		t.Fatal("ensurePeerKey returned success with no response")
	}

	ctx2, cancel2 := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel2()
	if err := s.ensurePeerKeys(ctx2, []Identity{unreachable}); err == nil {
		t.Fatal("ensurePeerKeys returned success with no response")
	}
}

// TestNaClKeyResponseCannotBindSelf proves the response handler cannot
// be steered into binding our own identity, even for a pending
// challenge that names it and a response that verifies: bindPeerKey
// refuses self and the peer table stays clean.
func TestNaClKeyResponseCannotBindSelf(t *testing.T) {
	s := keyXchgServer(t)
	challenge := freshChallenge(81)
	pendingChallenge(t, s, s.secret.Identity, challenge)
	k := newKeyXchgCtx(t, s, mustSecret(t).Identity)

	if handleNaClKeyResponse(k.dc, signedKeyResponse(t, s.secret, challenge)) {
		t.Fatal("handler asked to close the session")
	}
	if _, ok := s.peerNaClPub(s.secret.Identity); ok {
		t.Fatal("the exchange bound a key for our own identity")
	}
	s.mtx.RLock()
	_, tracked := s.peers[s.secret.Identity]
	s.mtx.RUnlock()
	if tracked {
		t.Fatal("the exchange added a peer record for our own identity")
	}
}

// TestEnsurePeerKeyRetries proves the retry ticker re-sends while
// waiting, each time with a fresh challenge, so a lost request or a
// route that only appears later still converges.
//
// Pending challenges are observed DURING the wait: they are registered
// against the caller's context, so they are reaped as soon as
// ensurePeerKey returns.
func TestEnsurePeerKeyRetries(t *testing.T) {
	s := keyXchgServer(t)
	unreachable := mustSecret(t).Identity

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.ensurePeerKey(ctx, unreachable) }()

	// Initial request plus at least one retry, each registering its
	// own pending challenge.
	waitForCondition(t, "retry did not issue a fresh challenge",
		naclXchgRetry*3, func() bool {
			return s.naclXchg.Len() >= 2
		})

	cancel()
	exitCtx, exitCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer exitCancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ensurePeerKey returned success with no response")
		}
	case <-exitCtx.Done():
		t.Fatal("ensurePeerKey did not return after cancellation")
	}
}

// TestPeerKeyPromCounters covers the exported telemetry for the two
// conditions operators care about: a rejected rebind attempt, which is
// always hostile, and dropped exchange traffic.
func TestPeerKeyPromCounters(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()

	if got := s.promKeyConflicts(); got != 0 {
		t.Fatalf("initial key conflicts = %v, want 0", got)
	}
	if got := s.promNaClXchgDrops(); got != 0 {
		t.Fatalf("initial xchg drops = %v, want 0", got)
	}

	peer := mustSecret(t)
	if err := s.bindPeerKey(ctx, peer.Identity, mustNaClPub(t, peer)); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}
	if err := s.bindPeerKey(ctx, peer.Identity,
		mustNaClPub(t, mustSecret(t))); err == nil {
		t.Fatal("accepted a conflicting key")
	}
	if got := s.promKeyConflicts(); got != 1 {
		t.Fatalf("key conflicts = %v, want 1", got)
	}

	k := newKeyXchgCtx(t, s, mustSecret(t).Identity)
	handleNaClKeyResponse(k.dc, &NaClKeyResponse{}) // malformed
	if got := s.promNaClXchgDrops(); got != 1 {
		t.Fatalf("xchg drops = %v, want 1", got)
	}
}

// TestEnsurePeerKeyObservesConcurrentBind proves the poll path: a key
// bound by any other route (an inbound handshake, a concurrent
// exchange) satisfies a waiter.
func TestEnsurePeerKeyObservesConcurrentBind(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	peerPub := mustNaClPub(t, peer)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.ensurePeerKey(ctx, peer.Identity) }()

	// Bind out from under the waiter, as a handshake would.
	time.Sleep(naclXchgPoll)
	if err := s.bindPeerKey(ctx, peer.Identity, peerPub); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ensurePeerKey did not observe the binding: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("ensurePeerKey did not return after the key was bound")
	}
}

// TestSendNaClKeyRequestRegistersPending proves the challenge is
// registered before the send (so a fast response cannot lose the
// race), maps to the identity we asked about, and is fresh per call.
func TestSendNaClKeyRequestRegistersPending(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)

	// No session and no route: the send fails, but the pending
	// challenge must already be recorded.
	if err := s.sendNaClKeyRequest(t.Context(), peer.Identity); err == nil {
		t.Fatal("expected a send failure with no route")
	}
	if got := s.naclXchg.Len(); got != 1 {
		t.Fatalf("pending challenges = %d, want 1", got)
	}
	// The single pending entry maps to the peer we asked about, so
	// only that identity's signature can satisfy it.
	if n := s.naclXchg.DeleteByValue(func(v any) bool {
		id, ok := v.(Identity)
		return ok && id == peer.Identity
	}); n != 1 {
		t.Fatalf("pending entry for %v not found (removed %d)", peer.Identity, n)
	}

	// Each call uses a fresh challenge: two requests for the same
	// peer leave two distinct pending entries.
	_ = s.sendNaClKeyRequest(t.Context(), peer.Identity)
	_ = s.sendNaClKeyRequest(t.Context(), peer.Identity)
	if got := s.naclXchg.Len(); got != 2 {
		t.Fatalf("pending challenges = %d after two requests, want 2 "+
			"(challenges must be fresh per request)", got)
	}
}

// TestSendNaClKeyRequestUninitialized covers the guard for servers
// built by hand in tests rather than through NewServer.
func TestSendNaClKeyRequestUninitialized(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
	}
	if err := s.sendNaClKeyRequest(t.Context(), mustSecret(t).Identity); err == nil {
		t.Fatal("expected an error with uninitialized exchange state")
	}
}

// TestHandleNaClKeyResponseUninitialized covers the same guard on the
// response path.
func TestHandleNaClKeyResponseUninitialized(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
	}
	peer := mustSecret(t)
	k := newKeyXchgCtx(t, s, peer.Identity)

	before := s.naclXchgDrops.Load()
	if handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, freshChallenge(61))) {
		t.Fatal("handler asked to close the session")
	}
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("drop counter %d, want %d", got, before+1)
	}
}

// TestHandleNaClKeyRequestUninitializedRates proves the rate-limiter
// guard degrades to answering rather than crashing on a hand-built
// server.
func TestHandleNaClKeyRequestUninitializedRates(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
	}
	requester := mustSecret(t).Identity
	k := newKeyXchgCtx(t, s, requester)

	before := s.naclXchgDrops.Load()
	if handleNaClKeyRequest(k.dc, &NaClKeyRequest{
		Requester: requester,
		Challenge: freshChallenge(71),
	}) {
		t.Fatal("handler asked to close the session")
	}
	// Reached the send (which fails, no route) rather than being
	// dropped by a nil map dereference.
	if got := s.naclXchgDrops.Load(); got != before {
		t.Fatalf("request was dropped: drops %d, want %d", got, before)
	}
}

// TestNaClKeyRequestSelfGuardIndependentOfSession proves the self
// guard keys off the Requester field, not the session peer: a peer
// reflecting our own identity into Requester is refused.
func TestNaClKeyRequestSelfGuardIndependentOfSession(t *testing.T) {
	s := keyXchgServer(t)
	other := mustSecret(t).Identity
	k := newKeyXchgCtx(t, s, other) // session is a normal peer

	before := s.naclXchgDrops.Load()
	handleNaClKeyRequest(k.dc, &NaClKeyRequest{
		Requester: s.secret.Identity, // ...but the reply target is us
		Challenge: freshChallenge(51),
	})
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("self-targeted request was not dropped: drops %d, want %d",
			got, before+1)
	}
}
