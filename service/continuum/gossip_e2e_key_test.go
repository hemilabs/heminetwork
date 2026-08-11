// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression suite: the end-to-end (X25519) peer key is unauthenticated.
//
// A node's NaClPub is derived from its PRIVATE key (X25519 of
// SHA256("continuum-x25519-v1" || secp256k1 privkey)), so it cannot be
// recomputed from a peer's public identity -- nothing lets a recipient verify
// that a gossiped NaClPub actually belongs to the identity it is attached to.
// PeerRecord carries no signature and addPeer stores s.peers[pr.Identity] = &pr
// after only structural checks (version, NaClPub length, non-zero, not-self), so
// an unsigned gossiped record can install -- or overwrite -- the key a node uses
// to seal point-to-point traffic in SendEncrypted (SealBox to s.peers[dest].NaClPub).
//
// Consequence: one connected peer can gossip a PeerListResponse binding a
// victim's identity to the ATTACKER's X25519 key; every recipient then encrypts
// the victim's confidential ceremony share material to a key the attacker holds
// (and can OpenBox), while the victim cannot.
//
// This file is the tight unit anchor: it drives addPeer -- the exact sink both
// the gossip handler and the authenticated handshake feed every record into --
// with the byte-for-byte record an attacker gossips. The companion
// gossip_e2e_key_integration_test.go proves the same defect through the real
// handlePeerListResponse dispatch handler.
//
// Fix-consistency (why the legit key is installed directly, not via addPeer):
// the correct remediation is a SIGNED PeerRecord that addPeer verifies with
// the sender's secp256k1 key. Under that fix, feeding the victim's LEGITIMATE
// bootstrap record through addPeer would be rejected too (it is unsigned), and
// this committed test cannot sign it -- the Signature field does not exist yet.
// So the already-authenticated key is installed DIRECTLY into the peer table
// (installPeerFromHandshake) -- modeling the state a completed handshake or a
// correctly signed record leaves behind -- and ONLY the attacker's gossip poison
// exercises addPeer. That keeps the suite green under the correct signed-record
// fix AND under a weaker refuse-overwrite fix, while first-binding still fails
// under refuse-overwrite alone, pinning the stronger remediation.
//
// Cases:
//   - overwrite-handshake-key: target already holds the victim's REAL key (from
//     a completed authenticated handshake); unsigned gossip then tries to rebind
//     that identity to the attacker's key. A correct fix must retain the real key.
//   - first-binding: no prior handshake; the poison is the FIRST thing the target
//     learns for the victim. Passes only under the signed-record fix.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"testing"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

// newPeerKeyServer builds a Server via the production constructor and adds only
// what Run() would otherwise supply: an identity secret and the peers TTL that
// addPeer writes to. It is deliberately not Run(), so there are no listeners or
// background loops beyond the per-record TTL goroutines addPeer schedules, which
// are reaped when the caller cancels the context it passes to addPeer.
func newPeerKeyServer(t *testing.T) *Server {
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

// naclIdentity returns a fresh identity together with its derived X25519 public
// key bytes (what peers store and seal to) and private key (what only the holder
// can decrypt with). It returns the Identity, not the Secret: victim and attacker
// are only ever recipients here, never senders, so their private key is all the
// crypto legs need beyond the identity.
func naclIdentity(t *testing.T) (Identity, []byte, *ecdh.PrivateKey) {
	t.Helper()
	s, err := NewSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	pub, err := s.NaClPublicKey()
	if err != nil {
		t.Fatalf("nacl pub: %v", err)
	}
	priv, err := s.NaClPrivateKey()
	if err != nil {
		t.Fatalf("nacl priv: %v", err)
	}
	return s.Identity, pub, priv
}

// peerRec builds a well-formed, current-version PeerRecord binding id to naclPub.
// It sets only fields that exist today; this is precisely the attacker's gossiped
// record, and once a signed-record fix adds a Signature field its signature is
// the zero value -- which addPeer's verification then rejects.
func peerRec(id Identity, naclPub []byte, addr string) PeerRecord {
	return PeerRecord{
		Identity: id,
		NaClPub:  naclPub,
		Version:  ProtocolVersion,
		Address:  addr,
	}
}

// installPeerFromHandshake writes a peer record straight into the table under
// s.mtx, WITHOUT routing it through addPeer. It models the record a completed,
// authenticated handshake (or a correctly signed gossip record) leaves behind.
// addPeer is the unauthenticated sink under test; sending the legitimate
// bootstrap through it would make the suite depend on addPeer accepting an
// UNSIGNED record, which the correct signed-record fix stops doing. Installing
// directly keeps the legitimate key out of the sink so only the attacker's
// gossip exercises it.
func installPeerFromHandshake(s *Server, pr PeerRecord) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	rec := pr
	s.peers[pr.Identity] = &rec
}

// storedPeerNaClPub returns the X25519 key the server currently holds for id --
// exactly the key SendEncrypted would seal to -- and whether any record is held.
// It does NOT fail on absence: a correct fix that rejects an unauthenticated
// first binding legitimately leaves no record, which the caller treats as the
// invariant being satisfied.
func storedPeerNaClPub(t *testing.T, s *Server, id Identity) ([]byte, bool) {
	t.Helper()
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	pr, ok := s.peers[id]
	if !ok {
		return nil, false
	}
	return pr.NaClPub, true
}

// assertPeerKeyUnhijacked encodes the peer-key-authenticity invariant against whatever key the
// target currently holds for id: the target must never hold the attacker's key
// under the victim's identity, and any message SendEncrypted would seal to that
// key must be readable ONLY by the victim, never by the attacker.
//
// wantRetained, when non-nil, is a key the target authenticated BEFORE the
// poison (the overwrite case): a correct fix must keep it intact -- not replace
// it (buggy) and not drop it (which the !held early return would otherwise mask).
func assertPeerKeyUnhijacked(t *testing.T, s *Server, id Identity, attackerPub, wantRetained []byte, victimPriv, attackerPriv *ecdh.PrivateKey) {
	t.Helper()

	stored, held := storedPeerNaClPub(t, s, id)

	// PRIMARY INVARIANT (kills false-pass, pins the fix): the target must never
	// hold the attacker's key under the victim's identity. Fails while buggy,
	// decoupled from the crypto below.
	if held && bytes.Equal(stored, attackerPub) {
		t.Errorf("target holds the ATTACKER's X25519 key bound to the " +
			"victim's identity: unsigned gossip hijacked the e2e key")
	}

	// RETENTION (overwrite case only): a previously authenticated binding must
	// survive the poison intact. Checked before the !held early return so a fix
	// that DROPS the record on conflict cannot slip through.
	if wantRetained != nil && (!held || !bytes.Equal(stored, wantRetained)) {
		t.Errorf("target no longer holds the victim's real key (held=%v): the "+
			"authenticated binding was lost", held)
	}

	// A correct fix may reject the unauthenticated binding outright, leaving no
	// record. That satisfies the invariant -- there is nothing to seal.
	if !held {
		return
	}

	// CONSEQUENCE: seal to whatever key the target now holds for the victim --
	// exactly SendEncrypted's step (SealBox to s.peers[dest].NaClPub). The result
	// must be readable ONLY by the victim. While buggy, `stored` is the attacker's
	// key, so this leaks; the victim leg is a positive control against a "nobody
	// can decrypt" false-pass.
	share := []byte("confidential TSS key share destined for the victim")
	ep, err := SealBox(share, stored, s.secret, PKeygenRequest)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, aerr := OpenBox(ep, attackerPriv); aerr == nil {
		t.Error("target sealed the victim's confidential traffic to a key " +
			"the attacker can decrypt")
	}
	if _, verr := OpenBox(ep, victimPriv); verr != nil {
		t.Errorf("target's traffic to the victim is not decryptable by the "+
			"victim: %v", verr)
	}
}

func TestGossipCannotHijackPeerE2EKey(t *testing.T) {
	const peerAddr = "10.0.0.1:9000"

	tests := []struct {
		name string
		// priorHandshake installs the victim's REAL key first (directly, as a
		// completed authenticated handshake would) so the poison is an OVERWRITE.
		// When false, the poison is the victim's FIRST binding.
		priorHandshake bool
	}{
		{name: "overwrite-handshake-key", priorHandshake: true},
		{name: "first-binding", priorHandshake: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel() // reap addPeer's per-record TTL goroutines

			// The target seals confidential ceremony traffic to the victim; the
			// attacker is any connected peer able to gossip a PeerListResponse.
			target := newPeerKeyServer(t)
			victim, victimPub, victimPriv := naclIdentity(t)
			_, attackerPub, attackerPriv := naclIdentity(t)

			// Distinct keys are what make the decrypt assertions meaningful.
			if bytes.Equal(victimPub, attackerPub) {
				t.Fatal("victim and attacker derived the same X25519 key")
			}

			var wantRetained []byte
			if tt.priorHandshake {
				// Target already holds the victim's REAL key from a completed
				// authenticated handshake (installed directly, NOT via the
				// unauthenticated sink). Confirm it landed so the poison provably
				// attempts an OVERWRITE and cannot silently degenerate into
				// first-binding.
				installPeerFromHandshake(target, peerRec(victim, victimPub, peerAddr))
				if stored, held := storedPeerNaClPub(t, target, victim); !held || !bytes.Equal(stored, victimPub) {
					t.Fatal("handshake bootstrap: victim's real key was not installed")
				}
				wantRetained = victimPub
			}

			// A connected peer (the attacker) gossips a PeerListResponse binding
			// the victim's identity to the attacker's X25519 key. This is exactly
			// the record handlePeerListResponse feeds into addPeer -- unsigned and
			// unchecked -- so we drive that vulnerable sink directly.
			target.addPeer(ctx, peerRec(victim, attackerPub, peerAddr))

			assertPeerKeyUnhijacked(t, target, victim, attackerPub, wantRetained, victimPriv, attackerPriv)
		})
	}
}
