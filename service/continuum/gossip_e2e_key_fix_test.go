// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Companion tests for the signed-PeerRecord remediation of the unauthenticated
// peer e2e key. gossip_e2e_key_test.go and its integration twin are REJECTION
// tests (fail while the defect is present, pass once records are verified) and
// therefore cannot cover the ACCEPT direction or the exact-key-authenticity
// property: a rejection suite would pass vacuously even if the fix rejected every
// record. These tests pin the parts that a fails-before/passes-after suite
// structurally cannot:
//
//   - the signature must authenticate the (Identity, NaClPub) BINDING, not merely
//     be present or valid over the bytes: a record signed by the WRONG KEY is
//     rejected (kills a presence-only weakening), AND a record carrying the owner's
//     genuine signature with the attacker's key SUBSTITUTED in is rejected (kills a
//     weakening that drops NaClPub from the signed binding -- the only test pinning
//     that half). Both rejection tests are needed; neither subsumes the other.
//   - a correctly self-signed record learned purely via gossip is ACCEPTED and
//     the stored key is the peer's real key, usable for sealing (liveness: kills a
//     silent vacuous-reject from a domain-tag typo or a preimage divergence
//     between the sign and verify sites);
//   - the record registerSelfAsPeer writes -- which is never verified locally
//     because self is stored directly -- carries a signature a REMOTE addPeer
//     accepts (kills a broken self-signature that silently self-eclipses the node);
//   - a real Handshake produces the correct binding signature and threads it
//     through to addPeer so a genuinely-handshaked peer is stored and usable
//     (guards the production sign+threading path no addPeer-input test exercises).

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"net"
	"testing"
	"time"
)

// signedBinding builds a PeerRecord claiming identity id bound to naclPub, signed
// by signer. signer NEED NOT own id: Verify recovers the signer's identity from the
// signature and compares it to pr.Identity, so signer != id is exactly the forgery
// the rejection tests exploit, while signer == id (with signer's real key) is a
// legitimate self-binding.
func signedBinding(signer *Secret, id Identity, naclPub []byte, addr string) PeerRecord {
	return PeerRecord{
		Identity:  id,
		NaClPub:   naclPub,
		Version:   ProtocolVersion,
		Address:   addr,
		Signature: signer.Sign(hashPeerBinding(id, naclPub)),
	}
}

// TestGossipRejectsWrongKeySignedBinding is the teeth: the signature must recover
// to the record's OWN identity. An attacker binds the victim's identity to the
// attacker's key and signs it with the ATTACKER's key -- a well-formed, valid
// signature over the exact bytes, just by the wrong signer. It must be rejected;
// a presence-only or verify-against-sender fix would wrongly accept it and reopen
// the hijack.
func TestGossipRejectsWrongKeySignedBinding(t *testing.T) {
	const peerAddr = "10.0.0.1:9000"
	target := newPeerKeyServer(t)

	victim, err := NewSecret()
	if err != nil {
		t.Fatalf("victim secret: %v", err)
	}
	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}
	attackerPub, err := attacker.NaClPublicKey()
	if err != nil {
		t.Fatalf("attacker nacl pub: %v", err)
	}

	// victim identity -> attacker key, signed by the attacker (the wrong signer).
	poison := signedBinding(attacker, victim.Identity, attackerPub, peerAddr)

	gossipPeerList(t, target, attacker.Identity, poison)

	if stored, held := storedPeerNaClPub(t, target, victim.Identity); held {
		t.Fatalf("target stored key %x under the victim's identity from a "+
			"wrong-signer binding: signature presence is being checked, not "+
			"authenticity of the identity<->key binding", stored)
	}
}

// TestGossipRejectsKeySubstitution proves the signature commits to the NaClPub,
// not just the identity -- the fix's central invariant. It takes a GENUINE
// self-signed binding over the owner's REAL key, then transplants the attacker's
// key into the record while keeping the owner's identity and genuine signature.
// The advertised key no longer matches what was signed, so verification against
// hashPeerBinding(ownerID, attackerKey) recovers a key that is not the owner and
// the record is rejected. This is the one axis the wrong-signer and malformed
// tests do not cover: a weakening that dropped NaClPub from the signed binding
// would reopen the hijack yet leave every other test green.
func TestGossipRejectsKeySubstitution(t *testing.T) {
	const peerAddr = "10.0.0.4:9000"
	target := newPeerKeyServer(t)

	owner, err := NewSecret()
	if err != nil {
		t.Fatalf("owner secret: %v", err)
	}
	ownerPub, err := owner.NaClPublicKey()
	if err != nil {
		t.Fatalf("owner nacl pub: %v", err)
	}
	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}
	attackerPub, err := attacker.NaClPublicKey()
	if err != nil {
		t.Fatalf("attacker nacl pub: %v", err)
	}

	// Genuine binding the owner really signed, over the owner's real key...
	poison := signedBinding(owner, owner.Identity, ownerPub, peerAddr)
	// ...then swap in the attacker's key, keeping the owner's genuine signature.
	poison.NaClPub = attackerPub

	gossipPeerList(t, target, attacker.Identity, poison)

	if stored, held := storedPeerNaClPub(t, target, owner.Identity); held {
		t.Fatalf("target accepted a signature-transplant record binding the "+
			"owner's identity to key %x: the signature is not committing to NaClPub",
			stored)
	}
}

// TestGossipRejectsMalformedSignature guards the RecoverCompact error branch
// distinctly from the wrong-key case: an empty, garbage, or truncated signature
// over an otherwise well-formed record must be rejected without panicking.
func TestGossipRejectsMalformedSignature(t *testing.T) {
	const peerAddr = "10.0.0.3:9000"

	peer, err := NewSecret()
	if err != nil {
		t.Fatalf("peer secret: %v", err)
	}
	peerPub, err := peer.NaClPublicKey()
	if err != nil {
		t.Fatalf("peer nacl pub: %v", err)
	}
	good := peer.Sign(hashPeerBinding(peer.Identity, peerPub))

	// A full-length (65-byte) signature with corrupted content: exercises the
	// RecoverCompact-parses-then-identity-mismatch branch that the shorter cases
	// (rejected on length) never reach. Flip a byte inside R (index 10), NOT the
	// index-0 recovery-id header, so the signature stays well-formed and recovers a
	// non-peer key rather than failing to parse (which would collapse this back into
	// the length/parse-reject path already covered above).
	corrupt := append([]byte(nil), good...)
	corrupt[10] ^= 0xff

	tests := []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"garbage", []byte("not-a-signature")},
		{"truncated", good[:len(good)-1]},
		{"corrupt-full-length", corrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := newPeerKeyServer(t)
			rec := PeerRecord{
				Identity:  peer.Identity,
				NaClPub:   peerPub,
				Version:   ProtocolVersion,
				Address:   peerAddr,
				Signature: tt.sig,
			}
			gossipPeerList(t, target, peer.Identity, rec)
			if _, held := storedPeerNaClPub(t, target, peer.Identity); held {
				t.Fatalf("target accepted a record with a %s signature", tt.name)
			}
		})
	}
}

// TestGossipAcceptsValidSelfSignedBinding is the liveness control: a correctly
// self-signed record, learned purely via gossip from a THIRD party (never a
// direct handshake), must be accepted, stored as the peer's REAL key, and usable
// for sealing. This is the ACCEPT direction no rejection test can cover; it fails
// if the fix is vacuously over-strict (e.g. a domain-tag typo, or the sign and
// verify sites hashing different preimages).
func TestGossipAcceptsValidSelfSignedBinding(t *testing.T) {
	const peerAddr = "10.0.0.2:9000"
	target := newPeerKeyServer(t)

	peer, err := NewSecret()
	if err != nil {
		t.Fatalf("peer secret: %v", err)
	}
	peerPub, err := peer.NaClPublicKey()
	if err != nil {
		t.Fatalf("peer nacl pub: %v", err)
	}
	peerPriv, err := peer.NaClPrivateKey()
	if err != nil {
		t.Fatalf("peer nacl priv: %v", err)
	}
	relay, err := NewSecret() // a third party forwarding the peer's signed record
	if err != nil {
		t.Fatalf("relay secret: %v", err)
	}

	gossipPeerList(t, target, relay.Identity,
		signedBinding(peer, peer.Identity, peerPub, peerAddr))

	stored, held := storedPeerNaClPub(t, target, peer.Identity)
	if !held {
		t.Fatal("target rejected a validly self-signed gossiped binding: the " +
			"fix is over-strict and the mesh would learn no gossiped peers")
	}
	if !bytes.Equal(stored, peerPub) {
		t.Fatalf("stored key is not the peer's real key: got %x want %x",
			stored, peerPub)
	}

	// Routable: what SendEncrypted would seal to the stored key must be openable
	// by the peer -- confirming the accepted key is genuinely the peer's.
	ep, err := SealBox([]byte("confidential TSS share"), stored, target.secret, PKeygenRequest)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenBox(ep, peerPriv); err != nil {
		t.Fatalf("peer cannot open traffic sealed to the learned key: %v", err)
	}
}

// TestSelfRecordIsRemotelyVerifiable pins the one binding that is never checked
// locally: registerSelfAsPeer writes s.peers[self] DIRECTLY (addPeer skips self),
// so a broken self-signature would never fail on the origin node yet every remote
// peer would reject the node's gossiped record and be unable to reach it. Assert
// the self-record both verifies directly and is accepted by a distinct node's
// gossip receive path.
func TestSelfRecordIsRemotelyVerifiable(t *testing.T) {
	origin := newPeerKeyServer(t)
	origin.registerSelfAsPeer()

	origin.mtx.RLock()
	self, ok := origin.peers[origin.secret.Identity]
	origin.mtx.RUnlock()
	if !ok {
		t.Fatal("registerSelfAsPeer did not store the self record")
	}

	// The self-signature must verify against the node's own identity. This is a
	// well-formedness precondition, not the gate under test: the origin stores its
	// own record directly and addPeer's not-self gate means the origin never
	// validates it -- only a remote does.
	if _, err := Verify(hashPeerBinding(self.Identity, self.NaClPub),
		self.Identity, self.Signature); err != nil {
		t.Fatalf("self record signature does not verify: %v", err)
	}

	// The teeth: a distinct remote must accept the origin's self-record through the
	// REAL gossip receive path (handlePeerListResponse + addPeer), exactly as it
	// arrives in production -- not via a lower-level addPeer call that would skip a
	// receive-side gate. The origin honestly gossips its own record; the differing
	// remote identity keeps the not-self gate satisfied.
	remote := newPeerKeyServer(t)
	gossipPeerList(t, remote, origin.secret.Identity, *self)

	stored, held := storedPeerNaClPub(t, remote, origin.secret.Identity)
	if !held {
		t.Fatal("a distinct node rejected the origin's self-record via the real " +
			"gossip receive path: the node would be unreachable for e2e despite " +
			"being reachable on the network")
	}
	if !bytes.Equal(stored, self.NaClPub) {
		t.Fatalf("remote stored the wrong key for the origin: got %x want %x",
			stored, self.NaClPub)
	}
}

// TestHandshakeProducedBindingIsAcceptedByAddPeer exercises the production sign +
// threading half of the fix that no addPeer-input test reaches: a real Handshake
// must sign the correct (Identity, NaClPub) binding and return the signature so
// the caller can store a peer that addPeer accepts. A regression in the binding
// arguments, the return arity, or any call-site swap would reject every honest
// live peer -- a silent mesh-wide availability collapse invisible to the
// addPeer-input tests, which never call Handshake.
func TestHandshakeProducedBindingIsAcceptedByAddPeer(t *testing.T) {
	target := newPeerKeyServer(t)

	peerSecret, err := NewSecret()
	if err != nil {
		t.Fatalf("peer secret: %v", err)
	}
	peerPub, err := peerSecret.NaClPublicKey()
	if err != nil {
		t.Fatalf("peer nacl pub: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Run a real mutual handshake over a loopback TCP connection (the mutual
	// HelloRequest exchange write-deadlocks on an unbuffered net.Pipe): the server
	// side uses the target's secret (as newTransport does), the client side is the
	// peer. We capture what the server's Handshake returns about the peer --
	// exactly the (id, naclPub, naclPubSig) the production call sites feed addPeer.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			acceptCh <- nil
			return
		}
		acceptCh <- c
	}()
	cliConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { cliConn.Close() })
	srvConn := <-acceptCh
	if srvConn == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { srvConn.Close() })

	trServer, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatalf("server transport: %v", err)
	}
	trClient := new(Transport) // responder side, mirroring the KeyExchange pairing

	// Key exchange (both ends concurrently -- net.Pipe is unbuffered).
	kxErr := make(chan error, 2)
	go func() { kxErr <- trServer.KeyExchange(ctx, srvConn) }()
	go func() { kxErr <- trClient.KeyExchange(ctx, cliConn) }()
	for i := 0; i < 2; i++ {
		if err := <-kxErr; err != nil {
			t.Fatalf("key exchange: %v", err)
		}
	}

	// Handshake (both ends concurrently). Only the server's view of the peer is
	// under test; the client side is driven just to complete the exchange.
	type hs struct {
		id  *Identity
		pub []byte
		sig []byte
		err error
	}
	srvRes := make(chan hs, 1)
	cliErr := make(chan error, 1)
	go func() {
		id, pub, sig, err := trServer.Handshake(ctx, target.secret)
		srvRes <- hs{id, pub, sig, err}
	}()
	go func() {
		_, _, _, err := trClient.Handshake(ctx, peerSecret)
		cliErr <- err
	}()
	if err := <-cliErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	r := <-srvRes
	if r.err != nil {
		t.Fatalf("server handshake: %v", r.err)
	}
	if r.id == nil || *r.id != peerSecret.Identity {
		t.Fatalf("server learned wrong peer identity: %v", r.id)
	}

	// Feed the handshake result into addPeer exactly as the production call sites
	// do. A regression in Handshake's binding args, the return arity, or a
	// call-site swap would make this record fail Verify and addPeer reject it.
	if !target.addPeer(ctx, PeerRecord{
		Identity:  *r.id,
		NaClPub:   r.pub,
		Version:   ProtocolVersion,
		LastSeen:  time.Now().Unix(),
		Signature: r.sig,
	}) {
		t.Fatal("addPeer rejected a peer produced by a real handshake: the " +
			"handshake did not sign/thread the binding that addPeer verifies")
	}

	stored, held := storedPeerNaClPub(t, target, peerSecret.Identity)
	if !held || !bytes.Equal(stored, peerPub) {
		t.Fatalf("stored key does not match the handshaked peer's real key: "+
			"held=%v got %x want %x", held, stored, peerPub)
	}
}
