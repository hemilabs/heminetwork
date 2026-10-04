// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression tests for the recovery companion to the peer-table leak fix (A).
// Closing the leak correctly removes a departed peer's s.peers row after
// peerTTL. connectRandom dials only from s.peers, so once an outage empties it
// (or, on an island, it holds only the peers we already have) the node needs a
// dial source that does NOT depend on s.peers. recoverConnections provides one,
// and deliberately dials ONLY trusted static config: the configured Connect
// anchors (skipping those with a live session) and a rate-limited DNS seed
// round. It stores no gossip-supplied or runtime-learned address, so no amount
// of gossip can steer or flush recovery. A node with neither Connect nor Seeds
// has no gossip-independent recovery source and relies on inbound connections.

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// TestPeerRecoveryAnchorsAreConfigOnly pins that recovery dials only configured
// Connect addresses, never a gossip-learned one (connectRandom covers s.peers).
func TestPeerRecoveryAnchorsAreConfigOnly(t *testing.T) {
	s := peerTableServer(t, 0)
	s.cfg.Connect = []string{"node-a.example:9000", "node-b.example:9000"}
	ctx := context.Background()
	s.addPeer(ctx, PeerRecord{Identity: fakeID(5), Version: ProtocolVersion, Address: "gossip-c.example:9000", LastSeen: time.Now().Unix()})

	anchors := s.connectAnchors()
	if !contains(anchors, "node-a.example:9000") || !contains(anchors, "node-b.example:9000") {
		t.Fatalf("connectAnchors must return the configured Connect entries: %v", anchors)
	}
	if contains(anchors, "gossip-c.example:9000") {
		t.Errorf("recovery must not dial a gossip-learned address: %v", anchors)
	}
}

// TestPeerRecoveryGossipCannotSteerRecovery is the core security property of the
// static-config-only design: no gossip record — however many, and even one that
// impersonates the anchor's own address — can add to, remove from, or otherwise
// change the recovery dial set, because recovery is derived purely from
// cfg.Connect and connectID, never from the gossip-rewritable peer table.
func TestPeerRecoveryGossipCannotSteerRecovery(t *testing.T) {
	s := peerTableServer(t, 0)
	s.cfg.Connect = []string{"anchor.example:9000"}
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		s.addPeer(ctx, PeerRecord{Identity: fakeID(1000 + i), Version: ProtocolVersion, Address: fmt.Sprintf("evil%d.example:1", i), LastSeen: time.Now().Unix()})
	}
	// A record impersonating the anchor's address under an attacker identity.
	s.addPeer(ctx, PeerRecord{Identity: fakeID(7), Version: ProtocolVersion, Address: "anchor.example:9000", LastSeen: time.Now().Unix()})

	anchors := s.connectAnchors()
	if len(anchors) != 1 || anchors[0] != "anchor.example:9000" {
		t.Fatalf("gossip flood changed the recovery anchor set: %v", anchors)
	}
}

// TestPeerRecoveryAnchorSkipsLiveSession pins the anti-churn behavior: a Connect
// peer we currently hold a session with (by the identity authenticated there) is
// skipped, while an unconnected one is still dialed.
func TestPeerRecoveryAnchorSkipsLiveSession(t *testing.T) {
	s := peerTableServer(t, 0)
	s.cfg.Connect = []string{"c1.example:9000", "c2.example:9000"}
	id := fakeID(11)
	s.rememberConnect("c1.example:9000", id)
	s.mtx.Lock()
	s.sessions[id] = &Transport{}
	s.mtx.Unlock()

	anchors := s.connectAnchors()
	if contains(anchors, "c1.example:9000") {
		t.Errorf("connectAnchors must skip a Connect peer with a live session: %v", anchors)
	}
	if !contains(anchors, "c2.example:9000") {
		t.Errorf("connectAnchors must still dial an unconnected Connect peer: %v", anchors)
	}
}

// TestPeerRecoveryForwardSkipsIPAnchor pins that in the default forward mode an
// IP-literal Connect anchor (which can never pass TXT verification) is skipped,
// while a hostname anchor is kept.
func TestPeerRecoveryForwardSkipsIPAnchor(t *testing.T) {
	s := peerTableServer(t, 0)
	s.cfg.DNS = DNSForward
	s.cfg.Connect = []string{"192.0.2.1:9000", "host.example:9000"}

	anchors := s.connectAnchors()
	if contains(anchors, "192.0.2.1:9000") {
		t.Errorf("forward mode must skip an IP-literal Connect anchor: %v", anchors)
	}
	if !contains(anchors, "host.example:9000") {
		t.Errorf("forward mode must keep a hostname Connect anchor: %v", anchors)
	}
}

// TestPeerRecoveryIslandDialsConfigAnchor pins that a configured island (nodes
// connected only to each other) still recovers the rest of the mesh:
// connectRandom finds no new candidate in s.peers, but recovery has the lost
// mesh member in cfg.Connect.
func TestPeerRecoveryIslandDialsConfigAnchor(t *testing.T) {
	s := peerTableServer(t, 0)
	s.cfg.PeersWanted = 8
	s.cfg.Connect = []string{"far-peer.example:9000"} // mesh member we lost
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		id := fakeID(i)
		s.addPeer(ctx, PeerRecord{Identity: id, Version: ProtocolVersion, Address: fmt.Sprintf("island%d.example:1", i), LastSeen: time.Now().Unix()})
		s.mtx.Lock()
		s.sessions[id] = &Transport{}
		s.mtx.Unlock()
	}

	if n := s.connectRandom(ctx); n != 0 {
		t.Fatalf("connectRandom dialed %d on an island with no unconnected peers; want 0", n)
	}
	if anchors := s.connectAnchors(); !contains(anchors, "far-peer.example:9000") {
		t.Fatalf("connectAnchors=%v missing the configured anchor: a configured island would stay partitioned", anchors)
	}
}

// TestPeerRecoveryNoConfigHasNoAnchors pins the documented limitation: a node
// with neither Connect nor Seeds has no gossip-independent recovery source
// (connectAnchors is empty); it relies on inbound connections. Operators of
// eclipse-sensitive nodes must configure Connect or Seeds.
func TestPeerRecoveryNoConfigHasNoAnchors(t *testing.T) {
	s := peerTableServer(t, 0)
	ctx := context.Background()
	s.addPeer(ctx, PeerRecord{Identity: fakeID(5), Version: ProtocolVersion, Address: "gossip.example:9000", LastSeen: time.Now().Unix()})

	if len(s.cfg.Connect) != 0 || len(s.cfg.Seeds) != 0 {
		t.Fatal("test expects a node with no Connect and no Seeds")
	}
	if anchors := s.connectAnchors(); len(anchors) != 0 {
		t.Fatalf("a no-config node must have no recovery anchors (relies on inbound); got %v", anchors)
	}
}

// TestPeerRecoverySelfAliasAnchorRetriesAfterTTL pins that a Connect address
// that resolved to ourselves (round-robin/LB/NAT hairpin, or a spoofed/
// misresolved record) is suppressed for only peerTTL, not permanently: a
// transient self-landing must not drop the only anchor until restart.
func TestPeerRecoverySelfAliasAnchorRetriesAfterTTL(t *testing.T) {
	s := peerTableServer(t, 0)
	s.cfg.Connect = []string{"self-alias.example:9000"}

	// A dial to the anchor landed on us: recorded as self.
	s.rememberConnect("self-alias.example:9000", s.secret.Identity)
	if anchors := s.connectAnchors(); contains(anchors, "self-alias.example:9000") {
		t.Fatalf("a recent self-landing anchor must be suppressed (no per-tick churn): %v", anchors)
	}

	// After peerTTL the suppression expires and the anchor is retried.
	s.mtx.Lock()
	s.connectSelfAt["self-alias.example:9000"] = time.Now().Add(-2 * peerTTL)
	s.mtx.Unlock()
	if anchors := s.connectAnchors(); !contains(anchors, "self-alias.example:9000") {
		t.Fatalf("a stale self-landing anchor must be retried, not dropped until restart: %v", anchors)
	}

	// A real peer answering at the anchor clears the self mark.
	s.rememberConnect("self-alias.example:9000", fakeID(1))
	if anchors := s.connectAnchors(); !contains(anchors, "self-alias.example:9000") {
		t.Fatalf("after a real peer answers, the anchor must be dialable: %v", anchors)
	}
}

// TestInboundDNSSameIdentityReconnectServedFromCache pins the reverse/all
// inbound-limiter fix: a peer that already reverse-verified from an IP is served
// from the cached positive result on reconnect instead of being refused by the
// per-IP rate limiter — so decoy dials at a Connect peer's IP cannot burn the
// token and keep the real peer's recovery reconnect refused. A different
// identity from the same IP is not a cache hit and stays rate-limited.
func TestInboundDNSSameIdentityReconnectServedFromCache(t *testing.T) {
	s := peerTableServer(t, 0)
	s.cfg.DNS = DNSReverse
	dl, err := ttl.New(8, true)
	if err != nil {
		t.Fatal(err)
	}
	s.dnsLookups = dl

	ip := "198.51.100.5"
	addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}
	id := fakeID(1)

	// A prior successful reverse verification cached this IP -> identity.
	s.dnsLookups.Put(context.Background(), 59*time.Second, ip, id, nil, nil)

	// Same identity, same IP: served from cache, not refused by the limiter.
	if err := s.verifyInboundDNS(context.Background(), addr, id); err != nil {
		t.Fatalf("same-identity reconnect must be served from cache, got: %v", err)
	}

	// Different identity from the same (rate-limited) IP: not a cache hit, so it
	// is subject to the limiter and refused.
	if err := s.verifyInboundDNS(context.Background(), addr, fakeID(2)); err == nil {
		t.Fatal("a different identity from a rate-limited IP must not be served from cache")
	}
}

// TestOutboundDNSLimiterSeparateFromInbound pins the DNSAll fix: our own
// outbound gossip dial to a peer's IP takes only the OUTBOUND rate-limit token
// and does NOT consume the INBOUND token that same peer needs to reconnect. A
// gossip attacker that makes us dial a victim's IP therefore cannot lock the
// victim's own inbound Connect/Seed reconnect out.
func TestOutboundDNSLimiterSeparateFromInbound(t *testing.T) {
	s := peerTableServer(t, 0)
	s.cfg.DNS = DNSAll
	dl, err := ttl.New(8, true)
	if err != nil {
		t.Fatal(err)
	}
	s.dnsLookups = dl

	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 9000}

	// Our outbound gossip dial takes the outbound token (as verifyOutboundDNS
	// with limit=true would), and a second outbound to the same IP is limited.
	if s.dnsRateLimitedNS(addr, "out|") {
		t.Fatal("first outbound lookup must not be limited")
	}
	if !s.dnsRateLimitedNS(addr, "out|") {
		t.Fatal("second outbound lookup to the same IP must be limited")
	}
	// The peer's legitimate inbound reconnect from that IP must NOT be refused
	// by the outbound token — the namespaces are separate.
	if s.dnsRateLimited(addr) {
		t.Fatal("inbound limiter must not be consumed by an outbound dial to the same IP")
	}
}
