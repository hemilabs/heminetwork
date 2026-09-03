// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"testing"
	"time"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

func TestBFSRoutes(t *testing.T) {
	// Helper to create identities from short hex strings.
	id := func(b byte) Identity {
		var i Identity
		i[0] = b
		return i
	}

	A := id(0x0A)
	B := id(0x0B)
	C := id(0x0C)
	D := id(0x0D)
	E := id(0x0E)

	tests := []struct {
		name string
		src  Identity
		adj  map[Identity][]Identity
		want map[Identity]Identity
	}{
		{
			name: "empty graph",
			src:  A,
			adj:  map[Identity][]Identity{},
			want: map[Identity]Identity{},
		},
		{
			name: "self only",
			src:  A,
			adj: map[Identity][]Identity{
				A: {A},
			},
			want: map[Identity]Identity{},
		},
		{
			name: "two direct neighbors",
			src:  A,
			adj: map[Identity][]Identity{
				A: {B, C},
				B: {A},
				C: {A},
			},
			want: map[Identity]Identity{
				B: B,
				C: C,
			},
		},
		{
			name: "linear chain A-B-C-D",
			src:  A,
			adj: map[Identity][]Identity{
				A: {B},
				B: {A, C},
				C: {B, D},
				D: {C},
			},
			want: map[Identity]Identity{
				B: B,
				C: B, // via B
				D: B, // via B→C
			},
		},
		{
			name: "star topology center=A",
			src:  A,
			adj: map[Identity][]Identity{
				A: {B, C, D, E},
				B: {A},
				C: {A},
				D: {A},
				E: {A},
			},
			want: map[Identity]Identity{
				B: B,
				C: C,
				D: D,
				E: E,
			},
		},
		{
			name: "cycle A-B-C-D-A",
			src:  A,
			adj: map[Identity][]Identity{
				A: {B, D},
				B: {A, C},
				C: {B, D},
				D: {C, A},
			},
			want: map[Identity]Identity{
				B: B,
				C: B, // A→B→C (2 hops) shorter than A→D→C
				D: D,
			},
		},
		{
			name: "disconnected node E unreachable",
			src:  A,
			adj: map[Identity][]Identity{
				A: {B},
				B: {A},
				E: {}, // isolated
			},
			want: map[Identity]Identity{
				B: B,
				// E not reachable — not in table
			},
		},
		{
			name: "asymmetric adjacency A sees B but B does not see A",
			src:  A,
			adj: map[Identity][]Identity{
				A: {B},
				B: {C},
				C: {},
			},
			want: map[Identity]Identity{
				B: B,
				C: B, // A→B→C
			},
		},
		{
			name: "src not in adjacency map",
			src:  A,
			adj: map[Identity][]Identity{
				B: {C},
				C: {B},
			},
			want: map[Identity]Identity{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bfsRoutes(tt.src, tt.adj)

			// Check all expected routes are present.
			for dest, wantHop := range tt.want {
				gotHop, ok := got[dest]
				if !ok {
					t.Errorf("missing route to %v: want hop %v", dest, wantHop)
					continue
				}
				if gotHop != wantHop {
					t.Errorf("route to %v: got hop %v, want %v", dest, gotHop, wantHop)
				}
			}

			// Check no unexpected routes.
			for dest, gotHop := range got {
				if _, expected := tt.want[dest]; !expected {
					t.Errorf("unexpected route to %v via %v", dest, gotHop)
				}
			}
		})
	}
}

// routeTestServer returns a server whose only routing inputs are its
// session and peer maps: no network, no gossip loop.  Self is stored
// the way Run stores it — with no Sessions on its own record.
func routeTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	s.secret, err = NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s.peersTTL, err = ttl.New(16, true)
	if err != nil {
		t.Fatal(err)
	}
	s.registerSelfAsPeer()
	return s
}

// gossipSessions records what peer id advertises as its sessions,
// through addPeer exactly as handlePeerListResponse stores gossip,
// then rebuilds the routing table like that handler does.
func gossipSessions(t *testing.T, s *Server, id Identity, sessions ...Identity) {
	t.Helper()
	s.addPeer(t.Context(), PeerRecord{
		Identity: id,
		Version:  ProtocolVersion,
		LastSeen: time.Now().Unix(),
		Sessions: sessions,
	})
	s.rebuildRoutes()
}

func TestRebuildRoutesSeedsSelfFromSessions(t *testing.T) {
	// self — B — C.  B is our only session and advertises (self, C).
	// Nothing but the session map says self is adjacent to B: our
	// own peer record carries no Sessions, so a BFS seeded from peer
	// records alone would start with no edges and route nothing.
	s := routeTestServer(t)
	B, C := Identity{0x0B}, Identity{0x0C}
	if err := s.newSession(&B, &Transport{}); err != nil {
		t.Fatal(err)
	}
	gossipSessions(t, s, B, s.secret.Identity, C)

	if hop, ok := s.routeNextHop(C); !ok || hop != B {
		t.Fatalf("route to C = %v/%v, want via B", hop, ok)
	}
	if hop, ok := s.routeNextHop(B); !ok || hop != B {
		t.Fatalf("route to B = %v/%v, want direct", hop, ok)
	}
}

func TestGossipTopologyChangeRebuildsRoutes(t *testing.T) {
	// Only gossip changes here — no local session event — so every
	// rebuild depends on addPeer and peerExpired marking the table
	// stale.
	s := routeTestServer(t)
	B, C, D := Identity{0x0B}, Identity{0x0C}, Identity{0x0D}
	if err := s.newSession(&B, &Transport{}); err != nil {
		t.Fatal(err)
	}
	gossipSessions(t, s, B, s.secret.Identity, C)
	if _, ok := s.routeNextHop(C); !ok {
		t.Fatal("no route to C after first gossip")
	}

	// B drops C and picks up D.
	gossipSessions(t, s, B, s.secret.Identity, D)
	if hop, ok := s.routeNextHop(D); !ok || hop != B {
		t.Fatalf("route to D = %v/%v, want via B", hop, ok)
	}
	if _, ok := s.routeNextHop(C); ok {
		t.Fatal("stale route to C survived B's topology change")
	}

	// The same sessions in a different order is not a change: the
	// generation must hold still, or every gossip round — session
	// lists are emitted in map order — would force a rebuild.
	gen := s.routeGen.Load()
	gossipSessions(t, s, B, D, s.secret.Identity)
	if got := s.routeGen.Load(); got != gen {
		t.Fatalf("routeGen %d -> %d on reordered sessions, want unchanged", gen, got)
	}

	// B's record expires: its advertised edges leave the graph.
	s.peerExpired(t.Context(), B, nil)
	s.rebuildRoutes()
	if _, ok := s.routeNextHop(D); ok {
		t.Fatal("route to D survived B's expiry")
	}
	if hop, ok := s.routeNextHop(B); !ok || hop != B {
		t.Fatalf("route to B = %v/%v, want direct (session still up)", hop, ok)
	}
}
