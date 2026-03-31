// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"testing"
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
