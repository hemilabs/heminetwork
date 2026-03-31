// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Routing implementation.
//
// The routing table maps every known peer identity to the next-hop
// identity on the shortest path from the local node.  It is derived
// from gossip topology data: each node advertises its direct session
// neighbors in PeerRecord.Sessions, and every receiver stores that
// data in its peer map.
//
// Rebuild is generation-gated: topology changes (session add/remove,
// gossip update) bump routeGen.  rebuildRoutes compares routeGen to
// routeBuiltGen and skips the BFS if already current.  This avoids
// redundant rebuilds when multiple gossip messages arrive in quick
// succession.
//
// Staleness: the table reflects the last rebuild.  A dropped session
// on a remote node takes up to one gossip round (~67s) to propagate.
// During that window, a route may point through a dead link.  When
// the next-hop write fails, SendTo and forward fall through to the
// flood path, which delivers as long as the mesh is connected.
//
// Complexity: BFS is O(V+E) where V = known peers and E = sum of
// session lists.  For 100 nodes with PeersWanted=8, that is ~900
// operations — microseconds.

// invalidateRoutes bumps the routing generation counter, marking
// the current table as stale.  Called under s.mtx.Lock by
// newSession and deleteSession.  The actual rebuild happens at the
// next safe call site (after the lock is released).
func (s *Server) invalidateRoutes() {
	s.routeGen.Add(1)
}

// rebuildRoutes recomputes the routing table if the generation
// counter indicates a topology change since the last build.
// Must NOT be called while holding s.mtx — it acquires s.mtx.RLock
// internally to snapshot the peer map.
func (s *Server) rebuildRoutes() {
	gen := s.routeGen.Load()
	s.routeMtx.Lock()
	if s.routeBuiltGen == gen {
		s.routeMtx.Unlock()
		return
	}
	s.routeMtx.Unlock()

	s.mtx.RLock()
	self := s.secret.Identity
	adj := make(map[Identity][]Identity, len(s.peers))
	for id, pr := range s.peers {
		if len(pr.Sessions) > 0 {
			adj[id] = pr.Sessions
		}
	}
	s.mtx.RUnlock()

	table := bfsRoutes(self, adj)

	s.routeMtx.Lock()
	s.routeTable = table
	s.routeBuiltGen = gen
	s.routeMtx.Unlock()
}

// bfsRoutes computes shortest-path next hops from src using the
// given adjacency list.  Returns a map from destination to next
// hop (the first step on the shortest path from src to dest).
func bfsRoutes(src Identity, adj map[Identity][]Identity) map[Identity]Identity {
	table := make(map[Identity]Identity)
	visited := make(map[Identity]bool)
	visited[src] = true

	// BFS queue entries: (node, firstHop)
	type entry struct {
		node     Identity
		firstHop Identity
	}
	queue := make([]entry, 0, len(adj))

	// Seed queue with direct neighbors.
	for _, neighbor := range adj[src] {
		if neighbor == src {
			continue
		}
		if !visited[neighbor] {
			visited[neighbor] = true
			table[neighbor] = neighbor // direct neighbor: next hop is itself
			queue = append(queue, entry{neighbor, neighbor})
		}
	}

	// BFS.
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		for _, neighbor := range adj[cur.node] {
			if neighbor == src || visited[neighbor] {
				continue
			}
			visited[neighbor] = true
			table[neighbor] = cur.firstHop // inherit the first hop
			queue = append(queue, entry{neighbor, cur.firstHop})
		}
	}
	return table
}

// routeNextHop returns the next-hop identity for the given destination,
// or zero Identity + false if no route is known.
func (s *Server) routeNextHop(dest Identity) (Identity, bool) {
	s.routeMtx.RLock()
	hop, ok := s.routeTable[dest]
	s.routeMtx.RUnlock()
	return hop, ok
}
