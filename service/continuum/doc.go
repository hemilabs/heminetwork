// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package continuum implements a peer-to-peer mesh network with
// threshold signature ceremony support.
//
// # Architecture
//
// In production, a smart contract initiates all ceremonies and
// determines committee membership.  TSS round messages travel
// over the p2p mesh.  The mesh provides transport encryption,
// end-to-end NaCl encryption, peer discovery via gossip, and
// routed point-to-point messaging.
//
// In debug mode, hemictl commands trigger ceremonies for testing
// without a blockchain.  The CeremonyInitiator interface abstracts
// ceremony dispatch so the same engine handles both modes.
//
// # Messaging Layers
//
// Messages are classified by routing behavior:
//
//   - One-hop: PingRequest/PingResponse, PeerNotify, PeerListRequest/
//     PeerListResponse.  These travel only between directly connected
//     peers over the transport-encrypted link.
//
//   - Routed: TSSMessage, KeygenRequest, SignRequest, ReshareRequest.
//     These carry a Destination identity and are forwarded hop-by-hop
//     through the mesh until they reach the target.  Messages with
//     NaCl e2e encryption are wrapped in EncryptedPayload envelopes.
//
//   - Broadcast: CeremonyResult.  These are flooded to all peers with
//     TTL-based propagation and deduplication via a time-bounded cache.
//
// # Transport
//
// Each connection begins with an ECDH X25519 key exchange.  Both
// sides generate ephemeral keys, derive a shared secret, and use it
// to encrypt all subsequent traffic with XSalsa20-Poly1305 (NaCl
// secretbox).  After key exchange, a mutual challenge-response
// handshake authenticates both peers using their long-term ed25519
// signing keys.  The handshake also exchanges NaCl public keys for
// end-to-end encryption of routed messages.
//
// Messages are length-prefixed and JSON-encoded within the encrypted
// stream.  Each message carries a Header with source identity,
// optional destination, TTL, and payload type, followed by the
// type-specific payload.
//
// # Peer Discovery
//
// Peers discover each other through gossip.  On connection, each side
// sends a PeerNotify with its known peer count.  If the remote knows
// more peers, a PeerListRequest/PeerListResponse exchange follows.
// Newly learned peers trigger a PeerNotify broadcast to all connected
// peers, propagating the discovery.  PeerListResponse entries are
// validated for protocol version and address format before acceptance.
//
// Peers may also be discovered via DNS TXT records.  A node can
// advertise its identity and address through a DNS name, which other
// nodes verify during handshake.
//
// # Session Management
//
// Each connected peer gets a handle() goroutine that reads messages
// and dispatches them through a registration-based handler map
// (payloadDispatch).  A companion pingLoop goroutine sends periodic
// heartbeats; missed pongs trigger session teardown via a TTL-based
// timeout.  When the server is at connection capacity, new connections
// receive a BusyResponse and are closed.  TCP keepalive is enabled on
// all connections to detect dead peers at the OS level.
//
// # Broadcast Design — flood+dedup
//
// Broadcast (CeremonyResult, CeremonyAbort) uses simple flood+dedup:
// the originator sends to all connected peers, each receiver processes
// locally and re-sends to all its peers except the source, and a
// time-bounded dedup cache (PayloadHash → seen, capacity 1024,
// TTL 67s) prevents infinite loops.  Messages carry a hop counter
// (defaultTTL=8) decremented on each forward; messages with TTL=0
// are dropped.
//
// This design was chosen for simplicity and correctness at the target
// scale.  Only CeremonyResult and CeremonyAbort use broadcast; all
// other traffic is either one-hop (ping, gossip) or routed point-to-
// point (TSS round messages, ceremony requests).  TSS round messages
// are the heaviest traffic but use direct transport writes between
// committee members — no mesh routing, no broadcast, no amplification.
//
// # Broadcast Cost at 100 Nodes
//
// With 100 nodes each maintaining 8 peers (bidirectional), the
// overlay is a random 8-regular graph.
//
// Graph properties (random d-regular, N=100, d=8):
//   - Expected diameter: log(100)/log(8) ≈ 2.2
//   - Worst-case diameter (high probability): 3-4 hops
//   - defaultTTL=8 covers diameter with 2× margin
//   - Connected with high probability for d ≥ 3
//
// Wire cost per broadcast: each node receives the message from ~8
// peers, processes it once, dedup-drops the rest.  Total wire
// messages ≈ N×P = 800 for one broadcast.  Payload size is small
// (~500 bytes on the wire including header and NaCl overhead).
// Total bandwidth: ~400 KB across the entire network, ~4 KB per node.
//
// Each ceremony produces exactly one CeremonyResult broadcast (plus
// possibly one CeremonyAbort on the error path): 1-2 broadcasts per
// ceremony.
//
// Dedup capacity: 1024 entries at 67s TTL supports ~15 unique
// broadcast hashes per second before eviction.  At 1-2 broadcasts
// per ceremony, this supports 8-15 ceremonies completing per second.
// Realistic peak for 100 nodes with committees of 5: 2-4 ceremonies
// per second.  Headroom: 4-7×.
//
// Background traffic budget per node (steady state, non-broadcast):
// ping sends+receives ≈ 0.4 msg/s.  Gossip is event-driven, rare.
// Broadcast adds bursty spikes bounded by writeTimeout (4s) and
// sequential writes in forwardBroadcast.
//
// # Broadcast Scaling Limits
//
// The design degrades gracefully with scale:
//
//   - ≤200 nodes: no changes needed.  All dimensions have headroom.
//
//   - 200-500 nodes: write fan-out grows (1600-4000 wire messages per
//     broadcast).  Still fast if peers are healthy; one slow peer
//     delays 7 others.  Current design already writes outside the
//     lock, so slow peers don't block new broadcasts.  Monitor write
//     latency.
//
//   - 500-1000 nodes: graph diameter rises to ~3.0, worst case ~5.
//     Still within TTL=8 but headroom shrinks.  Non-uniform topology
//     (clusters with sparse interconnects) could push effective
//     diameter past TTL.  Raise defaultTTL to 12-16.  Cost: more
//     dedup cache hits, acceptable if ceremony rate stays below 10/s.
//
//   - 1000-2000 nodes: dedup cache pressure.  A single broadcast
//     generates ~8000 wire messages.  At 15 ceremonies/s peak,
//     seenCapacity=1024 becomes tight.  Eviction causes duplicate
//     re-forwarding — a mild amplification storm bounded by TTL.
//     Raise seenCapacity to 4096-8192 (negligible memory cost).
//
//   - 2000+ nodes: O(N×P) becomes expensive.  At 5000 nodes, one
//     broadcast = 40,000 wire messages with 87.5% waste (7/8 copies
//     are dedup drops).  Switch broadcast algorithm.
//
// # Alternative Broadcast Algorithms
//
// If the network grows past the flood+dedup threshold:
//
// Probabilistic relay (easiest, ~10 lines changed): forward to
// K < P randomly chosen peers instead of all P.  Reduces wire
// messages from N×P to N×K.  K ≥ 2-3 provides connected coverage
// with high probability on random graphs.  Implementation: shuffle
// targets in forwardBroadcast, take first K.  Add config knob.
//
// Plumtree / epidemic broadcast trees (moderate, ~300-500 lines):
// split peers into "eager" (tree edges, forward immediately) and
// "lazy" (send IHAVE digests only).  Reduces wire messages to ~N
// (tree-optimal) plus small IHAVE overhead.  Self-healing via
// GRAFT/PRUNE.  Requires new message types.
//
// Structured overlay / Kademlia (major change): distance-based
// routing with O(N) messages and O(log N) latency.  Not recommended
// unless the network reaches 10,000+ nodes with sub-second broadcast
// latency requirements.
package continuum
