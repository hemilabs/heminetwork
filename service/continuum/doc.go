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
package continuum
