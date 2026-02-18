// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package continuum implements the service that runs the p2p network for
// MinerFI Multi-Party Threshold Signature Scheme.
package continuum

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/juju/loggo/v2"
	"github.com/mitchellh/go-homedir"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/v2/service/deucalion"
	"github.com/hemilabs/heminetwork/v2/service/pprof"
	"github.com/hemilabs/heminetwork/v2/ttl"
)

const (
	logLevel = "INFO"
	appName  = "continuum"

	defaultListenAddress = "localhost:45067"
	defaultPeersWanted   = 8

	// peerTTL is the duration a peer record stays alive without
	// refresh.  Prime to avoid resonance with other timers.
	peerTTL = 67 * time.Second

	// maxGossipPeers caps the number of peer records accepted in a
	// single PeerListResponse to prevent memory exhaustion from a
	// malicious peer.
	maxGossipPeers = 256

	// pingInterval is how often each session sends a heartbeat.
	// Prime to avoid resonance with other periodic timers.
	pingInterval = 61 * time.Second

	// maintainInterval is how often the server checks whether it
	// needs to dial additional peers.  Prime, distinct from ping.
	maintainInterval = 67 * time.Second

	// seenTTL is the duration a message hash stays in the dedup
	// cache.  Prime, ~1 minute.  After expiry the same message
	// can be processed again.
	seenTTL = 67 * time.Second

	// seenCapacity is the maximum number of entries in the message
	// dedup cache.
	seenCapacity = 1024
)

var log = loggo.GetLogger(appName)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

// Config holds the configuration for a continuum Server.
type Config struct {
	Connect                 []string
	DNSName                 string // Hostname to advertise in hello, empty = don't
	DNSRequired             bool   // Require remote to advertise and verify DNS
	Home                    string
	ListenAddress           string
	LogLevel                string
	PeersWanted             int
	PingInterval            time.Duration // 0 uses default (61s)
	MaintainInterval        time.Duration // 0 uses default (67s)
	PprofListenAddress      string
	PrivateKey              string
	PrometheusListenAddress string
	PrometheusNamespace     string
	Seeds                   []string // DNS seed hostnames, format host:port
}

// Server is a continuum protocol node that manages encrypted peer
// connections, gossip-based peer discovery, and TSS ceremonies.
type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg  *Config
	data string // Data directory home+identity

	// Sessions
	sessions map[Identity]*Transport

	// Secrets
	secret *Secret

	// TSS
	preParams keygen.LocalPreParams
	tss       TSS
	tssStore  TSSStore
	stt       *serverTSSTransport
	tssCtx    context.Context

	// Listener
	listenConfig  *net.ListenConfig
	listenAddress string // Actual bound address after Listen()

	// DNS resolver; nil uses net.DefaultResolver.  Tests inject a
	// mock resolver pointing at an in-process DNS server.
	resolver *net.Resolver

	// Peer tracking
	peers    map[Identity]*PeerRecord // all known peers
	peersTTL *ttl.TTL                 // expiry for known peers

	// Message deduplication — prevents forwarding loops in
	// non-tree topologies.
	seen *ttl.TTL

	// Routing counters for observability and testing.
	routedReceived atomic.Int64 // messages received at final destination
	forwarded      atomic.Int64 // messages forwarded to next hop

	// Prometheus
	promCollectors  []prometheus.Collector
	promPollVerbose bool // set to true to print stats during poll
	isRunning       bool
}

// Info reports the current status of the server.
type Info struct {
	Online bool
}

// NewDefaultConfig returns a Config with sensible defaults.
func NewDefaultConfig() *Config {
	return &Config{
		LogLevel:            logLevel,
		PrometheusNamespace: appName,
		PrivateKey:          "",
		ListenAddress:       defaultListenAddress,
		PeersWanted:         defaultPeersWanted,
	}
}

// NewServer creates a new Server from the provided config.
// If cfg is nil, NewDefaultConfig is used.
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	return &Server{
		cfg:          cfg,
		listenConfig: &net.ListenConfig{},
		sessions:     make(map[Identity]*Transport, cfg.PeersWanted),
		peers:        make(map[Identity]*PeerRecord),
	}, nil
}

func (s *Server) newSession(id *Identity, t *Transport) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if _, ok := s.sessions[*id]; ok {
		return errors.New("duplicate identity")
	}
	s.sessions[*id] = t

	return nil
}

func (s *Server) deleteSession(id *Identity) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	t := s.sessions[*id]
	if t == nil {
		return fmt.Errorf("no session: %v", id)
	}
	delete(s.sessions, *id)
	return t.Close()
}

func (s *Server) deleteAllSessions() {
	// XXX holds mutex for duration of all Close() calls.  If a
	// transport's Close() blocks (broken TCP, slow FIN), every
	// goroutine needing s.mtx stalls.  Consider collecting
	// transports under lock, then closing outside it.
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for id, t := range s.sessions {
		if err := t.Close(); err != nil {
			log.Errorf("close session %s: %v", id, err)
		}
		delete(s.sessions, id)
	}
}

func (s *Server) newTransport(ctx context.Context, conn net.Conn) (*Identity, *Transport, []byte, error) {
	transport, err := NewTransportFromCurve(ecdh.X25519()) // XXX config option
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new transport: %w", err)
	}

	err = transport.KeyExchange(ctx, conn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key exchange: %w", err) // XXX too loud?
	}

	// After KX, transport owns conn.  Ensure cleanup on failure so
	// the remote side gets a connection reset instead of hanging.
	ok := false
	defer func() {
		if !ok {
			transport.Close()
		}
	}()

	id, theirDNS, naclPub, err := transport.Handshake(ctx, s.secret, s.cfg.DNSName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("handshake: %w", err) // XXX too loud?
	}

	if s.cfg.DNSRequired {
		if theirDNS == "" {
			return nil, nil, nil, errors.New("remote did not advertise dns name")
		}
		// XXX no rate limiting on DNS lookups here — an attacker
		// can open connections with fake DNS names and force
		// unbounded TXT queries.  Entangled with the accept-loop
		// blocking issue below.
		if err := s.verifyDNSIdentity(ctx, theirDNS, *id); err != nil {
			return nil, nil, nil, fmt.Errorf("dns verify: %w", err)
		}
	}

	ok = true
	return id, transport, naclPub, nil
}

// isDuplicate returns true if the message identified by header hash
// has been seen before within seenTTL.  On first encounter it records
// the hash and returns false.  Uses the PayloadHash from the header
// which is invariant across forwarding hops (unlike cleartext which
// changes as TTL is decremented and transport re-encrypts).
//
// NOTE: after seenTTL expires (~67s), a replayed message will be
// accepted again.  This is acceptable for idempotent commands
// (PingRequest) but should be reconsidered if non-idempotent
// commands are routed through the mesh.
func (s *Server) isDuplicate(ctx context.Context, h *Header) bool {
	log.Tracef("isDuplicate %v", h.PayloadHash)

	key := h.PayloadHash.String()
	if _, _, err := s.seen.Get(key); err == nil {
		return true
	}
	s.seen.Put(ctx, seenTTL, key, struct{}{}, nil, nil)
	return false
}

// defaultTTL is the hop count for originated routed messages.
const defaultTTL = 8

// forward relays a message that is not destined for us.  If TTL is
// zero, the message is dropped.  Otherwise TTL is decremented and the
// message is sent to the destination (if directly connected) or
// flooded to all peers except the source.
//
// Complexity: O(1) for direct send, O(n) over connected sessions for
// flood.  RLock is held during transport writes which are bounded by
// writeTimeout (4s).  This matches the existing notifyAllPeers
// pattern.
func (s *Server) forward(header *Header, payload any, from *Identity) {
	log.Tracef("forward %v -> %v TTL %d", header.Origin, header.Destination, header.TTL)

	if header.TTL == 0 {
		log.Debugf("forward: TTL expired, dropping")
		return
	}

	fwd := *header
	fwd.TTL--

	dest := *header.Destination

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	// Direct: destination is a connected peer.
	if t, ok := s.sessions[dest]; ok {
		if err := t.WriteHeader(fwd, payload); err != nil {
			log.Debugf("forward direct to %v: %v", dest, err)
		} else {
			log.Debugf("forward direct to %v TTL %d", dest, fwd.TTL)
			s.forwarded.Add(1)
		}
		return
	}

	// Flood: send to all connected peers except the source.
	var sent int
	for id, t := range s.sessions {
		if from != nil && id == *from {
			continue
		}
		if err := t.WriteHeader(fwd, payload); err != nil {
			log.Debugf("flood forward to %v: %v", id, err)
		} else {
			s.forwarded.Add(1)
			sent++
		}
	}
	log.Debugf("forward flood %v -> %v: sent to %d peer(s) TTL %d",
		header.Origin, dest, sent, fwd.TTL)
}

func (s *Server) handle(ctx context.Context, id *Identity, t *Transport) {
	// Per-session context: cancelled when handle() exits (read
	// error, shutdown, etc.), which also stops the pingLoop.
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()
	defer func() {
		if err := s.deleteSession(id); err != nil {
			log.Errorf("delete session %v: %v", id, err)
		}
	}()
	defer s.wg.Done()

	log.Debugf("handle: %v", id)
	defer log.Debugf("handle exit: %v", id)

	// Start heartbeat goroutine.  It exits when sessionCtx is
	// cancelled or when a ping write fails.
	s.wg.Add(1)
	go s.pingLoop(sessionCtx, id, t)

	// Announce our peer count and request their list.  On initial
	// session we always exchange; the count comparison in the
	// PeerNotify handler is for ongoing gossip only.
	if err := t.Write(s.secret.Identity, PeerNotify{
		Count: s.PeerCount(),
	}); err != nil {
		log.Warningf("initial peer notify %v: %v", id, err)
	}
	if err := t.Write(s.secret.Identity,
		PeerListRequest{}); err != nil {
		log.Warningf("initial peer list request %v: %v", id, err)
	}

	for {
		header, payload, _, err := t.ReadEnvelope()
		if err != nil {
			// XXX too loud?
			log.Errorf("read %v: %v", id, err)
			return
		}

		// Dedup: drop messages we have already seen.
		// Only applied to routed messages (those with a
		// destination).  Local one-hop messages like ping,
		// gossip are unique per exchange and don't need dedup.
		if header.Destination != nil {
			if s.isDuplicate(sessionCtx, header) {
				log.Debugf("handle %v: duplicate message dropped", id)
				continue
			}
		}

		// Forward: if destination is set and is not us,
		// decrement TTL and relay to the next hop.
		if header.Destination != nil && *header.Destination != s.secret.Identity {
			s.forward(header, payload, id)
			continue
		}

		// If this message was routed to us (has destination == us),
		// count it for observability.
		if header.Destination != nil {
			s.routedReceived.Add(1)
		}

		log.Debugf("%v", spew.Sdump(header))
		log.Debugf("%v", spew.Sdump(payload))

		// XXX make this a map like str2pt with callbacks
		switch v := payload.(type) {
		case *PingRequest:
			err := t.Write(s.secret.Identity, PingResponse{
				OriginTimestamp: v.OriginTimestamp,
				PeerTimestamp:   time.Now().Unix(),
			})
			if err != nil {
				log.Warningf("ping response %v: %v", id, err)
				return
			}

		case *PingResponse:
			// Heartbeat received — peer is alive.  Refresh
			// its TTL and update LastSeen.
			s.refreshPeerLastSeen(sessionCtx, *id)

		case *PeerNotify:
			// Remote has v.Count peers.  If they know more
			// than us, request their list.
			if v.Count > s.PeerCount() {
				if err := t.Write(s.secret.Identity,
					PeerListRequest{}); err != nil {
					log.Warningf("peer list request %v: %v",
						id, err)
				}
			}

		case *PeerListRequest:
			peers := s.knownPeerList(*id)
			if err := t.Write(s.secret.Identity,
				PeerListResponse{Peers: peers}); err != nil {
				log.Warningf("peer list response %v: %v",
					id, err)
			}

		case *PeerListResponse:
			peers := v.Peers
			if len(peers) > maxGossipPeers {
				log.Warningf("peer list from %v truncated: "+
					"%d > %d", id, len(peers),
					maxGossipPeers)
				peers = peers[:maxGossipPeers]
			}
			var learned int
			for _, pr := range peers {
				if pr.Version != ProtocolVersion {
					log.Warningf("peer %v version %d != %d, rejected",
						pr.Identity, pr.Version, ProtocolVersion)
					continue
				}
				// Validate address only if present.  Peers learned
				// from the listen path may not know their own
				// address yet — they still carry useful fields
				// like NaClPub for e2e encryption.
				if pr.Address != "" {
					if err := validatePeerAddress(pr.Address); err != nil {
						log.Warningf("peer %v bad address %q: %v",
							pr.Identity, pr.Address, err)
						continue
					}
				}
				if s.addPeer(ctx, pr) {
					learned++
				}
			}
			if learned > 0 {
				s.notifyAllPeers(ctx)
			}

		case *KeygenRequest:
			s.dispatchKeygen(*v)

		case *SignRequest:
			s.dispatchSign(*v)

		case *ReshareRequest:
			s.dispatchReshare(*v)

		case *TSSMessage:
			s.dispatchTSSMessage(*v)

		case *EncryptedPayload:
			inner, err := s.decryptPayload(v)
			if err != nil {
				log.Warningf("handle %v: decrypt: %v", id, err)
				continue
			}
			// Re-dispatch the decrypted inner command.
			switch iv := inner.(type) {
			case *PingRequest:
				err := t.Write(s.secret.Identity, PingResponse{
					OriginTimestamp: iv.OriginTimestamp,
					PeerTimestamp:   time.Now().Unix(),
				})
				if err != nil {
					log.Warningf("ping response %v: %v", id, err)
					return
				}
			case *TSSMessage:
				s.dispatchTSSMessage(*iv)
			default:
				log.Debugf("handle %v: unhandled encrypted inner %T",
					id, inner)
			}

		default:
			log.Debugf("handle %v: unhandled %T", id, payload)
		}
	}
}

// pingLoop sends periodic PingRequest heartbeats to the peer.  It exits
// when ctx is cancelled (handle() returned) or a write fails.
func (s *Server) pingLoop(ctx context.Context, id *Identity, t *Transport) {
	defer s.wg.Done()

	interval := s.cfg.PingInterval
	if interval == 0 {
		interval = pingInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := t.Write(s.secret.Identity, PingRequest{
				OriginTimestamp: time.Now().Unix(),
			})
			if err != nil {
				log.Debugf("ping %v failed: %v", id, err)
				return
			}
		}
	}
}

// refreshPeerLastSeen updates a peer's LastSeen timestamp and refreshes
// its TTL entry to prevent expiry.
func (s *Server) refreshPeerLastSeen(ctx context.Context, id Identity) {
	s.mtx.Lock()
	pr, ok := s.peers[id]
	if ok {
		pr.LastSeen = time.Now().Unix()
	}
	s.mtx.Unlock()

	if ok {
		s.peersTTL.Put(ctx, peerTTL, id,
			nil, s.peerExpired, nil)
	}
}

// maintainConnections periodically checks whether the session count is
// below PeersWanted and dials randomly-chosen known-but-unconnected
// peers to fill the gap.
func (s *Server) maintainConnections(ctx context.Context) {
	defer s.wg.Done()

	interval := s.cfg.MaintainInterval
	if interval == 0 {
		interval = maintainInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mtx.RLock()
			active := len(s.sessions)
			want := s.cfg.PeersWanted
			s.mtx.RUnlock()

			if active < want {
				s.connectRandom(ctx)
			}
		}
	}
}

// dnsResolver returns the server's DNS resolver. If none was injected
// (e.g. by tests), it returns the default system resolver.
func (s *Server) dnsResolver() *net.Resolver {
	if s.resolver != nil {
		return s.resolver
	}
	return net.DefaultResolver
}

// seed resolves DNS seed hostnames to IP addresses and kicks off
// connections. Errors are logged, not fatal — a node can still
// operate in listen-only mode or learn peers via inbound gossip.
func (s *Server) seed(ctx context.Context) {
	log.Tracef("seed")
	defer log.Tracef("seed exit")

	resolver := s.dnsResolver()
	seedCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	for _, v := range s.cfg.Seeds {
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			log.Errorf("seed parse: %v", err)
			continue
		}
		ips, err := resolver.LookupHost(seedCtx, host)
		if err != nil {
			log.Errorf("seed lookup %v: %v", host, err)
			continue
		}
		for _, ip := range ips {
			addr := net.JoinHostPort(ip, port)
			log.Infof("seed resolved %v -> %v", v, addr)
			s.wg.Add(1)
			go s.connectPeer(ctx, addr)
		}
	}
}

// verifyDNSIdentity does a forward TXT lookup on hostname and verifies
// the identity in the TXT record matches the expected identity. This
// avoids reverse DNS lookups which are unreliable.
//
// NOTE: DNS is NOT an authentication mechanism.  The real identity
// proof comes from the KX + secretbox layer.  DNS verification is
// defense-in-depth for operational assurance — it lets operators
// detect misconfigured or rogue nodes early.  An attacker who
// controls DNS responses can forge TXT records; the crypto layer
// prevents them from impersonating a node regardless.
//
// If multiple TXT records exist, only the first with v=transfunctioner
// is considered authoritative.  A hostname should publish exactly one
// record for this application.
func (s *Server) verifyDNSIdentity(ctx context.Context, hostname string, id Identity) error {
	log.Tracef("verifyDNSIdentity %v", hostname)
	defer log.Tracef("verifyDNSIdentity %v exit", hostname)
	resolver := s.dnsResolver()
	txts, err := resolver.LookupTXT(ctx, hostname)
	if err != nil {
		return fmt.Errorf("dns txt lookup %v: %w", hostname, err)
	}
	if len(txts) == 0 {
		return fmt.Errorf("dns no txt records for %v", hostname)
	}
	// Try each TXT record — there may be multiple.
	for _, txt := range txts {
		m, err := kvFromTxt(txt)
		if err != nil {
			continue
		}
		if m["v"] != dnsAppName {
			continue
		}
		remoteDNSID, err := NewIdentityFromString(m["identity"])
		if err != nil {
			continue
		}
		if bytes.Equal(id[:], remoteDNSID[:]) {
			return nil
		}
		return fmt.Errorf("dns identity mismatch: got %v, want %v",
			remoteDNSID, id)
	}
	return fmt.Errorf("dns no valid txt record for %v", hostname)
}

// connectRandom picks a random known peer that has no active session
// and dials it.  Errors are logged, not fatal.
func (s *Server) connectRandom(ctx context.Context) {
	s.mtx.RLock()
	candidates := make([]PeerRecord, 0, len(s.peers))
	for id, pr := range s.peers {
		if id == s.secret.Identity {
			continue // skip self
		}
		if _, active := s.sessions[id]; active {
			continue // already connected
		}
		if pr.Address == "" {
			continue // no address to dial
		}
		candidates = append(candidates, *pr)
	}
	s.mtx.RUnlock()

	if len(candidates) == 0 {
		return
	}

	// Pick one at random to avoid topology clustering.
	pr := candidates[mrand.IntN(len(candidates))]
	log.Infof("maintainConnections: dialing %v at %v",
		pr.Identity, pr.Address)

	s.wg.Add(1)
	go s.connectPeer(ctx, pr.Address)
}

// connectPeer dials addr, performs key exchange and handshake, registers
// the session, and enters handle().  Unlike connect(), errors are logged
// rather than sent to errC — failed maintenance dials must not kill the
// server.
func (s *Server) connectPeer(ctx context.Context, addr string) {
	defer s.wg.Done()

	log.Debugf("connectPeer: %v", addr)
	defer log.Debugf("connectPeer: %v exit", addr)

	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Warningf("connectPeer dial %v: %v", addr, err)
		return
	}

	transport := new(Transport)
	greatSuccess := false
	defer func() {
		if !greatSuccess {
			if err := transport.Close(); err != nil {
				log.Errorf("connectPeer close %v: %v", addr, err)
			}
		}
	}()

	if err := transport.KeyExchange(ctx, conn); err != nil {
		log.Warningf("connectPeer kx %v: %v", addr, err)
		return
	}
	them, theirDNS, naclPub, err := transport.Handshake(ctx, s.secret, s.cfg.DNSName)
	if err != nil {
		log.Warningf("connectPeer handshake %v: %v", addr, err)
		return
	}

	if s.cfg.DNSRequired {
		if theirDNS == "" {
			log.Warningf("connectPeer %v: remote did not advertise dns name", addr)
			return
		}
		if err := s.verifyDNSIdentity(ctx, theirDNS, *them); err != nil {
			log.Warningf("connectPeer dns verify %v: %v", addr, err)
			return
		}
	}

	if err := s.newSession(them, transport); err != nil {
		log.Warningf("connectPeer session %v: %v", them, err)
		return
	}

	s.addPeer(ctx, PeerRecord{
		Identity: *them,
		Address:  addr,
		NaClPub:  naclPub,
		Version:  ProtocolVersion,
		LastSeen: time.Now().Unix(),
	})
	s.notifyAllPeers(ctx)

	log.Infof("connectPeer connected %v: %v", conn.RemoteAddr(), them)

	greatSuccess = true
	s.wg.Add(1)
	s.handle(ctx, them, transport)
}

// Collectors returns the Prometheus collectors available for the server.
func (s *Server) Collectors() []prometheus.Collector {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.promCollectors == nil {
		// Naming: https://prometheus.io/docs/practices/naming/
		s.promCollectors = []prometheus.Collector{
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "running",
				Help:      "Whether the continuum service is running",
			}, s.promRunning),
		}
	}
	return s.promCollectors
}

// Running reports whether the server is currently running.
func (s *Server) Running() bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return s.isRunning
}

// ListenAddress returns the actual address the server is listening on.
func (s *Server) ListenAddress() string {
	log.Tracef("ListenAddress")

	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return s.listenAddress
}

// Identity returns the server's identity. Only valid after Run() has been
// called.
func (s *Server) Identity() Identity {
	log.Tracef("Identity")

	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if s.secret == nil {
		return Identity{}
	}
	return s.secret.Identity
}

// SessionIdentities returns the identities of all active sessions.
func (s *Server) SessionIdentities() []Identity {
	log.Tracef("SessionIdentities")

	s.mtx.RLock()
	defer s.mtx.RUnlock()
	ids := make([]Identity, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	return ids
}

// PeerCount returns the number of known peers.
func (s *Server) PeerCount() int {
	log.Tracef("PeerCount")

	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return len(s.peers)
}

// SendTo sends a command to a remote peer, routing through the mesh if
// no direct session exists.  When no direct session is available, the
// message is sent via an arbitrary connected peer for multi-hop
// forwarding.  Returns an error if no sessions are available.
func (s *Server) SendTo(dest Identity, cmd any) error {
	log.Tracef("SendTo %v", dest)

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	// Direct session: send with routing header so the destination
	// knows this was an addressed message.
	if t, ok := s.sessions[dest]; ok {
		return t.WriteTo(s.secret.Identity, dest, defaultTTL, cmd)
	}

	// No direct session: send via first available peer for
	// multi-hop routing.  The recipient will forward based on
	// the destination header.
	for _, t := range s.sessions {
		return t.WriteTo(s.secret.Identity, dest, defaultTTL, cmd)
	}
	return errors.New("no route to destination")
}

// SendEncrypted encrypts cmd with nacl box to the destination's X25519
// public key, then routes the EncryptedPayload through the mesh.
// Intermediate nodes can read the routing header but not the payload.
func (s *Server) SendEncrypted(dest Identity, cmd any) error {
	log.Tracef("SendEncrypted %v %T", dest, cmd)

	// Look up the inner command's PayloadType.
	innerType, ok := pt2str[reflect.TypeOf(cmd)]
	if !ok {
		return fmt.Errorf("unknown command type: %T", cmd)
	}

	// Look up destination's NaCl public key.
	s.mtx.RLock()
	pr, ok := s.peers[dest]
	s.mtx.RUnlock()
	if !ok {
		return fmt.Errorf("unknown peer: %v", dest)
	}
	if len(pr.NaClPub) == 0 {
		return fmt.Errorf("peer %v has no NaCl public key", dest)
	}

	// Serialize the inner command.
	plaintext, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("marshal inner: %w", err)
	}

	// Derive our NaCl private key.
	senderPriv, err := s.secret.NaClPrivateKey()
	if err != nil {
		return fmt.Errorf("nacl private key: %w", err)
	}

	// Encrypt.
	ep, err := SealBox(plaintext, pr.NaClPub, senderPriv, s.secret.Identity, innerType)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	return s.SendTo(dest, *ep)
}

// decryptPayload decrypts an EncryptedPayload received at this node.
// Looks up the sender's NaCl public key from the peer map, derives
// our private key, opens the nacl box, and decodes using InnerType.
// The nacl box authenticates the sender implicitly — if Sender is
// tampered, the wrong public key is used and Open fails.
func (s *Server) decryptPayload(ep *EncryptedPayload) (any, error) {
	log.Tracef("decryptPayload sender %v type %v", ep.Sender, ep.InnerType)
	s.mtx.RLock()
	senderPR, ok := s.peers[ep.Sender]
	s.mtx.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown sender: %v", ep.Sender)
	}
	if len(senderPR.NaClPub) == 0 {
		return nil, fmt.Errorf("sender %v has no NaCl public key", ep.Sender)
	}

	recipientPriv, err := s.secret.NaClPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("nacl private key: %w", err)
	}

	plaintext, err := OpenBox(ep, senderPR.NaClPub, recipientPriv)
	if err != nil {
		return nil, err
	}

	// XXX Replay protection: the routing-layer dedup cache (67s TTL)
	// suppresses flood storms but does not prevent replay of encrypted
	// messages after expiry.  Once e2e encryption is used for real
	// traffic, add a per-sender nonce registry here — reject if
	// (Sender, Nonce) was already seen.  The nonce is random and
	// invariant across replays so collision == replay.  Separate
	// concern from routing dedup; needs its own TTL (ceremony
	// lifetime or similar).  TSS ceremony state machines may
	// reject stale messages anyway but defense in depth is cheap.

	// Decode using the InnerType hint.
	ct, ok := str2pt[ep.InnerType]
	if !ok {
		return nil, fmt.Errorf("unknown inner type: %v", ep.InnerType)
	}
	cmd := reflect.New(ct)
	if err := json.Unmarshal(plaintext, cmd.Interface()); err != nil {
		return nil, fmt.Errorf("unmarshal inner: %w", err)
	}
	return cmd.Interface(), nil
}

// RoutedReceived returns the count of messages that arrived at this
// node as their final destination via routing.
func (s *Server) RoutedReceived() int64 {
	return s.routedReceived.Load()
}

// Forwarded returns the count of messages this node has forwarded
// to other peers.
func (s *Server) Forwarded() int64 {
	return s.forwarded.Load()
}

// KnownPeers returns all known peer records.
func (s *Server) KnownPeers() []PeerRecord {
	log.Tracef("KnownPeers")

	s.mtx.RLock()
	defer s.mtx.RUnlock()
	records := make([]PeerRecord, 0, len(s.peers))
	for _, pr := range s.peers {
		records = append(records, *pr)
	}
	return records
}

// validatePeerAddress checks that a peer address is a well-formed
// host:port with reasonable length and no control characters.
// Loopback/private-range filtering happens at connect time, not here,
// because locally-learned addresses (e.g. our own) are valid records.
func validatePeerAddress(addr string) error {
	if len(addr) > 256 {
		return fmt.Errorf("address too long: %d", len(addr))
	}
	for _, c := range addr {
		if c < 0x20 {
			return fmt.Errorf("control character in address")
		}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("split host port: %w", err)
	}
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if port == "" || port == "0" {
		return fmt.Errorf("invalid port: %q", port)
	}
	return nil
}

// peerExpired is the TTL expiry callback for peer records.  It runs
// in its own goroutine (dispatched by the ttl package).
func (s *Server) peerExpired(_ context.Context, key, _ any) {
	id, ok := key.(Identity)
	if !ok {
		log.Errorf("peer expired: unexpected key type %T", key)
		return
	}
	s.mtx.Lock()
	delete(s.peers, id)
	s.mtx.Unlock()
	log.Debugf("peer expired: %v", id)
}

// addPeer adds or refreshes a peer record.  Returns true if the peer
// was previously unknown.  Rejects self and version mismatches.
// When updating an existing peer, preserves non-empty Address and
// NaClPub from the old record if the new record omits them.
func (s *Server) addPeer(ctx context.Context, pr PeerRecord) bool {
	log.Tracef("addPeer %v", pr.Identity)

	if pr.Version != ProtocolVersion {
		log.Warningf("addPeer %v: version %d != %d, rejected",
			pr.Identity, pr.Version, ProtocolVersion)
		return false
	}
	// Reject malformed NaCl public keys.  Zero-length is fine (peer
	// may not support e2e yet) but any other length must be exactly
	// NaClPubSize.
	if len(pr.NaClPub) > 0 && len(pr.NaClPub) != NaClPubSize {
		log.Warningf("addPeer %v: bad NaClPub length %d, rejected",
			pr.Identity, len(pr.NaClPub))
		return false
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Don't track ourselves.
	if pr.Identity == s.secret.Identity {
		return false
	}

	existing, existed := s.peers[pr.Identity]
	if existed {
		// Preserve fields the caller doesn't have.  The listen
		// path knows NaClPub but not Address; gossip may know
		// Address but not NaClPub (yet).
		if pr.Address == "" && existing.Address != "" {
			pr.Address = existing.Address
		}
		if len(pr.NaClPub) == 0 && len(existing.NaClPub) > 0 {
			pr.NaClPub = existing.NaClPub
		}
	}

	s.peers[pr.Identity] = &pr
	s.peersTTL.Put(ctx, peerTTL, pr.Identity, &pr, s.peerExpired, nil)

	if !existed {
		log.Debugf("new peer: %v at %s", pr.Identity, pr.Address)
	}
	return !existed
}

// knownPeerList returns peer records suitable for gossip, excluding
// only the specified identity (typically the requester, so we don't
// tell them about themselves).  Our own record IS included so that
// remote peers learn about us.
func (s *Server) knownPeerList(exclude Identity) []PeerRecord {
	log.Tracef("knownPeerList")

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	records := make([]PeerRecord, 0, len(s.peers))
	for id, pr := range s.peers {
		if id == exclude {
			continue
		}
		records = append(records, *pr)
	}
	return records
}

// notifyAllPeers sends a PeerNotify to all active sessions.
// Each write is bounded by the transport's 4s write deadline so
// a hung peer cannot block others.  Goroutines are intentionally
// orphaned (not tracked by s.wg) — if the write fails, we close
// the transport to aggressively cull dead sessions.
//
// XXX(marco): if a transport is closed here while a TSS keygen,
// reshare, or sign is in flight on that session, the TSS operation
// will fail.  The coordinator layer needs to handle this.
func (s *Server) notifyAllPeers(ctx context.Context) {
	log.Tracef("notifyAllPeers")

	select {
	case <-ctx.Done():
		return
	default:
	}

	s.mtx.RLock()
	count := len(s.peers)
	type dest struct {
		id Identity
		t  *Transport
	}
	targets := make([]dest, 0, len(s.sessions))
	for id, t := range s.sessions {
		targets = append(targets, dest{id: id, t: t})
	}
	s.mtx.RUnlock()

	notify := PeerNotify{Count: count}
	for _, d := range targets {
		go func(d dest) {
			if err := d.t.Write(s.secret.Identity, notify); err != nil {
				log.Warningf("peer notify %v: %v, closing", d.id, err)
				if cerr := d.t.Close(); cerr != nil {
					log.Errorf("peer notify close %v: %v", d.id, cerr)
				}
			}
		}(d)
	}
}

// registerSelfAsPeer adds our own record to the peer map so that we
// are included in gossip responses.  Self is stored directly (not via
// addPeer which skips self) and has no TTL — we never expire ourselves.
func (s *Server) registerSelfAsPeer() {
	log.Tracef("registerSelfAsPeer")

	naclPub, err := s.secret.NaClPublicKey()
	if err != nil {
		log.Errorf("registerSelfAsPeer nacl public key: %v", err)
		return
	}

	s.mtx.Lock()
	s.peers[s.secret.Identity] = &PeerRecord{
		Identity: s.secret.Identity,
		Address:  s.listenAddress,
		NaClPub:  naclPub,
		Version:  ProtocolVersion,
		LastSeen: time.Now().Unix(),
	}
	s.mtx.Unlock()
}

func (s *Server) testAndSetRunning(b bool) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	old := s.isRunning
	s.isRunning = b
	return old != s.isRunning
}

func (s *Server) promPoll(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
		}

		if s.promPollVerbose {
			s.mtx.RLock()
			log.Infof("promPoll: peers %d sessions %d",
				len(s.peers), len(s.sessions))
			s.mtx.RUnlock()
		}
	}
}

func (s *Server) promRunning() float64 {
	r := s.Running()
	if r {
		return 1
	}
	return 0
}

func (s *Server) isHealthy(_ context.Context) bool {
	return true // XXX
}

func (s *Server) health(ctx context.Context) (bool, any, error) {
	log.Tracef("health")
	defer log.Tracef("health exit")

	return s.isHealthy(ctx), Info{Online: true}, nil
}

func (s *Server) connect(ctx context.Context, c string, errC chan error) {
	defer s.wg.Done()

	log.Infof("connect: %v", c)
	defer log.Infof("connect: %v exit", c)

	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c)
	if err != nil {
		errC <- err
		return
	}

	transport := new(Transport)
	greatSuccess := false
	defer func() {
		if !greatSuccess {
			if err := transport.Close(); err != nil {
				log.Errorf("connect close %v: %v", c, err)
			}
		}
	}()

	if err := transport.KeyExchange(ctx, conn); err != nil {
		errC <- err
		return
	}
	them, theirDNS, naclPub, err := transport.Handshake(ctx, s.secret, s.cfg.DNSName)
	if err != nil {
		errC <- err
		return
	}

	if s.cfg.DNSRequired {
		if theirDNS == "" {
			errC <- errors.New("remote did not advertise dns name")
			return
		}

		// XXX potential bug; DNS is not an authentication system, and layers
		// below will prevent impersonating a node, but regardless:
		// The DNS name to check the records for here is passed as an option
		// during the handshake message exchange. As such, client verifies
		// against theirDNS (what the server claims), not the original hostname
		// the client connected to. This could allow for:
		// Client connects to "server.example.com:1234"
		//     ↓ MITM intercepts
		// MITM presents identity_m with theirDNS = "attacker.com"
		//     ↓ Client verifies
		// Client looks up attacker.com TXT → matches identity_m ✓
		//     ↓
		// Client believes it is connected to the legitimate server node.
		if err := s.verifyDNSIdentity(ctx, theirDNS, *them); err != nil {
			errC <- fmt.Errorf("dns verify: %w", err)
			return
		}
	}

	if err := s.newSession(them, transport); err != nil {
		// Duplicate session is transient (peer reconnected before
		// old session was reaped).  Don't send to errC — that
		// kills the server.  Deferred cleanup closes transport.
		log.Errorf("connect session %v: %v", them, err)
		return
	}

	// Register the peer we connected to.  We know their listen
	// address (c) — the listen side will learn ours via gossip.
	s.addPeer(ctx, PeerRecord{
		Identity: *them,
		Address:  c,
		NaClPub:  naclPub,
		Version:  ProtocolVersion,
		LastSeen: time.Now().Unix(),
	})
	s.notifyAllPeers(ctx)

	log.Infof("connected %v: %v", conn.RemoteAddr(), them)

	greatSuccess = true
	s.wg.Add(1)
	s.handle(ctx, them, transport)
}

func (s *Server) connectAll(ctx context.Context, errC chan error) {
	defer s.wg.Done()

	log.Tracef("connectAll")
	defer log.Tracef("connectAll exit")

	// XXX should we exit when we can't connect?
	for k := range s.cfg.Connect {
		s.wg.Add(1)
		go s.connect(ctx, s.cfg.Connect[k], errC)
	}
}

func (s *Server) listen(ctx context.Context, errC chan error) {
	defer s.wg.Done()

	listener, err := s.listenConfig.Listen(ctx, "tcp", s.cfg.ListenAddress)
	if err != nil {
		errC <- err
		return
	}
	s.mtx.Lock()
	s.listenAddress = listener.Addr().String()
	s.mtx.Unlock()
	s.registerSelfAsPeer()
	go func() {
		<-ctx.Done()
		if err := listener.Close(); err != nil {
			log.Errorf("listener close: %v", err)
		}
		s.deleteAllSessions()
	}()

	for {
		conn, err := listener.Accept()
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		if err != nil {
			log.Errorf("accept: %v", err)
			continue
		}

		s.mtx.RLock()
		conNum := len(s.sessions)
		s.mtx.RUnlock()
		if conNum >= s.cfg.PeersWanted {
			// XXX send a "busy" message?
			log.Debugf("server full, connection rejected: %s",
				conn.RemoteAddr())
			if err := conn.Close(); err != nil {
				log.Errorf("close connection %s: %v",
					conn.RemoteAddr(), err)
			}
			continue
		}

		// XXX this can cause rate limitting since it isn't in a go
		// routine. This is obviously a DDOS and needs fixing.
		id, transport, naclPub, err := s.newTransport(ctx, conn)
		if err != nil {
			log.Errorf("transport: %v", err)
			continue
		}

		// Insert into sessions
		if err := s.newSession(id, transport); err != nil {
			log.Errorf("session: %v", err)
			continue
		}

		// Register peer with NaCl public key.  Address is empty
		// because we don't know their listen address — they'll
		// advertise it via gossip.
		s.addPeer(ctx, PeerRecord{
			Identity: *id,
			NaClPub:  naclPub,
			Version:  ProtocolVersion,
			LastSeen: time.Now().Unix(),
		})

		// Tell existing peers we learned about someone new so
		// they can request our updated peer list.
		s.notifyAllPeers(ctx)

		log.Infof("connected %v: %v", conn.RemoteAddr(), id)

		// handle connection
		s.wg.Add(1)
		go s.handle(ctx, id, transport)
	}
}

func (s *Server) initPaillierPrimes(pctx context.Context) error {
	log.Tracef("initPaillierPrimes")
	defer log.Tracef("initPaillierPrimes exit")

	ctx, cancel := context.WithTimeout(pctx, 1*time.Minute)
	defer cancel()

	preparamsFilename := filepath.Join(s.data, "preparams.json")
	ppf, err := os.Open(preparamsFilename)
	if errors.Is(err, os.ErrNotExist) {
		log.Infof("Generating TSS Paillier primes")
		lpp, err := keygen.GeneratePreParamsWithContextAndRandom(ctx, rand.Reader)
		if err != nil {
			return err
		}
		jpp, err := json.MarshalIndent(lpp, "  ", "  ")
		if err != nil {
			return err
		}
		err = os.WriteFile(preparamsFilename, jpp, 0o400)
		if err != nil {
			return err
		}
		s.preParams = *lpp
		log.Infof("Generating TSS Paillier primes complete")
		return nil
	} else if err != nil {
		return err
	}

	if err := json.NewDecoder(ppf).Decode(&s.preParams); err != nil {
		return err
	}
	return ppf.Close()
}

// Run starts the server, listens for connections, and blocks until the
// context is cancelled or a fatal error occurs.
func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return errors.New("continuum already running")
	}
	defer s.testAndSetRunning(false)

	// Make sure we have a valid secret
	var err error
	s.secret, err = NewSecretFromString(s.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	// TODO(go1.26): wrap key loading in runtime/secret.Do for forward
	// secrecy.  Go strings are immutable so we cannot zero the backing
	// array; setting to "" only drops the reference.  secret.Do will
	// zero stack, registers, and heap allocations when they become
	// unreachable.  Requires GOEXPERIMENT=runtimesecret.
	s.cfg.PrivateKey = ""

	// Setup home
	s.cfg.Home, err = homedir.Expand(s.cfg.Home)
	if err != nil {
		return fmt.Errorf("expand: %w", err)
	}
	s.data = filepath.Join(s.cfg.Home, s.secret.String())
	err = os.MkdirAll(s.data, 0o700)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// Initialize peer TTL map.
	peersTTL, err := ttl.New(s.cfg.PeersWanted*2, true)
	if err != nil {
		return fmt.Errorf("peer ttl: %w", err)
	}
	s.peersTTL = peersTTL

	// Initialize message dedup cache.
	seen, err := ttl.New(seenCapacity, true)
	if err != nil {
		return fmt.Errorf("seen ttl: %w", err)
	}
	s.seen = seen

	// Read or generate Paillier primes.
	err = s.initPaillierPrimes(ctx)
	if err != nil {
		return fmt.Errorf("party: %w", err)
	}

	// Initialize TSS engine with encrypted transport bridge.
	s.tssCtx = ctx
	s.stt = newServerTSSTransport(s)
	tssDir := filepath.Join(s.data, "tss")
	s.tssStore, err = NewTSSStore(tssDir, s.secret)
	if err != nil {
		return fmt.Errorf("tss store: %w", err)
	}
	s.tss = NewTSS(s.secret.Identity, s.tssStore, s.stt)

	// pprof
	if s.cfg.PprofListenAddress != "" {
		p, err := pprof.NewServer(&pprof.Config{
			ListenAddress: s.cfg.PprofListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create pprof server: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := p.Run(ctx); !errors.Is(err, context.Canceled) {
				log.Errorf("pprof server terminated with error: %v", err)
				return
			}
			log.Infof("pprof server clean shutdown")
		}()
	}

	// Prometheus
	if s.cfg.PrometheusListenAddress != "" {
		d, err := deucalion.New(&deucalion.Config{
			ListenAddress: s.cfg.PrometheusListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := d.Run(ctx, s.Collectors(), s.health); !errors.Is(err, context.Canceled) {
				log.Errorf("prometheus terminated with error: %v", err)
				return
			}
			log.Infof("prometheus clean shutdown")
		}()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			err := s.promPoll(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Errorf("prometheus poll terminated with error: %v", err)
				}
				return
			}
		}()
	}

	errC := make(chan error)
	if s.cfg.ListenAddress != "" {
		s.wg.Add(1)
		go s.listen(ctx, errC)
	}

	if len(s.cfg.Connect) != 0 {
		s.wg.Add(1)
		go s.connectAll(ctx, errC)
	} else if len(s.cfg.Seeds) != 0 {
		s.seed(ctx)
	}

	// Periodically dial gossip-learned peers when below PeersWanted.
	s.wg.Add(1)
	go s.maintainConnections(ctx)

	log.Infof("Identity: %v", s.secret)

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errC:
	}
	cancel()

	log.Infof("continuum service shutting down")
	s.wg.Wait()
	log.Infof("continuum service clean shutdown")

	return err
}
