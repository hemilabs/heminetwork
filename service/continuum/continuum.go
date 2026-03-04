// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

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

	// DNS verification modes for Config.DNS.
	DNSOff     = "off"     // No DNS verification.
	DNSForward = "forward" // Forward TXT verify hostname peers; reject IP-only.
	DNSReverse = "reverse" // Reverse DNS verify IP peers.
	DNSAll     = "all"     // Forward on hostnames, reverse on IPs.

	// peerTTL is the duration a peer record stays alive without
	// refresh.  Prime to avoid resonance with other timers.
	peerTTL = 67 * time.Second

	// maxGossipPeers caps the number of peer records accepted in a
	// single PeerListResponse to prevent memory exhaustion from a
	// malicious peer.
	maxGossipPeers = 256

	// pingInterval is how often each session sends a heartbeat.
	// Prime to avoid resonance with other periodic timers.
	pingInterval = 41 * time.Second

	// pingTimeout is how long to wait for a pong before closing
	// the transport.  Prime, well under pingInterval.
	pingTimeout = 13 * time.Second

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

	// defaultPreParamsTimeout is the default timeout for Paillier
	// safe prime generation.  Sufficient for modern hardware;
	// increase for slow CI runners.
	defaultPreParamsTimeout = 1 * time.Minute

	// initialPingTimeout is how long to wait for the first pong
	// after connecting.  Fired immediately post-KX — real peers
	// reply in milliseconds; ephemeral clients (hemictl) never
	// pong and get reaped.  Short fuse, no settling.
	initialPingTimeout = 5 * time.Second
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
	DNS                     string // DNSOff, DNSForward, DNSReverse, DNSAll
	Hostname                string // Hostname to advertise in gossip; empty = IP
	Home                    string
	ListenAddress           string
	LogLevel                string
	PeersWanted             int
	PingInterval            time.Duration // 0 uses default (61s)
	PingTimeout             time.Duration // 0 uses default (19s)
	MaintainInterval        time.Duration // 0 uses default (67s)
	PprofListenAddress      string
	PreParamsTimeout        time.Duration // 0 uses default (1m); increase for slow CI
	PrivateKey              string
	PrometheusListenAddress string
	PrometheusNamespace     string
	Seeds                   []string // DNS seed hostnames, format host:port
}

// CeremonyInfo tracks the state of an active TSS ceremony.
type CeremonyInfo struct {
	Type        CeremonyType    `json:"type"`
	StartTime   int64           `json:"start_time"` // unix timestamp
	Status      string          `json:"status"`     // CeremonyRunning, CeremonyComplete, CeremonyFailed
	Error       string          `json:"error,omitempty"`
	Coordinator Identity        `json:"coordinator"` // node responsible for broadcasting result
	KeyID       []byte          `json:"key_id,omitempty"`
	Committee   []Identity      `json:"committee,omitempty"`
	ctx         context.Context // canceled on terminal state
	cancel      context.CancelFunc
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
	ponged   map[Identity]struct{} // peers that responded to at least one ping

	// Secrets
	secret *Secret

	// TSS
	preParams keygen.LocalPreParams
	tss       TSS
	tssStore  TSSStore
	stt       *serverTSSTransport
	tssCtx    context.Context

	// Ceremony tracking — admin RPCs report status from this map.
	ceremonies map[CeremonyID]*CeremonyInfo

	// Ceremony initiation — the seam between external triggers
	// (blockchain or debug) and the TSS engine.
	initiator CeremonyInitiator
	debugInit *debugInitiator // nil in production (blockchain initiator)

	// Listener
	listenConfig  *net.ListenConfig
	listenAddress string // Actual bound address after Listen()

	// handshakeSem limits concurrent handshake goroutines to
	// PeersWanted.  Acquired in the accept loop before spawning
	// a goroutine, released after KX completes (success or
	// failure).  Prevents goroutine exhaustion from connection
	// floods.
	handshakeSem chan struct{}

	// DNS resolver; nil uses net.DefaultResolver.  Tests inject a
	// mock resolver pointing at an in-process DNS server.
	resolver *net.Resolver

	// dnsLookups rate-limits DNS verification per remote IP.
	// Prevents attackers from forcing unbounded TXT queries by
	// repeatedly connecting.  Keyed by IP string, TTL of 60s.
	dnsLookups *ttl.TTL

	// Peer tracking
	peers    map[Identity]*PeerRecord // all known peers
	peersTTL *ttl.TTL                 // expiry for known peers
	pings    *ttl.TTL                 // unanswered ping timeout

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
// DNS defaults to DNSForward — operators must set Hostname or
// explicitly opt out with DNS="off".
func NewDefaultConfig() *Config {
	return &Config{
		DNS:                 DNSForward,
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

	// Validate DNS configuration.
	switch cfg.DNS {
	case DNSOff, DNSForward, DNSReverse, DNSAll:
	default:
		return nil, fmt.Errorf("invalid DNS mode %q: must be \"off\", \"forward\", \"reverse\", or \"all\"", cfg.DNS)
	}
	if (cfg.DNS == DNSForward || cfg.DNS == DNSAll) && cfg.Hostname == "" {
		return nil, fmt.Errorf("DNS=%q requires Hostname to be set", cfg.DNS)
	}

	di := newDebugInitiator()
	return &Server{
		cfg:          cfg,
		listenConfig: &net.ListenConfig{},
		sessions:     make(map[Identity]*Transport, cfg.PeersWanted),
		ponged:       make(map[Identity]struct{}, cfg.PeersWanted),
		peers:        make(map[Identity]*PeerRecord),
		ceremonies:   make(map[CeremonyID]*CeremonyInfo),
		handshakeSem: make(chan struct{}, cfg.PeersWanted),
		initiator:    di,
		debugInit:    di,
		tssCtx:       context.Background(), // replaced by Run() with lifecycle context
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
	if s.ponged != nil {
		delete(s.ponged, *id)
	}
	return t.Close()
}

func (s *Server) deleteAllSessions() {
	type idTransport struct {
		id Identity
		t  *Transport
	}

	s.mtx.Lock()
	closing := make([]idTransport, 0, len(s.sessions))
	for id, t := range s.sessions {
		closing = append(closing, idTransport{id, t})
		delete(s.sessions, id)
	}
	s.mtx.Unlock()

	for _, it := range closing {
		if err := it.t.Close(); err != nil {
			log.Errorf("close session %v: %v", it.id, err)
		}
	}
}

func (s *Server) newTransport(ctx context.Context, conn net.Conn) (*Identity, *Transport, []byte, error) {
	transport, err := NewTransportFromCurve(ecdh.X25519()) // Only supported curve.
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new transport: %w", err)
	}

	err = transport.KeyExchange(ctx, conn)
	if err != nil {
		// Expected from port scanners, TLS probes, wrong protocol.
		return nil, nil, nil, fmt.Errorf("key exchange: %w", err)
	}

	// After KX, transport owns conn.  Ensure cleanup on failure so
	// the remote side gets a connection reset instead of hanging.
	ok := false
	defer func() {
		if !ok {
			transport.Close()
		}
	}()

	id, naclPub, err := transport.Handshake(ctx, s.secret)
	if err != nil {
		// Expected from misconfigured peers and version mismatches.
		return nil, nil, nil, fmt.Errorf("handshake: %w", err)
	}

	// DNS verification for incoming connections.  In forward mode
	// we cannot verify (no hostname for the remote yet — they'll
	// gossip it later).  In reverse/all mode, reverse-verify the
	// remote IP.
	if err := s.verifyInboundDNS(ctx, conn.RemoteAddr(), *id); err != nil {
		return nil, nil, nil, err
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
// For routed (non-broadcast) messages, the destination is included
// in the dedup key so that identical payloads sent to different
// destinations are not falsely deduplicated.  Broadcast messages
// use PayloadHash alone since they share BroadcastDestination and
// require global dedup.
//
// NOTE: after seenTTL expires (~67s), a replayed message will be
// accepted again.  This is acceptable for idempotent commands
// (PingRequest) but should be reconsidered if non-idempotent
// commands are routed through the mesh.
func (s *Server) isDuplicate(ctx context.Context, h *Header) bool {
	log.Tracef("isDuplicate %v", h.PayloadHash)

	key := h.PayloadHash.String()
	if h.Destination != nil && *h.Destination != BroadcastDestination {
		key += ":" + h.Destination.String()
	}
	if _, _, err := s.seen.Get(key); err == nil {
		return true
	}
	s.seen.Put(ctx, seenTTL, key, struct{}{}, nil, nil)
	return false
}

// defaultTTL is the hop count for originated routed messages.
const defaultTTL = 8

// ceremonyMaxAge is how long completed/failed ceremonies remain in the
// tracking map before eviction.  Running ceremonies are never evicted.
const ceremonyMaxAge = 30 * time.Minute

// ceremonyEvictInterval is the tick period for the eviction goroutine.
const ceremonyEvictInterval = 5 * time.Minute

// tcpKeepAlivePeriod is the TCP keepalive probe interval.  With Linux
// default 9 retries, worst-case dead-peer detection is ~153s.
// Complements the application-layer ping TTL (~54s worst case).
const tcpKeepAlivePeriod = 17 * time.Second

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

// forwardBroadcast relays a broadcast message to all connected peers
// except the source.  TTL is decremented.  Called from handle() after
// isDuplicate and whitelist checks pass.
func (s *Server) forwardBroadcast(header *Header, payload any, from *Identity) {
	log.Tracef("forwardBroadcast %v TTL %d", header.Origin, header.TTL)

	fwd := *header
	fwd.TTL--

	// Collect transports under lock, write outside to avoid
	// blocking all broadcast forwarding on a slow peer.
	type target struct {
		id Identity
		t  *Transport
	}
	s.mtx.RLock()
	targets := make([]target, 0, len(s.sessions))
	for id, t := range s.sessions {
		if from != nil && id == *from {
			continue
		}
		targets = append(targets, target{id, t})
	}
	s.mtx.RUnlock()

	var sent int
	for _, tgt := range targets {
		if err := tgt.t.WriteHeader(fwd, payload); err != nil {
			log.Debugf("broadcast forward to %v: %v", tgt.id, err)
		} else {
			s.forwarded.Add(1)
			sent++
		}
	}
	log.Debugf("broadcast %v: forwarded to %d peer(s) TTL %d",
		header.Origin, sent, fwd.TTL)
}

// Broadcast sends a command to all connected peers using the broadcast
// primitive.  The payload type must be in broadcastWhitelist.  The
// message is sent with BroadcastDestination and defaultTTL.  Each
// receiver processes locally and forwards to its peers (flood + dedup).
func (s *Server) Broadcast(cmd any) error {
	return s.broadcastWithTTL(cmd, defaultTTL)
}

// broadcastWithTTL is the inner implementation of Broadcast.  It
// accepts a custom TTL for testing (e.g., verifying TTL expiry).
func (s *Server) broadcastWithTTL(cmd any, ttl uint8) error {
	if !IsBroadcastable(cmd) {
		return fmt.Errorf("payload type %T is not broadcastable", cmd)
	}

	pt, ok := pt2str[reflect.TypeOf(cmd)]
	if !ok {
		return fmt.Errorf("unknown command type: %T", cmd)
	}
	hash, payload, err := NewPayloadFromCommand(cmd)
	// untested: NewPayloadFromCommand uses json.Marshal on wire types; cannot fail with valid cmd
	if err != nil {
		return err
	}

	dest := BroadcastDestination
	header, err := json.Marshal(Header{
		PayloadType: pt,
		PayloadHash: *hash,
		Origin:      s.secret.Identity,
		Destination: &dest,
		TTL:         ttl,
	})
	// untested: json.Marshal of Header (strings + []byte) cannot fail
	if err != nil {
		return err
	}
	msg := append(header, payload...)

	// Collect transports under lock, write outside to avoid
	// blocking all broadcast sends on a slow peer.
	type target struct {
		id Identity
		t  *Transport
	}
	s.mtx.RLock()
	targets := make([]target, 0, len(s.sessions))
	for id, t := range s.sessions {
		targets = append(targets, target{id, t})
	}
	s.mtx.RUnlock()

	var sent int
	for _, tgt := range targets {
		if err := tgt.t.write(writeTimeout, msg); err != nil {
			log.Debugf("broadcast to %v: %v", tgt.id, err)
		} else {
			sent++
		}
	}
	log.Debugf("Broadcast %T: sent to %d peer(s)", cmd, sent)
	return nil
}

func (s *Server) handle(ctx context.Context, id *Identity, t *Transport) {
	// Per-session context: cancelled when handle() exits (read
	// error, shutdown, etc.), which also stops the pingLoop.
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()
	defer func() {
		// Disarm any pending ping timeout so pingExpired does
		// not fire on an already-closing transport.
		_, _ = s.pings.Delete(*id)
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

	// Liveness ping — fired immediately, short fuse.  Real peers
	// pong in milliseconds; ephemeral clients (hemictl) never
	// pong and get reaped when the timeout fires pingExpired.
	// The regular pingLoop takes over after its first tick.
	// Write failure is not fatal — the pingLoop will retry.
	if err := t.Write(s.secret.Identity, PingRequest{
		OriginTimestamp: time.Now().Unix(),
	}); err != nil {
		log.Warningf("initial ping %v: %v", id, err)
	} else {
		s.pings.Put(sessionCtx, initialPingTimeout, *id, t, s.pingExpired, nil)
	}

	for {
		header, payload, _, err := t.ReadEnvelope()
		if err != nil {
			// Debug not Error — fires on every normal session
			// teardown (transport close breaks ReadEnvelope).
			log.Debugf("read %v: %v", id, err)
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
		// Broadcast: if destination is BroadcastDestination,
		// forward to all peers except source, then fall
		// through to local dispatch.
		if header.Destination != nil && *header.Destination == BroadcastDestination {
			if header.TTL == 0 {
				log.Debugf("handle %v: broadcast TTL expired", id)
				continue
			}
			if !IsBroadcastable(payload) {
				log.Warningf("handle %v: non-broadcastable type %T dropped", id, payload)
				continue
			}
			s.forwardBroadcast(header, payload, id)
			// Fall through to dispatch for local processing.
		} else if header.Destination != nil && *header.Destination != s.secret.Identity {
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

		// Dispatch payload through the registration-based handler map.
		dc := &dispatchCtx{
			ctx:        ctx,
			sessionCtx: sessionCtx,
			s:          s,
			id:         id,
			t:          t,
		}
		if dispatchPayload(dc, payload) {
			return
		}
	}
}

// pingLoop sends periodic PingRequest heartbeats to the peer.  It exits
// when ctx is cancelled (handle() returned) or a write fails.
// After each ping, a TTL is armed; if no pong arrives before it
// expires, pingExpired closes the transport which breaks the blocked
// read in handle().
func (s *Server) pingLoop(ctx context.Context, id *Identity, t *Transport) {
	defer s.wg.Done()

	interval := s.cfg.PingInterval
	if interval == 0 {
		interval = pingInterval
	}
	timeout := s.cfg.PingTimeout
	if timeout == 0 {
		timeout = pingTimeout
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Cancel any previous unanswered ping.
			_ = s.pings.Cancel(*id)

			err := t.Write(s.secret.Identity, PingRequest{
				OriginTimestamp: time.Now().Unix(),
			})
			if err != nil {
				log.Debugf("ping %v failed: %v", id, err)
				return
			}

			// Arm timeout — pingExpired closes the transport
			// if no pong arrives.
			s.pings.Put(ctx, timeout, *id, t, s.pingExpired, nil)
		}
	}
}

// pingExpired is called when a ping TTL expires without a pong.
// Closing the transport breaks the blocked ReadEnvelope in handle(),
// which tears down the session.
func (s *Server) pingExpired(_ context.Context, key any, value any) {
	id, ok := key.(Identity)
	if !ok {
		log.Errorf("pingExpired: invalid key type: %T", key)
		return
	}
	t, ok := value.(*Transport)
	if !ok {
		log.Errorf("pingExpired %v: invalid value type: %T", id, value)
		return
	}
	log.Debugf("pingExpired %v: closing transport", id)
	t.Close()
}

// refreshPeerLastSeen updates a peer's LastSeen timestamp and refreshes
// its TTL entry to prevent expiry.
func (s *Server) refreshPeerLastSeen(ctx context.Context, id Identity) {
	s.mtx.Lock()
	pr, ok := s.peers[id]
	if ok {
		pr.LastSeen = time.Now().Unix()
		if s.ponged != nil {
			s.ponged[id] = struct{}{}
		}
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
// the identity in the TXT record matches the expected identity.
//
// DNS verification is defense-in-depth for operational assurance — it
// lets operators detect misconfigured or rogue nodes early.  The real
// identity proof comes from the KX + secretbox layer.  An attacker who
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

// isHostname returns true if host is a DNS name (not an IP address).
func isHostname(host string) bool {
	return net.ParseIP(host) == nil
}

// dnsRateLimited returns true if the remote IP has exceeded the DNS
// lookup rate limit.  Keyed by IP string with a 60s TTL — each IP
// gets one lookup attempt per minute.  The handshake semaphore limits
// concurrency; this limits frequency.
func (s *Server) dnsRateLimited(remoteAddr net.Addr) bool {
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return false
	}
	if _, _, err := s.dnsLookups.Get(host); err == nil {
		return true // already looked up recently
	}
	// context.Background is intentional: the rate limit entry must
	// outlive the caller's request context.  If we used the caller's
	// ctx, canceling the request would cancel the TTL entry and
	// defeat the rate limit.
	s.dnsLookups.Put(context.Background(), 60*time.Second,
		host, struct{}{}, nil, nil)
	return false
}

// verifyOutboundDNS verifies DNS identity for outbound connections
// (connect and connectPeer).  The dial target determines the
// verification method:
//
//   - Hostname target: forward TXT lookup (DNS="forward" or "all")
//   - IP target: reverse DNS lookup (DNS="reverse" or "all")
//   - DNS="off": no verification
//
// In forward mode, IP-only peers are rejected — only nodes that
// advertise a verifiable hostname in gossip are accepted.
func (s *Server) verifyOutboundDNS(ctx context.Context, dialTarget string, remoteAddr net.Addr, id Identity) error {
	if s.cfg.DNS == DNSOff {
		return nil
	}

	host, _, err := net.SplitHostPort(dialTarget)
	if err != nil {
		host = dialTarget
	}

	if isHostname(host) {
		// Forward verification — available in forward and all modes.
		switch s.cfg.DNS {
		case DNSForward, DNSAll:
			if s.dnsRateLimited(remoteAddr) {
				return fmt.Errorf("dns rate limited: %v", remoteAddr)
			}
			return s.verifyDNSIdentity(ctx, host, id)
		}
		return nil
	}

	// IP target — forward mode rejects IP-only peers.
	switch s.cfg.DNS {
	case DNSForward:
		return fmt.Errorf("dns forward: rejecting IP-only peer %v", dialTarget)
	case DNSReverse, DNSAll:
		if s.dnsRateLimited(remoteAddr) {
			return fmt.Errorf("dns rate limited: %v", remoteAddr)
		}
		ok, err := VerifyRemoteDNSIdentity(ctx, s.dnsResolver(), remoteAddr, id)
		if err != nil {
			return fmt.Errorf("dns reverse verify %v: %w", remoteAddr, err)
		}
		if !ok {
			return fmt.Errorf("dns reverse identity mismatch: %v", remoteAddr)
		}
		return nil
	}
	return nil
}

// verifyInboundDNS verifies DNS identity for incoming connections.
// Incoming connections only have a remote IP — no hostname is known
// until the peer gossips its address.
//
//   - DNS="forward": accept without verification (no hostname to check)
//   - DNS="reverse" or "all": reverse DNS verify the remote IP
//   - DNS="off": no verification
func (s *Server) verifyInboundDNS(ctx context.Context, remoteAddr net.Addr, id Identity) error {
	switch s.cfg.DNS {
	case DNSReverse, DNSAll:
		if s.dnsRateLimited(remoteAddr) {
			return fmt.Errorf("dns rate limited: %v", remoteAddr)
		}
		ok, err := VerifyRemoteDNSIdentity(ctx, s.dnsResolver(), remoteAddr, id)
		if err != nil {
			return fmt.Errorf("dns reverse verify %v: %w", remoteAddr, err)
		}
		if !ok {
			return fmt.Errorf("dns reverse identity mismatch: %v", remoteAddr)
		}
	}
	return nil
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
		// In forward mode, skip peers that only advertise an IP
		// address — they cannot be verified via TXT lookup.
		if s.cfg.DNS == DNSForward || s.cfg.DNS == DNSAll {
			if host, _, err := net.SplitHostPort(pr.Address); err == nil {
				if !isHostname(host) {
					continue
				}
			}
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

// tcpKeepAlive enables TCP keepalive on conn with the given period.
// Non-TCP connections (e.g. net.Pipe in tests) are a silent no-op.
func tcpKeepAlive(conn net.Conn, period time.Duration) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tc.SetKeepAlive(true); err != nil {
		log.Warningf("tcp keepalive: %v", err)
		return
	}
	if err := tc.SetKeepAlivePeriod(period); err != nil {
		log.Warningf("tcp keepalive period: %v", err)
	}
}

func (s *Server) connectPeer(ctx context.Context, addr string) {
	defer s.wg.Done()

	log.Debugf("connectPeer: %v", addr)
	defer log.Debugf("connectPeer: %v exit", addr)

	// Reject self before wasting a dial.
	s.mtx.RLock()
	selfAddr := s.listenAddress
	s.mtx.RUnlock()
	if selfAddr != "" && addr == selfAddr {
		log.Debugf("connectPeer: skipping self %v", addr)
		return
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Warningf("connectPeer dial %v: %v", addr, err)
		return
	}
	tcpKeepAlive(conn, tcpKeepAlivePeriod)

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
	them, naclPub, err := transport.Handshake(ctx, s.secret)
	if err != nil {
		log.Warningf("connectPeer handshake %v: %v", addr, err)
		return
	}

	// Defense-in-depth: reject self even if the address didn't
	// match (e.g. hostname resolved to our IP, NAT hairpin).
	if *them == s.secret.Identity {
		log.Warningf("connectPeer: connected to self at %v", addr)
		return
	}

	// DNS verification based on peer address from gossip.
	// Hostname addresses get forward TXT verification.
	// IP addresses get reverse DNS verification (if enabled).
	if err := s.verifyOutboundDNS(ctx, addr, conn.RemoteAddr(), *them); err != nil {
		log.Warningf("connectPeer dns %v: %v", addr, err)
		return
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

	// Broadcast-type payloads must use Broadcast(), not point-to-point
	// e2e encryption.  This guard prevents accidental misuse.
	if IsBroadcastable(cmd) {
		return ErrUseBroadcast
	}

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
	// untested: json.Marshal of wire command types cannot fail (no channels, funcs, or cycles)
	if err != nil {
		return fmt.Errorf("marshal inner: %w", err)
	}

	// Derive our NaCl private key.
	senderPriv, err := s.secret.NaClPrivateKey()
	// untested: NaClPrivateKey derives curve25519 from valid secp256k1; cannot fail with valid secret
	if err != nil {
		return fmt.Errorf("nacl private key: %w", err)
	}

	// Encrypt.
	ep, err := SealBox(plaintext, pr.NaClPub, senderPriv, s.secret.Identity, innerType)
	// untested: SealBox wraps rand.Read + secretbox.Seal; fails only on OS entropy exhaustion
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
	// untested: NaClPrivateKey derives curve25519 from valid secp256k1; cannot fail with valid secret
	if err != nil {
		return nil, fmt.Errorf("nacl private key: %w", err)
	}

	plaintext, err := OpenBox(ep, senderPR.NaClPub, recipientPriv)
	if err != nil {
		return nil, err
	}

	// Replay protection analysis (SOW4 §4 — deferred).
	//
	// The routing-layer dedup cache (67s TTL) prevents immediate
	// replay of routed messages.  Beyond that window:
	//
	//  - Ceremony-initiating messages (KeygenRequest, SignRequest,
	//    ReshareRequest): in production these originate from the
	//    blockchain watcher via CeremonyInitiator, never from the
	//    wire.  Debug-mode wire initiation is build-tagged out of
	//    production binaries.  No replay risk in production.
	//
	//  - TSS round messages (TSSMessage): tss-lib state machines
	//    reject duplicate or out-of-order round messages internally.
	//    Replay after dedup expiry is harmless.
	//
	//  - CeremonyResult (broadcast): handleCeremonyResult is
	//    idempotent — duplicate results for a completed ceremony
	//    are logged and dropped.
	//
	// If a future protocol change routes non-idempotent encrypted
	// commands through the mesh, add a per-sender nonce registry
	// here: reject if (Sender, Nonce) was already seen.  The NaCl
	// box nonce is random per SealBox and invariant across replays,
	// so collision == replay.

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

// isLocalhost reports whether the given net.Addr is a loopback address.
func isLocalhost(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// requireAdmin checks that the transport originates from localhost.
// Returns false and logs a warning if rejected.  Used by admin RPCs.
func requireAdmin(t *Transport, id *Identity) bool {
	if isLocalhost(t.RemoteAddr()) {
		return true
	}
	log.Warningf("handle %v: admin request from non-localhost, rejected", id)
	return false
}

// registerCeremony records a new ceremony in the tracking map.
// The ceremony context derives from s.tssCtx so server shutdown
// propagates cancellation to all waiting callers.
func (s *Server) registerCeremony(cid CeremonyID, ct CeremonyType, coordinator Identity, committee []Identity) {
	ctx, cancel := context.WithCancel(s.tssCtx)
	s.mtx.Lock()
	s.ceremonies[cid] = &CeremonyInfo{
		Type:        ct,
		StartTime:   time.Now().Unix(),
		Status:      CeremonyRunning,
		Coordinator: coordinator,
		Committee:   committee,
		ctx:         ctx,
		cancel:      cancel,
	}
	s.mtx.Unlock()
}

// completeCeremony marks a tracked ceremony as complete.
// Cancel is called outside the lock to avoid potential deadlock
// if a ci.ctx.Done() waiter touches s.mtx.
func (s *Server) completeCeremony(cid CeremonyID) {
	s.mtx.Lock()
	ci, ok := s.ceremonies[cid]
	if ok {
		ci.Status = CeremonyComplete
	}
	s.mtx.Unlock()
	if ok {
		ci.cancel()
	}
}

// failCeremony marks a tracked ceremony as failed with an error.
func (s *Server) failCeremony(cid CeremonyID, reason string) {
	s.mtx.Lock()
	ci, ok := s.ceremonies[cid]
	if ok {
		ci.Status = CeremonyFailed
		ci.Error = reason
	}
	s.mtx.Unlock()
	if ok {
		ci.cancel()
	}
}

// handleCeremonyResult processes a broadcast CeremonyResult.  If this
// node is already tracking the ceremony (as a committee member), the
// local dispatchKeygen/dispatchSign goroutine owns the status
// transition — the broadcast is a no-op.  For non-committee nodes
// this is the only notification — register the ceremony as complete
// or failed.
func (s *Server) handleCeremonyResult(r CeremonyResult) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	_, ok := s.ceremonies[r.CeremonyID]
	if ok {
		// Committee member: local goroutine owns status; ignore
		// the broadcast to avoid racing ahead of SaveKeyShare.
		return
	}

	// Non-committee node: first time seeing this ceremony.
	// Pre-cancelled context.Background() — this record is status-only,
	// no goroutine lifecycle is attached.  The cancel() call is
	// immediate; the ctx exists solely to satisfy the CeremonyInfo
	// struct fields so that ci.ctx.Done() is already closed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ci := &CeremonyInfo{
		Type:      CeremonyKeygen, // broadcast only comes from keygen for now
		StartTime: time.Now().Unix(),
		ctx:       ctx,
		cancel:    cancel,
	}
	if r.Success {
		ci.Status = CeremonyComplete
	} else {
		ci.Status = CeremonyFailed
		ci.Error = r.Error
	}
	s.ceremonies[r.CeremonyID] = ci
}

// handlePeerListAdmin builds a PeerListAdminResponse from the peer
// and session maps.
func (s *Server) handlePeerListAdmin() PeerListAdminResponse {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	resp := PeerListAdminResponse{
		Peers: make([]PeerAdminRecord, 0, len(s.peers)),
	}
	for id, pr := range s.peers {
		_, connected := s.sessions[id]
		_, hasPonged := s.ponged[id]
		self := id == s.secret.Identity
		resp.Peers = append(resp.Peers, PeerAdminRecord{
			PeerRecord: *pr,
			Connected:  connected,
			Live:       self || (connected && hasPonged),
			Self:       self,
		})
	}
	return resp
}

// handleCeremonyStatus returns the status of a specific ceremony.
func (s *Server) handleCeremonyStatus(cid CeremonyID) CeremonyStatusResponse {
	s.mtx.RLock()
	ci, ok := s.ceremonies[cid]
	s.mtx.RUnlock()

	if !ok {
		return CeremonyStatusResponse{
			CeremonyID: cid,
			Found:      false,
		}
	}
	return CeremonyStatusResponse{
		CeremonyID: cid,
		Found:      true,
		Type:       ci.Type.String(),
		Status:     ci.Status,
		StartTime:  ci.StartTime,
		KeyID:      ci.KeyID,
		Committee:  ci.Committee,
		Error:      ci.Error,
	}
}

// handleCeremonyList returns the status of all known ceremonies.
func (s *Server) handleCeremonyList() CeremonyListResponse {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	resp := CeremonyListResponse{
		Ceremonies: make([]CeremonyStatusResponse, 0, len(s.ceremonies)),
	}
	for cid, ci := range s.ceremonies {
		resp.Ceremonies = append(resp.Ceremonies, CeremonyStatusResponse{
			CeremonyID: cid,
			Found:      true,
			Type:       ci.Type.String(),
			Status:     ci.Status,
			StartTime:  ci.StartTime,
			KeyID:      ci.KeyID,
			Committee:  ci.Committee,
			Error:      ci.Error,
		})
	}
	return resp
}

// evictCeremonies removes completed/failed ceremonies older than
// ceremonyMaxAge from the tracking map.  Running ceremonies are never
// evicted.  Called periodically from a goroutine started by Run().
func (s *Server) evictCeremonies(ctx context.Context) {
	defer s.wg.Done()
	log.Tracef("evictCeremonies")
	defer log.Tracef("evictCeremonies exit")

	ticker := time.NewTicker(ceremonyEvictInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		cutoff := time.Now().Add(-ceremonyMaxAge).Unix()
		var evicted int
		s.mtx.Lock()
		for cid, ci := range s.ceremonies {
			if ci.Status == CeremonyRunning {
				continue
			}
			if ci.StartTime < cutoff {
				delete(s.ceremonies, cid)
				evicted++
			}
		}
		s.mtx.Unlock()
		if evicted > 0 {
			log.Debugf("evictCeremonies: removed %d stale entries", evicted)
		}
	}
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
// was previously unknown.  Rejects self, version mismatches, and
// missing or malformed NaClPub (e2e encryption is mandatory).
// When updating an existing peer, preserves non-empty Address from
// the old record if the new record omits it.
func (s *Server) addPeer(ctx context.Context, pr PeerRecord) bool {
	log.Tracef("addPeer %v", pr.Identity)

	if pr.Version != ProtocolVersion {
		log.Warningf("addPeer %v: version %d != %d, rejected",
			pr.Identity, pr.Version, ProtocolVersion)
		return false
	}
	// Reject peers without NaCl public keys.  E2e encryption is
	// mandatory — every peer MUST have a valid NaClPub.
	if len(pr.NaClPub) != NaClPubSize {
		log.Warningf("addPeer %v: bad NaClPub length %d (want %d), rejected",
			pr.Identity, len(pr.NaClPub), NaClPubSize)
		return false
	}
	// Reject all-zeros NaClPub — cryptographically useless and
	// collides with the BroadcastDestination sentinel.
	var zeroKey [NaClPubSize]byte
	if bytes.Equal(pr.NaClPub, zeroKey[:]) {
		log.Warningf("addPeer %v: all-zeros NaClPub, rejected",
			pr.Identity)
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
		// Preserve Address if the caller doesn't have it.
		// The listen path learns NaClPub (from handshake) but
		// not Address; gossip may later provide Address.
		if pr.Address == "" && existing.Address != "" {
			pr.Address = existing.Address
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
// NOTE: if a transport is closed here while a TSS keygen, reshare,
// or sign is in flight on that session, the TSS operation will fail.
// The ceremony coordinator handles this by detecting session loss
// and allowing the blockchain to re-issue the ceremony.
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

	// Advertise hostname:port when Hostname is configured so
	// peers in forward/all mode can verify us via TXT lookup.
	// Otherwise advertise IP:port from the bound listener.
	addr := s.listenAddress
	if s.cfg.Hostname != "" {
		_, port, err := net.SplitHostPort(s.listenAddress)
		if err == nil {
			addr = net.JoinHostPort(s.cfg.Hostname, port)
		}
	}

	s.mtx.Lock()
	s.peers[s.secret.Identity] = &PeerRecord{
		Identity: s.secret.Identity,
		Address:  addr,
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
	return true // TODO(SOW4-§9): implement real health checks (last-item-before-ship).
}

func (s *Server) health(ctx context.Context) (bool, any, error) {
	log.Tracef("health")
	defer log.Tracef("health exit")

	return s.isHealthy(ctx), Info{Online: true}, nil
}

// sendErr sends err to errC unless ctx is already cancelled.
// Multiple goroutines may race to report errors on the same
// unbuffered channel; without this guard the losers block
// forever and leak their defer wg.Done().
func sendErr(ctx context.Context, errC chan<- error, err error) {
	select {
	case <-ctx.Done():
	case errC <- err:
	}
}

func (s *Server) connect(ctx context.Context, c string, errC chan error) {
	defer s.wg.Done()

	log.Infof("connect: %v", c)
	defer log.Infof("connect: %v exit", c)

	// Reject self before wasting a dial.
	s.mtx.RLock()
	selfAddr := s.listenAddress
	s.mtx.RUnlock()
	if selfAddr != "" && c == selfAddr {
		log.Warningf("connect: skipping self %v", c)
		return
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c)
	if err != nil {
		sendErr(ctx, errC, err)
		return
	}
	tcpKeepAlive(conn, tcpKeepAlivePeriod)

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
		sendErr(ctx, errC, err)
		return
	}
	them, naclPub, err := transport.Handshake(ctx, s.secret)
	if err != nil {
		sendErr(ctx, errC, err)
		return
	}

	// Defense-in-depth: reject self even if the address didn't
	// match (e.g. hostname resolved to our IP, NAT hairpin).
	if *them == s.secret.Identity {
		log.Warningf("connect: connected to self at %v", c)
		return
	}

	// DNS verification based on the dial target.
	// Hostname targets get forward TXT verification.
	// IP targets get reverse DNS verification (if enabled).
	if err := s.verifyOutboundDNS(ctx, c, conn.RemoteAddr(), *them); err != nil {
		sendErr(ctx, errC, err)
		return
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

	// Errors are logged per-connection in connectPeer; no global
	// exit needed since partial mesh connectivity is normal.
	for k := range s.cfg.Connect {
		s.wg.Add(1)
		go s.connect(ctx, s.cfg.Connect[k], errC)
	}
}

func (s *Server) listen(ctx context.Context, errC chan error) {
	defer s.wg.Done()

	listener, err := s.listenConfig.Listen(ctx, "tcp", s.cfg.ListenAddress)
	if err != nil {
		sendErr(ctx, errC, err)
		return
	}
	s.mtx.Lock()
	s.listenAddress = listener.Addr().String()
	s.mtx.Unlock()
	s.registerSelfAsPeer()
	go func() {
		<-ctx.Done()
		// untested: listener.Close error is logged not returned; cosmetic
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
		// untested: Accept error after ctx cancel; requires mock net.Listener
		if err != nil {
			log.Errorf("accept: %v", err)
			continue
		}

		// Limit concurrent handshakes to PeersWanted.  If the
		// semaphore is full, block until a slot opens or ctx
		// cancels.  This prevents goroutine exhaustion from
		// connection floods — the attacker must wait for existing
		// handshakes to complete before new ones start.
		select {
		case <-ctx.Done():
			conn.Close() // best-effort: shutting down
			return
		case s.handshakeSem <- struct{}{}:
		}

		// Handle handshake and session setup in goroutine.
		// Capacity check happens post-KX inside
		// handleIncomingConnection (BusyResponse).
		tcpKeepAlive(conn, tcpKeepAlivePeriod)
		s.wg.Add(1)
		go s.handleIncomingConnection(ctx, conn)
	}
}

func (s *Server) initPaillierPrimes(pctx context.Context) error {
	log.Tracef("initPaillierPrimes")
	defer log.Tracef("initPaillierPrimes exit")

	timeout := s.cfg.PreParamsTimeout
	if timeout == 0 {
		timeout = defaultPreParamsTimeout
	}
	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	preparamsFilename := filepath.Join(s.data, "preparams.json")
	ppf, err := os.Open(preparamsFilename)
	if errors.Is(err, os.ErrNotExist) {
		log.Infof("Generating TSS Paillier primes (timeout %v)", timeout)
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
	peersTTL, err := ttl.New(s.cfg.PeersWanted, true)
	if err != nil {
		return fmt.Errorf("peer ttl: %w", err)
	}
	s.peersTTL = peersTTL

	// Initialize unanswered ping timeout map.
	pings, err := ttl.New(s.cfg.PeersWanted, true)
	if err != nil {
		return fmt.Errorf("ping ttl: %w", err)
	}
	s.pings = pings

	// Initialize message dedup cache.
	seen, err := ttl.New(seenCapacity, true)
	if err != nil {
		return fmt.Errorf("seen ttl: %w", err)
	}
	s.seen = seen

	// Initialize DNS lookup rate limiter — one lookup per IP
	// per 60 seconds.
	dnsLookups, err := ttl.New(s.cfg.PeersWanted, true)
	if err != nil {
		return fmt.Errorf("dns ttl: %w", err)
	}
	s.dnsLookups = dnsLookups

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
	// Seed the store with the server's pre-loaded Paillier primes
	// so that GetPreParams() returns immediately instead of
	// generating fresh ones (~30s).
	s.tssStore.SetPreParams(&s.preParams)
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

	// Evict completed/failed ceremonies older than ceremonyMaxAge.
	s.wg.Add(1)
	go s.evictCeremonies(ctx)

	// Ceremony dispatcher — reads from CeremonyInitiator channel.
	s.wg.Add(1)
	go s.ceremonyLoop(ctx)

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

// handleIncomingConnection processes an incoming connection in a separate
// goroutine to prevent blocking the accept loop. This protects against
// DDoS attacks where an attacker opens many slow connections.
func (s *Server) handleIncomingConnection(ctx context.Context, conn net.Conn) {
	var success bool
	defer func() {
		if !success {
			s.wg.Done()
		}
	}()

	log.Debugf("handleIncomingConnection: %v", conn.RemoteAddr())
	defer log.Debugf("handleIncomingConnection: %v exit", conn.RemoteAddr())

	// Perform KX and handshake, then release the semaphore.
	// The semaphore only gates the expensive KX phase —
	// once complete, the slot is free for the next connection.
	id, transport, naclPub, err := s.newTransport(ctx, conn)
	<-s.handshakeSem // release regardless of success/failure
	if err != nil {
		// Warning not Error — failed KX/handshake is expected
		// from port scanners and misconfigured peers.
		log.Warningf("transport %v: %v", conn.RemoteAddr(), err)
		return
	}

	// Reject self-connections (NAT hairpin, misconfigured seeds).
	if *id == s.secret.Identity {
		log.Warningf("handleIncomingConnection: rejecting self %v", conn.RemoteAddr())
		transport.Close()
		return
	}

	// Capacity check post-KX.  The peer proved identity via
	// handshake (proof-of-work against trivial DoS).  If at
	// capacity, send BusyResponse so the peer backs off
	// instead of hammering reconnect.
	s.mtx.RLock()
	full := len(s.sessions) >= s.cfg.PeersWanted
	s.mtx.RUnlock()
	if full {
		log.Debugf("server full, sending busy to %v", id)
		// Best-effort: peer is being rejected, write failure is harmless.
		_ = transport.Write(s.secret.Identity, BusyResponse{})
		// Best-effort: transport is being discarded.
		transport.Close()
		return
	}

	// Insert into sessions
	if err := s.newSession(id, transport); err != nil {
		log.Errorf("session %v: %v", conn.RemoteAddr(), err)
		return
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

	// Connection successful
	success = true
	log.Infof("connected %v: %v", conn.RemoteAddr(), id)

	// handle connection
	s.handle(ctx, id, transport)
}
