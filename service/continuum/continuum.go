// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package continuum implements the service that runs the p2p network for
// MinerFI Multi-Party Threshold Signature Scheme.
package continuum

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
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
)

var log = loggo.GetLogger(appName)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	Connect                 []string
	Home                    string
	ListenAddress           string
	LogLevel                string
	PeersWanted             int
	PprofListenAddress      string
	PrivateKey              string
	PrometheusListenAddress string
	PrometheusNamespace     string
}

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

	// Peer tracking
	peers    map[Identity]*PeerRecord // all known peers
	peersTTL *ttl.TTL                 // expiry for known peers

	// Prometheus
	promCollectors  []prometheus.Collector
	promPollVerbose bool // set to true to print stats during poll
	isRunning       bool
}

type Info struct {
	Online bool
}

func NewDefaultConfig() *Config {
	return &Config{
		LogLevel:            logLevel,
		PrometheusNamespace: appName,
		PrivateKey:          "",
		ListenAddress:       defaultListenAddress,
		PeersWanted:         defaultPeersWanted,
	}
}

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

func (s *Server) newTransport(ctx context.Context, conn net.Conn) (*Identity, *Transport, error) {
	transport, err := NewTransportFromCurve(ecdh.X25519()) // XXX config option
	if err != nil {
		return nil, nil, fmt.Errorf("new transport: %w", err)
	}

	err = transport.KeyExchange(ctx, conn)
	if err != nil {
		return nil, nil, fmt.Errorf("key exchange: %w", err) // XXX too loud?
	}

	id, err := transport.Handshake(ctx, s.secret)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err) // XXX too loud?
	}

	return id, transport, nil
}

func (s *Server) handle(ctx context.Context, id *Identity, t *Transport) {
	defer func() {
		if err := s.deleteSession(id); err != nil {
			log.Errorf("delete session %v: %v", id, err)
		}
	}()
	defer s.wg.Done()

	log.Debugf("handle: %v", id)
	defer log.Debugf("handle exit: %v", id)

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
		header, payload, err := t.Read()
		if err != nil {
			// XXX too loud?
			log.Errorf("read %v: %v", id, err)
			return
		}
		log.Infof("%v", spew.Sdump(header))
		log.Infof("%v", spew.Sdump(payload))

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
				if err := validatePeerAddress(pr.Address); err != nil {
					log.Warningf("peer %v bad address %q: %v",
						pr.Identity, pr.Address, err)
					continue
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

		default:
			log.Debugf("handle %v: unhandled %T", id, payload)
		}
	}
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
				Help:      "Whether the TBC service is running",
			}, s.promRunning),
		}
	}
	return s.promCollectors
}

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
// was previously unknown.
func (s *Server) addPeer(ctx context.Context, pr PeerRecord) bool {
	log.Tracef("addPeer %v", pr.Identity)

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Don't track ourselves.
	if pr.Identity == s.secret.Identity {
		return false
	}

	_, existed := s.peers[pr.Identity]
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
// a hung peer cannot block others.  We don't wait for completion
// because errors are logged by the goroutine and the caller has
// no use for the results.
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
				log.Warningf("peer notify %v: %v", d.id, err)
			}
		}(d)
	}
}

// registerSelfAsPeer adds our own record to the peer map so that we
// are included in gossip responses.  Self is stored directly (not via
// addPeer which skips self) and has no TTL — we never expire ourselves.
func (s *Server) registerSelfAsPeer() {
	log.Tracef("registerSelfAsPeer")

	s.mtx.Lock()
	s.peers[s.secret.Identity] = &PeerRecord{
		Identity: s.secret.Identity,
		Address:  s.listenAddress,
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
			log.Infof("promPoll XXX")
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
	them, err := transport.Handshake(ctx, s.secret)
	if err != nil {
		errC <- err
		return
	}

	if err := s.newSession(them, transport); err != nil {
		log.Errorf("connect session %v: %v", them, err)
		return
	}

	// Register the peer we connected to.  We know their listen
	// address (c) — the listen side will learn ours via gossip.
	s.addPeer(ctx, PeerRecord{
		Identity: *them,
		Address:  c,
		Version:  ProtocolVersion,
		LastSeen: time.Now().Unix(),
	})

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
			log.Errorf("listner close: %v", err)
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
		id, transport, err := s.newTransport(ctx, conn)
		if err != nil {
			log.Errorf("transport: %v", err)
			continue
		}

		// Insert into sessions
		if err := s.newSession(id, transport); err != nil {
			log.Errorf("session: %v", err)
			continue
		}

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
	s.cfg.PrivateKey = "" // hopefully PrivateKey is reaped later.

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
	}

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
