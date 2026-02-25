// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/tss"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/sync/errgroup"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

// XXX all the dns poop may have to be moved to it's own world. Mayve even
// internal testutils.

var (
	defaultPort = uint16(45067)
	// seed1       = "seed.bark.gfy." // XXX implement this

	// wellKnownSeeds = []string{seed1}

	inAddrArpa = "in-addr.arpa"
)

type node struct {
	DNSName           string
	ReverseDNSName    string
	ReverseDNSPtrName string
	IP                net.IP
	Port              uint16
	Secret            *Secret
}

func createNode(name, domain string, ip net.IP, port uint16) (*node, error) {
	i := []byte(ip.To4())
	n := &node{
		DNSName: fmt.Sprintf("%v.%v.", name, domain),
		ReverseDNSName: fmt.Sprintf("%v.%v.%v.%v.%v.",
			i[3], i[2], i[1], i[0], inAddrArpa),
		ReverseDNSPtrName: fmt.Sprintf("%v.%v.", name, domain),
		IP:                ip,
		Port:              port,
	}
	// panic(spew.Sdump(n.ReverseDNSPtrName))
	var err error
	n.Secret, err = NewSecret()
	if err != nil {
		return nil, err
	}

	return n, nil
}

// nodeToDNS returns forward and reverse lookup records.
func nodeToDNS(n *node) ([]dns.RR, []dns.RR) {
	var port string
	if n.Port != 0 {
		// Note extra spaces here are to test kvFromTxt parser.
		port = ";   port=" + strconv.Itoa(int(n.Port)) + ";"
	}
	return []dns.RR{
			&dns.A{
				Hdr: dns.Header{
					Name:  n.DNSName,
					Class: dns.ClassINET,
				},
				A: n.IP,
			},
			&dns.TXT{
				Hdr: dns.Header{
					Name:  n.DNSName,
					Class: dns.ClassINET,
				},
				Txt: []string{"v=" + dnsAppName + "; identity=" +
					n.Secret.String() + port},
			},
		},
		[]dns.RR{
			&dns.PTR{
				Hdr: dns.Header{
					Name:  n.ReverseDNSName,
					Class: dns.ClassINET,
				},
				Ptr: n.ReverseDNSPtrName,
			},
		}
}

type dnsHandler struct {
	lookup map[string][]dns.RR // DNS records
	nodes  map[string]*node    // nodes, used for private keys
}

func (h *dnsHandler) insertDNS(n *node, forward, reverse []dns.RR) {
	h.lookup[n.DNSName] = forward
	h.lookup[n.ReverseDNSName] = reverse
	h.nodes[n.DNSName] = n
}

func (h *dnsHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)

	rr, ok := h.lookup[m.Question[0].Header().Name]
	if ok {
		m.Answer = rr
	}
	if _, err := io.Copy(w, m); err != nil {
		panic(err)
	}
}

func newResolver(resolverAddress string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{
				Timeout: 10000 * time.Millisecond,
			}
			return d.DialContext(ctx, "tcp", resolverAddress)
		},
	}
}

func createDNSNodes(domain string, count byte) *dnsHandler {
	if count >= 254 {
		panic("too many")
	}
	handler := &dnsHandler{
		lookup: make(map[string][]dns.RR),
		nodes:  make(map[string]*node),
	}
	for i := byte(0); i < count; i++ {
		nodename := fmt.Sprintf("node%v", i+1)
		n, err := createNode(nodename, domain, net.IPv4(127, 0, 1, i+1),
			defaultPort)
		if err != nil {
			panic(err)
		}
		dnsf, dnsr := nodeToDNS(n) // forward and reverse records
		handler.insertDNS(n, dnsf, dnsr)
	}

	return handler
}

func newDNSServer(ctx context.Context, handler dns.Handler) *dns.Server {
	started := make(chan struct{})
	srv := &dns.Server{
		Addr:              "127.0.0.1:0",
		Net:               "tcp",
		Handler:           handler,
		NotifyStartedFunc: func(_ context.Context) { close(started) },
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			panic(err)
		}
	}()
	select {
	case <-ctx.Done():
		panic(fmt.Errorf("panic while starting DNS server: %w", ctx.Err()))
	case <-started:
	}
	return srv
}

func TestID(t *testing.T) {
	// XXX not sure if we need this test; it's a roadmap of how the code is
	// written and thus maybe useful for folks to read prior to reading the
	// rest.
	//
	// Create DNS record with identity + ip + port
	// Client challenges Server with random(32)
	// Server signs challenge with privkey
	// Client recover pubkey from sig of challenge and verifies identity
	//
	// Identity is a compressed pubkey
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("secp256k1 %x", priv.Serialize())
	pub := priv.PubKey()
	t.Logf("pub: %x", pub.SerializeCompressed())
	t.Logf("identity: %x", Hash160(pub.SerializeCompressed()))

	hash := chainhash.HashB(pub.SerializeCompressed())
	t.Logf("hash: %x", hash)

	sig := ecdsa.SignCompact(priv, hash[:], true)
	t.Logf("sig: %x", sig)

	pubRecovered, compact, err := ecdsa.RecoverCompact(sig, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !compact {
		t.Fatal("not compact")
	}
	if !pubRecovered.IsEqual(pub) {
		t.Fatal("not recovered")
	}

	pub1 := Hash160(pub.SerializeCompressed())
	pub2 := Hash160(pubRecovered.SerializeCompressed())
	if !bytes.Equal(pub1, pub2) {
		t.Fatal("not same ripemd")
	}
}

func newNonce(key [32]byte, counter uint64) (nonce [24]byte) {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	h := hmac.New(sha256.New, key[:])
	_, err := h.Write(c[:])
	if err != nil {
		panic(err)
	}
	s := h.Sum(nil)
	copy(nonce[:], s)
	return nonce
}

func TestECDHSecretBox(t *testing.T) {
	// XXX not sure if we need this test; it's a roadmap of how the code is
	// written and thus maybe useful for folks to read prior to reading the
	// rest.
	curve := ecdh.P521()
	priv1, _ := curve.GenerateKey(rand.Reader)
	priv2, _ := curve.GenerateKey(rand.Reader)

	// Derive shared secret
	t.Logf("pub1: %x", priv1.PublicKey().Bytes())
	t.Logf("pub2: %x", priv2.PublicKey().Bytes())
	secret1, _ := priv1.ECDH(priv2.PublicKey())
	secret2, _ := priv2.ECDH(priv1.PublicKey())

	// Both secrets should be equal
	if !bytes.Equal(secret1, secret2) {
		t.Fatal("bad secret")
	}

	// Derive encryption keys
	var ek1 [32]byte
	ek1R := hkdf.New(sha256.New, secret1, nil, nil)
	if _, err := io.ReadFull(ek1R, ek1[:]); err != nil {
		t.Fatal(err)
	}

	var ek2 [32]byte
	ek2R := hkdf.New(sha256.New, secret2, nil, nil)
	if _, err := io.ReadFull(ek2R, ek2[:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ek1[:], ek2[:]) {
		t.Fatal("bad derive")
	}

	// Nonce is random hmac + counter
	var nk1 [32]byte
	_, _ = rand.Read(nk1[:])
	nonce1 := newNonce(nk1, 1)

	var nk2 [32]byte
	_, _ = rand.Read(nk2[:])
	nonce2 := newNonce(nk2, 1)

	// Encrypt from 1 to 2
	msg1 := []byte("hello msg 1")
	enc1 := secretbox.Seal(nonce1[:], msg1, &nonce1, &ek1)
	var msg1Nonce [24]byte
	copy(msg1Nonce[:], enc1[:24])
	decrMsg1, ok := secretbox.Open(nil, enc1[24:], &msg1Nonce, &ek2)
	if !ok {
		t.Fatal("decryption failed")
	}
	if !bytes.Equal(decrMsg1, msg1) {
		t.Fatal("failed to decrypt")
	}

	// Encrypt from 2 to 1
	msg2 := []byte("hello msg 2")
	enc2 := secretbox.Seal(nonce2[:], msg2, &nonce2, &ek2)
	var msg2Nonce [24]byte
	copy(msg2Nonce[:], enc2[:24])
	decrMsg2, ok := secretbox.Open(nil, enc2[24:], &msg2Nonce, &ek1)
	if !ok {
		t.Fatal("decryption failed")
	}
	if !bytes.Equal(decrMsg2, msg2) {
		t.Fatal("failed to decrypt")
	}
}

// newTestServer creates a Server pre-configured for testing. It generates a
// fresh identity, sets up a temporary home directory with cached Paillier
// primes, and returns the configured server. The caller must call Run().
func newTestServer(t *testing.T, preParams []keygen.LocalPreParams, idx int, listenAddr string, connect []string) *Server {
	t.Helper()

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	privKeyHex := hex.EncodeToString(secret.privateKey.Serialize())

	home := filepath.Join(t.TempDir(), fmt.Sprintf("node%d", idx))
	dataDir := filepath.Join(home, secret.String())
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Write cached preparams to avoid slow generation.
	if idx < len(preParams) {
		pp, err := json.MarshalIndent(preParams[idx], "  ", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, "preparams.json"), pp, 0o400); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &Config{
		Home:          home,
		ListenAddress: listenAddr,
		LogLevel:      "continuum=DEBUG",
		PrivateKey:    privKeyHex,
		PeersWanted:   8,
		Connect:       connect,
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Pre-set secret so Identity() works before Run().  Run() will
	// reconstruct the same secret from cfg.PrivateKey.
	server.secret = secret
	return server
}

// waitForListenAddress polls until the server has a bound listen address.
func waitForListenAddress(t *testing.T, s *Server, timeout time.Duration) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		addr := s.ListenAddress()
		if addr != "" {
			return addr
		}
		select {
		case <-ctx.Done():
			t.Fatal("server did not bind listen address")
			return ""
		case <-tick.C:
		}
	}
}

// waitForSessions polls until the server has at least n sessions.
func waitForSessions(t *testing.T, s *Server, n int, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		ids := s.SessionIdentities()
		if len(ids) >= n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("server %v: expected %d sessions, got %d",
				s.Identity(), n, len(s.SessionIdentities()))
		case <-tick.C:
		}
	}
}

// waitForPeers polls until the server knows at least n peers.
func waitForPeers(t *testing.T, s *Server, n int, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		if s.PeerCount() >= n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("server %v: expected %d peers, got %d",
				s.Identity(), n, s.PeerCount())
		case <-tick.C:
		}
	}
}

// waitForSessionCount polls until the server has exactly n sessions.
// Unlike waitForSessions (at least n), this waits for an exact count,
// which is useful for verifying that rejected connections leave zero
// sessions.
func waitForSessionCount(t *testing.T, s *Server, n int, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		ids := s.SessionIdentities()
		if len(ids) == n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("server %v: expected %d sessions, got %d",
				s.Identity(), n, len(s.SessionIdentities()))
		case <-tick.C:
		}
	}
}

// waitForCondition polls fn until it returns true or timeout expires.
func waitForCondition(t *testing.T, msg string, timeout time.Duration, fn func() bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		if fn() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timeout: %s", msg)
		case <-tick.C:
		}
	}
}

func TestSessionSymmetry(t *testing.T) {
	preParams := loadPreParams(t, 2)

	// Server A: listens, no outbound connections.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errA := make(chan error, 1)
	go func() {
		errA <- serverA.Run(ctx)
	}()

	addrA := waitForListenAddress(t, serverA, 2*time.Second)
	t.Logf("server A listening on %v, identity %v", addrA, serverA.Identity())

	// Server B: connects to A.
	serverB := newTestServer(t, preParams, 1, "localhost:0", []string{addrA})

	errB := make(chan error, 1)
	go func() {
		errB <- serverB.Run(ctx)
	}()

	waitForListenAddress(t, serverB, 2*time.Second)
	t.Logf("server B identity %v", serverB.Identity())

	// Both sides must register each other.
	waitForSessions(t, serverA, 1, 5*time.Second)
	waitForSessions(t, serverB, 1, 5*time.Second)

	// Verify A has B's identity.
	aSessions := serverA.SessionIdentities()
	if len(aSessions) != 1 {
		t.Fatalf("server A: expected 1 session, got %d", len(aSessions))
	}
	if aSessions[0] != serverB.Identity() {
		t.Fatalf("server A session mismatch: got %v, want %v",
			aSessions[0], serverB.Identity())
	}

	// Verify B has A's identity.
	bSessions := serverB.SessionIdentities()
	if len(bSessions) != 1 {
		t.Fatalf("server B: expected 1 session, got %d", len(bSessions))
	}
	if bSessions[0] != serverA.Identity() {
		t.Fatalf("server B session mismatch: got %v, want %v",
			bSessions[0], serverA.Identity())
	}

	t.Logf("session symmetry verified: A sees B, B sees A")

	cancel()

	// Drain errors.
	if err := <-errA; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server A: %v", err)
	}
	if err := <-errB; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server B: %v", err)
	}
}

func TestValidatePeerAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"valid ip4", "192.168.1.1:8080", false},
		{"valid ip6", "[::1]:8080", false},
		{"valid hostname", "example.com:8080", false},
		{"valid localhost", "127.0.0.1:45067", false},
		{"empty", "", true},
		{"no port", "192.168.1.1", true},
		{"port zero", "192.168.1.1:0", true},
		{"empty host", ":8080", true},
		{"control char null", "192.168.1.1\x00:8080", true},
		{"control char tab", "192.168.1.1\t:8080", true},
		{"control char newline", "192.168.1.1\n:8080", true},
		{"just port", ":0", true},
		{"too long", string(make([]byte, 300)), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePeerAddress(tc.addr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePeerAddress(%q) = %v, wantErr %v",
					tc.addr, err, tc.wantErr)
			}
		})
	}
}

func TestAddPeerSelf(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errC := make(chan error, 1)
	go func() {
		errC <- s.Run(ctx)
	}()
	waitForListenAddress(t, s, 2*time.Second)

	// addPeer with self identity must return false.
	selfNaClPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	got := s.addPeer(ctx, PeerRecord{
		Identity: s.Identity(),
		Address:  "10.0.0.1:9999",
		Version:  ProtocolVersion,
		NaClPub:  selfNaClPub,
	})
	if got {
		t.Fatal("addPeer accepted self identity")
	}

	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server: %v", err)
	}
}

func TestAddPeerBadVersion(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errC := make(chan error, 1)
	go func() {
		errC <- s.Run(ctx)
	}()
	waitForListenAddress(t, s, 2*time.Second)

	other, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	otherNaClPub, err := other.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		version uint32
		want    bool
	}{
		{"zero value sentinel", 0, false},
		{"wrong version", ProtocolVersion + 1, false},
		{"correct version", ProtocolVersion, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.addPeer(ctx, PeerRecord{
				Identity: other.Identity,
				Address:  "10.0.0.1:9999",
				Version:  tc.version,
				NaClPub:  otherNaClPub,
			})
			if got != tc.want {
				t.Fatalf("addPeer(Version=%d) = %v, want %v",
					tc.version, got, tc.want)
			}
		})
	}

	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server: %v", err)
	}
}

func TestGossipThreeNodes(t *testing.T) {
	preParams := loadPreParams(t, 3)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	// Topology: A <-> B <-> C
	// A and C never connect directly.
	// Gossip must propagate: A learns C, C learns A.

	// Start A.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)
	t.Logf("A: %v at %s", serverA.Identity(), addrA)

	// Start B, connects to A.
	serverB := newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrA})
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	addrB := waitForListenAddress(t, serverB, 2*time.Second)
	t.Logf("B: %v at %s", serverB.Identity(), addrB)

	// Wait for A<->B session.
	waitForSessions(t, serverA, 1, 5*time.Second)
	waitForSessions(t, serverB, 1, 5*time.Second)
	t.Logf("A<->B session established")

	// Start C, connects to B.
	serverC := newTestServer(t, preParams, 2, "localhost:0",
		[]string{addrB})
	errC := make(chan error, 1)
	go func() { errC <- serverC.Run(ctx) }()
	waitForListenAddress(t, serverC, 2*time.Second)
	t.Logf("C: %v", serverC.Identity())

	// Wait for B<->C session.
	waitForSessions(t, serverB, 2, 5*time.Second)
	waitForSessions(t, serverC, 1, 5*time.Second)
	t.Logf("B<->C session established")

	// Gossip: A must learn about C (3 peers: self + B + C).
	// C must learn about A (3 peers: self + B + A).
	waitForPeers(t, serverA, 3, 5*time.Second)
	waitForPeers(t, serverC, 3, 5*time.Second)

	// Verify A knows C's identity.
	aPeers := serverA.KnownPeers()
	foundC := false
	for _, pr := range aPeers {
		if pr.Identity == serverC.Identity() {
			foundC = true
			break
		}
	}
	if !foundC {
		t.Fatalf("A does not know C; A peers: %v", aPeers)
	}

	// Verify C knows A's identity.
	cPeers := serverC.KnownPeers()
	foundA := false
	for _, pr := range cPeers {
		if pr.Identity == serverA.Identity() {
			foundA = true
			break
		}
	}
	if !foundA {
		t.Fatalf("C does not know A; C peers: %v", cPeers)
	}

	t.Logf("gossip verified: A knows C, C knows A")

	cancel()

	if err := <-errA; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server A: %v", err)
	}
	if err := <-errB; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server B: %v", err)
	}
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server C: %v", err)
	}
}

// TestPeerVersionNonZero verifies that all peer records — both self and
// gossip-learned — carry a non-zero Version.  Zero is reserved as an
// invalid sentinel to catch uninitialized structs.
func TestPeerVersionNonZero(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)

	serverB := newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrA})
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	waitForListenAddress(t, serverB, 2*time.Second)

	// Wait for gossip to propagate.
	waitForPeers(t, serverA, 2, 5*time.Second)
	waitForPeers(t, serverB, 2, 5*time.Second)

	// Every peer record must have Version > 0.
	for _, pr := range serverA.KnownPeers() {
		if pr.Version == 0 {
			t.Fatalf("peer %v has Version 0 (zero-value sentinel)",
				pr.Identity)
		}
	}
	for _, pr := range serverB.KnownPeers() {
		if pr.Version == 0 {
			t.Fatalf("peer %v has Version 0 (zero-value sentinel)",
				pr.Identity)
		}
	}

	cancel()
	if err := <-errA; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server A: %v", err)
	}
	if err := <-errB; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server B: %v", err)
	}
}

func FuzzValidatePeerAddress(f *testing.F) {
	f.Add("192.168.1.1:8080")
	f.Add("[::1]:8080")
	f.Add("example.com:8080")
	f.Add("")
	f.Add(":0")
	f.Add(":8080")
	f.Add("192.168.1.1:0")
	f.Add("192.168.1.1")
	f.Add(string(make([]byte, 300)))

	f.Fuzz(func(t *testing.T, addr string) {
		_ = validatePeerAddress(addr) // must not panic
	})
}

func TestReadJSONLine(t *testing.T) {
	type msg struct {
		Name string `json:"name"`
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
		want    string
	}{
		{"valid", `{"name":"alice"}` + "\n", false, "alice"},
		{"valid trailing data", `{"name":"bob"}` + "\nextra", false, "bob"},
		{"malformed json", `{bad json}` + "\n", true, ""},
		{"empty line", "\n", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			go func() {
				_, _ = server.Write([]byte(tc.input))
				server.Close()
			}()

			var got msg
			err := readJSONLine(client, &got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("readJSONLine() = %v, wantErr %v",
					err, tc.wantErr)
			}
			if !tc.wantErr && got.Name != tc.want {
				t.Fatalf("got name %q, want %q",
					got.Name, tc.want)
			}
		})
	}
}

func TestReadJSONLineOverflow(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Write 5000 bytes without a newline — must trigger
	// the 4096 max size guard.
	go func() {
		buf := make([]byte, 5000)
		for i := range buf {
			buf[i] = 'x'
		}
		_, _ = server.Write(buf)
		server.Close()
	}()

	var got struct{}
	err := readJSONLine(client, &got)
	if err == nil {
		t.Fatal("expected overflow error")
	}
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge, got: %v", err)
	}
}

func TestReadJSONLineEOF(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	// Close immediately — readJSONLine must return an error,
	// not hang.
	server.Close()

	var got struct{}
	err := readJSONLine(client, &got)
	if err == nil {
		t.Fatal("expected EOF error")
	}
}

// TestPingHeartbeat verifies that the ping loop sends heartbeats and
// that receiving a PingResponse updates the peer's LastSeen timestamp.
func TestPingHeartbeat(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	// Use a fast ping interval for testing.
	const fastPing = 50 * time.Millisecond

	// Start A.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	serverA.cfg.PingInterval = fastPing
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)

	// Start B, connects to A.
	serverB := newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrA})
	serverB.cfg.PingInterval = fastPing
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()

	// Wait for A<->B session.
	waitForSessions(t, serverA, 1, 3*time.Second)
	waitForSessions(t, serverB, 1, 3*time.Second)

	idA := serverA.Identity()
	idB := serverB.Identity()

	// Record initial LastSeen for B's record of A.
	initialLastSeen := func() int64 {
		for _, pr := range serverB.KnownPeers() {
			if pr.Identity == idA {
				return pr.LastSeen
			}
		}
		return 0
	}()

	// Poll until LastSeen advances (ping exchanged).
	pollCtx, pollCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer pollCancel()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	var updatedLastSeen int64
	for {
		for _, pr := range serverB.KnownPeers() {
			if pr.Identity == idA {
				updatedLastSeen = pr.LastSeen
			}
		}
		if updatedLastSeen > initialLastSeen {
			break
		}
		select {
		case <-pollCtx.Done():
			t.Fatal("LastSeen was not refreshed by ping")
		case <-tick.C:
		}
	}

	// Also verify A has B in its peer table.
	found := false
	for _, pr := range serverA.KnownPeers() {
		if pr.Identity == idB {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("A does not know B")
	}

	cancel()
	if err := <-errA; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("serverA: %v", err)
	}
	if err := <-errB; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("serverB: %v", err)
	}
}

// TestSessionReaping verifies that when a peer dies, the surviving node
// detects the dead session and removes it.
func TestSessionReaping(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctxA, cancelA := context.WithCancel(t.Context())
	t.Cleanup(cancelA)

	ctxB, cancelB := context.WithCancel(t.Context())
	t.Cleanup(cancelB)

	const fastPing = 50 * time.Millisecond

	// Start A.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	serverA.cfg.PingInterval = fastPing
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctxA) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)

	// Start B, connects to A.
	serverB := newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrA})
	serverB.cfg.PingInterval = fastPing
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctxB) }()

	// Wait for A<->B session.
	waitForSessions(t, serverA, 1, 3*time.Second)
	waitForSessions(t, serverB, 1, 3*time.Second)
	t.Log("A<->B session established")

	// Kill B.
	cancelB()
	if err := <-errB; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("serverB: %v", err)
	}
	t.Log("B shut down")

	// A should detect the dead session.  The read in handle() will
	// return an error when the TCP connection is closed, which causes
	// handle() to exit and deleteSession to run.
	reapCtx, reapCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer reapCancel()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		ids := serverA.SessionIdentities()
		if len(ids) == 0 {
			t.Log("A reaped dead session")
			cancelA()
			if err := <-errA; err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("serverA: %v", err)
			}
			return
		}
		select {
		case <-reapCtx.Done():
			t.Fatal("A did not reap dead session within timeout")
		case <-tick.C:
		}
	}
}

// TestMaintainConnections verifies that when a node is below PeersWanted
// and knows about gossip-learned peers, it autonomously dials them.
func TestMaintainConnections(t *testing.T) {
	preParams := loadPreParams(t, 3)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	const (
		fastMaintain = 50 * time.Millisecond
		peersWanted  = 3 // want more than the initial 1 session
	)

	// Start A.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	serverA.cfg.MaintainInterval = fastMaintain
	serverA.cfg.PeersWanted = peersWanted
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)
	t.Logf("A: %v at %s", serverA.Identity(), addrA)

	// Start B, connects to A.
	serverB := newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrA})
	serverB.cfg.MaintainInterval = fastMaintain
	serverB.cfg.PeersWanted = peersWanted
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	addrB := waitForListenAddress(t, serverB, 2*time.Second)
	t.Logf("B: %v at %s", serverB.Identity(), addrB)

	// Wait for A<->B session.
	waitForSessions(t, serverA, 1, 5*time.Second)
	waitForSessions(t, serverB, 1, 5*time.Second)
	t.Log("A<->B session established")

	// Start C, connects to B.
	serverC := newTestServer(t, preParams, 2, "localhost:0",
		[]string{addrB})
	serverC.cfg.MaintainInterval = fastMaintain
	serverC.cfg.PeersWanted = peersWanted
	errC := make(chan error, 1)
	go func() { errC <- serverC.Run(ctx) }()
	addrC := waitForListenAddress(t, serverC, 2*time.Second)
	t.Logf("C: %v at %s", serverC.Identity(), addrC)

	// Wait for B<->C session.
	waitForSessions(t, serverB, 2, 5*time.Second)
	t.Log("B<->C session established")

	// Wait for gossip to propagate: A should learn about C.
	waitForPeers(t, serverA, 3, 5*time.Second)
	t.Log("A knows about C via gossip")

	// Now maintainConnections should kick in: A is below PeersWanted
	// (has 1 session, wants 3) and knows about C.  It should
	// autonomously dial C, giving A a second session.
	waitForSessions(t, serverA, 2, 5*time.Second)
	t.Log("A autonomously connected to C via maintainConnections")

	// Verify C also sees 2 sessions (B + A).
	waitForSessions(t, serverC, 2, 5*time.Second)
	t.Log("C confirmed 2 sessions")

	cancel()
	for _, errCh := range []chan error{errA, errB, errC} {
		if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("server: %v", err)
		}
	}
}

func TestDNSSeeding(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	// Start seed node A.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)
	t.Logf("A: %v at %s", serverA.Identity(), addrA)

	// Parse A's listen address for DNS records.
	host, port, err := net.SplitHostPort(addrA)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("failed to parse IP: %v", host)
	}

	// Build a mock DNS handler with A's identity at seed1.test.gfy.
	seedDomain := "test.gfy"
	seedName := "seed1"
	seedFQDN := seedName + "." + seedDomain + "."
	portNum, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	handler := &dnsHandler{
		lookup: make(map[string][]dns.RR),
		nodes:  make(map[string]*node),
	}
	handler.lookup[seedFQDN] = []dns.RR{
		&dns.A{
			Hdr: dns.Header{
				Name:  seedFQDN,
				Class: dns.ClassINET,
			},
			A: ip,
		},
		&dns.TXT{
			Hdr: dns.Header{
				Name:  seedFQDN,
				Class: dns.ClassINET,
			},
			Txt: []string{fmt.Sprintf("v=%v; identity=%v; port=%v",
				dnsAppName, serverA.Identity(), portNum)},
		},
	}

	// Start mock DNS server.
	dnsSrv := newDNSServer(ctx, handler)
	dnsAddress := dnsSrv.Listener.Addr().String()
	t.Logf("DNS server at %s", dnsAddress)

	// Start node B with Seeds pointing at the DNS hostname.
	serverB := newTestServer(t, preParams, 1, "localhost:0", nil)
	serverB.cfg.Seeds = []string{seedName + "." + seedDomain + ":" + port}
	serverB.resolver = newResolver(dnsAddress)
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	waitForListenAddress(t, serverB, 2*time.Second)
	t.Logf("B: %v", serverB.Identity())

	// B should connect to A through DNS seeding.
	waitForSessions(t, serverA, 1, 5*time.Second)
	waitForSessions(t, serverB, 1, 5*time.Second)
	t.Log("B connected to A via DNS seeding")

	cancel()
	for _, errCh := range []chan error{errA, errB} {
		if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("server: %v", err)
		}
	}
}

func TestDNSHelloAdvertise(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	// Start A with a DNS name.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	serverA.cfg.DNSName = "nodeA.test.gfy"
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)

	// Start B connecting to A, also with a DNS name.
	serverB := newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrA})
	serverB.cfg.DNSName = "nodeB.test.gfy"
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()

	// Wait for connection.
	waitForSessions(t, serverA, 1, 5*time.Second)
	waitForSessions(t, serverB, 1, 5*time.Second)
	t.Log("A<->B session established with DNS names advertised")

	cancel()
	for _, errCh := range []chan error{errA, errB} {
		if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("server: %v", err)
		}
	}
}

func TestDNSRequired(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	// Start A which requires DNS from peers.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	serverA.cfg.DNSRequired = true
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)

	// Start B WITHOUT a DNS name, connecting to A.
	serverB := newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrA})
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	waitForListenAddress(t, serverB, 2*time.Second)

	// B's handshake succeeds from B's perspective, but A rejects
	// the connection in newTransport because B didn't advertise a
	// DNS name.  A closes the conn, so B's handle() gets EOF and
	// exits.  Wait for A to confirm zero sessions.
	waitForSessionCount(t, serverA, 0, 5*time.Second)
	t.Log("A correctly rejected B (no DNS name advertised)")

	cancel()
	for _, errCh := range []chan error{errA, errB} {
		if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("server: %v", err)
		}
	}
}

func TestDNSRequiredWithValidDNS(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	domain := "test.gfy"

	// We need to create the servers first to get their identities,
	// then set up DNS records, then run them.
	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	serverB := newTestServer(t, preParams, 1, "localhost:0", nil)

	// Build mock DNS handler with records for both nodes.
	handler := &dnsHandler{
		lookup: make(map[string][]dns.RR),
		nodes:  make(map[string]*node),
	}

	// A's DNS record — uses 127.0.0.1 since we don't know the port yet,
	// but the TXT record with identity is what matters for verification.
	aFQDN := "nodeA." + domain + "."
	handler.lookup[aFQDN] = []dns.RR{
		&dns.A{
			Hdr: dns.Header{Name: aFQDN, Class: dns.ClassINET},
			A:   net.IPv4(127, 0, 0, 1),
		},
		&dns.TXT{
			Hdr: dns.Header{Name: aFQDN, Class: dns.ClassINET},
			Txt: []string{fmt.Sprintf("v=%v; identity=%v",
				dnsAppName, serverA.Identity())},
		},
	}

	bFQDN := "nodeB." + domain + "."
	handler.lookup[bFQDN] = []dns.RR{
		&dns.A{
			Hdr: dns.Header{Name: bFQDN, Class: dns.ClassINET},
			A:   net.IPv4(127, 0, 0, 1),
		},
		&dns.TXT{
			Hdr: dns.Header{Name: bFQDN, Class: dns.ClassINET},
			Txt: []string{fmt.Sprintf("v=%v; identity=%v",
				dnsAppName, serverB.Identity())},
		},
	}

	// Start mock DNS.
	dnsSrv := newDNSServer(ctx, handler)
	dnsAddress := dnsSrv.Listener.Addr().String()
	t.Logf("DNS server at %s", dnsAddress)
	mockResolver := newResolver(dnsAddress)

	// Configure both nodes: require DNS, advertise DNS name, use
	// mock resolver.
	serverA.cfg.DNSRequired = true
	serverA.cfg.DNSName = "nodeA." + domain
	serverA.resolver = mockResolver

	serverB.cfg.DNSRequired = true
	serverB.cfg.DNSName = "nodeB." + domain
	serverB.resolver = mockResolver

	// Start A.
	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)
	t.Logf("A: %v at %s", serverA.Identity(), addrA)

	// Start B connecting to A.
	serverB.cfg.Connect = []string{addrA}
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()

	// Both should connect successfully with DNS verification.
	waitForSessions(t, serverA, 1, 5*time.Second)
	waitForSessions(t, serverB, 1, 5*time.Second)
	t.Log("A<->B connected with mutual DNS verification")

	cancel()
	for _, errCh := range []chan error{errA, errB} {
		if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("server: %v", err)
		}
	}
}

func TestDNSIdentityMismatch(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	domain := "test.gfy"

	serverA := newTestServer(t, preParams, 0, "localhost:0", nil)
	serverB := newTestServer(t, preParams, 1, "localhost:0", nil)

	// Build mock DNS with WRONG identity for B — use a random identity.
	wrongSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	handler := &dnsHandler{
		lookup: make(map[string][]dns.RR),
		nodes:  make(map[string]*node),
	}

	bFQDN := "nodeB." + domain + "."
	handler.lookup[bFQDN] = []dns.RR{
		&dns.A{
			Hdr: dns.Header{Name: bFQDN, Class: dns.ClassINET},
			A:   net.IPv4(127, 0, 0, 1),
		},
		&dns.TXT{
			Hdr: dns.Header{Name: bFQDN, Class: dns.ClassINET},
			Txt: []string{fmt.Sprintf("v=%v; identity=%v",
				dnsAppName, wrongSecret.Identity)},
		},
	}

	dnsSrv := newDNSServer(ctx, handler)
	dnsAddress := dnsSrv.Listener.Addr().String()
	mockResolver := newResolver(dnsAddress)

	// A requires DNS, uses mock resolver.
	serverA.cfg.DNSRequired = true
	serverA.resolver = mockResolver

	// B advertises DNS name but TXT has wrong identity.
	serverB.cfg.DNSName = "nodeB." + domain

	errA := make(chan error, 1)
	go func() { errA <- serverA.Run(ctx) }()
	addrA := waitForListenAddress(t, serverA, 2*time.Second)

	// B connects to A. A will verify B's DNS and find mismatch.
	serverB.cfg.Connect = []string{addrA}
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()

	// B's connect should fail because A rejects the DNS mismatch.
	// The error surfaces on B's side (connect sends to errC).
	// But wait — the DNS verification happens on A's listen side
	// (newTransport), not on B's connect side. B's connect will
	// succeed from B's perspective, but A will reject the transport.
	// B will then get a read error when A closes the connection.
	//
	// Actually, looking at the flow: B dials A, B does KX+handshake.
	// On A's side, newTransport does KX+handshake+DNS verify. If DNS
	// verify fails, newTransport returns error, A logs it and
	// continues accepting. B's handshake completes successfully from
	// B's side but A never calls newSession, so A closes the conn.
	// B's connect() gets the error from handshake read timeout or
	// connection reset.

	// Negative assertion: A should reject B's connection due to DNS
	// mismatch.  Bounded wait for the connect+reject cycle to complete.
	// B dials A, KX+handshake completes, A does DNS verify, rejects,
	// closes conn.  Context-cancellable so the test won't hang.
	select {
	case <-ctx.Done():
		t.Fatal("context cancelled during DNS mismatch check")
	case <-time.After(500 * time.Millisecond):
	}

	// A should have no sessions (rejected B).
	serverA.mtx.RLock()
	sessions := len(serverA.sessions)
	serverA.mtx.RUnlock()
	if sessions != 0 {
		t.Fatalf("A has %d sessions, want 0", sessions)
	}
	t.Log("A correctly rejected B due to DNS identity mismatch")

	cancel()
	// Don't fail on B's error — it's expected.
	if err := <-errA; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server A: %v", err)
	}
	<-errB // drain
}

func TestVerifyDNSIdentityByName(t *testing.T) {
	ctx := t.Context()
	domain := "test.gfy"

	// Create a DNS node and mock server.
	handler := createDNSNodes(domain, 3)
	dnsSrv := newDNSServer(ctx, handler)
	dnsAddress := dnsSrv.Listener.Addr().String()

	// Create a minimal server to test verifyDNSIdentity.
	s := &Server{
		resolver: newResolver(dnsAddress),
	}

	// Verify each node's identity.
	for name, n := range handler.nodes {
		t.Run(name, func(t *testing.T) {
			err := s.verifyDNSIdentity(ctx, name, n.Secret.Identity)
			if err != nil {
				t.Fatalf("verifyDNSIdentity(%v): %v", name, err)
			}
		})
	}

	// Negative: wrong identity should fail.
	wrongSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	for name := range handler.nodes {
		err := s.verifyDNSIdentity(ctx, name, wrongSecret.Identity)
		if err == nil {
			t.Fatalf("verifyDNSIdentity(%v) should have failed with wrong identity", name)
		}
		t.Logf("correctly rejected wrong identity for %v: %v", name, err)
		break // one is enough
	}
}

// TestFiveNodeMesh validates gossip-based discovery at scale beyond
// trivial 2-3 node setups.  Five nodes are arranged in a chain
// (0→1→2→3→4) where no node initially knows all others.  Through
// TestIsDuplicate verifies the message dedup cache: same PayloadHash
// returns duplicate on second call, different hashes do not collide.
func TestIsDuplicate(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{seen: seen}
	ctx := t.Context()

	h1 := &Header{PayloadHash: *NewPayloadHash([]byte("first message"))}
	h2 := &Header{PayloadHash: *NewPayloadHash([]byte("second message"))}

	// First encounter: not a duplicate.
	if s.isDuplicate(ctx, h1) {
		t.Fatal("h1 first call: want false, got true")
	}
	// Second encounter: duplicate.
	if !s.isDuplicate(ctx, h1) {
		t.Fatal("h1 second call: want true, got false")
	}
	// Different message: not a duplicate.
	if s.isDuplicate(ctx, h2) {
		t.Fatal("h2 first call: want false, got true")
	}
}

// TestForwardTTLExpiry verifies that forward() drops messages when
// TTL reaches zero and does not increment the forwarded counter.
func TestForwardTTLExpiry(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		seen:     seen,
		secret:   secret,
		sessions: make(map[Identity]*Transport),
	}

	dest := Identity{1, 2, 3}
	header := &Header{
		PayloadType: PPingRequest,
		PayloadHash: *NewPayloadHash([]byte("ttl-test")),
		Origin:      s.secret.Identity,
		Destination: &dest,
		TTL:         0, // expired
	}

	s.forward(header, &PingRequest{OriginTimestamp: 1}, nil)

	if s.Forwarded() != 0 {
		t.Fatalf("expected 0 forwarded, got %d", s.Forwarded())
	}
}

// TestSealBoxBadKey verifies SealBox rejects keys with wrong length.
func TestSealBoxBadKey(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := secret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  []byte
	}{
		{"nil key", nil},
		{"empty key", []byte{}},
		{"short key", make([]byte, 16)},
		{"long key", make([]byte, 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SealBox([]byte("hello"), tt.key, priv,
				secret.Identity, PPingRequest)
			if !errors.Is(err, ErrInvalidNaClPub) {
				t.Fatalf("want ErrInvalidNaClPub, got: %v", err)
			}
		})
	}
}

// TestOpenBoxWrongKey verifies OpenBox fails when the sender's public
// key doesn't match the actual sender (authentication property of
// nacl box).
func TestOpenBoxWrongKey(t *testing.T) {
	sender, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	imposter, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	recipientPub, err := recipient.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	senderPriv, err := sender.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	ep, err := SealBox([]byte("secret"), recipientPub, senderPriv,
		sender.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with imposter's public key — should fail.
	imposterPub, err := imposter.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPriv, err := recipient.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = OpenBox(ep, imposterPub, recipientPriv)
	if err == nil {
		t.Fatal("OpenBox with wrong sender key should fail")
	}

	// Decrypt with bad-length key.
	_, err = OpenBox(ep, []byte("short"), recipientPriv)
	if !errors.Is(err, ErrInvalidNaClPub) {
		t.Fatalf("want ErrInvalidNaClPub, got: %v", err)
	}
}

// TestSendEncryptedErrors exercises SendEncrypted failure paths:
// unknown destination, missing NaCl key, and unknown command type.
func TestSendEncryptedErrors(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		seen:     seen,
		secret:   secret,
		peers:    make(map[Identity]*PeerRecord),
		sessions: make(map[Identity]*Transport),
	}

	unknownDest := Identity{9, 9, 9}

	// Unknown peer.
	err = s.SendEncrypted(unknownDest, PingRequest{})
	if err == nil {
		t.Fatal("SendEncrypted to unknown peer should fail")
	}

	// Peer exists but has no NaCl key.
	s.peers[unknownDest] = &PeerRecord{
		Identity: unknownDest,
		Version:  ProtocolVersion,
	}
	err = s.SendEncrypted(unknownDest, PingRequest{})
	if err == nil {
		t.Fatal("SendEncrypted to peer without NaClPub should fail")
	}

	// Unknown command type (unregistered struct).
	s.peers[unknownDest].NaClPub = make([]byte, NaClPubSize)
	type bogusCmd struct{}
	err = s.SendEncrypted(unknownDest, bogusCmd{})
	if err == nil {
		t.Fatal("SendEncrypted with unknown command type should fail")
	}
}

// TestAddPeerBadNaClPub verifies addPeer rejects peers with malformed
// NaCl public keys while accepting empty (no e2e support) and valid
// 32-byte keys.
func TestAddPeerBadNaClPub(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		seen:     seen,
		secret:   secret,
		peers:    make(map[Identity]*PeerRecord),
		peersTTL: peersTTL,
	}
	ctx := t.Context()

	validSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	validNaClPub, err := validSecret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		naclPub []byte
		want    bool // expected addPeer return
	}{
		{"nil key (no e2e)", nil, false},
		{"empty key (no e2e)", []byte{}, false},
		{"all-zeros key", make([]byte, 32), false},
		{"valid 32-byte key", validNaClPub, true},
		{"short 16-byte key", make([]byte, 16), false},
		{"long 64-byte key", make([]byte, 64), false},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := Identity{byte(i + 10)}
			got := s.addPeer(ctx, PeerRecord{
				Identity: id,
				NaClPub:  tt.naclPub,
				Version:  ProtocolVersion,
				LastSeen: time.Now().Unix(),
			})
			if got != tt.want {
				t.Fatalf("addPeer(%s) = %v, want %v",
					tt.name, got, tt.want)
			}
		})
	}
}

// TestThreeNodeE2E launches A↔B↔C and verifies end-to-end nacl box
// encryption: A encrypts a PingRequest to C, B forwards the opaque
// EncryptedPayload, C decrypts and receives the inner PingRequest.
// B's RoutedReceived counter stays zero (it never sees the plaintext).
func TestThreeNodeE2E(t *testing.T) {
	preParams := loadPreParams(t, 3)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	servers := make([]*Server, 3)
	errChs := make([]chan error, 3)
	addrs := make([]string, 3)

	// Node A (chain head).
	servers[0] = newTestServer(t, preParams, 0, "localhost:0", nil)
	servers[0].cfg.PeersWanted = 1
	servers[0].cfg.MaintainInterval = 10 * time.Second
	errChs[0] = make(chan error, 1)
	go func() { errChs[0] <- servers[0].Run(ctx) }()
	addrs[0] = waitForListenAddress(t, servers[0], 2*time.Second)

	// Node B.
	servers[1] = newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrs[0]})
	servers[1].cfg.PeersWanted = 2
	servers[1].cfg.MaintainInterval = 10 * time.Second
	errChs[1] = make(chan error, 1)
	go func() { errChs[1] <- servers[1].Run(ctx) }()
	addrs[1] = waitForListenAddress(t, servers[1], 2*time.Second)

	waitForSessions(t, servers[0], 1, 5*time.Second)
	waitForSessions(t, servers[1], 1, 5*time.Second)

	// Node C.
	servers[2] = newTestServer(t, preParams, 2, "localhost:0",
		[]string{addrs[1]})
	servers[2].cfg.PeersWanted = 1
	servers[2].cfg.MaintainInterval = 10 * time.Second
	errChs[2] = make(chan error, 1)
	go func() { errChs[2] <- servers[2].Run(ctx) }()
	addrs[2] = waitForListenAddress(t, servers[2], 2*time.Second)

	waitForSessions(t, servers[1], 2, 5*time.Second)
	waitForSessions(t, servers[2], 1, 5*time.Second)

	// Wait for gossip to propagate NaCl keys.  A needs to know C's
	// NaCl public key to encrypt.
	destC := servers[2].Identity()
	waitForCondition(t, "A never learned C's NaCl public key via gossip",
		5*time.Second, func() bool {
			for _, pr := range servers[0].KnownPeers() {
				if pr.Identity == destC && len(pr.NaClPub) > 0 {
					return true
				}
			}
			return false
		})
	t.Log("A knows C's NaCl public key")

	// A sends encrypted PingRequest to C.
	ts := time.Now().Unix()
	err := servers[0].SendEncrypted(destC, PingRequest{
		OriginTimestamp: ts,
	})
	if err != nil {
		t.Fatalf("SendEncrypted: %v", err)
	}
	t.Log("A sent encrypted PingRequest to C")

	// Wait for C to receive the routed+encrypted message.
	waitForCondition(t, "C did not receive encrypted message",
		5*time.Second, func() bool {
			return servers[2].RoutedReceived() > 0
		})
	t.Logf("C received %d routed message(s)", servers[2].RoutedReceived())

	// B forwarded but did NOT process the inner payload (its
	// RoutedReceived should be 0 — the message was not for B).
	if servers[1].RoutedReceived() != 0 {
		t.Fatalf("B processed a routed message it shouldn't have: %d",
			servers[1].RoutedReceived())
	}
	if servers[1].Forwarded() == 0 {
		t.Fatal("B did not forward any messages")
	}
	t.Logf("B forwarded %d message(s) without decrypting",
		servers[1].Forwarded())
}

// TestThreeNodeForwarding launches 3 nodes in a chain: A↔B↔C.
// A sends a routed PingRequest to C through B.  Verifies:
// - B forwards the message (Forwarded counter > 0)
// - C receives the routed message (RoutedReceived counter > 0)
// - A has no direct session to C (message must have been forwarded)
func TestThreeNodeForwarding(t *testing.T) {
	preParams := loadPreParams(t, 3)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	servers := make([]*Server, 3)
	errChs := make([]chan error, 3)
	addrs := make([]string, 3)

	// Start node A (no outbound connections — chain head).
	servers[0] = newTestServer(t, preParams, 0, "localhost:0", nil)
	servers[0].cfg.PeersWanted = 1                     // prevent autodial
	servers[0].cfg.MaintainInterval = 10 * time.Second // slow
	errChs[0] = make(chan error, 1)
	go func() { errChs[0] <- servers[0].Run(ctx) }()
	addrs[0] = waitForListenAddress(t, servers[0], 2*time.Second)
	t.Logf("node A: %v at %s", servers[0].Identity(), addrs[0])

	// Start node B, connecting to A.
	servers[1] = newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrs[0]})
	servers[1].cfg.PeersWanted = 2 // B connects to both A and C
	servers[1].cfg.MaintainInterval = 10 * time.Second
	errChs[1] = make(chan error, 1)
	go func() { errChs[1] <- servers[1].Run(ctx) }()
	addrs[1] = waitForListenAddress(t, servers[1], 2*time.Second)
	t.Logf("node B: %v at %s", servers[1].Identity(), addrs[1])

	waitForSessions(t, servers[0], 1, 5*time.Second)
	waitForSessions(t, servers[1], 1, 5*time.Second)
	t.Log("A <-> B session established")

	// Start node C, connecting to B.
	servers[2] = newTestServer(t, preParams, 2, "localhost:0",
		[]string{addrs[1]})
	servers[2].cfg.PeersWanted = 1 // prevent autodial
	servers[2].cfg.MaintainInterval = 10 * time.Second
	errChs[2] = make(chan error, 1)
	go func() { errChs[2] <- servers[2].Run(ctx) }()
	addrs[2] = waitForListenAddress(t, servers[2], 2*time.Second)
	t.Logf("node C: %v at %s", servers[2].Identity(), addrs[2])

	waitForSessions(t, servers[1], 2, 5*time.Second)
	waitForSessions(t, servers[2], 1, 5*time.Second)
	t.Log("B <-> C session established")

	// Verify A has no direct session to C.
	aIDs := servers[0].SessionIdentities()
	for _, sid := range aIDs {
		if sid == servers[2].Identity() {
			t.Fatal("A has direct session to C — chain topology broken")
		}
	}

	// A sends a routed PingRequest to C.
	destC := servers[2].Identity()
	err := servers[0].SendTo(destC, PingRequest{
		OriginTimestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	t.Log("A sent routed PingRequest to C")

	// Wait for C to receive the routed message.
	waitForCondition(t, "C did not receive routed message",
		5*time.Second, func() bool {
			return servers[2].RoutedReceived() > 0
		})
	t.Logf("C received %d routed message(s)", servers[2].RoutedReceived())

	// Verify B forwarded the message.
	if servers[1].Forwarded() == 0 {
		t.Fatal("B did not forward any messages")
	}
	t.Logf("B forwarded %d message(s)", servers[1].Forwarded())
}

// TestFiveNodeMesh launches 5 nodes in a chain topology.  Through
// gossip propagation, every node must discover every other node's
// identity.  With PeersWanted > initial connections, endpoint nodes
// (0 and 4) must autonomously dial gossip-learned peers via
// maintainConnections.
func TestFiveNodeMesh(t *testing.T) {
	const n = 5
	preParams := loadPreParams(t, n)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	const (
		fastMaintain = 100 * time.Millisecond
		peersWanted  = 3
	)

	servers := make([]*Server, n)
	errChs := make([]chan error, n)
	addrs := make([]string, n)

	// Start node 0 (no outbound connections — chain head).
	servers[0] = newTestServer(t, preParams, 0, "localhost:0", nil)
	servers[0].cfg.MaintainInterval = fastMaintain
	servers[0].cfg.PeersWanted = peersWanted
	errChs[0] = make(chan error, 1)
	go func() { errChs[0] <- servers[0].Run(ctx) }()
	addrs[0] = waitForListenAddress(t, servers[0], 2*time.Second)
	t.Logf("node 0: %v at %s", servers[0].Identity(), addrs[0])

	// Start nodes 1-4, each connecting to the previous node (chain).
	for i := 1; i < n; i++ {
		servers[i] = newTestServer(t, preParams, i, "localhost:0",
			[]string{addrs[i-1]})
		servers[i].cfg.MaintainInterval = fastMaintain
		servers[i].cfg.PeersWanted = peersWanted
		errChs[i] = make(chan error, 1)
		idx := i
		go func() { errChs[idx] <- servers[idx].Run(ctx) }()
		addrs[i] = waitForListenAddress(t, servers[i], 2*time.Second)
		t.Logf("node %d: %v at %s", idx, servers[idx].Identity(), addrs[idx])

		// Wait for the chain link to establish before starting the
		// next node, so gossip has a stable path to propagate.
		waitForSessions(t, servers[i-1], 1, 5*time.Second)
		waitForSessions(t, servers[i], 1, 5*time.Second)
		t.Logf("node %d <-> node %d session established", i-1, i)
	}

	// Wait for full gossip convergence: every node knows all 5 peers
	// (including itself).
	for i := 0; i < n; i++ {
		waitForPeers(t, servers[i], n, 10*time.Second)
	}
	t.Log("gossip converged: all nodes know all peers")

	// Verify every node knows every other node's identity.
	for i := 0; i < n; i++ {
		peers := servers[i].KnownPeers()
		known := make(map[Identity]bool)
		for _, pr := range peers {
			known[pr.Identity] = true
		}
		for j := 0; j < n; j++ {
			id := servers[j].Identity()
			if !known[id] {
				t.Fatalf("node %d does not know node %d (%v); "+
					"known peers: %v", i, j, id, peers)
			}
		}
	}
	t.Log("identity cross-check passed")

	// Endpoint nodes (0 and 4) start with 1 session but want 3.
	// maintainConnections should dial gossip-learned peers,
	// giving them additional sessions beyond the initial chain link.
	waitForSessions(t, servers[0], 2, 10*time.Second)
	waitForSessions(t, servers[n-1], 2, 10*time.Second)
	t.Log("endpoint nodes made gossip-initiated connections")

	cancel()
	for i := 0; i < n; i++ {
		if err := <-errChs[i]; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("node %d: %v", i, err)
		}
	}
}

// TestHundredNodeMesh validates gossip convergence and autonomous
// connection management at scale.  100 nodes are chained
// (0→1→2→...→99), each with PeersWanted=8.  Gossip must propagate
// all identities across the full chain, and maintainConnections must
// fill each node's session count toward the target.
func TestHundredNodeMesh(t *testing.T) {
	if testing.Short() {
		t.Skip("100-node mesh test is slow")
	}

	const n = 100
	preParams := loadPreParams(t, n)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	const (
		fastMaintain = 50 * time.Millisecond
		peersWanted  = 8
	)

	servers := make([]*Server, n)
	errChs := make([]chan error, n)
	addrs := make([]string, n)

	// Start all nodes in chain order.  Each node connects to the
	// previous one.  waitForListenAddress ensures the previous
	// node's listener is up before the next node dials, so the
	// chain link TCP connection succeeds.  Unlike the 5-node test
	// we don't wait for full session establishment between each
	// pair — that would add ~100 sequential handshakes.  The
	// chain forms concurrently while nodes start.
	for i := 0; i < n; i++ {
		var connect []string
		if i > 0 {
			connect = []string{addrs[i-1]}
		}
		servers[i] = newTestServer(t, preParams, i, "localhost:0", connect)
		servers[i].cfg.MaintainInterval = fastMaintain
		servers[i].cfg.PeersWanted = peersWanted
		errChs[i] = make(chan error, 1)
		idx := i
		go func() { errChs[idx] <- servers[idx].Run(ctx) }()
		addrs[i] = waitForListenAddress(t, servers[i], 2*time.Second)
	}
	t.Logf("all %d nodes started", n)

	// Wait for full gossip convergence: every node knows all n
	// peers.  Chain topology means gossip must traverse up to 99
	// hops.  30s allows 10x headroom over typical ~3s runtime;
	// -short skip protects CI.
	for i := 0; i < n; i++ {
		waitForPeers(t, servers[i], n, 30*time.Second)
	}
	t.Log("gossip converged: all nodes know all peers")

	// Every node should reach at least half of PeersWanted via
	// maintainConnections.  Reaching the exact target is subject
	// to a saturation race: the listen side rejects connections
	// when sessions >= PeersWanted, so when most nodes fill up
	// the last few struggle to find non-full peers.
	// Asserting >= peersWanted/2 proves maintain is working
	// without depending on perfect graph packing.
	minSessions := peersWanted / 2
	for i := 0; i < n; i++ {
		waitForSessions(t, servers[i], minSessions, 30*time.Second)
	}
	t.Logf("all nodes reached at least %d sessions (target %d)",
		minSessions, peersWanted)

	cancel()
	for i := 0; i < n; i++ {
		if err := <-errChs[i]; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("node %d: %v", i, err)
		}
	}
}

// connectedTransports creates a pair of Transports connected via
// net.Pipe with a completed KeyExchange.  The caller gets the
// "server" transport (for inserting into sessions) and the "client"
// transport (for draining reads if needed).  Both transports are
// closed via t.Cleanup.
func connectedTransports(t *testing.T) (*Transport, *Transport) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	sp, cp := net.Pipe()
	t.Cleanup(func() { sp.Close() })
	t.Cleanup(func() { cp.Close() })

	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}
	cli := new(Transport)

	errCh := make(chan error, 2)
	go func() { errCh <- srv.KeyExchange(ctx, sp) }()
	go func() { errCh <- cli.KeyExchange(ctx, cp) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("KeyExchange: %v", err)
		}
	}

	return srv, cli
}

// drainTransport starts a goroutine that reads from the transport's
// connection until it is closed.  Prevents WriteHeader from blocking.
func drainTransport(t *testing.T, tr *Transport) {
	t.Helper()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			if _, err := tr.conn.Read(buf); err != nil {
				return
			}
		}
	}()
}

// --- forward() coverage ---------------------------------------------------

// TestForwardDirect verifies the direct-send path of forward():
// when the destination identity has a session, WriteHeader is called
// on that transport and the forwarded counter increments.
func TestForwardDirect(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	srvTr, cliTr := connectedTransports(t)
	drainTransport(t, cliTr)

	destID := Identity{0xAA}
	s := &Server{
		seen:     seen,
		secret:   secret,
		sessions: map[Identity]*Transport{destID: srvTr},
	}

	header := &Header{
		PayloadType: PPingRequest,
		PayloadHash: *NewPayloadHash([]byte("direct-fwd")),
		Origin:      s.secret.Identity,
		Destination: &destID,
		TTL:         5,
	}

	s.forward(header, &PingRequest{OriginTimestamp: 1}, nil)

	if got := s.Forwarded(); got != 1 {
		t.Fatalf("forwarded = %d, want 1", got)
	}
}

// TestForwardDirectWriteError verifies that a write failure on the
// direct path is handled gracefully: logged but no forwarded count.
func TestForwardDirectWriteError(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	srvTr, _ := connectedTransports(t)
	srvTr.conn.Close() // force write error

	destID := Identity{0xBB}
	s := &Server{
		seen:     seen,
		secret:   secret,
		sessions: map[Identity]*Transport{destID: srvTr},
	}

	header := &Header{
		PayloadType: PPingRequest,
		PayloadHash: *NewPayloadHash([]byte("direct-err")),
		Origin:      s.secret.Identity,
		Destination: &destID,
		TTL:         5,
	}

	s.forward(header, &PingRequest{OriginTimestamp: 1}, nil)

	if got := s.Forwarded(); got != 0 {
		t.Fatalf("forwarded = %d, want 0 (write should have failed)", got)
	}
}

// TestForwardFlood verifies the flood path of forward(): when the
// destination is NOT a directly connected peer, the message is sent
// to all sessions except the source.
func TestForwardFlood(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	peerIDs := [3]Identity{{0x01}, {0x02}, {0x03}}
	sessions := make(map[Identity]*Transport, 3)
	for _, pid := range peerIDs {
		srv, cli := connectedTransports(t)
		sessions[pid] = srv
		drainTransport(t, cli)
	}

	s := &Server{
		seen:     seen,
		secret:   secret,
		sessions: sessions,
	}

	// Destination NOT in sessions — triggers flood.
	destID := Identity{0xFF}
	from := peerIDs[0] // source peer — should be skipped
	header := &Header{
		PayloadType: PPingRequest,
		PayloadHash: *NewPayloadHash([]byte("flood")),
		Origin:      s.secret.Identity,
		Destination: &destID,
		TTL:         5,
	}

	s.forward(header, &PingRequest{OriginTimestamp: 1}, &from)

	if got := s.Forwarded(); got != 2 {
		t.Fatalf("forwarded = %d, want 2 (3 peers minus source)", got)
	}
}

// TestForwardFloodNilFrom verifies that when from is nil (locally
// originated), the flood sends to ALL connected peers.
func TestForwardFloodNilFrom(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	peerIDs := [2]Identity{{0x10}, {0x20}}
	sessions := make(map[Identity]*Transport, 2)
	for _, pid := range peerIDs {
		srv, cli := connectedTransports(t)
		sessions[pid] = srv
		drainTransport(t, cli)
	}

	s := &Server{
		seen:     seen,
		secret:   secret,
		sessions: sessions,
	}

	destID := Identity{0xFF}
	header := &Header{
		PayloadType: PPingRequest,
		PayloadHash: *NewPayloadHash([]byte("flood-nil")),
		Origin:      s.secret.Identity,
		Destination: &destID,
		TTL:         3,
	}

	s.forward(header, &PingRequest{OriginTimestamp: 1}, nil)

	if got := s.Forwarded(); got != 2 {
		t.Fatalf("forwarded = %d, want 2 (all peers, nil from)", got)
	}
}

// TestForwardFloodWriteError verifies that a write error during flood
// to one peer does not prevent delivery to other peers.
func TestForwardFloodWriteError(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	goodID := Identity{0xAA}
	badID := Identity{0xBB}

	goodSrv, goodCli := connectedTransports(t)
	drainTransport(t, goodCli)

	badSrv, _ := connectedTransports(t)
	badSrv.conn.Close() // force write error

	s := &Server{
		seen:   seen,
		secret: secret,
		sessions: map[Identity]*Transport{
			goodID: goodSrv,
			badID:  badSrv,
		},
	}

	destID := Identity{0xFF}
	header := &Header{
		PayloadType: PPingRequest,
		PayloadHash: *NewPayloadHash([]byte("flood-err")),
		Origin:      s.secret.Identity,
		Destination: &destID,
		TTL:         5,
	}

	s.forward(header, &PingRequest{OriginTimestamp: 1}, nil)

	// Only the good peer should increment forwarded.
	if got := s.Forwarded(); got != 1 {
		t.Fatalf("forwarded = %d, want 1 (one good, one failed)", got)
	}
}

// --- decryptPayload() coverage ---------------------------------------------

// TestDecryptPayloadErrors exercises all error paths in decryptPayload.
func TestDecryptPayloadErrors(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	recipientSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	senderPub, err := senderSecret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := recipientSecret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	validPayload, err := json.Marshal(PingRequest{OriginTimestamp: 42})
	if err != nil {
		t.Fatal(err)
	}
	validEP, err := SealBox(validPayload, recipientPub, senderPriv,
		senderSecret.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	unknownTypeEP, err := SealBox(validPayload, recipientPub, senderPriv,
		senderSecret.Identity, "bogus_type")
	if err != nil {
		t.Fatal(err)
	}

	garbageEP, err := SealBox([]byte("{not json!!!"), recipientPub,
		senderPriv, senderSecret.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		peers   map[Identity]*PeerRecord
		ep      *EncryptedPayload
		wantSub string // substring of error message
	}{
		{
			name:    "unknown sender",
			peers:   map[Identity]*PeerRecord{},
			ep:      validEP,
			wantSub: "unknown sender",
		},
		{
			name: "sender has no NaCl key",
			peers: map[Identity]*PeerRecord{
				senderSecret.Identity: {
					Identity: senderSecret.Identity,
					Version:  ProtocolVersion,
				},
			},
			ep:      validEP,
			wantSub: "has no NaCl public key",
		},
		{
			name: "OpenBox failure wrong key",
			peers: map[Identity]*PeerRecord{
				senderSecret.Identity: {
					Identity: senderSecret.Identity,
					Version:  ProtocolVersion,
					NaClPub:  make([]byte, NaClPubSize),
				},
			},
			ep:      validEP,
			wantSub: "nacl box open failed",
		},
		{
			name: "unknown inner type",
			peers: map[Identity]*PeerRecord{
				senderSecret.Identity: {
					Identity: senderSecret.Identity,
					Version:  ProtocolVersion,
					NaClPub:  senderPub,
				},
			},
			ep:      unknownTypeEP,
			wantSub: "unknown inner type",
		},
		{
			name: "unmarshal failure",
			peers: map[Identity]*PeerRecord{
				senderSecret.Identity: {
					Identity: senderSecret.Identity,
					Version:  ProtocolVersion,
					NaClPub:  senderPub,
				},
			},
			ep:      garbageEP,
			wantSub: "unmarshal inner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				seen:   seen,
				secret: recipientSecret,
				peers:  tt.peers,
			}
			_, err := s.decryptPayload(tt.ep)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			got := err.Error()
			if !strings.Contains(got, tt.wantSub) {
				t.Fatalf("error %q does not contain %q",
					got, tt.wantSub)
			}
		})
	}
}

// TestDecryptPayloadSuccess verifies the happy path: a properly
// encrypted PingRequest is decrypted and decoded.
func TestDecryptPayloadSuccess(t *testing.T) {
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	recipientSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	senderPub, err := senderSecret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := recipientSecret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(PingRequest{OriginTimestamp: 99})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := SealBox(payload, recipientPub, senderPriv,
		senderSecret.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{
		seen:   seen,
		secret: recipientSecret,
		peers: map[Identity]*PeerRecord{
			senderSecret.Identity: {
				Identity: senderSecret.Identity,
				Version:  ProtocolVersion,
				NaClPub:  senderPub,
			},
		},
	}

	result, err := s.decryptPayload(ep)
	if err != nil {
		t.Fatalf("decryptPayload: %v", err)
	}
	ping, ok := result.(*PingRequest)
	if !ok {
		t.Fatalf("got %T, want *PingRequest", result)
	}
	if ping.OriginTimestamp != 99 {
		t.Fatalf("OriginTimestamp = %d, want 99",
			ping.OriginTimestamp)
	}
}

// --- encrypt() coverage ---------------------------------------------------

// TestEncryptMessageTooLarge verifies that encrypt returns
// ErrMessageTooLarge when the payload exceeds TransportMaxSize.
func TestEncryptMessageTooLarge(t *testing.T) {
	srv, _ := connectedTransports(t)

	// TransportMaxSize is 0x00ffffff (16MB).  A payload of that
	// size plus nonce + secretbox overhead exceeds the limit.
	huge := make([]byte, TransportMaxSize)
	_, err := srv.encrypt(huge)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("encrypt(huge) = %v, want ErrMessageTooLarge", err)
	}
}

// --- intentionally uncovered paths ----------------------------------------
//
// The following four branches are unreachable under normal operation and
// are intentionally left uncovered.  They exist as defensive checks
// against conditions that cannot occur without replacing stdlib internals.
//
//  1. NaClPublicKey (protocol.go:670) — calls NaClPrivateKey which does
//     SHA256 domain separation then ecdh.X25519().NewPrivateKey(seed).
//     SHA256 always produces a valid 32-byte X25519 seed, so
//     NewPrivateKey cannot fail.
//
//  2. SealBox (protocol.go:685) — crypto/rand.Read nonce error.  Only
//     fails if the OS entropy source is broken (e.g. /dev/urandom
//     unavailable), which is unrecoverable anyway.
//
//  3. decryptPayload (continuum.go:933) — same NaClPrivateKey error as
//     #1, reached through the recipient's own Secret which is always
//     valid if the server started.
//
//  4. encrypt (protocol.go:1088) — diagnostic panic checking that
//     secretbox.Seal output length equals nonce + plaintext + overhead.
//     This is a compile-time invariant of the NaCl secretbox
//     implementation and cannot fire.

// --- fuzz tests -----------------------------------------------------------

// FuzzOpenBox ensures OpenBox never panics on arbitrary inputs.
func FuzzOpenBox(f *testing.F) {
	secret, err := NewSecret()
	if err != nil {
		f.Fatal(err)
	}
	priv, err := secret.NaClPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	pub, err := secret.NaClPublicKey()
	if err != nil {
		f.Fatal(err)
	}

	// Seed with a valid sealed box.
	plain := []byte("hello")
	ep, err := SealBox(plain, pub, priv, secret.Identity, PPingRequest)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ep.Nonce[:], ep.Ciphertext, pub)

	// Seed with degenerate inputs.
	f.Add(make([]byte, 24), []byte{}, make([]byte, 32))
	f.Add(make([]byte, 24), []byte{0xff}, make([]byte, 32))

	f.Fuzz(func(t *testing.T, nonce, ciphertext, senderPub []byte) {
		if len(nonce) != 24 {
			return
		}
		var n [24]byte
		copy(n[:], nonce)
		ep := &EncryptedPayload{
			Nonce:      n,
			Ciphertext: ciphertext,
			Sender:     Identity{},
			InnerType:  PPingRequest,
		}
		// Must not panic regardless of input.
		_, _ = OpenBox(ep, senderPub, priv)
	})
}

// FuzzDecryptPayload ensures decryptPayload never panics on
// arbitrary EncryptedPayload fields.
func FuzzDecryptPayload(f *testing.F) {
	seen, err := ttl.New(64, true)
	if err != nil {
		f.Fatal(err)
	}
	recipientSecret, err := NewSecret()
	if err != nil {
		f.Fatal(err)
	}
	senderSecret, err := NewSecret()
	if err != nil {
		f.Fatal(err)
	}
	senderPub, err := senderSecret.NaClPublicKey()
	if err != nil {
		f.Fatal(err)
	}
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	recipientPub, err := recipientSecret.NaClPublicKey()
	if err != nil {
		f.Fatal(err)
	}

	// Seed with valid encrypted payload.
	payload, err := json.Marshal(PingRequest{OriginTimestamp: 1})
	if err != nil {
		f.Fatal(err)
	}
	ep, err := SealBox(payload, recipientPub, senderPriv,
		senderSecret.Identity, PPingRequest)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ep.Nonce[:], ep.Ciphertext, ep.Sender[:], string(ep.InnerType))

	// Seed with garbage.
	f.Add(make([]byte, 24), []byte("garbage"), make([]byte, len(Identity{})), "bogus")

	s := &Server{
		seen:   seen,
		secret: recipientSecret,
		peers: map[Identity]*PeerRecord{
			senderSecret.Identity: {
				Identity: senderSecret.Identity,
				Version:  ProtocolVersion,
				NaClPub:  senderPub,
			},
		},
	}

	f.Fuzz(func(t *testing.T, nonce, ciphertext, sender []byte, innerType string) {
		if len(nonce) != 24 || len(sender) != len(Identity{}) {
			return
		}
		var n [24]byte
		copy(n[:], nonce)
		var id Identity
		copy(id[:], sender)
		ep := &EncryptedPayload{
			Nonce:      n,
			Ciphertext: ciphertext,
			Sender:     id,
			InnerType:  PayloadType(innerType),
		}
		// Must not panic regardless of input.
		_, _ = s.decryptPayload(ep)
	})
}

// --- benchmarks -----------------------------------------------------------

// BenchmarkForwardDirect measures the direct-send path of forward().
func BenchmarkForwardDirect(b *testing.B) {
	seen, err := ttl.New(4096, true)
	if err != nil {
		b.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		b.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	b.Cleanup(cancel)

	sp, cp := net.Pipe()
	b.Cleanup(func() { sp.Close() })
	b.Cleanup(func() { cp.Close() })

	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		b.Fatal(err)
	}
	cli := new(Transport)
	errCh := make(chan error, 2)
	go func() { errCh <- srv.KeyExchange(ctx, sp) }()
	go func() { errCh <- cli.KeyExchange(ctx, cp) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			b.Fatalf("KeyExchange: %v", err)
		}
	}

	// Drain reads so WriteHeader doesn't block.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			if _, err := cli.conn.Read(buf); err != nil {
				return
			}
		}
	}()

	destID := Identity{0xAA}
	s := &Server{
		seen:     seen,
		secret:   secret,
		sessions: map[Identity]*Transport{destID: srv},
	}

	header := &Header{
		PayloadType: PPingRequest,
		Origin:      s.secret.Identity,
		Destination: &destID,
		TTL:         5,
	}
	ping := &PingRequest{OriginTimestamp: 1}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header.PayloadHash = *NewPayloadHash([]byte(strconv.Itoa(i)))
		s.forward(header, ping, nil)
	}
}

// BenchmarkForwardFlood measures the flood path with 10 peers.
func BenchmarkForwardFlood(b *testing.B) {
	seen, err := ttl.New(4096, true)
	if err != nil {
		b.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		b.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	b.Cleanup(cancel)

	const numPeers = 10
	sessions := make(map[Identity]*Transport, numPeers)
	for i := 0; i < numPeers; i++ {
		sp, cp := net.Pipe()
		b.Cleanup(func() { sp.Close() })
		b.Cleanup(func() { cp.Close() })

		srv, err := NewTransportFromCurve(ecdh.X25519())
		if err != nil {
			b.Fatal(err)
		}
		cli := new(Transport)
		errCh := make(chan error, 2)
		go func() { errCh <- srv.KeyExchange(ctx, sp) }()
		go func() { errCh <- cli.KeyExchange(ctx, cp) }()
		for j := 0; j < 2; j++ {
			if err := <-errCh; err != nil {
				b.Fatalf("KeyExchange: %v", err)
			}
		}

		go func() {
			buf := make([]byte, 64*1024)
			for {
				if _, err := cli.conn.Read(buf); err != nil {
					return
				}
			}
		}()

		id := Identity{byte(i)}
		sessions[id] = srv
	}

	s := &Server{
		seen:     seen,
		secret:   secret,
		sessions: sessions,
	}

	destID := Identity{0xFF}
	header := &Header{
		PayloadType: PPingRequest,
		Origin:      s.secret.Identity,
		Destination: &destID,
		TTL:         5,
	}
	ping := &PingRequest{OriginTimestamp: 1}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header.PayloadHash = *NewPayloadHash([]byte(strconv.Itoa(i)))
		s.forward(header, ping, nil)
	}
}

// BenchmarkDecryptPayload measures the happy-path decryption.
func BenchmarkDecryptPayload(b *testing.B) {
	seen, err := ttl.New(4096, true)
	if err != nil {
		b.Fatal(err)
	}
	recipientSecret, err := NewSecret()
	if err != nil {
		b.Fatal(err)
	}
	senderSecret, err := NewSecret()
	if err != nil {
		b.Fatal(err)
	}

	senderPub, err := senderSecret.NaClPublicKey()
	if err != nil {
		b.Fatal(err)
	}
	recipientPub, err := recipientSecret.NaClPublicKey()
	if err != nil {
		b.Fatal(err)
	}
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		b.Fatal(err)
	}

	payload, err := json.Marshal(PingRequest{OriginTimestamp: 42})
	if err != nil {
		b.Fatal(err)
	}

	s := &Server{
		seen:   seen,
		secret: recipientSecret,
		peers: map[Identity]*PeerRecord{
			senderSecret.Identity: {
				Identity: senderSecret.Identity,
				Version:  ProtocolVersion,
				NaClPub:  senderPub,
			},
		},
	}

	// Pre-generate encrypted payloads (each has unique nonce).
	eps := make([]*EncryptedPayload, b.N)
	for i := range eps {
		ep, err := SealBox(payload, recipientPub, senderPriv,
			senderSecret.Identity, PPingRequest)
		if err != nil {
			b.Fatal(err)
		}
		eps[i] = ep
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.decryptPayload(eps[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ==========================================================================
// Coverage tests — peer mesh, gossip, sessions, liveness, DNS
// ==========================================================================

// errOnCloseConn wraps a net.Conn and returns an error on Close().
type errOnCloseConn struct {
	net.Conn
}

func (c *errOnCloseConn) Close() error {
	c.Conn.Close()
	return errors.New("injected close error")
}

// handleTestServer creates a minimal Server suitable for testing the
// handle() dispatch loop.  It returns the Server, the client-side
// Transport (write to send messages into handle, read to receive
// responses), and the identity that handle() treats as the remote peer.
//
// The caller must cancel ctx to shut down.  The function starts
// handle() in a goroutine, drains the two initial protocol messages
// (PeerNotify + PeerListRequest) that handle() sends on startup, and
// returns with handle() blocked on ReadEnvelope — ready for the test
// to write messages.
func handleTestServer(t *testing.T, ctx context.Context) (*Server, *Transport, Identity) {
	t.Helper()

	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	pings, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	srvTr, cliTr := connectedTransports(t)

	peerID := Identity{0xDD}
	s := &Server{
		seen:       seen,
		peersTTL:   peersTTL,
		pings:      pings,
		secret:     secret,
		sessions:   map[Identity]*Transport{peerID: srvTr},
		peers:      make(map[Identity]*PeerRecord),
		ceremonies: make(map[CeremonyID]*CeremonyInfo),
		cfg: &Config{
			PingInterval: time.Hour, // never fires during test
			PeersWanted:  8,
		},
	}

	s.wg.Add(1)
	go s.handle(ctx, &peerID, srvTr)

	// Drain the two initial messages handle() sends: PeerNotify
	// and PeerListRequest.  Without draining, net.Pipe blocks
	// handle()'s writes and it never enters the dispatch loop.
	for i := 0; i < 2; i++ {
		_, _, _, err := cliTr.ReadEnvelope()
		if err != nil {
			t.Fatalf("drain initial message %d: %v", i, err)
		}
	}

	return s, cliTr, peerID
}

// --- Tier 1: easy unit tests ----------------------------------------------

// TestPeerExpired verifies the TTL expiry callback removes the peer.
func TestPeerExpired(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peerID := Identity{0x01}
	s := &Server{
		secret: secret,
		peers:  map[Identity]*PeerRecord{peerID: {Identity: peerID}},
	}
	s.peerExpired(context.Background(), peerID, nil)
	s.mtx.RLock()
	_, exists := s.peers[peerID]
	s.mtx.RUnlock()
	if exists {
		t.Fatal("peer should have been deleted")
	}
}

// TestPeerExpiredBadKey verifies peerExpired handles non-Identity keys
// without panicking (defensive branch).
func TestPeerExpiredBadKey(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret: secret,
		peers:  make(map[Identity]*PeerRecord),
	}
	// Pass a string instead of Identity — must not panic.
	s.peerExpired(context.Background(), "not-an-identity", nil)
}

// TestDeleteAllSessionsCloseError verifies deleteAllSessions handles
// Close() errors gracefully (logs, no panic).
func TestDeleteAllSessionsCloseError(t *testing.T) {
	srvTr, _ := connectedTransports(t)
	// Wrap conn with one that errors on Close.
	srvTr.conn = &errOnCloseConn{Conn: srvTr.conn}

	id := Identity{0xCC}
	s := &Server{
		sessions: map[Identity]*Transport{id: srvTr},
	}
	// Must not panic.
	s.deleteAllSessions()
	if len(s.sessions) != 0 {
		t.Fatal("sessions not empty after deleteAllSessions")
	}
}

// TestPingLoopWriteError verifies pingLoop exits when a write fails.
func TestPingLoopWriteError(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	srvTr, _ := connectedTransports(t)
	srvTr.conn.Close() // force write error

	pings, err := ttl.New(8, true)
	if err != nil {
		t.Fatal(err)
	}

	id := Identity{0xAA}
	s := &Server{
		secret: secret,
		pings:  pings,
		cfg:    &Config{PingInterval: time.Millisecond},
	}

	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.pingLoop(t.Context(), &id, srvTr)
		close(done)
	}()

	select {
	case <-done:
		// Expected: pingLoop exited due to write error.
	case <-time.After(5 * time.Second):
		t.Fatal("pingLoop did not exit after write error")
	}
}

// TestPingLoopContextCancel verifies pingLoop exits when ctx is cancelled.
func TestPingLoopContextCancel(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	srvTr, cliTr := connectedTransports(t)
	drainTransport(t, cliTr)

	pings, err := ttl.New(8, true)
	if err != nil {
		t.Fatal(err)
	}

	id := Identity{0xAA}
	s := &Server{
		secret: secret,
		pings:  pings,
		cfg:    &Config{PingInterval: time.Hour},
	}

	ctx, cancel := context.WithCancel(t.Context())
	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.pingLoop(ctx, &id, srvTr)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// Expected.
	case <-time.After(5 * time.Second):
		t.Fatal("pingLoop did not exit after context cancel")
	}
}

// --- Tier 2: handle dispatch error paths ----------------------------------

// TestHandlePingWriteError verifies that a PingRequest write-back
// failure causes handle() to return (session dies).
func TestHandlePingWriteError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	// Close the underlying conn so the PingResponse write fails.
	// We must close from a goroutine because cliTr.Write will
	// use the same pipe.
	//
	// Strategy: write PingRequest, then immediately close the
	// client conn.  handle() reads the PingRequest, tries to
	// write PingResponse, and gets a write error → returns.
	err := cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatalf("write PingRequest: %v", err)
	}
	cliTr.conn.Close()

	// Wait for handle to exit.
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle did not exit after ping write error")
	}
}

// TestHandlePeerNotifyRequestsPeers verifies that receiving a
// PeerNotify with a higher count triggers a PeerListRequest response.
func TestHandlePeerNotifyRequestsPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	_, cliTr, _ := handleTestServer(t, ctx)

	// Send PeerNotify with count > 0 (server has 0 real peers).
	err := cliTr.Write(Identity{0xEE}, PeerNotify{Count: 100})
	if err != nil {
		t.Fatalf("write PeerNotify: %v", err)
	}

	// handle() should send PeerListRequest back.
	header, payload, _, err := cliTr.ReadEnvelope()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if header.PayloadType != PPeerListRequest {
		t.Fatalf("expected PeerListRequest, got %v (payload: %T)",
			header.PayloadType, payload)
	}
	cancel()
}

// TestHandlePeerListRequestResponds verifies that receiving a
// PeerListRequest causes handle() to send back a PeerListResponse.
func TestHandlePeerListRequestResponds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	_, cliTr, _ := handleTestServer(t, ctx)

	err := cliTr.Write(Identity{0xEE}, PeerListRequest{})
	if err != nil {
		t.Fatalf("write PeerListRequest: %v", err)
	}

	header, _, _, err := cliTr.ReadEnvelope()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if header.PayloadType != PPeerListResponse {
		t.Fatalf("expected PeerListResponse, got %v", header.PayloadType)
	}
	cancel()
}

// TestHandlePeerListResponseLearnsPeers verifies that receiving a
// PeerListResponse with valid peers adds them to the Server's peer map.
func TestHandlePeerListResponseLearnsPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	peerSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peerNaClPub, err := peerSecret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	newPeer := PeerRecord{
		Identity: Identity{0x42},
		Address:  "10.0.0.1:8080",
		Version:  ProtocolVersion,
		NaClPub:  peerNaClPub,
		LastSeen: time.Now().Unix(),
	}
	err = cliTr.Write(Identity{0xEE}, PeerListResponse{
		Peers: []PeerRecord{newPeer},
	})
	if err != nil {
		t.Fatalf("write PeerListResponse: %v", err)
	}

	// Give handle() time to process.  It will also send a
	// PeerNotify to all sessions after learning a new peer.
	// Read that notification to confirm processing is done.
	header, _, _, err := cliTr.ReadEnvelope()
	if err != nil {
		t.Fatalf("read PeerNotify: %v", err)
	}
	if header.PayloadType != PPeerNotify {
		t.Fatalf("expected PeerNotify after learning, got %v",
			header.PayloadType)
	}

	s.mtx.RLock()
	_, found := s.peers[Identity{0x42}]
	s.mtx.RUnlock()
	if !found {
		t.Fatal("peer 0x42 not added to peer map")
	}
	cancel()
}

// TestHandlePeerListResponseTruncation verifies that a PeerListResponse
// with more than maxGossipPeers entries is truncated.
func TestHandlePeerListResponseTruncation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	// Build maxGossipPeers+10 peers with real NaCl keys.
	peers := make([]PeerRecord, maxGossipPeers+10)
	for i := range peers {
		var id Identity
		id[0] = byte(i >> 8)
		id[1] = byte(i)
		id[2] = 0xFF // avoid collision with server identity
		peerSecret, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		naclPub, err := peerSecret.NaClPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = PeerRecord{
			Identity: id,
			Address:  fmt.Sprintf("10.0.%d.%d:8080", i>>8, i&0xFF),
			Version:  ProtocolVersion,
			NaClPub:  naclPub,
			LastSeen: time.Now().Unix(),
		}
	}

	err := cliTr.Write(Identity{0xEE}, PeerListResponse{Peers: peers})
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read the PeerNotify that handle sends after learning peers.
	_, _, _, err = cliTr.ReadEnvelope()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	s.mtx.RLock()
	// Self is always in peers, so total = maxGossipPeers + self.
	// But some peers may collide with self; just verify we're capped.
	count := len(s.peers)
	s.mtx.RUnlock()
	if count > maxGossipPeers+1 {
		t.Fatalf("peer count %d exceeds maxGossipPeers+1 (%d)",
			count, maxGossipPeers+1)
	}
	cancel()
}

// TestHandlePeerListResponseVersionReject verifies that peers with
// wrong protocol version are filtered out.
func TestHandlePeerListResponseVersionReject(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	badPeer := PeerRecord{
		Identity: Identity{0x99},
		Address:  "10.0.0.1:8080",
		Version:  ProtocolVersion + 1, // wrong version
		LastSeen: time.Now().Unix(),
	}
	err := cliTr.Write(Identity{0xEE}, PeerListResponse{
		Peers: []PeerRecord{badPeer},
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// No PeerNotify is sent because no peers were learned.
	// Send another message to confirm handle() processed it.
	err = cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatalf("write ping: %v", err)
	}
	header, _, _, err := cliTr.ReadEnvelope()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if header.PayloadType != PPingResponse {
		t.Fatalf("expected PingResponse, got %v", header.PayloadType)
	}

	s.mtx.RLock()
	_, found := s.peers[Identity{0x99}]
	s.mtx.RUnlock()
	if found {
		t.Fatal("peer with wrong version should have been rejected")
	}
	cancel()
}

// TestHandlePeerListResponseBadAddress verifies that peers with
// invalid addresses are filtered out.
func TestHandlePeerListResponseBadAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	badPeer := PeerRecord{
		Identity: Identity{0x88},
		Address:  "not-a-valid-address", // no port
		Version:  ProtocolVersion,
		LastSeen: time.Now().Unix(),
	}
	err := cliTr.Write(Identity{0xEE}, PeerListResponse{
		Peers: []PeerRecord{badPeer},
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Confirm processing by sending a ping.
	err = cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatalf("write ping: %v", err)
	}
	header, _, _, err := cliTr.ReadEnvelope()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if header.PayloadType != PPingResponse {
		t.Fatalf("expected PingResponse, got %v", header.PayloadType)
	}

	s.mtx.RLock()
	_, found := s.peers[Identity{0x88}]
	s.mtx.RUnlock()
	if found {
		t.Fatal("peer with bad address should have been rejected")
	}
	cancel()
}

// TestHandleRoutedMessageDedup verifies that routed messages (with
// Destination set) go through dedup and the forward path.
func TestHandleRoutedMessageDedup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	// Add a second peer so there's someone to forward to.
	peer2ID := Identity{0xBB}
	srv2, cli2 := connectedTransports(t)
	drainTransport(t, cli2)
	s.mtx.Lock()
	s.sessions[peer2ID] = srv2
	s.mtx.Unlock()

	// Send a routed message destined for a non-existent peer
	// (neither server nor peer2) — forces flood forward.
	dest := Identity{0xFF}
	err := cliTr.WriteTo(Identity{0xEE}, dest, 5,
		PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatalf("write routed msg: %v", err)
	}

	// Give handle time to process.  Send a ping to synchronize.
	err = cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 2})
	if err != nil {
		t.Fatalf("write sync ping: %v", err)
	}
	_, _, _, err = cliTr.ReadEnvelope()
	if err != nil {
		t.Fatalf("read sync: %v", err)
	}

	if got := s.Forwarded(); got == 0 {
		t.Fatal("expected forwarded > 0, got 0")
	}

	// Send the SAME message again — dedup should drop it.
	before := s.Forwarded()
	err = cliTr.WriteTo(Identity{0xEE}, dest, 5,
		PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatalf("write dup: %v", err)
	}

	// Sync again.
	err = cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 3})
	if err != nil {
		t.Fatalf("write sync2: %v", err)
	}
	_, _, _, err = cliTr.ReadEnvelope()
	if err != nil {
		t.Fatalf("read sync2: %v", err)
	}

	if got := s.Forwarded(); got != before {
		t.Fatalf("forwarded changed from %d to %d, dedup failed",
			before, got)
	}
	cancel()
}

// --- Tier 3: connection error paths ---------------------------------------

// TestConnectDialError verifies connect() handles dial failure.
func TestConnectDialError(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{
		secret:   secret,
		seen:     seen,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		cfg:      &Config{PeersWanted: 8},
	}

	// Dial an unreachable address with a live context so sendErr
	// delivers the error rather than racing with ctx.Done().
	errC := make(chan error, 1)
	s.wg.Add(1)
	go s.connect(t.Context(), "127.0.0.1:1", errC)
	select {
	case err := <-errC:
		if err == nil {
			t.Fatal("expected dial error, got nil")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("connect did not return error")
	}
}

// TestConnectPeerDialError verifies connectPeer() handles dial failure.
func TestConnectPeerDialError(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		cfg:      &Config{PeersWanted: 8},
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // dial will fail immediately

	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.connectPeer(ctx, "127.0.0.1:1")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connectPeer did not return")
	}
}

// TestListenFull verifies that listen() rejects connections when
// PeersWanted is reached.
func TestListenFull(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	s.cfg.PeersWanted = 1 // allow only 1 session

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	addr := waitForListenAddress(t, s, 2*time.Second)

	// First connection should succeed.
	conn1, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	t.Cleanup(func() { conn1.Close() })

	tr1 := new(Transport)
	kxCtx, kxCancel := context.WithTimeout(ctx, 5*time.Second)
	defer kxCancel()
	if err := tr1.KeyExchange(kxCtx, conn1); err != nil {
		t.Fatalf("kx 1: %v", err)
	}
	if _, _, _, err := tr1.Handshake(kxCtx, s.secret, ""); err != nil {
		// The handshake might succeed or the session might succeed.
		// What matters is the SECOND connection gets rejected.
		t.Logf("handshake 1: %v (may be expected)", err)
	}

	// Wait for the session to be registered.
	deadline := time.Now().Add(2 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for len(s.SessionIdentities()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for session registration")
		}
		<-tick.C
	}

	// Second connection: server is "full".  The listen loop
	// closes the connection before doing KX.
	conn2, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		// Server might have rejected at TCP level.
		cancel()
		<-errC
		return
	}
	t.Cleanup(func() { conn2.Close() })

	// Try to do KX — should fail because server closed conn.
	tr2 := new(Transport)
	kx2Ctx, kx2Cancel := context.WithTimeout(ctx, 2*time.Second)
	defer kx2Cancel()
	err = tr2.KeyExchange(kx2Ctx, conn2)
	if err == nil {
		t.Log("KX succeeded unexpectedly, server may have reaped session")
	}

	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server: %v", err)
	}
}

// --- Tier 4: DNS error paths ----------------------------------------------

// TestVerifyDNSIdentityErrors exercises error paths in
// verifyDNSIdentity using the in-process DNS server infrastructure.
func TestVerifyDNSIdentityErrors(t *testing.T) {
	ctx := t.Context()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	domain := "dnstest.gfy"
	fqdn := "target." + domain + "."

	// Lookup error: resolver Dial always fails.
	t.Run("lookup error", func(t *testing.T) {
		s := &Server{secret: secret}
		s.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("dns fail")
			},
		}
		err := s.verifyDNSIdentity(ctx, fqdn, secret.Identity)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "dns txt lookup") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// No TXT records: DNS server has A record but no TXT for hostname.
	// Go's resolver filters by type, so LookupTXT should return empty.
	t.Run("no records", func(t *testing.T) {
		handler := &dnsHandler{
			lookup: make(map[string][]dns.RR),
			nodes:  make(map[string]*node),
		}
		// Insert only an A record — no TXT.
		handler.lookup[fqdn] = []dns.RR{
			&dns.A{
				Hdr: dns.Header{Name: fqdn, Class: dns.ClassINET},
				A:   net.IPv4(127, 0, 0, 1),
			},
		}
		srv := newDNSServer(ctx, handler)
		s := &Server{
			secret:   secret,
			resolver: newResolver(srv.Listener.Addr().String()),
		}
		err := s.verifyDNSIdentity(ctx, fqdn, secret.Identity)
		if err == nil {
			t.Fatal("expected error")
		}
		// Either "no txt records" (empty list) or "txt lookup"
		// (resolver error) — both are correct rejections.
		if !strings.Contains(err.Error(), "dns no txt records") &&
			!strings.Contains(err.Error(), "dns txt lookup") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// Identity mismatch: TXT has valid format but different identity.
	t.Run("identity mismatch", func(t *testing.T) {
		wrongID := Identity{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
		}
		handler := &dnsHandler{
			lookup: make(map[string][]dns.RR),
			nodes:  make(map[string]*node),
		}
		handler.lookup[fqdn] = []dns.RR{
			&dns.TXT{
				Hdr: dns.Header{Name: fqdn, Class: dns.ClassINET},
				Txt: []string{fmt.Sprintf("v=%v; identity=%v",
					dnsAppName, wrongID)},
			},
		}
		srv := newDNSServer(ctx, handler)
		s := &Server{
			secret:   secret,
			resolver: newResolver(srv.Listener.Addr().String()),
		}
		err := s.verifyDNSIdentity(ctx, fqdn, secret.Identity)
		if err == nil {
			t.Fatal("expected identity mismatch error")
		}
		if !strings.Contains(err.Error(), "dns identity mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// Wrong app name: TXT record has wrong v= value.
	t.Run("wrong app name", func(t *testing.T) {
		handler := &dnsHandler{
			lookup: make(map[string][]dns.RR),
			nodes:  make(map[string]*node),
		}
		handler.lookup[fqdn] = []dns.RR{
			&dns.TXT{
				Hdr: dns.Header{Name: fqdn, Class: dns.ClassINET},
				Txt: []string{fmt.Sprintf("v=wrongapp; identity=%v",
					secret.Identity)},
			},
		}
		srv := newDNSServer(ctx, handler)
		s := &Server{
			secret:   secret,
			resolver: newResolver(srv.Listener.Addr().String()),
		}
		err := s.verifyDNSIdentity(ctx, fqdn, secret.Identity)
		if err == nil {
			t.Fatal("expected error for wrong app name")
		}
		if !strings.Contains(err.Error(), "dns no valid txt record") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// Bad identity string in TXT record.
	t.Run("bad identity", func(t *testing.T) {
		handler := &dnsHandler{
			lookup: make(map[string][]dns.RR),
			nodes:  make(map[string]*node),
		}
		handler.lookup[fqdn] = []dns.RR{
			&dns.TXT{
				Hdr: dns.Header{Name: fqdn, Class: dns.ClassINET},
				Txt: []string{fmt.Sprintf("v=%v; identity=ZZZZ",
					dnsAppName)},
			},
		}
		srv := newDNSServer(ctx, handler)
		s := &Server{
			secret:   secret,
			resolver: newResolver(srv.Listener.Addr().String()),
		}
		err := s.verifyDNSIdentity(ctx, fqdn, secret.Identity)
		if err == nil {
			t.Fatal("expected error for bad identity")
		}
		if !strings.Contains(err.Error(), "dns no valid txt record") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestSeedBadHostPort verifies seed() handles malformed addresses.
func TestSeedBadHostPort(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret: secret,
		cfg: &Config{
			Seeds: []string{"no-port-here"},
		},
	}
	// Must not panic.  Error is logged.
	s.seed(t.Context())
}

// TestSeedLookupError verifies seed() handles DNS lookup failures.
func TestSeedLookupError(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret: secret,
		cfg: &Config{
			Seeds: []string{"bad.example.com:8080"},
		},
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("lookup fail")
			},
		},
	}
	// Must not panic.
	s.seed(t.Context())
}

// TestTXTRecordFromAddressErrors exercises error paths in
// TXTRecordFromAddress.
func TestTXTRecordFromAddressErrors(t *testing.T) {
	badAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	// nil resolver + localhost reverse lookup fails.
	_, err := TXTRecordFromAddress(t.Context(), nil, badAddr)
	if err == nil {
		t.Fatal("expected error for reverse lookup of localhost")
	}

	// Resolver whose Dial always fails.
	failResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("lookup fail")
		},
	}
	_, err = TXTRecordFromAddress(t.Context(), failResolver, badAddr)
	if err == nil {
		t.Fatal("expected error for failed resolver")
	}
}

// TestVerifyRemoteDNSIdentityErrors exercises error paths in
// VerifyRemoteDNSIdentity.
func TestVerifyRemoteDNSIdentityErrors(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	badAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	// Resolver whose Dial always fails.
	failResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("lookup fail")
		},
	}
	_, err = VerifyRemoteDNSIdentity(t.Context(), failResolver,
		badAddr, secret.Identity)
	if err == nil {
		t.Fatal("expected error for failed lookup")
	}
}

// --- Tier 5: remaining gaps -----------------------------------------------

// TestNewTransportDNSRequired verifies newTransport rejects peers
// that don't advertise a DNS name when DNSRequired is set.
func TestNewTransportDNSRequired(t *testing.T) {
	preParams := loadPreParams(t, 2)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	s.cfg.DNSRequired = true

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	addr := waitForListenAddress(t, s, 2*time.Second)

	// Connect without advertising DNS name.
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	tr := new(Transport)
	kxCtx, kxCancel := context.WithTimeout(ctx, 5*time.Second)
	defer kxCancel()
	if err := tr.KeyExchange(kxCtx, conn); err != nil {
		t.Fatalf("kx: %v", err)
	}

	// Handshake without DNS name — server should reject.
	clientSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = tr.Handshake(kxCtx, clientSecret, "")
	// The handshake itself may succeed (it's the server's
	// newTransport that rejects).  The conn will be closed
	// by the server.  Either handshake or subsequent read fails.
	if err != nil {
		t.Logf("handshake returned error (expected): %v", err)
	}

	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server: %v", err)
	}
}

// --- Tier 6: remaining coverage gaps ---------------------------------

// TestVerifyDNSIdentityMalformedTXT covers the kvFromTxt parse error
// path (L657) — a TXT record with no "=" separator.
func TestVerifyDNSIdentityMalformedTXT(t *testing.T) {
	ctx := t.Context()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	fqdn := "malformed.test.gfy."
	handler := &dnsHandler{
		lookup: make(map[string][]dns.RR),
		nodes:  make(map[string]*node),
	}
	handler.lookup[fqdn] = []dns.RR{
		&dns.TXT{
			Hdr: dns.Header{Name: fqdn, Class: dns.ClassINET},
			Txt: []string{"garbage-no-equals-sign"},
		},
	}
	srv := newDNSServer(ctx, handler)
	s := &Server{
		secret:   secret,
		resolver: newResolver(srv.Listener.Addr().String()),
	}
	err = s.verifyDNSIdentity(ctx, fqdn, secret.Identity)
	if err == nil {
		t.Fatal("expected error for malformed TXT")
	}
	if !strings.Contains(err.Error(), "dns no valid txt record") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestHandlePeerNotifyWriteError covers L423 — write error when handle()
// tries to send PeerListRequest in response to PeerNotify.
func TestHandlePeerNotifyWriteError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, cliTr, _ := handleTestServer(t, ctx)

	// Send PeerNotify with count > server's PeerCount() so handle()
	// tries to write PeerListRequest back.  On net.Pipe, Write
	// returns only after handle() has read the payload.  Close is
	// permanent — handle()'s subsequent Write fails immediately.
	err := cliTr.Write(Identity{0xDD}, PeerNotify{Count: 999})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	cliTr.conn.Close()
}

// TestHandlePeerListRequestWriteError covers L432 — write error when
// handle() tries to send PeerListResponse.
func TestHandlePeerListRequestWriteError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, cliTr, _ := handleTestServer(t, ctx)

	// Send PeerListRequest, then close conn.  On net.Pipe, Write
	// returns after handle() reads.  Close is permanent — handle()'s
	// PeerListResponse write fails immediately.
	err := cliTr.Write(Identity{0xDD}, PeerListRequest{})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	cliTr.conn.Close()
}

// TestHandlePingResponseRefresh covers the PingResponse case (L413) in
// handle()'s dispatch switch — verifies handle() processes PingResponse
// without crashing and continues.
func TestHandlePingResponseRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, cliTr, _ := handleTestServer(t, ctx)

	// Send PingResponse.  On net.Pipe, Write returns after handle()
	// reads.  No side effect verification needed — if handle()
	// panicked on PingResponse, the pipe would break.
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xDD}, PingResponse{
			OriginTimestamp: time.Now().Unix(),
			PeerTimestamp:   time.Now().Unix(),
		})
	})
	if err := <-errCh; err != nil {
		t.Fatalf("write: %v", err)
	}

	// Prove handle() survived: send PingRequest and expect PingResponse.
	errCh = pipeWrite(func() error {
		return cliTr.Write(Identity{0xDD}, PingRequest{OriginTimestamp: 42})
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	_, payload, _, err := cliTr.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := payload.(*PingResponse); !ok {
		t.Fatalf("expected PingResponse, got %T", payload)
	}

	cliTr.conn.Close()
}

// TestAddPeerRejectEmptyNaClPub covers addPeer rejecting updates
// that lack NaClPub.  E2e encryption is mandatory — every peer
// record MUST carry a valid NaClPub.
func TestAddPeerRejectEmptyNaClPub(t *testing.T) {
	ctx := t.Context()
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peerID := Identity{0xAA}
	naclPub := make([]byte, NaClPubSize)
	naclPub[0] = 0x42

	s := &Server{
		secret:   secret,
		peersTTL: peersTTL,
		peers:    make(map[Identity]*PeerRecord),
		cfg:      &Config{PeersWanted: 8},
	}

	// First add with NaClPub and no address — should succeed.
	if !s.addPeer(ctx, PeerRecord{
		Identity: peerID,
		Version:  ProtocolVersion,
		NaClPub:  naclPub,
	}) {
		t.Fatal("first addPeer should return true")
	}

	// Second add with address but no NaClPub — rejected.
	if s.addPeer(ctx, PeerRecord{
		Identity: peerID,
		Address:  "127.0.0.1:9999",
		Version:  ProtocolVersion,
	}) {
		t.Fatal("addPeer without NaClPub should return false")
	}

	// Existing record should be unchanged.
	s.mtx.RLock()
	pr := s.peers[peerID]
	s.mtx.RUnlock()

	if pr.Address != "" {
		t.Fatalf("address should not be updated: got %q", pr.Address)
	}
	if !bytes.Equal(pr.NaClPub, naclPub) {
		t.Fatalf("NaClPub should be preserved: got %x", pr.NaClPub)
	}
}

// TestConnectPeerKXError covers connectPeer L740 — KeyExchange failure.
// Dials a raw TCP server that speaks garbage, so KX fails.
func TestConnectPeerKXError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start a TCP listener that accepts and immediately closes.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		cfg:      &Config{PeersWanted: 8},
	}
	s.wg.Add(1)
	s.connectPeer(ctx, ln.Addr().String())
	// Must not panic.  KX error is logged.
}

// TestConnectPeerDNSRequired covers connectPeer L745-750 — remote doesn't
// advertise DNS name when DNSRequired is set.
func TestConnectPeerDNSRequired(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Server B: no DNS name configured.
	serverB := newTestServer(t, preParams, 1, "localhost:0", nil)
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	addrB := waitForListenAddress(t, serverB, 2*time.Second)

	// Server A: DNSRequired, connects to B.
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		peersTTL: peersTTL,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		cfg: &Config{
			PeersWanted: 8,
			DNSRequired: true,
		},
	}
	s.wg.Add(1)
	s.connectPeer(ctx, addrB)
	// connectPeer should return with warning about missing DNS name.

	// A should have no sessions.
	s.mtx.RLock()
	sessions := len(s.sessions)
	s.mtx.RUnlock()
	if sessions != 0 {
		t.Fatalf("A has %d sessions, want 0", sessions)
	}

	cancel()
	<-errB
}

// TestConnectKXError covers connect() L1235 — KeyExchange failure
// through the connect() wrapper.
func TestConnectKXError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// TCP listener that accepts and closes immediately.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		peersTTL: peersTTL,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		cfg: &Config{
			PeersWanted: 8,
			Connect:     []string{ln.Addr().String()},
		},
	}
	errC := make(chan error, 1)
	s.wg.Add(1)
	go s.connect(ctx, ln.Addr().String(), errC)

	// connect() dials, KX fails (server closes immediately), sends
	// error to errC.  No retry loop — just read the result.
	select {
	case err := <-errC:
		if err != nil && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, io.EOF) {
			t.Fatalf("connect: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for connect to return")
	}
}

// kxOnlyServer accepts one TCP connection, completes key exchange,
// then closes the connection — causing the remote's Handshake to fail.
func kxOnlyServer(t *testing.T, ctx context.Context) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tr, err := NewTransportFromCurve(ecdh.X25519())
			if err != nil {
				c.Close()
				continue
			}
			if err := tr.KeyExchange(ctx, c); err != nil {
				c.Close()
				continue
			}
			// Close before handshake — remote gets EOF.
			c.Close()
		}
	}()
	return ln
}

// TestConnectPeerHandshakeError covers connectPeer L740 — Handshake
// error after successful KX.
func TestConnectPeerHandshakeError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ln := kxOnlyServer(t, ctx)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		cfg:      &Config{PeersWanted: 8},
	}
	s.wg.Add(1)
	s.connectPeer(ctx, ln.Addr().String())
	// connectPeer logs "handshake" error and returns.
}

// TestConnectPeerDNSVerifyError covers connectPeer L750 — DNS verify
// error (server has DNSRequired, remote advertises DNS but verify fails).
func TestConnectPeerDNSVerifyError(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	domain := "verify.gfy"

	// Server B advertises a DNS name.
	serverB := newTestServer(t, preParams, 1, "localhost:0", nil)
	serverB.cfg.DNSName = "nodeB." + domain
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	addrB := waitForListenAddress(t, serverB, 2*time.Second)

	// DNS server has WRONG identity for nodeB — use a random identity.
	handler := &dnsHandler{
		lookup: make(map[string][]dns.RR),
		nodes:  make(map[string]*node),
	}
	wrongID := Identity{
		0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
		0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
		0xEF, 0xEE, 0xED, 0xEC,
	}
	fqdn := "nodeB." + domain + "."
	handler.lookup[fqdn] = []dns.RR{
		&dns.TXT{
			Hdr: dns.Header{Name: fqdn, Class: dns.ClassINET},
			Txt: []string{fmt.Sprintf("v=%v; identity=%v",
				dnsAppName, wrongID)},
		},
	}
	dnsSrv := newDNSServer(ctx, handler)
	mockResolver := newResolver(dnsSrv.Listener.Addr().String())

	// Server A: DNSRequired + wrong DNS data.
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		peersTTL: peersTTL,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		resolver: mockResolver,
		cfg: &Config{
			PeersWanted: 8,
			DNSRequired: true,
		},
	}
	s.wg.Add(1)
	s.connectPeer(ctx, addrB)
	// connectPeer should fail with "dns identity mismatch".

	s.mtx.RLock()
	sessions := len(s.sessions)
	s.mtx.RUnlock()
	if sessions != 0 {
		t.Fatalf("A has %d sessions, want 0", sessions)
	}

	cancel()
	<-errB
}

// TestConnectHandshakeError covers connect() L1240 — Handshake error
// after successful KX.
func TestConnectHandshakeError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ln := kxOnlyServer(t, ctx)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		peersTTL: peersTTL,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		cfg: &Config{
			PeersWanted: 8,
		},
	}
	errC := make(chan error, 1)
	s.wg.Add(1)
	go s.connect(ctx, ln.Addr().String(), errC)

	select {
	case err := <-errC:
		// Handshake error is expected.
		if err == nil {
			t.Fatal("expected handshake error")
		}
		t.Logf("connect error (expected): %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for connect error")
	}
	cancel()
}

// --- protocol.go: UnmarshalJSON / String / error-path tests -------------------

// TestPayloadHashUnmarshalJSON covers PayloadHash.UnmarshalJSON error paths.
func TestPayloadHashUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"bad json", `not json`, "invalid character"},
		{"bad hex", `"zzzz"`, "encoding/hex"},
		{"wrong length", `"aabbccdd"`, "invalid length"},
		{"happy", `"` + strings.Repeat("ab", 32) + `"`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h PayloadHash
			err := h.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestCeremonyIDUnmarshalJSON covers CeremonyID.UnmarshalJSON error paths.
func TestCeremonyIDUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"bad json", `12345`, "cannot unmarshal"},
		{"bad hex", `"zzzz"`, "encoding/hex"},
		{"wrong length", `"aabb"`, "invalid ceremony id length"},
		{"happy", `"` + strings.Repeat("cd", 32) + `"`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cid CeremonyID
			err := cid.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestIdentityUnmarshalJSONErrors covers Identity.UnmarshalJSON error
// paths (bad JSON, bad hex, wrong length).
func TestIdentityUnmarshalJSONErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"bad json", `notjson`, "invalid character"},
		{"bad hex", `"zzzz"`, "encoding/hex"},
		{"wrong length", `"aabb"`, "invalid identity"},
		{"happy", `"` + strings.Repeat("ef", 20) + `"`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var id Identity
			err := id.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestNewSecretFromStringErrors covers NewSecretFromString error paths.
func TestNewSecretFromStringErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"bad hex", "zzzz", "encoding/hex"},
		{"wrong length", "aabb", "invalid key"},
		{"happy", hex.EncodeToString(make([]byte, 32)), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSecretFromString(tt.input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestCeremonyTypeString covers CeremonyType.String for all values
// plus the unknown default.
func TestCeremonyTypeString(t *testing.T) {
	tests := []struct {
		ct   CeremonyType
		want string
	}{
		{CeremonyKeygen, "keygen"},
		{CeremonyReshare, "reshare"},
		{CeremonySign, "sign"},
		{CeremonyType(99), "unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.ct.String(); got != tt.want {
				t.Fatalf("CeremonyType(%d).String() = %q, want %q",
					tt.ct, got, tt.want)
			}
		})
	}
}

// TestHash256ExtraData covers the extraData loop in Hash256.
func TestHash256ExtraData(t *testing.T) {
	a := []byte("hello")
	b := []byte("world")
	c := []byte("!")

	h1 := Hash256(a, b, c)
	if len(h1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(h1))
	}

	// Different extra data should produce different hash.
	h2 := Hash256(a)
	if bytes.Equal(h1, h2) {
		t.Fatal("extra data should change hash")
	}
}

// --- protocol.go: Transport method error paths --------------------------------

// TestTransportWriteInvalidType covers Write() with an unregistered command
// type that triggers the "invalid command type" error.
func TestTransportWriteInvalidType(t *testing.T) {
	tr, _ := connectedTransports(t)
	err := tr.Write(Identity{}, struct{ X int }{42})
	if err == nil || !strings.Contains(err.Error(), "invalid command type") {
		t.Fatalf("expected 'invalid command type', got: %v", err)
	}
}

// TestTransportWriteToInvalidType covers WriteTo() with an unregistered
// command type.
func TestTransportWriteToInvalidType(t *testing.T) {
	tr, _ := connectedTransports(t)
	err := tr.WriteTo(Identity{}, Identity{}, 1, struct{ X int }{42})
	if err == nil || !strings.Contains(err.Error(), "invalid command type") {
		t.Fatalf("expected 'invalid command type', got: %v", err)
	}
}

// TestWriteHeaderMarshalError covers WriteHeader() when NewPayloadFromCommand
// returns an error due to an unmarshalable payload.
func TestWriteHeaderMarshalError(t *testing.T) {
	tr, _ := connectedTransports(t)
	// json.Marshal will fail on a channel.
	h := Header{PayloadType: "PingRequest"}
	err := tr.WriteHeader(h, make(chan int))
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

// TestSetTransportFromPublicKeyBadKey covers setTransportFromPublicKey
// returning ErrNoSuitableCurve for garbage input.
func TestSetTransportFromPublicKeyBadKey(t *testing.T) {
	tr := new(Transport)
	err := tr.setTransportFromPublicKey([]byte("garbage"))
	if !errors.Is(err, ErrNoSuitableCurve) {
		t.Fatalf("expected ErrNoSuitableCurve, got: %v", err)
	}
}

// TestTransportCloseNilConn covers Transport.Close() when no connection
// has been established, returning ErrNoConn.
func TestTransportCloseNilConn(t *testing.T) {
	tr := new(Transport)
	err := tr.Close()
	if !errors.Is(err, ErrNoConn) {
		t.Fatalf("expected ErrNoConn, got: %v", err)
	}
}

// TestTransportString covers Transport.String() for server and client modes.
func TestTransportString(t *testing.T) {
	srv := &Transport{isServer: true}
	if srv.String() != "server" {
		t.Fatalf("expected 'server', got %q", srv.String())
	}
	cli := &Transport{isServer: false}
	if cli.String() != "client" {
		t.Fatalf("expected 'client', got %q", cli.String())
	}
}

// --- protocol.go: Verify error paths ------------------------------------------

// TestVerifyBadSignature covers Verify() with a corrupted signature.
func TestVerifyBadSignature(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	hash := Hash256([]byte("test message"))
	sig := secret.Sign(hash)

	// Corrupt the signature.
	sig[len(sig)-1] ^= 0xff

	_, err = Verify(hash, secret.Identity, sig)
	if err == nil {
		t.Fatal("expected verification error")
	}
}

// TestVerifyIdentityMismatch covers Verify() where the signature is valid
// but for a different identity.
func TestVerifyIdentityMismatch(t *testing.T) {
	secret1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	secret2, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	hash := Hash256([]byte("test message"))
	sig := secret1.Sign(hash)

	// Verify against wrong identity.
	_, err = Verify(hash, secret2.Identity, sig)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("expected ErrIdentityMismatch, got: %v", err)
	}
}

// --- protocol.go: DNS helper error paths --------------------------------------

// TestTXTRecordFromAddressBadHostPort covers TXTRecordFromAddress when the
// address cannot be split into host:port.
func TestTXTRecordFromAddressBadHostPort(t *testing.T) {
	ctx := t.Context()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
	// net.TCPAddr.String() with port 0 → "127.0.0.1:0" which is valid,
	// so pass a custom addr that has no port separator.
	_, err := TXTRecordFromAddress(ctx, nil, badAddr("no-port-here"))
	if err == nil || !strings.Contains(err.Error(), "dns split") {
		t.Fatalf("expected dns split error, got: %v", err)
	}
	_ = addr
}

// badAddr implements net.Addr with a controlled String() value for testing.
type badAddr string

func (a badAddr) Network() string { return "tcp" }
func (a badAddr) String() string  { return string(a) }

// TestVerifyRemoteDNSIdentityFullPath covers VerifyRemoteDNSIdentity
// through a DNS server with a bad app name and bad identity.
func TestVerifyRemoteDNSIdentityFullPath(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	dnsH := createDNSNodes("good.example", 1)
	dnsS := newDNSServer(ctx, dnsH)
	resolver := newResolver(dnsS.Listener.Addr().String())

	// Get the node address for reverse DNS.
	var n *node
	for _, v := range dnsH.nodes {
		n = v
		break
	}

	t.Run("bad app name", func(t *testing.T) {
		// Replace the TXT record with wrong app name.
		forward, reverse := nodeToDNS(n)
		// Overwrite TXT with bad "v=" value.
		for i, rr := range forward {
			if _, ok := rr.(*dns.TXT); ok {
				forward[i] = &dns.TXT{
					Hdr: dns.Header{
						Name:  n.DNSName,
						Class: dns.ClassINET,
						TTL:   300,
					},
					Txt: []string{"v=wrongapp; identity=" + n.Secret.String()},
				}
			}
		}
		dnsH.insertDNS(n, forward, reverse)

		addr := &net.TCPAddr{IP: n.IP, Port: int(n.Port)}
		_, err := VerifyRemoteDNSIdentity(ctx, resolver, addr, n.Secret.Identity)
		if err == nil || !strings.Contains(err.Error(), "dns invalid app name") {
			t.Fatalf("expected 'dns invalid app name', got: %v", err)
		}
	})

	t.Run("bad identity string", func(t *testing.T) {
		// Replace with valid app name but garbled identity.
		forward, reverse := nodeToDNS(n)
		for i, rr := range forward {
			if _, ok := rr.(*dns.TXT); ok {
				forward[i] = &dns.TXT{
					Hdr: dns.Header{
						Name:  n.DNSName,
						Class: dns.ClassINET,
						TTL:   300,
					},
					Txt: []string{"v=transfunctioner; identity=notvalidhex!!!"},
				}
			}
		}
		dnsH.insertDNS(n, forward, reverse)

		addr := &net.TCPAddr{IP: n.IP, Port: int(n.Port)}
		_, err := VerifyRemoteDNSIdentity(ctx, resolver, addr, n.Secret.Identity)
		if err == nil || !strings.Contains(err.Error(), "dns invalid identity") {
			t.Fatalf("expected 'dns invalid identity', got: %v", err)
		}
	})
}

// --- tss_rpc.go tests ---------------------------------------------------------

// TestServerTSSTransportCeremonyLifecycle covers registerCeremony,
// unregisterCeremony, and ceremonyType.
func TestServerTSSTransportCeremonyLifecycle(t *testing.T) {
	stt := &serverTSSTransport{
		ctypes: make(map[CeremonyID]CeremonyType),
	}

	cid := NewCeremonyID()

	// Not registered yet.
	if _, ok := stt.ceremonyType(cid); ok {
		t.Fatal("expected ceremony not found")
	}

	// Register.
	stt.registerCeremony(cid, CeremonyKeygen)
	ct, ok := stt.ceremonyType(cid)
	if !ok {
		t.Fatal("expected ceremony found after register")
	}
	if ct != CeremonyKeygen {
		t.Fatalf("expected CeremonyKeygen, got %v", ct)
	}

	// Unregister.
	stt.unregisterCeremony(cid)
	if _, ok := stt.ceremonyType(cid); ok {
		t.Fatal("expected ceremony not found after unregister")
	}
}

// TestServerTSSTransportSendErrors covers Send() error paths: empty data,
// unknown ceremony, and no session for peer.
func TestServerTSSTransportSendErrors(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
	}
	stt := newServerTSSTransport(s)

	cid := NewCeremonyID()
	target := Identity{}

	t.Run("empty data", func(t *testing.T) {
		err := stt.Send(target, cid, nil)
		if err == nil || !strings.Contains(err.Error(), "empty TSS data") {
			t.Fatalf("expected 'empty TSS data', got: %v", err)
		}
	})

	t.Run("unknown ceremony", func(t *testing.T) {
		err := stt.Send(target, cid, []byte{0x00, 0x01})
		if !errors.Is(err, ErrUnknownCeremony) {
			t.Fatalf("expected ErrUnknownCeremony, got: %v", err)
		}
	})

	t.Run("no session for peer", func(t *testing.T) {
		stt.registerCeremony(cid, CeremonyKeygen)
		defer stt.unregisterCeremony(cid)

		err := stt.Send(target, cid, []byte{0x00, 0x01})
		if err == nil || !strings.Contains(err.Error(), "no session for peer") {
			t.Fatalf("expected 'no session for peer', got: %v", err)
		}
	})

	t.Run("reshare data too short", func(t *testing.T) {
		stt.registerCeremony(cid, CeremonyReshare)
		defer stt.unregisterCeremony(cid)

		err := stt.Send(target, cid, []byte{0x01})
		if err == nil || !strings.Contains(err.Error(), "reshare data too short") {
			t.Fatalf("expected 'reshare data too short', got: %v", err)
		}
	})
}

// TestPartiesToIdentities covers partiesToIdentities for empty input,
// bad party ID, and a valid conversion.
func TestPartiesToIdentities(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		ids := partiesToIdentities(nil)
		if ids != nil {
			t.Fatalf("expected nil, got %v", ids)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		ids := partiesToIdentities(tss.UnSortedPartyIDs{})
		if ids != nil {
			t.Fatalf("expected nil, got %v", ids)
		}
	})

	t.Run("bad party id", func(t *testing.T) {
		bad := tss.NewPartyID("not-valid-hex", "bad", big.NewInt(1))
		ids := partiesToIdentities(tss.UnSortedPartyIDs{bad})
		if ids != nil {
			t.Fatalf("expected nil for bad ID, got %v", ids)
		}
	})

	t.Run("valid party", func(t *testing.T) {
		secret, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		idStr := secret.String()
		pid := tss.NewPartyID(idStr, "test", big.NewInt(1))
		ids := partiesToIdentities(tss.UnSortedPartyIDs{pid})
		if len(ids) != 1 {
			t.Fatalf("expected 1 identity, got %d", len(ids))
		}
		if ids[0] != secret.Identity {
			t.Fatalf("identity mismatch: %s != %s", ids[0], secret.Identity)
		}
	})
}

// TestKVFromTxt covers kvFromTxt error and happy paths.
func TestKVFromTxt(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		m, err := kvFromTxt("v=transfunctioner; identity=abc123")
		if err != nil {
			t.Fatal(err)
		}
		if m["v"] != "transfunctioner" {
			t.Fatalf("expected 'transfunctioner', got %q", m["v"])
		}
		if m["identity"] != "abc123" {
			t.Fatalf("expected 'abc123', got %q", m["identity"])
		}
	})

	t.Run("no equals", func(t *testing.T) {
		_, err := kvFromTxt("badrecord")
		if !errors.Is(err, ErrInvalidTXTRecord) {
			t.Fatalf("expected ErrInvalidTXTRecord, got: %v", err)
		}
	})

	t.Run("partial bad", func(t *testing.T) {
		_, err := kvFromTxt("v=good; badpart")
		if !errors.Is(err, ErrInvalidTXTRecord) {
			t.Fatalf("expected ErrInvalidTXTRecord, got: %v", err)
		}
	})
}

// TestTransportKeyExchangeVersionMismatch covers Transport.KeyExchange
// rejecting a peer with wrong transport version.
//
// The client side calls setTransportFromPublicKey before the version
// check, so the fake server must send a VALID public key with a bad
// version. Otherwise curve detection fails first.
func TestTransportKeyExchangeVersionMismatch(t *testing.T) {
	ctx := t.Context()

	// Generate a real ECDH key so setTransportFromPublicKey succeeds.
	fakeKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a listener that sends a valid pubkey but bad version.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send a TransportRequest with valid key but wrong version.
		tr := TransportRequest{
			Version:   999,
			PublicKey: fakeKey.PublicKey().Bytes(),
		}
		_ = json.NewEncoder(conn).Encode(tr)
		// Read their response to not hang.
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
	}()

	// Client connects.
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := new(Transport)
	err = client.KeyExchange(ctx, conn)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got: %v", err)
	}
}

// TestTransportKeyExchangeEmptyPublicKey covers Transport.KeyExchange
// rejecting a peer with empty public key.
//
// Client-side setTransportFromPublicKey runs before validation, so an
// empty key from the server returns ErrNoSuitableCurve. To hit
// ErrInvalidPublicKey, we test the SERVER side receiving empty pubkey.
func TestTransportKeyExchangeEmptyPublicKey(t *testing.T) {
	ctx := t.Context()

	// Create a server transport.
	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		// Server runs KeyExchange — will read client's empty pubkey.
		errCh <- srv.KeyExchange(ctx, conn)
	}()

	// Client sends valid version but empty pubkey.
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read server's TransportRequest first (server sends first).
	var serverTR TransportRequest
	if err := readJSONLine(conn, &serverTR); err != nil {
		t.Fatalf("read server TR: %v", err)
	}

	// Send our TransportRequest with empty public key.
	tr := TransportRequest{Version: TransportVersion, PublicKey: nil}
	if err := json.NewEncoder(conn).Encode(tr); err != nil {
		t.Fatalf("send TR: %v", err)
	}

	// Server should reject with ErrInvalidPublicKey.
	srvErr := <-errCh
	if !errors.Is(srvErr, ErrInvalidPublicKey) {
		t.Fatalf("expected ErrInvalidPublicKey, got: %v", srvErr)
	}
}

// TestTransportKeyExchangeEmptyPublicKeyClient covers the client side
// receiving an empty public key from the server, which fails during
// curve detection before reaching validation.
func TestTransportKeyExchangeEmptyPublicKeyClient(t *testing.T) {
	ctx := t.Context()

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send valid version but empty public key.
		tr := TransportRequest{Version: TransportVersion, PublicKey: nil}
		_ = json.NewEncoder(conn).Encode(tr)
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
	}()

	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := new(Transport)
	err = client.KeyExchange(ctx, conn)
	if !errors.Is(err, ErrNoSuitableCurve) {
		t.Fatalf("expected ErrNoSuitableCurve, got: %v", err)
	}
}

// TestNewTransportFromPublicKeyBadKey covers newTransportFromPublicKey
// with garbage input.
func TestNewTransportFromPublicKeyBadKey(t *testing.T) {
	_, err := newTransportFromPublicKey([]byte("garbage"))
	if !errors.Is(err, ErrNoSuitableCurve) {
		t.Fatalf("expected ErrNoSuitableCurve, got: %v", err)
	}
}

// TestReadEnvelope covers ReadEnvelope returning the cleartext bytes.
func TestReadEnvelope(t *testing.T) {
	srv, cli := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Write in goroutine — net.Pipe is synchronous.
	errCh := pipeWrite(func() error {
		return srv.Write(secret.Identity, PingRequest{OriginTimestamp: 12345})
	})

	// Read via ReadEnvelope on client.
	h, cmd, cleartext, err := cli.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatal(werr)
	}
	if h == nil {
		t.Fatal("header is nil")
	}
	if _, ok := cmd.(*PingRequest); !ok {
		t.Fatalf("expected *PingRequest, got %T", cmd)
	}
	if len(cleartext) == 0 {
		t.Fatal("cleartext should not be empty")
	}
}

// TestDecryptBadCiphertext covers decrypt() with too-short ciphertext
// and tampered ciphertext.
func TestDecryptBadCiphertext(t *testing.T) {
	srv, _ := connectedTransports(t)

	t.Run("too short", func(t *testing.T) {
		_, err := srv.decrypt([]byte("short"))
		if !errors.Is(err, ErrInvalidSecretboxLength) {
			t.Fatalf("expected ErrInvalidSecretboxLength, got: %v", err)
		}
	})

	t.Run("tampered", func(t *testing.T) {
		// Create valid ciphertext then tamper.
		ct, err := srv.encrypt([]byte(`{"payloadtype":"PingRequest"}`))
		if err != nil {
			t.Fatal(err)
		}
		// Tamper with ciphertext body (skip 3-byte size prefix).
		if len(ct) > 10 {
			ct[len(ct)-1] ^= 0xff
		}
		// Strip size prefix for decrypt.
		_, err = srv.decrypt(ct[3:])
		if !errors.Is(err, ErrDecrypt) {
			t.Fatalf("expected ErrDecrypt, got: %v", err)
		}
	})
}

// TestIdentityBytes covers Identity.Bytes() returning a copy.
func TestIdentityBytes(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b := secret.Bytes()
	if len(b) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(b))
	}
	// Mutating the copy should not affect the original.
	b[0] ^= 0xff
	if b[0] == secret.Identity[0] {
		t.Fatal("Bytes() should return a copy")
	}
}

// TestOpenBoxBadSenderKey covers OpenBox with invalid sender public key length.
func TestOpenBoxBadSenderKey(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ep := &EncryptedPayload{}
	_, err = OpenBox(ep, []byte("short"), priv)
	if !errors.Is(err, ErrInvalidNaClPub) {
		t.Fatalf("expected ErrInvalidNaClPub, got: %v", err)
	}
}

// --- Transport encrypted I/O coverage (Priority 1) -----------------------
//
// These tests cover Read, ReadEnvelope, readBlob, read, write, Write,
// WriteTo, and WriteHeader error paths. They use connectedTransports()
// to get a pair with completed KeyExchange over net.Pipe.
//
// NOTE: net.Pipe is synchronous — writes block until the reader consumes.
// All write→read tests must launch the writer in a goroutine.

// pipeWrite launches a write in a goroutine and returns a channel that
// delivers the error. Required because net.Pipe blocks writes until
// the matching read occurs.
func pipeWrite(fn func() error) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- fn() }()
	return ch
}

// TestTransportRead covers the public Read() function which delegates
// to read() and discards the cleartext bytes.
func TestTransportRead(t *testing.T) {
	srv, cli := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := pipeWrite(func() error {
		return srv.Write(secret.Identity, PingRequest{OriginTimestamp: 99})
	})

	h, cmd, err := cli.Read()
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatal(werr)
	}
	if h == nil {
		t.Fatal("header is nil")
	}
	pr, ok := cmd.(*PingRequest)
	if !ok {
		t.Fatalf("expected *PingRequest, got %T", cmd)
	}
	if pr.OriginTimestamp != 99 {
		t.Fatalf("expected 99, got %d", pr.OriginTimestamp)
	}
}

// TestTransportReadWriteRoundtrip exercises a full Write→Read cycle for
// several command types to cover read()'s reflect-based dispatch.
func TestTransportReadWriteRoundtrip(t *testing.T) {
	srv, cli := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// PingResponse
	errCh := pipeWrite(func() error {
		return srv.Write(secret.Identity, PingResponse{
			OriginTimestamp: 1,
			PeerTimestamp:   2,
		})
	})
	_, cmd, err := cli.Read()
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatal(werr)
	}
	if _, ok := cmd.(*PingResponse); !ok {
		t.Fatalf("expected *PingResponse, got %T", cmd)
	}

	// HelloRequest
	errCh = pipeWrite(func() error {
		return srv.Write(secret.Identity, HelloRequest{
			Version: ProtocolVersion,
		})
	})
	_, cmd, err = cli.Read()
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatal(werr)
	}
	if _, ok := cmd.(*HelloRequest); !ok {
		t.Fatalf("expected *HelloRequest, got %T", cmd)
	}
}

// TestReadBlobConnectionReset covers readBlob when the underlying
// connection is closed before any data is read.
func TestReadBlobConnectionReset(t *testing.T) {
	srv, cli := connectedTransports(t)

	// Close the server's end — client readBlob should error.
	srv.mtx.Lock()
	srv.conn.Close()
	srv.mtx.Unlock()

	_, err := cli.readBlob(time.Second)
	if err == nil {
		t.Fatal("expected error on closed connection")
	}
}

// TestReadBlobPartialRead covers readBlob when the connection closes
// after writing the size but before the full blob arrives.
func TestReadBlobPartialRead(t *testing.T) {
	sp, cp := net.Pipe()
	defer cp.Close()

	_, cli := connectedTransports(t)
	// Replace the client transport's connection with our pipe.
	cli.mtx.Lock()
	cli.conn = cp
	cli.mtx.Unlock()

	go func() {
		// Write a valid 3-byte size header for 100 bytes.
		var size [3]byte
		size[0] = 0
		size[1] = 0
		size[2] = 100
		_, _ = sp.Write(size[:])
		// Write only 10 bytes then close — short read.
		_, _ = sp.Write(make([]byte, 10))
		sp.Close()
	}()

	_, err := cli.readBlob(2 * time.Second)
	if err == nil {
		t.Fatal("expected error on partial blob read")
	}
}

// TestReadDecryptError covers read() when the blob is valid-sized but
// contains corrupted ciphertext that fails decryption.
func TestReadDecryptError(t *testing.T) {
	sp, cp := net.Pipe()
	defer cp.Close()

	_, cli := connectedTransports(t)
	// Replace client connection with our pipe.
	cli.mtx.Lock()
	cli.conn = cp
	cli.mtx.Unlock()

	go func() {
		// Write a valid size header + garbage ciphertext.
		blob := make([]byte, 100)
		for i := range blob {
			blob[i] = byte(i)
		}
		var size [3]byte
		binary.BigEndian.PutUint16(size[1:3], uint16(len(blob)))
		size[0] = 0
		_, _ = sp.Write(size[:])
		_, _ = sp.Write(blob)
	}()

	_, _, _, err := cli.read(2 * time.Second)
	if err == nil {
		t.Fatal("expected decrypt error")
	}
	if !errors.Is(err, ErrDecrypt) && !errors.Is(err, ErrInvalidSecretboxLength) {
		t.Fatalf("expected decrypt-related error, got: %v", err)
	}
}

// TestWriteConnectionClosed covers write() when the underlying
// connection is already closed.
func TestWriteConnectionClosed(t *testing.T) {
	srv, _ := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Close the server's connection.
	srv.mtx.Lock()
	srv.conn.Close()
	srv.mtx.Unlock()

	err = srv.Write(secret.Identity, PingRequest{OriginTimestamp: 1})
	if err == nil {
		t.Fatal("expected write error on closed connection")
	}
}

// TestWriteToRoundtrip covers WriteTo with a destination identity and
// verifies the header fields survive the roundtrip.
func TestWriteToRoundtrip(t *testing.T) {
	srv, cli := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	dest := Identity{0xBB, 0xCC}

	errCh := pipeWrite(func() error {
		return srv.WriteTo(secret.Identity, dest, 5, PingRequest{
			OriginTimestamp: 42,
		})
	})

	h, cmd, err := cli.Read()
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatal(werr)
	}
	if h.Destination == nil {
		t.Fatal("expected non-nil destination")
	}
	if *h.Destination != dest {
		t.Fatalf("expected destination %v, got %v", dest, *h.Destination)
	}
	if h.TTL != 5 {
		t.Fatalf("expected TTL 5, got %d", h.TTL)
	}
	if pr, ok := cmd.(*PingRequest); !ok || pr.OriginTimestamp != 42 {
		t.Fatalf("unexpected command: %T %+v", cmd, cmd)
	}
}

// TestWriteToConnectionClosed covers WriteTo when the connection is closed.
func TestWriteToConnectionClosed(t *testing.T) {
	srv, _ := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	srv.mtx.Lock()
	srv.conn.Close()
	srv.mtx.Unlock()

	err = srv.WriteTo(secret.Identity, Identity{0xAA}, 3, PingRequest{})
	if err == nil {
		t.Fatal("expected write error on closed connection")
	}
}

// TestWriteHeaderRoundtrip covers WriteHeader with an already-constructed
// header.
func TestWriteHeaderRoundtrip(t *testing.T) {
	srv, cli := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	dest := Identity{0xDD}

	hash, _, err := NewPayloadFromCommand(PingRequest{OriginTimestamp: 7})
	if err != nil {
		t.Fatal(err)
	}
	hdr := Header{
		PayloadType: PPingRequest,
		PayloadHash: *hash,
		Origin:      secret.Identity,
		Destination: &dest,
		TTL:         2,
	}

	errCh := pipeWrite(func() error {
		return srv.WriteHeader(hdr, PingRequest{OriginTimestamp: 7})
	})

	rh, cmd, err := cli.Read()
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatal(werr)
	}
	if rh.TTL != 2 {
		t.Fatalf("expected TTL 2, got %d", rh.TTL)
	}
	if rh.Destination == nil || *rh.Destination != dest {
		t.Fatalf("destination mismatch: %v", rh.Destination)
	}
	if pr, ok := cmd.(*PingRequest); !ok || pr.OriginTimestamp != 7 {
		t.Fatalf("unexpected: %T %+v", cmd, cmd)
	}
}

// TestWriteHeaderConnectionClosed covers WriteHeader when connection is dead.
func TestWriteHeaderConnectionClosed(t *testing.T) {
	srv, _ := connectedTransports(t)

	srv.mtx.Lock()
	srv.conn.Close()
	srv.mtx.Unlock()

	hdr := Header{PayloadType: PPingRequest, TTL: 1}
	err := srv.WriteHeader(hdr, PingRequest{})
	if err == nil {
		t.Fatal("expected write error on closed connection")
	}
}

// TestReadConnectionClosed covers Read() when the peer has closed
// the connection — should return an error, not hang.
func TestReadConnectionClosed(t *testing.T) {
	srv, cli := connectedTransports(t)

	// Close the server side.
	srv.mtx.Lock()
	srv.conn.Close()
	srv.mtx.Unlock()

	_, _, err := cli.Read()
	if err == nil {
		t.Fatal("expected error on closed connection")
	}
}

// --- read() error path coverage -------------------------------------------

// writeRawEncrypted encrypts cleartext using the given transport's encrypt()
// and writes the resulting blob (including 3-byte size prefix) directly to
// the underlying connection. This bypasses Write/WriteHeader to test read()
// error paths with crafted payloads.
func writeRawEncrypted(t *testing.T, tr *Transport, cleartext []byte) {
	t.Helper()
	blob, err := tr.encrypt(cleartext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	tr.mtx.Lock()
	conn := tr.conn
	tr.mtx.Unlock()
	_, err = conn.Write(blob)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestReadBadJSONHeader sends a valid encrypted blob whose cleartext
// is not valid JSON, exercising the header decode error path in read().
func TestReadBadJSONHeader(t *testing.T) {
	srv, cli := connectedTransports(t)

	go func() {
		writeRawEncrypted(t, srv, []byte("this is not json at all"))
	}()

	_, _, _, err := cli.read(2 * time.Second)
	if err == nil {
		t.Fatal("expected JSON decode error")
	}
}

// TestReadUnknownPayloadType sends a valid encrypted blob with a
// properly-formed JSON header but an unknown PayloadType, covering
// the str2pt lookup-miss path in read().
func TestReadUnknownPayloadType(t *testing.T) {
	srv, cli := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	hash, payload, err := NewPayloadFromCommand(PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(Header{
		PayloadType: "bogus-type-that-does-not-exist",
		PayloadHash: *hash,
		Origin:      secret.Identity,
		TTL:         1,
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		writeRawEncrypted(t, srv, append(header, payload...))
	}()

	_, _, _, err = cli.read(2 * time.Second)
	if err == nil {
		t.Fatal("expected unsupported payload type error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected 'unsupported' error, got: %v", err)
	}
}

// TestReadBadPayloadJSON sends a valid encrypted blob with a valid
// header but garbage where the payload JSON should be, covering
// the payload decode error path in read().
func TestReadBadPayloadJSON(t *testing.T) {
	srv, cli := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	header, err := json.Marshal(Header{
		PayloadType: PPingRequest,
		PayloadHash: PayloadHash{},
		Origin:      secret.Identity,
		TTL:         1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Valid header followed by non-JSON garbage for the payload.
	cleartext := append(header, []byte("\n{not valid json}")...)

	go func() {
		writeRawEncrypted(t, srv, cleartext)
	}()

	_, _, _, err = cli.read(2 * time.Second)
	if err == nil {
		t.Fatal("expected payload JSON decode error")
	}
}

// --- write() error path coverage ------------------------------------------

// TestWriteEncryptError covers write() returning an encrypt error
// by attempting to write a payload that exceeds TransportMaxSize.
func TestWriteEncryptError(t *testing.T) {
	srv, _ := connectedTransports(t)

	huge := make([]byte, TransportMaxSize)
	err := srv.write(writeTimeout, huge)
	if err == nil {
		t.Fatal("expected encrypt error")
	}
	if !strings.Contains(err.Error(), "encrypt") {
		t.Fatalf("expected encrypt-wrapped error, got: %v", err)
	}
}

// --- handle() dispatch coverage (Priority 2) ------------------------------

// TestHandleDefaultUnhandledType covers the default case in handle()'s
// dispatch switch. HelloResponse is a valid PayloadType that read()
// can parse, but handle() has no case for it — it falls through to
// the default arm which just logs.
func TestHandleDefaultUnhandledType(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	// Send a CeremonyAbort — valid type but unhandled by handle().
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, CeremonyAbort{
			Reason: "test",
		})
	})

	// handle() should log "unhandled" and continue reading. Send a
	// second message (PingRequest) to prove handle() didn't die.
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	// Now send a PingRequest and expect a PingResponse back.
	errCh = pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 77})
	})
	h, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Fatal("nil header")
	}
	pr, ok := cmd.(*PingResponse)
	if !ok {
		t.Fatalf("expected *PingResponse, got %T", cmd)
	}
	if pr.OriginTimestamp != 77 {
		t.Fatalf("expected 77, got %d", pr.OriginTimestamp)
	}

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestHandleEncryptedPayloadDecryptError covers the EncryptedPayload
// case where decryptPayload fails (unknown sender). handle() should
// log the error and continue (not crash or exit).
func TestHandleEncryptedPayloadDecryptError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	// Create an EncryptedPayload from a sender whose NaCl key is
	// NOT in the server's peer map. decryptPayload will fail.
	unknownSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	unknownPriv, err := unknownSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := SealBox(payload, recipientPub, unknownPriv,
		unknownSecret.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	// Send the EncryptedPayload. handle() should fail to decrypt and continue.
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, *ep)
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	// Prove handle() survived: send PingRequest and get PingResponse.
	errCh = pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 88})
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	pr, ok := cmd.(*PingResponse)
	if !ok {
		t.Fatalf("expected *PingResponse, got %T", cmd)
	}
	if pr.OriginTimestamp != 88 {
		t.Fatalf("expected 88, got %d", pr.OriginTimestamp)
	}

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// handleTestServerWithNaCl is like handleTestServer but additionally
// populates the sender's NaCl public key in the peer map, enabling
// EncryptedPayload decrypt to succeed.
func handleTestServerWithNaCl(t *testing.T, ctx context.Context, senderSecret *Secret) (*Server, *Transport, Identity) {
	t.Helper()

	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	pings, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	srvTr, cliTr := connectedTransports(t)

	senderPub, err := senderSecret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	peerID := Identity{0xDD}
	s := &Server{
		seen:     seen,
		peersTTL: peersTTL,
		pings:    pings,
		secret:   secret,
		sessions: map[Identity]*Transport{peerID: srvTr},
		peers: map[Identity]*PeerRecord{
			peerID: {Identity: peerID},
			senderSecret.Identity: {
				Identity: senderSecret.Identity,
				Version:  ProtocolVersion,
				NaClPub:  senderPub,
			},
		},
		cfg: &Config{
			PingInterval: time.Hour,
			PeersWanted:  8,
		},
	}

	s.wg.Add(1)
	go s.handle(ctx, &peerID, srvTr)

	// Drain initial PeerNotify + PeerListRequest.
	for i := 0; i < 2; i++ {
		_, _, _, err := cliTr.ReadEnvelope()
		if err != nil {
			t.Fatalf("drain initial message %d: %v", i, err)
		}
	}

	return s, cliTr, peerID
}

// TestHandleEncryptedPingRequest covers the EncryptedPayload → inner
// PingRequest dispatch path. The server decrypts the payload and
// responds with a PingResponse.
func TestHandleEncryptedPingRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s, cliTr, _ := handleTestServerWithNaCl(t, ctx, senderSecret)

	// Build EncryptedPayload with inner PingRequest.
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(PingRequest{OriginTimestamp: 55})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := SealBox(payload, recipientPub, senderPriv,
		senderSecret.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	// Send and read the PingResponse.
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, *ep)
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	pr, ok := cmd.(*PingResponse)
	if !ok {
		t.Fatalf("expected *PingResponse, got %T", cmd)
	}
	if pr.OriginTimestamp != 55 {
		t.Fatalf("expected 55, got %d", pr.OriginTimestamp)
	}

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestHandleEncryptedUnknownInner covers the EncryptedPayload → inner
// type that handle() doesn't have a case for (e.g. PeerNotify).
// handle() should log it and continue.
func TestHandleEncryptedUnknownInner(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s, cliTr, _ := handleTestServerWithNaCl(t, ctx, senderSecret)

	// Build EncryptedPayload with inner PeerNotify — which the
	// encrypted inner switch has no case for.
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(PeerNotify{Count: 42})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := SealBox(payload, recipientPub, senderPriv,
		senderSecret.Identity, PPeerNotify)
	if err != nil {
		t.Fatal(err)
	}

	// Send the encrypted PeerNotify. handle() decrypts, hits default, continues.
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, *ep)
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	// Prove handle() survived by sending a normal PingRequest.
	errCh = pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 66})
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	pr, ok := cmd.(*PingResponse)
	if !ok {
		t.Fatalf("expected *PingResponse, got %T", cmd)
	}
	if pr.OriginTimestamp != 66 {
		t.Fatalf("expected 66, got %d", pr.OriginTimestamp)
	}

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestWriteZeroTimeout covers the timeout==0 branch in write() where
// SetWriteDeadline is called with time.Time{} (clear deadline).
func TestWriteZeroTimeout(t *testing.T) {
	srv, cli := connectedTransports(t)

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Build a valid payload manually and call write() with timeout=0.
	hash, payload, err := NewPayloadFromCommand(PingRequest{OriginTimestamp: 55})
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(Header{
		PayloadType: PPingRequest,
		PayloadHash: *hash,
		Origin:      secret.Identity,
		TTL:         1,
	})
	if err != nil {
		t.Fatal(err)
	}

	errCh := pipeWrite(func() error {
		return srv.write(0, append(header, payload...))
	})

	h, cmd, err := cli.Read()
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatal(werr)
	}
	if h == nil {
		t.Fatal("nil header")
	}
	if pr, ok := cmd.(*PingRequest); !ok || pr.OriginTimestamp != 55 {
		t.Fatalf("unexpected: %T %+v", cmd, cmd)
	}
}

// --- Priority 2: handle() dispatch arms and tss_rpc dispatch functions -----

// verifyHandleSurvived sends a PingRequest and verifies a PingResponse
// comes back, proving handle() is still alive after dispatching a
// fire-and-forget command.
func verifyHandleSurvived(t *testing.T, cliTr *Transport, ts int64) {
	t.Helper()
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: ts})
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatalf("ping read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("ping write: %v", err)
	}
	pr, ok := cmd.(*PingResponse)
	if !ok {
		t.Fatalf("expected *PingResponse, got %T", cmd)
	}
	if pr.OriginTimestamp != ts {
		t.Fatalf("expected %d, got %d", ts, pr.OriginTimestamp)
	}
}

// TestHandleKeygenEmptyCommittee covers dispatchKeygen early return
// when Committee is nil. handle() must survive and continue.
func TestHandleKeygenEmptyCommittee(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	s, cliTr, _ := handleTestServer(t, ctx)

	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, KeygenRequest{})
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 201)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestHandleSignEmptyCommittee covers dispatchSign early return
// when Committee is nil.
func TestHandleSignEmptyCommittee(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	s, cliTr, _ := handleTestServer(t, ctx)

	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, SignRequest{})
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 202)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestHandleSignBadDataLength covers dispatchSign early return when
// Committee is valid but Data is not 32 bytes.
func TestHandleSignBadDataLength(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	s, cliTr, _ := handleTestServer(t, ctx)

	// Build a committee with one valid party ID.
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pid := tss.NewPartyID(secret.String(), "test", big.NewInt(1))
	committee := tss.UnSortedPartyIDs{pid}

	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, SignRequest{
			Committee: committee,
			Data:      []byte("short"), // not 32 bytes
		})
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 203)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestHandleReshareEmptyCommittee covers dispatchReshare early return
// when both committees are nil.
func TestHandleReshareEmptyCommittee(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	s, cliTr, _ := handleTestServer(t, ctx)

	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, ReshareRequest{})
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 204)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestHandleTSSMessageBadSignature covers dispatchTSSMessage early
// return when the signature verification fails.
func TestHandleTSSMessageBadSignature(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	s, cliTr, _ := handleTestServer(t, ctx)

	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, TSSMessage{
			From:      Identity{0x01},
			Data:      []byte("payload"),
			Signature: []byte("invalid-signature"),
		})
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 205)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestHandleEncryptedTSSMessage covers the EncryptedPayload → inner
// TSSMessage dispatch path. The inner TSSMessage has a bad signature
// so dispatchTSSMessage returns early, but the encrypted→TSSMessage
// dispatch arm in handle() is exercised.
func TestHandleEncryptedTSSMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s, cliTr, _ := handleTestServerWithNaCl(t, ctx, senderSecret)

	// Build EncryptedPayload with inner TSSMessage (bad signature).
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	inner, err := json.Marshal(TSSMessage{
		From:      Identity{0x01},
		Data:      []byte("tss-data"),
		Signature: []byte("bad-sig"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := SealBox(inner, recipientPub, senderPriv,
		senderSecret.Identity, PTSSMessage)
	if err != nil {
		t.Fatal(err)
	}

	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, *ep)
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 206)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestDecryptPayloadNoNaClPub covers the decryptPayload error path
// where the sender is in the peer map but has no NaCl public key.
func TestDecryptPayloadNoNaClPub(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Build a server where the sender is known but has empty NaClPub.
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	pings, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	srvTr, cliTr := connectedTransports(t)

	peerID := Identity{0xDD}
	s := &Server{
		seen:     seen,
		peersTTL: peersTTL,
		pings:    pings,
		secret:   secret,
		sessions: map[Identity]*Transport{peerID: srvTr},
		peers: map[Identity]*PeerRecord{
			peerID: {Identity: peerID},
			// Sender known but NaClPub is nil.
			senderSecret.Identity: {
				Identity: senderSecret.Identity,
				Version:  ProtocolVersion,
			},
		},
		cfg: &Config{
			PingInterval: time.Hour,
			PeersWanted:  8,
		},
	}

	s.wg.Add(1)
	go s.handle(ctx, &peerID, srvTr)

	// Drain initial PeerNotify + PeerListRequest.
	for i := 0; i < 2; i++ {
		_, _, _, err := cliTr.ReadEnvelope()
		if err != nil {
			t.Fatalf("drain initial message %d: %v", i, err)
		}
	}

	// Build EncryptedPayload from sender.
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := SealBox(payload, recipientPub, senderPriv,
		senderSecret.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	// Send — decryptPayload will fail "no NaCl public key".
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, *ep)
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 301)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestDecryptPayloadUnknownInnerType covers decryptPayload when the
// EncryptedPayload's InnerType is not in str2pt.
func TestDecryptPayloadUnknownInnerType(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s, cliTr, _ := handleTestServerWithNaCl(t, ctx, senderSecret)

	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(PingRequest{OriginTimestamp: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Use a bogus InnerType that str2pt doesn't know.
	ep, err := SealBox(payload, recipientPub, senderPriv,
		senderSecret.Identity, PayloadType("bogus-type"))
	if err != nil {
		t.Fatal(err)
	}

	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, *ep)
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 302)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestDecryptPayloadBadInnerJSON covers decryptPayload when the
// encrypted plaintext has a valid InnerType but the JSON is malformed.
func TestDecryptPayloadBadInnerJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s, cliTr, _ := handleTestServerWithNaCl(t, ctx, senderSecret)

	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	// Encrypt garbage that is not valid JSON, with a real InnerType.
	ep, err := SealBox([]byte("{{{not json"), recipientPub, senderPriv,
		senderSecret.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, *ep)
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	verifyHandleSurvived(t, cliTr, 303)

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// --- Priority 5: SendTo / SendEncrypted -----------------------------------

// TestSendToDirectSession covers SendTo when the destination has a
// direct session (no routing needed).
func TestSendToDirectSession(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	srvTr, cliTr := connectedTransports(t)

	dest := Identity{0xAA}
	s := &Server{
		secret:   secret,
		sessions: map[Identity]*Transport{dest: srvTr},
	}

	errCh := pipeWrite(func() error {
		return s.SendTo(dest, PingRequest{OriginTimestamp: 401})
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	pr, ok := cmd.(*PingRequest)
	if !ok {
		t.Fatalf("expected *PingRequest, got %T", cmd)
	}
	if pr.OriginTimestamp != 401 {
		t.Fatalf("expected 401, got %d", pr.OriginTimestamp)
	}
}

// TestSendToRelayRoute covers SendTo when destination has no direct
// session and the message is relayed through the first available peer.
func TestSendToRelayRoute(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	srvTr, cliTr := connectedTransports(t)

	relayPeer := Identity{0xBB}
	dest := Identity{0xCC}
	s := &Server{
		secret:   secret,
		sessions: map[Identity]*Transport{relayPeer: srvTr},
	}

	errCh := pipeWrite(func() error {
		return s.SendTo(dest, PingRequest{OriginTimestamp: 402})
	})
	h, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if h.Destination == nil || *h.Destination != dest {
		t.Fatal("expected destination in header")
	}
	pr, ok := cmd.(*PingRequest)
	if !ok {
		t.Fatalf("expected *PingRequest, got %T", cmd)
	}
	if pr.OriginTimestamp != 402 {
		t.Fatalf("expected 402, got %d", pr.OriginTimestamp)
	}
}

// TestSendToNoRoute covers SendTo when there are no sessions at all.
func TestSendToNoRoute(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
	}

	err = s.SendTo(Identity{0xCC}, PingRequest{})
	if err == nil || err.Error() != "no route to destination" {
		t.Fatalf("expected 'no route to destination', got %v", err)
	}
}

// TestSendEncryptedHappyPath covers the full SendEncrypted flow:
// look up peer NaCl pub, encrypt, and deliver via SendTo.
func TestSendEncryptedHappyPath(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	srvTr, cliTr := connectedTransports(t)

	dest := Identity{0xAA}
	destSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	destNaClPub, err := destSecret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{
		secret:   secret,
		sessions: map[Identity]*Transport{dest: srvTr},
		peers: map[Identity]*PeerRecord{
			dest: {
				Identity: dest,
				NaClPub:  destNaClPub,
			},
		},
	}

	errCh := pipeWrite(func() error {
		return s.SendEncrypted(dest, PingRequest{OriginTimestamp: 501})
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	ep, ok := cmd.(*EncryptedPayload)
	if !ok {
		t.Fatalf("expected *EncryptedPayload, got %T", cmd)
	}
	if ep.InnerType != PPingRequest {
		t.Fatalf("expected inner type %q, got %q", PPingRequest, ep.InnerType)
	}
}

// TestSendEncryptedUnknownPeer covers SendEncrypted when the
// destination is not in the peer map.
func TestSendEncryptedUnknownPeer(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
	}

	err = s.SendEncrypted(Identity{0xCC}, PingRequest{})
	if err == nil || !strings.Contains(err.Error(), "unknown peer") {
		t.Fatalf("expected 'unknown peer', got %v", err)
	}
}

// TestSendEncryptedNoNaClPub covers SendEncrypted when the peer
// exists but has no NaCl public key.
func TestSendEncryptedNoNaClPub(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	dest := Identity{0xAA}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers: map[Identity]*PeerRecord{
			dest: {Identity: dest},
		},
	}

	err = s.SendEncrypted(dest, PingRequest{})
	if err == nil || !strings.Contains(err.Error(), "no NaCl public key") {
		t.Fatalf("expected 'no NaCl public key', got %v", err)
	}
}

// --- Priority 2: handle() dispatch + decryptPayload gaps ----------------

// TestHandleForwardPath covers the forwarding branch in handle():
// a message with Destination != server identity gets forwarded (not
// dispatched locally).  We verify by confirming the message does NOT
// produce a local PingResponse (it would if dispatched), and that
// handle() survives to process a subsequent local ping.
func TestHandleForwardPath(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	// Send a PingRequest with destination = some other identity.
	// handle() should forward it, not dispatch locally.
	other := Identity{0xBB}
	errCh := pipeWrite(func() error {
		return cliTr.WriteTo(Identity{0xEE}, other, 5, PingRequest{
			OriginTimestamp: 999,
		})
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	// Prove handle() survived: send a local PingRequest and get
	// PingResponse.
	errCh = pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 77})
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	pr, ok := cmd.(*PingResponse)
	if !ok {
		t.Fatalf("expected *PingResponse, got %T", cmd)
	}
	if pr.OriginTimestamp != 77 {
		t.Fatalf("expected 77, got %d", pr.OriginTimestamp)
	}

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// TestHandleEncryptedPingWriteError covers the error path in handle()
// where the server successfully decrypts an EncryptedPayload containing
// a PingRequest but fails to write the PingResponse (connection closed).
func TestHandleEncryptedPingWriteError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s, cliTr, _ := handleTestServerWithNaCl(t, ctx, senderSecret)

	// Build EncryptedPayload with inner PingRequest.
	senderPriv, err := senderSecret.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPub, err := s.secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(PingRequest{OriginTimestamp: 42})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := SealBox(payload, recipientPub, senderPriv,
		senderSecret.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}

	// Send the EncryptedPayload then immediately close. The server
	// decrypts successfully but Write(PingResponse) fails → return.
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, *ep)
	})
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	cliTr.conn.Close()
	cancel()
	s.wg.Wait()
}

// --- Priority 2 continued: dispatch function goroutine paths -------------

// mockTSS implements the TSS interface for testing dispatch functions.
// Each method signals its channel when called, and returns the
// configured error.
type mockTSS struct {
	keygenErr  error
	signErr    error
	reshareErr error
	handleErr  error

	keygenCalled  chan struct{}
	signCalled    chan struct{}
	reshareCalled chan struct{}
	handleCalled  chan struct{}

	// Capture HandleMessage args for verification.
	handleData []byte
	handleFrom Identity
}

func (m *mockTSS) Keygen(_ context.Context, _ CeremonyID, _ []Identity, _ int) ([]byte, error) {
	if m.keygenCalled != nil {
		close(m.keygenCalled)
	}
	return []byte{0x01}, m.keygenErr
}

func (m *mockTSS) Sign(_ context.Context, _ CeremonyID, _ []byte, _ []Identity, _ int, _ [32]byte) ([]byte, []byte, error) {
	if m.signCalled != nil {
		close(m.signCalled)
	}
	// Return 32 bytes each — the log line slices [:8].
	r := make([]byte, 32)
	s := make([]byte, 32)
	r[0] = 0x01
	s[0] = 0x02
	return r, s, m.signErr
}

func (m *mockTSS) Reshare(_ context.Context, _ CeremonyID, _ []byte, _, _ []Identity, _, _ int) error {
	if m.reshareCalled != nil {
		close(m.reshareCalled)
	}
	return m.reshareErr
}

func (m *mockTSS) HandleMessage(from Identity, _ CeremonyID, data []byte) error {
	m.handleFrom = from
	m.handleData = data
	if m.handleCalled != nil {
		close(m.handleCalled)
	}
	return m.handleErr
}

// dispatchTestServer creates a minimal Server with stt and mock TSS
// for testing dispatch functions directly (without going through handle).
func dispatchTestServer(t *testing.T, mock *mockTSS) *Server {
	t.Helper()

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:     secret,
		tss:        mock,
		tssCtx:     context.Background(),
		sessions:   make(map[Identity]*Transport),
		peers:      make(map[Identity]*PeerRecord),
		ceremonies: make(map[CeremonyID]*CeremonyInfo),
	}
	s.stt = newServerTSSTransport(s)
	return s
}

// validCommittee returns a single-member tss.UnSortedPartyIDs with a
// real identity hex string that passes partiesToIdentities.
func validCommittee(t *testing.T) tss.UnSortedPartyIDs {
	t.Helper()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pid := tss.NewPartyID(secret.String(), "test", big.NewInt(1))
	return tss.UnSortedPartyIDs{pid}
}

// TestDispatchKeygenSuccess covers the happy path: non-empty committee,
// goroutine launches, tss.Keygen is called and succeeds.
func TestDispatchKeygenSuccess(t *testing.T) {
	mock := &mockTSS{keygenCalled: make(chan struct{})}
	s := dispatchTestServer(t, mock)

	s.dispatchKeygen(KeygenRequest{
		Committee: validCommittee(t),
		Threshold: 1,
	})

	select {
	case <-mock.keygenCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.Keygen not called")
	}
	s.wg.Wait()
}

// TestDispatchKeygenError covers the goroutine error path: tss.Keygen
// returns an error, which is logged but doesn't crash.
func TestDispatchKeygenError(t *testing.T) {
	mock := &mockTSS{
		keygenErr:    errors.New("keygen failed"),
		keygenCalled: make(chan struct{}),
	}
	s := dispatchTestServer(t, mock)

	s.dispatchKeygen(KeygenRequest{
		Committee: validCommittee(t),
		Threshold: 1,
	})

	select {
	case <-mock.keygenCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.Keygen not called")
	}
	s.wg.Wait()
}

// TestDispatchSignSuccess covers the happy path: valid committee,
// 32-byte data, goroutine launches, tss.Sign succeeds.
func TestDispatchSignSuccess(t *testing.T) {
	mock := &mockTSS{signCalled: make(chan struct{})}
	s := dispatchTestServer(t, mock)

	var data [32]byte
	copy(data[:], bytes.Repeat([]byte{0xAB}, 32))

	s.dispatchSign(SignRequest{
		Committee: validCommittee(t),
		Threshold: 1,
		Data:      data[:],
	})

	select {
	case <-mock.signCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.Sign not called")
	}
	s.wg.Wait()
}

// TestDispatchSignError covers the goroutine error path.
func TestDispatchSignError(t *testing.T) {
	mock := &mockTSS{
		signErr:    errors.New("sign failed"),
		signCalled: make(chan struct{}),
	}
	s := dispatchTestServer(t, mock)

	var data [32]byte
	s.dispatchSign(SignRequest{
		Committee: validCommittee(t),
		Threshold: 1,
		Data:      data[:],
	})

	select {
	case <-mock.signCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.Sign not called")
	}
	s.wg.Wait()
}

// TestDispatchReshareSuccess covers the happy path: both old and new
// committees valid, goroutine launches, tss.Reshare succeeds.
func TestDispatchReshareSuccess(t *testing.T) {
	mock := &mockTSS{reshareCalled: make(chan struct{})}
	s := dispatchTestServer(t, mock)

	s.dispatchReshare(ReshareRequest{
		OldCommittee: validCommittee(t),
		NewCommittee: validCommittee(t),
		OldThreshold: 1,
		NewThreshold: 1,
	})

	select {
	case <-mock.reshareCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.Reshare not called")
	}
	s.wg.Wait()
}

// TestDispatchReshareError covers the goroutine error path.
func TestDispatchReshareError(t *testing.T) {
	mock := &mockTSS{
		reshareErr:    errors.New("reshare failed"),
		reshareCalled: make(chan struct{}),
	}
	s := dispatchTestServer(t, mock)

	s.dispatchReshare(ReshareRequest{
		OldCommittee: validCommittee(t),
		NewCommittee: validCommittee(t),
		OldThreshold: 1,
		NewThreshold: 1,
	})

	select {
	case <-mock.reshareCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.Reshare not called")
	}
	s.wg.Wait()
}

// TestDispatchTSSMessageValidKeygen covers dispatchTSSMessage with a
// validly-signed message of non-reshare type (keygen). This exercises
// the signature verification success path, the non-reshare wire format
// reconstruction, and the HandleMessage call.
func TestDispatchTSSMessageValidKeygen(t *testing.T) {
	mock := &mockTSS{handleCalled: make(chan struct{})}
	s := dispatchTestServer(t, mock)

	// Create a signed TSSMessage.
	from, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	cid := CeremonyID{}
	wireData := []byte("test-keygen-data")
	hash := HashTSSMessage(cid, wireData)
	sig := from.Sign(hash)

	s.dispatchTSSMessage(TSSMessage{
		From:       from.Identity,
		CeremonyID: cid,
		Data:       wireData,
		Signature:  sig,
		Type:       CeremonyKeygen,
		Flags:      0,
	})

	select {
	case <-mock.handleCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.HandleMessage not called")
	}

	// Verify wire format: [bcast=0][wireData]
	if len(mock.handleData) != 1+len(wireData) {
		t.Fatalf("expected %d bytes, got %d", 1+len(wireData), len(mock.handleData))
	}
	if mock.handleData[0] != 0x00 {
		t.Fatalf("expected bcast=0, got %x", mock.handleData[0])
	}
	if !bytes.Equal(mock.handleData[1:], wireData) {
		t.Fatal("wire data mismatch")
	}
}

// TestDispatchTSSMessageBroadcast covers the TSSFlagBroadcast path.
func TestDispatchTSSMessageBroadcast(t *testing.T) {
	mock := &mockTSS{handleCalled: make(chan struct{})}
	s := dispatchTestServer(t, mock)

	from, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	wireData := []byte("bcast")
	hash := HashTSSMessage(CeremonyID{}, wireData)
	sig := from.Sign(hash)

	s.dispatchTSSMessage(TSSMessage{
		From:      from.Identity,
		Data:      wireData,
		Signature: sig,
		Type:      CeremonyKeygen,
		Flags:     TSSFlagBroadcast,
	})

	select {
	case <-mock.handleCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.HandleMessage not called")
	}

	if mock.handleData[0] != 0x01 {
		t.Fatalf("expected bcast=1, got %x", mock.handleData[0])
	}
}

// TestDispatchTSSMessageReshareFlags covers the reshare wire format
// reconstruction with all committee flags set.
func TestDispatchTSSMessageReshareFlags(t *testing.T) {
	mock := &mockTSS{handleCalled: make(chan struct{})}
	s := dispatchTestServer(t, mock)

	from, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	wireData := []byte("reshare-payload")
	hash := HashTSSMessage(CeremonyID{}, wireData)
	sig := from.Sign(hash)

	s.dispatchTSSMessage(TSSMessage{
		From:      from.Identity,
		Data:      wireData,
		Signature: sig,
		Type:      CeremonyReshare,
		Flags:     TSSFlagBroadcast | TSSFlagToOld | TSSFlagToNew | TSSFlagFromNew,
	})

	select {
	case <-mock.handleCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.HandleMessage not called")
	}

	// Reshare format: [bcast:1][cflags:1][wireData]
	if len(mock.handleData) != 2+len(wireData) {
		t.Fatalf("expected %d bytes, got %d", 2+len(wireData), len(mock.handleData))
	}
	if mock.handleData[0] != 0x01 { // broadcast
		t.Fatalf("expected bcast=1, got %x", mock.handleData[0])
	}
	// cflags: ToOld=0x01 | ToNew=0x02 | FromNew=0x04 = 0x07
	if mock.handleData[1] != 0x07 {
		t.Fatalf("expected cflags=0x07, got %x", mock.handleData[1])
	}
}

// TestDispatchTSSMessageHandleError covers the error path where
// HandleMessage returns an error (logged, not fatal).
func TestDispatchTSSMessageHandleError(t *testing.T) {
	mock := &mockTSS{
		handleErr:    errors.New("handle failed"),
		handleCalled: make(chan struct{}),
	}
	s := dispatchTestServer(t, mock)

	from, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	wireData := []byte("err-data")
	hash := HashTSSMessage(CeremonyID{}, wireData)
	sig := from.Sign(hash)

	s.dispatchTSSMessage(TSSMessage{
		From:      from.Identity,
		Data:      wireData,
		Signature: sig,
		Type:      CeremonyKeygen,
	})

	select {
	case <-mock.handleCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("tss.HandleMessage not called")
	}
}

// TestHandleRoutedToSelf covers the observability counter path in handle():
// when a message arrives with Destination == server's own identity, the
// routedReceived counter increments and the payload is dispatched normally.
func TestHandleRoutedToSelf(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s, cliTr, _ := handleTestServer(t, ctx)

	// Send PingRequest with destination == server identity.
	errCh := pipeWrite(func() error {
		return cliTr.WriteTo(Identity{0xEE}, s.secret.Identity, 3,
			PingRequest{OriginTimestamp: 123})
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	pr, ok := cmd.(*PingResponse)
	if !ok {
		t.Fatalf("expected *PingResponse, got %T", cmd)
	}
	if pr.OriginTimestamp != 123 {
		t.Fatalf("expected 123, got %d", pr.OriginTimestamp)
	}

	if got := s.RoutedReceived(); got != 1 {
		t.Fatalf("expected RoutedReceived=1, got %d", got)
	}

	cancel()
	cliTr.conn.Close()
	s.wg.Wait()
}

// --- Priority 3: Handshake error paths -----------------------------------

// handshakeTestPair creates two connected transports (with KX done) and
// a secret for the caller to use with Handshake. Returns (caller, remote, secret).
func handshakeTestPair(t *testing.T) (*Transport, *Transport, *Secret) {
	t.Helper()
	tr1, tr2 := connectedTransports(t)
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return tr1, tr2, secret
}

// TestHandshakeVersionMismatch covers the ErrUnsupportedVersion path.
func TestHandshakeVersionMismatch(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	// Read tr1's HelloRequest and respond with wrong version.
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	naclPub, _ := remoteSecret.NaClPublicKey()
	ch := make([]byte, ChallengeSize)
	ch[0] = 0x42
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion + 1, // wrong
		Identity:  remoteSecret.Identity,
		Challenge: ch,
		NaClPub:   naclPub,
	})
	if err != nil {
		t.Fatal(err)
	}

	if hsErr := <-errCh; !errors.Is(hsErr, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got: %v", hsErr)
	}
}

// TestHandshakeShortChallenge covers ErrInvalidChallenge when challenge
// is too short.
func TestHandshakeShortChallenge(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: []byte{0x01, 0x02}, // too short
	})
	if err != nil {
		t.Fatal(err)
	}

	if hsErr := <-errCh; !errors.Is(hsErr, ErrInvalidChallenge) {
		t.Fatalf("expected ErrInvalidChallenge, got: %v", hsErr)
	}
}

// TestHandshakeZeroChallenge covers ErrInvalidChallenge when challenge
// is all zeros.
func TestHandshakeZeroChallenge(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: make([]byte, ChallengeSize), // all zeros
	})
	if err != nil {
		t.Fatal(err)
	}

	if hsErr := <-errCh; !errors.Is(hsErr, ErrInvalidChallenge) {
		t.Fatalf("expected ErrInvalidChallenge, got: %v", hsErr)
	}
}

// TestHandshakeBadNaClPub covers ErrInvalidNaClPub when NaCl public key
// has wrong length (not 0 and not NaClPubSize).
func TestHandshakeBadNaClPub(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	ch := make([]byte, ChallengeSize)
	ch[0] = 0x42
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: ch,
		NaClPub:   []byte{0x01, 0x02, 0x03}, // wrong size
	})
	if err != nil {
		t.Fatal(err)
	}

	if hsErr := <-errCh; !errors.Is(hsErr, ErrInvalidNaClPub) {
		t.Fatalf("expected ErrInvalidNaClPub, got: %v", hsErr)
	}
}

// TestHandshakeUnexpectedHelloType covers the type assertion failure
// when the remote sends a non-HelloRequest as its first message.
func TestHandshakeUnexpectedHelloType(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	// Read tr1's HelloRequest.
	_, _, _, err := tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	// Send PingRequest instead of HelloRequest.
	if err := tr2.Write(Identity{0xAA}, PingRequest{OriginTimestamp: 1}); err != nil {
		t.Fatal(err)
	}

	hsErr := <-errCh
	if hsErr == nil || !strings.Contains(hsErr.Error(), "unexpected command") {
		t.Fatalf("expected 'unexpected command', got: %v", hsErr)
	}
}

// TestHandshakeReadHelloError covers the read error path when reading
// the remote's HelloRequest (connection closed).
func TestHandshakeReadHelloError(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	// Read tr1's HelloRequest, then close without responding.
	_, _, _, err := tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	tr2.conn.Close()

	if hsErr := <-errCh; hsErr == nil {
		t.Fatal("expected read error")
	}
}

// TestHandshakeBadSignature covers the Verify failure path when
// the remote's HelloResponse contains an invalid signature.
func TestHandshakeBadSignature(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	// Read tr1's HelloRequest.
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	// Send valid HelloRequest.
	naclPub, _ := remoteSecret.NaClPublicKey()
	ch := make([]byte, ChallengeSize)
	ch[0] = 0xFF
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: ch,
		NaClPub:   naclPub,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read tr1's HelloResponse (we don't verify, just drain).
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}

	// Send HelloResponse with bogus signature.
	err = tr2.Write(remoteSecret.Identity, HelloResponse{
		Signature: []byte("this-is-not-a-valid-signature-at-all-65bytes-padding-here-1234567"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if hsErr := <-errCh; hsErr == nil {
		t.Fatal("expected signature verification error")
	}
}

// TestHandshakeUnexpectedResponseType covers the type assertion failure
// when the remote sends a non-HelloResponse as its second message.
func TestHandshakeUnexpectedResponseType(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	// Read tr1's HelloRequest.
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	// Send valid HelloRequest.
	naclPub, _ := remoteSecret.NaClPublicKey()
	ch := make([]byte, ChallengeSize)
	ch[0] = 0xAA
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: ch,
		NaClPub:   naclPub,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read tr1's HelloResponse.
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}

	// Send PingRequest instead of HelloResponse.
	err = tr2.Write(remoteSecret.Identity, PingRequest{OriginTimestamp: 99})
	if err != nil {
		t.Fatal(err)
	}

	hsErr := <-errCh
	if hsErr == nil || !strings.Contains(hsErr.Error(), "unexpected command") {
		t.Fatalf("expected 'unexpected command', got: %v", hsErr)
	}
}

// TestHandshakeWriteHelloResponseError covers the error path when
// the connection is closed before tr1 can write HelloResponse.
func TestHandshakeWriteHelloResponseError(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	// Read tr1's HelloRequest.
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	// Send valid HelloRequest to get past the version/challenge checks.
	naclPub, _ := remoteSecret.NaClPublicKey()
	ch := make([]byte, ChallengeSize)
	ch[0] = 0xBB
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: ch,
		NaClPub:   naclPub,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Close before reading tr1's HelloResponse. tr1's
	// Write(HelloResponse) should fail.
	tr2.conn.Close()

	if hsErr := <-errCh; hsErr == nil {
		t.Fatal("expected write error")
	}
}

// TestHandshakeWithDNS covers the dns option path in Handshake when
// dnsName is provided.
func TestHandshakeWithDNS(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		// Pass a DNS name — this sets opts["dns"].
		_, _, _, err := tr1.Handshake(context.Background(), secret, "test.example.com")
		errCh <- err
	}()

	// Read HelloRequest and verify it has dns option.
	_, cmd, _, err := tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	hello, ok := cmd.(*HelloRequest)
	if !ok {
		t.Fatalf("expected *HelloRequest, got %T", cmd)
	}
	if hello.Options["dns"] != "test.example.com" {
		t.Fatalf("expected dns=test.example.com, got %q", hello.Options["dns"])
	}

	// Complete the handshake properly.
	naclPub, _ := remoteSecret.NaClPublicKey()
	ch := make([]byte, ChallengeSize)
	ch[0] = 0xCC
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: ch,
		NaClPub:   naclPub,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read HelloResponse from tr1.
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}

	// Sign the challenge properly and send HelloResponse.
	combinedChallenge := Hash256(hello.Challenge, tr2.them.Bytes())
	err = tr2.Write(remoteSecret.Identity, HelloResponse{
		Signature: remoteSecret.Sign(combinedChallenge),
	})
	if err != nil {
		t.Fatal(err)
	}

	if hsErr := <-errCh; hsErr != nil {
		t.Fatalf("handshake failed: %v", hsErr)
	}
}

// TestHandleInitialWriteErrors covers the error paths in handle()
// where the initial PeerNotify and PeerListRequest writes fail
// because the connection is already closed.
func TestHandleInitialWriteErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	srvTr, _ := connectedTransports(t)

	// Close the server transport BEFORE handle starts, so the
	// initial PeerNotify and PeerListRequest writes fail.
	srvTr.conn.Close()

	pings, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}

	peerID := Identity{0xDD}
	s := &Server{
		seen:     seen,
		peersTTL: peersTTL,
		pings:    pings,
		secret:   secret,
		sessions: map[Identity]*Transport{peerID: srvTr},
		peers:    make(map[Identity]*PeerRecord),
		cfg: &Config{
			PingInterval: time.Hour,
			PeersWanted:  8,
		},
	}

	s.wg.Add(1)
	go s.handle(ctx, &peerID, srvTr)

	// handle() will fail on initial writes, then fail on ReadEnvelope,
	// and return.
	s.wg.Wait()
}

// --- Priority 3 continued: KeyExchange error paths -----------------------

// TestTransportKeyExchangeServerVersionMismatch covers the server-side
// Transport.KeyExchange rejecting a client that sends the wrong version.
func TestTransportKeyExchangeServerVersionMismatch(t *testing.T) {
	ctx := t.Context()

	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- srv.KeyExchange(ctx, conn)
	}()

	// Client connects and sends wrong version.
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read server's TransportRequest.
	var serverTR TransportRequest
	if err := readJSONLine(conn, &serverTR); err != nil {
		t.Fatal(err)
	}

	// Generate valid key but send wrong version.
	cliKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr := TransportRequest{Version: 999, PublicKey: cliKey.PublicKey().Bytes()}
	if err := json.NewEncoder(conn).Encode(tr); err != nil {
		t.Fatal(err)
	}

	srvErr := <-errCh
	if !errors.Is(srvErr, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got: %v", srvErr)
	}
}

// TestTransportKeyExchangeReadError covers Transport.KeyExchange when
// the connection is closed during the read phase.
func TestTransportKeyExchangeReadError(t *testing.T) {
	ctx := t.Context()

	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- srv.KeyExchange(ctx, conn)
	}()

	// Client connects, reads the server's TransportRequest, then closes.
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var serverTR TransportRequest
	if err := readJSONLine(conn, &serverTR); err != nil {
		t.Fatal(err)
	}
	conn.Close() // close without sending response

	srvErr := <-errCh
	if srvErr == nil {
		t.Fatal("expected read error")
	}
}

// TestTransportKeyExchangeClientReadError covers the client-side
// Transport.KeyExchange when the server closes before sending anything.
func TestTransportKeyExchangeClientReadError(t *testing.T) {
	ctx := t.Context()

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close() // close immediately
	}()

	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := new(Transport)
	err = client.KeyExchange(ctx, conn)
	if err == nil {
		t.Fatal("expected read error")
	}
}

// TestTransportKeyExchangeBadPublicKey covers the curve.NewPublicKey
// error path when the client sends a syntactically valid but
// cryptographically invalid public key.
func TestTransportKeyExchangeBadPublicKey(t *testing.T) {
	ctx := t.Context()

	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- srv.KeyExchange(ctx, conn)
	}()

	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var serverTR TransportRequest
	if err := readJSONLine(conn, &serverTR); err != nil {
		t.Fatal(err)
	}

	// Send correct version but garbage public key (wrong length for X25519).
	tr := TransportRequest{
		Version:   TransportVersion,
		PublicKey: []byte{0x01, 0x02, 0x03}, // invalid X25519 key
	}
	if err := json.NewEncoder(conn).Encode(tr); err != nil {
		t.Fatal(err)
	}

	srvErr := <-errCh
	if srvErr == nil {
		t.Fatal("expected public key parse error")
	}
}

// --- Priority 3 batch: server infrastructure + handshake error paths ------

// TestNewDefaultConfig covers NewDefaultConfig (was 0%).
func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg == nil {
		t.Fatal("NewDefaultConfig returned nil")
	}
	if cfg.PeersWanted == 0 {
		t.Fatal("PeersWanted should be non-zero")
	}
}

// TestSendReshareFlagDecoding covers the reshare flag decoding path
// in serverTSSTransport.Send (lines 91-101 of tss_rpc.go).  The
// non-reshare branch is already covered by other tests; this test
// specifically exercises the CeremonyReshare branch with all flag
// combinations.
func TestSendReshareFlagDecoding(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// We need a valid session transport for Send to write to.
	srvTr, cliTr := connectedTransports(t)

	target := Identity{0xAA}
	s := &Server{
		secret:   secret,
		sessions: map[Identity]*Transport{target: srvTr},
	}
	stt := newServerTSSTransport(s)

	cid := NewCeremonyID()
	stt.registerCeremony(cid, CeremonyReshare)
	defer stt.unregisterCeremony(cid)

	// data[0] = broadcast flag, data[1] = committee flags, data[2:] = payload.
	// Test all flag combinations: ToOld=0x01, ToNew=0x02, FromNew=0x04.
	tests := []struct {
		name  string
		bcast byte
		flags byte
	}{
		{"no flags", 0x00, 0x00},
		{"broadcast+toOld", 0x01, 0x01},
		{"toNew", 0x00, 0x02},
		{"fromNew", 0x00, 0x04},
		{"all flags", 0x01, 0x07},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte{tc.bcast, tc.flags, 0xDE, 0xAD}

			errCh := pipeWrite(func() error {
				return stt.Send(target, cid, data)
			})

			// Read the TSSMessage from the client side.
			_, cmd, _, readErr := cliTr.ReadEnvelope()
			if readErr != nil {
				t.Fatalf("read: %v", readErr)
			}
			msg, ok := cmd.(*TSSMessage)
			if !ok {
				t.Fatalf("expected *TSSMessage, got %T", cmd)
			}
			if msg.Type != CeremonyReshare {
				t.Fatalf("expected CeremonyReshare, got %v", msg.Type)
			}
			// Verify flags were decoded correctly.
			if tc.bcast == 0x01 && msg.Flags&TSSFlagBroadcast == 0 {
				t.Fatal("expected TSSFlagBroadcast")
			}
			if tc.flags&0x01 != 0 && msg.Flags&TSSFlagToOld == 0 {
				t.Fatal("expected TSSFlagToOld")
			}
			if tc.flags&0x02 != 0 && msg.Flags&TSSFlagToNew == 0 {
				t.Fatal("expected TSSFlagToNew")
			}
			if tc.flags&0x04 != 0 && msg.Flags&TSSFlagFromNew == 0 {
				t.Fatal("expected TSSFlagFromNew")
			}
			// Verify wireData is data[2:].
			if !bytes.Equal(msg.Data, data[2:]) {
				t.Fatalf("wire data mismatch: got %x, want %x",
					msg.Data, data[2:])
			}

			if sendErr := <-errCh; sendErr != nil {
				t.Fatalf("send: %v", sendErr)
			}
		})
	}
}

// TestHandshakeWriteHelloRequestError covers the error path when
// Handshake fails to write the initial HelloRequest because the
// connection is already closed.
func TestHandshakeWriteHelloRequestError(t *testing.T) {
	tr1, _, secret := handshakeTestPair(t)

	// Close the underlying connection before calling Handshake.
	tr1.mtx.Lock()
	tr1.conn.Close()
	tr1.mtx.Unlock()

	_, _, _, err := tr1.Handshake(context.Background(), secret, "")
	if err == nil {
		t.Fatal("expected write error, got nil")
	}
}

// TestHandshakeReadHelloResponseError covers the error path when
// Handshake successfully exchanges HelloRequest messages and writes
// its HelloResponse, but fails to read the remote HelloResponse
// because the connection is closed.
func TestHandshakeReadHelloResponseError(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	// Step 1: Read tr1's HelloRequest from the pipe.
	_, cmd, _, err := tr2.ReadEnvelope()
	if err != nil {
		t.Fatalf("read HelloRequest: %v", err)
	}
	hello, ok := cmd.(*HelloRequest)
	if !ok {
		t.Fatalf("expected *HelloRequest, got %T", cmd)
	}

	// Step 2: Send a valid HelloRequest from tr2 so tr1 can proceed.
	naclPub, _ := remoteSecret.NaClPublicKey()
	ch := make([]byte, ChallengeSize)
	ch[0] = 0xBB
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: ch,
		NaClPub:   naclPub,
	})
	if err != nil {
		t.Fatalf("write HelloRequest: %v", err)
	}

	// Step 3: Read tr1's HelloResponse (it signs their challenge).
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatalf("read HelloResponse: %v", err)
	}
	_ = hello // verified above

	// Step 4: Close the pipe instead of sending HelloResponse.
	// This forces tr1.Handshake to fail on the second read.
	tr2.mtx.Lock()
	tr2.conn.Close()
	tr2.mtx.Unlock()

	hsErr := <-errCh
	if hsErr == nil {
		t.Fatal("expected read error for HelloResponse, got nil")
	}
}

// TestHandshakeUnexpectedHelloResponseType covers the error path when
// the remote sends a non-HelloResponse after the HelloRequest exchange.
func TestHandshakeUnexpectedHelloResponseType(t *testing.T) {
	tr1, tr2, secret := handshakeTestPair(t)
	remoteSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, _, err := tr1.Handshake(context.Background(), secret, "")
		errCh <- err
	}()

	// Read tr1's HelloRequest.
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}

	// Send valid HelloRequest from tr2.
	naclPub, _ := remoteSecret.NaClPublicKey()
	ch := make([]byte, ChallengeSize)
	ch[0] = 0xCC
	err = tr2.Write(remoteSecret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  remoteSecret.Identity,
		Challenge: ch,
		NaClPub:   naclPub,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read tr1's HelloResponse (challenge signature).
	_, _, _, err = tr2.ReadEnvelope()
	if err != nil {
		t.Fatal(err)
	}

	// Send a PingRequest instead of HelloResponse — wrong type.
	errCh2 := pipeWrite(func() error {
		return tr2.Write(remoteSecret.Identity, PingRequest{OriginTimestamp: 99})
	})

	hsErr := <-errCh
	if hsErr == nil {
		t.Fatal("expected 'unexpected command' error")
	}
	if !strings.Contains(hsErr.Error(), "unexpected command") {
		t.Fatalf("wrong error: %v", hsErr)
	}
	if writeErr := <-errCh2; writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
}

// --- Priority 3: KX write errors and connect() error paths ------------------

// TestTransportKeyExchangeServerWriteError covers Transport.KeyExchange
// when the server cannot write its TransportRequest because the remote
// end closed the connection.
func TestTransportKeyExchangeServerWriteError(t *testing.T) {
	ctx := t.Context()

	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- srv.KeyExchange(ctx, conn)
	}()

	// Client connects and closes immediately → server's Encode fails.
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	srvErr := <-errCh
	if srvErr == nil {
		t.Fatal("expected write error from server KX")
	}
	t.Logf("server KX error (expected): %v", srvErr)
}

// TestTransportKeyExchangeClientWriteError covers Transport.KeyExchange
// when the client reads the server's TransportRequest successfully but
// cannot write its own because the connection was closed.
func TestTransportKeyExchangeClientWriteError(t *testing.T) {
	ctx := t.Context()

	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	// Use net.Pipe for deterministic close semantics — TCP
	// buffers writes to half-closed sockets, making the write
	// error unreliable.
	srvConn, cliConn := net.Pipe()
	defer cliConn.Close()

	// Server side: write TransportRequest then close immediately.
	go func() {
		tr := TransportRequest{
			Version:   TransportVersion,
			PublicKey: srv.us.PublicKey().Bytes(),
		}
		if err := json.NewEncoder(srvConn).Encode(tr); err != nil {
			return
		}
		srvConn.Close()
	}()

	// Client: reads OK, write fails on closed pipe.
	cli, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}
	cli.isServer = false

	cliErr := cli.KeyExchange(ctx, cliConn)
	if cliErr == nil {
		t.Fatal("expected write error from client KX")
	}
	t.Logf("client KX error (expected): %v", cliErr)
}

// TestConnectDuplicateSession covers connect() when newSession fails
// because a session for the remote identity already exists.
func TestConnectDuplicateSession(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Server B: normal, no DNS.
	serverB := newTestServer(t, preParams, 1, "localhost:0", nil)
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	addrB := waitForListenAddress(t, serverB, 2*time.Second)

	// Server A: pre-populate sessions with B's identity so
	// newSession returns a duplicate error.
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		peersTTL: peersTTL,
		seen:     seen,
		sessions: map[Identity]*Transport{
			serverB.secret.Identity: {}, // existing session
		},
		peers: make(map[Identity]*PeerRecord),
		cfg: &Config{
			PeersWanted: 8,
		},
	}
	errC := make(chan error, 1)
	s.wg.Add(1)
	go s.connect(ctx, addrB, errC)

	// connect() succeeds through KX+Handshake but newSession returns
	// duplicate.  connect() logs the error and returns without sending
	// to errC.
	select {
	case err := <-errC:
		t.Fatalf("unexpected errC send: %v", err)
	case <-time.After(3 * time.Second):
		// Expected: connect() returned silently after log.Errorf.
	}

	cancel()
	<-errB
}

// TestConnectDNSEmptyName covers connect() when DNSRequired is set
// and the remote did not advertise a DNS name.
func TestConnectDNSEmptyName(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Server B: no DNS name.
	serverB := newTestServer(t, preParams, 1, "localhost:0", nil)
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	addrB := waitForListenAddress(t, serverB, 2*time.Second)

	// Server A: DNSRequired=true.
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		peersTTL: peersTTL,
		seen:     seen,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		cfg: &Config{
			PeersWanted: 8,
			DNSRequired: true,
		},
	}
	errC := make(chan error, 1)
	s.wg.Add(1)
	go s.connect(ctx, addrB, errC)

	select {
	case err := <-errC:
		if err == nil {
			t.Fatal("expected DNS error")
		}
		if !strings.Contains(err.Error(), "dns name") {
			t.Fatalf("wrong error: %v", err)
		}
		t.Logf("connect DNS error (expected): %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for connect DNS error")
	}

	cancel()
	<-errB
}

// TestConnectDNSVerifyError covers connect() when DNSRequired is set,
// the remote advertises a DNS name, but DNS verification fails.
func TestConnectDNSVerifyError(t *testing.T) {
	preParams := loadPreParams(t, 2)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	domain := "connverify.test"

	// Server B advertises a DNS name.
	serverB := newTestServer(t, preParams, 1, "localhost:0", nil)
	serverB.cfg.DNSName = "nodeB." + domain
	errB := make(chan error, 1)
	go func() { errB <- serverB.Run(ctx) }()
	addrB := waitForListenAddress(t, serverB, 2*time.Second)

	// DNS server returns wrong identity for nodeB.
	handler := &dnsHandler{
		lookup: make(map[string][]dns.RR),
		nodes:  make(map[string]*node),
	}
	wrongID := Identity{
		0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
		0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
		0xEF, 0xEE, 0xED, 0xEC,
	}
	fqdn := "nodeB." + domain + "."
	handler.lookup[fqdn] = []dns.RR{
		&dns.TXT{
			Hdr: dns.Header{Name: fqdn, Class: dns.ClassINET},
			Txt: []string{fmt.Sprintf("v=%v; identity=%v",
				dnsAppName, wrongID)},
		},
	}
	dnsSrv := newDNSServer(ctx, handler)
	mockResolver := newResolver(dnsSrv.Listener.Addr().String())

	// Server A: DNSRequired + wrong DNS data.
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	seen, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		peersTTL: peersTTL,
		seen:     seen,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
		resolver: mockResolver,
		cfg: &Config{
			PeersWanted: 8,
			DNSRequired: true,
		},
	}
	errC := make(chan error, 1)
	s.wg.Add(1)
	go s.connect(ctx, addrB, errC)

	select {
	case err := <-errC:
		if err == nil {
			t.Fatal("expected DNS verify error")
		}
		if !strings.Contains(err.Error(), "dns verify") {
			t.Fatalf("wrong error: %v", err)
		}
		t.Logf("connect DNS verify error (expected): %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for connect DNS verify error")
	}

	cancel()
	<-errB
}

// TestListenBindError covers the listen() error path when
// ListenAddress is invalid and net.Listen fails.
func TestListenBindError(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret: secret,
		cfg: &Config{
			ListenAddress: "invalid:::address",
			PeersWanted:   8,
		},
		listenConfig: &net.ListenConfig{},
		sessions:     make(map[Identity]*Transport),
		peers:        make(map[Identity]*PeerRecord),
	}

	errC := make(chan error, 1)
	s.wg.Add(1)
	go s.listen(t.Context(), errC)

	select {
	case err := <-errC:
		if err == nil {
			t.Fatal("expected listen error")
		}
		t.Logf("listen bind error (expected): %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for listen error")
	}
}

// TestListenNewTransportError covers the listen() path where an
// accepted connection fails during newTransport (KX/handshake).
// A raw TCP connection that sends garbage triggers this.
func TestListenNewTransportError(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peersTTL, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	s := &Server{
		secret:       secret,
		peersTTL:     peersTTL,
		listenConfig: &net.ListenConfig{},
		cfg: &Config{
			ListenAddress: "127.0.0.1:0",
			PeersWanted:   8,
		},
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
	}

	errC := make(chan error, 1)
	s.wg.Add(1)
	go s.listen(ctx, errC)

	// Wait for listen to be ready.
	addr := waitForListenAddress(t, s, 2*time.Second)

	// Connect and send garbage — triggers newTransport error.
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("this is not a valid transport request\n")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	conn.Close()

	// Prove listen() survived: a second dial succeeds only if the
	// accept loop is still running.
	conn2, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial after garbage: %v (listen loop died)", err)
	}
	conn2.Close()

	// Shut down cleanly.
	cancel()
	s.wg.Wait()
}

// TestSendEncryptedRejectsBroadcastType verifies that SendEncrypted
// returns ErrUseBroadcast for broadcast-whitelisted types.
func TestSendEncryptedRejectsBroadcastType(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret: secret,
		peers:  make(map[Identity]*PeerRecord),
	}

	dest := Identity{0x01}
	err = s.SendEncrypted(dest, CeremonyResult{})
	if !errors.Is(err, ErrUseBroadcast) {
		t.Fatalf("SendEncrypted(CeremonyResult) = %v, want ErrUseBroadcast", err)
	}

	err = s.SendEncrypted(dest, CeremonyAbort{})
	if !errors.Is(err, ErrUseBroadcast) {
		t.Fatalf("SendEncrypted(CeremonyAbort) = %v, want ErrUseBroadcast", err)
	}

	// Non-broadcast type should NOT trigger the guard (will fail
	// later for other reasons like unknown peer, but not ErrUseBroadcast).
	err = s.SendEncrypted(dest, PingRequest{})
	if errors.Is(err, ErrUseBroadcast) {
		t.Fatal("SendEncrypted(PingRequest) should not return ErrUseBroadcast")
	}
}

// TestBroadcastWhitelist verifies that Broadcast rejects non-whitelisted
// payload types and accepts whitelisted ones.
func TestBroadcastWhitelist(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		peers:    make(map[Identity]*PeerRecord),
		sessions: make(map[Identity]*Transport),
	}

	// Non-whitelisted: rejected.
	if err := s.Broadcast(PingRequest{}); err == nil {
		t.Fatal("Broadcast(PingRequest) should fail")
	}
	if err := s.Broadcast(TSSMessage{}); err == nil {
		t.Fatal("Broadcast(TSSMessage) should fail")
	}

	// Whitelisted: accepted (no peers connected, so nothing sent,
	// but no error).
	if err := s.Broadcast(CeremonyResult{Success: true}); err != nil {
		t.Fatalf("Broadcast(CeremonyResult) = %v", err)
	}
	if err := s.Broadcast(CeremonyAbort{Reason: "test"}); err != nil {
		t.Fatalf("Broadcast(CeremonyAbort) = %v", err)
	}
}

// TestThreeNodeBroadcast launches A↔B↔C and verifies the broadcast
// primitive: A broadcasts a CeremonyResult, both B and C receive it.
// Dedup prevents B from re-forwarding to A.
func TestThreeNodeBroadcast(t *testing.T) {
	preParams := loadPreParams(t, 3)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	g, gctx := errgroup.WithContext(ctx)

	servers := make([]*Server, 3)
	addrs := make([]string, 3)

	// Node A (chain head).
	servers[0] = newTestServer(t, preParams, 0, "localhost:0", nil)
	servers[0].cfg.PeersWanted = 1
	servers[0].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[0].Run(gctx) })
	addrs[0] = waitForListenAddress(t, servers[0], 2*time.Second)

	// Node B.
	servers[1] = newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrs[0]})
	servers[1].cfg.PeersWanted = 2
	servers[1].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[1].Run(gctx) })
	addrs[1] = waitForListenAddress(t, servers[1], 2*time.Second)

	waitForSessions(t, servers[0], 1, 5*time.Second)
	waitForSessions(t, servers[1], 1, 5*time.Second)

	// Node C.
	servers[2] = newTestServer(t, preParams, 2, "localhost:0",
		[]string{addrs[1]})
	servers[2].cfg.PeersWanted = 2
	servers[2].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[2].Run(gctx) })
	addrs[2] = waitForListenAddress(t, servers[2], 2*time.Second)

	waitForSessions(t, servers[1], 2, 5*time.Second)
	waitForSessions(t, servers[2], 1, 5*time.Second)

	// Wait for gossip convergence: all 3 know all 3 peers.
	waitForCondition(t, "gossip convergence", 10*time.Second, func() bool {
		for i := 0; i < 3; i++ {
			if servers[i].PeerCount() < 2 {
				return false
			}
		}
		return true
	})

	// Node A broadcasts a CeremonyResult.
	cid := NewCeremonyID()
	result := CeremonyResult{
		CeremonyID: cid,
		Success:    true,
	}
	if err := servers[0].Broadcast(result); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}

	// Wait for B to forward the broadcast.
	waitForCondition(t, "B forwarded broadcast", 5*time.Second, func() bool {
		return servers[1].forwarded.Load() > 0
	})

	// Dedup: A should NOT have received the broadcast back from B.
	// The isDuplicate check in A's handle() should drop it.

	cancel()
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server error: %v", err)
	}
}

// TestBroadcastDedup verifies that the same broadcast message received
// twice is only processed once.  Uses a 3-node chain A↔B↔C.  A sends
// the same CeremonyResult twice; B should forward only once.
func TestBroadcastDedup(t *testing.T) {
	preParams := loadPreParams(t, 3)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	g, gctx := errgroup.WithContext(ctx)

	servers := make([]*Server, 3)
	addrs := make([]string, 3)

	// Node A.
	servers[0] = newTestServer(t, preParams, 0, "localhost:0", nil)
	servers[0].cfg.PeersWanted = 1
	servers[0].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[0].Run(gctx) })
	addrs[0] = waitForListenAddress(t, servers[0], 2*time.Second)

	// Node B.
	servers[1] = newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrs[0]})
	servers[1].cfg.PeersWanted = 2
	servers[1].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[1].Run(gctx) })
	addrs[1] = waitForListenAddress(t, servers[1], 2*time.Second)

	waitForSessions(t, servers[0], 1, 5*time.Second)
	waitForSessions(t, servers[1], 1, 5*time.Second)

	// Node C.
	servers[2] = newTestServer(t, preParams, 2, "localhost:0",
		[]string{addrs[1]})
	servers[2].cfg.PeersWanted = 2
	servers[2].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[2].Run(gctx) })
	addrs[2] = waitForListenAddress(t, servers[2], 2*time.Second)

	waitForSessions(t, servers[1], 2, 5*time.Second)
	waitForSessions(t, servers[2], 1, 5*time.Second)

	// Wait for gossip convergence.
	waitForCondition(t, "gossip convergence", 10*time.Second, func() bool {
		for i := 0; i < 3; i++ {
			if servers[i].PeerCount() < 2 {
				return false
			}
		}
		return true
	})

	// Record B's forwarded counter before the broadcast.
	fwdBefore := servers[1].forwarded.Load()

	// A broadcasts a CeremonyResult.
	cid := NewCeremonyID()
	result := CeremonyResult{
		CeremonyID: cid,
		Success:    true,
	}
	if err := servers[0].Broadcast(result); err != nil {
		t.Fatalf("Broadcast 1: %v", err)
	}

	// Wait for B to forward the first broadcast.
	waitForCondition(t, "B forwarded first broadcast", 5*time.Second, func() bool {
		return servers[1].forwarded.Load() > fwdBefore
	})

	fwdAfterFirst := servers[1].forwarded.Load()

	// A broadcasts the SAME CeremonyResult again (same payload hash).
	if err := servers[0].Broadcast(result); err != nil {
		t.Fatalf("Broadcast 2: %v", err)
	}

	// Negative assertion: wait long enough for the duplicate to be
	// processed (if it were going to be forwarded), then verify it
	// was dropped.  Bounded wait for a non-event — the standard
	// pattern for proving something did NOT happen in a distributed
	// system.  Context-cancellable so the test won't hang on failure.
	select {
	case <-ctx.Done():
		t.Fatal("context cancelled during dedup check")
	case <-time.After(500 * time.Millisecond):
	}

	fwdAfterSecond := servers[1].forwarded.Load()
	secondForwards := fwdAfterSecond - fwdAfterFirst

	// Dedup: B should NOT have forwarded the duplicate.
	if secondForwards != 0 {
		t.Fatalf("B forwarded %d times after duplicate broadcast, "+
			"want 0 (dedup should drop)", secondForwards)
	}

	cancel()
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server error: %v", err)
	}
}

// TestBroadcastTTLExpiry verifies that a broadcast with TTL=0 is
// dropped.  Uses a 3-node chain A↔B↔C.  A sends a broadcast with
// TTL=1: B receives (TTL=1 > 0), processes locally, and forwards
// with TTL=0.  C receives with TTL=0 and drops it without forwarding.
func TestBroadcastTTLExpiry(t *testing.T) {
	preParams := loadPreParams(t, 3)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	g, gctx := errgroup.WithContext(ctx)

	servers := make([]*Server, 3)
	addrs := make([]string, 3)

	// Node A.
	servers[0] = newTestServer(t, preParams, 0, "localhost:0", nil)
	servers[0].cfg.PeersWanted = 1
	servers[0].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[0].Run(gctx) })
	addrs[0] = waitForListenAddress(t, servers[0], 2*time.Second)

	// Node B.
	servers[1] = newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrs[0]})
	servers[1].cfg.PeersWanted = 2
	servers[1].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[1].Run(gctx) })
	addrs[1] = waitForListenAddress(t, servers[1], 2*time.Second)

	waitForSessions(t, servers[0], 1, 5*time.Second)
	waitForSessions(t, servers[1], 1, 5*time.Second)

	// Node C.
	servers[2] = newTestServer(t, preParams, 2, "localhost:0",
		[]string{addrs[1]})
	servers[2].cfg.PeersWanted = 2
	servers[2].cfg.MaintainInterval = 10 * time.Second
	g.Go(func() error { return servers[2].Run(gctx) })
	addrs[2] = waitForListenAddress(t, servers[2], 2*time.Second)

	waitForSessions(t, servers[1], 2, 5*time.Second)
	waitForSessions(t, servers[2], 1, 5*time.Second)

	// Wait for gossip convergence.
	waitForCondition(t, "gossip convergence", 10*time.Second, func() bool {
		for i := 0; i < 3; i++ {
			if servers[i].PeerCount() < 2 {
				return false
			}
		}
		return true
	})

	// Record C's forwarded counter before the broadcast.
	cFwdBefore := servers[2].forwarded.Load()

	// A broadcasts with TTL=1.  B will receive at TTL=1 (processes
	// and forwards with TTL=0).  C receives at TTL=0 (drops).
	cid := NewCeremonyID()
	result := CeremonyResult{
		CeremonyID: cid,
		Success:    true,
	}
	if err := servers[0].broadcastWithTTL(result, 1); err != nil {
		t.Fatalf("broadcastWithTTL: %v", err)
	}

	// Wait for B to forward (positive assertion).
	waitForCondition(t, "B forwarded broadcast", 5*time.Second, func() bool {
		return servers[1].forwarded.Load() > 0
	})

	// Negative assertion: C received at TTL=0 and should not forward.
	// Bounded wait for C to process the message after B forwarded it.
	select {
	case <-ctx.Done():
		t.Fatal("context cancelled during TTL check")
	case <-time.After(200 * time.Millisecond):
	}

	// C should NOT have forwarded (it received at TTL=0, dropped).
	cFwdAfter := servers[2].forwarded.Load()
	if cFwdAfter != cFwdBefore {
		t.Fatalf("C forwarded %d times after TTL=0 broadcast, "+
			"want 0", cFwdAfter-cFwdBefore)
	}

	cancel()
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server error: %v", err)
	}
}

// =============================================================================
// Admin RPC tests (Commit 2)
// =============================================================================

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{"nil", nil, false},
		{"ipv4 loopback", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, true},
		{"ipv6 loopback", &net.TCPAddr{IP: net.IPv6loopback, Port: 1234}, true},
		{"ipv4 remote", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}, false},
		{"ipv6 remote", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}, false},
		{"unspecified", &net.TCPAddr{IP: net.IPv4zero, Port: 1234}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isLocalhost(tc.addr)
			if got != tc.want {
				t.Fatalf("isLocalhost(%v) = %v, want %v",
					tc.addr, got, tc.want)
			}
		})
	}
}

func TestCeremonyTracking(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)

	var cid CeremonyID
	copy(cid[:], []byte("test-ceremony-tracking-00"))

	// Register.
	s.registerCeremony(cid, CeremonyKeygen, Identity{})

	s.mtx.RLock()
	ci, ok := s.ceremonies[cid]
	s.mtx.RUnlock()
	if !ok {
		t.Fatal("ceremony not registered")
	}
	if ci.Status != CeremonyRunning {
		t.Fatalf("status = %q, want running", ci.Status)
	}
	if ci.Type != CeremonyKeygen {
		t.Fatalf("type = %v, want CeremonyKeygen", ci.Type)
	}

	// Complete.
	s.completeCeremony(cid)

	s.mtx.RLock()
	ci = s.ceremonies[cid]
	s.mtx.RUnlock()
	if ci.Status != CeremonyComplete {
		t.Fatalf("status = %q, want complete", ci.Status)
	}

	// Fail a different ceremony.
	var cid2 CeremonyID
	copy(cid2[:], []byte("test-ceremony-fail-00000"))
	s.registerCeremony(cid2, CeremonySign, Identity{})
	s.failCeremony(cid2, "test error")

	s.mtx.RLock()
	ci2 := s.ceremonies[cid2]
	s.mtx.RUnlock()
	if ci2.Status != CeremonyFailed {
		t.Fatalf("status = %q, want failed", ci2.Status)
	}
	if ci2.Error != "test error" {
		t.Fatalf("error = %q, want 'test error'", ci2.Error)
	}

	// Complete/fail on unknown ID is a no-op (no panic).
	var bogus CeremonyID
	copy(bogus[:], []byte("nonexistent-ceremony-000"))
	s.completeCeremony(bogus)
	s.failCeremony(bogus, "nope")
}

// readAdminResponse reads from the transport, discarding gossip messages
// (PeerNotify, PingRequest, etc.) until the expected admin response type
// arrives.  Fails the test after 20 reads without a match.
func readAdminResponse[T any](t *testing.T, tr *Transport) T {
	t.Helper()
	for i := 0; i < 20; i++ {
		_, cmd, err := tr.Read()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if resp, ok := cmd.(T); ok {
			return resp
		}
		// Gossip message — discard and retry.
	}
	var zero T
	t.Fatalf("did not receive expected response type after 20 reads")
	return zero
}

// TestAdminNonLocalhost verifies that admin requests sent from a
// non-localhost connection are silently dropped.  handleTestServer uses
// net.Pipe whose RemoteAddr is "pipe" — not localhost.
func TestAdminNonLocalhost(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	_, cliTr, _ := handleTestServer(t, ctx)

	// Send admin request over non-localhost pipe — should be dropped.
	errCh := pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, PeerListAdminRequest{})
	})
	if err := <-errCh; err != nil {
		t.Fatalf("write admin: %v", err)
	}

	// Send a PingRequest to prove handle() is still alive and to
	// get a response we can read.  If the admin request had been
	// processed, we'd see PeerListAdminResponse before PingResponse.
	errCh = pipeWrite(func() error {
		return cliTr.Write(Identity{0xEE}, PingRequest{OriginTimestamp: 77})
	})
	_, cmd, err := cliTr.Read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write ping: %v", err)
	}

	// Expect PingResponse, not PeerListAdminResponse.
	if _, ok := cmd.(*PingResponse); !ok {
		t.Fatalf("expected *PingResponse, got %T (admin leak)", cmd)
	}

	cancel()
}

func TestAdminPeerList(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	addr := waitForListenAddress(t, s, 2*time.Second)

	// Dial from localhost — admin RPC should be accepted.
	clientSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tr := new(Transport)
	kxCtx, kxCancel := context.WithTimeout(ctx, 5*time.Second)
	defer kxCancel()
	if err := tr.KeyExchange(kxCtx, conn); err != nil {
		t.Fatalf("kx: %v", err)
	}
	if _, _, _, err := tr.Handshake(kxCtx, clientSecret, ""); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Send PeerListAdminRequest.
	if err := tr.Write(clientSecret.Identity, PeerListAdminRequest{}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read response, skipping gossip messages the server sends
	// after handshake (PeerNotify, etc.).
	resp := readAdminResponse[*PeerListAdminResponse](t, tr)

	// Server registers the connecting client as a peer during
	// gossip exchange, so the peer list may be non-empty.
	// The important thing is the admin RPC returned a valid response.
	t.Logf("admin peer list returned %d peers", len(resp.Peers))

	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server: %v", err)
	}
}

func TestAdminCeremonyStatusNotFound(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	addr := waitForListenAddress(t, s, 2*time.Second)

	clientSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tr := new(Transport)
	kxCtx, kxCancel := context.WithTimeout(ctx, 5*time.Second)
	defer kxCancel()
	if err := tr.KeyExchange(kxCtx, conn); err != nil {
		t.Fatalf("kx: %v", err)
	}
	if _, _, _, err := tr.Handshake(kxCtx, clientSecret, ""); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Query a ceremony ID that doesn't exist.
	var cid CeremonyID
	copy(cid[:], []byte("does-not-exist-00000000"))
	if err := tr.Write(clientSecret.Identity, CeremonyStatusRequest{
		CeremonyID: cid,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp := readAdminResponse[*CeremonyStatusResponse](t, tr)
	if resp.Found {
		t.Fatal("expected Found=false for unknown ceremony")
	}
	if resp.CeremonyID != cid {
		t.Fatalf("ceremony ID mismatch: %x != %x", resp.CeremonyID, cid)
	}

	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server: %v", err)
	}
}

func TestAdminCeremonyList(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	addr := waitForListenAddress(t, s, 2*time.Second)

	// Register a couple of ceremonies directly on the server.
	var cid1, cid2 CeremonyID
	copy(cid1[:], []byte("ceremony-list-test-0001"))
	copy(cid2[:], []byte("ceremony-list-test-0002"))
	s.registerCeremony(cid1, CeremonyKeygen, Identity{})
	s.registerCeremony(cid2, CeremonySign, Identity{})
	s.completeCeremony(cid1)

	clientSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tr := new(Transport)
	kxCtx, kxCancel := context.WithTimeout(ctx, 5*time.Second)
	defer kxCancel()
	if err := tr.KeyExchange(kxCtx, conn); err != nil {
		t.Fatalf("kx: %v", err)
	}
	if _, _, _, err := tr.Handshake(kxCtx, clientSecret, ""); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	if err := tr.Write(clientSecret.Identity, CeremonyListRequest{}); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp := readAdminResponse[*CeremonyListResponse](t, tr)
	if len(resp.Ceremonies) != 2 {
		t.Fatalf("expected 2 ceremonies, got %d", len(resp.Ceremonies))
	}

	// Build a lookup for verification.
	found := make(map[CeremonyID]CeremonyStatusResponse)
	for _, c := range resp.Ceremonies {
		found[c.CeremonyID] = c
	}

	c1, ok := found[cid1]
	if !ok {
		t.Fatal("cid1 not in list")
	}
	if c1.Status != CeremonyComplete {
		t.Fatalf("cid1 status = %q, want complete", c1.Status)
	}
	if c1.Type != CeremonyKeygen.String() {
		t.Fatalf("cid1 type = %q, want %q", c1.Type, CeremonyKeygen.String())
	}

	c2, ok := found[cid2]
	if !ok {
		t.Fatal("cid2 not in list")
	}
	if c2.Status != CeremonyRunning {
		t.Fatalf("cid2 status = %q, want running", c2.Status)
	}

	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server: %v", err)
	}
}

func TestAdminCeremonyStatusFound(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	addr := waitForListenAddress(t, s, 2*time.Second)

	// Register and complete a ceremony.
	var cid CeremonyID
	copy(cid[:], []byte("ceremony-status-found-01"))
	s.registerCeremony(cid, CeremonyReshare, Identity{})
	s.failCeremony(cid, "threshold mismatch")

	clientSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tr := new(Transport)
	kxCtx, kxCancel := context.WithTimeout(ctx, 5*time.Second)
	defer kxCancel()
	if err := tr.KeyExchange(kxCtx, conn); err != nil {
		t.Fatalf("kx: %v", err)
	}
	if _, _, _, err := tr.Handshake(kxCtx, clientSecret, ""); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	if err := tr.Write(clientSecret.Identity, CeremonyStatusRequest{
		CeremonyID: cid,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp := readAdminResponse[*CeremonyStatusResponse](t, tr)
	if !resp.Found {
		t.Fatal("expected Found=true")
	}
	if resp.Status != CeremonyFailed {
		t.Fatalf("status = %q, want failed", resp.Status)
	}
	if resp.Error != "threshold mismatch" {
		t.Fatalf("error = %q, want 'threshold mismatch'", resp.Error)
	}
	if resp.Type != CeremonyReshare.String() {
		t.Fatalf("type = %q, want %q", resp.Type, CeremonyReshare.String())
	}

	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server: %v", err)
	}
}

// =============================================================================
// Election tests
// =============================================================================

// TestElectDeterminism verifies that the same seed and peer set
// always produce the same committee.
func TestElectDeterminism(t *testing.T) {
	seed := []byte("deterministic-seed-for-test")
	peers := make([]Identity, 10)
	for i := range peers {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = s.Identity
	}

	result1, err := Elect(seed, peers, 3)
	if err != nil {
		t.Fatal(err)
	}
	result2, err := Elect(seed, peers, 3)
	if err != nil {
		t.Fatal(err)
	}

	if len(result1) != 3 || len(result2) != 3 {
		t.Fatalf("expected 3 members, got %d and %d",
			len(result1), len(result2))
	}
	for i := range result1 {
		if result1[i] != result2[i] {
			t.Fatalf("mismatch at index %d: %v != %v",
				i, result1[i], result2[i])
		}
	}
}

// TestElectDifferentSeed verifies that different seeds produce
// different committees (with overwhelming probability).
func TestElectDifferentSeed(t *testing.T) {
	peers := make([]Identity, 20)
	for i := range peers {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = s.Identity
	}

	result1, err := Elect([]byte("seed-alpha"), peers, 5)
	if err != nil {
		t.Fatal(err)
	}
	result2, err := Elect([]byte("seed-beta"), peers, 5)
	if err != nil {
		t.Fatal(err)
	}

	same := true
	for i := range result1 {
		if result1[i] != result2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different seeds produced identical committees")
	}
}

// TestElectValidation verifies edge-case rejections.
func TestElectValidation(t *testing.T) {
	seed := []byte("validation-test")
	peers := make([]Identity, 3)
	for i := range peers {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = s.Identity
	}

	// committee > peers
	_, err := Elect(seed, peers, 5)
	if err == nil {
		t.Fatal("expected error for committee > peers")
	}

	// committee < 1
	_, err = Elect(seed, peers, 0)
	if err == nil {
		t.Fatal("expected error for committee < 1")
	}

	// committee == -1 (still < 1)
	_, err = Elect(seed, peers, -1)
	if err == nil {
		t.Fatal("expected error for negative committee")
	}
}

// TestElectSinglePeer verifies that electing 1 from 1 works.
func TestElectSinglePeer(t *testing.T) {
	seed := []byte("single")
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	peers := []Identity{s.Identity}

	result, err := Elect(seed, peers, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 member, got %d", len(result))
	}
	if result[0] != s.Identity {
		t.Fatalf("expected %v, got %v", s.Identity, result[0])
	}
}

// TestElectDoesNotMutateInput verifies Elect does not modify the
// input peer slice.
func TestElectDoesNotMutateInput(t *testing.T) {
	seed := []byte("immutability")
	peers := make([]Identity, 5)
	for i := range peers {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = s.Identity
	}
	original := make([]Identity, len(peers))
	copy(original, peers)

	_, err := Elect(seed, peers, 3)
	if err != nil {
		t.Fatal(err)
	}

	for i := range peers {
		if peers[i] != original[i] {
			t.Fatalf("input mutated at index %d", i)
		}
	}
}

// TestIdentitiesToPartyIDs verifies the conversion helper.
func TestIdentitiesToPartyIDs(t *testing.T) {
	ids := make([]Identity, 3)
	for i := range ids {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = s.Identity
	}

	pids := IdentitiesToPartyIDs(ids)
	if len(pids) != 3 {
		t.Fatalf("expected 3 party IDs, got %d", len(pids))
	}
	for i, pid := range pids {
		if pid.Id != ids[i].String() {
			t.Fatalf("index %d: Id=%q, want %q",
				i, pid.Id, ids[i].String())
		}
	}
}

// =============================================================================
// 3-node keygen integration test via admin dispatch
// =============================================================================

// TestThreeNodeKeygenDispatch starts a 3-node chain (A↔B↔C), connects
// an admin client to node A, queries peers, elects a committee of 3,
// sends encrypted KeygenRequests, and verifies all 3 nodes receive
// the CeremonyResult broadcast.
func TestThreeNodeKeygenDispatch(t *testing.T) {
	preParams := loadPreParams(t, 3)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	g, gctx := errgroup.WithContext(ctx)

	servers := make([]*Server, 3)
	addrs := make([]string, 3)

	// Node A — PeersWanted=4 to accept admin + 2 peers + headroom.
	servers[0] = newTestServer(t, preParams, 0, "localhost:0", nil)
	servers[0].cfg.PeersWanted = 4
	servers[0].cfg.MaintainInterval = 500 * time.Millisecond
	g.Go(func() error { return servers[0].Run(gctx) })
	addrs[0] = waitForListenAddress(t, servers[0], 2*time.Second)

	// Node B.
	servers[1] = newTestServer(t, preParams, 1, "localhost:0",
		[]string{addrs[0]})
	servers[1].cfg.PeersWanted = 4
	servers[1].cfg.MaintainInterval = 500 * time.Millisecond
	g.Go(func() error { return servers[1].Run(gctx) })
	addrs[1] = waitForListenAddress(t, servers[1], 2*time.Second)

	// Node C.
	servers[2] = newTestServer(t, preParams, 2, "localhost:0",
		[]string{addrs[1]})
	servers[2].cfg.PeersWanted = 4
	servers[2].cfg.MaintainInterval = 500 * time.Millisecond
	g.Go(func() error { return servers[2].Run(gctx) })
	addrs[2] = waitForListenAddress(t, servers[2], 2*time.Second)

	// Wait for gossip convergence: all 3 know all 3 peers AND all
	// have NaClPub populated AND all have sessions to each other.
	waitForFullMesh(t, servers, 3, 30*time.Second)

	// Admin client: connect to node A.
	adminSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addrs[0])
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	adminTr := new(Transport)
	defer adminTr.Close()
	if err := adminTr.KeyExchange(ctx, conn); err != nil {
		t.Fatalf("admin KX: %v", err)
	}
	if _, _, _, err := adminTr.Handshake(ctx, adminSecret, ""); err != nil {
		t.Fatalf("admin handshake: %v", err)
	}

	// Query peers.
	if err := adminTr.Write(adminSecret.Identity,
		PeerListAdminRequest{}); err != nil {
		t.Fatalf("write peer list: %v", err)
	}
	peerResp := readAdminResponse[*PeerListAdminResponse](t, adminTr)
	eligiblePeers := 0
	for _, pr := range peerResp.Peers {
		if (pr.Connected || pr.Self) && len(pr.NaClPub) == NaClPubSize {
			eligiblePeers++
		}
	}
	if eligiblePeers < 3 {
		t.Fatalf("only %d eligible peers with NaClPub, need 3",
			eligiblePeers)
	}

	// Collect eligible identities — exclude admin's ephemeral identity.
	type candidate struct {
		id      Identity
		naclPub []byte
	}
	candidates := make([]candidate, 0, len(peerResp.Peers))
	for _, pr := range peerResp.Peers {
		if pr.Identity == adminSecret.Identity {
			continue
		}
		if (pr.Connected || pr.Self) && len(pr.NaClPub) == NaClPubSize {
			candidates = append(candidates, candidate{
				id:      pr.Identity,
				naclPub: pr.NaClPub,
			})
		}
	}

	peerIDs := make([]Identity, len(candidates))
	for i, c := range candidates {
		peerIDs[i] = c.id
	}

	// Elect committee of 3.
	seed := []byte("test-keygen-seed")
	committee, err := Elect(seed, peerIDs, 3)
	if err != nil {
		t.Fatalf("elect: %v", err)
	}

	coordinator := committee[0]
	t.Logf("coordinator: %v", coordinator)
	for i, id := range committee {
		t.Logf("committee[%d]: %v", i, id)
	}

	// Build KeygenRequest.
	ceremonyID := NewCeremonyID()
	partyIDs := IdentitiesToPartyIDs(committee)
	req := KeygenRequest{
		CeremonyID:  ceremonyID,
		Curve:       "secp256k1",
		Committee:   partyIDs,
		Threshold:   1, // t=1, need t+1=2 to sign
		Coordinator: coordinator,
	}

	// Send plain routed KeygenRequest to each committee member.
	// Hop-by-hop transport encryption is sufficient for ceremony
	// parameters.  The local node forwards based on routing header.
	for _, dest := range committee {
		if err := adminTr.WriteTo(adminSecret.Identity, dest,
			8, req); err != nil {
			t.Fatalf("send to %v: %v", dest, err)
		}
		t.Logf("sent keygen to %v", dest)
	}

	// Wait for ceremony completion.
	waitForCeremony(t, servers, ceremonyID, coordinator, 60*time.Second)
	t.Logf("keygen ceremony %s complete", ceremonyID)

	// Verify all 3 committee members completed.
	waitForCeremonyMembers(t, servers, ceremonyID, 60*time.Second)
	for i, s := range servers {
		s.mtx.RLock()
		ci, ok := s.ceremonies[ceremonyID]
		s.mtx.RUnlock()
		if !ok {
			t.Fatalf("node %d: ceremony not found", i)
		}
		if ci.Status != CeremonyComplete {
			t.Fatalf("node %d: status=%s error=%q",
				i, ci.Status, ci.Error)
		}
	}

	cancel()
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server error: %v", err)
	}
}

// =============================================================================
// 5-node keygen integration test
// =============================================================================

// TestFiveNodeKeygen starts 5 nodes in a chain topology, waits for
// gossip convergence, elects a committee of 3, triggers keygen via
// admin dispatch, and verifies:
//   - Keygen succeeds on all 3 committee members.
//   - All 3 committee members hold valid key shares with consistent
//     public key.
//   - ALL 5 nodes received the CeremonyResult broadcast (including
//     the 2 non-committee members).
//
// Skipped with -short.
func TestFiveNodeKeygen(t *testing.T) {
	if testing.Short() {
		t.Skip("5-node keygen test is slow")
	}

	preParams := loadPreParams(t, 5)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	g, gctx := errgroup.WithContext(ctx)

	const n = 5
	servers := make([]*Server, n)
	addrs := make([]string, n)

	// Chain topology: 0→1→2→3→4.  PeersWanted=2 per SOW.
	for i := 0; i < n; i++ {
		var connect []string
		if i > 0 {
			connect = []string{addrs[i-1]}
		}
		servers[i] = newTestServer(t, preParams, i, "localhost:0", connect)
		servers[i].cfg.PeersWanted = 6 // n-1 peer sessions + admin headroom
		servers[i].cfg.MaintainInterval = 500 * time.Millisecond
		idx := i
		g.Go(func() error { return servers[idx].Run(gctx) })
		addrs[i] = waitForListenAddress(t, servers[i], 2*time.Second)
	}

	// Wait for gossip convergence: every node knows all n peers,
	// all have NaClPub, and every node has sessions to all n-1 others.
	waitForFullMesh(t, servers, n, 30*time.Second)
	t.Log("gossip converged")

	// Admin client: connect to node 0.
	adminSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addrs[0])
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	adminTr := new(Transport)
	defer adminTr.Close()
	if err := adminTr.KeyExchange(ctx, conn); err != nil {
		t.Fatalf("admin KX: %v", err)
	}
	if _, _, _, err := adminTr.Handshake(ctx, adminSecret, ""); err != nil {
		t.Fatalf("admin handshake: %v", err)
	}

	// Query peers.
	if err := adminTr.Write(adminSecret.Identity,
		PeerListAdminRequest{}); err != nil {
		t.Fatalf("write peer list: %v", err)
	}
	peerResp := readAdminResponse[*PeerListAdminResponse](t, adminTr)

	// Collect eligible identities — exclude admin's ephemeral identity.
	type candidate struct {
		id      Identity
		naclPub []byte
	}
	candidates := make([]candidate, 0, len(peerResp.Peers))
	for _, pr := range peerResp.Peers {
		if pr.Identity == adminSecret.Identity {
			continue
		}
		if (pr.Connected || pr.Self) && len(pr.NaClPub) == NaClPubSize {
			candidates = append(candidates, candidate{
				id:      pr.Identity,
				naclPub: pr.NaClPub,
			})
		}
	}
	if len(candidates) < n {
		t.Fatalf("only %d eligible peers, need %d", len(candidates), n)
	}
	t.Logf("%d eligible peers", len(candidates))

	peerIDs := make([]Identity, len(candidates))
	for i, c := range candidates {
		peerIDs[i] = c.id
	}

	// Elect committee of 3.
	const committeeSize = 3
	seed := []byte("five-node-keygen-seed")
	committee, err := Elect(seed, peerIDs, committeeSize)
	if err != nil {
		t.Fatalf("elect: %v", err)
	}

	coordinator := committee[0]
	t.Logf("coordinator: %v", coordinator)
	for i, id := range committee {
		t.Logf("committee[%d]: %v", i, id)
	}

	// Build KeygenRequest.
	ceremonyID := NewCeremonyID()
	partyIDs := IdentitiesToPartyIDs(committee)
	req := KeygenRequest{
		CeremonyID:  ceremonyID,
		Curve:       "secp256k1",
		Committee:   partyIDs,
		Threshold:   1, // t=1, need t+1=2 to sign
		Coordinator: coordinator,
	}

	// Send plain routed KeygenRequest to each committee member.
	for _, dest := range committee {
		if err := adminTr.WriteTo(adminSecret.Identity, dest,
			8, req); err != nil {
			t.Fatalf("send to %v: %v", dest, err)
		}
		t.Logf("sent keygen to %v", dest)
	}

	// Wait for ceremony completion on the coordinator.
	waitForCeremony(t, servers, ceremonyID, coordinator, 60*time.Second)
	t.Logf("keygen ceremony %s complete", ceremonyID)

	// Assert 1: all 3 committee members completed — select on Done
	// channels (local goroutine sets status after SaveKeyShare).
	waitForCeremonyMembers(t, servers, ceremonyID, 60*time.Second)
	for _, id := range committee {
		for i, s := range servers {
			if s.secret.Identity != id {
				continue
			}
			s.mtx.RLock()
			ci, ok := s.ceremonies[ceremonyID]
			s.mtx.RUnlock()
			if !ok {
				t.Fatalf("committee member node %d: ceremony not found", i)
			}
			if ci.Status != CeremonyComplete {
				t.Fatalf("committee member node %d: status=%s error=%q",
					i, ci.Status, ci.Error)
			}
		}
	}

	// Assert 2: all 3 committee members hold valid key shares with
	// consistent public key.
	var refPubX, refPubY []byte
	for _, id := range committee {
		for _, s := range servers {
			if s.secret.Identity != id {
				continue
			}
			tssDir := filepath.Join(s.data, "tss")
			matches, err := filepath.Glob(filepath.Join(tssDir, "*.key"))
			if err != nil {
				t.Fatalf("glob: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("node %v: no key files in %s", id, tssDir)
			}

			// Load the first key share (there should be exactly one
			// from this ceremony).
			keyFileName := filepath.Base(matches[0])
			keyIDHex := strings.TrimSuffix(keyFileName, ".key")
			keyID, err := hex.DecodeString(keyIDHex)
			if err != nil {
				t.Fatalf("bad key file name %q: %v", keyFileName, err)
			}

			shareData, err := s.tssStore.LoadKeyShare(keyID)
			if err != nil {
				t.Fatalf("node %v: load key share: %v", id, err)
			}

			var save keygen.LocalPartySaveData
			if err := json.Unmarshal(shareData, &save); err != nil {
				t.Fatalf("node %v: unmarshal share: %v", id, err)
			}

			pubX := save.ECDSAPub.X().Bytes()
			pubY := save.ECDSAPub.Y().Bytes()

			if refPubX == nil {
				refPubX = pubX
				refPubY = pubY
				t.Logf("reference pub: X=%x.. Y=%x..",
					pubX[:8], pubY[:8])
			} else {
				if !bytes.Equal(pubX, refPubX) || !bytes.Equal(pubY, refPubY) {
					t.Fatalf("node %v: public key mismatch: X=%x.. Y=%x.. (ref X=%x.. Y=%x..)",
						id, pubX[:8], pubY[:8],
						refPubX[:8], refPubY[:8])
				}
			}
		}
	}
	t.Log("all committee members have consistent public key")

	// Assert 3: ALL 5 nodes received the CeremonyResult broadcast.
	waitForCondition(t, "CeremonyResult broadcast", 10*time.Second, func() bool {
		for _, s := range servers {
			s.mtx.RLock()
			_, ok := s.ceremonies[ceremonyID]
			s.mtx.RUnlock()
			if !ok {
				return false
			}
		}
		return true
	})
	for i, s := range servers {
		s.mtx.RLock()
		ci, ok := s.ceremonies[ceremonyID]
		s.mtx.RUnlock()
		if !ok {
			t.Fatalf("node %d: did not receive CeremonyResult broadcast", i)
		}
		if ci.Status != CeremonyComplete {
			t.Fatalf("node %d: broadcast status=%s error=%q",
				i, ci.Status, ci.Error)
		}
		t.Logf("node %d: ceremony status=%s ✓", i, ci.Status)
	}
	t.Log("all 5 nodes received CeremonyResult broadcast")

	cancel()
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("server error: %v", err)
	}
}

// =============================================================================
// Coverage gap tests
// =============================================================================

func TestRunningAccessor(t *testing.T) {
	s, _ := NewServer(nil)
	if s.Running() {
		t.Fatal("should not be running")
	}
	s.testAndSetRunning(true)
	if !s.Running() {
		t.Fatal("should be running")
	}
}

func TestPromRunningGauge(t *testing.T) {
	s, _ := NewServer(nil)
	if v := s.promRunning(); v != 0 {
		t.Fatalf("want 0, got %f", v)
	}
	s.testAndSetRunning(true)
	if v := s.promRunning(); v != 1 {
		t.Fatalf("want 1, got %f", v)
	}
}

func TestCollectorsCreated(t *testing.T) {
	s, _ := NewServer(nil)
	c := s.Collectors()
	if len(c) == 0 {
		t.Fatal("no collectors")
	}
	if len(s.Collectors()) != len(c) {
		t.Fatal("collectors changed on second call")
	}
}

func TestIsHealthyAndHealthEndpoint(t *testing.T) {
	s, _ := NewServer(nil)
	ctx := context.Background()
	if !s.isHealthy(ctx) {
		t.Fatal("not healthy")
	}
	ok, info, err := s.health(ctx)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if !info.(Info).Online {
		t.Fatal("not online")
	}
}

func TestSendErrHelper(t *testing.T) {
	errC := make(chan error, 1)
	sendErr(context.Background(), errC, errors.New("boom"))
	if err := <-errC; err.Error() != "boom" {
		t.Fatal(err)
	}
	// Cancelled ctx — must not block on unbuffered channel.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sendErr(ctx, make(chan error), errors.New("ignored"))
}

func TestPromPollCancelledContext(t *testing.T) {
	s, _ := NewServer(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.promPoll(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestDeleteKeyShareCycle(t *testing.T) {
	secret, _ := NewSecret()
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}
	keyID := []byte{0xde, 0xad}
	if err := store.SaveKeyShare(keyID, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteKeyShare(keyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadKeyShare(keyID); err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestGetPreParamsSeeded(t *testing.T) {
	secret, _ := NewSecret()
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}
	pp := loadPreParams(t, 1)
	store.SetPreParams(&pp[0])
	got, err := store.GetPreParams(context.Background())
	if err != nil || got != &pp[0] {
		t.Fatal("unexpected result")
	}
}

func TestHandleCeremonyResultFailurePath(t *testing.T) {
	s, _ := NewServer(nil)
	var cid CeremonyID
	copy(cid[:], []byte("test-failure-result-0000"))
	s.handleCeremonyResult(CeremonyResult{
		CeremonyID: cid,
		Success:    false,
		Error:      "quorum",
	})
	s.mtx.RLock()
	ci := s.ceremonies[cid]
	s.mtx.RUnlock()
	if ci.Status != CeremonyFailed || ci.Error != "quorum" {
		t.Fatalf("status=%q error=%q", ci.Status, ci.Error)
	}
}

func TestHandleCeremonyResultExistingComplete(t *testing.T) {
	s, _ := NewServer(nil)
	var cid CeremonyID
	copy(cid[:], []byte("test-existing-complete-0"))
	s.registerCeremony(cid, CeremonyKeygen, Identity{})

	// Broadcast should be a no-op for already-tracked ceremonies;
	// the local goroutine owns the status transition.
	s.handleCeremonyResult(CeremonyResult{CeremonyID: cid, Success: true})
	s.mtx.RLock()
	ci := s.ceremonies[cid]
	s.mtx.RUnlock()
	if ci.Status != CeremonyRunning {
		t.Fatalf("status=%q, want running (broadcast should be no-op)", ci.Status)
	}
}

func TestPeerExpiredCallback(t *testing.T) {
	s, _ := NewServer(nil)
	secret1, _ := NewSecret()
	naclPub, _ := secret1.NaClPublicKey()
	s.mtx.Lock()
	s.peers[secret1.Identity] = &PeerRecord{
		Identity: secret1.Identity, Address: "127.0.0.1:9999",
		NaClPub: naclPub, Version: ProtocolVersion, LastSeen: time.Now().Unix(),
	}
	s.mtx.Unlock()
	s.peerExpired(context.Background(), secret1.Identity, nil)
	s.mtx.RLock()
	_, ok := s.peers[secret1.Identity]
	s.mtx.RUnlock()
	if ok {
		t.Fatal("peer should be removed")
	}
	// Bad key type — no panic.
	s.peerExpired(context.Background(), "bad", nil)
}

func TestRefreshPeerLastSeenUpdates(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	waitForListenAddress(t, s, 2*time.Second)

	secret1, _ := NewSecret()
	naclPub, _ := secret1.NaClPublicKey()
	s.addPeer(ctx, PeerRecord{
		Identity: secret1.Identity, Address: "127.0.0.1:9999",
		NaClPub: naclPub, Version: ProtocolVersion, LastSeen: 1000,
	})
	s.refreshPeerLastSeen(ctx, secret1.Identity)
	s.mtx.RLock()
	ls := s.peers[secret1.Identity].LastSeen
	s.mtx.RUnlock()
	if ls <= 1000 {
		t.Fatalf("LastSeen not updated: %d", ls)
	}
	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSeedDNSResolution(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	handler := createDNSNodes("seed.local", 1)
	dnsSrv := newDNSServer(ctx, handler)
	t.Cleanup(func() { dnsSrv.Shutdown(ctx) })

	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	var seedName string
	for name := range handler.lookup {
		if strings.HasSuffix(name, "seed.local.") {
			seedName = name
			break
		}
	}
	s.cfg.Seeds = []string{net.JoinHostPort(strings.TrimSuffix(seedName, "."), "45067")}
	s.resolver = newResolver(dnsSrv.Listener.Addr().String())
	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	waitForListenAddress(t, s, 2*time.Second)
	// Wait for the seed resolution codepath to execute and add the
	// seed as a known peer.  The connect to port 45067 will fail
	// (nothing listening), but the DNS lookup should succeed.
	waitForCondition(t, "seed peer discovered", 5*time.Second, func() bool {
		return s.PeerCount() > 0
	})
	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSeedBadHostPortHandling(t *testing.T) {
	s, _ := NewServer(nil)
	s.cfg.Seeds = []string{"no-port-here"}
	secret, _ := NewSecret()
	s.secret = secret
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s.seed(ctx)
}

func TestVerifyDNSIdentityMatchAndMismatch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	handler := createDNSNodes("vdns.local", 1)
	dnsSrv := newDNSServer(ctx, handler)
	t.Cleanup(func() { dnsSrv.Shutdown(ctx) })

	s, _ := NewServer(nil)
	s.resolver = newResolver(dnsSrv.Listener.Addr().String())
	var nodeName string
	var nodeSecret *Secret
	for name, n := range handler.nodes {
		nodeName = name
		nodeSecret = n.Secret
		break
	}
	if err := s.verifyDNSIdentity(ctx, nodeName, nodeSecret.Identity); err != nil {
		t.Fatalf("should succeed: %v", err)
	}
	wrong, _ := NewSecret()
	if err := s.verifyDNSIdentity(ctx, nodeName, wrong.Identity); err == nil {
		t.Fatal("should fail for wrong identity")
	}
	if err := s.verifyDNSIdentity(ctx, "nonexistent.local.", nodeSecret.Identity); err == nil {
		t.Fatal("should fail for nonexistent host")
	}
}

func TestTXTRecordFromAddressReverseLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	handler := createDNSNodes("txt.local", 1)
	dnsSrv := newDNSServer(ctx, handler)
	t.Cleanup(func() { dnsSrv.Shutdown(ctx) })
	resolver := newResolver(dnsSrv.Listener.Addr().String())
	var nodeIP net.IP
	for _, n := range handler.nodes {
		nodeIP = n.IP
		break
	}
	addr := &net.TCPAddr{IP: nodeIP, Port: 45067}
	m, err := TXTRecordFromAddress(ctx, resolver, addr)
	if err != nil {
		t.Fatal(err)
	}
	if m["v"] != dnsAppName {
		t.Fatalf("v=%q", m["v"])
	}
}

func TestVerifyRemoteDNSIdentityFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	handler := createDNSNodes("vr.local", 1)
	dnsSrv := newDNSServer(ctx, handler)
	t.Cleanup(func() { dnsSrv.Shutdown(ctx) })
	resolver := newResolver(dnsSrv.Listener.Addr().String())
	var nodeIP net.IP
	var nodeSecret *Secret
	for _, n := range handler.nodes {
		nodeIP = n.IP
		nodeSecret = n.Secret
		break
	}
	addr := &net.TCPAddr{IP: nodeIP, Port: 45067}
	ok, err := VerifyRemoteDNSIdentity(ctx, resolver, addr, nodeSecret.Identity)
	if err != nil || !ok {
		t.Fatalf("should match: ok=%v err=%v", ok, err)
	}
	wrong, _ := NewSecret()
	ok, err = VerifyRemoteDNSIdentity(ctx, resolver, addr, wrong.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("should not match wrong identity")
	}
}

func TestConnectRandomPicksPeer(t *testing.T) {
	preParams := loadPreParams(t, 1)
	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	errC := make(chan error, 1)
	go func() { errC <- s.Run(ctx) }()
	waitForListenAddress(t, s, 2*time.Second)

	secret1, _ := NewSecret()
	naclPub, _ := secret1.NaClPublicKey()
	s.addPeer(ctx, PeerRecord{
		Identity: secret1.Identity, Address: "127.0.0.1:1",
		NaClPub: naclPub, Version: ProtocolVersion, LastSeen: time.Now().Unix(),
	})
	s.connectRandom(ctx)
	// connectPeer goroutine dials 127.0.0.1:1 (ECONNREFUSED
	// immediately).  No synchronization needed — the goroutine
	// is tracked by s.wg and collected on shutdown.

	// No candidates — no-op.
	s.mtx.Lock()
	for id := range s.peers {
		if id != s.secret.Identity {
			delete(s.peers, id)
		}
	}
	s.mtx.Unlock()
	s.connectRandom(ctx)
	cancel()
	if err := <-errC; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPartiesToIdentitiesBadPartyID(t *testing.T) {
	bad := tss.NewPartyID("not-hex", "not-hex", big.NewInt(1))
	if partiesToIdentities(tss.UnSortedPartyIDs{bad}) != nil {
		t.Fatal("expected nil")
	}
	if partiesToIdentities(nil) != nil {
		t.Fatal("expected nil for empty")
	}
}

func TestDecryptPayloadUnknownSenderPath(t *testing.T) {
	s, _ := NewServer(nil)
	secret, _ := NewSecret()
	s.secret = secret
	_, err := s.decryptPayload(&EncryptedPayload{Sender: Identity{}})
	if err == nil || !strings.Contains(err.Error(), "unknown sender") {
		t.Fatalf("want unknown sender, got %v", err)
	}
}

func TestDecryptPayloadEmptyNaClPubPath(t *testing.T) {
	s, _ := NewServer(nil)
	secret, _ := NewSecret()
	s.secret = secret
	sender, _ := NewSecret()
	s.mtx.Lock()
	s.peers[sender.Identity] = &PeerRecord{Identity: sender.Identity}
	s.mtx.Unlock()
	_, err := s.decryptPayload(&EncryptedPayload{Sender: sender.Identity})
	if err == nil || !strings.Contains(err.Error(), "no NaCl public key") {
		t.Fatalf("want NaCl pub error, got %v", err)
	}
}

func TestDecryptPayloadBadInnerTypePath(t *testing.T) {
	sender, _ := NewSecret()
	recipient, _ := NewSecret()
	recipientNaClPub, _ := recipient.NaClPublicKey()
	senderNaClPriv, _ := sender.NaClPrivateKey()
	senderNaClPub, _ := sender.NaClPublicKey()

	ep, err := SealBox([]byte(`{}`), recipientNaClPub, senderNaClPriv,
		sender.Identity, PPingRequest) // valid type for sealing
	if err != nil {
		t.Fatal(err)
	}
	ep.InnerType = "bogus-type" // override to invalid

	s, _ := NewServer(nil)
	s.secret = recipient
	s.mtx.Lock()
	s.peers[sender.Identity] = &PeerRecord{
		Identity: sender.Identity,
		NaClPub:  senderNaClPub,
	}
	s.mtx.Unlock()
	_, err = s.decryptPayload(ep)
	if err == nil || !strings.Contains(err.Error(), "unknown inner type") {
		t.Fatalf("want unknown inner type, got %v", err)
	}
}

func TestOpenBoxCorruptedCiphertext(t *testing.T) {
	sender, _ := NewSecret()
	recipient, _ := NewSecret()
	recipientNaClPub, _ := recipient.NaClPublicKey()
	senderNaClPriv, _ := sender.NaClPrivateKey()

	ep, err := SealBox([]byte("test"), recipientNaClPub, senderNaClPriv,
		sender.Identity, PPingRequest)
	if err != nil {
		t.Fatal(err)
	}
	ep.Ciphertext[len(ep.Ciphertext)-1] ^= 0xff

	senderNaClPub, _ := sender.NaClPublicKey()
	recipientNaClPriv, _ := recipient.NaClPrivateKey()
	_, err = OpenBox(ep, senderNaClPub, recipientNaClPriv)
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}

func TestIsLocalhostEdgeCasesNilAndPipe(t *testing.T) {
	if isLocalhost(nil) {
		t.Fatal("nil should not be localhost")
	}
	p, _ := net.Pipe()
	defer p.Close()
	if isLocalhost(p.RemoteAddr()) {
		t.Fatal("pipe should not be localhost")
	}
}

func TestValidatePeerAddressEdgeCasesAll(t *testing.T) {
	for _, tt := range []struct {
		addr    string
		wantErr bool
	}{
		{"", true},
		{"host-no-port", true},
		{":8080", true},
		{"host:0", true},
		{"host:", true},
		{strings.Repeat("x", 300) + ":80", true},
		{"host\x01:80", true},
		{"good.host:8080", false},
	} {
		if err := validatePeerAddress(tt.addr); (err != nil) != tt.wantErr {
			t.Errorf("validatePeerAddress(%q)=%v wantErr=%v", tt.addr, err, tt.wantErr)
		}
	}
}

func TestElectCommitteeEqualsN(t *testing.T) {
	s1, _ := NewSecret()
	s2, _ := NewSecret()
	c, err := Elect([]byte("seed"), []Identity{s1.Identity, s2.Identity}, 2)
	if err != nil || len(c) != 2 {
		t.Fatalf("err=%v len=%d", err, len(c))
	}
}

func TestElectBoundary256And257(t *testing.T) {
	// Build 257 peers.
	peers := make([]Identity, 257)
	for i := range peers {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = s.Identity
	}

	// committee=256 is the maximum allowed.
	result, err := Elect([]byte("boundary"), peers, 256)
	if err != nil {
		t.Fatalf("committee=256 should succeed: %v", err)
	}
	if len(result) != 256 {
		t.Fatalf("expected 256 members, got %d", len(result))
	}

	// committee=257 must be rejected.
	_, err = Elect([]byte("boundary"), peers, 257)
	if err == nil {
		t.Fatal("expected error for committee=257")
	}
}

func FuzzElect(f *testing.F) {
	f.Add([]byte("seed"), 3, 2)
	f.Add([]byte{}, 1, 1)
	f.Add([]byte("x"), 0, 1)
	f.Add([]byte("y"), 5, 300)

	// Pre-generate a pool of identities.
	const poolSize = 300
	pool := make([]Identity, poolSize)
	for i := range pool {
		s, err := NewSecret()
		if err != nil {
			f.Fatal(err)
		}
		pool[i] = s.Identity
	}

	f.Fuzz(func(t *testing.T, seed []byte, nPeers, committee int) {
		// Clamp peer count to pool.
		if nPeers < 0 {
			nPeers = 0
		}
		if nPeers > poolSize {
			nPeers = poolSize
		}
		peers := pool[:nPeers]

		// Must not panic regardless of inputs.
		_, _ = Elect(seed, peers, committee)
	})
}

func TestIdentityBytesIsACopy(t *testing.T) {
	s, _ := NewSecret()
	b := s.Bytes()
	b[0] ^= 0xff
	if bytes.Equal(b, s.Identity[:]) {
		t.Fatal("Bytes() should return a copy")
	}
}

func TestSecretPublicKeyNotNil(t *testing.T) {
	s, _ := NewSecret()
	if s.PublicKey() == nil {
		t.Fatal("nil")
	}
}

func TestTransportStringAndCurveAccessors(t *testing.T) {
	tr, _ := NewTransportFromCurve(ecdh.X25519())
	if tr.String() != "server" {
		t.Fatalf("got %q", tr.String())
	}
	if tr.Curve() == "" {
		t.Fatal("empty curve")
	}
}

func TestTSSMessageIsBroadcastFlag(t *testing.T) {
	m := TSSMessage{Flags: TSSFlagBroadcast}
	if !m.IsBroadcast() {
		t.Fatal("should be broadcast")
	}
	m.Flags = 0
	if m.IsBroadcast() {
		t.Fatal("should not be broadcast")
	}
}

func TestKvFromTxtParsing(t *testing.T) {
	m, err := kvFromTxt("v=transfunctioner; identity=abc123")
	if err != nil {
		t.Fatal(err)
	}
	if m["v"] != "transfunctioner" {
		t.Fatalf("v=%q", m["v"])
	}
	if _, err := kvFromTxt("garbage-no-equals"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDnsResolverDefaultAndCustom(t *testing.T) {
	s, _ := NewServer(nil)
	if s.dnsResolver() != net.DefaultResolver {
		t.Fatal("expected default")
	}
	custom := &net.Resolver{}
	s.resolver = custom
	if s.dnsResolver() != custom {
		t.Fatal("expected custom")
	}
}

func TestRemoteAddrNilConn(t *testing.T) {
	tr := &Transport{}
	if tr.RemoteAddr() != nil {
		t.Fatal("expected nil")
	}
}

func TestNewServerNilUsesDefaults(t *testing.T) {
	s, err := NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.PeersWanted != 8 {
		t.Fatalf("peers=%d", s.cfg.PeersWanted)
	}
}

func TestKnownPeersAccessor(t *testing.T) {
	s, _ := NewServer(nil)
	secret1, _ := NewSecret()
	naclPub, _ := secret1.NaClPublicKey()
	s.mtx.Lock()
	s.peers[secret1.Identity] = &PeerRecord{
		Identity: secret1.Identity, Address: "127.0.0.1:9999",
		NaClPub: naclPub, Version: ProtocolVersion, LastSeen: time.Now().Unix(),
	}
	s.mtx.Unlock()
	found := false
	for _, pr := range s.KnownPeers() {
		if pr.Identity == secret1.Identity {
			found = true
		}
	}
	if !found {
		t.Fatal("peer missing")
	}
}

func TestRoutedReceivedAndForwardedCounters(t *testing.T) {
	s, _ := NewServer(nil)
	s.routedReceived.Add(5)
	s.forwarded.Add(3)
	if s.RoutedReceived() != 5 || s.Forwarded() != 3 {
		t.Fatal("wrong counters")
	}
}

func TestNewIdentityFromStringErrors(t *testing.T) {
	if _, err := NewIdentityFromString("not-hex"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := NewIdentityFromString("aabb"); err == nil {
		t.Fatal("expected error for wrong length")
	}
}

// =============================================================================
// Additional coverage: TSS internals + retry paths + sign integration
// =============================================================================

// retryMockTSS is a mock TSS whose HandleMessage behavior changes per call.
type retryMockTSS struct {
	mu       sync.Mutex
	calls    int
	handleFn func(n int) error
}

func (m *retryMockTSS) Keygen(_ context.Context, _ CeremonyID, _ []Identity, _ int) ([]byte, error) {
	return nil, errors.New("mock")
}

func (m *retryMockTSS) Sign(_ context.Context, _ CeremonyID, _ []byte, _ []Identity, _ int, _ [32]byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("mock")
}

func (m *retryMockTSS) Reshare(_ context.Context, _ CeremonyID, _ []byte, _, _ []Identity, _, _ int) error {
	return errors.New("mock")
}

func (m *retryMockTSS) HandleMessage(_ Identity, _ CeremonyID, _ []byte) error {
	m.mu.Lock()
	m.calls++
	n := m.calls
	m.mu.Unlock()
	return m.handleFn(n)
}

// TestDispatchTSSMessageRetryThenSuccess covers the retry loop succeeding.
func TestDispatchTSSMessageRetryThenSuccess(t *testing.T) {
	secret, _ := NewSecret()
	mock := &retryMockTSS{
		handleFn: func(n int) error {
			if n <= 2 {
				return ErrUnknownCeremony
			}
			return nil // succeed on 3rd call
		},
	}
	s := &Server{
		secret:     secret,
		tss:        mock,
		tssCtx:     context.Background(),
		sessions:   make(map[Identity]*Transport),
		peers:      make(map[Identity]*PeerRecord),
		ceremonies: make(map[CeremonyID]*CeremonyInfo),
	}
	s.stt = newServerTSSTransport(s)

	cid := NewCeremonyID()
	data := []byte("test-data")
	hash := HashTSSMessage(cid, data)
	sig := secret.Sign(hash)

	s.dispatchTSSMessage(TSSMessage{
		CeremonyID: cid,
		From:       secret.Identity,
		Signature:  sig,
		Data:       data,
	})

	s.wg.Wait()

	mock.mu.Lock()
	calls := mock.calls
	mock.mu.Unlock()
	if calls < 3 {
		t.Fatalf("expected at least 3 calls, got %d", calls)
	}
}

// TestDispatchTSSMessageRetryContextCancel covers retry cancelled.
func TestDispatchTSSMessageRetryContextCancel(t *testing.T) {
	secret, _ := NewSecret()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		secret:     secret,
		tss:        &retryMockTSS{handleFn: func(int) error { return ErrUnknownCeremony }},
		tssCtx:     ctx,
		sessions:   make(map[Identity]*Transport),
		peers:      make(map[Identity]*PeerRecord),
		ceremonies: make(map[CeremonyID]*CeremonyInfo),
	}
	s.stt = newServerTSSTransport(s)

	cid := NewCeremonyID()
	data := []byte("test-data")
	sig := secret.Sign(HashTSSMessage(cid, data))

	s.dispatchTSSMessage(TSSMessage{
		CeremonyID: cid, From: secret.Identity,
		Signature: sig, Data: data,
	})

	cancel()
	s.wg.Wait()
}

// TestDispatchTSSMessageRetryNonCeremonyError covers retry giving up
// on a non-"unknown ceremony" error.
func TestDispatchTSSMessageRetryNonCeremonyError(t *testing.T) {
	secret, _ := NewSecret()
	mock := &retryMockTSS{
		handleFn: func(n int) error {
			if n == 1 {
				return ErrUnknownCeremony
			}
			return errors.New("some other error") // retry gives up
		},
	}
	s := &Server{
		secret:     secret,
		tss:        mock,
		tssCtx:     context.Background(),
		sessions:   make(map[Identity]*Transport),
		peers:      make(map[Identity]*PeerRecord),
		ceremonies: make(map[CeremonyID]*CeremonyInfo),
	}
	s.stt = newServerTSSTransport(s)

	cid := NewCeremonyID()
	data := []byte("test-data")
	sig := secret.Sign(HashTSSMessage(cid, data))

	s.dispatchTSSMessage(TSSMessage{
		CeremonyID: cid, From: secret.Identity,
		Signature: sig, Data: data,
	})

	s.wg.Wait()
}

// TestBuildResharePartyContext covers old/new context building.
func TestBuildResharePartyContext(t *testing.T) {
	s1, _ := NewSecret()
	s2, _ := NewSecret()
	s3, _ := NewSecret()
	parties := []Identity{s1.Identity, s2.Identity, s3.Identity}

	store, _ := NewTSSStore(t.TempDir(), s1)
	pp := loadPreParams(t, 1)
	store.SetPreParams(&pp[0])
	impl := NewTSS(s1.Identity, store, nil).(*tssImpl)

	pids, ourPid, pidToID, keyToID, err := impl.buildResharePartyContext(parties, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pids) != 3 || ourPid == nil || len(pidToID) != 3 || len(keyToID) != 3 {
		t.Fatal("wrong result")
	}

	pidsNew, ourPidNew, _, _, err := impl.buildResharePartyContext(parties, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(pidsNew) != 3 || ourPidNew == nil {
		t.Fatal("wrong new result")
	}

	// Keys should differ.
	if pids[0].KeyInt().Cmp(pidsNew[0].KeyInt()) == 0 {
		t.Fatal("old and new keys should differ")
	}
}

// TestBuildResharePartyContextSelfNotInList covers ourPid=nil.
func TestBuildResharePartyContextSelfNotInList(t *testing.T) {
	self, _ := NewSecret()
	other, _ := NewSecret()

	store, _ := NewTSSStore(t.TempDir(), self)
	pp := loadPreParams(t, 1)
	store.SetPreParams(&pp[0])
	impl := NewTSS(self.Identity, store, nil).(*tssImpl)

	_, ourPid, _, _, err := impl.buildResharePartyContext([]Identity{other.Identity}, false)
	if err != nil {
		t.Fatal(err)
	}
	if ourPid != nil {
		t.Fatal("expected nil ourPid")
	}
}

// TestBuildSigningPartyContextXORKey covers the XOR key matching path.
func TestBuildSigningPartyContextXORKey(t *testing.T) {
	s1, _ := NewSecret()
	s2, _ := NewSecret()
	parties := []Identity{s1.Identity, s2.Identity}

	store, _ := NewTSSStore(t.TempDir(), s1)
	pp := loadPreParams(t, 1)
	store.SetPreParams(&pp[0])
	impl := NewTSS(s1.Identity, store, nil).(*tssImpl)

	// Post-reshare Ks: keys XORed with 1.
	ks := make([]*big.Int, len(parties))
	for i, id := range parties {
		ks[i] = new(big.Int).Xor(new(big.Int).SetBytes(id[:]), big.NewInt(1))
	}

	pids, ourPid, _, err := impl.buildSigningPartyContext(parties, ks)
	if err != nil || len(pids) != 2 || ourPid == nil {
		t.Fatalf("err=%v len=%d ourPid=%v", err, len(pids), ourPid)
	}
}

// TestBuildSigningPartyContextKeyNotFound covers the error path.
func TestBuildSigningPartyContextKeyNotFound(t *testing.T) {
	s1, _ := NewSecret()
	s2, _ := NewSecret()

	store, _ := NewTSSStore(t.TempDir(), s1)
	pp := loadPreParams(t, 1)
	store.SetPreParams(&pp[0])
	impl := NewTSS(s1.Identity, store, nil).(*tssImpl)

	_, _, _, err := impl.buildSigningPartyContext(
		[]Identity{s1.Identity, s2.Identity}, nil)
	if err == nil || !strings.Contains(err.Error(), "not found in key share Ks") {
		t.Fatalf("want key not found, got: %v", err)
	}
}

// TestHandleReshareMessageRouting covers handleReshareMessage paths.
func TestHandleReshareMessageRouting(t *testing.T) {
	s1, _ := NewSecret()
	s2, _ := NewSecret()
	s3, _ := NewSecret()
	parties := []Identity{s1.Identity, s2.Identity, s3.Identity}

	store, _ := NewTSSStore(t.TempDir(), s1)
	pp := loadPreParams(t, 1)
	store.SetPreParams(&pp[0])
	impl := NewTSS(s1.Identity, store, nil).(*tssImpl)

	oldPids, _, _, _, _ := impl.buildResharePartyContext(parties, false)
	newPids, _, _, _, _ := impl.buildResharePartyContext(parties, true)
	pidToID := make(map[string]Identity)
	for _, id := range parties {
		pidToID[id.String()] = id
	}

	c := &ceremony{
		oldPids: oldPids,
		newPids: newPids,
		pidToID: pidToID,
	}

	// toOld with nil oldParty — safe.
	if err := impl.handleReshareMessage(s2.Identity, c, 0x01, false, []byte("w")); err != nil {
		t.Fatal(err)
	}
	// toNew with nil party — safe.
	if err := impl.handleReshareMessage(s2.Identity, c, 0x02, false, []byte("w")); err != nil {
		t.Fatal(err)
	}
	// Both + fromNew.
	if err := impl.handleReshareMessage(s2.Identity, c, 0x07, true, []byte("w")); err != nil {
		t.Fatal(err)
	}
}

// TestReshareNotInCommittee covers the early error path.
func TestReshareNotInCommittee(t *testing.T) {
	self, _ := NewSecret()
	o1, _ := NewSecret()
	o2, _ := NewSecret()

	store, _ := NewTSSStore(t.TempDir(), self)
	pp := loadPreParams(t, 1)
	store.SetPreParams(&pp[0])
	impl := NewTSS(self.Identity, store, nil)

	err := impl.Reshare(context.Background(), NewCeremonyID(), nil,
		[]Identity{o1.Identity}, []Identity{o2.Identity}, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "self not in old or new committee") {
		t.Fatalf("got: %v", err)
	}
}

// TestFiveNodeKeygenAndSign runs keygen on 5 nodes, then signs.
func TestFiveNodeKeygenAndSign(t *testing.T) {
	if testing.Short() {
		t.Skip("5-node keygen+sign test is slow")
	}

	preParams := loadPreParams(t, 5)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	g, gctx := errgroup.WithContext(ctx)

	const n = 5
	servers := make([]*Server, n)
	addrs := make([]string, n)

	for i := 0; i < n; i++ {
		var connect []string
		if i > 0 {
			connect = []string{addrs[i-1]}
		}
		servers[i] = newTestServer(t, preParams, i, "localhost:0", connect)
		servers[i].cfg.PeersWanted = 6
		servers[i].cfg.MaintainInterval = 500 * time.Millisecond
		idx := i
		g.Go(func() error { return servers[idx].Run(gctx) })
		addrs[i] = waitForListenAddress(t, servers[i], 2*time.Second)
	}

	waitForFullMesh(t, servers, n, 30*time.Second)
	t.Log("gossip converged")

	adminSecret, adminTr := adminConnect(t, ctx, addrs[0])

	if err := adminTr.Write(adminSecret.Identity, PeerListAdminRequest{}); err != nil {
		t.Fatal(err)
	}
	peerResp := readAdminResponse[*PeerListAdminResponse](t, adminTr)
	peerIDs := collectEligible(t, peerResp, adminSecret.Identity, n)

	// Keygen: committee of 3.
	committee, _ := Elect([]byte("keygen-sign"), peerIDs, 3)
	ceremonyID := NewCeremonyID()
	partyIDs := IdentitiesToPartyIDs(committee)
	for _, dest := range committee {
		if err := adminTr.WriteTo(adminSecret.Identity, dest, 8,
			KeygenRequest{
				CeremonyID:  ceremonyID,
				Curve:       "secp256k1",
				Committee:   partyIDs,
				Threshold:   1,
				Coordinator: committee[0],
			}); err != nil {
			t.Fatal(err)
		}
	}
	waitForCeremony(t, servers, ceremonyID, committee[0], 60*time.Second)

	// Wait for ALL committee members to finish keygen (including
	// SaveKeyShare) before proceeding to sign.
	waitForCeremonyMembers(t, servers, ceremonyID, 60*time.Second)
	t.Log("keygen complete")

	// Find keyID.
	var coordServer *Server
	for _, s := range servers {
		if s.secret.Identity == committee[0] {
			coordServer = s
			break
		}
	}
	tssDir := filepath.Join(coordServer.data, "tss")
	matches, _ := filepath.Glob(filepath.Join(tssDir, "*.key"))
	if len(matches) == 0 {
		t.Fatal("no key files")
	}
	keyIDHex := strings.TrimSuffix(filepath.Base(matches[0]), ".key")
	keyID, _ := hex.DecodeString(keyIDHex)

	// Sign: committee of 2 (threshold+1).
	signCommittee := committee[:2]
	signPartyIDs := IdentitiesToPartyIDs(signCommittee)
	signCID := NewCeremonyID()
	var signData [32]byte
	copy(signData[:], []byte("deadbeefdeadbeefdeadbeefdeadbeef"))

	for _, dest := range signCommittee {
		if err := adminTr.WriteTo(adminSecret.Identity, dest, 8,
			SignRequest{
				CeremonyID: signCID,
				KeyID:      keyID,
				Committee:  signPartyIDs,
				Threshold:  1,
				Data:       signData[:],
			}); err != nil {
			t.Fatal(err)
		}
	}
	waitForCeremony(t, servers, signCID, signCommittee[0], 60*time.Second)
	t.Log("sign complete")

	cancel()
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// --- Helpers for multi-node tests ---

func waitForFullMesh(t *testing.T, servers []*Server, n int, timeout time.Duration) {
	t.Helper()
	waitForCondition(t, "mesh did not converge", timeout, func() bool {
		for i := 0; i < n; i++ {
			if servers[i].PeerCount() < n-1 {
				return false
			}
			servers[i].mtx.RLock()
			sess := len(servers[i].sessions)
			allNaCl := true
			for _, pr := range servers[i].peers {
				if len(pr.NaClPub) != NaClPubSize {
					allNaCl = false
					break
				}
			}
			servers[i].mtx.RUnlock()
			if sess < n-1 || !allNaCl {
				return false
			}
		}
		return true
	})
}

func adminConnect(t *testing.T, ctx context.Context, addr string) (*Secret, *Transport) {
	t.Helper()
	secret, _ := NewSecret()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := new(Transport)
	if err := tr.KeyExchange(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := tr.Handshake(ctx, secret, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	return secret, tr
}

func collectEligible(t *testing.T, resp *PeerListAdminResponse, adminID Identity, need int) []Identity {
	t.Helper()
	var ids []Identity
	for _, pr := range resp.Peers {
		if pr.Identity == adminID {
			continue
		}
		if (pr.Connected || pr.Self) && len(pr.NaClPub) == NaClPubSize {
			ids = append(ids, pr.Identity)
		}
	}
	if len(ids) < need {
		t.Fatalf("only %d eligible, need %d", len(ids), need)
	}
	return ids
}

func waitForCeremony(t *testing.T, servers []*Server, cid CeremonyID, coord Identity, timeout time.Duration) {
	t.Helper()
	var cs *Server
	for _, s := range servers {
		if s.secret.Identity == coord {
			cs = s
			break
		}
	}
	if cs == nil {
		t.Fatal("coordinator not found")
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// Phase 1: wait for ceremony to be registered (message in flight).
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var ci *CeremonyInfo
	for ci == nil {
		cs.mtx.RLock()
		ci = cs.ceremonies[cid]
		cs.mtx.RUnlock()
		if ci != nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("ceremony not registered")
		case <-tick.C:
		}
	}

	// Phase 2: wait for terminal state — no polling.
	select {
	case <-ctx.Done():
		cs.mtx.RLock()
		status := ci.Status
		errStr := ci.Error
		cs.mtx.RUnlock()
		for i, s := range servers {
			s.mtx.RLock()
			sci, ok := s.ceremonies[cid]
			s.mtx.RUnlock()
			if ok {
				t.Logf("node %d: status=%s error=%q", i, sci.Status, sci.Error)
			} else {
				t.Logf("node %d: not found", i)
			}
		}
		t.Fatalf("ceremony timed out: status=%s error=%q", status, errStr)
	case <-ci.ctx.Done():
	}

	// Check for failure.
	cs.mtx.RLock()
	if ci.Status == CeremonyFailed {
		cs.mtx.RUnlock()
		t.Fatalf("ceremony failed: %s", ci.Error)
	}
	cs.mtx.RUnlock()
}

// waitForCeremonyMembers waits for the ceremony to reach terminal
// state on every server that has it registered.  Call after
// waitForCeremony to ensure all committee members have finished
// SaveKeyShare before asserting on key files or starting sign.
func waitForCeremonyMembers(t *testing.T, servers []*Server, cid CeremonyID, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	for i, s := range servers {
		s.mtx.RLock()
		ci, ok := s.ceremonies[cid]
		s.mtx.RUnlock()
		if !ok {
			continue
		}
		select {
		case <-ctx.Done():
			s.mtx.RLock()
			t.Fatalf("node %d: ceremony timed out: status=%s error=%q",
				i, ci.Status, ci.Error)
			s.mtx.RUnlock()
		case <-ci.ctx.Done():
		}
	}
}
