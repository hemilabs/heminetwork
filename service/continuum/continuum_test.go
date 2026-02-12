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
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"

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
	got := s.addPeer(ctx, PeerRecord{
		Identity: s.Identity(),
		Address:  "10.0.0.1:9999",
		Version:  ProtocolVersion,
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

	// Give B time to attempt and fail.
	time.Sleep(500 * time.Millisecond)

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
	servers[0].cfg.PeersWanted = 1 // prevent autodial
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
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if servers[2].RoutedReceived() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if servers[2].RoutedReceived() == 0 {
		t.Fatal("C did not receive routed message")
	}
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
