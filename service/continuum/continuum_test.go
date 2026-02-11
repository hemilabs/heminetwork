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
