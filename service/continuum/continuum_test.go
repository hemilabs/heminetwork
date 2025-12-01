// Copyright (c) 2025 Hemi Labs, Inc.
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
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

// seeds is a dns query with N ip addresses on the default port
// nodes are connected to by ip
// nodes must resolve in reverse to obtain security record
// seeds := lookup(seeds.hemi.xyz)
// for { lookup(seed); verify id+sig }

// var defaultSeeds

// DNS server listens on 127.0.2:5353
// seed1 -> node1, node2
// seed2 -> node3
// node1 127.0.0.101
// node2 127.0.0.102
// node3 127.0.0.103
// node4 127.0.0.104:50000 // non default port, only discoverable over p2p
// node5 127.0.0.105:50001 // non default port, only discoverable over p2p
//
// launch node2 first
// seed using dns, node1 fails node2 succeeds
// launch other nodes
//	they seed using seed1 or seed2
//	nodes connect to no more than 2 total nodes
// p2p node discovery commences when node4 and node5 join
// node3 disconnects (should we brodcast that?)

var (
	defaultPort = uint16(49152)
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
	// PrivateKey        *secp256k1.PrivateKey
	// PublicKey         *secp256k1.PublicKey
	// Identity
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
		port = " port=" + strconv.Itoa(int(n.Port))
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
				Txt: []string{"v=" + dnsAppName + " identity=" +
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

func newResolver(resolverAddress string, t *testing.T) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{
				Timeout: 10000 * time.Millisecond,
			}
			return d.DialContext(t.Context(), "tcp", resolverAddress)
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

func newDNSServer(address string, handler dns.Handler) *dns.Server {
	srv := &dns.Server{
		Addr:    address,
		Net:     "tcp",
		Handler: handler,
	}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
	return srv
}

func waitForDNSServer(address string, t *testing.T) {
	// All of this to replace a sleep!
	d := net.Dialer{}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		conn, err := d.DialContext(ctx, "tcp", address)
		if err == nil {
			err = conn.Close()
			if err != nil {
				t.Fatal(err)
			}
			break
		}

		if err.(*net.OpError).Err.(*os.SyscallError).Err == syscall.ECONNREFUSED {
			continue
		}
	}
}

//func TestDNSServer(t *testing.T) {
//	go func() {
//		handler := &dnsHandler{
//			lookup: make(map[string][]dns.RR),
//		}
//		n, err := createNode("node2", "moop.gfy", net.IPv4(111, 222, 0, 1), 9321)
//		if err != nil {
//			panic(err)
//		}
//		dnsf, dnsr := nodeToDNS(n)
//		handler.insertDNS(n, dnsf, dnsr)
//
//		newDNSServer("127.0.0.1:5353", handler)
//	}()
//	// time.Sleep(1 * time.Second)
//	// All of this to replace a sleep!
//	d := net.Dialer{}
//	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
//	defer cancel()
//	for {
//		conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:5353")
//		if err == nil {
//			err = conn.Close()
//			if err != nil {
//				t.Fatal(err)
//			}
//			break
//		}
//
//		if err.(*net.OpError).Err.(*os.SyscallError).Err == syscall.ECONNREFUSED {
//			continue
//		}
//	}
//
//	t.Logf("resolving")
//	r := &net.Resolver{
//		PreferGo: true,
//		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
//			d := net.Dialer{
//				Timeout: time.Millisecond * time.Duration(10000),
//			}
//			return d.DialContext(ctx, "tcp", "127.0.0.1:5353")
//		},
//	}
//	addr, err := r.LookupAddr(t.Context(), "111.222.0.1")
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Logf("%v", addr)
//
//	ip, err := r.LookupHost(t.Context(), "node2.moop.gfy.")
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Logf("%v", ip)
//
//	txtRecords, err := r.LookupTXT(t.Context(), "node2.moop.gfy.")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	for _, txt := range txtRecords {
//		t.Logf("%v", txt)
//	}
//}

// type Command struct {
// 	Tag         [4]byte
// 	PayloadHint [2]byte
// 	Sender      *Identity // Optional
// 	Receiver    *Identity // Optional
// 	Path        string    // XXX do we want this
// 	TTL         byte
// }

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

// Below this line should be all retained
func TestIdentity(t *testing.T) {
	s1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	var c1 [32]byte
	_, err = rand.Read(c1[:])
	if err != nil {
		t.Fatal(err)
	}

	var c2 [32]byte
	_, err = rand.Read(c2[:])
	if err != nil {
		t.Fatal(err)
	}

	sig1 := s1.Sign(c2[:])
	sig2 := s2.Sign(c1[:])

	rec1, err := Verify(c1[:], sig2)
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := Verify(c2[:], sig1)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("id1: %v", s1)
	t.Logf("id2: %v", s2)
	t.Logf("rec1: %v", NewIdentityFromPub(rec1))
	t.Logf("rec2: %v", NewIdentityFromPub(rec2))

	if s1.String() != NewIdentityFromPub(rec2).String() {
		t.Fatal("recovery failed in 1")
	}
	if s2.String() != NewIdentityFromPub(rec1).String() {
		t.Fatal("recovery failed in 2")
	}
}

// XXX this is racy. When one side receives a message
// sometimes it differs from what is sent, or
// perhaps is not properly decrypted.
//func TestTransportHandshake(t *testing.T) {
//	type testTableItem struct {
//		name                     string
//		serverCurve, clientCurve string
//		expectedError            error
//	}
//	curves := []string{CurveP521, CurveP384, CurveP256, CurveX25519}
//	testTable := make([]testTableItem, 0, 20)
//	for _, us := range curves {
//		for _, them := range append(curves, "none") {
//			tti := testTableItem{
//				name:        fmt.Sprintf("%s - %s", us, them),
//				serverCurve: us,
//				clientCurve: them,
//			}
//			if them != "none" {
//				tti.expectedError = ErrMisbehavedClient
//			}
//			testTable = append(testTable, tti)
//		}
//	}
//	for _, tti := range testTable {
//		t.Run(tti.name, func(t *testing.T) {
//			server, err := NewTransportServer(tti.serverCurve, "")
//			if err != nil {
//				t.Fatal(err)
//			}
//			serverSecret, err := NewSecret()
//			if err != nil {
//				t.Fatal(err)
//			}
//			t.Logf("server: %v", serverSecret)
//
//			var client *Transport
//			if tti.clientCurve != "none" {
//				// this should fail
//				client, err = NewTransportServer(tti.clientCurve, "")
//			} else {
//				client, err = NewTransportClient("")
//			}
//			if err != nil {
//				t.Fatal(err)
//			}
//			clientSecret, err := NewSecret()
//			if err != nil {
//				t.Fatal(err)
//			}
//			t.Logf("client: %v", clientSecret)
//			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
//			defer cancel()
//			l := net.ListenConfig{}
//			listener, err := l.Listen(ctx, "tcp", ":0")
//			if err != nil {
//				t.Fatal(err)
//			}
//			defer listener.Close()
//			port := listener.Addr().(*net.TCPAddr).Port
//
//			var (
//				wg    sync.WaitGroup
//				msgCh = make(chan string)
//				errCh = make(chan error)
//			)
//			exchangeFunc := func(conn net.Conn, tr *Transport, us, them *Secret) error {
//				defer wg.Done()
//				if err := tr.KeyExchange(ctx, conn); err != nil {
//					return err
//				}
//				recovered, err := tr.Handshake(ctx, us)
//				if err != nil {
//					return err
//				}
//				if recovered.String() != them.String() {
//					return fmt.Errorf("recovered not equal got %v, want %v",
//						recovered, them)
//				}
//				return nil
//			}
//
//			wg.Add(2) // Wait for both key exchanges to complete
//
//			// client
//			go func() {
//				d := &net.Dialer{}
//				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1",
//					strconv.Itoa(port)))
//				if err != nil {
//					panic(err)
//				}
//				defer func() {
//					if err := client.Close(); err != nil {
//						return
//					}
//				}()
//				err = exchangeFunc(conn, client, clientSecret, serverSecret)
//				if err != nil {
//					t.Logf("client error: %v", err)
//					select {
//					case <-ctx.Done():
//						return
//					case errCh <- err:
//					}
//				}
//				select {
//				case <-ctx.Done():
//					return
//				case msgCh <- "done":
//				}
//			}()
//
//			// server
//			go func() {
//				conn, err := listener.Accept()
//				if err != nil {
//					panic(err)
//				}
//				defer func() {
//					if err := server.Close(); err != nil {
//						return
//					}
//				}()
//				err = exchangeFunc(conn, server, serverSecret, clientSecret)
//				if err != nil {
//					t.Logf("server error: %v", err)
//					select {
//					case <-ctx.Done():
//						return
//					case errCh <- err:
//					}
//				}
//				select {
//				case <-ctx.Done():
//					return
//				case msgCh <- "done":
//				}
//			}()
//
//			wg.Wait()
//			if server.encryptionKey != nil || client.encryptionKey != nil {
//				if !bytes.Equal(server.encryptionKey[:], client.encryptionKey[:]) {
//					t.Fatal(spew.Sdump(server.encryptionKey) + spew.Sdump(server.encryptionKey))
//				}
//			}
//
//			var (
//				done int
//				cerr error
//			)
//			for {
//				select {
//				case <-ctx.Done():
//					t.Fatal(ctx.Err())
//				case cerr = <-errCh:
//				case <-msgCh:
//					done++
//				}
//				if !errors.Is(cerr, tti.expectedError) {
//					t.Fatalf("expected error %v, got %v", tti.expectedError, cerr)
//				}
//				if done == 2 {
//					return
//				}
//			}
//		})
//	}
//}
//
//func TestMany(t *testing.T) {
//	// XXX remove once debugged
//	nodes := byte(2)
//	dnsAddress := "127.0.1.1:5353"
//	domain := "moop.gfy"
//	handler := createDNSNodes(domain, nodes)
//	go func() { newDNSServer(dnsAddress, handler) }()
//	waitForDNSServer(dnsAddress, t)
//	r := newResolver(dnsAddress, t)
//
//	for i := 0; i < 1111; i++ {
//		DNSTransportHandshake(r, handler, t)
//	}
//}
//
//func DNSTransportHandshake(r *net.Resolver, handler *dnsHandler, t *testing.T) {
//	// XXX remove once debugged
//	server, err := NewTransportServer(CurveX25519, "yes")
//	if err != nil {
//		t.Fatal(err)
//	}
//	server.resolver = r
//	node1 := handler.nodes["node1.moop.gfy."]
//	serverSecret := node1.Secret
//	t.Logf("server: %v", serverSecret)
//
//	client, err := NewTransportClient("yes")
//	if err != nil {
//		t.Fatal(err)
//	}
//	client.resolver = r
//	node2 := handler.nodes["node2.moop.gfy."]
//	clientSecret := node2.Secret
//	t.Logf("client: %v", clientSecret)
//
//	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
//	defer cancel()
//	l := net.ListenConfig{}
//	listener, err := l.Listen(ctx, "tcp", net.JoinHostPort(node1.IP.String(), "0"))
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer listener.Close()
//	port := listener.Addr().(*net.TCPAddr).Port
//	log.Infof("Listening: %v", node1.IP)
//
//	var (
//		wg    sync.WaitGroup
//		msgCh = make(chan string)
//		errCh = make(chan error)
//	)
//	exchangeFunc := func(conn net.Conn, tr *Transport, us, them *Secret) (*Identity, error) {
//		defer wg.Done()
//		if err := tr.KeyExchange(ctx, conn); err != nil {
//			return nil, err
//		}
//		recovered, err := tr.Handshake(ctx, us)
//		if err != nil {
//			return nil, err
//		}
//		if recovered.String() != them.String() {
//			return nil, fmt.Errorf("recovered not equal got %v, want %v",
//				recovered, them)
//		}
//		return recovered, nil
//	}
//
//	wg.Add(2) // Wait for both key exchanges to complete
//
//	// client
//	go func() {
//		// note that we connect to node1.
//		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(node2.IP.String(), "0"))
//		if err != nil {
//			panic(err)
//		}
//
//		d := &net.Dialer{
//			LocalAddr: addr,
//		}
//		conn, err := d.DialContext(ctx, "tcp",
//			net.JoinHostPort(node1.IP.String(), strconv.Itoa(port)))
//		if err != nil {
//			panic(err)
//		}
//		defer func() {
//			if err := client.Close(); err != nil {
//				panic(err)
//			}
//		}()
//		r, err := exchangeFunc(conn, client, clientSecret, serverSecret)
//		if err != nil {
//			t.Logf("client error: %v", err)
//			select {
//			case <-ctx.Done():
//				return
//			case errCh <- err:
//			}
//		}
//		t.Logf("client recovered: %v", r)
//		select {
//		case <-ctx.Done():
//			return
//		case msgCh <- "done":
//		}
//	}()
//
//	// server
//	go func() {
//		conn, err := listener.Accept()
//		if err != nil {
//			panic(err)
//		}
//		defer func() {
//			if err := server.Close(); err != nil {
//				panic(err)
//			}
//		}()
//		r, err := exchangeFunc(conn, server, serverSecret, clientSecret)
//		if err != nil {
//			t.Logf("server error: %v", err)
//			select {
//			case <-ctx.Done():
//				return
//			case errCh <- err:
//			}
//		}
//		t.Logf("server recovered: %v", r)
//		select {
//		case <-ctx.Done():
//			return
//		case msgCh <- "done":
//		}
//	}()
//
//	wg.Wait()
//	if server.encryptionKey != nil || client.encryptionKey != nil {
//		if !bytes.Equal(server.encryptionKey[:], client.encryptionKey[:]) {
//			t.Fatal(spew.Sdump(server.encryptionKey) + spew.Sdump(server.encryptionKey))
//		}
//	}
//
//	var done int
//	for {
//		select {
//		case <-ctx.Done():
//			t.Fatal(ctx.Err())
//		case err := <-errCh:
//			t.Fatal(err)
//		case <-msgCh:
//			done++
//		}
//		if done == 2 {
//			return
//		}
//	}
//}
//
//func TestDNSTransportHandshake(t *testing.T) {
//	nodes := byte(2)
//	dnsAddress := "127.0.1.1:5353"
//	domain := "moop.gfy"
//	handler := createDNSNodes(domain, nodes)
//	go func() { newDNSServer(dnsAddress, handler) }()
//	waitForDNSServer(dnsAddress, t)
//	r := newResolver(dnsAddress, t)
//
//	server, err := NewTransportServer(CurveX25519, "yes")
//	if err != nil {
//		t.Fatal(err)
//	}
//	server.resolver = r
//	node1 := handler.nodes["node1.moop.gfy."]
//	serverSecret := node1.Secret
//	t.Logf("server: %v", serverSecret)
//
//	client, err := NewTransportClient("yes")
//	if err != nil {
//		t.Fatal(err)
//	}
//	client.resolver = r
//	node2 := handler.nodes["node2.moop.gfy."]
//	clientSecret := node2.Secret
//	t.Logf("client: %v", clientSecret)
//
//	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
//	defer cancel()
//	l := net.ListenConfig{}
//	listener, err := l.Listen(ctx, "tcp", net.JoinHostPort(node1.IP.String(), "0"))
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer listener.Close()
//	port := listener.Addr().(*net.TCPAddr).Port
//	log.Infof("Listening: %v", node1.IP)
//
//	var (
//		wg    sync.WaitGroup
//		msgCh = make(chan string)
//		errCh = make(chan error)
//	)
//	exchangeFunc := func(conn net.Conn, tr *Transport, us, them *Secret) (*Identity, error) {
//		defer wg.Done()
//		if err := tr.KeyExchange(ctx, conn); err != nil {
//			return nil, err
//		}
//		recovered, err := tr.Handshake(ctx, us)
//		if err != nil {
//			return nil, err
//		}
//		if recovered.String() != them.String() {
//			return nil, fmt.Errorf("recovered not equal got %v, want %v",
//				recovered, them)
//		}
//		return recovered, nil
//	}
//
//	wg.Add(2) // Wait for both key exchanges to complete
//
//	// client
//	go func() {
//		// note that we connect to node1.
//		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(node2.IP.String(), "0"))
//		if err != nil {
//			panic(err)
//		}
//
//		d := &net.Dialer{
//			LocalAddr: addr,
//		}
//		conn, err := d.DialContext(ctx, "tcp",
//			net.JoinHostPort(node1.IP.String(), strconv.Itoa(port)))
//		if err != nil {
//			panic(err)
//		}
//		defer func() {
//			if err := client.Close(); err != nil {
//				return
//			}
//		}()
//		r, err := exchangeFunc(conn, client, clientSecret, serverSecret)
//		if err != nil {
//			t.Logf("client error: %v", err)
//			select {
//			case <-ctx.Done():
//				return
//			case errCh <- err:
//			}
//		}
//		t.Logf("client recovered: %v", r)
//		select {
//		case <-ctx.Done():
//			return
//		case msgCh <- "done":
//		}
//	}()
//
//	// server
//	go func() {
//		conn, err := listener.Accept()
//		if err != nil {
//			panic(err)
//		}
//		defer func() {
//			if err := server.Close(); err != nil {
//				return
//			}
//		}()
//		r, err := exchangeFunc(conn, server, serverSecret, clientSecret)
//		if err != nil {
//			t.Logf("server error: %v", err)
//			select {
//			case <-ctx.Done():
//				return
//			case errCh <- err:
//			}
//		}
//		t.Logf("server recovered: %v", r)
//		select {
//		case <-ctx.Done():
//			return
//		case msgCh <- "done":
//		}
//	}()
//
//	wg.Wait()
//	if server.encryptionKey != nil || client.encryptionKey != nil {
//		if !bytes.Equal(server.encryptionKey[:], client.encryptionKey[:]) {
//			t.Fatal(spew.Sdump(server.encryptionKey) + spew.Sdump(server.encryptionKey))
//		}
//	}
//
//	var done int
//	for {
//		select {
//		case <-ctx.Done():
//			t.Fatal(ctx.Err())
//		case err := <-errCh:
//			t.Fatal(err)
//		case <-msgCh:
//			done++
//		}
//		if done == 2 {
//			return
//		}
//	}
//}
//
//func TestDNSServerSetup(t *testing.T) {
//	nodes := byte(200)
//	dnsAddress := "127.0.0.1:5353"
//	domain := "moop.gfy"
//	handler := createDNSNodes(domain, nodes)
//	go func() { newDNSServer(dnsAddress, handler) }()
//	waitForDNSServer(dnsAddress, t)
//	r := newResolver(dnsAddress, t)
//
//	// Lookup all nodes
//	for k, v := range handler.nodes {
//		addr, err := r.LookupAddr(t.Context(), v.IP.String())
//		if err != nil {
//			t.Fatal(err)
//		}
//		// Verify reverse record
//		if v.DNSName != addr[0] {
//			t.Fatalf("got %v wanted %v", addr[0], v.DNSName)
//		}
//
//		ip, err := r.LookupHost(t.Context(), k)
//		if err != nil {
//			t.Fatal(err)
//		}
//		if ip[0] != v.IP.String() {
//			t.Fatalf("got %v wanted %v", ip[0], v.IP.String())
//		}
//
//		txtRecords, err := r.LookupTXT(t.Context(), k)
//		if err != nil {
//			t.Fatal(err)
//		}
//		txtExpected := fmt.Sprintf("v=%v identity=%v port=%v",
//			dnsAppName, v.Secret.Identity, defaultPort)
//		if txtRecords[0] != txtExpected {
//			t.Fatalf("got %v, wanted %v", txtRecords[0], txtExpected)
//		}
//
//		ok, err := DNSVerifyIdentityByIP(t.Context(), v.IP, v.Secret.Identity, r)
//		if err != nil {
//			t.Fatal(err)
//		}
//		if !ok {
//			t.Fatalf("not verified identity: %v", v.IP)
//		}
//	}
//}
//
//func TestKeyExchange(t *testing.T) {
//	var wg sync.WaitGroup
//
//	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
//	defer cancel()
//
//	// Server
//	l := net.ListenConfig{}
//	listener, err := l.Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", "0"))
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer listener.Close()
//	port := listener.Addr().(*net.TCPAddr).Port
//	server, err := NewTransportServer(CurveX25519, "")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	wg.Add(1)
//	go func() {
//		defer wg.Done()
//		t.Logf("Listening: %v", port)
//		conn, err := listener.Accept()
//		if err != nil {
//			panic(err)
//		}
//
//		if err := server.KeyExchange(ctx, conn); err != nil {
//			panic(err)
//		}
//	}()
//
//	// Client
//	addr, err := net.ResolveTCPAddr("tcp",
//		net.JoinHostPort("127.0.0.1", "0"))
//	if err != nil {
//		t.Fatal(err)
//	}
//	d := &net.Dialer{LocalAddr: addr}
//	cc, err := d.DialContext(ctx, "tcp",
//		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
//	if err != nil {
//		t.Fatal(err)
//	}
//	client, err := NewTransportClient("")
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer func() {
//		if err := client.Close(); err != nil {
//			panic(err)
//		}
//	}()
//
//	wg.Add(1)
//	go func(conn net.Conn) {
//		defer wg.Done()
//
//		if err := client.KeyExchange(ctx, conn); err != nil {
//			panic(err)
//		}
//	}(cc)
//
//	wg.Wait()
//
//	if server.encryptionKey != nil || client.encryptionKey != nil {
//		if !bytes.Equal(server.encryptionKey[:], client.encryptionKey[:]) {
//			t.Fatalf("%v%v", spew.Sdump(server.encryptionKey),
//				spew.Sdump(server.encryptionKey))
//		}
//	}
//}
