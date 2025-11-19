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
	"strconv"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
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
	defaultPort = "49152"
	// seed1       = "seed.bark.gfy."

	// wellKnownSeeds = []string{seed1}

	inAddrArpa = "in-addr.arpa"
	// node1A     = "node1.meow.gfy."
	// node1Ptr   = "101.0.0.127.in-addr.arpa."
	// node1Priv  = "0daf6bf4928ccf2d1e19400a4ab088c854a2d8de3bb11eac899137d0591405ad"
	// node1ID    = "33a10c33e612a491dd1de98aff56e875d70a48e1"

	// node2Priv = "632cc339c0e7961b65bf539604c0326083ccd69ab8d57483b41cae839b94a803"
	// node3Priv = "94379ce360385c925a5bcd029db541f6fd1b8ac78143dabeac2357c43a531540"
	// node4Priv = "f642dea0fc0627aceb6c371a9ebb242dd3c9a42ab59a760d9d2e2a692cc5e716"
	// node5Priv = "6d353152c25824f96df7ce55b2d3d85c0c1591ec2a3b195554e7055bcf78162f"
)

type node struct {
	DNSName           string
	ReverseDNSName    string
	ReverseDNSPtrName string
	IP                net.IP
	Port              uint16
	PrivateKey        *secp256k1.PrivateKey
	PublicKey         *secp256k1.PublicKey
	Identity          Identity
}

func createNode(name, domain string, ip net.IP, port uint16) (*node, error) {
	i := []byte(ip.To4())
	n := &node{
		DNSName: fmt.Sprintf("%v.%v.", name, domain),
		ReverseDNSName: fmt.Sprintf("%v.%v.%v.%v.%v.",
			i[3], i[2], i[1], i[0], inAddrArpa),
		ReverseDNSPtrName: fmt.Sprintf("%v-%v-%v-%v-%v.%v.",
			i[0], i[1], i[2], i[3], name, domain),
		IP:   ip,
		Port: port,
	}
	// panic(spew.Sdump(n.ReverseDNSPtrName))
	var err error
	n.PrivateKey, err = secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	n.PublicKey = n.PrivateKey.PubKey()
	n.Identity = NewIdentityFromPub(n.PublicKey)

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
				Txt: []string{"identity=" + n.Identity.String() + port},
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

//type Node struct {
//	Identity Identity // Identity
//	Name     string   // DNS name
//	Listen   string   // Listen adddress
//
//	private *secp256k1.PrivateKey // Private key
//	ip      net.IP                // DNS IP address
//}

// var domainsToAddresses map[string][]dns.RR = map[string][]dns.RR{
//seed1: {
//	&dns.A{
//		Hdr: dns.Header{
//			Name:  seed1,
//			Class: dns.ClassINET,
//		},
//		A: net.IPv4(127, 0, 0, 1),
//	},
//	&dns.AAAA{
//		Hdr: dns.Header{
//			Name:  seed1,
//			Class: dns.ClassINET,
//		},
//		AAAA: net.IPv6loopback,
//	},
//},
//node1R: {
//	&dns.A{
//		Hdr: dns.Header{
//			Name:  node1R,
//			Class: dns.ClassINET,
//		},
//		A: net.IPv4(127, 0, 0, 1),
//	},
//	&dns.TXT{
//		Hdr: dns.Header{
//			Name:  node1R,
//			Class: dns.ClassINET,
//		},
//		Txt: []string{"identity=" + node1 + " port=9999"},
//	},
//},
//node1A: {
//	&dns.A{
//		Hdr: dns.Header{
//			Name:  node1A,
//			Class: dns.ClassINET,
//		},
//		A: net.IPv4(127, 0, 0, 101),
//	},
//	&dns.TXT{
//		Hdr: dns.Header{
//			Name:  node1A,
//			Class: dns.ClassINET,
//		},
//		Txt: []string{"identity=" + node1ID + " port=9999"},
//	},
//},
//node1Ptr: {
//	&dns.PTR{
//		Hdr: dns.Header{
//			Name:  node1Ptr,
//			Class: dns.ClassINET,
//		},
//		Ptr: "127-0-0-101.meow.gfy.",
//	},
//},
//"node2.test.gfy.": "127.0.0.1",
//"node3.test.gfy.": "127.0.0.1",
//"node4.test.gfy.": "::1",
//"node5.test.gfy.": "::1",
//}

type dnsHandler struct {
	lookup map[string][]dns.RR
}

func (h *dnsHandler) insertDNS(n *node, forward, reverse []dns.RR) {
	h.lookup[n.DNSName] = forward
	h.lookup[n.ReverseDNSName] = reverse
}

func (h *dnsHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)

	rr, ok := h.lookup[m.Question[0].Header().Name]
	if ok {
		m.Answer = rr
	}
	io.Copy(w, m)
}

func newDNSServer(host string, port uint16, handler dns.Handler) *dns.Server {
	srv := &dns.Server{
		Addr:    net.JoinHostPort(host, strconv.Itoa(int(port))),
		Net:     "tcp",
		Handler: handler,
	}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
	return srv
}

func TestDNSServer(t *testing.T) {
	go func() {
		handler := &dnsHandler{
			lookup: make(map[string][]dns.RR),
		}
		n, err := createNode("node2", "moop.gfy", net.IPv4(111, 222, 0, 1), 9321)
		if err != nil {
			t.Fatal(err)
		}
		dnsf, dnsr := nodeToDNS(n)
		handler.insertDNS(n, dnsf, dnsr)

		newDNSServer("127.0.0.1", 5353, handler)
	}()
	time.Sleep(1 * time.Second)

	t.Logf("resolving")
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, "tcp", "127.0.0.1:5353")
		},
	}
	addr, err := r.LookupAddr(t.Context(), "111.222.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v", addr)

	ip, err := r.LookupHost(t.Context(), "node2.moop.gfy.")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v", ip)

	txtRecords, err := r.LookupTXT(t.Context(), "node2.moop.gfy.")
	if err != nil {
		t.Fatal(err)
	}

	for _, txt := range txtRecords {
		t.Logf("%v", txt)
	}
}

type Command struct {
	Tag         [4]byte
	PayloadHint [2]byte
	Sender      *Identity // Optional
	Receiver    *Identity // Optional
	Path        string    // XXX do we want this
	TTL         byte
}

//// Hello challenges the other side to sign the challenge.
//type Hello struct {
//	Identity  Identity                 `json:"identity"`
//	Challenge [chainhash.HashSize]byte // Challenge them
//}
//
//// HelloReply returns the signed response. The Identity of the other side can
//// be recovered fomr the challenge response.
//type HelloReply struct {
//	ChallengeResponse []byte
//}

func TestID(t *testing.T) {
	// Create DNS record with identity + ip + port
	// Client challenges Server with random(32)
	// Server signs challenge with privkey
	// Client recover pubkey from sig of challenge and verifies identity
	//
	// ID is a compressed pubkey
	//for i := 0; i < 5; i++ {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("secp256k1 %x", priv.Serialize())
	//}
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
	return
}

func TestECDHSecretBox(t *testing.T) {
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
	io.ReadFull(ek1R, ek1[:])

	var ek2 [32]byte
	ek2R := hkdf.New(sha256.New, secret2, nil, nil)
	io.ReadFull(ek2R, ek2[:])
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

func TestTransportHandshake(t *testing.T) {
	// XXX make this table driven and test all possible permutations.
	us, err := NewTransport("P521")
	if err != nil {
		t.Fatal(err)
	}
	usSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("us: %v", usSecret)

	them, err := NewTransport("P521")
	if err != nil {
		t.Fatal(err)
	}
	themSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("them: %v", themSecret)

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	ctx := context.TODO()
	var wg sync.WaitGroup
	wg.Add(2) // Wait for both key exchanges to complete
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				panic(err)
			}
		}()
		if err = them.KeyExchange(ctx, conn); err != nil {
			panic(err)
		}
		usRecovered, err := them.Handshake(ctx, themSecret)
		if err != nil {
			t.Fatal(err)
		}
		wg.Done()

		wg.Wait()
		if !bytes.Equal(us.encryptionKey[:], them.encryptionKey[:]) {
			panic(spew.Sdump(us.encryptionKey) + spew.Sdump(them.encryptionKey))
		}
		t.Logf("us recovered: %v", usRecovered)
		if usRecovered.String() != usSecret.String() {
			t.Fatalf("us recovered not equal got %v, want %v",
				usRecovered, usSecret)
		}
	}()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1",
		strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := us.KeyExchange(ctx, conn); err != nil {
		t.Fatal(err)
	}
	themRecovered, err := us.Handshake(ctx, usSecret)
	if err != nil {
		t.Fatal(err)
	}
	// spew.Dump(hr)
	wg.Done()

	wg.Wait()
	if !bytes.Equal(us.encryptionKey[:], them.encryptionKey[:]) {
		t.Fatal(spew.Sdump(us.encryptionKey) + spew.Sdump(them.encryptionKey))
	}
	t.Logf("them recovered: %v", themRecovered)
	if themRecovered.String() != themSecret.String() {
		t.Fatalf("them recovered not equal got %v, want %v",
			themRecovered, themSecret)
	}
	// XXX conn must go
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}
