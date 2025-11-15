package continuum

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/crypto/ripemd160"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
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
	n.Identity = IdentityFromPub(n.PublicKey)

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

func Hash160(data []byte) []byte {
	hash := chainhash.HashB(data)
	ripemd := ripemd160.New()
	ripemd.Write(hash[:])
	return ripemd.Sum(nil)
}

type Identity [ripemd160.Size]byte // ripemd160 of compressed pubkey

func (i Identity) String() string {
	return hex.EncodeToString(i[:])
}

func (i *Identity) UnmarshalJSON(data []byte) error {
	if len(data) != len(i) {
		return errors.New("invalid length")
	}
	copy(i[:], data)
	return nil
}

func IdentityFromPub(pub *secp256k1.PublicKey) Identity {
	id := Hash160(pub.SerializeCompressed())
	var i Identity
	copy(i[:], id)
	return i
}

type Command struct {
	Tag         [4]byte
	PayloadHint [2]byte
	Sender      *Identity // Optional
	Receiver    *Identity // Optional
	Path        string    // XXX do we want this
	TTL         byte
}

// Hello challenges the other side to sign the challenge.
type Hello struct {
	Identity  Identity                 `json:"identity"`
	Challenge [chainhash.HashSize]byte // Challenge them
}

// HelloReply returns the signed response. The Identity of the other side can
// be recovered fomr the challenge response.
type HelloReply struct {
	ChallengeResponse []byte
}

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
