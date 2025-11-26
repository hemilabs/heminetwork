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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/crypto/ripemd160"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

// XXX this needs to be rewritten to match new reality
//
// The continuum protocol is a simple gossipy P2P system.
//
// The continuum transfunctioner is a very mysterious and powerful device and
// it's mystery is exceeded only by it's power.
//
// Continuum runs directly on top of TCP and can run in the clear since it does
// it's own encryption. It is a streaming protocol that prefixes encrypted
// payloads with a size (that is capped). If the message is too large the
// receiver will drop the connection and potentially blacklist the caller.
//
// An envelope is constructed on the wire as: [size][payload]. Once an envelope
// is decrypted there are two distinct pieces, a header and a message or
// another envelope.  The header contains information akin to TCP and is used
// to route the envelope.  Anologous to wire protocol it is encoded with size
// prefixes followed by a payload, i.e. [[size][header] [size][envelope]]. A
// message is for the reader and an envelope should be routed to a third party.
//
// Size is encoded as a big endian 24 bit unsigned integer.

// Version
//	1:
//		Defaults to JSON encoding
//
// Options (default):
//	encoding=json
//	compression=no
//
// XXX describe the types a bit here and add a drawing if needed to tie it all together.

type PayloadType string

const (
	PHelloRequest  PayloadType = "hello"
	PHelloResponse PayloadType = "hello-response" // XXX does the linter allow this?
)

var (
	pt2str = map[reflect.Type]PayloadType{
		reflect.TypeOf(HelloRequest{}):  PHelloRequest,
		reflect.TypeOf(HelloResponse{}): PHelloResponse,
	}

	str2pt map[PayloadType]reflect.Type
)

func init() {
	// reverse pt2str map
	str2pt = make(map[PayloadType]reflect.Type, len(pt2str))
	for k, v := range pt2str {
		str2pt[v] = k
	}
}

type PayloadHash [32]byte

func (p PayloadHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(p[:]))
}

func (p *PayloadHash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(d) != len(p) {
		return fmt.Errorf("invalid length: %v", len(d))
	}
	copy(p[:], d)
	return nil
}

func (p PayloadHash) String() string {
	return hex.EncodeToString(p[:])
}

func NewPayloadHash(x []byte) *PayloadHash {
	p := PayloadHash(sha256.Sum256(x))
	return &p
}

func NewPayloadFromCommand(cmd any) (*PayloadHash, []byte, error) {
	jc, err := json.Marshal(cmd)
	if err != nil {
		return nil, nil, err
	}
	return NewPayloadHash(jc), jc, nil
}

type Header struct {
	PayloadType PayloadType `json:"payloadtype"`           // Hint to decode payload
	PayloadHash PayloadHash `json:"payloadhash"`           // Message identifier
	Origin      Identity    `json:"origin"`                // Origin identity
	Destination *Identity   `json:"destination,omitempty"` // Intended receiver
	TTL         uint8       `json:"ttl"`                   // Time To Live
	// Path        []Identity      // Record path when routing XXX ?
}

type HelloRequest struct {
	Version   uint32            `json:"version"`           // Version number
	Options   map[string]string `json:"options,omitempty"` // x=y
	Challenge []byte            `json:"challenge"`         // Random challenge, min 32 bytes
}

type HelloResponse struct {
	Signature []byte `json:"signature"` // Signature of Challenge and identity is derived
}

const (
	TransportVersion = 1

	ProtocolVersion = 1

	TransportNonceSize = 24         // 24 bytes, per secretbox
	TransportMaxSize   = 0x00ffffff // 24 bit, 3 bytes

	ChallengeSize = 32 // 32 bytes random data

	// Transport curves
	CurveP256   = "P256"
	CurveP384   = "P384"
	CurveP521   = "P521"
	CurveX25519 = "x25519"
	CurveClient = "none"

	dnsAppName = "transfunctioner"
)

var ZeroChallenge = [ChallengeSize]byte{} // All zeroes is invalid

type Nonce struct {
	counter atomic.Uint64
	key     [TransportNonceSize]byte
}

// Next returns the next nonce by atomically incrementing the nonce counter and
// then running an HMAC-SHA256 over the big endian encoding of it. Since sha256
// is 32 bytes and the nonce is 24 the bottom 8 bytes are clipped.
func (n *Nonce) Next() *[TransportNonceSize]byte {
	var (
		counter [8]byte
		nonce   [TransportNonceSize]byte
	)
	binary.BigEndian.PutUint64(counter[:], n.counter.Add(1))
	h := hmac.New(sha256.New, n.key[:])
	_, err := h.Write(counter[:])
	if err != nil {
		panic(err)
	}
	copy(nonce[:], h.Sum(nil))
	return &nonce
}

func NewNonce() (*Nonce, error) {
	n := &Nonce{}
	_, err := rand.Read(n.key[:])
	if err != nil {
		return nil, err
	}
	return n, nil
}

func Hash160(data []byte) []byte {
	ripemd := ripemd160.New()
	ripemd.Write(data[:])
	return ripemd.Sum(nil)
}

type Identity [ripemd160.Size]byte // ripemd160 of compressed pubkey

func (i Identity) String() string {
	return hex.EncodeToString(i[:])
}

func (i Identity) Bytes() []byte {
	return append([]byte{}, i[:]...) // Fucking linter rejects append(i[:])
}

func (i *Identity) UnmarshalJSON(data []byte) error {
	var d string
	err := json.Unmarshal(data, &d)
	if err != nil {
		return err
	}
	ni, err := NewIdentityFromString(d)
	if err != nil {
		return err
	}
	copy(i[:], ni[:])
	return nil
}

func (i Identity) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(i[:]))
}

func NewIdentityFromPub(pub *secp256k1.PublicKey) Identity {
	id := Hash160(pub.SerializeCompressed())
	var i Identity
	copy(i[:], id)
	return i
}

func NewIdentityFromString(identity string) (*Identity, error) {
	id, err := hex.DecodeString(identity)
	if err != nil {
		return nil, err
	}
	i := Identity{}
	if len(id) != len(i) {
		return nil, errors.New("invalid identity")
	}
	copy(i[:], id)
	return &i, nil
}

type Secret struct {
	privateKey *secp256k1.PrivateKey

	Identity // Provides stringer
}

func (s Secret) PublicKey() *secp256k1.PublicKey {
	return s.privateKey.PubKey()
}

func (s Secret) Sign(hash []byte) []byte {
	return ecdsa.SignCompact(s.privateKey, hash[:], true)
}

func Verify(hash []byte, sig []byte) (*secp256k1.PublicKey, error) {
	publicKey, compact, err := ecdsa.RecoverCompact(sig, hash[:])
	if err != nil {
		return nil, err
	}
	if !compact {
		return nil, ErrNotCompact
	}
	return publicKey, nil
}

func NewSecretFromPrivate(privateKey *secp256k1.PrivateKey) *Secret {
	return &Secret{
		privateKey: privateKey,
		Identity:   NewIdentityFromPub(privateKey.PubKey()),
	}
}

func NewSecretFromString(secret string) (*Secret, error) {
	s, err := hex.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	// XXX this may not always be the case and may need to be a range
	if len(s) != 32 {
		return nil, fmt.Errorf("invalid key")
	}
	return NewSecretFromPrivate(secp256k1.PrivKeyFromBytes(s)), nil
}

func NewSecret() (*Secret, error) {
	s, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return NewSecretFromPrivate(s), nil
}

type TransportRequest struct {
	Version   uint32 `json:"version"`
	Curve     string `json:"curve"`
	PublicKey []byte `json:"publickey"`
}

var (
	ErrCurveDoesnotMatch  = errors.New("curve does not match")
	ErrDecrypt            = errors.New("could not decrypt")
	ErrInvalidChallenge   = errors.New("invalid challenge")
	ErrInvalidHandshake   = errors.New("invalid handshake")
	ErrInvalidPublicKey   = errors.New("invalid public key")
	ErrInvalidTXTRecord   = errors.New("invalid TXT record")
	ErrNotCompact         = errors.New("not a compact public key")
	ErrUnsupportedCurve   = errors.New("unsupported cruve")
	ErrUnsupportedVersion = errors.New("unsupported version")
)

type Transport struct {
	mtx sync.Mutex

	curveName string
	curve     ecdh.Curve
	us        *ecdh.PrivateKey
	nonce     *Nonce

	them          *ecdh.PublicKey // Their public key
	encryptionKey *[32]byte       // Shared ephemeral encryption key

	// DNS lookup and verification
	dns      string        // Validate identity using DNS
	resolver *net.Resolver // only set to non default for test

	conn net.Conn
}

func NewTransport(curve, dns string) (*Transport, error) {
	t := &Transport{
		dns:      dns,
		resolver: net.DefaultResolver,
	}
	if err := t.begin(curve); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Transport) begin(curve string) error {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	t.curveName = curve

	var err error
	switch curve {
	case CurveClient:
		return nil
	case CurveP521:
		t.curve = ecdh.P521()
	case CurveP384:
		t.curve = ecdh.P384()
	case CurveX25519:
		t.curve = ecdh.X25519()
	case CurveP256:
		t.curve = ecdh.P256()
	default:
		return ErrUnsupportedCurve
	}

	t.us, err = t.curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	t.nonce, err = NewNonce()
	if err != nil {
		return err
	}

	return nil
}

func (t *Transport) Close() error {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.conn == nil {
		// didn't finish exchanging keys
		// or was previously closed
		return nil
	}
	err := t.conn.Close()
	t.conn = nil // XXX should we do this?
	return err
}

func (t *Transport) kx() error {
	// Shared secret seed.
	shared, err := t.us.ECDH(t.them)
	if err != nil {
		return err
	}

	// Derive shared ephemeral encryption key.
	var encryptionKey [32]byte
	er := hkdf.New(sha256.New, shared, nil, nil)
	if _, err := io.ReadFull(er, encryptionKey[:]); err != nil {
		return err
	}
	t.encryptionKey = &encryptionKey // Assign encryption key

	return nil
}

func (t *Transport) KeyExchange(ctx context.Context, conn net.Conn) error {
	var (
		tr  TransportRequest
		err error
	)
	var greatSuccess bool
	defer func() {
		if !greatSuccess {
			if err := conn.Close(); err != nil {
				log.Errorf("connection: %v", conn.Close())
			}
		}
	}()
	sendRequest := func() error {
		return json.NewEncoder(conn).Encode(TransportRequest{
			Version:   TransportVersion,
			Curve:     t.curveName,
			PublicKey: t.us.PublicKey().Bytes(),
		})
	}
	if t.curveName != CurveClient {
		if err = sendRequest(); err != nil {
			return err
		}
		if err = json.NewDecoder(conn).Decode(&tr); err != nil {
			return err
		}
	} else {
		if err = json.NewDecoder(conn).Decode(&tr); err != nil {
			return err
		}
		if err := t.begin(tr.Curve); err != nil {
			return err
		}
		if err := sendRequest(); err != nil {
			return err
		}
	}

	if tr.Version != TransportVersion {
		return ErrUnsupportedVersion
	}
	if tr.Curve != t.curveName {
		return ErrCurveDoesnotMatch
	}
	if len(tr.PublicKey) == 0 {
		return ErrInvalidPublicKey
	}

	t.them, err = t.curve.NewPublicKey(tr.PublicKey)
	if err != nil {
		return err
	}

	err = t.kx()
	if err != nil {
		return err
	}

	greatSuccess = true
	t.conn = conn // Now we are ready to talk through transport.

	return nil
}

func (t *Transport) encrypt(cmd []byte) ([]byte, error) {
	ts := TransportNonceSize + len(cmd) + secretbox.Overhead
	if ts > TransportMaxSize {
		return nil, fmt.Errorf("overflow")
	}

	// Encode size to prefix nonce
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(ts))
	nonce := t.nonce.Next()
	blob := secretbox.Seal(append(size[1:4], nonce[:]...), cmd, nonce,
		t.encryptionKey)

	// diagnostic
	if ts != len(blob)-3 {
		panic(fmt.Sprintf("encryption diagnostic: wanted %v got %v",
			ts, len(blob)))
	}
	return blob, nil
}

func (t *Transport) decrypt(blob []byte) ([]byte, error) {
	var nonce [TransportNonceSize]byte
	copy(nonce[:], blob[:TransportNonceSize])
	cleartext, ok := secretbox.Open(nil, blob[TransportNonceSize:], &nonce,
		t.encryptionKey)
	if !ok {
		return nil, ErrDecrypt
	}
	return cleartext, nil
}

func (t *Transport) Handshake(ctx context.Context, secret *Secret) (*Identity, error) {
	// XXX add timeout based on context
	var ourChallenge [32]byte
	_, err := rand.Read(ourChallenge[:])
	if err != nil {
		return nil, err
	}

	// XXX this needs to be a function of sorts
	var remoteDNSID *Identity
	if t.dns != "" {
		// XXX should we not panic on conn == nil?
		t.mtx.Lock()
		addr := t.conn.RemoteAddr()
		t.mtx.Unlock()

		// XXX this needs to be a function of sorts
		h, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil, fmt.Errorf("dns split: %w", err)
		}
		rl, err := t.resolver.LookupAddr(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("dns lookup: %w", err)
		}
		if len(rl) < 1 {
			return nil, fmt.Errorf("dns lookup: no records for %v", addr)
		}
		txts, err := t.resolver.LookupTXT(ctx, rl[0])
		if err != nil {
			return nil, err
		}
		if len(txts) != 1 {
			return nil, fmt.Errorf("dns no txt records: %v", len(txts))
		}
		m, err := kvFomTxt(txts[0])
		if err != nil {
			return nil, fmt.Errorf("dns txt record: %w", err)
		}

		if m["v"] != dnsAppName {
			return nil, fmt.Errorf("dns invalid app name: '%v'", m["v"])
		}
		remoteDNSID, err = NewIdentityFromString(m["identity"])
		if err != nil {
			return nil, fmt.Errorf("dns invalid identity: %w", err)
		}
		// XXX are we going to use port?
	}

	// Write HelloRequest
	err = t.Write(secret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Challenge: ourChallenge[:],
		Options: map[string]string{
			"encoding":    "json",
			"compression": "none",
		},
	})
	if err != nil {
		return nil, err
	}

	// Read response.
	// This can be either HelloRequest or HelloResponse depnding on
	// mystical timing solar flares. Handle them regardless of order but
	// require both to always complete.
	var (
		helloRequest  *HelloRequest
		helloResponse *HelloResponse
	)
	for i := 0; i < 2; i++ {
		log.Infof("%v: %p %p", secret.Identity, helloRequest, helloResponse)
		cmd, err := t.read(2 * time.Second) // XXX figure out a good read timeout
		if err != nil {
			return nil, err
		}

		// XXX move this into read
		nr := bytes.NewReader(cmd)
		jd := json.NewDecoder(nr)
		var header Header
		err = jd.Decode(&header)
		if err != nil {
			return nil, err
		}
		// XXX i was too clever to make the payload hash in the write
		// but we can't really get to it here. It is a valid unique
		// hash but it would be cute if we could verify the payload
		// actual hash
		switch header.PayloadType {
		case PHelloRequest:
			var req HelloRequest
			if err := jd.Decode(&req); err != nil {
				return nil, err
			}

			// Sign challenge and reply
			err = t.Write(secret.Identity, HelloResponse{
				Signature: secret.Sign(req.Challenge),
			})
			if err != nil {
				return nil, err
			}

			// Mark valid
			helloRequest = &req

		case PHelloResponse:
			var resp HelloResponse
			if err := jd.Decode(&resp); err != nil {
				return nil, err
			}
			helloResponse = &resp

		default:
			return nil, fmt.Errorf("invalid command: %v", header.PayloadType)
		}
	}

	// See if we completed the handshake
	if helloRequest == nil || helloResponse == nil {
		return nil, ErrInvalidHandshake
	}

	// Validate HelloRequest
	if helloRequest.Version != ProtocolVersion {
		return nil, ErrUnsupportedVersion
	}
	if len(helloRequest.Challenge) != ChallengeSize {
		return nil, ErrInvalidChallenge
	}
	if bytes.Equal(ZeroChallenge[:], helloRequest.Challenge) {
		return nil, ErrInvalidChallenge
	}

	// XXX do something with options

	// Verify response
	themPub, err := Verify(ourChallenge[:], helloResponse.Signature)
	if err != nil {
		return nil, err
	}
	themID := NewIdentityFromPub(themPub)

	// XXX move this into a function
	if t.dns != "" {
		if remoteDNSID == nil {
			return nil, errors.New("remote dns id not set")
		}
		if themID.String() != remoteDNSID.String() {
			return nil, fmt.Errorf("dns identity does not match: got %v, want %v",
				themID, remoteDNSID)
		}
	}

	return &themID, nil
}

func noTimeout() error { return nil }

// readBlob locks the connection and reads a size and the associated blob into
// a slice and returns that.
func (t *Transport) readBlob(timeout time.Duration) ([]byte, error) {
	// Don't interleave blobs and sizes
	t.mtx.Lock()
	defer t.mtx.Unlock()

	// XXX should we be using 3 as a constant here or not?

	var sizeRE [4]byte
	n, err := t.conn.Read(sizeRE[1:4]) // read 3 bytes for the nonce+ciphertext
	if err != nil {
		return nil, err
	}
	if n != 3 {
		return nil, fmt.Errorf("short read size: %v != 3", n)
	}
	sizeR := binary.BigEndian.Uint32(sizeRE[:])
	if sizeR > 1000 {
		log.Infof("readBlob %v", spew.Sdump(sizeRE))
		panic("")
	}

	blob := make([]byte, sizeR)

	// Timeout
	to := noTimeout
	if timeout != 0 {
		to = func() error {
			return t.conn.SetReadDeadline(time.Now().Add(timeout))
		}
	}

	var at int
	for {
		err := to()
		if err != nil {
			return nil, err
		}
		n, err = t.conn.Read(blob[at:])
		if err != nil {
			return nil, err
		}
		at += n
		if at < len(blob) {
			continue
		}
		return blob, nil
	}
}

func (t *Transport) read(timeout time.Duration) ([]byte, error) {
	blob, err := t.readBlob(timeout)
	if err != nil {
		return nil, err
	}
	return t.decrypt(blob)
}

func (t *Transport) Read() (any, error) {
	return nil, fmt.Errorf("nope")
}

func (t *Transport) write(timeout time.Duration, blob []byte) error {
	request, err := t.encrypt(blob)
	if err != nil {
		return err
	}

	// Don't interleave blobs and sizes
	t.mtx.Lock()
	defer t.mtx.Unlock()

	// Timeout
	to := noTimeout
	if timeout != 0 {
		to = func() error {
			return t.conn.SetWriteDeadline(time.Now().Add(timeout))
		}
	}

	var at int
	for {
		err := to()
		if err != nil {
			return err
		}
		n, err := t.conn.Write(request[at:])
		if err != nil {
			return err
		}
		at += n
		if at < len(request) {
			continue
		}
		return nil
	}
}

// Write creats a new payload and header and sends that to the peer.
// XXX think about header construction and if we need like a WriteTo which adds
// an explicit origin that may need routing.
func (t *Transport) Write(origin Identity, cmd any) error {
	pt, ok := pt2str[reflect.TypeOf(cmd)]
	if !ok {
		return fmt.Errorf("invalid command type: %T", cmd)
	}
	hash, payload, err := NewPayloadFromCommand(cmd)
	if err != nil {
		return err
	}
	header, err := json.Marshal(Header{
		PayloadType: pt,
		PayloadHash: *hash,
		Origin:      origin,
		Destination: nil,
		TTL:         1, // expires at the receiver
	})
	log.Infof("origin %v write %v", origin, spew.Sdump(header))
	if err != nil {
		return err
	}

	return t.write(1*time.Second, append(header, payload...)) // XXX timeout
}

func NewResolver(resolverAddress string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{}
			return d.DialContext(ctx, network, resolverAddress)
		},
	}
}

func kvFomTxt(txt string) (map[string]string, error) {
	s := strings.Split(txt, " ")
	m := make(map[string]string)
	for _, v := range s {
		kv := strings.Split(v, "=")
		if len(kv) != 2 {
			return nil, ErrInvalidTXTRecord
		}
		m[kv[0]] = kv[1]
	}
	return m, nil
}

// XXX this seems broken because the identity parameter is not necessarily known
func DNSVerifyIdentityByAddress(ctx context.Context, address string, identity Identity, resolver *net.Resolver) (bool, error) {
	if resolver == nil {
		resolver = &net.Resolver{}
	}

	if !strings.HasSuffix(address, ".") {
		address = address + "."
	}

	txts, err := resolver.LookupTXT(ctx, address)
	if err != nil {
		return false, fmt.Errorf("lookup txt: %w", err)
	}
	if len(txts) != 1 {
		return false, errors.New("lookup txt: invalid response")
	}

	m, err := kvFomTxt(txts[0])
	if err != nil {
		return false, err
	}

	if m["v"] != dnsAppName {
		return false, fmt.Errorf("invalid dns app name: '%v'", m["v"])
	}
	if m["identity"] == identity.String() {
		return true, nil
	}

	return false, nil
}

func DNSVerifyIdentityByIP(ctx context.Context, ip net.IP, identity Identity, resolver *net.Resolver) (bool, error) {
	addr, err := resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return false, fmt.Errorf("reverse lookup: %w", err)
	}
	if len(addr) != 1 {
		return false, errors.New("reverse lookup: invalid response")
	}

	return DNSVerifyIdentityByAddress(ctx, addr[0], identity, resolver)
}
