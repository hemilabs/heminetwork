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
	PublicKey []byte `json:"publickey"`
}

var (
	ErrDecrypt            = errors.New("could not decrypt")
	ErrInvalidChallenge   = errors.New("invalid challenge")
	ErrInvalidPublicKey   = errors.New("invalid public key")
	ErrInvalidTXTRecord   = errors.New("invalid TXT record")
	ErrNoConn             = errors.New("no connection")
	ErrNotCompact         = errors.New("not a compact public key")
	ErrNoSuitableCurve    = errors.New("no suitable curve found")
	ErrUnsupportedVersion = errors.New("unsupported version")
)

// Transport is an opaque type that provides encrypted transport for
// arbitrarily sized cleartext.
//
// XXX toni please add an example here on how to use it.
type Transport struct {
	mtx sync.Mutex

	// Transport encryption bits
	isServer      bool             // server or client
	curve         ecdh.Curve       // transport encryption curve
	us            *ecdh.PrivateKey // our transport ephemeral private key
	them          *ecdh.PublicKey  // their ephemeral public key
	encryptionKey *[32]byte        // shared symmetric ephemeral encryption key
	nonce         *Nonce           // transport nonce

	conn net.Conn
}

// String returns what mode this transport is in.
func (t *Transport) String() string {
	if t.isServer {
		return "server"
	}
	return "client"
}

// Curve returns the curve name.
func (t *Transport) Curve() string {
	return fmt.Sprintf("%v", t.curve) // Can't directly call the stringer.
}

// NewTransportFromCurve creates a server transport for the provided curve.
// This is the listening side.
func NewTransportFromCurve(curve ecdh.Curve) (*Transport, error) {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Transport{
		curve:    curve,
		us:       privateKey,
		isServer: true,
	}, nil
}

// newTransportFromPublicKey creates a client transport based on the server
// public key. This is the connecting side.
//
// This utility function is probably only useful in tests.
func newTransportFromPublicKey(publicKey []byte) (*Transport, error) {
	t := new(Transport)
	err := t.setTransportFromPublicKey(publicKey)
	return t, err
}

// setTransportFromPublicKey is used during Handshake to fill out the client
// side ephemeral key. The correct curve is picked based on the public key that
// is passed in.
func (t *Transport) setTransportFromPublicKey(publicKey []byte) error {
	curves := []ecdh.Curve{ecdh.X25519(), ecdh.P521(), ecdh.P384(), ecdh.P256()}
	for _, curve := range curves {
		theirPublicKey, err := curve.NewPublicKey(publicKey)
		if err != nil {
			continue
		}

		privateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		t.mtx.Lock()
		t.curve = curve
		t.us = privateKey
		t.them = theirPublicKey
		t.mtx.Unlock()
		return nil
	}

	return ErrNoSuitableCurve
}

// Close closes the underlying connection but leaves the ephemeral encryption
// key and connection set. This is deliberate to prevent reuse.
func (t *Transport) Close() error {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.conn == nil {
		return ErrNoConn
	}
	return t.conn.Close()
}

// KeyExchange returns a shared encryption key for the provided private and
// public keys. The returned encryption key is derived from the shared ECDH
// secret using HKDF and has 256 bits of entropy.
func KeyExchange(us *ecdh.PrivateKey, them *ecdh.PublicKey) (*[32]byte, error) {
	// Shared secret seed.
	shared, err := us.ECDH(them)
	if err != nil {
		return nil, err
	}

	// Derive shared ephemeral encryption key.
	var encryptionKey [32]byte
	er := hkdf.New(sha256.New, shared, nil, nil)
	if _, err := io.ReadFull(er, encryptionKey[:]); err != nil {
		return nil, err
	}

	return &encryptionKey, nil
}

// KeyExchange performs a series of reads and writes to establish a transport
// encryption key between the server and the client. Note that the server
// dictates the curve.
func (t *Transport) KeyExchange(ctx context.Context, conn net.Conn) error {
	// XXX do we need to close the connection on the way out if it fails?
	var (
		them *ecdh.PublicKey
		tr   TransportRequest
	)
	// XXX the conn timeout could and maybe should be set by the caller.
	timeout := 5 * time.Second // XXX config?
	if t.isServer {
		// Send TransportRequest
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if err := json.NewEncoder(conn).Encode(TransportRequest{
			Version:   TransportVersion,
			PublicKey: t.us.PublicKey().Bytes(),
		}); err != nil {
			return err
		}

		// Read TransportRequest
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if err := json.NewDecoder(conn).Decode(&tr); err != nil {
			return err
		}
		// log.Infof("server read %v", spew.Sdump(tr))
	} else {
		// Read TransportRequest
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if err := json.NewDecoder(conn).Decode(&tr); err != nil {
			return err
		}
		// log.Infof("client read %v", spew.Sdump(tr))

		if err := t.setTransportFromPublicKey(tr.PublicKey); err != nil {
			return err
		}

		// Send TransportRequest
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if err := json.NewEncoder(conn).Encode(TransportRequest{
			Version:   TransportVersion,
			PublicKey: t.us.PublicKey().Bytes(),
		}); err != nil {
			return err
		}
	}

	// Validate other side TransportRequest
	if tr.Version != TransportVersion {
		return ErrUnsupportedVersion
	}
	if len(tr.PublicKey) <= 0 {
		return ErrInvalidPublicKey
	}

	them, err := t.curve.NewPublicKey(tr.PublicKey)
	if err != nil {
		return err
	}
	encryptionKey, err := KeyExchange(t.us, them)
	if err != nil {
		return err
	}

	nonce, err := NewNonce()
	if err != nil {
		return err
	}

	// Finish KX
	t.mtx.Lock()
	t.encryptionKey = encryptionKey
	t.them = them
	t.nonce = nonce
	t.conn = conn
	t.mtx.Unlock()

	return nil
}

// encrypt encrypts the passed in slice. The returned encrypted data is
// prepended with a length and a nonce. This is to facilitate writes directly
// on the wire.
func (t *Transport) encrypt(cleartext []byte) ([]byte, error) {
	ts := TransportNonceSize + len(cleartext) + secretbox.Overhead
	if ts > TransportMaxSize {
		return nil, fmt.Errorf("overflow")
	}

	if t.encryptionKey == nil {
		panic("wtf")
	}

	// Encode size to prefix nonce
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(ts))
	nonce := t.nonce.Next()
	blob := secretbox.Seal(append(size[1:4], nonce[:]...), cleartext, nonce,
		t.encryptionKey)

	// diagnostic
	if ts != len(blob)-3 {
		panic(fmt.Sprintf("encryption diagnostic: wanted %v got %v",
			ts, len(blob)))
	}
	return blob, nil
}

// decrypt decrypts the passed in ciphertext. The ciphertext must be prefixed
// with the nonce. Note that the three byte length must have been clipped off.
func (t *Transport) decrypt(ciphertext []byte) ([]byte, error) {
	var nonce [TransportNonceSize]byte
	copy(nonce[:], ciphertext[:TransportNonceSize])
	cleartext, ok := secretbox.Open(nil, ciphertext[TransportNonceSize:], &nonce,
		t.encryptionKey)
	if !ok {
		return nil, ErrDecrypt
	}
	return cleartext, nil
}

// Handshake advertises to the other side what version and options this
// transport wishes to use. It is also used to verify that the derived Identity
// identity did indeed sign the challenge.
func (t *Transport) Handshake(ctx context.Context, secret *Secret) (*Identity, error) {
	var ourChallenge [32]byte
	_, err := rand.Read(ourChallenge[:])
	if err != nil {
		return nil, err
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

	// Read Hello
	header, cmd, err := t.readEncrypted(4 * time.Second) // XXX figure out a good read timeout
	if err != nil {
		return nil, err
	}
	_ = header
	helloRequest, ok := cmd.(*HelloRequest)
	if !ok {
		return nil, fmt.Errorf("unexpected command: %T, wanted HelloRequest", cmd)
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

	// Sign challenge and reply
	if err := t.Write(secret.Identity, HelloResponse{
		Signature: secret.Sign(helloRequest.Challenge),
	}); err != nil {
		return nil, err
	}

	// Read HelloResponse
	header2, cmd2, err := t.readEncrypted(4 * time.Second) // XXX figure out a good read timeout
	if err != nil {
		return nil, err
	}
	_ = header2
	helloResponse, ok := cmd2.(*HelloResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected command: %T", cmd2)
	}

	// Verify response
	themPub, err := Verify(ourChallenge[:], helloResponse.Signature)
	if err != nil {
		return nil, err
	}

	// XXX do something with options

	themID := NewIdentityFromPub(themPub)

	return &themID, nil
}

// readBlob locks the connection and reads a size and the associated blob into
// a slice and returns that. It is locked for the duration to prevent
// interleaved reads.
func (t *Transport) readBlob(timeout time.Duration) ([]byte, error) {
	t.mtx.Lock()
	conn := t.conn
	t.mtx.Unlock()

	if timeout != 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
	} else {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}

	// XXX should we be using 3 as a constant here or not?
	var sizeRE [4]byte
	n, err := conn.Read(sizeRE[1:4]) // read 3 bytes for the nonce+ciphertext
	if err != nil {
		return nil, err
	}
	if n != 3 {
		return nil, fmt.Errorf("short read size: %v != 3", n)
	}
	sizeR := binary.BigEndian.Uint32(sizeRE[:])

	blob := make([]byte, sizeR)
	var at int
	for {
		n, err = conn.Read(blob[at:])
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

// readEncrypted reads the next encrypted blob from the connection stream.
func (t *Transport) readEncrypted(timeout time.Duration) (*Header, any, error) {
	ciphertext, err := t.readBlob(timeout)
	if err != nil {
		return nil, nil, err
	}
	cleartext, err := t.decrypt(ciphertext)
	if err != nil {
		return nil, nil, err
	}

	// log.Infof("%v: read cleartext %v", t, spew.Sdump(cleartext))
	jd := json.NewDecoder(bytes.NewReader(cleartext))
	var header Header
	if err := jd.Decode(&header); err != nil {
		return nil, nil, err
	}
	// log.Infof("%v: read %v", t, header.PayloadType)
	// XXX i was too clever to make the payload hash in the write
	// but we can't really get to it here. It is a valid unique
	// hash but it would be cute if we could verify the payload
	// actual hash
	//
	// XXX can we make this generic using the PayloadType map and reflection?
	switch header.PayloadType {
	case PHelloRequest:
		var helloRequest HelloRequest
		if err := jd.Decode(&helloRequest); err != nil {
			return nil, nil, err
		}
		return &header, &helloRequest, nil
	case PHelloResponse:
		var helloResponse HelloResponse
		if err := jd.Decode(&helloResponse); err != nil {
			return nil, nil, err
		}
		return &header, &helloResponse, nil
	}

	return nil, nil, fmt.Errorf("unsupported: %v", header.PayloadType)
}

// Read reads and decrypts the next command from the connection stream. It
// returns the header and command.
func (t *Transport) Read() (any, any, error) {
	return nil, nil, fmt.Errorf("nope")
}

// write encrypts the passed in cleartext and writes it to the connection
// stream. This function takes the lock to prevent interleaving writes.
func (t *Transport) write(timeout time.Duration, cleartext []byte) error {
	request, err := t.encrypt(cleartext)
	if err != nil {
		panic(err)
	}

	// Don't interleave writes
	t.mtx.Lock()
	defer t.mtx.Unlock()

	// Timeout
	if timeout != 0 {
		if err := t.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
	} else {
		if err := t.conn.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
	}

	var at int
	for {
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
//
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
	if err != nil {
		return err
	}
	return t.write(4*time.Second, append(header, payload...)) // XXX timeout
}

// NewResolver returns a custom resolver that suports context.
func NewResolver(resolverAddress string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{}
			return d.DialContext(ctx, network, resolverAddress)
		},
	}
}

// kvFomTxt converts a TXT record to a key value map. The format is typical INI
// file style. E.g. "v=transfunctioner identity=myidentity key=value".
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

// TXTRecordFromAddress returns one and only one TXT record that is associated
// with an address.
func TXTRecordFromAddress(ctx context.Context, resolver *net.Resolver, addr net.Addr) (map[string]string, error) {
	if resolver == nil {
		resolver = &net.Resolver{}
	}

	h, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, fmt.Errorf("dns split: %w", err)
	}
	rl, err := resolver.LookupAddr(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("dns lookup: %w", err)
	}
	if len(rl) < 1 {
		return nil, fmt.Errorf("dns lookup: no records for %v", addr)
	}
	txts, err := resolver.LookupTXT(ctx, rl[0])
	if err != nil {
		return nil, err
	}
	if len(txts) != 1 {
		return nil, fmt.Errorf("dns no txt records: %v", len(txts))
	}
	return kvFomTxt(txts[0])
}

// VerifyRemoteDNSIdentity verifies that passed in identity matches it's
// associated TXT record identity. This can be used to determine if a server or
// client are indeed who they claim they are.
func VerifyRemoteDNSIdentity(ctx context.Context, r *net.Resolver, addr net.Addr, id Identity) (bool, error) {
	m, err := TXTRecordFromAddress(ctx, r, addr)
	if err != nil {
		return false, err
	}
	// XXX are we going to use port?

	if m["v"] != dnsAppName {
		return false, fmt.Errorf("dns invalid app name: '%v'", m["v"])
	}
	remoteDNSID, err := NewIdentityFromString(m["identity"])
	if err != nil {
		return false, fmt.Errorf("dns invalid identity: %w", err)
	}
	return bytes.Equal(id[:], remoteDNSID[:]), nil
}

// XXX add VerifyRemoteDNSIdentity by hostname and call VerifyRemoteDNSIdentity
