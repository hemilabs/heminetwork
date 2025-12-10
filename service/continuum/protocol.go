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
// Communication should occur between a transport "client" and a "server",
// where the server determines the type of Curve and encryption key shared
// by both. Communication between these two parties is initiated by performing
// a key exchange, followed by a handshake where the other party's identity
// is verified. After this, envelopes can be shared freely between both sides.
//
// An envelope is constructed on the wire as: [size+nonce][header+payload].
// The size and nonce are unencrypted, the former being used to validate the
// amount of data to be read, and the latter for decrypting the message.
//
// Once an envelope is decrypted there are two distinct pieces, a header
// and a message + payload. The header contains information akin to TCP
// and is used to route the envelope and specify the payload command type.
// A message is for the reader and an envelope should be routed to a third party.
//
// Version
//	1:
//		Defaults to JSON encoding
//
// Options (default):
//	encoding=json
//	compression=no

type PayloadType string

const (
	PHelloRequest  PayloadType = "hello"
	PHelloResponse PayloadType = "hello-response"
	PPingRequest   PayloadType = "ping"
	PPingResponse  PayloadType = "ping-response"
)

var (
	pt2str = map[reflect.Type]PayloadType{
		reflect.TypeOf(HelloRequest{}):  PHelloRequest,
		reflect.TypeOf(HelloResponse{}): PHelloResponse,
		reflect.TypeOf(PingRequest{}):   PPingRequest,
		reflect.TypeOf(PingResponse{}):  PPingResponse,
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

// PayloadHash is a wrapper around sha256 to enable human readable encoding.
// It is used as a unique identifier for the command.
type PayloadHash [32]byte

// MarshalJSON satisfies the JSON Encode interface.
func (p PayloadHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(p[:]))
}

// UnmarshalJSON satisfies the JSON Decode interface.
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

// String returns the payloadhash as a hexadecimal encoded string.
func (p PayloadHash) String() string {
	return hex.EncodeToString(p[:])
}

// NewPayloadHash returns a PayloadHash type that hashes x.
func NewPayloadHash(x []byte) *PayloadHash {
	p := PayloadHash(sha256.Sum256(x))
	return &p
}

// NewPayloadFromCommand returns the json encoding of a given command, along
// with its hash.
func NewPayloadFromCommand(cmd any) (*PayloadHash, []byte, error) {
	jc, err := json.Marshal(cmd)
	if err != nil {
		return nil, nil, err
	}
	return NewPayloadHash(jc), jc, nil
}

// Header is a part of every message sent by transport, and contains
// information about identity of the sender and intended receiver, as well as
// the payload.
type Header struct {
	PayloadType PayloadType `json:"payloadtype"`           // Hint to decode payload
	PayloadHash PayloadHash `json:"payloadhash"`           // Message identifier
	Origin      Identity    `json:"origin"`                // Origin identity
	Destination *Identity   `json:"destination,omitempty"` // Intended receiver
	TTL         uint8       `json:"ttl"`                   // Time To Live
	// Path        []Identity      // Record path when routing XXX ?
}

// HelloRequest is the first command that is sent to the other side after the
// key exchange pahse. It advertises the version the node is running and some
// desired options. The challenge must be signed by the remote node.
type HelloRequest struct {
	Version   uint32            `json:"version"`           // Version number
	Options   map[string]string `json:"options,omitempty"` // x=y
	Identity  Identity          `json:"identity"`          // Advertise our identity
	Challenge []byte            `json:"challenge"`         // Random challenge, min 32 bytes
}

// HelloResponse returns the signed challenge. The remote identity is dervied
// from the signature.
type HelloResponse struct {
	Signature []byte `json:"signature"` // Signature of Challenge
}

// PingRequest is a ping to the other side.
type PingRequest struct {
	OriginTimestamp int64 `json:"origintimestamp"` // Sender timestamp
}

// PingResponse is the response to a pin request.
type PingResponse struct {
	OriginTimestamp int64 `json:"origintimestamp"` // Copy the value back
	PeerTimestamp   int64 `json:"peertimestamp"`   // Remote timestamp
}

const (
	TransportVersion = 1 // Transport protocol version

	ProtocolVersion = 1 // Node version

	TransportNonceSize = 24         // 24 bytes, per secretbox
	TransportMaxSize   = 0x00ffffff // 24 bit, 3 bytes

	ChallengeSize = 32 // 32 bytes random data

	dnsAppName = "transfunctioner" // Expected "v=" value in DNS TXT record
)

var ZeroChallenge = [ChallengeSize]byte{} // All zeroes is an invalid challenge

// Nonce is used by transport for message encryption / decryption.
// It is first generated during key exchange, and is atomically
// incremented by every message sent, producing a new value.
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

// NewNonce returns a new Nonce type. This is used to guarantee a unique nonce
// that can be used with secretbox.
func NewNonce() (*Nonce, error) {
	n := &Nonce{}
	_, err := rand.Read(n.key[:])
	if err != nil {
		return nil, err
	}
	return n, nil
}

// Hash160 is a utility function that returns the ripemd160 hash for the
// provided data.
func Hash160(data []byte) []byte {
	ripemd := ripemd160.New()
	ripemd.Write(data[:])
	return ripemd.Sum(nil)
}

// Hash160 is a utility function that returns the sha256 of multiple byte
// slices.
func Hash256(data []byte, extraData ...[]byte) []byte {
	hash := sha256.New()
	_, err := hash.Write(data[:])
	if err != nil {
		panic(err)
	}
	for _, v := range extraData {
		_, err := hash.Write(v)
		if err != nil {
			panic(err)
		}
	}
	return hash.Sum(nil)
}

// Identity is how a node is identified. It simply is the ripemd160 of the
// public key.
type Identity [ripemd160.Size]byte // ripemd160 of compressed pubkey

// String returns the hex endoded string of the identity.
func (i Identity) String() string {
	return hex.EncodeToString(i[:])
}

// Bytes returns a copy of identity as a byte slice.
func (i Identity) Bytes() []byte {
	return append([]byte{}, i[:]...) // Fucking linter rejects append(i[:])
}

// UnmarshalJSON satisfies the JSON Decode interface.
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

// MarshalJSON satisfies the JSON Encode interface.
func (i Identity) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(i[:]))
}

// NewIdentityFromPub returns a new identity for the provided public key.
func NewIdentityFromPub(pub *secp256k1.PublicKey) Identity {
	id := Hash160(pub.SerializeCompressed())
	var i Identity
	copy(i[:], id)
	return i
}

// NewIdentityFromString returns a new identity for the provided string encoded
// public key.
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

// Secret is the ephemeral private key that a node uses for signing challenges.
// It also provides the publicly known derived Identity.
type Secret struct {
	privateKey *secp256k1.PrivateKey

	Identity // Provides stringer
}

// PublicKey returns the public key of the secret.
func (s Secret) PublicKey() *secp256k1.PublicKey {
	return s.privateKey.PubKey()
}

// Sign signs a hash and returns the signature. Don't be a smartass and send
// anything but a hash into this function.
func (s Secret) Sign(hash []byte) []byte {
	return ecdsa.SignCompact(s.privateKey, hash[:], true)
}

// Verify verifies that hash was signed by the provided identity. It returns
// the derived compact public key.
func Verify(hash []byte, remote Identity, sig []byte) (*secp256k1.PublicKey, error) {
	publicKey, compact, err := ecdsa.RecoverCompact(sig, hash[:])
	if err != nil {
		return nil, err
	}
	if !compact {
		return nil, ErrNotCompact
	}
	recoveredID := NewIdentityFromPub(publicKey)
	if !bytes.Equal(recoveredID[:], remote[:]) {
		return nil, ErrIdentityMismatch
	}
	return publicKey, nil
}

// NewSecretFromPrivate returns a secret type for the provided private key.
func NewSecretFromPrivate(privateKey *secp256k1.PrivateKey) *Secret {
	return &Secret{
		privateKey: privateKey,
		Identity:   NewIdentityFromPub(privateKey.PubKey()),
	}
}

// NewSecretFromPrivate returns a secret type for the provided string encoded
// private key.
func NewSecretFromString(secret string) (*Secret, error) {
	s, err := hex.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	// This may not always be the case and may need to be a range.
	if len(s) != 32 {
		return nil, fmt.Errorf("invalid key")
	}
	return NewSecretFromPrivate(secp256k1.PrivKeyFromBytes(s)), nil
}

// NewSecret returns a secret type with a randomly generated private key.
func NewSecret() (*Secret, error) {
	s, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return NewSecretFromPrivate(s), nil
}

// TransportRequest advertises the ephemeral public key. It is the only command
// that travels in the clear.
type TransportRequest struct {
	Version   uint32 `json:"version"`
	PublicKey []byte `json:"publickey"`
}

var (
	ErrDecrypt                = errors.New("could not decrypt")
	ErrIdentityMismatch       = errors.New("identity mismatch")
	ErrInvalidChallenge       = errors.New("invalid challenge")
	ErrInvalidPublicKey       = errors.New("invalid public key")
	ErrInvalidSecretboxLength = errors.New("invalid secretbox length")
	ErrInvalidTXTRecord       = errors.New("invalid TXT record")
	ErrNoConn                 = errors.New("no connection")
	ErrNotCompact             = errors.New("not a compact public key")
	ErrNoSuitableCurve        = errors.New("no suitable curve found")
	ErrUnsupportedVersion     = errors.New("unsupported version")
	ErrMessageTooLarge        = errors.New("message too large")

	// placeholders until we decide on timeout handling
	readTimeout  time.Duration = 4 * time.Second
	writeTimeout time.Duration = 4 * time.Second
)

// Transport is an opaque type that provides encrypted transport for
// arbitrarily sized cleartext.
//
// Server Example:
//
//	server, _ := NewTransportFromCurve(ecdh.P256())
//	serverSecret, _ := NewSecret()
//	l := net.ListenConfig{}
//	listener, _ := l.Listen(ctx, "tcp", <ADDRESS:PORT>)
//	conn, _ := listener.Accept()
//	server.KeyExchange(ctx, conn)
//	derivedClient, _ := server.Handshake(ctx, serverSecret)
//
// Client Example:
//
//	client := new(Transport)
//	clientSecret, _ := NewSecret()
//	d := &net.Dialer{}
//	conn, _ := d.DialContext(ctx, "tcp", <ADDRESS:PORT>)
//	client.KeyExchange(ctx, conn)
//	derivedServer, _ := client.Handshake(ctx, clientSecret)
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

// allowedCurves are the curves that the server and client are allowed to use.
// Note that the server side dictates which curve the client must use. If the
// client does not approve it should hang up.
var allowedCurves = []ecdh.Curve{ecdh.X25519(), ecdh.P521(), ecdh.P384(), ecdh.P256()}

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
	for _, curve := range allowedCurves {
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
	er := hkdf.New(sha256.New, shared, nil, []byte("continuum-transport-v1"))
	if _, err := io.ReadFull(er, encryptionKey[:]); err != nil {
		return nil, err
	}

	return &encryptionKey, nil
}

// KeyExchange performs a series of reads and writes to establish a transport
// encryption key between the server and the client. Note that the server
// dictates the curve.
func (t *Transport) KeyExchange(ctx context.Context, conn net.Conn) error {
	var (
		them         *ecdh.PublicKey
		tr           TransportRequest
		greatSuccess bool
	)

	// If KeyExchange is aborted the connection is killed.
	defer func() {
		if !greatSuccess {
			if err := conn.Close(); err != nil {
				log.Errorf("KeyExchange: %v", err)
			}
		}
	}()

	// The key exchange should finish in less than 5 seconds.
	timeout := 5 * time.Second
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if t.isServer {
		// Send TransportRequest
		if err := json.NewEncoder(conn).Encode(TransportRequest{
			Version:   TransportVersion,
			PublicKey: t.us.PublicKey().Bytes(),
		}); err != nil {
			return err
		}

		// Read TransportRequest
		if err := json.NewDecoder(conn).Decode(&tr); err != nil {
			return err
		}
		// log.Infof("server read %v", spew.Sdump(tr))
	} else {
		// Read TransportRequest
		if err := json.NewDecoder(conn).Decode(&tr); err != nil {
			return err
		}
		// log.Infof("client read %v", spew.Sdump(tr))

		if err := t.setTransportFromPublicKey(tr.PublicKey); err != nil {
			return err
		}

		// Send TransportRequest
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

	// Reset deadline for connection
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	// Finish KX
	t.mtx.Lock()
	t.encryptionKey = encryptionKey
	t.them = them
	t.nonce = nonce
	t.conn = conn
	t.mtx.Unlock()

	greatSuccess = true // High five!

	return nil
}

// encrypt encrypts the passed in slice. The returned encrypted data is
// prepended with a length and a nonce. This is to facilitate writes directly
// on the wire.
func (t *Transport) encrypt(cleartext []byte) ([]byte, error) {
	ts := TransportNonceSize + len(cleartext) + secretbox.Overhead
	if ts > TransportMaxSize {
		return nil, ErrMessageTooLarge
	}

	// Encode size to prefix nonce
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(ts))
	nonce := t.nonce.Next()
	blob := secretbox.Seal(append(size[1:4], nonce[:]...), cleartext, nonce,
		t.encryptionKey)

	// diagnostic
	if ts != len(blob)-3 {
		panic(fmt.Errorf("encryption diagnostic: wanted %v got %v",
			ts, len(blob)))
	}
	return blob, nil
}

// decrypt decrypts the passed in ciphertext. The ciphertext must be prefixed
// with the nonce. Note that the three byte length must have been clipped off.
func (t *Transport) decrypt(ciphertext []byte) ([]byte, error) {
	// Make sure we have received enough bytes to decrypt.
	if len(ciphertext) < TransportNonceSize+1+secretbox.Overhead {
		return nil, ErrInvalidSecretboxLength
	}

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
// did indeed sign the challenge.
func (t *Transport) Handshake(ctx context.Context, secret *Secret) (*Identity, error) {
	var ourChallenge [32]byte
	_, err := rand.Read(ourChallenge[:])
	if err != nil {
		return nil, err
	}
	// Write HelloRequest
	err = t.Write(secret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  secret.Identity,
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
	_, cmd, err := t.read(readTimeout)
	if err != nil {
		return nil, err
	}
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

	// Sign combined challenge that is represented by the sha256 hash of
	// their challenge plus ephemeral transport public key and reply.
	combinedChallenge := Hash256(helloRequest.Challenge, t.them.Bytes())
	if err := t.Write(secret.Identity, HelloResponse{
		Signature: secret.Sign(combinedChallenge),
	}); err != nil {
		return nil, err
	}

	// Read HelloResponse
	header2, cmd2, err := t.read(readTimeout)
	if err != nil {
		return nil, err
	}
	_ = header2
	helloResponse, ok := cmd2.(*HelloResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected command: %T", cmd2)
	}

	// Verify signature over sha256(our challenge + our tranport public key)
	linkedChallenge := Hash256(ourChallenge[:], t.us.PublicKey().Bytes())
	themPub, err := Verify(linkedChallenge[:], helloRequest.Identity,
		helloResponse.Signature)
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

	// Blob size is 24 bits or 3 bytes encoded in big endian
	var (
		sizeRE [4]byte
		at     int
		sizeR  uint32
	)
	for {
		n, err := conn.Read(sizeRE[1:4]) // read 3 bytes for the nonce+ciphertext
		if err != nil {
			return nil, err
		}
		at += n
		if at < 3 {
			continue
		}
		sizeR = binary.BigEndian.Uint32(sizeRE[:])
		break
	}

	if sizeR > TransportMaxSize {
		return nil, ErrMessageTooLarge
	}

	blob := make([]byte, sizeR)
	at = 0
	for {
		n, err := conn.Read(blob[at:])
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

// read reads the next encrypted blob from the connection stream.
func (t *Transport) read(timeout time.Duration) (*Header, any, error) {
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
	ct, ok := str2pt[header.PayloadType]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported: %v", header.PayloadType)
	}
	cmd := reflect.New(ct)
	if err := jd.Decode(cmd.Interface()); err != nil {
		return nil, nil, err
	}
	return &header, cmd.Interface(), nil
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
	return t.write(writeTimeout, append(header, payload...))
}

// kvFomTxt converts a TXT record to a key value map. The format is typical INI
// file style. E.g. "v=transfunctioner identity=myidentity key=value".
func kvFomTxt(txt string) (map[string]string, error) {
	s := strings.Split(txt, "; ")
	m := make(map[string]string)
	for _, v := range s {
		kv := strings.Split(v, "=")
		if len(kv) != 2 {
			return nil, ErrInvalidTXTRecord
		}
		m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return m, nil
}

// TXTRecordFromAddress returns one and only one TXT record that is associated
// with an address.
//
// XXX I slept some more on this and we should use provide a hint during
// handshake (already encrypted) as to where we are initiating the connection
// from. DNS has been sufficiently broken by you know who and reverse lookups
// are essentially undoable these days.
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
