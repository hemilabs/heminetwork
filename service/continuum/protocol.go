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
	"sync"
	"sync/atomic"

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
	if len(data) != len(i) {
		return errors.New("invalid length")
	}
	copy(i[:], data)
	return nil
}

func NewIdentityFromPub(pub *secp256k1.PublicKey) Identity {
	id := Hash160(pub.SerializeCompressed())
	var i Identity
	copy(i[:], id)
	return i
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
	ErrInvalidPublicKey   = errors.New("invalid public key")
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
	encryptionKey [32]byte        // Shared ephemeral encryption key

	conn net.Conn
}

func NewTransport(curve string) (*Transport, error) {
	t := &Transport{}
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
		return nil
	}
	err := t.conn.Close()
	t.conn = nil // XXX should we do this?
	return err
}

func (t *Transport) KeyExchange(ctx context.Context, conn net.Conn) error {
	var (
		tr  TransportRequest
		err error
	)
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

	// Shared secret seed.
	shared, err := t.us.ECDH(t.them)
	if err != nil {
		return err
	}

	// Derive shared ephemeral encryption key.
	er := hkdf.New(sha256.New, shared, nil, nil)
	if _, err := io.ReadFull(er, t.encryptionKey[:]); err != nil {
		return err
	}

	t.conn = conn // Now we are ready to talk through transport.

	return nil
}

func (t *Transport) encrypt(cmd []byte) ([]byte, []byte, error) {
	if len(cmd)+secretbox.Overhead+TransportNonceSize > TransportMaxSize {
		return nil, nil, fmt.Errorf("overflow")
	}

	// Should we prefix nonce with size? or better yet, nonce+size and read
	// 27 bytes instead of 3 to obtain size and noce.
	nonce := t.nonce.Next()
	blob := secretbox.Seal(nonce[:], cmd, nonce, &t.encryptionKey)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(blob)))
	return size[1:4], blob, nil
}

func (t *Transport) Handshake(ctx context.Context, secret *Secret) (*Identity, error) {
	// XXX add timeout based on context
	var ourChallenge [32]byte
	_, err := rand.Read(ourChallenge[:])
	if err != nil {
		return nil, err
	}

	// Write HelloRequest
	err = t.Write(HelloRequest{
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

	// Read HelloRequest
	jsonHelloRequest, err := t.read()
	if err != nil {
		return nil, err
	}
	var helloRequest HelloRequest
	err = json.Unmarshal(jsonHelloRequest, &helloRequest)
	if err != nil {
		return nil, err
	}
	if helloRequest.Version != ProtocolVersion {
		// XXX I have seen some tests go through here and I don't know
		// why. Just leaving a nugget as a reminder to debug that.
		// Basically, helloRequest is not unmarshaled.
		return nil, ErrUnsupportedVersion
	}
	if len(helloRequest.Challenge) != ChallengeSize {
		return nil, ErrInvalidChallenge
	}
	if bytes.Equal(ZeroChallenge[:], helloRequest.Challenge) {
		return nil, ErrInvalidChallenge
	}

	// XXX do something with options

	// Write HelloResponse
	err = t.Write(HelloResponse{
		Signature: secret.Sign(helloRequest.Challenge),
	})
	if err != nil {
		return nil, err
	}

	// Read HelloResponse
	jsonHelloResponse, err := t.read()
	if err != nil {
		return nil, err
	}
	var helloResponse HelloResponse
	err = json.Unmarshal(jsonHelloResponse, &helloResponse)
	if err != nil {
		return nil, err
	}
	themPub, err := Verify(ourChallenge[:], helloResponse.Signature)
	if err != nil {
		return nil, err
	}
	themID := NewIdentityFromPub(themPub)
	return &themID, nil
}

// readBlob locks the connection and reads a size and the associated blob into
// a slice and returns that.
func (t *Transport) readBlob() ([]byte, error) {
	// Don't interleave blobs and sizes
	t.mtx.Lock()
	defer t.mtx.Unlock()

	var sizeRE [4]byte
	n, err := t.conn.Read(sizeRE[1:4])
	if err != nil {
		return nil, err
	}
	if n != 3 {
		return nil, fmt.Errorf("short read size: %v != 3", n)
	}
	sizeR := binary.BigEndian.Uint32(sizeRE[:])

	blob := make([]byte, sizeR)
	n, err = t.conn.Read(blob)
	if err != nil {
		return nil, err
	}
	if n != len(blob) {
		return nil, fmt.Errorf("short read: %v != %v", n, sizeR)
	}

	return blob, nil
}

func (t *Transport) read() ([]byte, error) {
	blob, err := t.readBlob()
	if err != nil {
		return nil, err
	}

	var nonce [TransportNonceSize]byte
	copy(nonce[:], blob[:TransportNonceSize])
	cmd, ok := secretbox.Open(nil, blob[TransportNonceSize:], &nonce, &t.encryptionKey)
	if !ok {
		return nil, ErrDecrypt
	}

	return cmd, nil
}

func (t *Transport) Read() (any, error) {
	return nil, fmt.Errorf("nope")
}

func (t *Transport) write(blob []byte) error {
	size, request, err := t.encrypt(blob)
	if err != nil {
		return err
	}

	// Don't interleave blobs and sizes
	t.mtx.Lock()
	defer t.mtx.Unlock()

	n, err := t.conn.Write(size)
	if err != nil {
		return err
	}
	if n != len(size) {
		return fmt.Errorf("write error length: %v != %v",
			n, len(size))
	}

	n, err = t.conn.Write(request)
	if err != nil {
		return err
	}
	if n != len(request) {
		return fmt.Errorf("write error length: %v != %v",
			n, len(blob))
	}

	return nil
}

func (t *Transport) Write(cmd any) error {
	// XXX encoder interface here
	blob, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	return t.write(blob)
}
