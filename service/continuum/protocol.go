package continuum

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

// The continuum protocol is a simple gossipy P2P system.
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
//

type Size [3]byte

type Header struct{}

type Message struct{}

// Version
//	1:
//		Defaults to JSON encoding
//
// Options (default):
//	encoding=json
//	compression=no
//

//func Handshake(c net.Conn) {
//}

type HelloRequest struct {
	Version   uint32            `json:"version"`           // Version number
	Options   map[string]string `json:"options,omitempty"` // x=y
	Challenge []byte            `json:"challenge"`         // Random challenge, min 32 bytes
}

type HelloResponse struct {
	Signature []byte `json:"signature"` // Signature of Challenge and identity is derived
}

//type Server struct {
//	address *net.TCPAddr
//	lc      net.ListenConfig
//}
//
//func NewServer(o Options, address string) (*Server, error) {
//	a, err := net.ResolveTCPAddr("tcp", address)
//	if err != nil {
//		return nil, err
//	}
//	s := &Server{
//		address: a,
//		lc:      net.ListenConfig{},
//	}
//	return s, nil
//}
//
//func (s *Server) Run(ctx context.Context) error {
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	s.wg.Add(1)
//	go func() {
//		defer s.wg.Done()
//		listener, err := s.lc.ListenTCP(ctx, "tcp", s.address)
//		if err != nil {
//			return nil, err
//		}
//		defer listener.Close()
//	}()
//}
//
//func (s *Server) Read(ctx context.Context) (*Message, error) {
//}
//
//type Client struct{}
//
//func NewClient(o Options) (*Client, error) {
//}
//
//func Read(ctx context.Context) (*Message, error) {
//}

//func NewServer(private *secp256k1.PrivateKey) (*Remote, error) {
//}

const (
	TransportVersion = 1

	ProtocolVersion = 1

	TransportNonceSize = 24         // 24 bytes, per secretbox
	TransportMaxSize   = 0x00ffffff // 24 bit, 3 bytes
)

type Nonce struct {
	counter atomic.Uint64
	key     [TransportNonceSize]byte
}

// Next returns the next nonce by atomically incrementing the nonce counter and
// then running an HMAC-SHA256 over the big endian encoding of it.
func (n *Nonce) Next() *[TransportNonceSize]byte {
	var (
		counter [8]byte
		nonce   [24]byte
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

type TransportRequest struct {
	Version   uint32 `json:"version"`
	Curve     string `json:"curve"`
	PublicKey []byte `json:"publickey"`
}

var (
	ErrCurveDoesnotMatch  = errors.New("curve does not match")
	ErrDecrypt            = errors.New("could not decrypt")
	ErrInvalidPublicKey   = errors.New("invalid public key")
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
	t := &Transport{
		curveName: curve,
	}
	var err error
	// XXX make this an ordered list of more to less secure, client requests, server dictates.
	switch curve {
	case "P256":
		t.curve = ecdh.P256()
	case "P384":
		t.curve = ecdh.P384()
	case "P521":
		t.curve = ecdh.P521()
	case "x25519":
		t.curve = ecdh.X25519()
	default:
		return nil, ErrUnsupportedCurve
	}

	t.us, err = t.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	t.nonce, err = NewNonce()
	if err != nil {
		return nil, err
	}

	return t, nil
}

func (t *Transport) KeyExchange(ctx context.Context, conn net.Conn) error {
	err := json.NewEncoder(conn).Encode(TransportRequest{
		Version:   TransportVersion,
		Curve:     t.curveName,
		PublicKey: t.us.PublicKey().Bytes(),
	})
	if err != nil {
		return err
	}

	var tr TransportRequest
	err = json.NewDecoder(conn).Decode(&tr)
	if err != nil {
		return err
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

func (t *Transport) Handshake(ctx context.Context) (*HelloResponse, error) {
	// XXX add timeout based on context
	var challenge [32]byte
	_, err := rand.Read(challenge[:])
	if err != nil {
		return nil, err
	}

	err = t.Write(HelloRequest{
		Version:   ProtocolVersion,
		Challenge: challenge[:],
		Options: map[string]string{
			"encoding":    "json",
			"compression": "none",
		},
	})
	if err != nil {
		return nil, err
	}
	// panic(fmt.Sprintf("size %x len %v\n%v", size, len(request), spew.Sdump(request)))

	response, err := t.read()
	if err != nil {
		return nil, err
	}

	panic(spew.Sdump(response))

	// Sign challenge

	//var hr HelloResponse
	//err = json.NewDecoder(t.conn).Decode(&hr)
	//if err != nil {
	//	return nil, err
	//}

	return nil, fmt.Errorf("not yet")
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

	var nonce [24]byte
	copy(nonce[:], blob[:24])
	cmd, ok := secretbox.Open(nil, blob[24:], &nonce, &t.encryptionKey)
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
