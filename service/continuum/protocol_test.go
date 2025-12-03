// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
)

func TestEncryptDecrypt(t *testing.T) {
	for i := 0; i < 33; i++ {
		server, err := NewTransportFromCurve(ecdh.X25519())
		if err != nil {
			t.Fatal(err)
		}
		server.nonce, err = NewNonce()
		if err != nil {
			t.Fatal(err)
		}
		client, err := newTransportFromPublicKey(server.us.PublicKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		client.nonce, err = NewNonce()
		if err != nil {
			t.Fatal(err)
		}

		// Perform actual key exchange
		encryptionKeyServer, err := KeyExchange(server.us, client.us.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		encryptionKeyClient, err := KeyExchange(client.us, server.us.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encryptionKeyServer[:], encryptionKeyClient[:]) {
			t.Fatal("shared key not equal")
		}

		// Set keys to simulate incomming key exchange message
		server.encryptionKey = encryptionKeyServer
		client.encryptionKey = encryptionKeyClient

		// Encrypt a message
		message := []byte("this is a super secret message y'all!")
		em, err := server.encrypt(message)
		if err != nil {
			t.Fatal(err)
		}
		cleartext, err := client.decrypt(em[3:]) // clip size that is done by read normally
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(message, cleartext) {
			t.Fatal("message not equal")
		}
	}
}

func TestECDHKeyExchange(t *testing.T) {
	// This test illustrated that the server can dictate the curve and the
	// client can figure it out either by brute force as shown or by
	// inspecting the key itself.
	curves := []ecdh.Curve{ecdh.X25519(), ecdh.P521(), ecdh.P384(), ecdh.P256()}
	var success, failure int
	for _, curveI := range curves {
		server, err := curveI.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serverPub := server.PublicKey().Bytes()

		for _, curveJ := range curves {
			pub, err := curveJ.NewPublicKey(serverPub)
			if err != nil {
				// t.Logf("%v != %v", curves[0], curveJ)
				failure++
				continue
			}
			_ = pub
			success++
		}
	}
	if success != len(curves) {
		t.Fatalf("success got %v, wanted %v", success, len(curves))
	}
	if failure != (len(curves)-1)*len(curves) {
		t.Fatalf("failure got %v, wanted %v", failure,
			(len(curves)-1)*len(curves))
	}
}

func TestPayloadHash(t *testing.T) {
	hello := HelloRequest{
		Version:   0xdeadbeef,
		Options:   map[string]string{"moo": "MOO"},
		Challenge: []byte("this is a challenge"),
	}
	hash, payload, err := NewPayloadFromCommand(hello)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(payload)
	if !bytes.Equal(expected[:], hash[:]) {
		t.Fatal("not equal")
	}
	if hex.EncodeToString(expected[:]) != hash.String() {
		t.Fatal("string not equal")
	}

	// Encode payload
	m := map[string]PayloadHash{"iamhash": *hash}
	em, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var mm map[string]PayloadHash
	err = json.Unmarshal(em, &mm)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, mm) {
		t.Fatal("map not equal")
	}

	// Encode individual line
	el, err := hash.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(el) != `"`+hash.String()+`"` {
		t.Fatal("unexpected json")
	}
	var ph PayloadHash
	err = ph.UnmarshalJSON(el)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ph[:], hash[:]) {
		t.Fatal("json line not equal to hash")
	}

	// Negative
	crap := []byte("this is brocken")
	var mmm map[string]PayloadHash
	err = json.Unmarshal(crap, &mmm)
	if err == nil {
		t.Fatal("brocken")
	}
}

func TestNonce(t *testing.T) {
	n, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	var (
		wg  sync.WaitGroup
		mtx sync.Mutex
	)
	maxNonces := int(1e6)
	m := make(map[[TransportNonceSize]byte]int, maxNonces)
	for i := 0; i < maxNonces; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			nonce := n.Next() // race nonce

			// But be nice to map inserts
			mtx.Lock()
			defer mtx.Unlock()
			if _, ok := m[*nonce]; ok {
				panic(fmt.Sprintf("duplicate nonce: key %x i %v",
					n.key, i))
			}
			m[*nonce] = i + 1
		}()
	}

	wg.Wait()
	if len(m) != maxNonces {
		t.Fatalf("got %v want %v", len(m), maxNonces)
	}
}

func TestKeyExchange(t *testing.T) {
	// Setup server
	serverTransport, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	// Send public key to client
	serverPublicKey := serverTransport.us.PublicKey().Bytes()

	// Create transport from server public key
	clientTransport, err := newTransportFromPublicKey(serverPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("%v %v", clientTransport.curve, serverTransport.curve)
	if clientTransport.curve != serverTransport.curve {
		t.Fatalf("got %v, wanted %v",
			clientTransport.curve, serverTransport.curve)
	}

	// Send server client public key

	// Server derives ephemeral shared key
	serverEncryptionKey, err := KeyExchange(serverTransport.us,
		clientTransport.us.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	clientEncryptionKey, err := KeyExchange(clientTransport.us,
		serverTransport.us.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(serverEncryptionKey[:], clientEncryptionKey[:]) {
		t.Fatal("derived shared key not equal")
	}
}

func TestConnKeyExchange(t *testing.T) {
	curves := []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521(), ecdh.X25519()}
	for _, curve := range curves {
		testName := fmt.Sprintf("%v", curve)
		t.Run(testName, func(t *testing.T) {
			serverTransport, err := NewTransportFromCurve(curve)
			if err != nil {
				t.Fatal(err)
			}

			// Create blank transport
			clientTransport := new(Transport)

			ctx, cancel := context.WithTimeout(t.Context(), 9*time.Second)
			defer cancel()
			var wg sync.WaitGroup

			// Server
			l := net.ListenConfig{}
			listener, err := l.Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port

			wg.Add(1)
			go func() {
				defer wg.Done()

				t.Logf("Listening: %v", port)
				conn, err := listener.Accept()
				if err != nil {
					panic(err)
				}

				if err := serverTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}
			}()

			// Client
			wg.Add(1)
			go func() {
				defer wg.Done()

				addr, err := net.ResolveTCPAddr("tcp",
					net.JoinHostPort("127.0.0.1", "0"))
				if err != nil {
					panic(err)
				}
				d := &net.Dialer{LocalAddr: addr}
				conn, err := d.DialContext(ctx, "tcp",
					net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if err != nil {
					panic(err)
				}
				defer func() {
					if err := clientTransport.Close(); err != nil {
						panic(err)
					}
				}()

				if err := clientTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}

				t.Logf("client connected using: %v", clientTransport.Curve())
			}()

			wg.Wait()

			if !bytes.Equal(serverTransport.encryptionKey[:],
				clientTransport.encryptionKey[:]) {
				t.Fatal("derived shared key not equal")
			}
		})
	}
}

func TestKeyExchangeErrors(t *testing.T) {
	type testTableItem struct {
		name          string
		curve         ecdh.Curve
		isServer      bool
		keyExchange   func(context.Context, net.Conn) error
		expectedError error
	}
	ErrNoType := errors.New("any error")
	tests := []testTableItem{
		{
			name:          "unsupported version - server",
			curve:         ecdh.P256(),
			isServer:      true,
			expectedError: ErrUnsupportedVersion,
			keyExchange: func(ctx context.Context, c net.Conn) error {
				pk, err := ecdh.P256().GenerateKey(rand.Reader)
				if err != nil {
					return err
				}
				return json.NewEncoder(c).Encode(TransportRequest{
					Version:   0,
					PublicKey: pk.PublicKey().Bytes(),
				})
			},
		},
		{
			name:          "unsupported version - client",
			isServer:      false,
			expectedError: ErrUnsupportedVersion,
			keyExchange: func(ctx context.Context, c net.Conn) error {
				pk, err := ecdh.P256().GenerateKey(rand.Reader)
				if err != nil {
					return err
				}
				return json.NewEncoder(c).Encode(TransportRequest{
					Version:   0,
					PublicKey: pk.PublicKey().Bytes(),
				})
			},
		},
		{
			name:          "empty pub key",
			curve:         ecdh.P256(),
			isServer:      true,
			expectedError: ErrInvalidPublicKey,
			keyExchange: func(ctx context.Context, c net.Conn) error {
				return json.NewEncoder(c).Encode(TransportRequest{
					Version: TransportVersion,
				})
			},
		},
		{
			name:          "invalid pub key",
			curve:         ecdh.P256(),
			isServer:      true,
			expectedError: ErrNoType,
			keyExchange: func(ctx context.Context, c net.Conn) error {
				pk, err := ecdh.P521().GenerateKey(rand.Reader)
				if err != nil {
					return err
				}
				return json.NewEncoder(c).Encode(TransportRequest{
					Version:   TransportVersion,
					PublicKey: pk.PublicKey().Bytes(),
				})
			},
		},
		{
			name:          "invalid curve",
			isServer:      false,
			expectedError: ErrNoType,
			keyExchange: func(ctx context.Context, c net.Conn) error {
				return json.NewEncoder(c).Encode(TransportRequest{
					Version:   TransportVersion,
					PublicKey: []byte("invalid"),
				})
			},
		},
	}
	for _, tti := range tests {
		t.Run(tti.name, func(t *testing.T) {
			var (
				transport              *Transport
				serverConn, clientConn net.Conn
				wg                     sync.WaitGroup
				err                    error
			)
			if tti.isServer {
				transport, err = NewTransportFromCurve(tti.curve)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				transport = new(Transport)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 9*time.Second)
			defer cancel()

			// Server
			l := net.ListenConfig{}
			listener, err := l.Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port

			// Server conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				var cerr error
				serverConn, cerr = listener.Accept()
				if cerr != nil {
					panic(err)
				}
			}()

			// Client conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				var cerr error
				d := &net.Dialer{}
				clientConn, cerr = d.DialContext(ctx, "tcp",
					net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if cerr != nil {
					panic(err)
				}
			}()

			wg.Wait()

			go func() {
				if err := tti.keyExchange(ctx, clientConn); err != nil {
					panic(err)
				}
			}()

			err = transport.KeyExchange(ctx, serverConn)
			if err != nil {
				if errors.Is(err, tti.expectedError) ||
					errors.Is(tti.expectedError, ErrNoType) {
					return
				}
			}
			t.Fatalf("expected error %v, got %v", tti.expectedError, err)
		})
	}
}

func TestHandshakeErrors(t *testing.T) {
	type testTableItem struct {
		name          string
		curve         ecdh.Curve
		handshake     func(context.Context, *Transport, *Secret) error
		expectedError error
	}
	ErrNoType := errors.New("any error")
	tests := []testTableItem{
		{
			name:          "unsupported version",
			curve:         ecdh.P256(),
			expectedError: ErrUnsupportedVersion,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				return tr.Write(s.Identity, HelloRequest{
					Version:   0,
					Challenge: ourChallenge[:],
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				})
			},
		},
		{
			name:          "invalid challenge",
			curve:         ecdh.P256(),
			expectedError: ErrInvalidChallenge,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				return tr.Write(s.Identity, HelloRequest{
					Version: ProtocolVersion,
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				})
			},
		},
		{
			name:          "zero challenge",
			curve:         ecdh.P256(),
			expectedError: ErrInvalidChallenge,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				return tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ZeroChallenge[:],
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				})
			},
		},
		{
			name:          "malformed signature",
			curve:         ecdh.P256(),
			expectedError: ErrNoType,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				if err := tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				}); err != nil {
					return err
				}
				return tr.Write(s.Identity, HelloResponse{
					Signature: []byte("invalid"),
				})
			},
		},
		{
			name:          "uncompact signature",
			curve:         ecdh.P256(),
			expectedError: ErrNotCompact,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				if err := tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				}); err != nil {
					return err
				}
				sig := ecdsa.SignCompact(s.privateKey, []byte("test"), false)
				return tr.Write(s.Identity, HelloResponse{
					Signature: sig,
				})
			},
		},
		{
			name:          "invalid encryption",
			curve:         ecdh.P256(),
			expectedError: ErrDecrypt,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				nonce := tr.nonce.Next()
				msg := []byte("test")
				var size [4]byte
				binary.BigEndian.PutUint32(size[:], uint32(len(msg)+len(nonce)))
				header := append(size[1:4], nonce[0:24]...)
				_, err := tr.conn.Write(append(header, msg...))
				return err
			},
		},
		{
			name:          "unexpected cmd",
			curve:         ecdh.P256(),
			expectedError: ErrNoType,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				return tr.Write(s.Identity, HelloResponse{
					Signature: []byte("invalid"),
				})
			},
		},
	}
	for _, tti := range tests {
		t.Run(tti.name, func(t *testing.T) {
			var (
				serverConn, clientConn net.Conn
				wg                     sync.WaitGroup
				err                    error
			)

			serverTransport, err := NewTransportFromCurve(tti.curve)
			if err != nil {
				t.Fatal(err)
			}

			serverSecret, err := NewSecret()
			if err != nil {
				t.Fatal(err)
			}

			clientTransport := new(Transport)

			clientSecret, err := NewSecret()
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 9*time.Second)
			defer cancel()

			// Server
			l := net.ListenConfig{}
			listener, err := l.Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port

			// Server conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				var cerr error
				serverConn, cerr = listener.Accept()
				if cerr != nil {
					panic(err)
				}
			}()

			// Client conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				var cerr error
				d := &net.Dialer{}
				clientConn, cerr = d.DialContext(ctx, "tcp",
					net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if cerr != nil {
					panic(err)
				}
			}()

			wg.Wait()

			t.Logf("%s: %s", serverTransport, serverConn.LocalAddr())
			t.Logf("%s: %s", clientTransport, clientConn.LocalAddr())

			// Server conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := serverTransport.KeyExchange(ctx, serverConn)
				if err != nil {
					panic(err)
				}
			}()

			// Client conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := clientTransport.KeyExchange(ctx, clientConn)
				if err != nil {
					panic(err)
				}
			}()

			wg.Wait()

			go func() {
				err := tti.handshake(ctx, clientTransport, clientSecret)
				if err != nil {
					panic(err)
				}
			}()

			_, err = serverTransport.Handshake(ctx, serverSecret)
			if err != nil {
				if errors.Is(err, tti.expectedError) ||
					errors.Is(tti.expectedError, ErrNoType) {
					return
				}
			}
			t.Fatalf("expected error %v, got %v", tti.expectedError, err)
		})
	}
}

func TestTestConnHandshakeDNS(t *testing.T) {
	curves := []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521(), ecdh.X25519()}
	for _, curve := range curves {
		testName := fmt.Sprintf("%v", curve)
		t.Run(testName, func(t *testing.T) {
			nodes := byte(2)
			dnsPort := testutil.FreePort()
			dnsAddress := "127.0.1.1:" + dnsPort
			domain := "moop.gfy"
			handler := createDNSNodes(domain, nodes)
			go func() { newDNSServer(dnsAddress, handler) }()
			waitForDNSServer(dnsAddress, t)
			r := newResolver(dnsAddress)

			node1 := handler.nodes["node1.moop.gfy."]
			serverSecret := node1.Secret
			node2 := handler.nodes["node2.moop.gfy."]
			clientSecret := node2.Secret

			// log.Infof("server identity: %v", serverSecret)
			// log.Infof("client identity: %v", clientSecret)

			// Server
			serverTransport, err := NewTransportFromCurve(curve)
			if err != nil {
				t.Fatal(err)
			}

			// Create blank transport
			clientTransport := new(Transport)

			ctx, cancel := context.WithTimeout(t.Context(), 9*time.Second)
			defer cancel()
			var wg sync.WaitGroup

			// Server
			l := net.ListenConfig{}
			listener, err := l.Listen(ctx, "tcp", net.JoinHostPort(node1.IP.String(), "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port

			var clientAddress net.Addr // We obtain client IP when we accept a connection.
			wg.Add(1)
			go func() {
				defer wg.Done()

				t.Logf("Listening: %v:%v", node1.IP, port)
				conn, err := listener.Accept()
				if err != nil {
					panic(err)
				}
				clientAddress = conn.RemoteAddr()

				if err := serverTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}
			}()

			// Client
			wg.Add(1)
			go func() {
				defer wg.Done()

				addr, err := net.ResolveTCPAddr("tcp",
					net.JoinHostPort(node2.IP.String(), "0"))
				if err != nil {
					panic(err)
				}
				d := &net.Dialer{LocalAddr: addr}
				conn, err := d.DialContext(ctx, "tcp",
					net.JoinHostPort(node1.IP.String(), strconv.Itoa(port)))
				if err != nil {
					panic(err)
				}

				if err := clientTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}
			}()

			wg.Wait()

			if !bytes.Equal(serverTransport.encryptionKey[:],
				clientTransport.encryptionKey[:]) {
				t.Fatal("derived shared key not equal")
			}

			// Handshake
			var derivedClient, derivedServer *Identity

			wg.Add(1)
			go func() {
				defer wg.Done()

				var err error // prevent data race
				derivedClient, err = serverTransport.Handshake(ctx, serverSecret)
				if err != nil {
					panic(err)
				}
				// log.Infof("derived client: %v", derivedClient)

				// Perform DNS test
				ok, err := VerifyRemoteDNSIdentity(ctx, r, clientAddress,
					*derivedClient)
				if err != nil {
					panic(err)
				}
				if !ok {
					panic("client dns")
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()

				defer func() {
					if err := clientTransport.Close(); err != nil {
						panic(err)
					}
				}()

				var err error // prevent data race
				derivedServer, err = clientTransport.Handshake(ctx, clientSecret)
				if err != nil {
					panic(err)
				}

				// log.Infof("derived server: %v", derivedServer)

				// Perform DNS test
				ok, err := VerifyRemoteDNSIdentity(ctx, r, listener.Addr(),
					*derivedServer)
				if err != nil {
					panic(err)
				}
				if !ok {
					panic("server dns")
				}
			}()

			wg.Wait()

			if derivedServer.String() != serverSecret.String() {
				t.Fatalf("derived server got %v, want %v",
					derivedServer, serverSecret.Identity)
			}
			if derivedClient.String() != clientSecret.String() {
				t.Fatalf("derived client got %v, want %v",
					derivedClient, clientSecret.Identity)
			}
		})
	}
}

func TestConnHandshake(t *testing.T) {
	curves := []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521(), ecdh.X25519()}
	for _, curve := range curves {
		testName := fmt.Sprintf("%v", curve)
		t.Run(testName, func(t *testing.T) {
			serverTransport, err := NewTransportFromCurve(curve)
			if err != nil {
				t.Fatal(err)
			}
			serverSecret, err := NewSecret()
			if err != nil {
				t.Fatal(err)
			}

			// Create transport from server public key
			clientTransport := new(Transport)
			clientSecret, err := NewSecret()
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 9*time.Second)
			defer cancel()
			var wg sync.WaitGroup

			// Server
			l := net.ListenConfig{}
			listener, err := l.Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port

			wg.Add(1)
			go func() {
				defer wg.Done()

				t.Logf("Listening: %v", port)
				conn, err := listener.Accept()
				if err != nil {
					panic(err)
				}

				if err := serverTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}
			}()

			// Client
			wg.Add(1)
			go func() {
				defer wg.Done()

				addr, err := net.ResolveTCPAddr("tcp",
					net.JoinHostPort("127.0.0.1", "0"))
				if err != nil {
					panic(err)
				}
				d := &net.Dialer{LocalAddr: addr}
				conn, err := d.DialContext(ctx, "tcp",
					net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if err != nil {
					panic(err)
				}

				if err := clientTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}
			}()

			wg.Wait()

			if !bytes.Equal(serverTransport.encryptionKey[:],
				clientTransport.encryptionKey[:]) {
				t.Fatal("derived shared key not equal")
			}

			// Handshake
			var derivedClient, derivedServer *Identity

			wg.Add(1)
			go func() {
				defer wg.Done()

				var err error

				derivedClient, err = serverTransport.Handshake(ctx, serverSecret)
				if err != nil {
					panic(err)
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()

				var err error

				defer func() {
					if err := clientTransport.Close(); err != nil {
						panic(err)
					}
				}()

				derivedServer, err = clientTransport.Handshake(ctx, clientSecret)
				if err != nil {
					panic(err)
				}
			}()

			wg.Wait()

			if derivedServer.String() != serverSecret.String() {
				t.Fatalf("derived server got %v, want %v",
					derivedServer, serverSecret.Identity)
			}
			if derivedClient.String() != clientSecret.String() {
				t.Fatalf("derived client got %v, want %v",
					derivedClient, clientSecret.Identity)
			}
		})
	}
}

func TestDNSServerSetup(t *testing.T) {
	nodes := byte(200)
	dnsAddress := "127.0.0.1:5353"
	domain := "moop.gfy"
	handler := createDNSNodes(domain, nodes)
	go func() { newDNSServer(dnsAddress, handler) }()
	waitForDNSServer(dnsAddress, t)
	r := newResolver(dnsAddress)

	// Lookup all nodes
	for k, v := range handler.nodes {
		addr, err := r.LookupAddr(t.Context(), v.IP.String())
		if err != nil {
			t.Fatal(err)
		}
		// Verify reverse record
		if v.DNSName != addr[0] {
			t.Fatalf("got %v wanted %v", addr[0], v.DNSName)
		}

		ip, err := r.LookupHost(t.Context(), k)
		if err != nil {
			t.Fatal(err)
		}
		if ip[0] != v.IP.String() {
			t.Fatalf("got %v wanted %v", ip[0], v.IP.String())
		}

		txtRecords, err := r.LookupTXT(t.Context(), k)
		if err != nil {
			t.Fatal(err)
		}
		txtExpected := fmt.Sprintf("v=%v identity=%v port=%v",
			dnsAppName, v.Secret.Identity, defaultPort)
		if txtRecords[0] != txtExpected {
			t.Fatalf("got %v, wanted %v", txtRecords[0], txtExpected)
		}
		a, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(v.IP.String(), "0"))
		if err != nil {
			t.Fatal(err)
		}
		ok, err := VerifyRemoteDNSIdentity(t.Context(), r, a, v.Secret.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("not verified identity: %v", v.IP)
		}
	}
}

func TestSecret(t *testing.T) {
	pk, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// New Secret
	_, err = NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Secret from string
	_, err = NewSecretFromString(pk.Key.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSecretFromString("l337")
	if err == nil {
		t.Fatal("expected error")
	}
	fakePkS := hex.EncodeToString([]byte("fake"))
	_, err = NewSecretFromString(fakePkS)
	if err == nil {
		t.Fatal("expected error")
	}

	// Secret from private
	s := NewSecretFromPrivate(pk)
	if !s.PublicKey().IsEqual(pk.PubKey()) {
		t.Fatalf("pubKey mismatch: %v != %v", s.PublicKey(), pk.PubKey())
	}

	// Test sign and recovering
	hash := []byte("testhash")
	sig := s.Sign(hash)
	recPub, err := Verify(hash, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !recPub.IsEqual(pk.PubKey()) {
		t.Fatalf("pubKey mismatch: %v != %v", recPub, pk.PubKey())
	}
}

func TestIdentity(t *testing.T) {
	pk, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Identity from public key
	id := NewIdentityFromPub(pk.PubKey())

	// Identity from string
	ids, err := NewIdentityFromString(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ids.Bytes(), id.Bytes()) {
		t.Fatalf("identities mismatch: %v != %v", ids, id)
	}
	_, err = NewIdentityFromString("fail")
	if err == nil {
		t.Fatal("expected error")
	}
	fakeID := hex.EncodeToString([]byte("fake"))
	_, err = NewIdentityFromString(fakeID)
	if err == nil {
		t.Fatal("expected error")
	}

	// Unmarshal Identity
	idm := Identity{}
	marshaledID, err := id.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := idm.UnmarshalJSON([]byte("fake")); err == nil {
		t.Fatal("expected error")
	}
	if err := idm.UnmarshalJSON(marshaledID); err != nil {
		t.Fatal(err)
	}

	// Recover Identity
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
	if !bytes.Equal(NewIdentityFromPub(rec2).Bytes(), s1.Bytes()) {
		t.Fatal("recovery failed in 1")
	}
	if !bytes.Equal(NewIdentityFromPub(rec1).Bytes(), s2.Bytes()) {
		t.Fatal("recovery failed in 2")
	}
}
