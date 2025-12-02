// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
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

//func TestNewCommand(t *testing.T) {
//	helloChallenge := make([]byte, 32)
//	helloRequest := &HelloRequest{
//		Version:   TransportVersion,
//		Options:   nil,
//		Challenge: helloChallenge,
//	}
//	m := make(map[reflect.Type]PayloadType)
//	m[reflect.TypeOf(helloRequest)] = PHelloRequest
//	t.Logf("%v", m[reflect.TypeOf(helloRequest)])
//
//	hash, payload, err := NewPayloadFromCommand(helloRequest)
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Logf("%v", spew.Sdump(hash))
//	t.Logf("%v", spew.Sdump(payload))
//
//	var x any = helloRequest
//	header := Header{
//		PayloadType: m[reflect.TypeOf(x)],
//		PayloadHash: *hash,
//	}
//	t.Logf("header: %v", spew.Sdump(header))
//	jh, err := json.Marshal(header)
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Logf("%v", spew.Sdump(append(jh, payload...)))
//}

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
	// XXX do all curves
	serverTransport, err := NewTransportFromCurve(ecdh.X25519())
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
}

//func TestTestConnHandshakeDNS(t *testing.T) {
//	nodes := byte(2)
//	dnsAddress := "127.0.1.1:5353" // XXX make this :0 somehow
//	domain := "moop.gfy"
//	handler := createDNSNodes(domain, nodes)
//	go func() { newDNSServer(dnsAddress, handler) }()
//	waitForDNSServer(dnsAddress, t)
//	r := newResolver(dnsAddress, t)
//
//	node1 := handler.nodes["node1.moop.gfy."]
//	serverSecret := node1.Secret
//	node2 := handler.nodes["node2.moop.gfy."]
//	clientSecret := node1.Secret
//
//	// Mostly the same as TestConnHandshake, this should be rolled up into
//	// one bigger test.
//	serverTransport, err := NewTransportFromCurve(ecdh.X25519())
//	if err != nil {
//		t.Fatal(err)
//	}
//}

func TestConnHandshake(t *testing.T) {
	curves := []string{CurveP256, CurveP384, CurveP521, CurveX25519}
	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			cr, err := str2Curve(curve)
			if err != nil {
				t.Fatal(err)
			}
			serverTransport, err := NewTransportFromCurve(cr)
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

			if derivedServer.String() != serverSecret.Identity.String() {
				t.Fatalf("derived server got %v, want %v",
					derivedServer, serverSecret.Identity)
			}
			if derivedClient.String() != clientSecret.Identity.String() {
				t.Fatalf("derived client got %v, want %v",
					derivedClient, clientSecret.Identity)
			}
		})
	}
}

func str2Curve(name string) (ecdh.Curve, error) {
	switch name {
	case CurveP256:
		return ecdh.P256(), nil
	case CurveP384:
		return ecdh.P384(), nil
	case CurveP521:
		return ecdh.P521(), nil
	case CurveX25519:
		return ecdh.X25519(), nil
	default:
	}
	return nil, ErrNoSuitableCurve
}
