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

//func TestEncryptDecrypt(t *testing.T) {
//	for i := 0; i < 33; i++ {
//		server, err := NewTransportServer(CurveX25519, "")
//		if err != nil {
//			t.Fatal(err)
//		}
//		client, err := NewTransportClient("")
//		if err != nil {
//			t.Fatal(err)
//		}
//
//		// Set keys to simulate incomming key exchange message
//		//server.them, err = server.curve.NewPublicKey(client.us.PublicKey().Bytes())
//		//if err != nil {
//		//	t.Fatal(err)
//		//}
//		//client.them, err = client.curve.NewPublicKey(server.us.PublicKey().Bytes())
//		//if err != nil {
//		//	t.Fatal(err)
//		//}
//
//		// Perform actual key exchange
//		encryptionKeyServer, err := kx(server.us, client.us.PublicKey())
//		if err != nil {
//			t.Fatal(err)
//		}
//		encryptionKeyClient, err := kx(client.us, server.us.PublicKey())
//		if err != nil {
//			t.Fatal(err)
//		}
//
//		if !bytes.Equal(encryptionKeyServer[:], encryptionKeyClient[:]) {
//			t.Fatal("shared key not equal")
//		}
//
//		message := []byte("this is a super secret message y'all!")
//		em, err := server.encrypt(message)
//		if err != nil {
//			t.Fatal(err)
//		}
//		cleartext, err := client.decrypt(em[3:]) // clip size that is done by read normally
//		if err != nil {
//			t.Fatal(err)
//		}
//		if !bytes.Equal(message, cleartext) {
//			t.Fatal("message not equal")
//		}
//	}
//}
//
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

func NewTransportFromCurve(curve ecdh.Curve) (*Transport, error) {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Transport{
		curve: curve,
		us:    privateKey,
	}, nil
}

func NewTransportFromPublicKey(publicKey []byte) (*Transport, error) {
	curves := []ecdh.Curve{ecdh.X25519(), ecdh.P521(), ecdh.P384(), ecdh.P256()}
	for _, curve := range curves {
		theirPublicKey, err := curve.NewPublicKey(publicKey)
		if err != nil {
			continue
		}

		privateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &Transport{
			curve: curve,
			us:    privateKey,
			them:  theirPublicKey,
		}, nil
	}

	return nil, ErrNoSuitableCurve
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
	clientTransport, err := NewTransportFromPublicKey(serverPublicKey)
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
	serverTransport, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	// Send public key to client
	serverPublicKey := serverTransport.us.PublicKey().Bytes()

	// Create transport from server public key
	clientTransport, err := NewTransportFromPublicKey(serverPublicKey)
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
		defer func() {
			if err := clientTransport.Close(); err != nil {
				panic(err)
			}
		}()

		if err := clientTransport.KeyExchange(ctx, conn); err != nil {
			panic(err)
		}
	}()

	wg.Wait()

	if !bytes.Equal(serverTransport.encryptionKey[:],
		clientTransport.encryptionKey[:]) {
		t.Fatal("derived shared key not equal")
	}
}

func TestConnHandshake(t *testing.T) {
	serverTransport, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}
	serverSecret, err := NewSecret()

	// Send public key to client
	serverPublicKey := serverTransport.us.PublicKey().Bytes()

	// Create transport from server public key
	clientTransport, err := NewTransportFromPublicKey(serverPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	clientSecret, err := NewSecret()

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
	wg.Add(1)
	go func() {
		defer wg.Done()

		// XXX store id and verify after handshake
		log.Infof("server handshake complete")
		if _, err := serverTransport.Handshake(ctx, serverSecret); err != nil {
			panic(err)
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

		// XXX store id and verify after handshake
		if _, err := clientTransport.Handshake(ctx, clientSecret); err != nil {
			panic(err)
		}
	}()

	wg.Wait()
	t.Logf("handshake complete")
}
