// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/davecgh/go-spew/spew"
	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/api/protocol"
)

func TestHandshakeSignatureCrypto(t *testing.T) {
	privKey, err := dcrsecpk256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKey := privKey.PubKey()

	message := "Hello, World!"
	sigHash := sha256.Sum256([]byte(message))
	sig := dcrecdsa.SignCompact(privKey, sigHash[:], true)
	derived, _, err := dcrecdsa.RecoverCompact(sig, sigHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if !derived.IsEqual(pubKey) {
		t.Fatal("not the same key")
	}
}

func TestHandshake(t *testing.T) {
	// client generated private and public keys
	privKey, err := dcrsecpk256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKey := privKey.PubKey()

	// client sends hello
	h := &Secp256k1Hello{
		PublicKey: hex.EncodeToString(pubKey.SerializeCompressed()),
	}
	clientPubKey, am, hc, err := handleSecp256k1Hello("I am not a robot!", h)
	if err != nil {
		t.Fatal(err)
	}

	// client signs challenge from the server
	hca, err := handleSecp256k1HelloChallenge(privKey, hc)
	if err != nil {
		t.Fatal(err)
	}

	// server verifies challenge
	derived, err := handleSecp256k1HelloChallengeAccepted(am, hca)
	if err != nil {
		t.Fatal(err)
	}

	// server verifies if signer is identical to the derived key
	if !derived.IsEqual(clientPubKey) {
		t.Fatal("derived key is not the same as the advertised client key")
	}
}

func server(t *testing.T, want *int64) *httptest.Server {
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		t.Logf("websocket")
		defer t.Logf("websocket done")

		wao := &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionContextTakeover,
			OriginPatterns:  []string{"localhost"},
		}
		conn, err := websocket.Accept(w, r, wao)
		if err != nil {
			t.Fatalf("Failed to accept websocket connection for %v: %v",
				r.RemoteAddr, err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		pconn := protocol.NewWSConn(conn)

		// Start handshake
		serverAuth, err := NewSecp256k1AuthServer()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("server handshake starting")
		ctx := context.TODO()
		err = serverAuth.HandshakeServer(ctx, pconn)
		if err != nil {
			t.Fatalf("Failed to handshake connection for %v: %v",
				r.RemoteAddr, err)
		}
		t.Logf("server connected to: %x",
			serverAuth.RemotePublicKey().SerializeCompressed())

		// Handshake complete, do required protocol ping
		err = bssapi.Write(ctx, pconn, "requiredpingid", &bssapi.PingRequest{})
		if err != nil {
			t.Fatalf("write required ping: %v", err)
		}

		// Do a ping pong now
		_, _, payload, err := bssapi.Read(ctx, pconn)
		if err != nil {
			t.Fatalf("read ping: %v", err)
		}
		t.Logf("server responding to ping %v", spew.Sdump(payload))
		*want = payload.(*bssapi.PingRequest).Timestamp
		err = bssapi.Write(ctx, pconn, "pingid", &bssapi.PingResponse{
			Timestamp: *want,
		})
		if err != nil {
			t.Fatalf("write ping: %v", err)
		}
	}

	httpServer := httptest.NewServer(http.HandlerFunc(handlerFunc))
	return httpServer
}

func TestProtocolHandshake(t *testing.T) {
	var want int64
	testServer := server(t, &want) // launch server

	// client generated private and public keys
	privKey, err := dcrsecpk256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	clientAuth, err := NewSecp256k1AuthClient(privKey)
	if err != nil {
		t.Fatal(err)
	}

	clientURI := testServer.URL
	conn, err := protocol.NewConn(clientURI, &protocol.ConnOptions{
		Authenticator: clientAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.TODO()
	t.Logf("connect %v", clientURI)
	err = conn.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("connected %v", clientURI)

	t.Logf("client writing ping")
	err = bssapi.Write(ctx, conn, "ping-id", bssapi.PingRequest{
		Timestamp: time.Now().Unix(),
	})
	_, _, payload, err := bssapi.Read(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client read ping %v", spew.Sdump(payload))
	got := payload.(*bssapi.PingResponse).Timestamp
	if want != got {
		t.Fatalf("unexpected ping response want %v got %v", want, got)
	}
}
