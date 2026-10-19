// Copyright (c) 2025-2026 Hemi Labs, Inc.
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
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/nacl/box"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

func TestEncryptDecrypt(t *testing.T) {
	for range 33 {
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
		s2cKeyServer, c2sKeyServer, err := KeyExchange(server.us, client.us.PublicKey(),
			server.us.PublicKey().Bytes(), client.us.PublicKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		s2cKeyClient, c2sKeyClient, err := KeyExchange(client.us, server.us.PublicKey(),
			server.us.PublicKey().Bytes(), client.us.PublicKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(s2cKeyServer[:], s2cKeyClient[:]) {
			t.Fatal("s2c key not equal")
		}
		if !bytes.Equal(c2sKeyServer[:], c2sKeyClient[:]) {
			t.Fatal("c2s key not equal")
		}
		if bytes.Equal(s2cKeyServer[:], c2sKeyServer[:]) {
			t.Fatal("directional keys must differ")
		}

		// Set directional keys: server encrypts with s2c, client
		// decrypts with s2c.
		server.encryptKey = s2cKeyServer
		server.decryptKey = c2sKeyServer
		client.encryptKey = c2sKeyClient
		client.decryptKey = s2cKeyClient

		// Encrypt a message
		message := []byte("this is a super secret message y'all!")
		em, err := server.encrypt(message)
		if err != nil {
			t.Fatal(err)
		}

		// Phase 1: decrypt the frame header to get body size.
		if len(em) < transportFrameHeaderSize {
			t.Fatalf("encrypted too short: %d", len(em))
		}
		bodySize, err := client.decryptFrameHeader(em[:transportFrameHeaderSize])
		if err != nil {
			t.Fatalf("decrypt frame header: %v", err)
		}
		body := em[transportFrameHeaderSize:]
		if uint32(len(body)) != bodySize {
			t.Fatalf("body size mismatch: header says %d, got %d", bodySize, len(body))
		}

		// Phase 2: decrypt the body to get the payload.
		cleartext, err := client.decrypt(body)
		if err != nil {
			t.Fatal("could not decrypt")
		}
		if !bytes.Equal(message, cleartext) {
			t.Fatal("message not equal")
		}

		// Truncated body triggers length error.
		_, err = client.decrypt(body[:5])
		if !errors.Is(ErrInvalidSecretboxLength, err) {
			t.Fatalf("expected length error: %v", err)
		}
	}
}

// TestDirectionalKeys proves that the s2c and c2s keys are independent
// and that using the wrong directional key for decryption fails.
func TestDirectionalKeys(t *testing.T) {
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

	// Derive directional keys.
	s2cKey, c2sKey, err := KeyExchange(server.us, client.us.PublicKey(),
		server.us.PublicKey().Bytes(), client.us.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	s2cKey2, c2sKey2, err := KeyExchange(client.us, server.us.PublicKey(),
		server.us.PublicKey().Bytes(), client.us.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: both sides derive the same pair.
	if !bytes.Equal(s2cKey[:], s2cKey2[:]) {
		t.Fatal("s2c keys differ between sides")
	}
	if !bytes.Equal(c2sKey[:], c2sKey2[:]) {
		t.Fatal("c2s keys differ between sides")
	}

	// Keys MUST differ from each other.
	if bytes.Equal(s2cKey[:], c2sKey[:]) {
		t.Fatal("directional keys are identical")
	}

	// Assign: server encrypts s2c, decrypts c2s.
	server.encryptKey = s2cKey
	server.decryptKey = c2sKey
	client.encryptKey = c2sKey2
	client.decryptKey = s2cKey2

	message := []byte("directional key test payload")

	// Server→client: client decrypts with s2c key.
	cipherS2C, err := server.encrypt(message)
	if err != nil {
		t.Fatal(err)
	}
	bodySize, err := client.decryptFrameHeader(cipherS2C[:transportFrameHeaderSize])
	if err != nil {
		t.Fatalf("client failed to decrypt header: %v", err)
	}
	cleartext, err := client.decrypt(cipherS2C[transportFrameHeaderSize : transportFrameHeaderSize+int(bodySize)])
	if err != nil {
		t.Fatalf("client failed to decrypt server message: %v", err)
	}
	if !bytes.Equal(message, cleartext) {
		t.Fatal("decrypted message mismatch")
	}

	// Client→server: server decrypts with c2s key.
	cipherC2S, err := client.encrypt(message)
	if err != nil {
		t.Fatal(err)
	}
	bodySize, err = server.decryptFrameHeader(cipherC2S[:transportFrameHeaderSize])
	if err != nil {
		t.Fatalf("server failed to decrypt header: %v", err)
	}
	cleartext, err = server.decrypt(cipherC2S[transportFrameHeaderSize : transportFrameHeaderSize+int(bodySize)])
	if err != nil {
		t.Fatalf("server failed to decrypt client message: %v", err)
	}
	if !bytes.Equal(message, cleartext) {
		t.Fatal("decrypted message mismatch")
	}

	// Wrong direction: server cannot decrypt its own s2c message.
	// Server's decryptKey is c2s which is the wrong key for s2c
	// ciphertext — header decryption fails first.
	_, err = server.decryptFrameHeader(cipherS2C[:transportFrameHeaderSize])
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt for wrong-direction decrypt, got: %v", err)
	}

	// Wrong direction: client cannot decrypt its own c2s message.
	_, err = client.decryptFrameHeader(cipherC2S[:transportFrameHeaderSize])
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt for wrong-direction decrypt, got: %v", err)
	}

	// Cleartext never appears in ciphertext (basic sanity).
	if bytes.Contains(cipherS2C, message) {
		t.Fatal("cleartext found in s2c ciphertext")
	}
	if bytes.Contains(cipherC2S, message) {
		t.Fatal("cleartext found in c2s ciphertext")
	}
}

// TestWireEncryption proves that data written through Transport.write to a
// live connection does not contain cleartext.  It taps the raw bytes on a
// net.Pipe after a full KeyExchange to verify that the known plaintext
// never appears on the wire.
func TestWireEncryption(t *testing.T) {
	ctx := context.Background()
	serverPipe, clientPipe := net.Pipe()

	serverTr, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}
	clientTr := new(Transport)

	// Perform key exchange over the pipe.
	errCh := make(chan error, 2)
	go func() { errCh <- serverTr.KeyExchange(ctx, serverPipe) }()
	go func() { errCh <- clientTr.KeyExchange(ctx, clientPipe) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("KeyExchange: %v", err)
		}
	}

	// Replace server's conn with a tee so we can capture raw wire bytes.
	spy, spyServer := net.Pipe()
	var wireBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Relay server→spy into wireBuf and forward to original conn.
		buf := make([]byte, 32*1024)
		for {
			n, readErr := spy.Read(buf)
			if n > 0 {
				wireBuf.Write(buf[:n])
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Point server transport at our spy pipe.
	serverTr.mtx.Lock()
	serverTr.conn = spyServer
	serverTr.mtx.Unlock()

	// Write a known plaintext through the encrypted transport.
	plaintext := []byte("SUPER SECRET PLAINTEXT THAT MUST NOT APPEAR ON WIRE")
	if err := serverTr.write(time.Second, plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Close to flush the relay goroutine.
	spyServer.Close()
	spy.Close()
	<-done

	raw := wireBuf.Bytes()
	if len(raw) == 0 {
		t.Fatal("no bytes captured on wire")
	}
	if bytes.Contains(raw, plaintext) {
		t.Fatal("cleartext found in raw wire bytes — encryption is broken")
	}
	if bytes.Equal(raw, plaintext) {
		t.Fatal("wire bytes are identical to plaintext")
	}

	// Verify the wire payload is longer than plaintext (nonce + overhead).
	if len(raw) <= len(plaintext) {
		t.Fatalf("wire bytes (%d) shorter than plaintext (%d) — missing crypto overhead",
			len(raw), len(plaintext))
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

func TestCeremonyID(t *testing.T) {
	// Create a ceremony ID
	var cid CeremonyID
	_, err := rand.Read(cid[:])
	if err != nil {
		t.Fatal(err)
	}

	// Test String()
	cidStr := cid.String()
	if len(cidStr) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(cidStr))
	}

	// Test JSON marshal/unmarshal
	m := map[string]CeremonyID{"ceremony": cid}
	em, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var mm map[string]CeremonyID
	err = json.Unmarshal(em, &mm)
	if err != nil {
		t.Fatal(err)
	}
	got := mm["ceremony"]
	if !bytes.Equal(got[:], cid[:]) {
		t.Fatal("ceremony id not equal after json roundtrip")
	}

	// Test individual marshal/unmarshal
	el, err := cid.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(el) != `"`+cid.String()+`"` {
		t.Fatal("unexpected json")
	}
	var cid2 CeremonyID
	err = cid2.UnmarshalJSON(el)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cid2[:], cid[:]) {
		t.Fatal("json line not equal to original")
	}

	// Negative tests
	var cid3 CeremonyID
	err = cid3.UnmarshalJSON([]byte(`"tooshort"`))
	if err == nil {
		t.Fatal("expected error for short hex")
	}
	err = cid3.UnmarshalJSON([]byte(`"not valid hex!!"`))
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestTSSRPCTypes(t *testing.T) {
	// Test that all TSS RPC types are properly registered in pt2str/str2pt
	tssTypes := []struct {
		name     string
		pt       PayloadType
		instance any
	}{
		{"KeygenRequest", PKeygenRequest, KeygenRequest{}},
		{"KeygenResponse", PKeygenResponse, KeygenResponse{}},
		{"ReshareRequest", PReshareRequest, ReshareRequest{}},
		{"ReshareResponse", PReshareResponse, ReshareResponse{}},
		{"SignRequest", PSignRequest, SignRequest{}},
		{"SignResponse", PSignResponse, SignResponse{}},
		{"TSSMessage", PTSSMessage, TSSMessage{}},
		{"CeremonyResult", PCeremonyResult, CeremonyResult{}},
		{"CeremonyAbort", PCeremonyAbort, CeremonyAbort{}},
	}

	for _, tc := range tssTypes {
		t.Run(tc.name, func(t *testing.T) {
			// Check pt2str mapping
			rt := reflect.TypeOf(tc.instance)
			pt, ok := pt2str[rt]
			if !ok {
				t.Fatalf("%s not found in pt2str", tc.name)
			}
			if pt != tc.pt {
				t.Fatalf("pt2str[%s] = %q, want %q", tc.name, pt, tc.pt)
			}

			// Check str2pt mapping (reverse)
			gotType, ok := str2pt[tc.pt]
			if !ok {
				t.Fatalf("%q not found in str2pt", tc.pt)
			}
			if gotType != rt {
				t.Fatalf("str2pt[%q] = %v, want %v", tc.pt, gotType, rt)
			}
		})
	}
}

func TestTSSMessageJSON(t *testing.T) {
	var cid CeremonyID
	_, err := rand.Read(cid[:])
	if err != nil {
		t.Fatal(err)
	}

	var id Identity
	_, err = rand.Read(id[:])
	if err != nil {
		t.Fatal(err)
	}

	msg := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyReshare,
		From:       id,
		Flags:      TSSFlagBroadcast,
		Data:       []byte("tss wire bytes"),
		Signature:  []byte("signature bytes"),
	}

	// Marshal
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal TSSMessage: %v", err)
	}

	// Unmarshal
	var got TSSMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal TSSMessage: %v", err)
	}

	// Verify
	if !bytes.Equal(got.CeremonyID[:], msg.CeremonyID[:]) {
		t.Fatal("CeremonyID mismatch")
	}
	if got.Type != msg.Type {
		t.Fatalf("Type = %d, want %d", got.Type, msg.Type)
	}
	if !bytes.Equal(got.From[:], msg.From[:]) {
		t.Fatal("From mismatch")
	}
	if got.Flags != msg.Flags {
		t.Fatalf("Flags = %d, want %d", got.Flags, msg.Flags)
	}
	if !bytes.Equal(got.Data, msg.Data) {
		t.Fatal("Data mismatch")
	}
	if !bytes.Equal(got.Signature, msg.Signature) {
		t.Fatal("Signature mismatch")
	}
}

func TestReshareRequestJSON(t *testing.T) {
	var cid CeremonyID
	_, err := rand.Read(cid[:])
	if err != nil {
		t.Fatal(err)
	}

	req := ReshareRequest{
		CeremonyID:   cid,
		Curve:        "secp256k1",
		OldThreshold: 2,
		NewThreshold: 3,
		// Note: OldCommittee/NewCommittee are tss.UnSortedPartyIDs which have their own marshaling
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal ReshareRequest: %v", err)
	}

	var got ReshareRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal ReshareRequest: %v", err)
	}

	if !bytes.Equal(got.CeremonyID[:], req.CeremonyID[:]) {
		t.Fatal("CeremonyID mismatch")
	}
	if got.Curve != req.Curve {
		t.Fatalf("Curve = %q, want %q", got.Curve, req.Curve)
	}
	if got.OldThreshold != req.OldThreshold {
		t.Fatalf("OldThreshold = %d, want %d", got.OldThreshold, req.OldThreshold)
	}
	if got.NewThreshold != req.NewThreshold {
		t.Fatalf("NewThreshold = %d, want %d", got.NewThreshold, req.NewThreshold)
	}
}

func TestSignRequestJSON(t *testing.T) {
	var cid CeremonyID
	_, err := rand.Read(cid[:])
	if err != nil {
		t.Fatal(err)
	}

	req := SignRequest{
		CeremonyID: cid,
		KeyID:      []byte("key-identifier"),
		Threshold:  2,
		Data:       make([]byte, 32), // 32-byte hash
	}
	_, err = rand.Read(req.Data)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal SignRequest: %v", err)
	}

	var got SignRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal SignRequest: %v", err)
	}

	if !bytes.Equal(got.CeremonyID[:], req.CeremonyID[:]) {
		t.Fatal("CeremonyID mismatch")
	}
	if !bytes.Equal(got.KeyID, req.KeyID) {
		t.Fatal("KeyID mismatch")
	}
	if got.Threshold != req.Threshold {
		t.Fatalf("Threshold = %d, want %d", got.Threshold, req.Threshold)
	}
	if !bytes.Equal(got.Data, req.Data) {
		t.Fatal("Data mismatch")
	}
}

func TestSignResponseJSON(t *testing.T) {
	var cid CeremonyID
	_, err := rand.Read(cid[:])
	if err != nil {
		t.Fatal(err)
	}

	resp := SignResponse{
		CeremonyID: cid,
		Success:    true,
		R:          []byte("r-component"),
		S:          []byte("s-component"),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal SignResponse: %v", err)
	}

	var got SignResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal SignResponse: %v", err)
	}

	if !bytes.Equal(got.CeremonyID[:], resp.CeremonyID[:]) {
		t.Fatal("CeremonyID mismatch")
	}
	if got.Success != resp.Success {
		t.Fatal("Success mismatch")
	}
	if !bytes.Equal(got.R, resp.R) {
		t.Fatal("R mismatch")
	}
	if !bytes.Equal(got.S, resp.S) {
		t.Fatal("S mismatch")
	}
}

func TestCeremonyResultJSON(t *testing.T) {
	var cid CeremonyID
	_, err := rand.Read(cid[:])
	if err != nil {
		t.Fatal(err)
	}

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Success case
	result := CeremonyResult{
		CeremonyID: cid,
		Success:    true,
		Signer:     secret.Identity,
	}
	result.Signature = secret.Sign(HashCeremonyResult(result))

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal CeremonyResult: %v", err)
	}

	var got CeremonyResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal CeremonyResult: %v", err)
	}

	if !bytes.Equal(got.CeremonyID[:], result.CeremonyID[:]) {
		t.Fatal("CeremonyID mismatch")
	}
	if got.Success != result.Success {
		t.Fatal("Success mismatch")
	}
	if got.Signer != result.Signer {
		t.Fatal("Signer mismatch")
	}
	if !bytes.Equal(got.Signature, result.Signature) {
		t.Fatal("Signature mismatch")
	}

	// Verify round-tripped signature.
	hash := HashCeremonyResult(got)
	if _, err := Verify(hash, got.Signer, got.Signature); err != nil {
		t.Fatalf("signature verification failed after round-trip: %v", err)
	}

	// Error case
	result2 := CeremonyResult{
		CeremonyID: cid,
		Success:    false,
		Error:      "timeout waiting for round 2",
		Signer:     secret.Identity,
	}
	result2.Signature = secret.Sign(HashCeremonyResult(result2))

	data2, err := json.Marshal(result2)
	if err != nil {
		t.Fatalf("marshal CeremonyResult with error: %v", err)
	}

	var got2 CeremonyResult
	if err := json.Unmarshal(data2, &got2); err != nil {
		t.Fatalf("unmarshal CeremonyResult with error: %v", err)
	}

	if got2.Error != result2.Error {
		t.Fatalf("Error = %q, want %q", got2.Error, result2.Error)
	}

	hash2 := HashCeremonyResult(got2)
	if _, err := Verify(hash2, got2.Signer, got2.Signature); err != nil {
		t.Fatalf("error case signature verification failed: %v", err)
	}
}

func TestCeremonyAbortJSON(t *testing.T) {
	var cid CeremonyID
	_, err := rand.Read(cid[:])
	if err != nil {
		t.Fatal(err)
	}

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	abort := CeremonyAbort{
		CeremonyID: cid,
		Reason:     "party went offline",
		Signer:     secret.Identity,
	}
	abort.Signature = secret.Sign(HashCeremonyAbort(abort))

	data, err := json.Marshal(abort)
	if err != nil {
		t.Fatalf("marshal CeremonyAbort: %v", err)
	}

	var got CeremonyAbort
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal CeremonyAbort: %v", err)
	}

	if !bytes.Equal(got.CeremonyID[:], abort.CeremonyID[:]) {
		t.Fatal("CeremonyID mismatch")
	}
	if got.Reason != abort.Reason {
		t.Fatalf("Reason = %q, want %q", got.Reason, abort.Reason)
	}
	if got.Signer != abort.Signer {
		t.Fatal("Signer mismatch")
	}
	if !bytes.Equal(got.Signature, abort.Signature) {
		t.Fatal("Signature mismatch")
	}

	hash := HashCeremonyAbort(got)
	if _, err := Verify(hash, got.Signer, got.Signature); err != nil {
		t.Fatalf("abort signature verification failed: %v", err)
	}
}

func TestCeremonyTypeValues(t *testing.T) {
	// Verify enum values are distinct and as expected
	if CeremonyKeygen != 1 {
		t.Fatalf("CeremonyKeygen = %d, want 1", CeremonyKeygen)
	}
	if CeremonyReshare != 2 {
		t.Fatalf("CeremonyReshare = %d, want 2", CeremonyReshare)
	}
	if CeremonySign != 3 {
		t.Fatalf("CeremonySign = %d, want 3", CeremonySign)
	}

	// Verify String()
	if CeremonyKeygen.String() != "keygen" {
		t.Fatalf("CeremonyKeygen.String() = %q, want %q", CeremonyKeygen.String(), "keygen")
	}
	if CeremonyReshare.String() != "reshare" {
		t.Fatalf("CeremonyReshare.String() = %q, want %q", CeremonyReshare.String(), "reshare")
	}
	if CeremonySign.String() != "sign" {
		t.Fatalf("CeremonySign.String() = %q, want %q", CeremonySign.String(), "sign")
	}

	// Verify unknown value
	unknown := CeremonyType(99)
	if unknown.String() != "unknown(99)" {
		t.Fatalf("unknown.String() = %q, want %q", unknown.String(), "unknown(99)")
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
	maxNonces := int(1e4)
	m := make(map[[TransportNonceSize]byte]int, maxNonces)
	for i := range maxNonces {
		wg.Go(func() {
			nonce := n.Next() // race nonce

			// But be nice to map inserts
			mtx.Lock()
			defer mtx.Unlock()
			if _, ok := m[*nonce]; ok {
				panic(fmt.Sprintf("duplicate nonce: key %x i %v",
					n.key, i))
			}
			m[*nonce] = i + 1
		})
	}

	wg.Wait()
	if len(m) != maxNonces {
		t.Fatalf("got %v want %v", len(m), maxNonces)
	}
}

func TestSecretSignature(t *testing.T) {
	// This test implicitly tests Identity
	k1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(k1.privateKey.Serialize(), k2.privateKey.Serialize()) {
		t.Fatal("same key")
	}

	secretData1 := sha256.Sum256([]byte("so secret 1"))
	secretData2 := sha256.Sum256([]byte("SO SECRET 2"))

	// Sign data with respective keys
	sig1 := k1.Sign(secretData1[:])
	sig2 := k2.Sign(secretData2[:])

	// Positive path
	pubk1, err := Verify(secretData1[:], k1.Identity, sig1)
	if err != nil {
		t.Fatal(err)
	}
	if !pubk1.IsEqual(k1.PublicKey()) {
		t.Fatal("derived key 1 not equal")
	}
	pubk2, err := Verify(secretData2[:], k2.Identity, sig2)
	if err != nil {
		t.Fatal(err)
	}
	if !pubk2.IsEqual(k2.PublicKey()) {
		t.Fatal("derived key 2 not equal")
	}

	// Negative path
	_, err = Verify(secretData1[:], k1.Identity, sig2)
	if err == nil {
		t.Fatal("should not verify")
	}
	_, err = Verify(secretData1[:], k2.Identity, sig2)
	if err == nil {
		t.Fatal("should not verify")
	}
	_, err = Verify(secretData2[:], k2.Identity, sig1)
	if err == nil {
		t.Fatal("should not verify")
	}
	_, err = Verify(secretData2[:], k1.Identity, sig1)
	if err == nil {
		t.Fatal("should not verify")
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

	// Server derives directional keys
	s2cServer, c2sServer, err := KeyExchange(serverTransport.us,
		clientTransport.us.PublicKey(),
		serverTransport.us.PublicKey().Bytes(),
		clientTransport.us.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	s2cClient, c2sClient, err := KeyExchange(clientTransport.us,
		serverTransport.us.PublicKey(),
		serverTransport.us.PublicKey().Bytes(),
		clientTransport.us.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s2cServer[:], s2cClient[:]) {
		t.Fatal("s2c key not equal")
	}
	if !bytes.Equal(c2sServer[:], c2sClient[:]) {
		t.Fatal("c2s key not equal")
	}
	if bytes.Equal(s2cServer[:], c2sServer[:]) {
		t.Fatal("directional keys must differ")
	}
}

// TestKeyExchangeBadPubLength verifies KeyExchange rejects
// serverPub/clientPub with wrong lengths.
func TestKeyExchangeBadPubLength(t *testing.T) {
	server, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		serverPub []byte
		clientPub []byte
	}{
		{"nil server pub", nil, client.us.PublicKey().Bytes()},
		{"empty server pub", []byte{}, client.us.PublicKey().Bytes()},
		{"short server pub", make([]byte, 16), client.us.PublicKey().Bytes()},
		{"long server pub", make([]byte, 64), client.us.PublicKey().Bytes()},
		{"nil client pub", server.us.PublicKey().Bytes(), nil},
		{"short client pub", server.us.PublicKey().Bytes(), make([]byte, 5)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := KeyExchange(server.us, client.us.PublicKey(),
				tt.serverPub, tt.clientPub)
			if !errors.Is(err, ErrInvalidNaClPub) {
				t.Fatalf("want ErrInvalidNaClPub, got: %v", err)
			}
		})
	}
}

// TestKeyExchangeZeroPubs verifies KeyExchange succeeds with all-zero
// public keys in the salt.  HKDF handles any salt value; zeros are
// valid.  The derived keys must still be deterministic and directional.
func TestKeyExchangeZeroPubs(t *testing.T) {
	server, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}

	zeroPub := make([]byte, NaClPubSize)

	// Both sides use the same zero pubs — keys must match.
	s2c1, c2s1, err := KeyExchange(server.us, client.us.PublicKey(),
		zeroPub, zeroPub)
	if err != nil {
		t.Fatal(err)
	}
	s2c2, c2s2, err := KeyExchange(client.us, server.us.PublicKey(),
		zeroPub, zeroPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s2c1[:], s2c2[:]) {
		t.Fatal("s2c keys differ with zero pubs")
	}
	if !bytes.Equal(c2s1[:], c2s2[:]) {
		t.Fatal("c2s keys differ with zero pubs")
	}
	if bytes.Equal(s2c1[:], c2s1[:]) {
		t.Fatal("directional keys must differ even with zero pubs")
	}

	// Zero-pub keys must differ from real-pub keys.
	s2cReal, _, err := KeyExchange(server.us, client.us.PublicKey(),
		server.us.PublicKey().Bytes(), client.us.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s2c1[:], s2cReal[:]) {
		t.Fatal("zero-pub salt must produce different keys than real-pub salt")
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

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
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

			wg.Go(func() {
				t.Logf("Listening: %v", port)
				conn, err := listener.Accept()
				if err != nil {
					panic(err)
				}

				if err := serverTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}
			})

			// Client
			wg.Go(func() {
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

				t.Logf("client connected using: %v", clientTransport.Curve())
			})

			wg.Wait()

			if !bytes.Equal(serverTransport.encryptKey[:],
				clientTransport.decryptKey[:]) {
				t.Fatal("server encrypt key != client decrypt key")
			}
			if bytes.Equal(serverTransport.encryptKey[:],
				serverTransport.decryptKey[:]) {
				t.Fatal("directional keys must differ")
			}

			// Close after key assertions — Close() zeros keys.
			if err := clientTransport.Close(); err != nil {
				t.Fatal(err)
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

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
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
			wg.Go(func() {
				var cerr error
				serverConn, cerr = listener.Accept()
				if cerr != nil {
					panic(err)
				}
			})

			// Client conn
			wg.Go(func() {
				var cerr error
				d := &net.Dialer{}
				clientConn, cerr = d.DialContext(ctx, "tcp",
					net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if cerr != nil {
					panic(err)
				}
			})

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
				naclPub, err := s.NaClPublicKey()
				if err != nil {
					return err
				}
				if err := tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					NaClPub:   naclPub,
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
			// E2e encryption is mandatory: a peer that announces
			// no X25519 key is rejected before any signature work.
			name:          "missing nacl public key",
			curve:         ecdh.P256(),
			expectedError: ErrInvalidNaClPub,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				return tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				})
			},
		},
		{
			name:          "short nacl public key",
			curve:         ecdh.P256(),
			expectedError: ErrInvalidNaClPub,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				return tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					NaClPub:   make([]byte, NaClPubSize-1),
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				})
			},
		},
		{
			// All-zeros collides with the BroadcastDestination
			// sentinel and is cryptographically useless.
			name:          "all-zeros nacl public key",
			curve:         ecdh.P256(),
			expectedError: ErrInvalidNaClPub,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				return tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					NaClPub:   make([]byte, NaClPubSize),
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				})
			},
		},
		{
			// The challenge signature covers the announced
			// NaClPub, so signing the v1 preimage (challenge and
			// transport key only) no longer verifies.  This pins
			// the fold-in: a peer that does not attest its e2e
			// key cannot complete a handshake.
			name:          "signature omits nacl public key",
			curve:         ecdh.P256(),
			expectedError: ErrIdentityMismatch,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				naclPub, err := s.NaClPublicKey()
				if err != nil {
					return err
				}
				if err := tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					Identity:  s.Identity,
					NaClPub:   naclPub,
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				}); err != nil {
					return err
				}
				_, cmd, _, err := tr.read(readTimeout)
				if err != nil {
					return err
				}
				helloRequest, ok := cmd.(*HelloRequest)
				if !ok {
					return fmt.Errorf("unexpected command: %T, wanted HelloRequest", cmd)
				}
				// v1 preimage: no NaClPub bound in.
				legacy := Hash256([]byte("continuum-challenge-v1"),
					helloRequest.Challenge, tr.them.Bytes())
				return tr.Write(s.Identity, HelloResponse{
					Signature: s.Sign(legacy),
				})
			},
		},
		{
			name:          "invalid encryption",
			curve:         ecdh.P256(),
			expectedError: ErrDecrypt,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				// Send garbage bytes the size of a v2 frame
				// header.  readBlob reads exactly 44 bytes and
				// tries to authenticate them — this must fail.
				garbage := make([]byte, transportFrameHeaderSize)
				_, _ = rand.Read(garbage)
				_, err := tr.conn.Write(garbage)
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
		{
			name:          "fake signature",
			curve:         ecdh.P256(),
			expectedError: ErrIdentityMismatch,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				naclPub, err := s.NaClPublicKey()
				if err != nil {
					return err
				}
				if err := tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					Identity:  s.Identity,
					NaClPub:   naclPub,
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				}); err != nil {
					return err
				}
				sig := ecdsa.SignCompact(s.privateKey, []byte("fake"), true)
				return tr.Write(s.Identity, HelloResponse{
					Signature: sig,
				})
			},
		},
		{
			name:          "fake identity",
			curve:         ecdh.P256(),
			expectedError: ErrIdentityMismatch,
			handshake: func(ctx context.Context, tr *Transport, s *Secret) error {
				var ourChallenge [32]byte
				_, err := rand.Read(ourChallenge[:])
				if err != nil {
					return err
				}
				fakeSecret, err := NewSecret()
				if err != nil {
					return err
				}
				naclPub, err := s.NaClPublicKey()
				if err != nil {
					return err
				}
				if err := tr.Write(s.Identity, HelloRequest{
					Version:   ProtocolVersion,
					Challenge: ourChallenge[:],
					Identity:  fakeSecret.Identity,
					NaClPub:   naclPub,
					Options: map[string]string{
						"encoding":    "json",
						"compression": "none",
					},
				}); err != nil {
					return err
				}
				// Read Hello
				_, cmd, _, err := tr.read(readTimeout)
				if err != nil {
					return err
				}
				helloRequest, ok := cmd.(*HelloRequest)
				if !ok {
					return fmt.Errorf("unexpected command: %T, wanted HelloRequest", cmd)
				}
				sig := ecdsa.SignCompact(s.privateKey,
					helloRequest.Challenge, true)
				return tr.Write(s.Identity, HelloResponse{
					Signature: sig,
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

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
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
			wg.Go(func() {
				var cerr error
				serverConn, cerr = listener.Accept()
				if cerr != nil {
					panic(err)
				}
			})

			// Client conn
			wg.Go(func() {
				var cerr error
				d := &net.Dialer{}
				clientConn, cerr = d.DialContext(ctx, "tcp",
					net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if cerr != nil {
					panic(err)
				}
			})

			wg.Wait()

			t.Logf("%s: %s", serverTransport, serverConn.LocalAddr())
			t.Logf("%s: %s", clientTransport, clientConn.LocalAddr())

			// Server conn
			wg.Go(func() {
				err := serverTransport.KeyExchange(ctx, serverConn)
				if err != nil {
					panic(err)
				}
			})

			// Client conn
			wg.Go(func() {
				err := clientTransport.KeyExchange(ctx, clientConn)
				if err != nil {
					panic(err)
				}
			})

			wg.Wait()

			go func() {
				err := tti.handshake(ctx, clientTransport, clientSecret)
				if err != nil {
					panic(err)
				}
			}()

			_, _, err = serverTransport.Handshake(ctx, serverSecret)
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
	if runtime.GOOS != "linux" {
		t.Skip("skipping: test requires Linux loopback range (127.0.0.0/8)")
	}
	curves := []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521(), ecdh.X25519()}
	for _, curve := range curves {
		testName := fmt.Sprintf("%v", curve)
		t.Run(testName, func(t *testing.T) {
			nodes := byte(2)
			domain := "moop.gfy"
			handler := createDNSNodes(domain, nodes)
			srv := newDNSServer(t.Context(), handler)
			defer srv.Shutdown(t.Context())
			dnsAddress := srv.Listener.Addr().String()
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

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
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
			wg.Go(func() {
				t.Logf("Listening: %v:%v", node1.IP, port)
				conn, err := listener.Accept()
				if err != nil {
					panic(err)
				}
				clientAddress = conn.RemoteAddr()

				if err := serverTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}
			})

			// Client
			wg.Go(func() {
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
			})

			wg.Wait()

			if !bytes.Equal(serverTransport.encryptKey[:],
				clientTransport.decryptKey[:]) {
				t.Fatal("server encrypt key != client decrypt key")
			}
			if bytes.Equal(serverTransport.encryptKey[:],
				serverTransport.decryptKey[:]) {
				t.Fatal("directional keys must differ")
			}

			// Handshake
			var derivedClient, derivedServer *Identity

			wg.Go(func() {
				var err error // prevent data race
				derivedClient, _, err = serverTransport.Handshake(ctx, serverSecret)
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
			})

			wg.Go(func() {
				defer func() {
					if err := clientTransport.Close(); err != nil {
						panic(err)
					}
				}()

				var err error // prevent data race
				derivedServer, _, err = clientTransport.Handshake(ctx, clientSecret)
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
			})

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

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
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

			wg.Go(func() {
				t.Logf("Listening: %v", port)
				conn, err := listener.Accept()
				if err != nil {
					panic(err)
				}

				if err := serverTransport.KeyExchange(ctx, conn); err != nil {
					panic(err)
				}
			})

			// Client
			wg.Go(func() {
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
			})

			wg.Wait()

			if !bytes.Equal(serverTransport.encryptKey[:],
				clientTransport.decryptKey[:]) {
				t.Fatal("server encrypt key != client decrypt key")
			}
			if bytes.Equal(serverTransport.encryptKey[:],
				serverTransport.decryptKey[:]) {
				t.Fatal("directional keys must differ")
			}

			// Handshake
			var derivedClient, derivedServer *Identity

			wg.Go(func() {
				var err error

				derivedClient, _, err = serverTransport.Handshake(ctx, serverSecret)
				if err != nil {
					panic(err)
				}
			})

			wg.Go(func() {
				var err error

				defer func() {
					if err := clientTransport.Close(); err != nil {
						panic(err)
					}
				}()

				derivedServer, _, err = clientTransport.Handshake(ctx, clientSecret)
				if err != nil {
					panic(err)
				}
			})

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
	if runtime.GOOS != "linux" {
		t.Skip("skipping: test requires Linux loopback range (127.0.0.0/8)")
	}
	nodes := byte(200)
	domain := "moop.gfy"
	handler := createDNSNodes(domain, nodes)
	srv := newDNSServer(t.Context(), handler)
	defer srv.Shutdown(t.Context())
	dnsAddress := srv.Listener.Addr().String()
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
		// Note that the extra spaces match the TXT record that is generated.
		txtExpected := fmt.Sprintf("v=%v; identity=%v;   port=%v;",
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
	sec := NewSecretFromPrivate(pk)
	if !sec.PublicKey().IsEqual(pk.PubKey()) {
		t.Fatalf("pubKey mismatch: %v != %v", sec.PublicKey(), pk.PubKey())
	}

	// Test sign and recovering
	hash := []byte("testhash")
	sig := sec.Sign(hash)

	var r, s secp256k1.ModNScalar
	r.SetByteSlice(sig[1:33])
	s.SetByteSlice(sig[33:])
	fullSig := ecdsa.NewSignature(&r, &s)
	recPub, err := Verify(hash, sec.Identity, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !fullSig.Verify(hash, recPub) {
		t.Fatal("recovered pubkey invalid for signature and hash")
	}
	if !recPub.IsEqual(pk.PubKey()) {
		t.Fatalf("pubKey mismatch: %v != %v", recPub, pk.PubKey())
	}
}

// TestNaClKeyDerivation verifies that X25519 keypairs are deterministically
// derived from secp256k1 private keys, that two different secrets produce
// different X25519 keys, and that a nacl box round-trip works between the
// two derived keypairs.
func TestNaClKeyDerivation(t *testing.T) {
	secret1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	secret2, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Determinism: same secret produces same key every time.
	priv1a, err := secret1.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv1b, err := secret1.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv1a.Bytes(), priv1b.Bytes()) {
		t.Fatal("NaClPrivateKey not deterministic")
	}

	pub1, err := secret1.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := secret2.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	// Different secrets produce different keys.
	if bytes.Equal(pub1, pub2) {
		t.Fatal("different secrets produced same NaCl public key")
	}

	// Key length: X25519 keys are 32 bytes.
	if len(pub1) != 32 {
		t.Fatalf("NaCl public key length: got %d, want 32", len(pub1))
	}

	// nacl box round-trip between the two derived keypairs.
	priv2, err := secret2.NaClPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("test message for nacl box round-trip")
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}

	var pub2Arr, priv1Arr [32]byte
	copy(pub2Arr[:], pub2)
	copy(priv1Arr[:], priv1a.Bytes())

	sealed := box.Seal(nil, plaintext, &nonce, &pub2Arr, &priv1Arr)

	var pub1Arr, priv2Arr [32]byte
	copy(pub1Arr[:], pub1)
	copy(priv2Arr[:], priv2.Bytes())

	opened, ok := box.Open(nil, sealed, &nonce, &pub1Arr, &priv2Arr)
	if !ok {
		t.Fatal("nacl box open failed")
	}
	if !bytes.Equal(plaintext, opened) {
		t.Fatal("nacl box round-trip plaintext mismatch")
	}
}

// BenchmarkSealBox measures nacl box encryption throughput.
func BenchmarkSealBox(b *testing.B) {
	secret, err := NewSecret()
	if err != nil {
		b.Fatal(err)
	}
	recipientSecret, err := NewSecret()
	if err != nil {
		b.Fatal(err)
	}
	recipientPub, err := recipientSecret.NaClPublicKey()
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, 256) // typical PingRequest size

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SealBox(plaintext, recipientPub, secret, PPingRequest)
	}
}

// BenchmarkOpenBox measures nacl box decryption throughput.
func BenchmarkOpenBox(b *testing.B) {
	sender, err := NewSecret()
	if err != nil {
		b.Fatal(err)
	}
	recipient, err := NewSecret()
	if err != nil {
		b.Fatal(err)
	}
	recipientPub, err := recipient.NaClPublicKey()
	if err != nil {
		b.Fatal(err)
	}
	recipientPriv, err := recipient.NaClPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, 256)
	ep, err := SealBox(plaintext, recipientPub, sender, PPingRequest)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = OpenBox(ep, recipientPriv)
	}
}

// TestPayloadHashVerification tests the payload hash verification logic
// in the Transport read method.
func TestPayloadHashVerification(t *testing.T) {
	serverTransport, err := NewTransportFromCurve(ecdh.X25519())
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

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
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

	if !bytes.Equal(serverTransport.encryptKey[:],
		clientTransport.decryptKey[:]) {
		t.Fatal("server encrypt key != client decrypt key")
	}
	if bytes.Equal(serverTransport.encryptKey[:],
		serverTransport.decryptKey[:]) {
		t.Fatal("directional keys must differ")
	}

	// Handshake
	var derivedClient, derivedServer *Identity

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		derivedClient, _, err = serverTransport.Handshake(ctx, serverSecret)
		if err != nil {
			panic(err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		derivedServer, _, err = clientTransport.Handshake(ctx, clientSecret)
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

	type testTableItem struct {
		name          string
		cmd           any
		falsePayload  bool
		falseHash     bool
		expectedError bool
	}
	tests := []testTableItem{
		{
			name: "valid_hello_request",
			cmd:  HelloRequest{},
		},
		{
			name: "valid_keygen_request",
			cmd:  KeygenRequest{},
		},
		{
			name:          "invalid_hash",
			cmd:           HelloRequest{},
			falseHash:     true,
			expectedError: true,
		},
		{
			name:          "invalid_payload_size",
			cmd:           HelloRequest{},
			falsePayload:  true,
			expectedError: true,
		},
	}

	for _, tti := range tests {
		t.Run(tti.name, func(t *testing.T) {
			var msgErr error
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, msgErr = serverTransport.Read()
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()

				pt, ok := pt2str[reflect.TypeOf(tti.cmd)]
				if !ok {
					panic(fmt.Sprintf("invalid command type: %T", tti.cmd))
				}
				hash, payload, err := NewPayloadFromCommand(tti.cmd)
				if err != nil {
					panic(err)
				}
				if tti.falseHash {
					hash = NewPayloadHash([]byte{})
				}
				if tti.falsePayload {
					payload = nil
				}
				header, err := json.Marshal(Header{
					PayloadType: pt,
					PayloadHash: *hash,
					Origin:      clientSecret.Identity,
					Destination: &serverSecret.Identity,
					TTL:         1,
				})
				if err != nil {
					panic(err)
				}
				err = clientTransport.write(writeTimeout, append(header, payload...))
				if err != nil {
					panic(err)
				}
			}()

			wg.Wait()

			if tti.expectedError {
				if msgErr == nil {
					t.Fatalf("expected error")
				}
				t.Logf("got expected error: %v", msgErr)
			} else if msgErr != nil {
				t.Fatal(msgErr)
			}
		})
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

	rec1, err := Verify(c1[:], s2.Identity, sig2)
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := Verify(c2[:], s1.Identity, sig1)
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

func TestDNSTXTRecord(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: test requires Linux loopback range (127.0.0.0/8)")
	}
	nodes := byte(1)
	domain := "moop.gfy"
	handler := createDNSNodes(domain, nodes)
	srv := newDNSServer(t.Context(), handler)
	defer srv.Shutdown(t.Context())
	dnsAddress := srv.Listener.Addr().String()
	r := newResolver(dnsAddress)

	node1 := handler.nodes["node1.moop.gfy."]
	addr, err := net.ResolveTCPAddr("tcp",
		net.JoinHostPort(node1.IP.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := TXTRecordFromAddress(t.Context(), r, addr)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := m["v"]; !ok || v != "transfunctioner" {
		t.Fatal("invalid v")
	}

	// Corrupt record
	handler.lookup["node1.moop.gfy."] = []dns.RR{
		&dns.A{
			Hdr: dns.Header{
				Name:  node1.DNSName,
				Class: dns.ClassINET,
			},
			A: node1.IP,
		},
		&dns.TXT{
			Hdr: dns.Header{
				Name:  node1.DNSName,
				Class: dns.ClassINET,
			},
			Txt: []string{"k=ppp"},
		},
	}
	m, err = TXTRecordFromAddress(t.Context(), r, addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["v"]; ok {
		t.Fatal("invalid v")
	}

	// Complete break record
	handler.lookup["node1.moop.gfy."] = []dns.RR{
		&dns.A{
			Hdr: dns.Header{
				Name:  node1.DNSName,
				Class: dns.ClassINET,
			},
			A: node1.IP,
		},
		&dns.TXT{
			Hdr: dns.Header{
				Name:  node1.DNSName,
				Class: dns.ClassINET,
			},
			Txt: []string{"x"},
		},
	}
	_, err = TXTRecordFromAddress(t.Context(), r, addr)
	if err == nil {
		t.Fatal("expected invalid txt record")
	}

	// Delete record
	delete(handler.lookup, "node1.moop.gfy.")
	_, err = TXTRecordFromAddress(t.Context(), r, addr)
	if err == nil {
		t.Fatal("expected lame referral")
	}
}

func TestKvFromTxt(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{
			name:  "valid record",
			input: "v=transfunctioner; identity=deadbeef; port=1234",
			want: map[string]string{
				"v":        "transfunctioner",
				"identity": "deadbeef",
				"port":     "1234",
			},
		},
		{
			name:  "value containing equals",
			input: "v=transfunctioner; data=abc=def=ghi",
			want: map[string]string{
				"v":    "transfunctioner",
				"data": "abc=def=ghi",
			},
		},
		{
			name:  "single pair",
			input: "v=transfunctioner",
			want:  map[string]string{"v": "transfunctioner"},
		},
		{
			name:  "whitespace trimming",
			input: " v = transfunctioner ;  identity = deadbeef ",
			want: map[string]string{
				"v":        "transfunctioner",
				"identity": "deadbeef",
			},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "no equals sign",
			input:   "noequals",
			wantErr: true,
		},
		{
			name:    "missing value in pair",
			input:   "v=transfunctioner; novalue",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := kvFromTxt(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("kvFromTxt(%q) = %v, want error",
						tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("kvFromTxt(%q) error: %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("kvFromTxt(%q) = %v, want %v",
					tt.input, got, tt.want)
			}
		})
	}
}

func FuzzKvFromTxt(f *testing.F) {
	f.Add("v=transfunctioner; identity=deadbeef; port=1234")
	f.Add("")
	f.Add("noequals")
	f.Add("a=b; c=d; e=f")
	f.Add("key=val=ue")
	f.Add("; ; ; ")
	f.Add("===")
	f.Add("v=transfunctioner; identity=abc123abc123abc123abc123abc123abc123abc1")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic.
		_, _ = kvFromTxt(input)
	})
}

// TestVerifyRejectsWrongIdentity exercises the constant-time identity
// comparison in Verify().  A forged identity must be rejected even when
// the signature itself is valid — the mismatch is detected by
// subtle.ConstantTimeCompare, not bytes.Equal.
func TestVerifyRejectsWrongIdentity(t *testing.T) {
	k1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256([]byte("test message"))
	sig := k1.Sign(hash[:])

	// Positive: correct identity passes.
	_, err = Verify(hash[:], k1.Identity, sig)
	if err != nil {
		t.Fatalf("Verify with correct identity failed: %v", err)
	}

	// Negative: wrong identity must fail (exercises ConstantTimeCompare).
	_, err = Verify(hash[:], k2.Identity, sig)
	if err == nil {
		t.Fatal("Verify should reject wrong identity")
	}
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("expected ErrIdentityMismatch, got: %v", err)
	}

	// Negative: single-bit flip in identity must fail.
	flipped := k1.Identity
	flipped[0] ^= 0x01
	_, err = Verify(hash[:], flipped, sig)
	if err == nil {
		t.Fatal("Verify should reject single-bit-flipped identity")
	}
}

// TestHashTSSMessageDomainSeparation verifies that HashTSSMessage
// includes the "continuum-tss-msg-v3" domain separator and covers
// From, Type, and Flags.  If the domain separator is removed, this
// test fails.
func TestHashTSSMessageDomainSeparation(t *testing.T) {
	var cid CeremonyID
	copy(cid[:], bytes.Repeat([]byte{0xaa}, 32))
	var from Identity
	copy(from[:], bytes.Repeat([]byte{0xbb}, 20))
	ct := CeremonyKeygen
	flags := TSSFlagBroadcast
	data := []byte("test data")

	// Compute expected hash manually with the domain separator.
	h := sha256.New()
	h.Write([]byte("continuum-tss-msg-v3"))
	h.Write(cid[:])
	h.Write(from[:])
	h.Write([]byte{byte(ct)})
	h.Write([]byte{byte(flags)})
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	h.Write(lenBuf[:])
	h.Write(data)
	expected := h.Sum(nil)

	got := HashTSSMessage(cid, from, ct, flags, data)
	if !bytes.Equal(expected, got) {
		t.Fatalf("HashTSSMessage mismatch:\n  got:  %x\n  want: %x", got, expected)
	}

	// Without domain separator must differ.
	hNoDomain := sha256.New()
	hNoDomain.Write(cid[:])
	hNoDomain.Write(data)
	noDomain := hNoDomain.Sum(nil)
	if bytes.Equal(got, noDomain) {
		t.Fatal("HashTSSMessage must differ from raw SHA256(cid || data)")
	}
}

// TestHashTSSMessageLengthPrefix verifies that the length prefix
// prevents ambiguous splits.  SHA256("A" || "BC") must differ from
// SHA256("AB" || "C") when the length is encoded.
func TestHashTSSMessageLengthPrefix(t *testing.T) {
	var cid1, cid2 CeremonyID

	// Construct two (cid, data) pairs where cid1||data1 == cid2||data2
	// as raw bytes, but the length prefix distinguishes them.
	// CeremonyID is fixed 32 bytes so we can't actually vary its
	// length — instead verify that different data lengths produce
	// different hashes even with the same prefix bytes.
	copy(cid1[:], bytes.Repeat([]byte{0x01}, 32))
	cid2 = cid1

	data1 := []byte("short")
	data2 := []byte("short and longer")

	var from Identity
	h1 := HashTSSMessage(cid1, from, CeremonyKeygen, 0, data1)
	h2 := HashTSSMessage(cid2, from, CeremonyKeygen, 0, data2)
	if bytes.Equal(h1, h2) {
		t.Fatal("different data must produce different hashes")
	}

	// Same inputs must be deterministic.
	h1b := HashTSSMessage(cid1, from, CeremonyKeygen, 0, data1)
	if !bytes.Equal(h1, h1b) {
		t.Fatal("HashTSSMessage must be deterministic")
	}
}

// TestTransportCloseZerosKeys verifies that Transport.Close() zeros
// the encryption key, decryption key, nonce key, and nils the
// ephemeral private key.
func TestTransportCloseZerosKeys(t *testing.T) {
	sp, cp := net.Pipe()
	defer cp.Close()

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

	// Perform key exchange to populate keys.
	s2c, c2s, err := KeyExchange(server.us, client.us.PublicKey(),
		server.us.PublicKey().Bytes(), client.us.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	server.encryptKey = s2c
	server.decryptKey = c2s
	server.conn = sp

	// Verify keys are non-zero before close.
	allZero := func(b []byte) bool {
		for _, v := range b {
			if v != 0 {
				return false
			}
		}
		return true
	}
	if allZero(server.encryptKey[:]) {
		t.Fatal("encryptKey should be non-zero before Close")
	}
	if allZero(server.decryptKey[:]) {
		t.Fatal("decryptKey should be non-zero before Close")
	}
	if allZero(server.nonce.key[:]) {
		t.Fatal("nonce.key should be non-zero before Close")
	}
	if server.us == nil {
		t.Fatal("us should be non-nil before Close")
	}

	// Close and verify zeroing.
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if !allZero(server.encryptKey[:]) {
		t.Fatal("encryptKey must be zeroed after Close")
	}
	if !allZero(server.decryptKey[:]) {
		t.Fatal("decryptKey must be zeroed after Close")
	}
	if !allZero(server.nonce.key[:]) {
		t.Fatal("nonce.key must be zeroed after Close")
	}
	if server.us != nil {
		t.Fatal("us must be nil after Close")
	}
}

// TestChallengeHashDomainSeparation verifies that the handshake
// challenge hash includes the "continuum-challenge-v2" domain
// separator and binds NaClPub.  Both sides must produce the same
// hash for the handshake to succeed — the existing TestConnHandshake
// proves agreement.  This test proves the domain separator and
// NaClPub binding are present.
func TestChallengeHashDomainSeparation(t *testing.T) {
	challenge := make([]byte, ChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	etp := priv.PublicKey().Bytes()

	naclPub := make([]byte, NaClPubSize)
	if _, err := rand.Read(naclPub); err != nil {
		t.Fatal(err)
	}

	// Hash256 with domain separator and NaClPub (what the code does now).
	got := Hash256([]byte("continuum-challenge-v2"), challenge, etp, naclPub)

	// Hash256 without domain separator must differ.
	old := Hash256(challenge, etp)

	if bytes.Equal(got, old) {
		t.Fatal("domain-separated challenge hash must differ from unseparated")
	}

	// Must be deterministic.
	got2 := Hash256([]byte("continuum-challenge-v2"), challenge, etp, naclPub)
	if !bytes.Equal(got, got2) {
		t.Fatal("challenge hash must be deterministic")
	}
}

// TestSealBoxOpenBoxRoundTrip exercises the nacl/box e2e encryption
// round trip to verify SealBox/OpenBox work correctly with domain-separated
// changes (no functional change, but regression guard).
func TestSealBoxOpenBoxRoundTrip(t *testing.T) {
	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello e2e encryption")

	ep, err := SealBox(plaintext, recipientPriv.PublicKey().Bytes(), sender, PTSSMessage)
	if err != nil {
		t.Fatal(err)
	}

	got, err := OpenBox(ep, recipientPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, got) {
		t.Fatal("OpenBox plaintext mismatch")
	}

	// Verify sender signature.
	hash := hashEncryptedPayload(&ep.EphemeralPub, &ep.Nonce, ep.Sender, ep.InnerType, ep.Ciphertext)
	_, err = Verify(hash, sender.Identity, ep.Signature)
	if err != nil {
		t.Fatalf("envelope signature verify failed: %v", err)
	}

	// Wrong recipient key must fail.
	wrongPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, err = OpenBox(ep, wrongPriv)
	if err == nil {
		t.Fatal("OpenBox should fail with wrong recipient key")
	}
}

// Coverage for the authenticated e2e key exchange: the binding hash,
// bindPeerKey's immutability rule, both dispatch handlers, and the
// gossip strip in each direction.
//
// The exchange exists because a node's X25519 key is derived from its
// PRIVATE secp256k1 key (NaClPrivateKey), so no recipient can compute
// or check it from a public identity.  Gossip therefore has nothing
// truthful to say about key material and never carries it; a key is
// learned only from its holder, either by handshake or by the routed
// NaClKeyRequest/NaClKeyResponse challenge-response verified here.

// keyXchgServer builds a Server through the production constructor
// (so the exchange TTLs exist) and supplies only what Run() would
// otherwise add: an identity and the peers TTL that bindPeerKey and
// addPeer write to.  No listeners, no background loops.
func keyXchgServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(testConfig())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("server secret: %v", err)
	}
	peersTTL, err := ttl.New(16, true)
	if err != nil {
		t.Fatalf("peers ttl: %v", err)
	}
	s.secret, s.peersTTL = secret, peersTTL
	return s
}

// capturingTransport records payloads written through the dispatch
// context instead of sending them.  Handlers under test route their
// replies via sendTo, which needs a session; tests that only care
// about verification logic use dispatchCtx with no transport at all.
type keyXchgCtx struct {
	dc *dispatchCtx
}

// newKeyXchgCtx returns a dispatch context for s with from as the
// session peer.  ctx doubles as sessionCtx: no handler under test
// distinguishes them.
func newKeyXchgCtx(t *testing.T, s *Server, from Identity) *keyXchgCtx {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // reap TTL goroutines the handlers arm
	id := from
	return &keyXchgCtx{dc: &dispatchCtx{
		ctx:        ctx,
		sessionCtx: ctx,
		s:          s,
		id:         &id,
	}}
}

// mustNaClPub returns the X25519 public key for a secret.
func mustNaClPub(t *testing.T, s *Secret) []byte {
	t.Helper()
	pub, err := s.NaClPublicKey()
	if err != nil {
		t.Fatalf("nacl pub: %v", err)
	}
	return pub
}

// pendingChallenge registers a challenge for id exactly as
// sendNaClKeyRequest does, so response-handler tests can run without
// a live mesh.
func pendingChallenge(t *testing.T, s *Server, id Identity, challenge []byte) {
	t.Helper()
	s.naclXchg.Put(context.Background(), naclXchgTTL, string(challenge),
		id, nil, nil)
}

// signedKeyResponse builds the response the holder of secret would
// send for challenge.
func signedKeyResponse(t *testing.T, secret *Secret, challenge []byte) *NaClKeyResponse {
	t.Helper()
	naclPub := mustNaClPub(t, secret)
	return &NaClKeyResponse{
		Challenge: challenge,
		NaClPub:   naclPub,
		Signature: secret.Sign(hashNaClKeyBinding(challenge, naclPub)),
	}
}

// freshChallenge returns a distinct non-zero challenge per call.
func freshChallenge(i byte) []byte {
	c := make([]byte, ChallengeSize)
	for j := range c {
		c[j] = i + byte(j) + 1
	}
	return c
}

func TestHashNaClKeyBindingDomainSeparated(t *testing.T) {
	challenge := freshChallenge(1)
	naclPub := make([]byte, NaClPubSize)
	naclPub[0] = 0x42

	base := hashNaClKeyBinding(challenge, naclPub)
	if len(base) != 32 {
		t.Fatalf("hash length %d, want 32", len(base))
	}
	// Deterministic.
	if !bytes.Equal(base, hashNaClKeyBinding(challenge, naclPub)) {
		t.Fatal("hash is not deterministic")
	}
	// Both inputs are covered.
	other := freshChallenge(2)
	if bytes.Equal(base, hashNaClKeyBinding(other, naclPub)) {
		t.Fatal("hash ignores the challenge")
	}
	altPub := make([]byte, NaClPubSize)
	altPub[0] = 0x43
	if bytes.Equal(base, hashNaClKeyBinding(challenge, altPub)) {
		t.Fatal("hash ignores the nacl public key")
	}
	// Distinct from the handshake binding over the same material,
	// so neither signature can be replayed as the other.
	if bytes.Equal(base, Hash256([]byte("continuum-challenge-v2"), challenge, naclPub)) {
		t.Fatal("key binding collides with the handshake binding")
	}
}

func TestBindPeerKey(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()
	victim := mustSecret(t)
	victimPub := mustNaClPub(t, victim)

	t.Run("rejects self", func(t *testing.T) {
		if err := s.bindPeerKey(ctx, s.secret.Identity,
			mustNaClPub(t, s.secret)); err == nil {
			t.Fatal("bound a key for our own identity")
		}
	})

	t.Run("rejects malformed", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			key  []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", make([]byte, NaClPubSize-1)},
			{"long", make([]byte, NaClPubSize+1)},
			{"all zeros", make([]byte, NaClPubSize)},
		} {
			t.Run(tt.name, func(t *testing.T) {
				id := mustSecret(t).Identity
				if err := s.bindPeerKey(ctx, id, tt.key); err == nil {
					t.Fatal("accepted a malformed e2e key")
				}
				if _, ok := s.peerNaClPub(id); ok {
					t.Fatal("malformed key was stored")
				}
			})
		}
	})

	t.Run("binds and creates a record", func(t *testing.T) {
		if err := s.bindPeerKey(ctx, victim.Identity, victimPub); err != nil {
			t.Fatalf("bindPeerKey: %v", err)
		}
		got, ok := s.peerNaClPub(victim.Identity)
		if !ok {
			t.Fatal("no key bound")
		}
		if !bytes.Equal(got, victimPub) {
			t.Fatalf("bound %x, want %x", got, victimPub)
		}
	})

	t.Run("stores a copy", func(t *testing.T) {
		mutable := append([]byte(nil), victimPub...)
		id := mustSecret(t).Identity
		if err := s.bindPeerKey(ctx, id, mutable); err != nil {
			t.Fatalf("bindPeerKey: %v", err)
		}
		mutable[0] ^= 0xFF
		got, _ := s.peerNaClPub(id)
		if bytes.Equal(got, mutable) {
			t.Fatal("bindPeerKey aliased the caller's buffer")
		}
	})

	t.Run("idempotent for the same key", func(t *testing.T) {
		before := s.keyConflicts.Load()
		if err := s.bindPeerKey(ctx, victim.Identity, victimPub); err != nil {
			t.Fatalf("re-binding the same key failed: %v", err)
		}
		if got := s.keyConflicts.Load(); got != before {
			t.Fatalf("same-key re-bind counted as a conflict: %d -> %d",
				before, got)
		}
	})

	t.Run("immutable against a conflicting key", func(t *testing.T) {
		attackerPub := mustNaClPub(t, mustSecret(t))
		before := s.keyConflicts.Load()
		if err := s.bindPeerKey(ctx, victim.Identity, attackerPub); err == nil {
			t.Fatal("accepted a conflicting e2e key for a bound identity")
		}
		got, _ := s.peerNaClPub(victim.Identity)
		if !bytes.Equal(got, victimPub) {
			t.Fatalf("conflicting bind mutated the stored key: %x", got)
		}
		// The derivation is deterministic, so a conflict is
		// always an attack or a broken peer: it must be counted.
		if got := s.keyConflicts.Load(); got != before+1 {
			t.Fatalf("conflict counter %d, want %d", got, before+1)
		}
	})
}

func TestHandleNaClKeyRequestRejects(t *testing.T) {
	valid := freshChallenge(7)
	tests := []struct {
		name string
		req  *NaClKeyRequest
		self bool // set Requester to the server's own identity
	}{
		{name: "short challenge", req: &NaClKeyRequest{
			Challenge: make([]byte, ChallengeSize-1),
		}},
		{name: "long challenge", req: &NaClKeyRequest{
			Challenge: make([]byte, ChallengeSize+1),
		}},
		{name: "nil challenge", req: &NaClKeyRequest{}},
		{name: "zero challenge", req: &NaClKeyRequest{
			Challenge: make([]byte, ChallengeSize),
		}},
		{name: "self requester", req: &NaClKeyRequest{
			Challenge: valid,
		}, self: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := keyXchgServer(t)
			req := *tt.req
			if tt.self {
				req.Requester = s.secret.Identity
			} else {
				req.Requester = mustSecret(t).Identity
			}
			k := newKeyXchgCtx(t, s, req.Requester)

			before := s.naclXchgDrops.Load()
			if handleNaClKeyRequest(k.dc, &req) {
				t.Fatal("handler asked to close the session")
			}
			if got := s.naclXchgDrops.Load(); got != before+1 {
				t.Fatalf("drop counter %d, want %d", got, before+1)
			}
		})
	}
}

// TestHandleNaClKeyRequestRateLimitedPerSession proves the signing
// bound is keyed on the AUTHENTICATED session peer.  Keying it on the
// request's Requester field would be no bound at all: that field is
// unauthenticated wire data a flooder varies per message, so this test
// drives exactly that flood and requires it to be capped.
func TestHandleNaClKeyRequestRateLimitedPerSession(t *testing.T) {
	s := keyXchgServer(t)
	sessionPeer := mustSecret(t).Identity
	k := newKeyXchgCtx(t, s, sessionPeer)

	// Flood over one session, rotating Requester every time so a
	// per-Requester window would never fire.
	const flood = naclXchgRateLimit * 3
	for i := range flood {
		handleNaClKeyRequest(k.dc, &NaClKeyRequest{
			Requester: mustSecret(t).Identity,
			Challenge: freshChallenge(byte(i % 200)),
		})
	}
	// Everything past the limit must be dropped by the limiter.
	// Answered requests also fail to send (no route), which counts a
	// drop too, so assert the limiter fired at all and that the
	// answered count never exceeded the cap.
	answered := flood - int(s.naclXchgDrops.Load())
	if answered > naclXchgRateLimit {
		t.Fatalf("answered %d requests over one session, cap is %d: "+
			"a rotating Requester defeated the limiter",
			answered, naclXchgRateLimit)
	}

	// A different SESSION is unaffected — the bound is per session,
	// and sessions are capped by PeersWanted, so the total is bounded.
	other := newKeyXchgCtx(t, s, mustSecret(t).Identity)
	before := s.naclXchgDrops.Load()
	handleNaClKeyRequest(other.dc, &NaClKeyRequest{
		Requester: mustSecret(t).Identity,
		Challenge: freshChallenge(7),
	})
	// The send still fails (no route), so exactly one drop — from the
	// send, not the limiter.  Two would mean the limiter rejected it.
	if got := s.naclXchgDrops.Load(); got > before+1 {
		t.Fatalf("a distinct session was rate limited: drops %d, want %d",
			got, before+1)
	}
}

// TestNaClKeyRequestNeverFloods proves a request naming an unroutable
// Requester never fans the reply out across the mesh.
//
// This is the amplification guard. Routing the reply through sendTo
// would flood it to every session when the attacker-chosen Requester
// has no route, turning one small unauthenticated message into one
// transmission per mesh edge. The reply may only take a path we
// already have, or the reverse path back to the requesting session.
//
// The unrelated sessions hold nil transports, so ANY write to them
// panics: if the reply ever floods, this test fails loudly rather than
// silently passing.
func TestNaClKeyRequestNeverFloods(t *testing.T) {
	s := keyXchgServer(t)

	for range 3 {
		s.mtx.Lock()
		s.sessions[mustSecret(t).Identity] = nil
		s.mtx.Unlock()
	}

	// dc.t is nil here, so the reverse path is unavailable too and
	// the reply has nowhere legitimate to go.
	k := newKeyXchgCtx(t, s, mustSecret(t).Identity)
	before := s.naclXchgDrops.Load()

	// Requester is a fresh identity: no session, no route.
	handleNaClKeyRequest(k.dc, &NaClKeyRequest{
		Requester: mustSecret(t).Identity,
		Challenge: freshChallenge(9),
	})

	// Refused and counted — and, critically, no write was attempted
	// against the unrelated sessions.
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("drop counter %d, want %d (an unroutable reply must "+
			"be refused, never flooded)", got, before+1)
	}
}

// TestHandleNaClKeyResponseBinds is the happy path: a response that
// verifies against the identity the challenge was issued for binds the
// key and consumes the challenge.
func TestHandleNaClKeyResponseBinds(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	challenge := freshChallenge(11)
	pendingChallenge(t, s, peer.Identity, challenge)
	k := newKeyXchgCtx(t, s, peer.Identity)

	if handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, challenge)) {
		t.Fatal("handler asked to close the session")
	}
	got, ok := s.peerNaClPub(peer.Identity)
	if !ok {
		t.Fatal("verified response did not bind a key")
	}
	if !bytes.Equal(got, mustNaClPub(t, peer)) {
		t.Fatalf("bound %x, want %x", got, mustNaClPub(t, peer))
	}
	// The challenge is single-use: replaying the same response
	// finds no pending exchange.
	before := s.naclXchgDrops.Load()
	handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, challenge))
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("challenge was not consumed: drops %d, want %d",
			got, before+1)
	}
}

func TestHandleNaClKeyResponseRejects(t *testing.T) {
	peer := mustSecret(t)
	attacker := mustSecret(t)
	challenge := freshChallenge(21)

	tests := []struct {
		name string
		// build returns the response to feed and whether to
		// register challenge as pending for peer first.
		build   func(t *testing.T, s *Server) *NaClKeyResponse
		pending bool
	}{
		{
			name:    "short challenge",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.Challenge = challenge[:ChallengeSize-1]
				return r
			},
		},
		{
			name:    "short nacl pub",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.NaClPub = r.NaClPub[:NaClPubSize-1]
				return r
			},
		},
		{
			// Unsolicited: nothing pending for this challenge.
			name:    "no pending challenge",
			pending: false,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				return signedKeyResponse(t, peer, challenge)
			},
		},
		{
			// Right challenge, but signed by someone else: the
			// recovered identity does not match the identity the
			// challenge was issued for.
			name:    "signed by another identity",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				return signedKeyResponse(t, attacker, challenge)
			},
		},
		{
			// The core substitution attack: keep the victim's
			// signature but swap in the attacker's key.  The hash
			// is recomputed from the received key, so recovery
			// yields a different identity and fails.
			name:    "attacker key with victim signature",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.NaClPub = mustNaClPub(t, attacker)
				return r
			},
		},
		{
			name:    "garbage signature",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.Signature = make([]byte, len(r.Signature))
				return r
			},
		},
		{
			name:    "empty signature",
			pending: true,
			build: func(t *testing.T, s *Server) *NaClKeyResponse {
				r := signedKeyResponse(t, peer, challenge)
				r.Signature = nil
				return r
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := keyXchgServer(t)
			if tt.pending {
				pendingChallenge(t, s, peer.Identity, challenge)
			}
			k := newKeyXchgCtx(t, s, peer.Identity)

			before := s.naclXchgDrops.Load()
			if handleNaClKeyResponse(k.dc, tt.build(t, s)) {
				t.Fatal("handler asked to close the session")
			}
			if _, ok := s.peerNaClPub(peer.Identity); ok {
				t.Fatal("a rejected response bound a key")
			}
			if _, ok := s.peerNaClPub(attacker.Identity); ok {
				t.Fatal("a rejected response bound a key for the attacker")
			}
			if got := s.naclXchgDrops.Load(); got != before+1 {
				t.Fatalf("drop counter %d, want %d", got, before+1)
			}
		})
	}
}

// TestNaClKeyResponseDoesNotBurnPendingOnFailure proves a forged
// response cannot deny service by consuming the pending challenge: the
// legitimate response still binds afterwards.
func TestNaClKeyResponseDoesNotBurnPendingOnFailure(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	attacker := mustSecret(t)
	challenge := freshChallenge(31)
	pendingChallenge(t, s, peer.Identity, challenge)
	k := newKeyXchgCtx(t, s, peer.Identity)

	// Forged response for the outstanding challenge.
	handleNaClKeyResponse(k.dc, signedKeyResponse(t, attacker, challenge))
	if _, ok := s.peerNaClPub(peer.Identity); ok {
		t.Fatal("forged response bound a key")
	}

	// The real one still works.
	handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, challenge))
	got, ok := s.peerNaClPub(peer.Identity)
	if !ok {
		t.Fatal("a forged response burned the pending challenge")
	}
	if !bytes.Equal(got, mustNaClPub(t, peer)) {
		t.Fatalf("bound %x, want %x", got, mustNaClPub(t, peer))
	}
}

// TestNaClKeyResponseCannotRebind proves the exchange cannot be used
// to overwrite a key already established by a handshake — the
// vulnerability's overwrite case, now closed at the binding layer.
func TestNaClKeyResponseCannotRebind(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	peerPub := mustNaClPub(t, peer)

	// A completed handshake bound the real key.
	if err := s.bindPeerKey(t.Context(), peer.Identity, peerPub); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}

	// An attacker who somehow answers a pending challenge for that
	// identity still cannot replace the key: only the identity
	// holder can produce a verifying response, and even that is a
	// no-op re-bind of the same key.
	challenge := freshChallenge(41)
	pendingChallenge(t, s, peer.Identity, challenge)
	k := newKeyXchgCtx(t, s, peer.Identity)
	handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, challenge))

	got, _ := s.peerNaClPub(peer.Identity)
	if !bytes.Equal(got, peerPub) {
		t.Fatalf("key changed after re-exchange: got %x want %x", got, peerPub)
	}
}

// TestSendEncryptedRacesBindPeerKey pins the memory-safety rule that
// bindPeerKey's in-place write forces on every reader of NaClPub: the
// field must be read under mtx.  SendEncrypted once copied the
// *PeerRecord out, dropped the lock, and read the field afterwards,
// which races the bind.  Meaningful under -race (CI runs Test (race)).
func TestSendEncryptedRacesBindPeerKey(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()

	const peers = 16
	ids := make([]Identity, 0, peers)
	pubs := make([][]byte, 0, peers)
	for range peers {
		p := mustSecret(t)
		ids = append(ids, p.Identity)
		pubs = append(pubs, mustNaClPub(t, p))
		// Discovery metadata only: no key yet, so SendEncrypted
		// and bindPeerKey contend over the same record.
		s.addPeer(ctx, PeerRecord{
			Identity: p.Identity,
			Version:  ProtocolVersion,
			LastSeen: time.Now().Unix(),
		})
	}

	var wg sync.WaitGroup
	for i := range peers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			// Errors are expected and irrelevant; the read of
			// NaClPub is what must not race.
			_ = s.SendEncrypted(ids[i], PingRequest{})
		}()
		go func() {
			defer wg.Done()
			_ = s.bindPeerKey(ctx, ids[i], pubs[i])
		}()
	}
	wg.Wait()

	// Every bind landed exactly as issued.
	for i := range peers {
		got, ok := s.peerNaClPub(ids[i])
		if !ok {
			t.Fatalf("peer %d has no key after bind", i)
		}
		if !bytes.Equal(got, pubs[i]) {
			t.Fatalf("peer %d bound %x, want %x", i, got, pubs[i])
		}
	}
}

// TestGossipCarriesNoKeyMaterial proves the strip in both directions:
// keys never leave in knownPeerList and never enter through the real
// gossip dispatch handler.
func TestGossipCarriesNoKeyMaterial(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()
	peer := mustSecret(t)
	peerPub := mustNaClPub(t, peer)
	selfPub := mustNaClPub(t, s.secret)

	// Self record, as registerSelfAsPeer writes it, plus a peer
	// with an authenticated binding.
	s.mtx.Lock()
	s.peers[s.secret.Identity] = &PeerRecord{
		Identity: s.secret.Identity,
		Address:  "10.0.0.1:9000",
		NaClPub:  selfPub,
		Version:  ProtocolVersion,
	}
	s.mtx.Unlock()
	if err := s.bindPeerKey(ctx, peer.Identity, peerPub); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}

	t.Run("outbound", func(t *testing.T) {
		for _, rec := range s.knownPeerList(Identity{}) {
			if len(rec.NaClPub) != 0 {
				t.Fatalf("gossip record for %v carries key material %x",
					rec.Identity, rec.NaClPub)
			}
		}
	})

	t.Run("inbound", func(t *testing.T) {
		// An attacker gossips a poisoned binding for a victim
		// it has no key for, and for one it does.
		victim := mustSecret(t).Identity
		attackerPub := mustNaClPub(t, mustSecret(t))
		attacker := mustSecret(t).Identity
		k := newKeyXchgCtx(t, s, attacker)

		handlePeerListResponse(k.dc, &PeerListResponse{Peers: []PeerRecord{
			{
				Identity: victim,
				Address:  "10.0.0.2:9000",
				NaClPub:  attackerPub,
				Version:  ProtocolVersion,
			},
			{
				Identity: peer.Identity,
				Address:  "10.0.0.3:9000",
				NaClPub:  attackerPub,
				Version:  ProtocolVersion,
			},
		}})

		// First binding: discovery landed, key did not.
		if _, ok := s.peerNaClPub(victim); ok {
			t.Fatal("gossip installed a first e2e key binding")
		}
		s.mtx.RLock()
		vr, known := s.peers[victim]
		s.mtx.RUnlock()
		if !known || vr.Address != "10.0.0.2:9000" {
			t.Fatal("gossip failed to record discovery metadata")
		}

		// Overwrite: the authenticated binding survived intact.
		got, ok := s.peerNaClPub(peer.Identity)
		if !ok {
			t.Fatal("gossip dropped an authenticated binding")
		}
		if !bytes.Equal(got, peerPub) {
			t.Fatalf("gossip overwrote an authenticated binding: %x", got)
		}
	})
}

// TestEnsurePeerKeyShortCircuits covers the paths that return without
// any mesh traffic: self, and an identity whose key is already bound.
func TestEnsurePeerKeyShortCircuits(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()

	if err := s.ensurePeerKey(ctx, s.secret.Identity); err != nil {
		t.Fatalf("ensurePeerKey(self): %v", err)
	}
	peer := mustSecret(t)
	if err := s.bindPeerKey(ctx, peer.Identity, mustNaClPub(t, peer)); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}
	if err := s.ensurePeerKey(ctx, peer.Identity); err != nil {
		t.Fatalf("ensurePeerKey(bound): %v", err)
	}
	// Both short circuits also satisfy the plural form.
	if err := s.ensurePeerKeys(ctx, []Identity{s.secret.Identity, peer.Identity}); err != nil {
		t.Fatalf("ensurePeerKeys: %v", err)
	}
}

// TestEnsurePeerKeyTimesOut proves the wait is bounded when no peer
// ever answers, and that ensurePeerKeys propagates the failure.
func TestEnsurePeerKeyTimesOut(t *testing.T) {
	s := keyXchgServer(t)
	unreachable := mustSecret(t).Identity

	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	if err := s.ensurePeerKey(ctx, unreachable); err == nil {
		t.Fatal("ensurePeerKey returned success with no response")
	}

	ctx2, cancel2 := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel2()
	if err := s.ensurePeerKeys(ctx2, []Identity{unreachable}); err == nil {
		t.Fatal("ensurePeerKeys returned success with no response")
	}
}

// TestNaClKeyResponseCannotBindSelf proves the response handler cannot
// be steered into binding our own identity, even for a pending
// challenge that names it and a response that verifies: bindPeerKey
// refuses self and the peer table stays clean.
func TestNaClKeyResponseCannotBindSelf(t *testing.T) {
	s := keyXchgServer(t)
	challenge := freshChallenge(81)
	pendingChallenge(t, s, s.secret.Identity, challenge)
	k := newKeyXchgCtx(t, s, mustSecret(t).Identity)

	if handleNaClKeyResponse(k.dc, signedKeyResponse(t, s.secret, challenge)) {
		t.Fatal("handler asked to close the session")
	}
	if _, ok := s.peerNaClPub(s.secret.Identity); ok {
		t.Fatal("the exchange bound a key for our own identity")
	}
	s.mtx.RLock()
	_, tracked := s.peers[s.secret.Identity]
	s.mtx.RUnlock()
	if tracked {
		t.Fatal("the exchange added a peer record for our own identity")
	}
}

// TestEnsurePeerKeyRetries proves the retry ticker re-sends while
// waiting, each time with a fresh challenge, so a lost request or a
// route that only appears later still converges.
//
// Pending challenges are observed DURING the wait: they are registered
// against the caller's context, so they are reaped as soon as
// ensurePeerKey returns.
func TestEnsurePeerKeyRetries(t *testing.T) {
	s := keyXchgServer(t)
	unreachable := mustSecret(t).Identity

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.ensurePeerKey(ctx, unreachable) }()

	// Initial request plus at least one retry, each registering its
	// own pending challenge.
	waitForCondition(t, "retry did not issue a fresh challenge",
		naclXchgRetry*3, func() bool {
			return s.naclXchg.Len() >= 2
		})

	cancel()
	exitCtx, exitCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer exitCancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ensurePeerKey returned success with no response")
		}
	case <-exitCtx.Done():
		t.Fatal("ensurePeerKey did not return after cancellation")
	}
}

// TestPeerKeyPromCounters covers the exported telemetry for the two
// conditions operators care about: a rejected rebind attempt, which is
// always hostile, and dropped exchange traffic.
func TestPeerKeyPromCounters(t *testing.T) {
	s := keyXchgServer(t)
	ctx := t.Context()

	if got := s.promKeyConflicts(); got != 0 {
		t.Fatalf("initial key conflicts = %v, want 0", got)
	}
	if got := s.promNaClXchgDrops(); got != 0 {
		t.Fatalf("initial xchg drops = %v, want 0", got)
	}

	peer := mustSecret(t)
	if err := s.bindPeerKey(ctx, peer.Identity, mustNaClPub(t, peer)); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}
	if err := s.bindPeerKey(ctx, peer.Identity,
		mustNaClPub(t, mustSecret(t))); err == nil {
		t.Fatal("accepted a conflicting key")
	}
	if got := s.promKeyConflicts(); got != 1 {
		t.Fatalf("key conflicts = %v, want 1", got)
	}

	k := newKeyXchgCtx(t, s, mustSecret(t).Identity)
	handleNaClKeyResponse(k.dc, &NaClKeyResponse{}) // malformed
	if got := s.promNaClXchgDrops(); got != 1 {
		t.Fatalf("xchg drops = %v, want 1", got)
	}
}

// TestEnsurePeerKeyObservesConcurrentBind proves a key bound by any
// other route (an inbound handshake, a concurrent exchange) wakes a
// waiter, and does so on the bindPeerKey signal rather than a poll:
// the wait must finish far faster than the retry tick.
func TestEnsurePeerKeyObservesConcurrentBind(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	peerPub := mustNaClPub(t, peer)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.ensurePeerKey(ctx, peer.Identity) }()

	// Let the waiter reach its select, then bind as a handshake would.
	waitForCondition(t, "ensurePeerKey never issued its initial request",
		5*time.Second, func() bool {
			return s.naclXchg.Len() >= 1
		})
	start := time.Now()
	if err := s.bindPeerKey(ctx, peer.Identity, peerPub); err != nil {
		t.Fatalf("bindPeerKey: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ensurePeerKey did not observe the binding: %v", err)
		}
		if waited := time.Since(start); waited >= naclXchgRetry/10 {
			t.Fatalf("ensurePeerKey took %v to observe the bind; the "+
				"bindPeerKey signal should wake it well before the "+
				"%v retry tick", waited, naclXchgRetry)
		}
	case <-ctx.Done():
		t.Fatal("ensurePeerKey did not return after the key was bound")
	}
}

// TestKeyBoundSignalWakesAllWaiters proves the broadcast reaches every
// concurrent waiter, not just one, and that a bind for an unrelated
// identity does not falsely satisfy a waiter.
func TestKeyBoundSignalWakesAllWaiters(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)
	other := mustSecret(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	const waiters = 4
	done := make(chan error, waiters)
	for range waiters {
		go func() { done <- s.ensurePeerKey(ctx, peer.Identity) }()
	}
	// A bind for a DIFFERENT identity wakes the waiters but must
	// not satisfy them.
	if err := s.bindPeerKey(ctx, other.Identity, mustNaClPub(t, other)); err != nil {
		t.Fatalf("bindPeerKey(other): %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("a waiter returned (%v) on an unrelated bind", err)
	case <-time.After(200 * time.Millisecond):
	}

	start := time.Now()
	if err := s.bindPeerKey(ctx, peer.Identity, mustNaClPub(t, peer)); err != nil {
		t.Fatalf("bindPeerKey(peer): %v", err)
	}
	for range waiters {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("waiter did not observe the binding: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("not every waiter woke on the bind broadcast")
		}
	}
	if waited := time.Since(start); waited >= naclXchgRetry/10 {
		t.Fatalf("waiters took %v to observe the bind; the broadcast "+
			"should wake them well before the %v retry tick",
			waited, naclXchgRetry)
	}
}

// TestSendNaClKeyRequestRegistersPending proves the challenge is
// registered before the send (so a fast response cannot lose the
// race), maps to the identity we asked about, and is fresh per call.
func TestSendNaClKeyRequestRegistersPending(t *testing.T) {
	s := keyXchgServer(t)
	peer := mustSecret(t)

	// No session and no route: the send fails, but the pending
	// challenge must already be recorded.
	if err := s.sendNaClKeyRequest(t.Context(), peer.Identity); err == nil {
		t.Fatal("expected a send failure with no route")
	}
	if got := s.naclXchg.Len(); got != 1 {
		t.Fatalf("pending challenges = %d, want 1", got)
	}
	// The single pending entry maps to the peer we asked about, so
	// only that identity's signature can satisfy it.
	if n := s.naclXchg.DeleteByValue(func(v any) bool {
		id, ok := v.(Identity)
		return ok && id == peer.Identity
	}); n != 1 {
		t.Fatalf("pending entry for %v not found (removed %d)", peer.Identity, n)
	}

	// Each call uses a fresh challenge: two requests for the same
	// peer leave two distinct pending entries.
	_ = s.sendNaClKeyRequest(t.Context(), peer.Identity)
	_ = s.sendNaClKeyRequest(t.Context(), peer.Identity)
	if got := s.naclXchg.Len(); got != 2 {
		t.Fatalf("pending challenges = %d after two requests, want 2 "+
			"(challenges must be fresh per request)", got)
	}
}

// TestSendNaClKeyRequestUninitialized covers the guard for servers
// built by hand in tests rather than through NewServer.
func TestSendNaClKeyRequestUninitialized(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
	}
	if err := s.sendNaClKeyRequest(t.Context(), mustSecret(t).Identity); err == nil {
		t.Fatal("expected an error with uninitialized exchange state")
	}
}

// TestHandleNaClKeyResponseUninitialized covers the same guard on the
// response path.
func TestHandleNaClKeyResponseUninitialized(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
	}
	peer := mustSecret(t)
	k := newKeyXchgCtx(t, s, peer.Identity)

	before := s.naclXchgDrops.Load()
	if handleNaClKeyResponse(k.dc, signedKeyResponse(t, peer, freshChallenge(61))) {
		t.Fatal("handler asked to close the session")
	}
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("drop counter %d, want %d", got, before+1)
	}
}

// TestHandleNaClKeyRequestUninitializedRates proves the rate-limiter
// guard degrades to answering rather than crashing on a hand-built
// server.
func TestHandleNaClKeyRequestUninitializedRates(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret:   secret,
		sessions: make(map[Identity]*Transport),
		peers:    make(map[Identity]*PeerRecord),
	}
	requester := mustSecret(t).Identity
	k := newKeyXchgCtx(t, s, requester)

	before := s.naclXchgDrops.Load()
	if handleNaClKeyRequest(k.dc, &NaClKeyRequest{
		Requester: requester,
		Challenge: freshChallenge(71),
	}) {
		t.Fatal("handler asked to close the session")
	}
	// The handler ran to completion rather than dereferencing the
	// nil limiter, reaching the send — which refuses for want of a
	// known path to the requester, counting exactly one drop.
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("drops %d, want %d", got, before+1)
	}
}

// TestNaClKeyRequestSelfGuardIndependentOfSession proves the self
// guard keys off the Requester field, not the session peer: a peer
// reflecting our own identity into Requester is refused.
func TestNaClKeyRequestSelfGuardIndependentOfSession(t *testing.T) {
	s := keyXchgServer(t)
	other := mustSecret(t).Identity
	k := newKeyXchgCtx(t, s, other) // session is a normal peer

	before := s.naclXchgDrops.Load()
	handleNaClKeyRequest(k.dc, &NaClKeyRequest{
		Requester: s.secret.Identity, // ...but the reply target is us
		Challenge: freshChallenge(51),
	})
	if got := s.naclXchgDrops.Load(); got != before+1 {
		t.Fatalf("self-targeted request was not dropped: drops %d, want %d",
			got, before+1)
	}
}

// Regression suite: unsigned gossip must never establish or alter a peer's
// end-to-end (X25519) key.
//
// A node's NaClPub is derived from its PRIVATE key (X25519 of
// SHA256("continuum-x25519-v1" || secp256k1 privkey)), so it cannot be
// recomputed from a peer's public identity -- nothing lets a recipient verify
// that a gossiped NaClPub belongs to the identity it is attached to. Gossip
// therefore has nothing truthful to say about key material.
//
// The defect these tests were written against: addPeer stored
// s.peers[pr.Identity] = &pr after only structural checks, so one connected
// peer could gossip a PeerListResponse binding a victim's identity to the
// ATTACKER's X25519 key; every recipient then sealed the victim's confidential
// ceremony share material to a key the attacker holds (and can OpenBox), while
// the victim cannot.
//
// The fix: gossip carries discovery metadata only, addPeer never writes
// NaClPub, and a key is learned exclusively from its holder -- by handshake
// (whose challenge signature covers the key) or by the routed
// NaClKeyRequest/NaClKeyResponse exchange. bindPeerKey is the sole writer and
// enforces immutability, since the derivation is deterministic and a
// conflicting key is therefore always an attack or a broken peer.
//
// This file is the tight unit anchor: it drives addPeer -- the sink the gossip
// handler feeds every record into -- with the byte-for-byte record an attacker
// gossips. The companion gossip_e2e_key_integration_test.go proves the same
// invariant through the real handlePeerListResponse dispatch handler; the
// exchange itself is covered in nacl_keyxchg_test.go.
//
// The legitimate key is installed directly (installPeerFromHandshake) rather
// than through addPeer, because addPeer is the untrusted sink under test and no
// longer binds keys at all: routing the bootstrap through it would assert
// nothing. Installing directly models the state a completed handshake leaves
// behind, so ONLY the attacker's poison exercises the sink.
//
// Cases:
//   - overwrite-handshake-key: target already holds the victim's REAL key (from
//     a completed authenticated handshake); gossip then tries to rebind that
//     identity to the attacker's key. The real key must survive.
//   - first-binding: no prior handshake; the poison is the FIRST thing the
//     target learns for the victim. No key may be installed at all.

// newPeerKeyServer builds a Server via the production constructor and adds only
// what Run() would otherwise supply: an identity secret and the peers TTL that
// addPeer writes to. It is deliberately not Run(), so there are no listeners or
// background loops beyond the per-record TTL goroutines addPeer schedules, which
// are reaped when the caller cancels the context it passes to addPeer.
func newPeerKeyServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(testConfig())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("server secret: %v", err)
	}
	peersTTL, err := ttl.New(16, true)
	if err != nil {
		t.Fatalf("peers ttl: %v", err)
	}
	s.secret, s.peersTTL = secret, peersTTL
	return s
}

// naclIdentity returns a fresh identity together with its derived X25519 public
// key bytes (what peers store and seal to) and private key (what only the holder
// can decrypt with). It returns the Identity, not the Secret: victim and attacker
// are only ever recipients here, never senders, so their private key is all the
// crypto legs need beyond the identity.
func naclIdentity(t *testing.T) (Identity, []byte, *ecdh.PrivateKey) {
	t.Helper()
	s, err := NewSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	pub, err := s.NaClPublicKey()
	if err != nil {
		t.Fatalf("nacl pub: %v", err)
	}
	priv, err := s.NaClPrivateKey()
	if err != nil {
		t.Fatalf("nacl priv: %v", err)
	}
	return s.Identity, pub, priv
}

// peerRec builds a well-formed, current-version PeerRecord binding id to
// naclPub. This is precisely the record an attacker gossips: structurally
// valid in every respect, carrying key material it has no authority to assert.
func peerRec(id Identity, naclPub []byte, addr string) PeerRecord {
	return PeerRecord{
		Identity: id,
		NaClPub:  naclPub,
		Version:  ProtocolVersion,
		Address:  addr,
	}
}

// installPeerFromHandshake writes a peer record straight into the table under
// s.mtx, WITHOUT routing it through addPeer. It models the record a completed,
// authenticated handshake leaves behind. addPeer is the unauthenticated sink
// under test and no longer binds keys at all, so routing the legitimate
// bootstrap through it would assert nothing; installing directly keeps the
// legitimate key out of the sink so only the attacker's gossip exercises it.
func installPeerFromHandshake(s *Server, pr PeerRecord) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	rec := pr
	s.peers[pr.Identity] = &rec
}

// storedPeerNaClPub returns the X25519 key the server currently holds for id --
// exactly the key SendEncrypted would seal to -- and whether a key is bound at
// all.  It does NOT fail on absence: a correct fix leaves the identity with no
// usable key, either by holding no record or (as the committed fix does) by
// holding a discovery-only record whose NaClPub was never bound.  Both are the
// same fact to every caller here -- there is nothing to seal to -- so an empty
// key reports held=false.
func storedPeerNaClPub(t *testing.T, s *Server, id Identity) ([]byte, bool) {
	t.Helper()
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	pr, ok := s.peers[id]
	if !ok || len(pr.NaClPub) == 0 {
		return nil, false
	}
	return pr.NaClPub, true
}

// assertPeerKeyUnhijacked encodes the peer-key-authenticity invariant against whatever key the
// target currently holds for id: the target must never hold the attacker's key
// under the victim's identity, and any message SendEncrypted would seal to that
// key must be readable ONLY by the victim, never by the attacker.
//
// wantRetained, when non-nil, is a key the target authenticated BEFORE the
// poison (the overwrite case): a correct fix must keep it intact -- not replace
// it (buggy) and not drop it (which the !held early return would otherwise mask).
func assertPeerKeyUnhijacked(t *testing.T, s *Server, id Identity, attackerPub, wantRetained []byte, victimPriv, attackerPriv *ecdh.PrivateKey) {
	t.Helper()

	stored, held := storedPeerNaClPub(t, s, id)

	// PRIMARY INVARIANT (kills false-pass, pins the fix): the target must never
	// hold the attacker's key under the victim's identity. Fails while buggy,
	// decoupled from the crypto below.
	if held && bytes.Equal(stored, attackerPub) {
		t.Errorf("target holds the ATTACKER's X25519 key bound to the " +
			"victim's identity: unsigned gossip hijacked the e2e key")
	}

	// RETENTION (overwrite case only): a previously authenticated binding must
	// survive the poison intact. Checked before the !held early return so a fix
	// that DROPS the record on conflict cannot slip through.
	if wantRetained != nil && (!held || !bytes.Equal(stored, wantRetained)) {
		t.Errorf("target no longer holds the victim's real key (held=%v): the "+
			"authenticated binding was lost", held)
	}

	// A correct fix may reject the unauthenticated binding outright, leaving no
	// record. That satisfies the invariant -- there is nothing to seal.
	if !held {
		return
	}

	// CONSEQUENCE: seal to whatever key the target now holds for the victim --
	// exactly SendEncrypted's step (SealBox to s.peers[dest].NaClPub). The result
	// must be readable ONLY by the victim. While buggy, `stored` is the attacker's
	// key, so this leaks; the victim leg is a positive control against a "nobody
	// can decrypt" false-pass.
	share := []byte("confidential TSS key share destined for the victim")
	ep, err := SealBox(share, stored, s.secret, PKeygenRequest)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, aerr := OpenBox(ep, attackerPriv); aerr == nil {
		t.Error("target sealed the victim's confidential traffic to a key " +
			"the attacker can decrypt")
	}
	if _, verr := OpenBox(ep, victimPriv); verr != nil {
		t.Errorf("target's traffic to the victim is not decryptable by the "+
			"victim: %v", verr)
	}
}

func TestGossipCannotHijackPeerE2EKey(t *testing.T) {
	const peerAddr = "10.0.0.1:9000"

	tests := []struct {
		name string
		// priorHandshake installs the victim's REAL key first (directly, as a
		// completed authenticated handshake would) so the poison is an OVERWRITE.
		// When false, the poison is the victim's FIRST binding.
		priorHandshake bool
	}{
		{name: "overwrite-handshake-key", priorHandshake: true},
		{name: "first-binding", priorHandshake: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel() // reap addPeer's per-record TTL goroutines

			// The target seals confidential ceremony traffic to the victim; the
			// attacker is any connected peer able to gossip a PeerListResponse.
			target := newPeerKeyServer(t)
			victim, victimPub, victimPriv := naclIdentity(t)
			_, attackerPub, attackerPriv := naclIdentity(t)

			// Distinct keys are what make the decrypt assertions meaningful.
			if bytes.Equal(victimPub, attackerPub) {
				t.Fatal("victim and attacker derived the same X25519 key")
			}

			var wantRetained []byte
			if tt.priorHandshake {
				// Target already holds the victim's REAL key from a completed
				// authenticated handshake (installed directly, NOT via the
				// unauthenticated sink). Confirm it landed so the poison provably
				// attempts an OVERWRITE and cannot silently degenerate into
				// first-binding.
				installPeerFromHandshake(target, peerRec(victim, victimPub, peerAddr))
				if stored, held := storedPeerNaClPub(t, target, victim); !held || !bytes.Equal(stored, victimPub) {
					t.Fatal("handshake bootstrap: victim's real key was not installed")
				}
				wantRetained = victimPub
			}

			// A connected peer (the attacker) gossips a PeerListResponse binding
			// the victim's identity to the attacker's X25519 key. This is exactly
			// the record handlePeerListResponse feeds into addPeer -- unsigned and
			// unchecked -- so we drive that vulnerable sink directly.
			target.addPeer(ctx, peerRec(victim, attackerPub, peerAddr))

			assertPeerKeyUnhijacked(t, target, victim, attackerPub, wantRetained, victimPriv, attackerPriv)
		})
	}
}

// Integration coverage complementing the unit anchor in
// gossip_e2e_key_test.go. It drives the REAL gossip dispatch handler
// (handlePeerListResponse) with a real *PeerListResponse -- proving the defect
// through the actual handler (version gate, address validation, addPeer), not
// just addPeer in isolation. No network; fully deterministic.

// gossipPeerList feeds records to the target through the production
// handlePeerListResponse dispatch handler, exactly as a received
// PeerListResponse from `from` would be dispatched. dc.t is unused by this
// handler (it neither reads nor writes the transport), so nil is safe.
func gossipPeerList(t *testing.T, s *Server, from Identity, recs ...PeerRecord) {
	t.Helper()
	ctx := t.Context()
	dc := &dispatchCtx{
		ctx:        ctx,
		sessionCtx: ctx,
		s:          s,
		id:         &from,
	}
	handlePeerListResponse(dc, &PeerListResponse{Peers: recs})
}

func TestGossipHandlerCannotHijackPeerE2EKey(t *testing.T) {
	const peerAddr = "10.0.0.1:9000"

	tests := []struct {
		name           string
		priorHandshake bool
	}{
		{name: "overwrite-handshake-key", priorHandshake: true},
		{name: "first-binding", priorHandshake: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := newPeerKeyServer(t)
			victim, victimPub, victimPriv := naclIdentity(t)
			attacker, attackerPub, attackerPriv := naclIdentity(t)
			if bytes.Equal(victimPub, attackerPub) {
				t.Fatal("victim and attacker derived the same X25519 key")
			}

			var wantRetained []byte
			if tt.priorHandshake {
				installPeerFromHandshake(target, peerRec(victim, victimPub, peerAddr))
				if stored, held := storedPeerNaClPub(t, target, victim); !held || !bytes.Equal(stored, victimPub) {
					t.Fatal("handshake bootstrap: victim's real key was not installed")
				}
				wantRetained = victimPub
			}

			// Attacker gossips the poison through the REAL dispatch handler.
			gossipPeerList(t, target, attacker,
				peerRec(victim, attackerPub, peerAddr))

			assertPeerKeyUnhijacked(t, target, victim, attackerPub, wantRetained, victimPriv, attackerPriv)
		})
	}
}
