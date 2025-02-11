// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
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
