// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package memory

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
)

// TestPutTSSKeyIndexing verifies a TSS key enrolled under its
// aggregated pubkey is discoverable via the ECDSA-signable address
// forms (P2PKH, P2WPKH) and NOT via the taproot form.  ECDSA
// signatures cannot satisfy a BIP-341 key-path spend, so the TSS
// address surface must exclude P2TR.
func TestPutTSSKeyIndexing(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := New(params)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a pubkey to stand in for the aggregated TSS group key.
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PubKey()

	keyID := []byte("test-tss-key-id-0")
	err = m.PutTSSKey(&zuul.TSSNamedKey{
		Name:      "tss",
		KeyID:     keyID,
		PublicKey: pub,
	})
	if err != nil {
		t.Fatalf("PutTSSKey: %v", err)
	}

	pkHash := btcutil.Hash160(pub.SerializeCompressed())
	p2pkh, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(pub)
	p2tr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}

	// Both P2PKH and P2WPKH must resolve to the TSS key.
	for _, tc := range []struct {
		name string
		addr btcutil.Address
	}{
		{"P2PKH", p2pkh},
		{"P2WPKH", p2wpkh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.GetTSSKey(tc.addr)
			if err != nil {
				t.Fatalf("GetTSSKey: %v", err)
			}
			if string(got.KeyID) != string(keyID) {
				t.Fatalf("keyID mismatch: got %x want %x", got.KeyID, keyID)
			}

			tnk, ok, err := m.LookupTSSKeyByAddr(tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			if !ok || tnk == nil {
				t.Fatal("LookupTSSKeyByAddr: not found")
			}
		})
	}

	// P2TR must NOT resolve to a TSS key.  ECDSA cannot sign a key-path
	// taproot spend; exposing the TSS key under this address would be
	// a soft footgun for anyone trying to send to that taproot output.
	if _, err := m.GetTSSKey(p2tr); err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
		t.Fatalf("GetTSSKey(p2tr): expected ErrKeyDoesntExist, got %v", err)
	}
	if _, ok, _ := m.LookupTSSKeyByAddr(p2tr); ok {
		t.Fatal("LookupTSSKeyByAddr(p2tr): must not resolve")
	}
}

// TestPutTSSKeyPurgeRoundTrip verifies PurgeTSSKey removes every
// indexed address form in a single call.
func TestPutTSSKeyPurgeRoundTrip(t *testing.T) {
	params := &chaincfg.TestNet3Params
	m, err := New(params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PubKey()

	err = m.PutTSSKey(&zuul.TSSNamedKey{
		Name:      "purge-test",
		KeyID:     []byte("kid-purge"),
		PublicKey: pub,
	})
	if err != nil {
		t.Fatal(err)
	}

	pkHash := btcutil.Hash160(pub.SerializeCompressed())
	p2pkh, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}

	// Purge via P2WPKH form should drop P2PKH too.
	err = m.PurgeTSSKey(p2wpkh)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.GetTSSKey(p2pkh); err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
		t.Fatalf("P2PKH still present after purge: %v", err)
	}
	if _, err := m.GetTSSKey(p2wpkh); err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
		t.Fatalf("P2WPKH still present after purge: %v", err)
	}
}

// TestPutTSSKeyRequiresFields verifies that PutTSSKey rejects
// malformed inputs: nil key struct, nil public key, or zero-length
// keyID.
func TestPutTSSKeyRequiresFields(t *testing.T) {
	m, err := New(&chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := m.PutTSSKey(nil); err == nil {
		t.Fatal("nil TSSNamedKey: expected error")
	}
	if err := m.PutTSSKey(&zuul.TSSNamedKey{KeyID: []byte("k")}); err == nil {
		t.Fatal("missing PublicKey: expected error")
	}
	if err := m.PutTSSKey(&zuul.TSSNamedKey{PublicKey: priv.PubKey()}); err == nil {
		t.Fatal("missing KeyID: expected error")
	}
}

// TestPutKeyVsPutTSSKeyCollision verifies that a local private key
// and a TSS key cannot claim the same address: attempting to enrol
// one when the other already holds that address must fail with
// ErrKeyExists.
func TestPutKeyVsPutTSSKeyCollision(t *testing.T) {
	m, err := New(&chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Enrol as local first; TSS enrolment for the same pubkey must
	// then fail because the P2PKH/P2WPKH slots are taken.
	if err := m.PutKey(&zuul.NamedKey{Name: "local", PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	err = m.PutTSSKey(&zuul.TSSNamedKey{
		Name:      "tss",
		KeyID:     []byte("kid"),
		PublicKey: priv.PubKey(),
	})
	if err == nil || !errors.Is(err, zuul.ErrKeyExists) {
		t.Fatalf("expected ErrKeyExists for TSS after local, got %v", err)
	}

	// Reverse direction: fresh zuul, TSS first, local second.
	m2, err := New(&chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	err = m2.PutTSSKey(&zuul.TSSNamedKey{
		Name:      "tss",
		KeyID:     []byte("kid2"),
		PublicKey: priv2.PubKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = m2.PutKey(&zuul.NamedKey{Name: "local", PrivateKey: priv2})
	if err == nil || !errors.Is(err, zuul.ErrKeyExists) {
		t.Fatalf("expected ErrKeyExists for local after TSS, got %v", err)
	}
}

// TestPurgeTSSKeyUnknownAddress verifies PurgeTSSKey returns
// ErrKeyDoesntExist when asked to purge a TSS address that was
// never enrolled.
func TestPurgeTSSKeyUnknownAddress(t *testing.T) {
	params := &chaincfg.TestNet3Params
	m, err := New(params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}

	err = m.PurgeTSSKey(addr)
	if err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
		t.Fatalf("PurgeTSSKey on unknown addr: expected ErrKeyDoesntExist, got %v", err)
	}
}
