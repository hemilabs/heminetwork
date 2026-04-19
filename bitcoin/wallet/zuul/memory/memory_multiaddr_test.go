// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package memory

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
)

// TestMultiAddressIndexing verifies that a key put under one address
// form is discoverable via all address forms that derive from the same
// public key (P2PKH, P2WPKH, BIP-86 P2TR).
func TestMultiAddressIndexing(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := New(params)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a deterministic key.
	xprv := "xprv9s21ZrQH143K3ScRXhao5KSyozmph3B3Bop8C1iqnyCgXSpUDE8oYDsz2hDp897fwwqdsTFYKNQVg5jn5nLH2QkZWeF9MZeMwkbkN8uAafy"
	ek, err := hdkeychain.NewKeyFromString(xprv)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ek.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}

	err = m.PutKey(&zuul.NamedKey{
		Name:       "test",
		PrivateKey: priv,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Derive each address form that zuul should now recognize.
	pubCompressed := priv.PubKey().SerializeCompressed()
	pkHash := btcutil.Hash160(pubCompressed)

	p2pkh, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	btcecPub, err := btcec.ParsePubKey(pubCompressed)
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(btcecPub)
	p2tr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		addr btcutil.Address
	}{
		{"P2PKH", p2pkh},
		{"P2WPKH", p2wpkh},
		{"P2TR-BIP86", p2tr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.GetKey(tc.addr)
			if err != nil {
				t.Fatalf("GetKey: %v", err)
			}
			if got.PrivateKey == nil || !got.PrivateKey.Key.Equals(&priv.Key) {
				t.Fatalf("GetKey returned wrong key")
			}

			gotPriv, ok, err := m.LookupKeyByAddr(tc.addr)
			if err != nil {
				t.Fatalf("LookupKeyByAddr: %v", err)
			}
			if !ok {
				t.Fatal("LookupKeyByAddr: not found")
			}
			if !gotPriv.Key.Equals(&priv.Key) {
				t.Fatal("LookupKeyByAddr returned wrong key")
			}
		})
	}

	// Purging via any address form must remove all three entries.
	err = m.PurgeKey(p2wpkh) // use segwit address to exercise non-legacy path
	if err != nil {
		t.Fatalf("PurgeKey: %v", err)
	}

	for _, tc := range []struct {
		name string
		addr btcutil.Address
	}{
		{"P2PKH", p2pkh},
		{"P2WPKH", p2wpkh},
		{"P2TR-BIP86", p2tr},
	} {
		t.Run("PurgedNotFound_"+tc.name, func(t *testing.T) {
			_, err := m.GetKey(tc.addr)
			if err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
				t.Fatalf("expected ErrKeyDoesntExist, got %v", err)
			}
		})
	}
}

// TestPutDuplicateAcrossAddressForms verifies that attempting to
// re-insert the same key (with any of its address forms already
// indexed) returns ErrKeyExists and does not mutate state.
func TestPutDuplicateAcrossAddressForms(t *testing.T) {
	params := &chaincfg.TestNet3Params
	m, err := New(params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = m.PutKey(&zuul.NamedKey{Name: "first", PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}

	// Re-insert: every address form already maps to a key, so the
	// insert must fail with ErrKeyExists.
	err = m.PutKey(&zuul.NamedKey{Name: "dup", PrivateKey: priv})
	if err == nil || !errors.Is(err, zuul.ErrKeyExists) {
		t.Fatalf("expected ErrKeyExists, got %v", err)
	}

	// Ensure the original key is still retrievable and unchanged.
	pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
	p2pkh, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	nk, err := m.GetKey(p2pkh)
	if err != nil {
		t.Fatal(err)
	}
	if nk.Name != "first" {
		t.Fatalf("original key was overwritten: got name %q", nk.Name)
	}
}

// TestPurgeKeyUnknownAddress verifies PurgeKey returns
// ErrKeyDoesntExist when asked to purge an address that was never
// enrolled.  Without this guard the caller would have no feedback
// that the purge was a no-op.
func TestPurgeKeyUnknownAddress(t *testing.T) {
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

	err = m.PurgeKey(addr)
	if err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
		t.Fatalf("PurgeKey on unknown addr: expected ErrKeyDoesntExist, got %v", err)
	}
}

// TestPurgeKeyZeroesOutstandingReference demonstrates the
// documented contract for PurgeKey: a caller holding a pointer to
// the private key observes zeroed scalar bytes after the purge.
// This is not a bug, it is the security guarantee — PurgeKey
// destroys the key material rather than leaving dangling
// references usable.  The test exists so a future maintainer who
// accidentally removes the Zero() call sees this fail and
// rediscovers why the zeroing is there.
func TestPurgeKeyZeroesOutstandingReference(t *testing.T) {
	params := &chaincfg.TestNet3Params
	m, err := New(params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	err = m.PutKey(&zuul.NamedKey{Name: "sacrificial", PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}

	pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}

	nk, err := m.GetKey(addr)
	if err != nil {
		t.Fatal(err)
	}
	// Hold an outstanding reference to the underlying scalar.
	outstandingPriv := nk.PrivateKey
	if outstandingPriv.Key.IsZero() {
		t.Fatal("private key was zero before purge — test setup broken")
	}

	if err := m.PurgeKey(addr); err != nil {
		t.Fatalf("PurgeKey: %v", err)
	}

	// The outstanding reference now points at a zeroed scalar.  A
	// sign attempt using it would produce garbage.  The contract
	// is working as documented.
	if !outstandingPriv.Key.IsZero() {
		t.Fatal("PurgeKey did not zero the outstanding private key scalar")
	}
}
