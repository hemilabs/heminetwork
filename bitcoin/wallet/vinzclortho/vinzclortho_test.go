// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package vinzclortho

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/davecgh/go-spew/spew"
	"github.com/tyler-smith/go-bip39"
)

func TestDerivePath(t *testing.T) {
	mnemonic := "dinosaur banner version pistol need area dream champion kiss thank business shrug explain intact puzzle"
	vc, err := New(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	err = vc.Unlock(mnemonic)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Source https://iancoleman.io/bip39/
	expect := []string{
		"1JrfuYPAWrum33zGXK136n6gM8KNj1PUR3",
		"1ASZnMhiWXJ8aGigzYAXBeXVdRkbeMK7sS",
		"12kP3USpmHMynnXXvP3APhoPHqCNZTnLzr",
		"1G4ppesVsX1CSUDzVaXEJAh5UHPm7LeM48",
		"157mHF16CG39h6YWDY4QbAEoHjzeguiENd",
	}
	// standard HD key path m/1337'/0'/0'
	for k := range expect {
		path := fmt.Sprintf("m/1337'/0'/%v'", k)
		ek, err := vc.DerivePath(path)
		if err != nil {
			t.Fatalf("derive path: %v", err)
		}
		addr, _, err := AddressAndPublicFromExtended(&chaincfg.MainNetParams, ek)
		if err != nil {
			t.Fatalf("address: %v", err)
		}
		if addr.String() != expect[k] {
			t.Logf("invalid address %v: %v != %v",
				k, addr, expect[k])
		}

		// Now derive using DeriveHD
		ek2, err := vc.DeriveHD(1337, 0, uint32(k))
		if err != nil {
			t.Fatalf("derive uint path: %v", err)
		}
		addr2, _, _ := AddressAndPublicFromExtended(&chaincfg.MainNetParams, ek2)
		if addr2.String() != addr.String() {
			t.Fatalf("got %v, wanted %v", addr2, addr)
		}
	}

	// Mix HD+normal path m/1337'/0'/0
	expect = []string{
		"1NLymtCszixrUGt3T2k1jdKzdQMvMRAFZ2",
		"1Bwsc2kLDXJ1oxY24SAeBNinQg9jJcRWdn",
		"1Q6y8LZUG7vPa2TvgKHvhcn754zpq6TbRc",
		"1SR7Hj2NAPKQumDZN6MgfmE3Ab69QDx1K",
		"12efxcdszLdBXR9FZMMgSvgEwW1tBnJHg4",
	}
	for k := range expect {
		path := fmt.Sprintf("m/1337'/0'/%v", k)
		ek, err := vc.DerivePath(path)
		if err != nil {
			t.Fatalf("derive path: %v", err)
		}
		addr, _, err := AddressAndPublicFromExtended(&chaincfg.MainNetParams, ek)
		if err != nil {
			t.Fatalf("address: %v", err)
		}
		if addr.String() != expect[k] {
			t.Logf("invalid address %v: %v != %v",
				k, addr, expect[k])
		}
	}

	// Test negative paths
	path := ""
	_, err = vc.DerivePath(path)
	if err == nil {
		t.Fatalf("expected invalid path")
	}

	path = "m"
	_, err = vc.DerivePath(path)
	if err == nil {
		t.Fatalf("expected invalid path")
	}

	path = "m/"
	_, err = vc.DerivePath(path)
	if err == nil {
		t.Fatalf("invalid syntax")
	}

	path = "x/1337'/0'"
	_, err = vc.DerivePath(path)
	if err == nil {
		t.Fatalf("expected invalid prefix")
	}

	path = "m/A'/0'"
	_, err = vc.DerivePath(path)
	if err == nil {
		t.Fatalf("expected invalid syntax")
	}
}

func TestEntropyMnemonicSeed(t *testing.T) {
	// Do the whole rigamarole of Entropy -> Mnemonic -> Seed
	entropy, err := bip39.NewEntropy(128) // 128 bits of entropy
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(entropy))

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(mnemonic))

	entropyX, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(entropyX))

	if !bytes.Equal(entropy, entropyX) {
		t.Fatal("entropy not equal")
	}

	// The following is educational only on how to get to a master key.
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(seed))

	seed2 := bip39.NewSeed(mnemonic, "")
	t.Log(spew.Sdump(seed2))
	if !bytes.Equal(seed, seed2) {
		t.Fatal("seeds not equal")
	}

	mk, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(mk)) // check on https://iancoleman.io/bip39
}

func TestDeriveAddresses(t *testing.T) {
	// Test vectors generated on https://iancoleman.io/bip39 using bip32
	mnemonic := "dinosaur banner version pistol need area dream champion kiss thank business shrug explain intact puzzle"

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}

	mk, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(mk)) // check on https://iancoleman.io/bip39

	// Derive extended key for hardened account 0: m/0'
	acct0, err := mk.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(acct0))

	// Derive extended key for external hardened account 0 m/0'/0'
	acct0eh, err := acct0.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(acct0eh))
	pkHHash, err := acct0eh.Address(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(pkHHash))
	if pkHHash.String() != "14fjqmZJU7qrRtWHgVjh6jcoKjqu6y1gyM" {
		t.Fatal("invalid hardned address")
	}

	// Derive extended key for external account 0 m/0'/0
	acct0e, err := acct0.Derive(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(acct0e))
	pkHash, err := acct0e.Address(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(pkHash))
	if pkHash.String() != "1KWtnYZmQwnwCdGNwjbzpvh3YibNV6KWb9" {
		t.Fatal("invalid address")
	}
}

func TestVinzClorthoCreate(t *testing.T) {
	mnemonic := "dinosaur banner version pistol need area dream champion kiss thank business shrug explain intact puzzle"
	seed := "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634cb0602599b867332dfec245547baafae40dad247f21564a0de925527f2445a086fd"
	xpriv := "xprv9s21ZrQH143K4H14eaYTxfuxn6eDqoPhuQx2sRr9ZvmvkBQ39KMHfaNQ9GDdUkgRbibGXu66XQTZj9QJRSXBEibqrHb34BdJRPvqqiZMTCA"
	expectedAddress := "14fjqmZJU7qrRtWHgVjh6jcoKjqu6y1gyM"
	expectedPub, _ := hex.DecodeString("02dc2f5439d4e4e1d7da99daa5707d7d7da72caf4e31c5aa206322e00bc1f2ce8c")

	vc, err := New(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range []string{mnemonic, seed, "0x" + seed, xpriv} {
		t.Logf("using secret: %v", v)
		err = vc.Unlock(v)
		if err != nil {
			t.Fatalf("failed %v: %v", k, err)
		}

		ek, err := vc.DeriveHD(0, 0)
		if err != nil {
			t.Fatal(err)
		}
		addr, pub, err := AddressAndPublicFromExtended(&chaincfg.MainNetParams, ek)
		if err != nil {
			t.Fatal(err)
		}
		if addr.String() != expectedAddress {
			t.Fatal("invalid hardened address")
		}
		expub, err := Compressed(pub)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expub, expectedPub) {
			t.Fatal("invalid hardened compressed public key")
		}
		err = vc.Lock()
		if err != nil {
			t.Fatal(err)
		}
	}

	// use a pub key to test negative path
	failpub := "xpub68GbL9kRsJSW9YgqXTnAy1JsiCjZEwbecAx1dcNhxdypbFmsDP7NviUgvWmX7ighnsTe9eLJQHDcnoGQUtVKViSnAKzxQ2DHC6QeNbYiztE"
	err = vc.Unlock(failpub)
	if err == nil {
		t.Fatal("expected error")
	}
}
