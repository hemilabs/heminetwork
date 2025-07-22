// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package vinzclortho handles creation and deriviation of Bitcoin addresses.
//
// Vinz Clortho, a minion of the god known as Gozer, was worshiped as a demigod
// by the Sumerians, Mesopotamians and Hittites in 6000 BC.
package vinzclortho

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/tyler-smith/go-bip39"
)

// VinzClortho is a wallet implementation that handles the creation and
// derivation of Bitcoin addresses.
type VinzClortho struct {
	mtx sync.Mutex

	params *chaincfg.Params

	// secret information
	master *hdkeychain.ExtendedKey
}

// New returns a new VinzClortho with the given chain params.
func New(params *chaincfg.Params) (*VinzClortho, error) {
	vc := &VinzClortho{
		params: params,
	}
	return vc, nil
}

func (vc *VinzClortho) rootKey() *hdkeychain.ExtendedKey {
	vc.mtx.Lock()
	defer vc.mtx.Unlock()
	return vc.master
}

func (vc *VinzClortho) RootKey() string {
	rk := vc.rootKey()
	if rk == nil {
		return ""
	}
	return rk.String()
}

// Lock locks the wallet.
func (vc *VinzClortho) Lock() error {
	if vc.master == nil {
		return errors.New("wallet already locked")
	}

	vc.mtx.Lock()
	vc.master.Zero()
	vc.master = nil
	vc.mtx.Unlock()

	return nil
}

// Unlock unlocks the wallet by deriving a seed from the provided secret.
// Supports xprv, hex encoded seed and mnemonic.
func (vc *VinzClortho) Unlock(secret string) error {
	vc.mtx.Lock()
	defer vc.mtx.Unlock()
	if vc.master != nil {
		return fmt.Errorf("wallet already unlocked")
	}

	switch {
	case strings.HasPrefix(secret, "0x"):
		secret = secret[2:]
	case strings.HasPrefix(secret, "xpub"):
		return fmt.Errorf("not an extended private key")
	case strings.HasPrefix(secret, "xprv"):
		var err error
		vc.master, err = hdkeychain.NewKeyFromString(secret)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	// try hex first, if this works it's a seed
	seed, err := hex.DecodeString(secret)
	if err == nil {
		// we got a seed
		vc.master, err = hdkeychain.NewMaster(seed, vc.params)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	// try mnemonic
	seed, err = bip39.NewSeedWithErrorChecking(secret, "")
	if err == nil {
		// we got a seed
		vc.master, err = hdkeychain.NewMaster(seed, vc.params)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	return err
}

// derive derives the public extended key and address from the account and
// child using BIP32 derivation. When offset is greater or equal to
// hdkeychain.HardenedKeyStart it returns a hardened address.
//
// Hardened addresses require the private key to derive public keys whereas a
// regular address can derive public keys without.
//
// This function uses the same paths as used in Bitcoin core and Electrum.
func (vc *VinzClortho) derive(account, offset uint32, children ...uint32) (*hdkeychain.ExtendedKey, error) {
	if vc.master == nil {
		return nil, errors.New("wallet locked")
	}

	// Derive child key for (hardened) account.
	// E.g. hardened account 0: m/0'
	ek, err := vc.master.Derive(account + offset)
	if err != nil {
		return nil, err
	}

	// Derive child keys
	for _, child := range children {
		ek, err = ek.Derive(child + offset) // Yes, overwrite ek!
		if err != nil {
			return nil, err
		}
	}

	return ek, nil
}

// DeriveHD derives a hardened extended public key and address.
// E.g. account 1 child 4 m/1'/4'
func (vc *VinzClortho) DeriveHD(account uint32, children ...uint32) (*hdkeychain.ExtendedKey, error) {
	return vc.derive(account, hdkeychain.HardenedKeyStart, children...)
}

// Derive derives an extended public key and address.
// E.g. account 0 child 1 m/0/1
func (vc *VinzClortho) Derive(account uint32, children ...uint32) (*hdkeychain.ExtendedKey, error) {
	return vc.derive(account, 0, children...)
}

// pathElement decodes a path element into a child index. A ' suffix means
// it's a hardened address.
func pathElement(p string) (uint32, error) {
	var offset uint32
	e, isHD := strings.CutSuffix(p, "'")
	if isHD {
		offset = hdkeychain.HardenedKeyStart
	}
	x, err := strconv.ParseUint(e, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(x) + offset, nil
}

// DerivePath returns an extended key from the provided path. E.g.
// "m/1337'/0'/1", this will return a non-hardned extended key from the hardned
// 1337/0 path.
func (vc *VinzClortho) DerivePath(path string) (*hdkeychain.ExtendedKey, error) {
	if vc.master == nil {
		return nil, errors.New("wallet locked")
	}

	p := strings.Split(path, "/")
	if len(p) < 2 {
		return nil, fmt.Errorf("invalid path")
	}

	// p[0] must be m
	if p[0] != "m" {
		return nil, fmt.Errorf("invalid path prefix")
	}

	// p[1] is the account key and subsequent p elements are children.
	account, err := pathElement(p[1])
	if err != nil {
		return nil, err
	}
	// Use Derive since HD is already included in account
	ek, err := vc.master.Derive(account)
	if err != nil {
		return nil, err
	}

	// Now derive all children
	for _, v := range p[2:] {
		child, err := pathElement(v)
		if err != nil {
			return nil, err
		}

		// Overwrite ek
		ek, err = ek.Derive(child)
		if err != nil {
			return nil, err
		}
	}
	return ek, nil
}

// AddressAndPublicFromExtended returns the public bits from a private extended
// key.
func AddressAndPublicFromExtended(params *chaincfg.Params, ek *hdkeychain.ExtendedKey) (btcutil.Address, *hdkeychain.ExtendedKey, error) {
	// Generate address
	addr, err := ek.Address(params)
	if err != nil {
		return nil, nil, err
	}

	// Generate pubkey
	pub, err := ek.Neuter()
	if err != nil {
		return nil, nil, err
	}

	return addr, pub, nil
}

// Compressed converts an extended key to the compressed public key representation.
func Compressed(pub *hdkeychain.ExtendedKey) ([]byte, error) {
	ecpub, err := pub.ECPubKey()
	if err != nil {
		return nil, err
	}
	return ecpub.SerializeCompressed(), nil
}

// ScriptFromPubKeyHash creates a spend script for the specified address.
func ScriptFromPubKeyHash(pkh btcutil.Address) ([]byte, error) {
	payToScript, err := txscript.PayToAddrScript(pkh)
	if err != nil {
		return nil, err
	}
	return payToScript, nil
}

// ScriptHashFromScript returns the script hash of the provided script. Note
// that this is a simple sha256 wrapped in a chainhash.Hash.
func ScriptHashFromScript(pkscript []byte) chainhash.Hash {
	return chainhash.Hash(sha256.Sum256(pkscript))
}
