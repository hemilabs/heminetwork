// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package zuul provides an interface for handling the storage of secret
// material.
//
// Zuul, a minion of the god known as Gozer, was worshiped as a demigod by the
// Sumerians, Mesopotamians and Hittites in 6000 BC.
package zuul

import (
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	ErrKeyExists      = errors.New("key exists")
	ErrKeyDoesntExist = errors.New("key does not exist")
)

// NamedKeyHD contains a private key with metadata.
// Implement interface for various keytypes
// XXX we need an extended key in here somehow at some point
//type NamedKeyHD struct {
//	Name string // User defined name
//
//	DerivationPath string // Derivation path
//
//	PrivateKey *hdkeychain.ExtendedKey
//}

// NamedKey contains a private key with metadata.
type NamedKey struct {
	Name string // User defined name

	PrivateKey *dcrsecpk256k1.PrivateKey
}

// TSSNamedKey represents a key controlled by an external threshold
// signature scheme.  The private key material is sharded across a
// committee and never materialises on this host; this struct carries
// only the aggregated group public key and a keyID that external
// signers use to identify which distributed key to sign with.
//
// The keyID is opaque to the wallet.  Its format is determined by the
// TSS system that produced the key at keygen time and callers must
// not interpret its contents.  The wallet only stores and forwards
// it verbatim when asking the coordinator to sign.
//
// Signing a TSS input is a two-step dance: the wallet assembles the
// unsigned transaction, computes the sighash for the TSS input, and
// hands the sighash and keyID to the TSS coordinator.  The coordinator
// returns a signature which the wallet injects into the witness or
// signature script via TransactionApplyECDSA or TransactionApplySchnorr.
type TSSNamedKey struct {
	Name      string           // User defined name
	KeyID     []byte           // External TSS key identifier
	PublicKey *btcec.PublicKey // Aggregated group public key
}

// Zuul is an interface for storing secret material.
type Zuul interface {
	PutKey(nk *NamedKey) error
	GetKey(addr btcutil.Address) (*NamedKey, error)
	PurgeKey(addr btcutil.Address) error
	LookupKeyByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) // signing lookup

	// TSS key enrolment and lookup.  A TSSNamedKey carries no private
	// material; signing happens externally via the TSS committee and
	// the produced signature is applied to the transaction through
	// the wallet's external-signature entry points.
	PutTSSKey(tnk *TSSNamedKey) error
	GetTSSKey(addr btcutil.Address) (*TSSNamedKey, error)
	PurgeTSSKey(addr btcutil.Address) error
	LookupTSSKeyByAddr(addr btcutil.Address) (*TSSNamedKey, bool, error)
}
