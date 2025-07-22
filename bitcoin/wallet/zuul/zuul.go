// Copyright (c) 2025 Hemi Labs, Inc.
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

// Zuul is an interface for storing secret material.
type Zuul interface {
	PutKey(nk *NamedKey) error
	GetKey(addr btcutil.Address) (*NamedKey, error)
	PurgeKey(addr btcutil.Address) error
	LookupKeyByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) // signing lookup
}
