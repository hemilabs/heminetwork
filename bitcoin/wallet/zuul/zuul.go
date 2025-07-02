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
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

var (
	ErrKeyExists      = errors.New("key exists")
	ErrKeyDoesntExist = errors.New("key does not exist")
)

// NamedKey contains a private key with metadata.
type NamedKey struct {
	Name string // User defined name

	// Derivation path
	Account uint
	Child   uint
	HD      bool

	PrivateKey *hdkeychain.ExtendedKey
}

// Zuul is an interface for storing secret material.
type Zuul interface {
	Put(nk *NamedKey) error
	Get(addr btcutil.Address) (*NamedKey, error)
	Purge(addr btcutil.Address) error
	LookupByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) // signing lookup
}
