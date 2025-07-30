// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package memory provides an in-memory implementation of [zuul.Zuul].
package memory

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
)

// memoryZuul is an in-memory implementation of [zuul.Zuul].
type memoryZuul struct {
	mtx    sync.Mutex
	params *chaincfg.Params
	keys   map[string]*zuul.NamedKey
}

var _ zuul.Zuul = (*memoryZuul)(nil)

// New returns a new [zuul.Zuul] implementation that stores data in-memory.
func New(params *chaincfg.Params) (zuul.Zuul, error) {
	m := &memoryZuul{
		params: params,
		keys:   make(map[string]*zuul.NamedKey, 10),
	}
	return m, nil
}

func (m *memoryZuul) PutKey(nk *zuul.NamedKey) error {
	// Generate address for lookup
	pubBytes := nk.PrivateKey.PubKey().SerializeCompressed()
	btcAddress, err := btcutil.NewAddressPubKey(pubBytes, m.params)
	if err != nil {
		return fmt.Errorf("new address: %w", err)
	}
	addr := btcAddress.AddressPubKeyHash().String()

	m.mtx.Lock()
	defer m.mtx.Unlock()
	if _, ok := m.keys[addr]; ok {
		return zuul.ErrKeyExists
	}
	m.keys[addr] = nk
	return nil
}

func (m *memoryZuul) GetKey(addr btcutil.Address) (*zuul.NamedKey, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return nil, zuul.ErrKeyDoesntExist
	}
	return nk, nil
}

func (m *memoryZuul) PurgeKey(addr btcutil.Address) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return zuul.ErrKeyDoesntExist
	}
	delete(m.keys, addr.String())
	nk.PrivateKey.Zero()
	nk.PrivateKey = nil
	return nil
}

func (m *memoryZuul) LookupKeyByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return nil, false, zuul.ErrKeyDoesntExist
	}
	return nk.PrivateKey, true, nil
}
