// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package memory provides an in-memory implementation of [zuul.Zuul].
package memory

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
)

// memoryZuul is an in-memory implementation of [zuul.Zuul].
//
// Keys are indexed under every address type that derives from their
// public key, so LookupKeyByAddr succeeds regardless of which address
// form a caller presents.  Currently indexes P2PKH, P2WPKH, and
// BIP-86 P2TR addresses.
//
// TSS keys are tracked in a parallel map.  They share the same
// address-keyspace as local keys (an address is either controlled by
// a local private key or by a TSS committee, never both) but queries
// dispatch to the right side via the typed lookup methods.
type memoryZuul struct {
	mtx     sync.Mutex
	params  *chaincfg.Params
	keys    map[string]*zuul.NamedKey
	tssKeys map[string]*zuul.TSSNamedKey
}

var _ zuul.Zuul = (*memoryZuul)(nil)

// New returns a new [zuul.Zuul] implementation that stores data in-memory.
func New(params *chaincfg.Params) (zuul.Zuul, error) {
	m := &memoryZuul{
		params:  params,
		keys:    make(map[string]*zuul.NamedKey, 10),
		tssKeys: make(map[string]*zuul.TSSNamedKey, 10),
	}
	return m, nil
}

// addressesForPubKey returns the set of addresses that derive from the
// given compressed public key: P2PKH, P2WPKH, and BIP-86 P2TR.  The
// zuul stores the same NamedKey under each of these so callers may
// look up keys by whichever address form they encounter.
func addressesForPubKey(params *chaincfg.Params, pubCompressed []byte) ([]string, error) {
	addrs := make([]string, 0, 3)

	// P2PKH (legacy).
	pkHash := btcutil.Hash160(pubCompressed)
	p2pkh, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		return nil, fmt.Errorf("p2pkh address: %w", err)
	}
	addrs = append(addrs, p2pkh.EncodeAddress())

	// P2WPKH (native segwit v0).
	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		return nil, fmt.Errorf("p2wpkh address: %w", err)
	}
	addrs = append(addrs, p2wpkh.EncodeAddress())

	// BIP-86 P2TR (key-path only, no script commitment).
	pub, err := btcec.ParsePubKey(pubCompressed)
	if err != nil {
		return nil, fmt.Errorf("parse pubkey: %w", err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(pub)
	p2tr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params,
	)
	if err != nil {
		return nil, fmt.Errorf("p2tr address: %w", err)
	}
	addrs = append(addrs, p2tr.EncodeAddress())

	return addrs, nil
}

// PutKey enrols a local private key.  The key is indexed under every
// address form that derives from its public key — currently P2PKH,
// P2WPKH, and BIP-86 P2TR — so callers can later look it up by any
// of those addresses.
//
// All-or-nothing: if any of the derived addresses already maps to
// a stored local key the call returns ErrKeyExists; if mapped to a
// TSS key it returns ErrTSSKeyOccupied.  Both wrap ErrKeyExists.
// This prevents a single PutKey from partially populating the index
// when a collision exists on one address form but not others.
func (m *memoryZuul) PutKey(nk *zuul.NamedKey) error {
	pubBytes := nk.PrivateKey.PubKey().SerializeCompressed()
	addrs, err := addressesForPubKey(m.params, pubBytes)
	if err != nil {
		return err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// All-or-nothing: if any address already points at a stored key,
	// refuse the put without mutating.  Collisions are detected
	// against both the local and TSS key indexes so the two cannot
	// claim overlapping address space.
	for _, a := range addrs {
		if _, ok := m.keys[a]; ok {
			return zuul.ErrKeyExists
		}
		if _, ok := m.tssKeys[a]; ok {
			return zuul.ErrTSSKeyOccupied
		}
	}
	for _, a := range addrs {
		m.keys[a] = nk
	}
	return nil
}

// GetKey returns the local NamedKey indexed under addr.  Addr may be
// any of the address forms under which the key was enrolled (P2PKH,
// P2WPKH, P2TR-BIP86); the same key is returned for all of them.
// Returns ErrKeyDoesntExist if addr is unknown or is TSS-controlled.
func (m *memoryZuul) GetKey(addr btcutil.Address) (*zuul.NamedKey, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return nil, zuul.ErrKeyDoesntExist
	}
	return nk, nil
}

// PurgeKey removes the key indexed under addr from every address
// form it was stored under and zeroes the underlying scalar.
//
// SECURITY CONTRACT: PurgeKey zeroes the private key scalar in
// place.  Any goroutine still holding a pointer to this key from a
// prior GetKey/LookupKeyByAddr call will observe the zeroed scalar
// and produce invalid signatures.  Callers must guarantee no
// outstanding signing operation is in flight before invoking
// PurgeKey — the zuul mutex only serialises concurrent zuul calls,
// not the signing operations that run outside it.  The zeroing is
// deliberate: a caller invoking PurgeKey wants the secret gone,
// and leaving it in memory for late signers to use would defeat
// that intent.
func (m *memoryZuul) PurgeKey(addr btcutil.Address) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return zuul.ErrKeyDoesntExist
	}

	// Remove every address form this key was indexed under.
	pubBytes := nk.PrivateKey.PubKey().SerializeCompressed()
	addrs, err := addressesForPubKey(m.params, pubBytes)
	if err != nil {
		return fmt.Errorf("derive addresses: %w", err)
	}
	for _, a := range addrs {
		delete(m.keys, a)
	}

	nk.PrivateKey.Zero()
	nk.PrivateKey = nil
	return nil
}

// LookupKeyByAddr returns the private key for a local-key address.
// Designed for signing: returns (priv, true, nil) when the address is
// a locally-enrolled key, and (nil, false, ErrKeyDoesntExist) when
// the address is unknown or TSS-controlled.  Addr may be any of the
// indexed address forms (P2PKH, P2WPKH, P2TR-BIP86).
func (m *memoryZuul) LookupKeyByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return nil, false, zuul.ErrKeyDoesntExist
	}
	return nk.PrivateKey, true, nil
}

// ecdsaAddressesForPubKey returns the set of addresses an ECDSA key
// can sign for: P2PKH and P2WPKH.  Taproot (P2TR) key-path spends
// require schnorr signatures, so ECDSA TSS keys cannot be used to
// spend a P2TR output regardless of the aggregated pubkey.  This
// helper is used for TSS key enrolment to restrict the address
// surface accordingly.
func ecdsaAddressesForPubKey(params *chaincfg.Params, pubCompressed []byte) ([]string, error) {
	addrs := make([]string, 0, 2)

	pkHash := btcutil.Hash160(pubCompressed)
	p2pkh, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		return nil, fmt.Errorf("p2pkh address: %w", err)
	}
	addrs = append(addrs, p2pkh.EncodeAddress())

	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		return nil, fmt.Errorf("p2wpkh address: %w", err)
	}
	addrs = append(addrs, p2wpkh.EncodeAddress())

	return addrs, nil
}

// PutTSSKey enrols a TSS-controlled public key.  The key is indexed
// under the addresses an ECDSA signer can spend: P2PKH and P2WPKH.
// Taproot is not supported because ECDSA signatures cannot satisfy
// a BIP-341 key-path spend.
//
// Collisions are detected against both the local-key index and the
// TSS-key index: an address pointing to a local key refuses the
// insert with ErrLocalKeyOccupied; a duplicate TSS key refuses with
// ErrKeyExists.
func (m *memoryZuul) PutTSSKey(tnk *zuul.TSSNamedKey) error {
	if tnk == nil || tnk.PublicKey == nil {
		return fmt.Errorf("tss key: public key required")
	}
	if len(tnk.KeyID) == 0 {
		return fmt.Errorf("tss key: key id required")
	}

	pubBytes := tnk.PublicKey.SerializeCompressed()
	addrs, err := ecdsaAddressesForPubKey(m.params, pubBytes)
	if err != nil {
		return err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	for _, a := range addrs {
		if _, ok := m.keys[a]; ok {
			return zuul.ErrLocalKeyOccupied
		}
		if _, ok := m.tssKeys[a]; ok {
			return zuul.ErrKeyExists
		}
	}
	for _, a := range addrs {
		m.tssKeys[a] = tnk
	}
	return nil
}

// GetTSSKey returns the TSS key indexed under addr.  If addr maps to
// a local private key (or nothing), ErrKeyDoesntExist is returned.
func (m *memoryZuul) GetTSSKey(addr btcutil.Address) (*zuul.TSSNamedKey, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	tnk, ok := m.tssKeys[addr.String()]
	if !ok {
		return nil, zuul.ErrKeyDoesntExist
	}
	return tnk, nil
}

// PurgeTSSKey removes a TSS key.  Because PutTSSKey indexes under
// multiple address forms, PurgeTSSKey recomputes all of them from
// the stored public key and removes every entry.
func (m *memoryZuul) PurgeTSSKey(addr btcutil.Address) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	tnk, ok := m.tssKeys[addr.String()]
	if !ok {
		return zuul.ErrKeyDoesntExist
	}

	pubBytes := tnk.PublicKey.SerializeCompressed()
	addrs, err := ecdsaAddressesForPubKey(m.params, pubBytes)
	if err != nil {
		return fmt.Errorf("derive addresses: %w", err)
	}
	for _, a := range addrs {
		delete(m.tssKeys, a)
	}
	return nil
}

// LookupTSSKeyByAddr is the TSS counterpart to LookupKeyByAddr.  It
// returns the TSS key and true when addr is TSS-controlled, or false
// with ErrKeyDoesntExist when addr is unknown or controlled by a
// local private key.
func (m *memoryZuul) LookupTSSKeyByAddr(addr btcutil.Address) (*zuul.TSSNamedKey, bool, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	tnk, ok := m.tssKeys[addr.String()]
	if !ok {
		return nil, false, zuul.ErrKeyDoesntExist
	}
	return tnk, true, nil
}
