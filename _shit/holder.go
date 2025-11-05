package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
)

type outpointStore [common.AddressLength + 32]byte

func newOutpointStore(addr common.Address, out []byte) outpointStore {
	if len(out) != 32 {
		panic("invalid outpoint size")
	}
	var os outpointStore
	copy(os[:common.AddressLength], addr[:])
	copy(os[common.AddressLength:], out)
	return os
}

func (os outpointStore) getAddress() common.Address {
	var a common.Address
	a.SetBytes(os[:common.AddressLength])
	return a
}

func (os outpointStore) getOutpoint() []byte {
	return os[common.AddressLength:]
}

// TestHolder simulates ZK Indexing and storing in a Trie
type TestHolder struct {
	stateRoots       []common.Hash                             // [genesis, V1, V2...]
	pendingOutpoints []outpointStore                           // uncommited outpoints
	outpoints        []outpointStore                           // created outpoints for easy lookup
	accountOrigin    map[common.Address][]byte                 // to store current account values
	storageOrigin    map[common.Address]map[common.Hash][]byte // to store current storage values
	newAccounts      map[common.Hash][]byte                    // to store uncommited account values
	newStorage       map[common.Hash]map[common.Hash][]byte    // to store uncommited storage values
	mergeSet         *trienode.MergedNodeSet                   // nodes to merge and commit
	tdb              *triedb.Database                          // underlying database
}

func NewTestHolder(tdb *triedb.Database) *TestHolder {
	return &TestHolder{
		stateRoots:       make([]common.Hash, 0),
		pendingOutpoints: make([]outpointStore, 0),
		outpoints:        make([]outpointStore, 0),
		accountOrigin:    make(map[common.Address][]byte),
		storageOrigin:    make(map[common.Address]map[common.Hash][]byte),
		newStorage:       make(map[common.Hash]map[common.Hash][]byte),
		newAccounts:      make(map[common.Hash][]byte),
		mergeSet:         trienode.NewMergedNodeSet(),
		tdb:              tdb,
	}
}

var (
	ErrAccountNotFound  error = errors.New("account state not found")
	ErrOutpointNotFound error = errors.New("outpoint not found")
)

// Gets the most recent State Root
func (t *TestHolder) getCurrentState() common.Hash {
	if len(t.stateRoots) == 0 {
		return types.EmptyRootHash
	}
	return t.stateRoots[len(t.stateRoots)-1]
}

// Gets the account state associated with a PKScript
func (t *TestHolder) getAccountState(pkScript common.Address) (*types.StateAccount, error) {
	sr := t.getCurrentState()

	if sr.Cmp(types.EmptyRootHash) == 0 {
		return types.NewEmptyStateAccount(), ErrAccountNotFound
	}

	pkHash := crypto.Keccak256Hash(pkScript.Bytes())

	// New state trie ID
	id := trie.StateTrieID(sr)

	tr, err := trie.New(id, t.tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load state trie, err: %w", err))
	}

	val, err := tr.Get(pkHash[:])
	if err != nil || val == nil {
		return types.NewEmptyStateAccount(), ErrAccountNotFound
	}

	acc, err := types.FullAccount(val)
	if err != nil {
		panic("stored account value is not state account")
	}

	return acc, nil
}

func (t *TestHolder) getBalance(pkScript common.Address) (*uint256.Int, error) {
	acc, err := t.getAccountState(pkScript)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return uint256.NewInt(0), nil
		}
		return nil, err
	}
	return acc.Balance, nil
}

// Gets the value of an outpoint associated with a pkScript
func (t *TestHolder) getOutpointValue(os outpointStore) ([]byte, error) {
	pkScript := os.getAddress()
	outpoint := os.getOutpoint()

	acc, err := t.getAccountState(pkScript)
	if err != nil {
		return nil, err
	}

	pkHash := crypto.Keccak256Hash(pkScript.Bytes())
	sr := t.getCurrentState()

	// New storage trie ID
	id := trie.StorageTrieID(sr, pkHash, acc.Root)

	tr, err := trie.New(id, t.tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load storage trie, err: %w", err))
	}

	hash := common.BytesToHash(outpoint)
	val, err := tr.Get(hash[:])
	if err != nil {
		return nil, ErrOutpointNotFound
	}
	return val, nil
}

func (t *TestHolder) simulateOut(pkScript common.Address, value uint64) error {
	stateRoot := t.getCurrentState()
	pkHash := crypto.Keccak256Hash(pkScript.Bytes())

	// Get previous StateAccount of pkScript
	var accOrigin []byte
	ao, err := t.getAccountState(pkScript)
	if err != nil {
		if !errors.Is(err, ErrAccountNotFound) {
			return fmt.Errorf("get current account state: %w", err)
		}
	} else {
		accOrigin = types.SlimAccountRLP(*ao)
	}

	// make random outpoint and add to storage
	op := random(32)              // outpoint
	out := common.BytesToHash(op) // sha256(outpoint)

	var v [8]byte
	binary.BigEndian.PutUint64(v[:], value)

	// create new storage ID for trie
	storeID := trie.StorageTrieID(stateRoot, pkHash, ao.Root)

	// new storage trie
	storeTrie, err := trie.New(storeID, t.tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load trie, err: %w", err))
	}

	// add the created data to the trie
	if err := storeTrie.Update(out.Bytes(), v[:]); err != nil {
		return fmt.Errorf("update storage trie: %w", err)
	}

	// commit the trie, get storage trie root and node set
	newStorageRoot, set := storeTrie.Commit(false)
	if err := t.mergeSet.Merge(set); err != nil {
		return fmt.Errorf("merge storage nodes: %w", err)
	}

	// StateAccount is the Ethereum consensus representation of accounts
	acc := types.StateAccount{
		Balance: uint256.NewInt(0).Add(ao.Balance, uint256.NewInt(binary.BigEndian.Uint64(v[:]))),
		Root:    newStorageRoot,
	}

	t.newAccounts[pkHash] = types.SlimAccountRLP(acc)
	t.accountOrigin[pkScript] = accOrigin
	if _, ok := t.newStorage[pkHash]; !ok {
		t.newStorage[pkHash] = make(map[common.Hash][]byte)
	}
	t.newStorage[pkHash][out] = v[:]
	if _, ok := t.storageOrigin[pkScript]; !ok {
		t.storageOrigin[pkScript] = make(map[common.Hash][]byte)
	}
	t.storageOrigin[pkScript][out] = nil

	t.pendingOutpoints = append(t.pendingOutpoints, newOutpointStore(pkScript, op))

	return nil
}

func (t *TestHolder) simulateIn(os outpointStore) error {
	stateRoot := t.getCurrentState()
	pkScript := os.getAddress()
	outpoint := os.getOutpoint()
	pkHash := crypto.Keccak256Hash(pkScript.Bytes())
	var outHash common.Hash
	outHash.SetBytes(outpoint)

	var accOrigin []byte
	ao, err := t.getAccountState(pkScript)
	if err != nil {
		return fmt.Errorf("ins: get current account state: %w", err)
	}
	accOrigin = types.SlimAccountRLP(*ao)

	// get outpoint value
	val, err := t.getOutpointValue(os)
	if err != nil {
		return fmt.Errorf("ins: get current storage: %w", err)
	}

	// if val == nil {
	// 	spew.Dump(os)
	// 	panic("xxx")
	// }

	// set outpoint value to 0
	storage := make(map[common.Hash][]byte) // new storage
	oldVal := uint256.NewInt(binary.BigEndian.Uint64(val[:]))

	var zero [8]byte
	storage[outHash] = zero[:]

	// Associate this outpoint to the address hash
	t.newStorage[pkHash] = storage

	// create new storage ID for trie
	id := trie.StorageTrieID(stateRoot, pkHash, ao.Root)

	// new trie
	tr, err := trie.New(id, t.tdb)
	if err != nil {
		panic(fmt.Errorf("ins: failed to load trie, err: %w", err))
	}

	// add the created data to the trie
	for key, val := range storage {
		if err := tr.Update(key.Bytes(), val); err != nil {
			return fmt.Errorf("ins: update storage trie: %w", err)
		}
	}

	// commit the trie, get storage trie root and node set
	newStorageRoot, set := tr.Commit(false)
	if err := t.mergeSet.Merge(set); err != nil {
		return fmt.Errorf("ins: merge storage nodes: %w", err)
	}

	// StateAccount is the Ethereum consensus representation of accounts
	acc := types.StateAccount{
		Balance: uint256.NewInt(0).Sub(ao.Balance, oldVal),
		Root:    newStorageRoot,
	}

	t.newAccounts[pkHash] = types.SlimAccountRLP(acc)
	t.accountOrigin[pkScript] = accOrigin
	if _, ok := t.newStorage[pkHash]; !ok {
		t.newStorage[pkHash] = make(map[common.Hash][]byte)
	}
	t.newStorage[pkHash][outHash] = zero[:]

	if _, ok := t.storageOrigin[pkScript]; !ok {
		t.storageOrigin[pkScript] = make(map[common.Hash][]byte)
	}
	t.storageOrigin[pkScript][outHash] = val

	return nil
}

// Simulates the indexing of a new block
func (t *TestHolder) commitBlock(block uint64) error {
	var (
		stateRoot = t.getCurrentState()
		stateID   = trie.StateTrieID(stateRoot)
	)

	stateTrie, err := trie.New(stateID, t.tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load trie, err: %w", err))
	}

	// add the new account to the trie
	for key, val := range t.newAccounts {
		if err := stateTrie.Update(key.Bytes(), val); err != nil {
			return fmt.Errorf("update accounts trie: %w", err)
		}
	}

	// commit the trie, get state trie root and node set
	newStateRoot, set := stateTrie.Commit(false)
	if err := t.mergeSet.Merge(set); err != nil {
		return fmt.Errorf("merge account nodes: %w", err)
	}

	// StateSet represents a collection of mutated states during a state transition.
	s := triedb.StateSet{
		Accounts:       t.newAccounts,
		AccountsOrigin: t.accountOrigin,
		Storages:       t.newStorage,
		StoragesOrigin: t.storageOrigin,
		RawStorageKey:  false,
	}

	// performs a state transition
	if err := t.tdb.Update(newStateRoot, stateRoot, block, t.mergeSet, &s); err != nil {
		return fmt.Errorf("update db: %w", err)
	}

	if err := t.tdb.Commit(newStateRoot, true); err != nil {
		return fmt.Errorf("commit db: %w", err)
	}

	t.stateRoots = append(t.stateRoots, newStateRoot)
	t.outpoints = append(t.outpoints, t.pendingOutpoints...)

	t.pendingOutpoints = make([]outpointStore, 0)
	t.accountOrigin = make(map[common.Address][]byte)
	t.storageOrigin = make(map[common.Address]map[common.Hash][]byte)
	t.newStorage = make(map[common.Hash]map[common.Hash][]byte)
	t.newAccounts = make(map[common.Hash][]byte)
	t.mergeSet = trienode.NewMergedNodeSet()

	return nil
}

// random returns a variable number of random bytes.
func random(n int) []byte {
	buffer := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, buffer)
	if err != nil {
		panic(err)
	}
	return buffer
}
