package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/triedb"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/holiman/uint256"
)

// TestHolder simulates ZK Indexing and storing in a Trie
type TestHolder struct {
	stateRoots []common.Hash               // [genesis, V1, V2...]
	outpoints  map[common.Address][][]byte // outpoints per pkScript
	tdb        *triedb.Database
}

func NewTestHolder(tdb *triedb.Database) *TestHolder {
	return &TestHolder{
		stateRoots: make([]common.Hash, 0),
		outpoints:  make(map[common.Address][][]byte),
		tdb:        tdb,
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
	if err != nil {
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

// Gets an outpoint associated with a PKScript.
// If outpoint is nil, every outpoint is returned.
func (t *TestHolder) getStorage(pkScript common.Address, outpoint []byte) (map[common.Hash][]byte, error) {
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

	outs, ok := t.outpoints[pkScript]
	if !ok {
		return nil, nil
	}

	outMap := make(map[common.Hash][]byte, len(outs))
	if outpoint != nil {
		hash := common.BytesToHash(outpoint)
		val, err := tr.Get(hash[:])
		if err != nil {
			return nil, ErrOutpointNotFound
		}
		outMap[hash] = val
	} else {
		for _, o := range outs {
			hash := common.BytesToHash(o)
			val, err := tr.Get(hash[:])
			if err != nil {
				return nil, ErrOutpointNotFound
			}
			outMap[hash] = val
		}
	}

	return outMap, nil
}

// Simulates the indexing of a new UTXO
func (t *TestHolder) createOut(block uint64, pkScript common.Address, amount uint64) (common.Hash, error) {
	var (
		pkHash      = crypto.Keccak256Hash(pkScript.Bytes())
		newStorage  = make(map[common.Hash]map[common.Hash][]byte)
		newAccounts = make(map[common.Hash][]byte)
		mergeSet    = trienode.NewMergedNodeSet()
	)

	stateRoot := t.getCurrentState()

	var accOrigin []byte
	ao, err := t.getAccountState(pkScript)
	if err != nil {
		if !errors.Is(err, ErrAccountNotFound) {
			return common.Hash{}, fmt.Errorf("get current account state: %w", err)
		}
	} else {
		accOrigin = types.SlimAccountRLP(*ao)
	}

	// make random outpoint and add to storage

	var value [8]byte
	binary.BigEndian.PutUint64(value[:], amount)

	op := random(32)              // outpoint
	out := common.BytesToHash(op) // sha256(outpoint)

	// new storage
	storage := make(map[common.Hash][]byte)
	storage[out] = value[:]

	// since outpoint is new, storage origin is nil
	stOrigin := make(map[common.Hash][]byte)
	stOrigin[out] = nil

	// Associate this outpoint to the address hash
	newStorage[pkHash] = storage

	// create new storage ID for trie
	id := trie.StorageTrieID(stateRoot, pkHash, ao.Root)

	// new trie
	tr, err := trie.New(id, t.tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load trie, err: %w", err))
	}

	// add the created data to the trie
	for key, val := range storage {
		if err := tr.Update(key.Bytes(), val); err != nil {
			return common.Hash{}, fmt.Errorf("update storage trie: %w", err)
		}
	}

	// commit the trie, get storage trie root and node set
	newStorageRoot, set := tr.Commit(false)
	if err := mergeSet.Merge(set); err != nil {
		return common.Hash{}, fmt.Errorf("merge storage nodes: %w", err)
	}

	// StateAccount is the Ethereum consensus representation of accounts
	acc := types.StateAccount{
		Nonce:    uint64(mathrand.Intn(100)),
		Balance:  uint256.NewInt(0).Add(ao.Balance, uint256.NewInt(binary.BigEndian.Uint64(value[:]))),
		CodeHash: random(32),
		Root:     newStorageRoot,
	}

	newAccounts[pkHash] = types.SlimAccountRLP(acc)

	// New state trie ID
	id = trie.StateTrieID(stateRoot)

	tr, err = trie.New(id, t.tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load trie, err: %w", err))
	}

	// add the new account to the trie
	for key, val := range newAccounts {
		if err := tr.Update(key.Bytes(), val); err != nil {
			return common.Hash{}, fmt.Errorf("update accounts trie: %w", err)
		}
	}

	// commit the trie, get state trie root and node set
	newStateRoot, set := tr.Commit(false)
	if err := mergeSet.Merge(set); err != nil {
		return common.Hash{}, fmt.Errorf("merge account nodes: %w", err)
	}

	accountOrigin := make(map[common.Address][]byte)
	accountOrigin[pkScript] = accOrigin
	storageOrigin := make(map[common.Address]map[common.Hash][]byte)
	storageOrigin[pkScript] = stOrigin

	// StateSet represents a collection of mutated states during a state transition.
	s := triedb.StateSet{
		Accounts:       newAccounts,
		AccountsOrigin: accountOrigin,
		Storages:       newStorage,
		StoragesOrigin: storageOrigin,
		RawStorageKey:  false,
	}

	// performs a state transition
	if err := t.tdb.Update(newStateRoot, stateRoot, block, mergeSet, &s); err != nil {
		return common.Hash{}, fmt.Errorf("update db: %w", err)
	}

	if err := t.tdb.Commit(newStateRoot, true); err != nil {
		return common.Hash{}, fmt.Errorf("commit db: %w", err)
	}

	_, ok := t.outpoints[pkScript]
	if !ok {
		t.outpoints[pkScript] = make([][]byte, 0)
	}

	t.outpoints[pkScript] = append(t.outpoints[pkScript], op)

	t.stateRoots = append(t.stateRoots, newStateRoot)

	return out, nil
}

// Simulates the indexing of a new in
func (t *TestHolder) createIn(block uint64, pkScript common.Address, outpoint []byte) error {
	var (
		pkHash      = crypto.Keccak256Hash(pkScript.Bytes())
		newStorage  = make(map[common.Hash]map[common.Hash][]byte)
		newAccounts = make(map[common.Hash][]byte)
		mergeSet    = trienode.NewMergedNodeSet()
	)

	stateRoot := t.getCurrentState()

	var accOrigin []byte
	ao, err := t.getAccountState(pkScript)
	if err != nil {
		if !errors.Is(err, ErrAccountNotFound) {
			return fmt.Errorf("get current account state: %w", err)
		}
	} else {
		accOrigin = types.SlimAccountRLP(*ao)
	}

	// get outpoint
	stOrigin, err := t.getStorage(pkScript, outpoint)
	if err != nil {
		if !errors.Is(err, ErrAccountNotFound) && !errors.Is(err, ErrOutpointNotFound) {
			return fmt.Errorf("get current storage: %w", err)
		}
		stOrigin = make(map[common.Hash][]byte)
	}

	// set outpoint value to 0

	storage := make(map[common.Hash][]byte) // new storage
	var oldVal *uint256.Int
	for out, val := range stOrigin {
		// only has one outpoint
		storage[out] = nil
		oldVal = uint256.NewInt(binary.BigEndian.Uint64(val[:]))
	}

	// Associate this outpoint to the address hash
	newStorage[pkHash] = storage

	// create new storage ID for trie
	id := trie.StorageTrieID(stateRoot, pkHash, ao.Root)

	// new trie
	tr, err := trie.New(id, t.tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load trie, err: %w", err))
	}

	// add the created data to the trie
	for key, val := range storage {
		if err := tr.Update(key.Bytes(), val); err != nil {
			return fmt.Errorf("update storage trie: %w", err)
		}
	}

	// commit the trie, get storage trie root and node set
	newStorageRoot, set := tr.Commit(false)
	if err := mergeSet.Merge(set); err != nil {
		return fmt.Errorf("merge storage nodes: %w", err)
	}

	// StateAccount is the Ethereum consensus representation of accounts
	acc := types.StateAccount{
		Nonce:    uint64(mathrand.Intn(100)),
		Balance:  uint256.NewInt(0).Sub(ao.Balance, oldVal),
		CodeHash: random(32),
		Root:     newStorageRoot,
	}

	newAccounts[pkHash] = types.SlimAccountRLP(acc)

	// New state trie ID
	id = trie.StateTrieID(stateRoot)

	tr, err = trie.New(id, t.tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load trie, err: %w", err))
	}

	// add the new account to the trie
	for key, val := range newAccounts {
		if err := tr.Update(key.Bytes(), val); err != nil {
			return fmt.Errorf("update accounts trie: %w", err)
		}
	}

	// commit the trie, get state trie root and node set
	newStateRoot, set := tr.Commit(false)
	if err := mergeSet.Merge(set); err != nil {
		return fmt.Errorf("merge account nodes: %w", err)
	}

	accountOrigin := make(map[common.Address][]byte)
	accountOrigin[pkScript] = accOrigin
	storageOrigin := make(map[common.Address]map[common.Hash][]byte)
	storageOrigin[pkScript] = stOrigin

	// StateSet represents a collection of mutated states during a state transition.
	s := triedb.StateSet{
		Accounts:       newAccounts,
		AccountsOrigin: accountOrigin,
		Storages:       newStorage,
		StoragesOrigin: storageOrigin,
		RawStorageKey:  false,
	}

	// performs a state transition
	if err := t.tdb.Update(newStateRoot, stateRoot, block, mergeSet, &s); err != nil {
		return fmt.Errorf("update db: %w", err)
	}

	if err := t.tdb.Commit(newStateRoot, true); err != nil {
		return fmt.Errorf("commit db: %w", err)
	}

	t.stateRoots = append(t.stateRoots, newStateRoot)

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
