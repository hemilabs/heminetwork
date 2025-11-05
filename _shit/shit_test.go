package main

import (
	"fmt"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/leveldb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/holiman/uint256"

	"github.com/hemilabs/heminetwork/v2/testutil"
)

// TL;DR: I think basically the flow is:
// 1. You have state trie, which is basically ethereum accounts
// 2. You have storage trie, which associates data with accounts
// 3. Update these, add to memory.
// 4. Commit the memory to disk.
// 5. You can't recover the last state on disk, only those under it.
// e.g., genesis -> V1 -> V2 go to disk, you can recover genesis and V1.
func TestShit2(t *testing.T) {
	datadir := t.TempDir()

	// Open LevelDB database as the underlying disk DB
	db, err := leveldb.New(datadir, 0, 0, "", false)
	if err != nil {
		log.Errorf("Failed to open LevelDB: %v", err)
	}

	// You can now use db as a KeyValueStore
	var kv ethdb.KeyValueStore = db

	// high-level database wrapper for the given key-value store
	disk, err := rawdb.Open(kv, rawdb.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create triedb using pathDB.
	//
	// Basically, consists of one persistent base layer backed by a key-value
	// store (which is rawdb wrapped level), on top of which arbitrarily many
	// in-memory diff layers are stacked.
	//
	// On startup, attempts to load an already existing layer from the rawDB
	// store (with a number of memory layers from a journal). If the journal is not
	// matched with the base persistent layer, all the recorded diff layers are discarded.
	tdb := triedb.NewDatabase(disk, &triedb.Config{
		PathDB: &pathdb.Config{
			NoAsyncFlush: true,
		},
	})

	defer func() {
		if err := tdb.Close(); err != nil {
			t.Logf("ERROR: %v", err)
		}
	}()

	// ---------------- V1

	randBytes := testutil.FillBytes("addr", common.AddressLength)
	var (
		addr     = common.BytesToAddress(randBytes)   // New "random" address
		addrHash = crypto.Keccak256Hash(addr.Bytes()) // New address hash

		// Map that associates addresses to another map with keccak keys
		// and RLP values. I think this is basically to associate data to
		// an address.
		storages = make(map[common.Hash]map[common.Hash][]byte)

		// Map that associates address hashes to the account state in RLP
		accounts = make(map[common.Hash][]byte)

		mergeSet = trienode.NewMergedNodeSet()
	)

	// key / values to associate to this address or update
	storage := make(map[common.Hash][]byte)

	// origin is the original value of account data
	origin := make(map[common.Hash][]byte)

	// NOTE: I think origin basically points to the original
	// data, and storage changes it. Not sure why this is all
	// necessary, but without it, restore doesn't work

	// make random data and add to storage
	for i := 0; i < 10; i++ {
		v, _ := rlp.EncodeToBytes(common.TrimLeftZeroes(random(32)))
		key := random(32)
		hash := crypto.Keccak256Hash(key)

		storage[hash] = v
		origin[hash] = nil
	}

	// Associate this set of key values to the address hash
	storages[addrHash] = storage

	// create new storage ID for trie
	id := trie.StorageTrieID(types.EmptyRootHash, addrHash, types.EmptyRootHash)

	// new trie
	tr, err := trie.New(id, tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load trie, err: %w", err))
	}

	// add the created data to the trie
	for key, val := range storage {
		if err := tr.Update(key.Bytes(), val); err != nil {
			t.Fatal(err)
		}
	}

	// commit the trie, get storage trie root and node set
	storageRootV1, set := tr.Commit(false)
	if err := mergeSet.Merge(set); err != nil {
		t.Fatal(err)
	}

	// StateAccount is the Ethereum consensus representation of accounts
	acc := types.StateAccount{
		Nonce:    uint64(mathrand.Intn(100)),
		Balance:  uint256.NewInt(mathrand.Uint64()),
		CodeHash: random(32),
		Root:     storageRootV1,
	}

	// Associate state account to address
	accounts[addrHash] = types.SlimAccountRLP(acc)

	// New state trie ID
	id = trie.StateTrieID(common.Hash{})

	tr, err = trie.New(id, tdb)
	if err != nil {
		panic(fmt.Errorf("failed to load trie, err: %w", err))
	}

	// add the new account to the trie
	for key, val := range accounts {
		if err := tr.Update(key.Bytes(), val); err != nil {
			t.Fatal(err)
		}
	}

	// commit the trie, get state trie root and node set
	stateRootV1, set := tr.Commit(false)
	if err := mergeSet.Merge(set); err != nil {
		t.Fatal(err)
	}

	// again, these origins are the original data?
	accountOrigin := make(map[common.Address][]byte)
	accountOrigin[addr] = nil
	storageOrigin := make(map[common.Address]map[common.Hash][]byte)
	storageOrigin[addr] = origin

	// StateSet represents a collection of mutated states during a state transition.
	s := triedb.StateSet{
		Accounts:       accounts,
		AccountsOrigin: accountOrigin,
		Storages:       storages,
		StoragesOrigin: storageOrigin,
		RawStorageKey:  false,
	}

	// performs a state transition
	if err := tdb.Update(stateRootV1, types.EmptyRootHash, 0, mergeSet, &s); err != nil {
		t.Fatal(err)
	}

	// Commit stuff genesis and stateRootV1 from memory to underlying disk (leveldb).
	// After doing this, stateRootV1 becomes the "disk layer", meaning the
	// base layer where other new layers sit atop of in memory.
	if err := tdb.Commit(stateRootV1, true); err != nil {
		t.Fatal(err)
	}

	// After commiting, genesis is added to disk, but is not the
	// "disk layer" (that is stateRootV1), so it is recoverable.
	ok, err := tdb.Recoverable(types.EmptyRootHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("not recoverable")
	}

	if err := tdb.Recover(types.EmptyRootHash); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("done\n")
}

func TestZKTrie(t *testing.T) {
	const (
		blockCount uint64 = 1000000 // num of blocks
		// newOutsCount >= inCount + outCount
		newOutsCount uint64 = 1500 // num of outs with new scripts
		inCount      uint64 = 1000 // num of ins
		outCount     uint64 = 500  // num of outs with previous scripts
	)

	datadir := t.TempDir()

	// Open LevelDB database as the underlying disk DB
	db, err := leveldb.New(datadir, 0, 0, "", false)
	if err != nil {
		panic(err)
	}

	// You can now use db as a KeyValueStore
	var kv ethdb.KeyValueStore = db

	// high-level database wrapper for the given key-value store
	disk, err := rawdb.Open(kv, rawdb.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create triedb using pathDB.
	//
	// Basically, consists of one persistent base layer backed by a key-value
	// store (which is rawdb wrapped level), on top of which arbitrarily many
	// in-memory diff layers are stacked.
	//
	// On startup, attempts to load an already existing layer from the rawDB
	// store (with a number of memory layers from a journal). If the journal is not
	// matched with the base persistent layer, all the recorded diff layers are discarded.
	tdb := triedb.NewDatabase(disk, &triedb.Config{
		PathDB: &pathdb.Config{
			NoAsyncFlush: true,
		},
	})
	defer func() {
		if err := tdb.Close(); err != nil {
			t.Logf("ERROR: %v", err)
		}
	}()

	holder := NewTestHolder(tdb)
	for blk := range blockCount {
		realDuration := time.Now()
		for range newOutsCount {
			pkScript := common.BytesToAddress(random(common.AddressLength))
			if err := holder.simulateOut(pkScript, 1000); err != nil {
				t.Fatal(err)
			}
		}
		if blk != 0 {
			for range outCount {
				os := holder.outpoints[0]
				holder.outpoints = holder.outpoints[1:]
				pkScript := os.getAddress()
				if err := holder.simulateOut(pkScript, 75); err != nil {
					t.Fatal(err)
				}
			}
			for range inCount {
				os := holder.outpoints[0]
				holder.outpoints = holder.outpoints[1:]
				if err := holder.simulateIn(os); err != nil {
					t.Fatal(err)
				}
			}
		}
		commitDuration := time.Now()
		if err := holder.commitBlock(blk); err != nil {
			t.Fatal(err)
		}
		t.Logf("block %d: commited in %v, total time %v",
			blk, time.Since(commitDuration), time.Since(realDuration))
	}

	if err := tdb.Recover(types.EmptyRootHash); err != nil {
		t.Fatal(err)
	}
}
