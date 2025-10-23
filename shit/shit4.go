package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/leveldb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/juju/loggo"
	lerrors "github.com/syndtr/goleveldb/leveldb/errors"
)

var (
	lastrootKey = []byte("lastroot")
	log         = loggo.GetLogger("shit4")
)

func init() {
	if err := loggo.ConfigureLoggers("INFO"); err != nil {
		panic(err)
	}
	log.Infof("Welcome to shit4")
}

type KV struct {
	k []byte
	v []byte
}

func insert(tdb *triedb.Database, parent common.Hash, kvs []KV) (*common.Hash, error) {
	// Trie requires data that is converted to nodes. Without it, it
	// crashes.
	if len(kvs) == 0 {
		return nil, fmt.Errorf("must provide data")
	}

	// Create trie
	tr, err := trie.New(trie.StateTrieID(parent), tdb)
	if err != nil {
		return nil, err
	}

	// Insert KV
	for k := range kvs {
		err := tr.Update(kvs[k].k, kvs[k].v)
		if err != nil {
			return nil, err
		}
	}

	// Update underlying db
	root, nodes := tr.Commit(true)
	if nodes == nil {
		nodes = trienode.NewNodeSet(common.Hash{})
	}
	nodeset := trienode.NewWithNodeSet(nodes)
	state := triedb.NewStateSet()
	err = tdb.Update(root, parent, 0, nodeset, state)
	if err != nil {
		return nil, err
	}

	return &root, nil
}

func main() {
	// Setup DB
	home := "triehome"
	datadir := "datadir"
	db, err := leveldb.New(filepath.Join(home, datadir), 0, 0, "", false)
	if err != nil {
		panic(fmt.Sprintf("Failed to open LevelDB: %v", err))
	}
	var kv ethdb.KeyValueStore = db
	diskdb, err := rawdb.Open(kv, rawdb.OpenOptions{
		Ancient: filepath.Join(home, "ancient"),
	})
	if err != nil {
		panic(err)
	}
	d := pathdb.Defaults
	d.NoAsyncFlush = true
	tdb := triedb.NewDatabase(diskdb, &triedb.Config{
		PathDB: d,
	})

	// Close DB on the way out
	defer func() {
		if err := tdb.Disk(); err != nil {
			panic(err)
		}
	}()

	// See if we have a `lastroot`
	lastroot, err := db.Get(lastrootKey)
	if err != nil {
		if !errors.Is(err, lerrors.ErrNotFound) {
			panic(err)
		}
		// Not found, insert empty root.
		root, err := insert(tdb, types.EmptyRootHash, []KV{
			{
				k: []byte("genesis"),
				v: types.EmptyRootHash[:],
			},
		})
		if err != nil {
			panic(err)
		}
		lastroot = root[:]
	}

	// Make sure we breach immutability threshold several times.
	// Also note that we are off by one because we store lastroot insisde
	// the loop. If we don't save it first lastroor will be unknown at
	// restart.
	nodes := 1 + (params.FullImmutabilityThreshold * 3)
	for i := 0; i < nodes; i++ {
		s := "root"
		if i == 0 {
			s = "genesis"
		}
		log.Infof("%v %v: %x", s, i, lastroot)
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		value := sha256.Sum256(key[:])
		kvs := []KV{
			{
				k: key[:],
				v: value[:],
			},
		}

		root, err := insert(tdb, common.Hash(lastroot), kvs)
		if err != nil {
			panic(err)
		}
		err = db.Put(lastrootKey, lastroot[:])
		if err != nil {
			panic(err)
		}
		lastroot = root[:]
		break
	}
}
