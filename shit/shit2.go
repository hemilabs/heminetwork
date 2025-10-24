package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/trie"
)

// func main2() {
// 	// Path to the chaindata directory (LevelDB)
// 	datadir := "lxx"

// 	// Open LevelDB database (implements ethdb.KeyValueStore)
// 	db, err := leveldb.New(datadir, 0, 0, "", false)
// 	if err != nil {
// 		log.Fatalf("Failed to open LevelDB: %v", err)
// 	}
// 	// defer db.Close()

// 	// You can now use db as a KeyValueStore
// 	var kv ethdb.KeyValueStore = db

// 	// diskdb, err := rawdb.Open(rawdb.NewMemoryDatabase(), rawdb.OpenOptions{
// 	diskdb, err := rawdb.Open(kv, rawdb.OpenOptions{
// 		Ancient: "x", // os.TempDir(),
// 	})
// 	if err != nil {
// 		panic(err)
// 	}

// 	d := pathdb.Defaults
// 	d.NoAsyncFlush = true
// 	tdb := triedb.NewDatabase(diskdb, &triedb.Config{
// 		PathDB: d,
// 	})

// 	// V1
// 	trV0, err := trie.New(trie.StateTrieID(types.EmptyRootHash), tdb)
// 	if err != nil {
// 		panic(err)
// 	}
// 	if err := trV0.Update([]byte("apple"), []byte("red")); err != nil {
// 		panic(err)
// 	}
// 	if err := trV0.Update([]byte("banana"), []byte("yellow")); err != nil {
// 		panic(err)
// 	}
// 	if err := trV0.Update([]byte("cherry"), []byte("dark red")); err != nil {
// 		panic(err)
// 	}
// 	rootV1, nodesV1 := trV0.Commit(true)
// 	nodesetV1 := trienode.NewWithNodeSet(nodesV1)
// 	stateV1 := triedb.NewStateSet()
// 	if err := tdb.Update(rootV1, types.EmptyRootHash, 0, nodesetV1, stateV1); err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("Root V1:", rootV1)
// 	//if err := tdb.Enable(types.EmptyRootHash); err != nil {
// 	//	panic(err)
// 	//}

// 	// V2
// 	trV1, err := trie.New(trie.TrieID(rootV1), tdb)
// 	if err != nil {
// 		panic(err)
// 	}
// 	if err := trV1.Update([]byte("date"), []byte("brown")); err != nil {
// 		panic(err)
// 	}
// 	rootV2, nodesV2 := trV1.Commit(true)
// 	nodesetV2 := trienode.NewWithNodeSet(nodesV2)
// 	stateV2 := triedb.NewStateSet()
// 	if err := tdb.Update(rootV2, rootV1, 1, nodesetV2, stateV2); err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("Committed Root V2:", rootV2)
// 	//if err := tdb.Enable(rootV1); err != nil {
// 	//	panic(err)
// 	//}

// 	// V3
// 	trV2, err := trie.New(trie.TrieID(rootV2), tdb)
// 	if err != nil {
// 		panic(err)
// 	}
// 	if err := trV2.Update([]byte("elderberry"), []byte("black")); err != nil {
// 		panic(err)
// 	}
// 	if err := trV2.Update([]byte("fig"), []byte("purple")); err != nil {
// 		panic(err)
// 	}
// 	rootV3, nodesV3 := trV2.Commit(true)
// 	nodesetV3 := trienode.NewWithNodeSet(nodesV3)
// 	stateV3 := triedb.NewStateSet()
// 	if err := tdb.Update(rootV3, rootV2, 2, nodesetV3, stateV3); err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("Committed Root V3:", rootV3)

// 	// Print
// 	trV1, err = trie.New(trie.TrieID(rootV1), tdb)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("\nState at Root V1:")
// 	showKeys(trV1, []string{"apple", "banana", "cherry", "date", "elderberry", "fig"})

// 	trV2, err = trie.New(trie.TrieID(rootV2), tdb)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("\nState at Root V2:")
// 	showKeys(trV2, []string{"apple", "banana", "cherry", "date", "elderberry", "fig"})

// 	trV3, err := trie.New(trie.TrieID(rootV3), tdb)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("\nState at Root V3:")
// 	showKeys(trV3, []string{"apple", "banana", "cherry", "date", "elderberry", "fig"})

// 	// Got to V2
// 	//if err := tdb.Enable(types.EmptyRootHash); err != nil {
// 	//	panic(err)
// 	//}
// 	//if err := tdb.Enable(rootV1); err != nil {
// 	//	panic(err)
// 	//}
// 	// rawdb.WriteStateID(diskdb, types.EmptyRootHash, 0)
// 	// rawdb.WriteStateID(diskdb, rootV1, 1)
// 	// rawdb.WriteStateID(diskdb, rootV2, 2)
// 	// rawdb.WriteStateID(diskdb, rootV3, 3)
// 	//if err := tdb.Recover(rootV1); err != nil {
// 	//	panic(err)
// 	//}
// 	if err := tdb.Close(); err != nil {
// 		panic(err)
// 	}

// 	fmt.Printf("done\n")
// }

func showKeys(tr *trie.Trie, keys []string) {
	for _, k := range keys {
		val, _ := tr.Get([]byte(k))
		if val == nil {
			fmt.Printf("%s: <nil>\n", k)
		} else {
			fmt.Printf("%s: %s\n", k, val)
		}
	}
}
