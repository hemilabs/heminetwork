// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/lru"
)

func newBlock(prevHash *chainhash.Hash, nonce uint32) (chainhash.Hash, *btcutil.Block, []byte) {
	bh := wire.NewBlockHeader(0, prevHash, &chainhash.Hash{}, 0, nonce)
	b := wire.NewMsgBlock(bh)
	ub := btcutil.NewBlock(b)
	r, err := ub.Bytes()
	if err != nil {
		panic(err)
	}
	return bh.BlockHash(), ub, r
}

func TestBlockCache(t *testing.T) {
	maxCache := 10
	emptyBlockSize := 81 // size of an empty block
	maxCost := emptyBlockSize * maxCache

	l, err := lru.New[chainhash.Hash, []byte](maxCost, func(_ chainhash.Hash, v []byte) int {
		return len(v)
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	prevHash := chainhash.Hash{} // genesis
	blocks := make([]chainhash.Hash, 0, maxCache*2)
	for i := range maxCache {
		h, _, r := newBlock(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		blocks = append(blocks, h)
		l.Put(h, r)
		prevHash = h
	}

	// verify stats are 0
	s := l.Stats()
	if !(s.Hits == 0 && s.Misses == 0 && s.Purges == 0) {
		t.Fatal(spew.Sdump(s))
	}

	// retrieve all blocks
	for k := range blocks {
		if _, ok := l.Get(blocks[k]); !ok {
			t.Fatalf("block not found: %v", blocks[k])
		}
	}

	// verify hits are maxBlocks
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 0 && s.Purges == 0) {
		t.Fatal(spew.Sdump(s))
	}

	// purge oldest cache entries
	for i := maxCache; i < maxCache*2; i++ {
		h, _, r := newBlock(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		blocks = append(blocks, h)
		l.Put(h, r)
		prevHash = h
	}

	// verify purges are maxBlocks
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 0 && s.Purges == 10) {
		t.Fatal(spew.Sdump(s))
	}

	// retrieve purged blocks
	for k := range blocks {
		if k >= maxCache {
			break
		}
		if _, ok := l.Get(blocks[k]); ok {
			t.Fatalf("block found: %v", blocks[k])
		}
	}

	// verify misses are maxBlocks
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 10 && s.Purges == 10) {
		t.Fatal(spew.Sdump(s))
	}

	t.Log(spew.Sdump(s))
}

func newHeader(prevHash *chainhash.Hash, nonce uint32) (chainhash.Hash, *tbcd.BlockHeader) {
	bh := wire.NewBlockHeader(0, prevHash, &chainhash.Hash{}, 0, nonce)
	return bh.BlockHash(), &tbcd.BlockHeader{
		Hash:       bh.BlockHash(),
		Height:     uint64(nonce),
		Header:     h2b(bh),
		Difficulty: big.Int{},
	}
}

func TestHeaderCache(t *testing.T) {
	const headerCost = 8 + 32 + 80 + 8 + lru.EntryOverhead
	maxCacheCount := 10

	l, err := lru.New[chainhash.Hash, *tbcd.BlockHeader](
		headerCost*maxCacheCount,
		func(_ chainhash.Hash, _ *tbcd.BlockHeader) int {
			return headerCost
		},
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	prevHash := chainhash.Hash{} // genesis
	headers := make([]chainhash.Hash, 0, maxCacheCount*2)
	for i := range maxCacheCount {
		h, bh := newHeader(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		headers = append(headers, h)
		l.Put(bh.Hash, bh)
		prevHash = h
	}

	// verify stats are 0
	s := l.Stats()
	if !(s.Hits == 0 && s.Misses == 0 && s.Purges == 0) {
		t.Fatal(spew.Sdump(s))
	}

	// retrieve all headers
	for k := range headers {
		if _, ok := l.Get(headers[k]); !ok {
			t.Fatalf("header not found: %v", headers[k])
		}
	}

	// verify hits are maxCacheCount
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 0 && s.Purges == 0) {
		t.Fatal(spew.Sdump(s))
	}

	// evict oldest entries by inserting more
	for i := maxCacheCount; i < maxCacheCount*2; i++ {
		h, bh := newHeader(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		headers = append(headers, h)
		l.Put(bh.Hash, bh)
		prevHash = h
	}

	// verify purges are maxCacheCount
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 0 && s.Purges == 10) {
		t.Fatal(spew.Sdump(s))
	}

	// Force a miss
	hm, _ := newHeader(&chainhash.Hash{}, 0xdeadbeef)
	_, ok := l.Get(hm)
	if ok {
		t.Fatal("non cached header found")
	}

	// verify misses
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 1 && s.Purges == 10) {
		t.Fatal(spew.Sdump(s))
	}

	t.Log(spew.Sdump(s))
}

func TestLruStatsToCacheStats(t *testing.T) {
	s := lru.Stats{
		Hits:   10,
		Misses: 5,
		Purges: 3,
		Cost:   1024,
		Items:  7,
	}
	cs := lruStatsToCacheStats(s)
	if cs.Hits != 10 || cs.Misses != 5 || cs.Purges != 3 || cs.Size != 1024 || cs.Items != 7 {
		t.Fatalf("unexpected conversion: %+v", cs)
	}
}
