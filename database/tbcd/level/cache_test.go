package level

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

func newBlock(prevHash *chainhash.Hash, nonce uint32) (chainhash.Hash, *btcutil.Block) {
	bh := wire.NewBlockHeader(0, prevHash, &chainhash.Hash{}, 0, uint32(nonce))
	b := wire.NewMsgBlock(bh)
	return bh.BlockHash(), btcutil.NewBlock(b)
}

func TestLRUCache(t *testing.T) {
	maxCache := 10
	blockSize = 81 // we'll use empty blocks
	l, err := lowIQLRUNewSize(blockSize * maxCache)
	if err != nil {
		t.Fatal(err)
	}

	prevHash := chainhash.Hash{} // genesis
	blocks := make([]chainhash.Hash, 0, maxCache*2)
	for i := 0; i < maxCache; i++ {
		h, b := newBlock(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		blocks = append(blocks, h)
		l.Put(b)
		prevHash = h
	}

	// verify stats are 0
	s := l.Stats()
	if !(s.Hits == 0 && s.Misses == 0 && s.Purges == 0) {
		t.Fatal(spew.Sdump(s))
	}

	// retrieve all blocks
	for k := range blocks {
		if _, ok := l.Get(&blocks[k]); !ok {
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
		h, b := newBlock(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		blocks = append(blocks, h)
		l.Put(b)
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
		if _, ok := l.Get(&blocks[k]); ok {
			t.Fatalf("block found: %v", blocks[k])
		}
	}

	// verify misses are maxBlocks
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 10 && s.Purges == 10) {
		t.Fatal(spew.Sdump(s))
	}

	t.Logf(spew.Sdump(s))
}

func newHeader(prevHash *chainhash.Hash, nonce uint32) (chainhash.Hash, *tbcd.BlockHeader) {
	bh := wire.NewBlockHeader(0, prevHash, &chainhash.Hash{}, 0, uint32(nonce))
	return bh.BlockHash(), &tbcd.BlockHeader{
		Hash:       bh.BlockHash(),
		Height:     uint64(nonce),
		Header:     h2b(bh),
		Difficulty: big.Int{},
	}
}

func TestMapCache(t *testing.T) {
	maxCacheCount := 10
	l, err := lowIQMapNewCount(maxCacheCount)
	if err != nil {
		t.Fatal(err)
	}

	prevHash := chainhash.Hash{} // genesis
	headers := make([]chainhash.Hash, 0, maxCacheCount*2)
	for i := 0; i < maxCacheCount; i++ {
		h, bh := newHeader(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		headers = append(headers, h)
		l.Put(bh)
		prevHash = h
	}

	// verify stats are 0
	s := l.Stats()
	if !(s.Hits == 0 && s.Misses == 0 && s.Purges == 0) {
		t.Fatal(spew.Sdump(s))
	}

	// retrieve all headers
	for k := range headers {
		if _, ok := l.Get(&headers[k]); !ok {
			t.Fatalf("header not found: %v", headers[k])
		}
	}

	// verify hits are maxBlocks
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 0 && s.Purges == 0) {
		t.Fatal(spew.Sdump(s))
	}

	// purge random cache entries
	for i := maxCacheCount; i < maxCacheCount*2; i++ {
		h, bh := newHeader(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		headers = append(headers, h)
		l.Put(bh)
		prevHash = h
	}

	// verify purges are maxBlocks
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 0 && s.Purges == 10) {
		t.Fatal(spew.Sdump(s))
	}

	// Force a random miss
	hm, _ := newHeader(&chainhash.Hash{}, 0xdeadbeef)
	_, ok := l.Get(&hm)
	if ok {
		t.Fatal("non cached header found")
	}

	// verify misses
	s = l.Stats()
	if !(s.Hits == 10 && s.Misses == 1 && s.Purges == 10) {
		t.Fatal(spew.Sdump(s))
	}

	t.Logf(spew.Sdump(s))
}
