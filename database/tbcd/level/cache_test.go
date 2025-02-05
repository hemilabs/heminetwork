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

func newBlock(prevHash *chainhash.Hash, nonce uint32) (chainhash.Hash, *btcutil.Block, []byte) {
	bh := wire.NewBlockHeader(0, prevHash, &chainhash.Hash{}, 0, uint32(nonce))
	b := wire.NewMsgBlock(bh)
	ub := btcutil.NewBlock(b)
	r, err := ub.Bytes()
	if err != nil {
		panic(err)
	}
	return bh.BlockHash(), ub, r
}

func TestLRUCache(t *testing.T) {
	maxCache := 10
	blockSize = 81 // we'll use empty blocks
	l, err := lowIQLRUSizeNew(blockSize * maxCache)
	if err != nil {
		t.Fatal(err)
	}

	prevHash := chainhash.Hash{} // genesis
	blocks := make([]chainhash.Hash, 0, maxCache*2)
	for i := 0; i < maxCache; i++ {
		h, _, r := newBlock(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		blocks = append(blocks, h)
		l.Put(&h, r)
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
		h, _, r := newBlock(&prevHash, uint32(i))
		t.Logf("%v: %v", i, h)
		blocks = append(blocks, h)
		l.Put(&h, r)
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
	l, err := lowIQMapCountNew(maxCacheCount)
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

func intHash(b int) chainhash.Hash {
	return chainhash.Hash{byte(b)}
}

func TestHC(t *testing.T) {
	_, err := lowIQMapSizeNew(0)
	if err == nil {
		t.Fatalf("expected invalid size error for size <= 0")
	}
	_, err = lowIQMapSizeNew(1)
	if err == nil {
		t.Fatalf("expected invalid count error for count <= 0")
	}
	size := 1024
	l, err := lowIQMapSizeNew(size)
	if err != nil {
		t.Fatal(err)
	}
	hs := intHash(0)
	for range 2 {
		l.Put(&tbcd.BlockHeader{
			Hash: hs,
		})
	}
	if len(l.m) > 1 {
		t.Fatalf("duplicate headers not excluded by hash")
	}
	if _, ok := l.Get(&hs); !ok {
		t.Fatalf("failed to retrieve header present in map")
	}
	hs = intHash(1)
	if _, ok := l.Get(&hs); ok {
		t.Fatalf("invalid header retrieved from Map")
	}
	for k := range l.count + 5 {
		l.Put(&tbcd.BlockHeader{
			Hash: intHash(k),
		})
	}
	if len(l.m) > l.count {
		t.Fatalf("map size exceeded bounds. expected %v, got %v", l.count, len(l.m))
	}
	storedHashes := make([]*chainhash.Hash, 0, len(l.m)-1)
	var lastHash *chainhash.Hash
	for key := range l.m {
		keyc := key
		if len(storedHashes) >= len(l.m)-1 {
			lastHash = &keyc
		} else {
			storedHashes = append(storedHashes, &keyc)
		}
	}
	l.PurgeBatch(storedHashes)
	if len(l.m) != 1 {
		t.Fatalf("expected %d elements to be purged, purged %d", len(storedHashes), l.count-len(l.m))
	}
	if _, ok := l.Get(lastHash); !ok {
		t.Fatalf("incorrect element purged")
	}
}
