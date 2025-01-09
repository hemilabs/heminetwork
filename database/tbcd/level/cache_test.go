package level

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
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
	if s.Hits != 0 && s.Misses != 0 && s.Purges != 0 {
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
	if s.Hits != 10 && s.Misses != 0 && s.Purges != 0 {
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

	t.Logf("%v", spew.Sdump(l.Stats()))
}
