// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package cookedpeer

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func s2ch(s string) *chainhash.Hash {
	h, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return h
}

func TestCookedPeer(t *testing.T) {
	t.Skip("requires bitcoind access that supports mempool")

	addr := "192.168.101.152:18333"
	p := &chaincfg.TestNet3Params
	cp, err := New(wire.TestNet3, 0xc0ffee, addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = cp.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	to := 5 * time.Second

	// Get genesis block
	block0Hash := s2ch("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
	h, err := cp.GetHeaders(ctx, to, []*chainhash.Hash{block0Hash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.GenesisHash.IsEqual(&h.Headers[0].PrevBlock) {
		t.Fatal("expected genesis in previous block")
	}

	// Get unknown block
	blockUnknown := &chainhash.Hash{}
	h, err = cp.GetHeaders(ctx, to, []*chainhash.Hash{blockUnknown}, nil)
	if err != ErrUnknown {
		t.Fatalf("expected unknown error, got %v", err)
	}

	// Get block 1 headers
	block1Hash := s2ch("00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206")
	h, err = cp.GetHeaders(ctx, to, []*chainhash.Hash{block1Hash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !block1Hash.IsEqual(&h.Headers[0].PrevBlock) {
		t.Fatal("expected block 1 hash in previous block")
	}

	// Ask unknown and block 1
	h, err = cp.GetHeaders(ctx, to, []*chainhash.Hash{blockUnknown, block1Hash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !block1Hash.IsEqual(&h.Headers[0].PrevBlock) {
		t.Fatal("expected block 1 hash in previous block")
	}

	// Ask block 1 and unknown
	h, err = cp.GetHeaders(ctx, to, []*chainhash.Hash{block1Hash, blockUnknown}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !block1Hash.IsEqual(&h.Headers[0].PrevBlock) {
		t.Fatal("expected block 1 hash in previous block")
	}

	// Ask block 2 and block 1
	block2Hash := s2ch("000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820")
	h, err = cp.GetHeaders(ctx, to, []*chainhash.Hash{block2Hash, block1Hash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !block2Hash.IsEqual(&h.Headers[0].PrevBlock) {
		t.Fatal("expected block 2 hash in previous block")
	}

	// Ask block 1 and block 2
	h, err = cp.GetHeaders(ctx, to, []*chainhash.Hash{block1Hash, block2Hash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !block1Hash.IsEqual(&h.Headers[0].PrevBlock) {
		t.Fatal("expected block 1 hash in previous block")
	}

	// Ping
	wantPong := 13
	var (
		pongs sync.Map
		wg    sync.WaitGroup
	)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < wantPong; i++ {
		wg.Add(1)
		go func(nonce uint64) {
			defer wg.Done()

			// XXX bitcoind does not like a whole bunch of pings at
			// the same time.
			time.Sleep(time.Duration(r.Int31()%11) * time.Millisecond)

			pongs.Store(nonce, struct{}{})
			pong, err := cp.Ping(ctx, to, nonce)
			if err != nil {
				panic(err)
			}
			if pong.Nonce != nonce {
				panic(fmt.Sprintf("invalid nonce got %v, wanted %v",
					pong.Nonce, nonce))
			}
			if _, ok := pongs.LoadAndDelete(nonce); !ok {
				panic(fmt.Sprintf("nonce not found: %v", nonce))
			}
		}(uint64(i))

	}
	wg.Wait()
	pongs.Range(func(k, v any) bool {
		t.Fatalf("expected empty map: %v", k)
		return false
	})

	// Get addresses v2
	a, err := cp.GetAddr(ctx, to)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		t.Fatal("expected addrv2")
	}

	// Get block 1
	block1, err := cp.GetBlock(ctx, to, block1Hash)
	if err != nil {
		t.Fatal(err)
	}
	b1hash := block1.Header.BlockHash()
	if !block1Hash.IsEqual(&b1hash) {
		t.Fatalf("unexpected hash: %v", b1hash)
	}

	// Get unknown block
	bxx, err := cp.GetBlock(ctx, to, blockUnknown)
	if err != ErrUnknown {
		t.Fatal(err)
	}
	if bxx != nil {
		t.Fatal("didn't expect a block")
	}

	// Get coinbase Tx from block 1, has been pruned
	txID := s2ch("f0315ffc38709d70ad5647e22048358dd3745f3ce3874223c80a7c92fab0c8ba")
	tx, err := cp.GetTx(ctx, to, txID)
	if err != ErrUnknown {
		t.Fatal(err)
	}
	if tx != nil {
		t.Fatal("expected no tx")
	}

	// Get mempool
	mp, err := cp.MemPool(ctx, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(mp.InvList) == 0 {
		t.Fatal("no mempool")
	}
	if mp.InvList[0].Type != wire.InvTypeTx {
		t.Fatalf("mempool returned invalid type: %v", mp.InvList[0].Type)
	}

	// Ask for a recent TX, will be pruned later
	recentTx := &mp.InvList[0].Hash
	tx, err = cp.GetTx(ctx, to, recentTx)
	if err != nil {
		t.Fatal(err)
	}
	txhash := tx.TxHash()
	if !recentTx.IsEqual(&txhash) {
		t.Fatalf("invalid tx id: %v", txhash)
	}

	err = cp.Close()
	if err != nil {
		t.Fatal(err)
	}
}
