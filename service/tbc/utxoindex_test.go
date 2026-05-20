// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
	"github.com/hemilabs/heminetwork/v2/lru"
	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
)

// utxoReadCacheSizeOf matches production sizeOf in tbc.go.
func utxoReadCacheSizeOf(_ tbcd.Outpoint, _ tbcd.ScriptHash) int {
	return 37 + 32 + lru.EntryOverhead
}

func makeOutpoint(txIdx byte, outIdx uint32) tbcd.Outpoint {
	var h chainhash.Hash
	h[0] = txIdx
	return tbcd.NewOutpoint(h, outIdx)
}

func makeScriptHash(b byte) tbcd.ScriptHash {
	var sh tbcd.ScriptHash
	sh[0] = b
	return sh
}

func TestUtxoReadCachePutGet(t *testing.T) {
	const budget = 10 * (37 + 32 + lru.EntryOverhead) // room for 10 entries
	c, err := lru.New[tbcd.Outpoint, tbcd.ScriptHash](budget, utxoReadCacheSizeOf, 0)
	if err != nil {
		t.Fatal(err)
	}

	op := makeOutpoint(1, 0)
	sh := makeScriptHash(0xaa)
	c.Put(op, sh)

	got, ok := c.Get(op)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got != sh {
		t.Fatalf("expected %x, got %x", sh, got)
	}

	s := c.Stats()
	if s.Hits != 1 || s.Misses != 0 || s.Items != 1 {
		t.Fatalf("unexpected stats: %+v", s)
	}
}

func TestUtxoReadCacheLRUEviction(t *testing.T) {
	const n = 5
	const budget = n * (37 + 32 + lru.EntryOverhead) // exactly n entries
	c, err := lru.New[tbcd.Outpoint, tbcd.ScriptHash](budget, utxoReadCacheSizeOf, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Fill cache to capacity.
	for i := range n {
		c.Put(makeOutpoint(byte(i), 0), makeScriptHash(byte(i)))
	}
	if c.Len() != n {
		t.Fatalf("expected %d items, got %d", n, c.Len())
	}

	// Touch entry 0 to make it MRU.
	c.Get(makeOutpoint(0, 0))

	// Insert entry n — should evict entry 1 (LRU), not entry 0.
	c.Put(makeOutpoint(byte(n), 0), makeScriptHash(byte(n)))

	if c.Len() != n {
		t.Fatalf("expected %d items after eviction, got %d", n, c.Len())
	}

	// Entry 0 survived (was MRU).
	if _, ok := c.Get(makeOutpoint(0, 0)); !ok {
		t.Fatal("expected entry 0 to survive (MRU)")
	}

	// Entry 1 evicted (was LRU).
	if _, ok := c.Get(makeOutpoint(1, 0)); ok {
		t.Fatal("expected entry 1 evicted (LRU)")
	}

	// New entry present.
	if _, ok := c.Get(makeOutpoint(byte(n), 0)); !ok {
		t.Fatal("expected new entry present")
	}

	s := c.Stats()
	if s.Purges != 1 {
		t.Fatalf("expected 1 purge, got %d", s.Purges)
	}
}

func TestUtxoReadCacheSimulateFlushCycle(t *testing.T) {
	// Simulate: write cache fills, flushes, clears. Read cache survives.
	// Next batch re-reads same UTXOs — should hit read cache, not DB.
	const budget = 100 * (37 + 32 + lru.EntryOverhead)
	readCache, err := lru.New[tbcd.Outpoint, tbcd.ScriptHash](budget, utxoReadCacheSizeOf, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Batch 1: "DB reads" populate the read cache.
	for i := range 10 {
		op := makeOutpoint(byte(i), 0)
		sh := makeScriptHash(byte(i))
		readCache.Put(op, sh) // simulate DB hit → cache populate
	}

	s := readCache.Stats()
	if s.Items != 10 {
		t.Fatalf("batch 1: expected 10 items, got %d", s.Items)
	}

	// Simulate write cache flush + clear. Read cache NOT cleared.
	// (Write cache is a separate object; nothing happens to readCache.)

	// Batch 2: same outpoints re-read — should all hit read cache.
	for i := range 10 {
		op := makeOutpoint(byte(i), 0)
		_, ok := readCache.Get(op)
		if !ok {
			t.Fatalf("batch 2: expected cache hit for outpoint %d", i)
		}
	}

	s = readCache.Stats()
	if s.Hits != 10 {
		t.Fatalf("expected 10 hits in batch 2, got %d", s.Hits)
	}
	if s.Misses != 0 {
		t.Fatalf("expected 0 misses in batch 2, got %d", s.Misses)
	}
}

func TestUtxoReadCachePurgeOnSyncComplete(t *testing.T) {
	const budget = 100 * (37 + 32 + lru.EntryOverhead)
	readCache, err := lru.New[tbcd.Outpoint, tbcd.ScriptHash](budget, utxoReadCacheSizeOf, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Populate.
	for i := range 20 {
		readCache.Put(makeOutpoint(byte(i), 0), makeScriptHash(byte(i)))
	}
	if readCache.Len() != 20 {
		t.Fatalf("expected 20 items, got %d", readCache.Len())
	}

	// Wire the hook the same way Server does.
	cleared := false
	hook := func() {
		readCache.Clear()
		cleared = true
	}

	// Create a utxoIndexer with the hook.
	uxi := &utxoIndexer{
		syncCompleteHook: hook,
	}

	// Framework calls onSyncComplete.
	uxi.onSyncComplete()

	if !cleared {
		t.Fatal("syncCompleteHook was not called")
	}
	if readCache.Len() != 0 {
		t.Fatalf("expected empty cache after purge, got %d", readCache.Len())
	}

	// Cache is usable again after clear.
	readCache.Put(makeOutpoint(0xff, 0), makeScriptHash(0xff))
	if readCache.Len() != 1 {
		t.Fatalf("expected 1 item after re-use, got %d", readCache.Len())
	}
}

func TestUtxoReadCacheNilHookSafe(t *testing.T) {
	// onSyncComplete with nil hook must not panic.
	uxi := &utxoIndexer{}
	uxi.onSyncComplete() // should be a no-op
}

func TestUtxoReadCacheInfoHook(t *testing.T) {
	const budget = 10 * (37 + 32 + lru.EntryOverhead)
	c, err := lru.New[tbcd.Outpoint, tbcd.ScriptHash](budget, utxoReadCacheSizeOf, 0)
	if err != nil {
		t.Fatal(err)
	}

	uxi := &utxoIndexer{
		readCacheInfoHook: func() string {
			cs := c.Stats()
			fill := 0
			if cs.MaxCost > 0 {
				fill = cs.Cost * 100 / cs.MaxCost
			}
			hitPct := 0
			if total := cs.Hits + cs.Misses; total > 0 {
				hitPct = cs.Hits * 100 / total
			}
			return fmt.Sprintf(" rcache hits %v%% usage %v%%", hitPct, fill)
		},
	}

	// Empty cache — 0 hits, 0% fill.
	info := uxi.readCacheInfo()
	if info != " rcache hits 0% usage 0%" {
		t.Fatalf("unexpected empty info: %q", info)
	}

	// Populate 5 entries.
	for i := range 5 {
		c.Put(makeOutpoint(byte(i), 0), makeScriptHash(byte(i)))
	}
	// Hit 3 of them.
	for i := range 3 {
		c.Get(makeOutpoint(byte(i), 0))
	}

	info = uxi.readCacheInfo()
	if info != " rcache hits 100% usage 50%" {
		t.Fatalf("unexpected info: %q", info)
	}
}

func TestUtxoReadCacheInfoNilHook(t *testing.T) {
	uxi := &utxoIndexer{}
	if info := uxi.readCacheInfo(); info != "" {
		t.Fatalf("expected empty string, got %q", info)
	}
}

func TestLRUStatsMaxCost(t *testing.T) {
	const budget = 1000
	c, err := lru.New[string, string](budget, func(k, v string) int {
		return len(k) + len(v) + lru.EntryOverhead
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	s := c.Stats()
	if s.MaxCost != budget {
		t.Fatalf("expected MaxCost %d, got %d", budget, s.MaxCost)
	}
}

func TestUtxoReadCacheIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	n, err := newFakeNode(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := n.Stop(); err != nil {
			t.Logf("node stop: %v", err)
		}
	}()

	go func() {
		if err := n.Run(ctx); !testutil.ErrorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	cfg := &Config{
		AutoIndex:               false,
		BlockSanity:             false,
		LevelDBHome:             t.TempDir(),
		MaxCachedTxs:            3, // small write cache to force flushes
		Network:                 networkLocalnet,
		RequestTimeout:          10,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		MempoolEnabled:          false,
		Seeds:                   []string{n.Address()},
		NotificationBlocking:    true,
		UtxoReadCacheSize:       "1mb",
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) && !errors.Is(err, net.ErrClosed) {
			panic(err)
		}
	}()

	// Wait for peer connection.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	const blockCount = 20
	blocks := make([]*block, blockCount)

	prevHash := chaincfg.RegressionNetParams.GenesisHash
	for i := 1; i <= blockCount; i++ {
		blk, err := n.MineAndSend(ctx, "b"+strconv.Itoa(i), prevHash, n.address, MineWithMultiple)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = blk.Hash()
		blocks[i-1] = blk
	}

	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// Index to tip — fixup strategies will exercise the read cache.
	if err := s.SyncIndexersToHash(ctx, *blocks[blockCount-1].Hash()); err != nil {
		t.Fatal(err)
	}

	// After sync completes, onSyncComplete clears items but stats survive.
	if s.utxoReadCache == nil {
		t.Fatal("expected utxoReadCache to be initialized after Run")
	}
	cs := s.utxoReadCache.Stats()

	t.Logf("read cache stats: hits=%d misses=%d purges=%d items=%d cost=%d",
		cs.Hits, cs.Misses, cs.Purges, cs.Items, cs.Cost)

	// The cache must have been exercised during fixup.
	if cs.Hits+cs.Misses == 0 {
		t.Fatal("expected read cache to be exercised during indexing (hits+misses > 0)")
	}

	// onSyncComplete should have cleared the cache.
	if cs.Items != 0 {
		t.Fatalf("expected 0 items after sync complete, got %d", cs.Items)
	}
	if cs.Cost != 0 {
		t.Fatalf("expected 0 cost after sync complete, got %d", cs.Cost)
	}
}
