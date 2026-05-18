// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/lru"
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
