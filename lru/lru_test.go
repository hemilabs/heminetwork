// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package lru

import (
	"sync"
	"testing"
)

// trivial cost function: 1 per entry.

func TestNew(t *testing.T) {
	_, err := New(0, FixedSize[string, int](1), 0)
	if err == nil {
		t.Fatal("expected error for zero maxCost")
	}
	_, err = New(-1, FixedSize[string, int](1), 0)
	if err == nil {
		t.Fatal("expected error for negative maxCost")
	}
	_, err = New[string, int](10, nil, 0)
	if err == nil {
		t.Fatal("expected error for nil sizeOf")
	}
	c, err := New(10, FixedSize[string, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 0 {
		t.Fatalf("expected empty cache, got %d", c.Len())
	}
}

func TestPutGet(t *testing.T) {
	c, err := New(5, FixedSize[string, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	v, ok := c.Get("b")
	if !ok || v != 2 {
		t.Fatalf("expected 2, got %v (ok=%v)", v, ok)
	}

	_, ok = c.Get("missing")
	if ok {
		t.Fatal("expected miss")
	}

	s := c.Stats()
	if s.Hits != 1 {
		t.Fatalf("hits: want 1, got %d", s.Hits)
	}
	if s.Misses != 1 {
		t.Fatalf("misses: want 1, got %d", s.Misses)
	}
	if s.Items != 3 {
		t.Fatalf("items: want 3, got %d", s.Items)
	}
}

func TestEviction(t *testing.T) {
	c, err := New(3, FixedSize[string, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)
	// Cache full at cost 3.

	c.Put("d", 4)
	// "a" should be evicted (LRU).
	if c.Len() != 3 {
		t.Fatalf("expected 3 items, got %d", c.Len())
	}
	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected 'a' evicted")
	}
	v, ok := c.Get("d")
	if !ok || v != 4 {
		t.Fatalf("expected 4, got %v (ok=%v)", v, ok)
	}

	s := c.Stats()
	if s.Purges != 1 {
		t.Fatalf("purges: want 1, got %d", s.Purges)
	}
}

func TestLRUOrder(t *testing.T) {
	c, err := New(3, FixedSize[string, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	// Touch "a" to make it most recently used.
	c.Get("a")

	// Insert "d" — "b" should be evicted (now LRU), not "a".
	c.Put("d", 4)

	_, ok := c.Get("b")
	if ok {
		t.Fatal("expected 'b' evicted")
	}
	_, ok = c.Get("a")
	if !ok {
		t.Fatal("expected 'a' still present")
	}
}

func TestUpdateOnDuplicatePut(t *testing.T) {
	sizeOf := func(_ string, v int) int { return v }
	c, err := New(10, sizeOf, 0)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 3)
	c.Put("b", 3)
	// totalCost = 6

	// Default: Put updates value and cost.
	c.Put("a", 8)
	// totalCost = 8+3=11, exceeds 10 → evict "b" (LRU).
	if c.Len() != 1 {
		t.Fatalf("expected 1 item, got %d", c.Len())
	}
	v, ok := c.Get("a")
	if !ok || v != 8 {
		t.Fatalf("expected updated value 8, got %v (ok=%v)", v, ok)
	}
}

func TestPromoteOnlyPut(t *testing.T) {
	c, err := New(3, FixedSize[string, int](1), FlagPromoteOnly)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	// Re-put "a" — should promote only, not update value.
	c.Put("a", 99)

	// "a" is now MRU. Insert "d" → "b" evicted (LRU), not "a".
	c.Put("d", 4)

	_, ok := c.Get("b")
	if ok {
		t.Fatal("expected 'b' evicted")
	}
	v, ok := c.Get("a")
	if !ok {
		t.Fatal("expected 'a' still present")
	}
	if v != 1 {
		t.Fatalf("expected original value 1, got %d (promote should not update)", v)
	}
}

func TestDelete(t *testing.T) {
	c, err := New(5, FixedSize[string, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 1)
	c.Put("b", 2)

	if !c.Delete("a") {
		t.Fatal("expected delete to return true")
	}
	if c.Delete("a") {
		t.Fatal("expected second delete to return false")
	}
	if c.Len() != 1 {
		t.Fatalf("expected 1 item, got %d", c.Len())
	}
	s := c.Stats()
	if s.Cost != 1 {
		t.Fatalf("cost: want 1, got %d", s.Cost)
	}
}

func TestClear(t *testing.T) {
	c, err := New(10, FixedSize[string, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)
	c.Clear()

	if c.Len() != 0 {
		t.Fatalf("expected empty, got %d", c.Len())
	}
	s := c.Stats()
	if s.Cost != 0 {
		t.Fatalf("cost: want 0, got %d", s.Cost)
	}
	// Stats should survive clear.
	if s.Items != 0 {
		t.Fatalf("items: want 0, got %d", s.Items)
	}
}

func TestByteSized(t *testing.T) {
	// Simulate block-cache-like usage with variable-size values.
	sizeOf := func(_ string, v []byte) int { return len(v) + EntryOverhead }

	maxCost := 1000
	c, err := New(maxCost, sizeOf, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Insert entries that together exceed budget.
	c.Put("small", make([]byte, 100))  // cost: 228
	c.Put("medium", make([]byte, 400)) // cost: 528
	c.Put("large", make([]byte, 500))  // cost: 628
	// total: 1384, exceeds 1000 → "small" evicted first, then check.

	s := c.Stats()
	if s.Cost > maxCost {
		t.Fatalf("cost %d exceeds max %d", s.Cost, maxCost)
	}

	_, ok := c.Get("small")
	if ok {
		t.Fatal("expected 'small' evicted")
	}
}

func TestConcurrent(t *testing.T) {
	c, err := New(1000, FixedSize[int, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := range 100 {
				k := n*100 + j
				c.Put(k, k)
				c.Get(k)
			}
		}(i)
	}
	wg.Wait()

	s := c.Stats()
	if s.Items > 1000 {
		t.Fatalf("items %d exceed capacity", s.Items)
	}
	if s.Cost > 1000 {
		t.Fatalf("cost %d exceeds maxCost", s.Cost)
	}
}

func TestOversizedEntry(t *testing.T) {
	// A single entry whose cost exceeds the budget should still be
	// stored. Evict drains the list, hits the nil guard, and breaks.
	c, err := New(3, FixedSize[string, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}

	// Fill the cache.
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	// Insert an entry with cost 1 (unit cost), but the cache is full.
	// This forces eviction of "a", which is normal.
	// Now test the degenerate case: empty cache, item cost > maxCost.
	c.Clear()

	// Use a sizeOf that returns more than maxCost for a specific key.
	bigCache, err := New(100, func(_ string, v []byte) int {
		return len(v) + EntryOverhead
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Put an entry whose cost (200 + 128 = 328) exceeds maxCost (100).
	// The list is empty, evict hits nil guard and breaks.
	bigCache.Put("huge", make([]byte, 200))

	v, ok := bigCache.Get("huge")
	if !ok {
		t.Fatal("expected oversized entry to be stored")
	}
	if len(v) != 200 {
		t.Fatalf("expected len 200, got %d", len(v))
	}
	s := bigCache.Stats()
	if s.Items != 1 {
		t.Fatalf("items: want 1, got %d", s.Items)
	}

	// A subsequent normal-sized put should evict the oversized entry.
	bigCache.Put("small", make([]byte, 10))
	_, ok = bigCache.Get("huge")
	if ok {
		t.Fatal("expected oversized entry evicted")
	}
	_, ok = bigCache.Get("small")
	if !ok {
		t.Fatal("expected 'small' present")
	}
}

func TestEvictEmptiesList(t *testing.T) {
	// Evicting all entries when a new put arrives that alone fits the
	// budget but the cumulative cost exceeds it.
	sizeOf := func(_ string, v int) int { return v }
	c, err := New(10, sizeOf, 0)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 4)
	c.Put("b", 4)
	// totalCost = 8

	// Put "c" with cost 8 → total would be 16 → evict both "a" and "b",
	// list empties, then "c" is added. Cost = 8, within budget.
	c.Put("c", 8)

	if c.Len() != 1 {
		t.Fatalf("expected 1 item, got %d", c.Len())
	}
	v, ok := c.Get("c")
	if !ok || v != 8 {
		t.Fatalf("expected 8, got %v (ok=%v)", v, ok)
	}
	s := c.Stats()
	if s.Purges != 2 {
		t.Fatalf("purges: want 2, got %d", s.Purges)
	}
}

func TestHas(t *testing.T) {
	c, err := New(5, FixedSize[string, int](1), 0)
	if err != nil {
		t.Fatal(err)
	}

	c.Put("a", 1)

	if !c.Has("a") {
		t.Fatal("expected Has to return true")
	}
	if c.Has("missing") {
		t.Fatal("expected Has to return false for missing key")
	}

	s := c.Stats()
	if s.Hits != 1 {
		t.Fatalf("hits: want 1, got %d", s.Hits)
	}
	if s.Misses != 1 {
		t.Fatalf("misses: want 1, got %d", s.Misses)
	}
}
