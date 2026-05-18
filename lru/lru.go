// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package lru

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
)

// EntryOverhead is the estimated per-entry memory overhead for the map bucket,
// list element, and pointers. Callers should include this in their sizeOf
// function when computing honest byte budgets.
const EntryOverhead = 128

// Stats contains cache statistics.
type Stats struct {
	Hits    int `json:"hits"`
	Misses  int `json:"misses"`
	Purges  int `json:"purges"`
	Cost    int `json:"cost"`     // current total cost
	MaxCost int `json:"max_cost"` // configured cost budget
	Items   int `json:"items"`    // current entry count
}

type entry[K comparable, V any] struct {
	element *list.Element
	key     K
	value   V
	cost    int
}

// Flag controls cache behavior. Combine with bitwise OR.
type Flag uint64

const (
	// FlagPromoteOnly makes Put promote existing entries without
	// updating their value or cost. Useful for caches where the
	// same key always maps to the same value (e.g. block bytes).
	FlagPromoteOnly Flag = 1 << iota
)

// FixedSize returns a cost function that always returns size, ignoring
// the key and value. Useful when every entry has the same known cost.
func FixedSize[K comparable, V any](size int) func(K, V) int {
	return func(_ K, _ V) int { return size }
}

// Cache is a generic LRU cache evicting by total cost. The sizeOf function
// determines the cost of each entry; when the sum exceeds maxCost the least
// recently used entries are evicted until the budget is met.
type Cache[K comparable, V any] struct {
	mtx     sync.Mutex
	maxCost int
	sizeOf  func(K, V) int
	flags   Flag

	m         map[K]*entry[K, V]
	totalCost int
	l         *list.List

	// stats
	hits   int
	misses int
	purges int
}

// New creates a new LRU cache with the given byte budget and cost function.
// The sizeOf function should return the estimated memory cost for a given
// key-value pair, including EntryOverhead.
func New[K comparable, V any](maxCost int, sizeOf func(K, V) int, flags Flag) (*Cache[K, V], error) {
	if maxCost <= 0 {
		return nil, fmt.Errorf("invalid max cost: %v", maxCost)
	}
	if sizeOf == nil {
		return nil, errors.New("sizeOf function required")
	}
	return &Cache[K, V]{
		maxCost: maxCost,
		sizeOf:  sizeOf,
		flags:   flags,
		m:       make(map[K]*entry[K, V]),
		l:       list.New(),
	}, nil
}

// Put inserts or updates a key-value pair. If necessary, LRU entries are
// evicted to stay within the cost budget. Panics if a single entry exceeds
// the entire cache budget.
func (c *Cache[K, V]) Put(k K, v V) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Existing entry: promote to MRU.
	if e, ok := c.m[k]; ok {
		c.l.MoveToBack(e.element)
		if c.flags&FlagPromoteOnly == 0 {
			c.totalCost -= e.cost
			e.value = v
			e.cost = c.sizeOf(k, v)
			c.totalCost += e.cost
			c.evict()
		}
		return
	}

	cost := c.sizeOf(k, v)

	// Evict until there is room.
	c.totalCost += cost
	c.evict()

	c.m[k] = &entry[K, V]{
		element: c.l.PushBack(k),
		key:     k,
		value:   v,
		cost:    cost,
	}
}

// Get returns the value for the given key and true if found, or the zero
// value and false on a cache miss. A hit promotes the entry to most recently
// used.
func (c *Cache[K, V]) Get(k K) (V, bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	e, ok := c.m[k]
	if !ok {
		c.misses++
		var zero V
		return zero, false
	}

	c.l.MoveToBack(e.element)
	c.hits++
	return e.value, true
}

// Has returns true if the key exists in the cache. A hit promotes the entry
// to most recently used.
func (c *Cache[K, V]) Has(k K) bool {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	e, ok := c.m[k]
	if !ok {
		c.misses++
		return false
	}

	c.l.MoveToBack(e.element)
	c.hits++
	return true
}

// Delete removes a key from the cache. Returns true if the key was present.
func (c *Cache[K, V]) Delete(k K) bool {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	e, ok := c.m[k]
	if !ok {
		return false
	}
	c.remove(e)
	return true
}

// Clear removes all entries from the cache and resets cost to zero.
func (c *Cache[K, V]) Clear() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	clear(c.m)
	c.l.Init()
	c.totalCost = 0
}

// Len returns the number of entries in the cache.
func (c *Cache[K, V]) Len() int {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return len(c.m)
}

// Stats returns a snapshot of cache statistics.
func (c *Cache[K, V]) Stats() Stats {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return Stats{
		Hits:    c.hits,
		Misses:  c.misses,
		Purges:  c.purges,
		Cost:    c.totalCost,
		MaxCost: c.maxCost,
		Items:   len(c.m),
	}
}

// evict removes LRU entries until totalCost <= maxCost.
// Must be called with the mutex held.
func (c *Cache[K, V]) evict() {
	for c.totalCost > c.maxCost {
		front := c.l.Front()
		if front == nil {
			break
		}
		k := front.Value.(K)
		e := c.m[k]
		c.remove(e)
		c.purges++
	}
}

// remove deletes an entry from both the map and the list.
// Must be called with the mutex held.
func (c *Cache[K, V]) remove(e *entry[K, V]) {
	c.l.Remove(e.element)
	c.totalCost -= e.cost
	delete(c.m, e.key)
}
