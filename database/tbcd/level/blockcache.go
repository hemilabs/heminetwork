// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var blockSize = 1677721 // ~1.6MB rough size of a mainnet block as of Jan 2025

type blockElement struct {
	element *list.Element
	block   []byte
}

type CacheStats struct {
	Hits   int
	Misses int
	Purges int
}

type lowIQLRU struct {
	mtx sync.RWMutex

	size int // this is the approximate max size

	m         map[chainhash.Hash]blockElement
	totalSize int

	// lru list, when used move to back of the list
	l *list.List

	// stats
	c CacheStats
}

func (l *lowIQLRU) Put(v *btcutil.Block) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	hash := v.Hash()
	if _, ok := l.m[*hash]; ok {
		return
	}

	block, err := v.Bytes()
	if err != nil {
		// data corruption, panic
		panic(err)
	}

	// evict first element in list
	if l.totalSize+len(block) > l.size {
		// LET THEM EAT PANIC
		re := l.l.Front()
		rha := l.l.Remove(re)
		// fmt.Printf("rha %v\n", spew.Sdump(rha))
		// fmt.Printf("==== re %T rha %T\n", re, rha)
		rh := rha.(*list.Element).Value.(*chainhash.Hash)
		l.totalSize -= len(l.m[*rh].block)
		delete(l.m, *rh)
		l.c.Purges++
	}

	// lru list
	element := &list.Element{Value: hash}
	l.l.PushBack(element)

	// block lookup
	l.m[*hash] = blockElement{element: element, block: block}
	l.totalSize += len(block)
}

func (l *lowIQLRU) Get(k *chainhash.Hash) (*btcutil.Block, bool) {
	l.mtx.RLock()
	defer l.mtx.RUnlock()

	be, ok := l.m[*k]
	if !ok {
		l.c.Misses++
		return nil, false
	}
	b, err := btcutil.NewBlockFromBytes(be.block)
	if err != nil {
		// panic for diagnostics at this time
		panic(err)
	}

	// update access
	l.l.MoveToBack(be.element)

	l.c.Hits++

	return b, true
}

func (l *lowIQLRU) Stats() CacheStats {
	l.mtx.RLock()
	defer l.mtx.RUnlock()
	return l.c
}

func lowIQLRUNewSize(size int) (*lowIQLRU, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size: %v", size)
	}
	// approximate number of blocks
	count := size / blockSize
	if count <= 0 {
		return nil, fmt.Errorf("invalid count: %v", count)
	}
	return &lowIQLRU{
		size: size,
		m:    make(map[chainhash.Hash]blockElement, count),
		l:    list.New(),
	}, nil
}
