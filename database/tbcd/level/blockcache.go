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

	"github.com/hemilabs/heminetwork/database/tbcd"
)

var blockSize = 1677721 // ~1.6MB rough size of a mainnet block as of Jan 2025

type blockElement struct {
	element *list.Element
	block   []byte
}

type lowIQLRU struct {
	mtx sync.Mutex

	size int // this is the approximate max size

	m         map[chainhash.Hash]blockElement
	totalSize int

	// lru list, when used move to back of the list
	l *list.List

	// stats
	c tbcd.CacheStats
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
		rh := rha.(*chainhash.Hash)
		l.totalSize -= len(l.m[*rh].block)
		delete(l.m, *rh)
		l.c.Purges++
	}

	// block lookup and lru append
	l.m[*hash] = blockElement{element: l.l.PushBack(hash), block: block}
	l.totalSize += len(block)

	l.c.Size = l.totalSize
}

func (l *lowIQLRU) Get(k *chainhash.Hash) (*btcutil.Block, bool) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

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

func (l *lowIQLRU) Stats() tbcd.CacheStats {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	l.c.Items = len(l.m)
	return l.c
}

func lowIQLRUSizeNew(size int) (*lowIQLRU, error) {
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
