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

const blockSize = 1677721 // ~1.6MB rough size of a mainnet block as of Jan 2025

type timeBlock struct {
	element *list.Element
	block   []byte
}

type lowIQLRU struct {
	mtx sync.RWMutex

	size int // this is the approximate max size

	m         map[chainhash.Hash]timeBlock
	totalSize int

	// lru list
	l *list.List
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
		panic(err)
		// XXX don't cache but panic for now for diagnostic
	}

	// evict first element in list
	if l.totalSize+len(block) >= l.size {
		// LET THEM EAT PANIC
		re := l.l.Front()
		rha := l.l.Remove(re)
		rh := rha.(chainhash.Hash)
		l.totalSize -= len(l.m[rh].block)
		delete(l.m, rh)
	}

	// lru list
	element := &list.Element{Value: hash}
	l.l.PushBack(element)

	// block lookup
	l.m[*hash] = timeBlock{element: element, block: block}
	l.totalSize += len(block)
}

func (l *lowIQLRU) Get(k *chainhash.Hash) (*btcutil.Block, bool) {
	l.mtx.RLock()
	defer l.mtx.RUnlock()

	be, ok := l.m[*k]
	if !ok {
		return nil, false
	}
	b, err := btcutil.NewBlockFromBytes(be.block)
	if err != nil {
		panic(err) // XXX delete from cache and return nil, false but panic for diagnostics at this time
	}

	// update access
	l.l.MoveToBack(be.element)

	return b, true
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
		m:    make(map[chainhash.Hash]timeBlock, count),
		l:    list.New(),
	}, nil
}
