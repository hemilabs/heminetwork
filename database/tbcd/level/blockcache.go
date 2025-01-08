// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const blockSize = 1677721 // ~1.6MB rough size of a mainnet block as of Jan 2025

type lowIQLRU struct {
	mtx sync.RWMutex

	size int // this is the approximate max size

	m         map[chainhash.Hash][]byte
	totalSize int
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

	// XXX add eviction here
	if l.totalSize+len(block) >= l.size {
		panic("evict")
	}

	l.m[*hash] = block
	l.totalSize += len(block)
}

func (l *lowIQLRU) Get(k *chainhash.Hash) (*btcutil.Block, bool) {
	l.mtx.RLock()
	defer l.mtx.RUnlock()

	be, ok := l.m[*k]
	if !ok {
		return nil, false
	}
	b, err := btcutil.NewBlockFromBytes(be)
	if err != nil {
		panic(err) // XXX delete from cache and return nil, false but panic for diagnostics at this time
	}
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
		m:    make(map[chainhash.Hash][]byte, count),
	}, nil
}
