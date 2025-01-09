// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

const blockHeaderSize = 8 + 32 + 80 + 8 // rough size of tbcd.BlockHeader

type lowIQMap struct {
	mtx sync.Mutex

	count int

	m map[chainhash.Hash]*tbcd.BlockHeader // 32+8+80+len([]Word ~ 8)

	// stats
	c tbcd.CacheStats
}

func (l *lowIQMap) Put(v *tbcd.BlockHeader) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if _, ok := l.m[v.Hash]; ok {
		return
	}

	if len(l.m) >= l.count {
		// evict random entry
		for k := range l.m {
			delete(l.m, k)
			l.c.Purges++
			break
		}
	}

	l.m[v.Hash] = v
}

func (l *lowIQMap) Get(k *chainhash.Hash) (*tbcd.BlockHeader, bool) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	bh, ok := l.m[*k]
	if ok {
		l.c.Hits++
	} else {
		l.c.Misses++
	}
	return bh, ok
}

func (l *lowIQMap) PurgeBatch(ks []*chainhash.Hash) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	for v := range ks {
		delete(l.m, *ks[v])
		l.c.Purges++
	}
}

func (l *lowIQMap) Stats() tbcd.CacheStats {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	l.c.Items = len(l.m)
	l.c.Size = len(l.m) * blockHeaderSize // rough size
	return l.c
}

func lowIQMapCountNew(count int) (*lowIQMap, error) {
	if count <= 0 {
		return nil, fmt.Errorf("invalid count: %v", count)
	}
	return &lowIQMap{
		count: count,
		m:     make(map[chainhash.Hash]*tbcd.BlockHeader, count),
	}, nil
}

// lowIQMapNewSize does a bit of math to estimate the number of cache items.
// Since it is an estimate it will overflow if Difficulty becomes bigger than
// 64 bits. This is not an issue since 100MB caches all of mainnet in Jan 2025
// (~819200 items).
func lowIQMapSizeNew(size int) (*lowIQMap, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size: %v", size)
	}
	// approximate number of headers
	return lowIQMapCountNew(size / blockHeaderSize)
}
