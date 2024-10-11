// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

type lowIQMap struct {
	mtx sync.RWMutex

	count int

	m map[chainhash.Hash]*tbcd.BlockHeader
}

func (l *lowIQMap) Put(v *tbcd.BlockHeader) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if _, ok := l.m[v.Hash]; ok {
		return
	}

	if len(l.m) >= l.count {
		// evict entry
		for k := range l.m {
			delete(l.m, k)
			break
		}
	}

	l.m[v.Hash] = v
}

func (l *lowIQMap) Get(k *chainhash.Hash) (*tbcd.BlockHeader, bool) {
	l.mtx.RLock()
	defer l.mtx.RUnlock()

	bh, ok := l.m[*k]
	return bh, ok
}

func lowIQMapNew(count int) *lowIQMap {
	return &lowIQMap{
		count: count,
		m:     make(map[chainhash.Hash]*tbcd.BlockHeader, count),
	}
}
