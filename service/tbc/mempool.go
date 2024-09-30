// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
)

type mempool struct {
	mtx sync.RWMutex

	txs  map[chainhash.Hash][]byte // when nil, tx has not been downloaded
	size int                       // total memory used by mempool
}

func (m *mempool) getDataConstruct(ctx context.Context) (*wire.MsgGetData, error) {
	log.Tracef("getDataConstruct")
	defer log.Tracef("getDataConstruct exit")

	getData := wire.NewMsgGetData()

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for k, v := range m.txs {
		if v != nil {
			continue
		}
		if err := getData.AddInvVect(&wire.InvVect{
			Type: wire.InvTypeTx,
			Hash: k,
		}); err != nil {
			// only happens when asking max inventory
			return nil, fmt.Errorf("construct get data: %w", err)
		}
	}
	return getData, nil
}

func (m *mempool) txsInsert(ctx context.Context, msg *wire.MsgTx, raw []byte) error {
	log.Tracef("txsInsert")
	defer log.Tracef("txsInsert exit")

	m.mtx.Lock()
	defer m.mtx.Unlock()

	if tx := m.txs[msg.TxHash()]; tx == nil {
		m.txs[msg.TxHash()] = raw
		m.size += len(raw)
	}

	return nil
}

func (m *mempool) invTxsInsert(ctx context.Context, inv *wire.MsgInv) error {
	log.Tracef("invTxsInsert")
	defer log.Tracef("invTxsInsert exit")

	m.mtx.Lock()
	defer m.mtx.Unlock()

	l := len(m.txs)
	for _, v := range inv.InvList {
		switch v.Type {
		case wire.InvTypeTx:
			if _, ok := m.txs[v.Hash]; !ok {
				m.txs[v.Hash] = nil
			}
		}
	}

	if len(m.txs) != l {
		return errors.New("insert inventory tx: already exists")
	}
	return nil
}

func (m *mempool) txsRemove(ctx context.Context, txs []chainhash.Hash) error {
	log.Tracef("insertInvTxs")
	defer log.Tracef("insertInvTxs exit")

	m.mtx.Lock()
	defer m.mtx.Unlock()

	l := len(m.txs)
	for k := range txs {
		if tx, ok := m.txs[txs[k]]; ok {
			m.size -= len(tx)
			delete(m.txs, txs[k])
		}
	}
	if len(m.txs) != l {
		return errors.New("remove txs: nothing removed")
	}
	return nil
}

func (m *mempool) stats(ctx context.Context) (int, int) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	// Approximate size of mempool; map and cap overhead is missing.
	return len(m.txs), m.size + (len(m.txs) * chainhash.HashSize)
}

func (m *mempool) dump(ctx context.Context) string {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return spew.Sdump(m.txs)
}

func mempoolNew() (*mempool, error) {
	return &mempool{
		txs: make(map[chainhash.Hash][]byte, wire.MaxInvPerMsg),
	}, nil
}
