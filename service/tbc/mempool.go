// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

var MaxTxVersion = int32(2) // XXX this should not be a global

type mempoolTx struct {
	id       chainhash.Hash             // TxID
	expires  time.Time                  // When mempool tx expires
	weight   int64                      // transaction weight
	size     int64                      // transaction virtual size
	inValue  int64                      // total txin value
	outValue int64                      // total txout value
	txins    map[wire.OutPoint]struct{} // txins in transaction
}

type mempool struct {
	mtx sync.RWMutex

	reaping bool                          // set when reaping the mempool
	txs     map[chainhash.Hash]*mempoolTx // when nil, tx has not been downloaded
	size    int64                         // total "tx virtual" memory used by mempool
}

// inMempool looks for a utxo inside the mempool transaction inputs to see if
// it is in the process of being spend.
// Must be called with mutex held.
func (m *mempool) inMempool(utxo tbcd.Utxo) bool {
	opp := wire.NewOutPoint(utxo.ChainHash(), utxo.OutputIndex())
	op := *opp
	for _, tx := range m.txs {
		// Skip tx that aren't fully in the mempool yet.
		if tx == nil {
			continue
		}
		if _, ok := tx.txins[op]; ok {
			// Found in txins.
			return true
		}
	}
	return false
}

func (m *mempool) FilterUtxos(ctx context.Context, utxos []tbcd.Utxo) ([]tbcd.Utxo, error) {
	log.Tracef("filterUtxos")
	defer log.Tracef("filterUtxos exit")

	filtered := make([]tbcd.Utxo, 0, len(utxos))

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	// This may be too slow and we may need a merged map because it is more
	// likely to never find the utxo than it is to find it. That said, the
	// setup and teardown would me much more expensive despite this code
	// being called infrequently.
	for k := range utxos {
		if !m.inMempool(utxos[k]) {
			// Not found in mempool inputs.
			filtered = append(filtered, utxos[k])
		}
	}
	return filtered, nil
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
			Type: wire.InvTypeWitnessTx,
			Hash: k,
		}); err != nil {
			// Only happens when asking max inventory, just bail
			// and count on the random map walk to eventually catch
			// up.
			break
		}
	}
	return getData, nil
}

func (m *mempool) txProcessed(txid chainhash.Hash) bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.txs[txid] != nil // return true when tx is not nil
}

func (m *mempool) TxInsert(ctx context.Context, mptx *mempoolTx) error {
	log.Tracef("txInsert")
	defer log.Tracef("txInsert exit")

	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.txs[mptx.id] == nil {
		m.txs[mptx.id] = mptx
		m.size += mptx.size
	}

	return nil
}

func (m *mempool) invTxsInsert(ctx context.Context, inv *wire.MsgInv) error {
	log.Tracef("invTxsInsert")
	defer log.Tracef("invTxsInsert exit")

	if len(inv.InvList) == 0 {
		return errors.New("empty inventory")
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	l := len(m.txs)
	for _, v := range inv.InvList {
		switch v.Type {
		case wire.InvTypeTx, wire.InvTypeWitnessTx:
			if _, ok := m.txs[v.Hash]; !ok {
				m.txs[v.Hash] = nil
			}
		}
	}

	// if the map length does not change, nothing was inserted.
	if len(m.txs) != l {
		return errors.New("insert inventory tx: already exists")
	}
	return nil
}

// commented to fix linter
func (m *mempool) txsRemove(ctx context.Context, txs []chainhash.Hash) {
	log.Tracef("txsRemove")
	defer log.Tracef("txsRemove exit")

	if len(txs) == 0 {
		return
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	var reaped int
	for k := range txs {
		if tx, ok := m.txs[txs[k]]; ok {
			// tx can be nil if it hasn't been downloaded yet.
			if tx != nil {
				m.size -= tx.size
			}
			log.Tracef("remove %v", txs[k])
			delete(m.txs, txs[k])
			reaped++
		}
	}

	// Reap expired tx'
	go m.reap()

	// if the map length does not change, nothing was deleted.
	if reaped != 0 {
		log.Infof("Mempool removed txs: %v", reaped)
	}
}

func (m *mempool) reap() {
	log.Tracef("reap")
	defer log.Tracef("reap exit")

	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.reaping {
		return
	}
	m.reaping = true
	for _, tx := range m.txs {
		if tx == nil {
			continue
		}
		if time.Now().After(tx.expires) {
			log.Debugf("tx expired %v", tx.id)
			m.size -= tx.size
			delete(m.txs, tx.id)
		}
	}
	m.reaping = false
}

func (m *mempool) stats(ctx context.Context) (int, int) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	// Approximate size of mempool; overhead is missing.
	return len(m.txs), int(m.size) + (len(m.txs) * chainhash.HashSize)
}

func NewMempoolTx(id chainhash.Hash, txins map[wire.OutPoint]struct{}) mempoolTx {
	return mempoolTx{id: id, txins: txins}
}

func (m *mempool) Dump(ctx context.Context) string {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return spew.Sdump(m.txs)
}

func MempoolNew() (*mempool, error) {
	return &mempool{
		txs: make(map[chainhash.Hash]*mempoolTx, 10000),
	}, nil
}
