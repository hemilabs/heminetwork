// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

var MaxTxVersion = int32(2) // XXX this should not be a global

type MempoolTx struct {
	id       chainhash.Hash             // TxID
	expires  time.Time                  // When mempool tx expires
	weight   int64                      // transaction weight
	size     int64                      // transaction virtual size
	inValue  int64                      // total txin value
	outValue int64                      // total txout value
	txins    map[wire.OutPoint]struct{} // txins in transaction
}

func NewMempoolTx(id chainhash.Hash, txins map[wire.OutPoint]struct{}) MempoolTx {
	return MempoolTx{id: id, txins: txins}
}

type Mempool struct {
	mtx sync.RWMutex

	reaping bool                          // set when reaping the mempool
	txs     map[chainhash.Hash]*MempoolTx // when nil, tx has not been downloaded
	size    int64                         // total "tx virtual" memory used by mempool
}

func NewMempool() (*Mempool, error) {
	return &Mempool{
		txs: make(map[chainhash.Hash]*MempoolTx, 10000),
	}, nil
}

// inMempool looks for a utxo inside the mempool transaction inputs to see if
// it is in the process of being spent.
// Must be called with mutex held.
func (m *Mempool) inMempool(utxo tbcd.Utxo) bool {
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

func (m *Mempool) FilterUtxos(ctx context.Context, utxos []tbcd.Utxo) ([]tbcd.Utxo, error) {
	log.Tracef("filterUtxos")
	defer log.Tracef("filterUtxos exit")

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	// This may be too slow, and we may need a merged map because it is more
	// likely to never find the utxo than it is to find it. That said, the
	// setup and teardown would be much more expensive despite this code
	// being called infrequently.
	return slices.DeleteFunc(utxos[:], m.inMempool), nil
}

func (m *Mempool) getDataConstruct(ctx context.Context) (*wire.MsgGetData, error) {
	log.Tracef("getDataConstruct")
	defer log.Tracef("getDataConstruct exit")

	getData := wire.NewMsgGetData()

	m.mtx.RLock()
	defer m.mtx.RUnlock()

	for k, v := range m.txs {
		if v != nil {
			continue
		}
		err := getData.AddInvVect(&wire.InvVect{
			Type: wire.InvTypeWitnessTx,
			Hash: k,
		})
		if err != nil {
			// Only happens when asking max inventory, just bail
			// and count on the random map walk to eventually catch
			// up.
			break
		}
	}
	return getData, nil
}

func (m *Mempool) txProcessed(txid chainhash.Hash) bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.txs[txid] != nil // return true when tx is not nil
}

func (m *Mempool) TxInsert(ctx context.Context, mptx *MempoolTx) error {
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

func (m *Mempool) invTxsInsert(ctx context.Context, inv *wire.MsgInv) error {
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

func (m *Mempool) txsRemove(ctx context.Context, txs []chainhash.Hash) {
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

	// Reap expired tx
	go m.reap()

	// if the map length does not change, nothing was deleted.
	if reaped != 0 {
		log.Infof("Mempool removed txs: %v", reaped)
	}
}

func (m *Mempool) reap() {
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

func (m *Mempool) stats(ctx context.Context) (int, int) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	// Approximate size of mempool; overhead is missing.
	return len(m.txs), int(m.size) + (len(m.txs) * chainhash.HashSize)
}

func (m *Mempool) Dump(ctx context.Context) string {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return spew.Sdump(m.txs)
}
