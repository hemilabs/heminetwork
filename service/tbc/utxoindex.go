// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type utxoIndexer struct {
	indexerCommon

	cache     *Cache[tbcd.Outpoint, tbcd.CacheOutput]
	fixupHook fixupCacheFunc
}

var (
	_ Indexer = (*utxoIndexer)(nil)
	_ indexer = (*utxoIndexer)(nil)
)

type fixupCacheFunc func(context.Context, *btcutil.Block, map[tbcd.Outpoint]tbcd.CacheOutput) error

func NewUtxoIndexer(chain *chaincfg.Params, cacheLen int, db tbcd.Database, f fixupCacheFunc) Indexer {
	uxi := &utxoIndexer{
		cache:     NewCache[tbcd.Outpoint, tbcd.CacheOutput](cacheLen),
		fixupHook: f,
	}
	uxi.indexerCommon = indexerCommon{
		name:    "utxo",
		enabled: true,
		geometry: geometryParams{
			db:    db,
			chain: chain,
		},
		p:     uxi,
		cache: uxi.cache,
	}
	return uxi
}

func (i *utxoIndexer) indexAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bh, err := i.geometry.db.BlockHeaderByUtxoIndex(ctx)
	return i.evaluateBlockHeaderIndex(bh, err)
}

func (i *utxoIndexer) process(ctx context.Context, direction int, block *btcutil.Block) error {
	if direction == -1 {
		return unprocessUtxos(ctx, i.geometry.db, block, i.cache.Map())
	}
	return processUtxos(block, i.cache.Map())
}

func (i *utxoIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash) error {
	return i.geometry.db.BlockUtxoUpdate(ctx, direction, i.cache.Map(), atHash)
}

func (i *utxoIndexer) fixupCacheHook(ctx context.Context, block *btcutil.Block) error {
	return i.fixupHook(ctx, block, i.cache.Map())
}

func processUtxos(block *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	txs := block.Transactions()
	for _, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}
			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if utxo, ok := utxos[op]; ok && !utxo.IsDelete() {
				delete(utxos, op)
				continue
			}
		}
		for outIndex, txOut := range tx.MsgTx().TxOut {
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}
			utxos[tbcd.NewOutpoint(*tx.Hash(), uint32(outIndex))] = tbcd.NewCacheOutput(
				tbcd.NewScriptHashFromScript(txOut.PkScript),
				uint64(txOut.Value),
				uint32(outIndex))
		}
	}
	return nil
}

func txOutFromOutPoint(ctx context.Context, db tbcd.Database, op tbcd.Outpoint) (*wire.TxOut, error) {
	txId := op.TxIdHash()
	txIndex := op.TxIndex()

	// Find block hashes
	blockHash, err := db.BlockHashByTxId(ctx, *txId)
	if err != nil {
		return nil, fmt.Errorf("block by txid: %w", err)
	}
	b, err := db.BlockByHash(ctx, *blockHash)
	if err != nil {
		return nil, fmt.Errorf("block by hash: %w", err)
	}
	for _, tx := range b.Transactions() {
		if !tx.Hash().IsEqual(txId) {
			continue
		}
		txOuts := tx.MsgTx().TxOut
		if len(txOuts) < int(txIndex) {
			return nil, fmt.Errorf("tx index invalid: %v", op)
		}
		return txOuts[txIndex], nil
	}

	return nil, fmt.Errorf("tx id not found: %v", op)
}

func unprocessUtxos(ctx context.Context, db tbcd.Database, block *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	txs := block.Transactions()
	// Walk backwards through the txs
	for idx := len(txs) - 1; idx >= 0; idx-- {
		tx := txs[idx]
		// TxIn get data from disk and insert into the cache as insert
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			prevTxOut, err := txOutFromOutPoint(ctx, db, op)
			if err != nil {
				return fmt.Errorf("script value: %w", err)
			}
			// XXX this should not happen. We are keeping it for
			// now to ensure it indeed does not happen. Remove in a
			// couple of years.
			if _, ok := utxos[op]; ok {
				return fmt.Errorf("impossible collision: %v", op)
			}
			utxos[op] = tbcd.NewCacheOutput(tbcd.NewScriptHashFromScript(prevTxOut.PkScript),
				uint64(prevTxOut.Value), txIn.PreviousOutPoint.Index)
		}

		// TxOut if those are in the cache delete from cache; if they
		// are not in the cache insert "delete from disk command" into
		// cache.
		for outIndex, txOut := range tx.MsgTx().TxOut {
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}

			op := tbcd.NewOutpoint(*tx.Hash(), uint32(outIndex))
			if _, ok := utxos[op]; ok {
				delete(utxos, op)
			} else {
				utxos[op] = tbcd.NewDeleteCacheOutput(tbcd.NewScriptHashFromScript(txOut.PkScript),
					op.TxIndex())
			}
		}
	}

	return nil
}

func (s *Server) fetchOPParallel(ctx context.Context, c chan struct{}, w *sync.WaitGroup, op tbcd.Outpoint, utxos map[tbcd.Outpoint]tbcd.CacheOutput) {
	defer w.Done()
	if c != nil {
		defer func() {
			select {
			case <-ctx.Done():
			case c <- struct{}{}:
			}
		}()
	}

	sh, err := s.g.db.ScriptHashByOutpoint(ctx, op)
	if err != nil {
		// This happens when a transaction is created and spent in the
		// same block.
		// XXX this is probably too loud but log for investigation and
		// remove later.
		log.Debugf("db missing pkscript: %v", op)
		return
	}
	s.mtx.Lock()
	utxos[op] = tbcd.NewDeleteCacheOutput(*sh, op.TxIndex())
	s.mtx.Unlock()
}

func (s *Server) fixupCacheParallel(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	w := new(sync.WaitGroup)
	for _, tx := range b.Transactions() {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			s.mtx.Lock()
			if _, ok := utxos[op]; ok {
				s.mtx.Unlock()
				continue
			}
			s.mtx.Unlock()

			// utxo not found, retrieve pkscript from database.
			w.Add(1)
			go s.fetchOPParallel(ctx, nil, w, op, utxos)
		}
	}

	w.Wait()

	return nil
}

func (s *Server) fixupCacheSerial(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	for _, tx := range b.Transactions() {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if _, ok := utxos[op]; ok {
				continue
			}

			sh, err := s.g.db.ScriptHashByOutpoint(ctx, op)
			if err != nil {
				// This happens when a transaction is created
				// and spent in the same block.
				continue
			}
			// utxo not found, retrieve pkscript from database.
			utxos[op] = tbcd.NewDeleteCacheOutput(*sh, op.TxIndex())
		}
	}

	return nil
}

func (s *Server) fixupCacheBatched(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	ops := make([]*tbcd.Outpoint, 0, 16384)
	defer clear(ops)
	for _, tx := range b.Transactions() {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if _, ok := utxos[op]; ok {
				continue
			}

			ops = append(ops, &op)
		}
	}
	found := func(op tbcd.Outpoint, sh tbcd.ScriptHash) error {
		utxos[op] = tbcd.NewDeleteCacheOutput(sh, op.TxIndex())
		return nil
	}
	return s.g.db.ScriptHashesByOutpoint(ctx, ops, found)
}

func (s *Server) fixupCacheChannel(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	// prime slots
	slots := 128
	c := make(chan struct{}, slots)
	defer close(c)
	for i := 0; i < slots; i++ {
		select {
		case <-ctx.Done():
			return nil
		case c <- struct{}{}:
		default:
			return errors.New("shouldn't happen")
		}
	}

	w := new(sync.WaitGroup)
	for _, tx := range b.Transactions() {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			s.mtx.Lock()
			if _, ok := utxos[op]; ok {
				s.mtx.Unlock()
				continue
			}
			s.mtx.Unlock()

			// get slot or wait
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-c:
			}

			// utxo not found, retrieve pkscript from database.
			w.Add(1)
			go s.fetchOPParallel(ctx, c, w, op, utxos)
		}
	}
	w.Wait()

	cl := len(c)
	if cl != slots {
		return fmt.Errorf("channel not empty: %v", cl)
	}

	return nil
}
