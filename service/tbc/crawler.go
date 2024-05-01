// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/dustin/go-humanize"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

var (
	UtxoIndexHeightKey = []byte("utxoindexheight") // last indexed utxo height key
	TxIndexHeightKey   = []byte("txindexheight")   // last indexed tx height key
)

func logMemStats() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// Go memory statistics are hard to interpret but the following list is
	// an aproximation:
	//	Alloc is currently allocated memory
	// 	TotalAlloc is all memory allocated over time
	// 	Sys is basicaly a peak memory use
	log.Infof("Alloc = %v, TotalAlloc = %v, Sys = %v, NumGC = %v\n",
		humanize.IBytes(mem.Alloc),
		humanize.IBytes(mem.TotalAlloc),
		humanize.IBytes(mem.Sys),
		mem.NumGC)
}

func processUtxos(cp *chaincfg.Params, txs []*btcutil.Tx, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	for idx, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if idx == 0 {
				// Skip coinbase inputs
				continue
			}
			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if utxo, ok := utxos[op]; ok && !utxo.IsDelete() {
				log.Infof("deleting utxo %s value %d", hex.EncodeToString(utxo.ScriptHashSlice()), utxo.Value())
				delete(utxos, op)
				continue
			}
		}
		for outIndex, txOut := range tx.MsgTx().TxOut {
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}

			scriptHash := sha256.Sum256(txOut.PkScript)
			log.Infof("adding utxo %s value %d", hex.EncodeToString(scriptHash[:]), uint64(txOut.Value))

			utxos[tbcd.NewOutpoint(*tx.Hash(), uint32(outIndex))] = tbcd.NewCacheOutput(
				sha256.Sum256(txOut.PkScript),
				uint64(txOut.Value),
				uint32(outIndex))
		}
	}
	// log.Infof("%v", spew.Sdump(utxos))
	return nil
}

func (s *Server) fetchOP(ctx context.Context, w *sync.WaitGroup, op tbcd.Outpoint, utxos map[tbcd.Outpoint]tbcd.CacheOutput) {
	defer w.Done()

	pkScript, err := s.db.ScriptHashByOutpoint(ctx, op)
	if err != nil {
		// This happens when a transaction is created and spent in the
		// same block.
		// XXX this is probably too loud but log for investigation and
		// remove later.
		log.Debugf("db missing pkscript: %v", op)
		return
	}
	s.mtx.Lock()
	utxos[op] = tbcd.NewDeleteCacheOutput(*pkScript, op.TxIndex())
	s.mtx.Unlock()
}

func (s *Server) fixupCache(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	w := new(sync.WaitGroup)
	txs := b.Transactions()
	for idx, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if idx == 0 {
				// Skip coinbase inputs
				continue
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
			go s.fetchOP(ctx, w, op, utxos)
		}
	}

	w.Wait()

	return nil
}

func (s *Server) indexUtxosInBlocks(ctx context.Context, startHeight, maxHeight uint64, utxos map[tbcd.Outpoint]tbcd.CacheOutput) (int, error) {
	log.Tracef("indexUtxoBlocks")
	defer log.Tracef("indexUtxoBlocks exit")

	circuitBreaker := false
	if maxHeight != 0 {
		circuitBreaker = true
	}

	utxosPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	for height := startHeight; ; height++ {
		bhs, err := s.db.BlockHeadersByHeight(ctx, height)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				log.Infof("No more blocks at: %v", height)
				break
			}
			return 0, fmt.Errorf("block headers by height %v: %w", height, err)
		}
		eb, err := s.db.BlockByHash(ctx, bhs[0].Hash)
		if err != nil {
			return 0, fmt.Errorf("block by hash %v: %w", height, err)
		}
		b, err := btcutil.NewBlockFromBytes(eb.Block)
		if err != nil {
			ch, _ := chainhash.NewHash(bhs[0].Hash)
			return 0, fmt.Errorf("could not decode block %v %v: %v",
				height, ch, err)
		}

		// fixupCache is executed in parallel meaning that the utxos
		// map must be locked as it is being processed.
		err = s.fixupCache(ctx, b, utxos)
		if err != nil {
			return 0, fmt.Errorf("parse block %v: %w", height, err)
		}
		// At this point we can lockless since it is all single
		// threaded again.
		err = processUtxos(s.chainParams, b.Transactions(), utxos)
		if err != nil {
			return 0, fmt.Errorf("process utxos %v: %w", height, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(utxos) * 100 / s.cfg.MaxCachedTxs
		if height%10000 == 0 || cp > utxosPercentage || blocksProcessed == 1 {
			log.Infof("Utxo indexer height: %v utxo cache %v%%", height, cp)
		}
		if cp > utxosPercentage {
			// Set utxosMax to the largest utxo capacity seen
			s.cfg.MaxCachedTxs = max(len(utxos), s.cfg.MaxCachedTxs)
			// Flush
			break
		}

		// If set we may have to exit early
		if circuitBreaker {
			if height >= maxHeight-1 {
				break
			}
		}
	}

	return blocksProcessed, nil
}

func (s *Server) UtxoIndexer(ctx context.Context, height, count uint64) error {
	log.Tracef("UtxoIndexer")
	defer log.Tracef("UtxoIndexer exit")

	var maxHeight uint64
	circuitBreaker := false
	if count != 0 {
		circuitBreaker = true
		maxHeight = height + count
	}

	// Allocate here so that we don't waste space when not indexing.
	utxos := make(map[tbcd.Outpoint]tbcd.CacheOutput, s.cfg.MaxCachedTxs)
	defer clear(utxos)

	log.Infof("Start indexing UTxos at height %v count %v", height, count)
	for {
		start := time.Now()
		blocksProcessed, err := s.indexUtxosInBlocks(ctx, height, maxHeight, utxos)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		utxosCached := len(utxos)
		log.Infof("Utxo indexer blocks processed %v in %v utxos cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Now().Sub(start), utxosCached,
			s.cfg.MaxCachedTxs-utxosCached, utxosCached/blocksProcessed)

		start = time.Now()
		err = s.db.BlockUtxoUpdate(ctx, utxos)
		if err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory preassure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing utxos complete %v took %v",
			utxosCached, time.Now().Sub(start))

		height += uint64(blocksProcessed)

		// Record height in metadata
		var dbHeight [8]byte
		binary.BigEndian.PutUint64(dbHeight[:], height)
		err = s.db.MetadataPut(ctx, UtxoIndexHeightKey, dbHeight[:])
		if err != nil {
			return fmt.Errorf("metadata utxo height: %w", err)
		}

		// If set we may have to exit early
		if circuitBreaker {
			log.Infof("Indexed utxos to height: %v", height-1)
			if height >= maxHeight {
				return nil
			}
		}
	}
}

func processTxs(cp *chaincfg.Params, blockHash *chainhash.Hash, txs []*btcutil.Tx, txsCache map[tbcd.TxKey]*tbcd.TxValue) error {
	for _, tx := range txs {
		// cache txid <-> block
		txsCache[tbcd.NewTxMapping(tx.Hash(), blockHash)] = nil

		// cache spent transactions
		for txInIdx, txIn := range tx.MsgTx().TxIn {
			txk, txv := tbcd.NewTxSpent(
				blockHash,
				tx.Hash(),
				&txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index,
				uint32(txInIdx))
			txsCache[txk] = &txv
		}
	}
	return nil
}

func (s *Server) indexTxsInBlocks(ctx context.Context, startHeight, maxHeight uint64, txs map[tbcd.TxKey]*tbcd.TxValue) (int, error) {
	log.Tracef("indexTxsInBlocks")
	defer log.Tracef("indexTxsInBlocks exit")

	circuitBreaker := false
	if maxHeight != 0 {
		circuitBreaker = true
	}

	txsPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	for height := startHeight; ; height++ {
		bhs, err := s.db.BlockHeadersByHeight(ctx, height)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				log.Infof("No more blocks at: %v", height)
				break
			}
			return 0, fmt.Errorf("block headers by height %v: %w", height, err)
		}
		eb, err := s.db.BlockByHash(ctx, bhs[0].Hash)
		if err != nil {
			return 0, fmt.Errorf("block by hash %v: %w", height, err)
		}
		b, err := btcutil.NewBlockFromBytes(eb.Block)
		if err != nil {
			ch, _ := chainhash.NewHash(bhs[0].Hash)
			return 0, fmt.Errorf("could not decode block %v %v: %v",
				height, ch, err)
		}

		err = processTxs(s.chainParams, b.Hash(), b.Transactions(), txs)
		if err != nil {
			return 0, fmt.Errorf("process txs %v: %w", height, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(txs) * 100 / s.cfg.MaxCachedTxs
		if height%10000 == 0 || cp > txsPercentage || blocksProcessed == 1 {
			log.Infof("Tx indexer height: %v tx cache %v%%", height, cp)
		}
		if cp > txsPercentage {
			// Set txsMax to the largest tx capacity seen
			s.cfg.MaxCachedTxs = max(len(txs), s.cfg.MaxCachedTxs)
			// Flush
			break
		}

		// If set we may have to exit early
		if circuitBreaker {
			if height >= maxHeight-1 {
				break
			}
		}
	}

	return blocksProcessed, nil
}

// TxIndexer starts indexing at start height for count blocks. If count is 0
// the indexers will index to tip. It does NOT verify that the provided start
// height is correct. This is the version of the function that has no training
// wheels and is meant for internal use only.
func (s *Server) TxIndexer(ctx context.Context, height, count uint64) error {
	log.Tracef("TxIndexer")
	defer log.Tracef("TxIndexer exit")

	var maxHeight uint64
	circuitBreaker := false
	if count != 0 {
		circuitBreaker = true
		maxHeight = height + count
	}

	// Allocate here so that we don't waste space when not indexing.
	txs := make(map[tbcd.TxKey]*tbcd.TxValue, s.cfg.MaxCachedTxs)
	// log.Infof("max %v %v", s.cfg.MaxCachedTxs, s.cfg.MaxCachedTxs*(105))
	// return nil
	defer clear(txs)

	log.Infof("Start indexing transactions at height %v count %v", height, count)
	for {
		start := time.Now()
		blocksProcessed, err := s.indexTxsInBlocks(ctx, height, maxHeight, txs)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		txsCached := len(txs)
		log.Infof("Tx indexer blocks processed %v in %v transactions cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Now().Sub(start), txsCached,
			s.cfg.MaxCachedTxs-txsCached, txsCached/blocksProcessed)

		start = time.Now()
		err = s.db.BlockTxUpdate(ctx, txs)
		if err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory preassure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing txs complete %v took %v",
			txsCached, time.Now().Sub(start))

		height += uint64(blocksProcessed)

		// Record height in metadata
		var dbHeight [8]byte
		binary.BigEndian.PutUint64(dbHeight[:], height)
		err = s.db.MetadataPut(ctx, TxIndexHeightKey, dbHeight[:])
		if err != nil {
			return fmt.Errorf("metadata tx height: %w", err)
		}

		// If set we may have to exit early
		if circuitBreaker {
			log.Infof("Indexed transactions to height: %v", height-1)
			if height >= maxHeight {
				return nil
			}
		}
	}
}

// SyncIndexersToHeight tries to move the various indexers to the suplied
// height (inclusive).
func (s *Server) SyncIndexersToHeight(ctx context.Context, height uint64) error {
	log.Tracef("SyncIndexersToHeight")
	defer log.Tracef("SyncIndexersToHeight exit")

	// Outputs index
	uhBE, err := s.db.MetadataGet(ctx, UtxoIndexHeightKey)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("utxo indexer metadata get: %w", err)
		}
		uhBE = make([]byte, 8)
	}
	heightUtxo := binary.BigEndian.Uint64(uhBE)
	countUtxo := int64(height) - int64(heightUtxo)
	if countUtxo >= 0 {
		err := s.UtxoIndexer(ctx, heightUtxo, uint64(countUtxo+1))
		if err != nil {
			return fmt.Errorf("utxo indexer: %w", err)
		}
	}

	// Transactions index
	thBE, err := s.db.MetadataGet(ctx, TxIndexHeightKey)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("tx indexer metadata get: %w", err)
		}
		thBE = make([]byte, 8)
	}
	heightTx := binary.BigEndian.Uint64(thBE)
	countTx := int64(height) - int64(heightTx)
	if countTx >= 0 {
		err := s.TxIndexer(ctx, heightTx, uint64(countTx+1))
		if err != nil {
			return fmt.Errorf("tx indexer: %w", err)
		}
	}

	return nil
}
