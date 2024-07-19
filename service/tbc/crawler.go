// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"
	"github.com/dustin/go-humanize"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

var (
	UtxoIndexHashKey = []byte("utxoindexhash") // last indexed utxo hash
	TxIndexHashKey   = []byte("txindexhash")   // last indexed tx hash

	ErrNotLinear = errors.New("not linear") // not a valid chain
)

type HashHeight struct {
	Hash   chainhash.Hash
	Height uint64
}

func (h HashHeight) String() string {
	return fmt.Sprintf("%v @ %v", h.Hash, h.Height)
}

func (s *Server) mdHashHeight(ctx context.Context, key []byte) (*HashHeight, error) {
	log.Tracef("mdHashHeight %v ", spew.Sdump(key))

	hh, err := s.db.MetadataGet(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("metadata get: %w", err)
	}
	ch, err := chainhash.NewHash(hh)
	if err != nil {
		return nil, fmt.Errorf("metadata hash: %w", err)
	}
	bh, err := s.db.BlockHeaderByHash(ctx, ch[:])
	if err != nil {
		return nil, fmt.Errorf("metadata block header: %w", err)
	}
	return &HashHeight{Hash: *ch, Height: bh.Height}, nil
}

// UtxoIndexHash returns the last hash that has been been UTxO indexed.
func (s *Server) UtxoIndexHash(ctx context.Context) (*HashHeight, error) {
	return s.mdHashHeight(ctx, UtxoIndexHashKey)
}

// TxIndexHash returns the last hash that has been been Tx indexed.
func (s *Server) TxIndexHash(ctx context.Context) (*HashHeight, error) {
	return s.mdHashHeight(ctx, TxIndexHashKey)
}

// findCanonicalHash determines which hash is on the canonical chain.by walking
// back the chain from the provided end point. It returns the index in bhs of
// the correct hash. On failure it returns -1 DELIBERATELY to crash the caller
// if error is not checked.
func (s *Server) findCanonicalHash(ctx context.Context, endHash *chainhash.Hash, bhs []tbcd.BlockHeader) (int, error) {
	switch len(bhs) {
	case 1:
		return 0, nil // most common fast path
	case 0:
		return -1, errors.New("no blockheaders provided")
	}

	// XXX make sure endHash has higher cumulative difficulty

	// When this happens we have to walk back from endHash to find the
	// connecting block. There is no shortcut possible without hitting edge
	// conditions.
	for k, v := range bhs {
		h := endHash
		for {
			bh, err := s.db.BlockHeaderByHash(ctx, h[:])
			if err != nil {
				return -1, fmt.Errorf("block header by hash: %w", err)
			}
			if h.IsEqual(v.BlockHash()) {
				return k, nil
			}
			if h.IsEqual(s.chainParams.GenesisHash) {
				break
			}
			h = bh.ParentHash()
		}
	}

	return -1, errors.New("path not found")
}

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
	for _, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}
			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if utxo, ok := utxos[op]; ok && !utxo.IsDelete() {
				// log.Infof("deleting utxo %s value %d", hex.EncodeToString(utxo.ScriptHashSlice()), utxo.Value())
				delete(utxos, op)
				continue
			}
		}
		for outIndex, txOut := range tx.MsgTx().TxOut {
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}

			// scriptHash := sha256.Sum256(txOut.PkScript)
			// log.Infof("adding utxo to script hash %s value %d", hex.EncodeToString(scriptHash[:]), uint64(txOut.Value))

			utxos[tbcd.NewOutpoint(*tx.Hash(), uint32(outIndex))] = tbcd.NewCacheOutput(
				sha256.Sum256(txOut.PkScript),
				uint64(txOut.Value),
				uint32(outIndex))
		}
	}
	// log.Infof("%v", spew.Sdump(utxos))
	return nil
}

func (s *Server) scriptValue(ctx context.Context, op tbcd.Outpoint) ([]byte, int64, error) {
	txId := op.TxId()
	txIndex := op.TxIndex()
	opHash, err := chainhash.NewHash(txId)
	if err != nil {
		return nil, 0, fmt.Errorf("new hash: %w", err)
	}

	// Find block hashes
	blockHashes, err := s.db.BlocksByTxId(ctx, txId[:])
	if err != nil {
		return nil, 0, fmt.Errorf("blocks by txid: %w", err)
	}

	// Note that we may have more than one block hash however since the
	// TxID is generated from the actual Tx the script hash and value
	// should be identical, and thus we can return the values from the first
	// block found.
	if len(blockHashes) == 0 {
		return nil, 0, errors.New("script value: no block hashes")
	}

	blk, err := s.db.BlockByHash(ctx, blockHashes[0][:])
	if err != nil {
		return nil, 0, fmt.Errorf("block by hash: %w", err)
	}

	b, err := btcutil.NewBlockFromBytes(blk.Block)
	if err != nil {
		return nil, 0, fmt.Errorf("new block: %w", err)
	}

	for _, tx := range b.Transactions() {
		if !tx.Hash().IsEqual(opHash) {
			continue
		}

		txOuts := tx.MsgTx().TxOut
		if len(txOuts) < int(txIndex) {
			return nil, 0, fmt.Errorf("tx index invalid: %v", op)
		}
		txOut := txOuts[txIndex]
		return txOut.PkScript, txOut.Value, nil
	}

	return nil, 0, fmt.Errorf("tx id not found: %v", op)
}

func (s *Server) unprocessUtxos(ctx context.Context, cp *chaincfg.Params, txs []*btcutil.Tx, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
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
			pkScript, value, err := s.scriptValue(ctx, op)
			if err != nil {
				return fmt.Errorf("script value: %v", err)
			}

			log.Infof("------ %v  %v", op, btcutil.Amount(value))
			if _, ok := utxos[op]; ok {
				return errors.New("collision")
			}
			utxos[op] = tbcd.NewCacheOutput(sha256.Sum256(pkScript),
				uint64(value), txIn.PreviousOutPoint.Index)
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
				log.Infof("------delete %v  %v", op, btcutil.Amount(txOut.Value))
				continue
			}

			log.Infof("------DELETE %v  %v", op, btcutil.Amount(txOut.Value))
			utxos[op] = tbcd.NewDeleteCacheOutput(sha256.Sum256(txOut.PkScript),
				op.TxIndex())
		}
	}

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
	var w sync.WaitGroup

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
			go s.fetchOP(ctx, &w, op, utxos)
		}
	}

	w.Wait()
	return nil
}

// indexUtxosInBlocks indexes utxos from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it has processed.
func (s *Server) indexUtxosInBlocks(ctx context.Context, endHash *chainhash.Hash, utxos map[tbcd.Outpoint]tbcd.CacheOutput) (int, *HashHeight, error) {
	log.Tracef("indexUtxoBlocks")
	defer log.Tracef("indexUtxoBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return 0, last, fmt.Errorf("utxo index hash: %w", err)
		}
		utxoHH = &HashHeight{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
		}
	}

	utxosPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	hh := utxoHH
	for {
		log.Debugf("indexing utxos: %v", hh)

		hash := hh.Hash
		bh, err := s.db.BlockHeaderByHash(ctx, hash[:])
		if err != nil {
			return 0, last, fmt.Errorf("block header %v: %w", hash, err)
		}

		// Index block
		eb, err := s.db.BlockByHash(ctx, bh.Hash)
		if err != nil {
			return 0, last, fmt.Errorf("block by hash %v: %w", bh, err)
		}
		b, err := btcutil.NewBlockFromBytes(eb.Block)
		if err != nil {
			return 0, last, fmt.Errorf("could not decode block %v: %w", hh, err)
		}

		// fixupCache is executed in parallel meaning that the utxos
		// map must be locked as it is being processed.
		if err = s.fixupCache(ctx, b, utxos); err != nil {
			return 0, last, fmt.Errorf("parse block %v: %w", hh, err)
		}
		// At this point we can lockless since it is all single
		// threaded again.
		// log.Infof("processing utxo at height %d", height)
		err = processUtxos(s.chainParams, b.Transactions(), utxos)
		if err != nil {
			return 0, last, fmt.Errorf("process utxos %v: %w", hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(utxos) * 100 / s.cfg.MaxCachedTxs
		if bh.Height%10000 == 0 || cp > utxosPercentage || blocksProcessed == 1 {
			log.Infof("Utxo indexer: %v utxo cache %v%%", hh, cp)
		}
		if cp > utxosPercentage {
			// Set utxosMax to the largest utxo capacity seen
			s.cfg.MaxCachedTxs = max(len(utxos), s.cfg.MaxCachedTxs)
			last = hh
			// Flush
			break
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		// Move to next block
		height := bh.Height + 1
		bhs, err := s.db.BlockHeadersByHeight(ctx, height)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				log.Infof("No more blocks at: %v", height)
				break
			}
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}
		index, err := s.findCanonicalHash(ctx, endHash, bhs)
		if err != nil {
			return 0, last, fmt.Errorf("could not determine canonical path %v: %w",
				height, err)
		}
		// Verify it connects to parent
		if !hash.IsEqual(bhs[index].ParentHash()) {
			return 0, last, fmt.Errorf("%v does not connect to: %v",
				bhs[index], hash)
		}
		hh.Hash = *bhs[index].BlockHash()
		hh.Height = bhs[index].Height
	}

	return blocksProcessed, last, nil
}

// unindexUtxosInBlocks unindexes utxos from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it has processedd.
func (s *Server) unindexUtxosInBlocks(ctx context.Context, endHash *chainhash.Hash, utxos map[tbcd.Outpoint]tbcd.CacheOutput) (int, *HashHeight, error) {
	log.Tracef("unindexUtxoBlocks")
	defer log.Tracef("unindexUtxoBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return 0, last, fmt.Errorf("utxo index hash: %w", err)
		}
		utxoHH = &HashHeight{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
		}
	}

	utxosPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	hh := utxoHH
	for {
		log.Debugf("unindexing utxos: %v", hh)
		log.Infof("unindexing utxos: %v", hh)

		hash := hh.Hash
		bh, err := s.db.BlockHeaderByHash(ctx, hash[:])
		if err != nil {
			return 0, last, fmt.Errorf("block header %v: %w", hash, err)
		}

		// Index block
		eb, err := s.db.BlockByHash(ctx, bh.Hash)
		if err != nil {
			return 0, last, fmt.Errorf("block by hash %v: %w", bh, err)
		}
		b, err := btcutil.NewBlockFromBytes(eb.Block)
		if err != nil {
			return 0, last, fmt.Errorf("could not decode block %v: %w", hh, err)
		}

		err = s.unprocessUtxos(ctx, s.chainParams, b.Transactions(), utxos)
		if err != nil {
			return 0, last, fmt.Errorf("process utxos %v: %w", hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(utxos) * 100 / s.cfg.MaxCachedTxs
		if bh.Height%10000 == 0 || cp > utxosPercentage || blocksProcessed == 1 {
			log.Infof("UTxo unindexer: %v utxo cache %v%%", hh, cp)
		}
		if cp > utxosPercentage {
			// Set txsMax to the largest tx capacity seen
			s.cfg.MaxCachedTxs = max(len(utxos), s.cfg.MaxCachedTxs)
			last = hh
			// Flush
			break
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		// Move to previous block
		height := bh.Height - 1
		pbh, err := s.db.BlockHeaderByHash(ctx, bh.ParentHash()[:])
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				log.Infof("No more blocks at: %v", height)
				break
			}
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}
		hh.Hash = *pbh.BlockHash()
		hh.Height = pbh.Height
	}

	return blocksProcessed, last, nil
}

func (s *Server) UtxoIndexerUnwind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("UtxoIndexerUnwind")
	defer log.Tracef("UtxoIndexerUnwind exit")

	// XXX dedup with TxIndexedWind; it's basically the same code but with the direction, start anf endhas flipped

	// Allocate here so that we don't waste space when not indexing.
	utxos := make(map[tbcd.Outpoint]tbcd.CacheOutput, s.cfg.MaxCachedTxs)
	defer clear(utxos)

	log.Infof("Start unwinding UTxos at hash %v height %v", startBH, startBH.Height)
	log.Infof("End unwinding UTxos at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.unindexUtxosInBlocks(ctx, endHash, utxos)
		if err != nil {
			return fmt.Errorf("unindex utxos in blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		utxosCached := len(utxos)
		log.Infof("UTxo unwinder blocks processed %v in %v transactions cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Since(start), utxosCached,
			s.cfg.MaxCachedTxs-utxosCached, utxosCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockUtxoUpdate(ctx, -1, utxos); err != nil {
			return fmt.Errorf("block utxo update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory usage.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing unwind utxos complete %v took %v",
			utxosCached, time.Since(start))

		// Record height in metadata
		err = s.db.MetadataPut(ctx, UtxoIndexHashKey, last.Hash[:])
		if err != nil {
			return fmt.Errorf("metadata utxo hash: %w", err)
		}

		if endHash.IsEqual(&last.Hash) {
			break
		}

	}
	return nil
}

func (s *Server) UtxoIndexerWind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("UtxoIndexerWind")
	defer log.Tracef("UtxoIndexerWind exit")

	// Allocate here so that we don't waste space when not indexing.
	utxos := make(map[tbcd.Outpoint]tbcd.CacheOutput, s.cfg.MaxCachedTxs)
	defer clear(utxos)

	log.Infof("Start indexing UTxos at hash %v height %v", startBH, startBH.Height)
	log.Infof("End indexing UTxos at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.indexUtxosInBlocks(ctx, endHash, utxos)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		utxosCached := len(utxos)
		log.Infof("Utxo indexer blocks processed %v in %v utxos cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Since(start), utxosCached,
			s.cfg.MaxCachedTxs-utxosCached, utxosCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockUtxoUpdate(ctx, 1, utxos); err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory usage.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing utxos complete %v took %v",
			utxosCached, time.Since(start))

		// Record height in metadata
		err = s.db.MetadataPut(ctx, UtxoIndexHashKey, last.Hash[:])
		if err != nil {
			return fmt.Errorf("metadata utxo hash: %w", err)
		}

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}

	return nil
}

func (s *Server) UtxoIndexer(ctx context.Context, endHash *chainhash.Hash) error {
	log.Tracef("UtxoIndexer")
	defer log.Tracef("UtxoIndexer exit")

	// XXX this is basically duplicate from UtxoIndexIsLinear

	// Verify exit condition hash
	if endHash == nil {
		return errors.New("must provide an end hash")
	}
	endBH, err := s.db.BlockHeaderByHash(ctx, endHash[:])
	if err != nil {
		return fmt.Errorf("blockheader hash: %w", err)
	}

	// Verify start point is not after the end point
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("utxo indexer : %w", err)
		}
		utxoHH = &HashHeight{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
		}
	}

	// XXX make sure there is no gap between start and end or vice versa.
	startBH, err := s.db.BlockHeaderByHash(ctx, utxoHH.Hash[:])
	if err != nil {
		return fmt.Errorf("blockheader hash: %w", err)
	}
	direction, err := s.UtxoIndexIsLinear(ctx, endHash)
	if err != nil {
		return fmt.Errorf("TxIndexIsLinear: %w", err)
	}
	switch direction {
	case 1:
		return s.UtxoIndexerWind(ctx, startBH, endBH)
	case -1:
		return s.UtxoIndexerUnwind(ctx, startBH, endBH)
	case 0:
		// XXX dedup UtxoIndexIsLinear with the above code so that it isn't so awkward.
		return nil // because we call TxIndexIsLinear we know it's the same block
	}
	return errors.New("wtf") // XXX fix code so thatw e can't get here
}

func processTxs(cp *chaincfg.Params, blockHash *chainhash.Hash, txs []*btcutil.Tx, txsCache map[tbcd.TxKey]*tbcd.TxValue) error {
	for _, tx := range txs {
		// cache txid <-> block
		txsCache[tbcd.NewTxMapping(tx.Hash(), blockHash)] = nil

		// Don't keep track of spent coinbase inputs
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

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

// indexTxsInBlocks indexes txs from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it has processedd.
func (s *Server) indexTxsInBlocks(ctx context.Context, endHash *chainhash.Hash, txs map[tbcd.TxKey]*tbcd.TxValue) (int, *HashHeight, error) {
	log.Tracef("indexTxsInBlocks")
	defer log.Tracef("indexTxsInBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return 0, last, fmt.Errorf("tx index hash: %w", err)
		}
		txHH = &HashHeight{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
		}
	}

	txsPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	hh := txHH
	for {
		log.Debugf("indexing txs: %v", hh)

		hash := hh.Hash
		bh, err := s.db.BlockHeaderByHash(ctx, hash[:])
		if err != nil {
			return 0, last, fmt.Errorf("block header %v: %w", hash, err)
		}

		// Index block
		eb, err := s.db.BlockByHash(ctx, bh.Hash)
		if err != nil {
			return 0, last, fmt.Errorf("block by hash %v: %w", bh, err)
		}
		b, err := btcutil.NewBlockFromBytes(eb.Block)
		if err != nil {
			return 0, last, fmt.Errorf("could not decode block %v: %w", hh, err)
		}

		err = processTxs(s.chainParams, b.Hash(), b.Transactions(), txs)
		if err != nil {
			return 0, last, fmt.Errorf("process txs %v: %w", hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(txs) * 100 / s.cfg.MaxCachedTxs
		if bh.Height%10000 == 0 || cp > txsPercentage || blocksProcessed == 1 {
			log.Infof("Tx indexer: %v tx cache %v%%", hh, cp)
		}
		if cp > txsPercentage {
			// Set txsMax to the largest tx capacity seen
			s.cfg.MaxCachedTxs = max(len(txs), s.cfg.MaxCachedTxs)
			last = hh
			// Flush
			break
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		// Move to next block
		height := bh.Height + 1
		bhs, err := s.db.BlockHeadersByHeight(ctx, height)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				log.Infof("No more blocks at: %v", height)
				break
			}
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}

		index, err := s.findCanonicalHash(ctx, endHash, bhs)
		if err != nil {
			return 0, last, fmt.Errorf("could not determine canonical path %v: %w",
				height, err)
		}

		// Verify it connects to parent
		if !hash.IsEqual(bhs[index].ParentHash()) {
			return 0, last, fmt.Errorf("%v does not connect to: %v",
				bhs[index], hash)
		}

		hh.Hash = *bhs[index].BlockHash()
		hh.Height = bhs[index].Height
	}

	return blocksProcessed, last, nil
}

// unindexTxsInBlocks indexes txs from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it has processedd.
func (s *Server) unindexTxsInBlocks(ctx context.Context, endHash *chainhash.Hash, txs map[tbcd.TxKey]*tbcd.TxValue) (int, *HashHeight, error) {
	log.Tracef("unindexTxsInBlocks")
	defer log.Tracef("unindexTxsInBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return 0, last, fmt.Errorf("tx index hash: %w", err)
		}
		txHH = &HashHeight{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
		}
	}

	txsPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	hh := txHH
	for {
		log.Debugf("unindexing txs: %v", hh)
		log.Infof("unindexing txs: %v", hh)

		hash := hh.Hash
		bh, err := s.db.BlockHeaderByHash(ctx, hash[:])
		if err != nil {
			return 0, last, fmt.Errorf("block header %v: %w", hash, err)
		}

		// Index block
		eb, err := s.db.BlockByHash(ctx, bh.Hash)
		if err != nil {
			return 0, last, fmt.Errorf("block by hash %v: %w", bh, err)
		}
		b, err := btcutil.NewBlockFromBytes(eb.Block)
		if err != nil {
			return 0, last, fmt.Errorf("could not decode block %v: %w", hh, err)
		}

		err = processTxs(s.chainParams, b.Hash(), b.Transactions(), txs)
		if err != nil {
			return 0, last, fmt.Errorf("process txs %v: %w", hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(txs) * 100 / s.cfg.MaxCachedTxs
		if bh.Height%10000 == 0 || cp > txsPercentage || blocksProcessed == 1 {
			log.Infof("Tx unindexer: %v tx cache %v%%", hh, cp)
		}
		if cp > txsPercentage {
			// Set txsMax to the largest tx capacity seen
			s.cfg.MaxCachedTxs = max(len(txs), s.cfg.MaxCachedTxs)
			last = hh
			// Flush
			break
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		// Move to previous block
		height := bh.Height - 1
		pbh, err := s.db.BlockHeaderByHash(ctx, bh.ParentHash()[:])
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				log.Infof("No more blocks at: %v", height)
				break
			}
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}
		hh.Hash = *pbh.BlockHash()
		hh.Height = pbh.Height
	}

	return blocksProcessed, last, nil
}

func (s *Server) TxIndexerUnwind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("TxIndexerUnwind")
	defer log.Tracef("TxIndexerUnwind exit")

	// XXX dedup with TxIndexedWind; it's basically the same code but with the direction, start anf endhas flipped

	// Allocate here so that we don't waste space when not indexing.
	txs := make(map[tbcd.TxKey]*tbcd.TxValue, s.cfg.MaxCachedTxs)
	defer clear(txs)

	log.Infof("Start unwinding Txs at hash %v height %v", startBH, startBH.Height)
	log.Infof("End unwinding Txs at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.unindexTxsInBlocks(ctx, endHash, txs)
		if err != nil {
			return fmt.Errorf("unindex txs in blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		txsCached := len(txs)
		log.Infof("Tx unwinder blocks processed %v in %v transactions cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Since(start), txsCached,
			s.cfg.MaxCachedTxs-txsCached, txsCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockTxUpdate(ctx, -1, txs); err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}

		// leveldb does all kinds of allocations, force GC to lower
		// memory usage.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing unwind txs complete %v took %v",
			txsCached, time.Since(start))

		// Record height in metadata
		err = s.db.MetadataPut(ctx, TxIndexHashKey, last.Hash[:])
		if err != nil {
			return fmt.Errorf("metadata tx hash: %w", err)
		}

		if endHash.IsEqual(&last.Hash) {
			break
		}

	}
	return nil
}

func (s *Server) TxIndexerWind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("TxIndexerWind")
	defer log.Tracef("TxIndexerWind exit")

	// Allocate here so that we don't waste space when not indexing.
	txs := make(map[tbcd.TxKey]*tbcd.TxValue, s.cfg.MaxCachedTxs)
	defer clear(txs)

	log.Infof("Start indexing Txs at hash %v height %v", startBH, startBH.Height)
	log.Infof("End indexing Txs at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.indexTxsInBlocks(ctx, endHash, txs)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		txsCached := len(txs)
		log.Infof("Tx indexer blocks processed %v in %v transactions cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Since(start), txsCached,
			s.cfg.MaxCachedTxs-txsCached, txsCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockTxUpdate(ctx, 1, txs); err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}

		// leveldb does all kinds of allocations, force GC to lower
		// memory usage.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing txs complete %v took %v",
			txsCached, time.Since(start))

		// Record height in metadata
		err = s.db.MetadataPut(ctx, TxIndexHashKey, last.Hash[:])
		if err != nil {
			return fmt.Errorf("metadata tx hash: %w", err)
		}

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}

	return nil
}

func (s *Server) TxIndexer(ctx context.Context, endHash *chainhash.Hash) error {
	log.Tracef("TxIndexer")
	defer log.Tracef("TxIndexer exit")

	// XXX this is basically duplicate from TxIndexIsLinear

	// Verify exit condition hash
	if endHash == nil {
		return errors.New("must provide an end hash")
	}
	endBH, err := s.db.BlockHeaderByHash(ctx, endHash[:])
	if err != nil {
		return fmt.Errorf("blockheader hash: %w", err)
	}

	// Verify start point is not after the end point
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("tx indexer : %w", err)
		}
		txHH = &HashHeight{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
		}
	}

	// XXX make sure there is no gap between start and end or vice versa.
	startBH, err := s.db.BlockHeaderByHash(ctx, txHH.Hash[:])
	if err != nil {
		return fmt.Errorf("blockheader hash: %w", err)
	}
	direction, err := s.TxIndexIsLinear(ctx, endHash)
	if err != nil {
		return fmt.Errorf("TxIndexIsLinear: %w", err)
	}
	switch direction {
	case 1:
		return s.TxIndexerWind(ctx, startBH, endBH)
	case -1:
		return s.TxIndexerUnwind(ctx, startBH, endBH)
	case 0:
		// XXX dedup TxIndexIsLinear with the above code so that it isn't so awkward.
		return nil // because we call TxIndexIsLinear we know it's the same block
	}
	return errors.New("wtf") // XXX fix code so thatw e can't get here
}

func (s *Server) UtxoIndexIsLinear(ctx context.Context, endHash *chainhash.Hash) (int, error) {
	log.Tracef("UtxoIndexIsLinear")
	defer log.Tracef("UtxoIndexIsLinear exit")

	// Verify start point is not after the end point
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return 0, fmt.Errorf("tx indexer : %w", err)
		}
		utxoHH = &HashHeight{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
		}
	}

	return s.IndexIsLinear(ctx, &utxoHH.Hash, endHash)
}

func (s *Server) TxIndexIsLinear(ctx context.Context, endHash *chainhash.Hash) (int, error) {
	log.Tracef("TxIndexIsLinear")
	defer log.Tracef("TxIndexIsLinear exit")

	// Verify start point is not after the end point
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return 0, fmt.Errorf("tx indexer : %w", err)
		}
		txHH = &HashHeight{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
		}
	}

	return s.IndexIsLinear(ctx, &txHH.Hash, endHash)
}

func (s *Server) IndexIsLinear(ctx context.Context, startHash, endHash *chainhash.Hash) (int, error) {
	log.Tracef("IndexIsLinear")
	defer log.Tracef("IndexIsLinear exit")

	// Verify exit condition hash
	if endHash == nil {
		return 0, errors.New("must provide an end hash")
	}
	endBH, err := s.db.BlockHeaderByHash(ctx, endHash[:])
	if err != nil {
		return 0, fmt.Errorf("blockheader hash: %w", err)
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := s.db.BlockHeaderByHash(ctx, startHash[:])
	if err != nil {
		return 0, fmt.Errorf("blockheader hash: %w", err)
	}
	direction := endBH.Difficulty.Cmp(&startBH.Difficulty)
	log.Infof("startBH %v %v", startBH, startBH.Difficulty)
	log.Infof("endBH %v %v", endBH, endBH.Difficulty)
	log.Infof("direction %v", direction)
	if startBH.BlockHash().IsEqual(endBH.BlockHash()) {
		return 0, nil
	}

	// Expensive linear test, this needs some performance love. We can
	// memoize it keep snapshot heights whereto we know the chain is
	// synced. For now just do the entire thing.

	// Always walk backwards because it's only a single lookup.
	// XXX is direction = 0 even meaningful?
	var h, e *chainhash.Hash
	switch direction {
	case 1:
		h = endBH.BlockHash()
		e = startBH.BlockHash()
	case -1:
		h = startBH.BlockHash()
		e = endBH.BlockHash()
	default:
		return 0, ErrNotLinear
	}
	for {
		bh, err := s.db.BlockHeaderByHash(ctx, h[:])
		if err != nil {
			return -1, fmt.Errorf("block header by hash: %w", err)
		}
		h = bh.ParentHash()
		if h.IsEqual(e) {
			return direction, nil
		}
		if h.IsEqual(s.chainParams.GenesisHash) {
			return direction, ErrNotLinear
		}
	}
}

// SyncIndexersToHash tries to move the various indexers to the supplied
// height (inclusive).
// Note: on unwind it means that it WILL unwind the the various indexers
// including the hash that was passed in. E.g. if this unwinds from 1001 to
// 1000 the indexes for block 1000 WILL be updated as well.
func (s *Server) SyncIndexersToHash(ctx context.Context, hash *chainhash.Hash) error {
	log.Tracef("SyncIndexersToHash")
	defer log.Tracef("SyncIndexersToHash exit")

	s.mtx.Lock()
	if s.indexing {
		s.mtx.Unlock()
		return errors.New("already indexing")
	}
	s.indexing = true
	s.mtx.Unlock()

	defer func() {
		// unquiesce
		s.mtx.Lock()
		s.quiesced = false
		s.indexing = false
		// s.clipped = false
		actualHeight, bhb, err := s.RawBlockHeaderBest(ctx)
		if err != nil {
			log.Errorf("sync indexers best: %v", err)
			s.mtx.Unlock()
			return
		}
		// get a random peer
		p, err := s.randomPeer(ctx)
		if err != nil {
			log.Errorf("sync indexers random peer: %v", err)
			s.mtx.Unlock()
			return
		}
		s.mtx.Unlock()

		// XXX explain why we need to get more headers here
		// continue getting headers, XXX this does not belong here either
		// XXX if bh download fails we will get jammed. We need a queued "must execute this command" added to peer/service.
		// XXX we may not want to do this when in special "driver mode"
		log.Infof("resuming block header download at: %v", actualHeight)
		if err = s.getHeaders(ctx, p, bhb); err != nil {
			log.Errorf("sync indexers: %v", err)
			return
		}
	}()

	log.Debugf("Syncing indexes to: %v", hash)

	// Utxos
	if err := s.UtxoIndexer(ctx, hash); err != nil {
		return fmt.Errorf("utxo indexer: %w", err)
	}

	// Transactions index
	if err := s.TxIndexer(ctx, hash); err != nil {
		return fmt.Errorf("tx indexer: %w", err)
	}
	log.Debugf("Done syncing to: %v", hash)

	return nil
}
