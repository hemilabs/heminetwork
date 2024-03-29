package tbc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

var IndexHeightKey = []byte("indexheight") // last indexed height key

func processTransactions(cp *chaincfg.Params, txs []*btcutil.Tx, utxos map[tbcd.Outpoint]tbcd.Utxo) error {
	for idx, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if idx == 0 {
				// Skip coinbase inputs
				continue
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
			utxos[tbcd.NewOutpoint(*tx.Hash(), uint32(outIndex))] = tbcd.NewUtxo(
				sha256.Sum256(txOut.PkScript),
				uint64(txOut.Value),
				uint32(outIndex))
		}
	}
	// log.Infof("%v", spew.Sdump(utxos))
	return nil
}

//// indexBlock XXX this function may need to become parseBlockAndCache. The idea
//// was to separate parseBlockAndCache for tests but we need a db lookup. Debate
//// if moving the lookup in the db makes sense or not.
//func (s *Server) indexBlock(ctx context.Context, height uint64, b *tbcd.Block) error {
//	log.Tracef("indexBlock")
//	defer log.Tracef("indexBlock")
//
//	_, err := s.parseBlockAndCache(ctx, s.chainParams, b.Block, s.utxos)
//
//	return err
//}

func (s *Server) fetchOP(ctx context.Context, w *sync.WaitGroup, op tbcd.Outpoint) {
	defer w.Done()

	pkScript, err := s.db.ScriptHashByOutpoint(ctx, op)
	if err != nil {
		// This happens when a transaction is created and spent in the
		// same block.
		// XXX this is probably too loud but log for investigation and
		// remove later.
		log.Errorf("db missing pkscript: %v", op)
		return
	}
	s.mtx.Lock()
	s.utxos[op] = tbcd.NewDeleteUtxo(*pkScript, op.TxIndex())
	s.mtx.Unlock()
}

func (s *Server) fixupCache(ctx context.Context, b *btcutil.Block) error {
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
			if _, ok := s.utxos[op]; ok {
				s.mtx.Unlock()
				continue
			}
			s.mtx.Unlock()

			// utxo not found, retrieve pkscript from database.
			w.Add(1)
			go s.fetchOP(ctx, w, op)
		}
	}

	w.Wait()

	return nil
}

func (s *Server) indexBlocks(ctx context.Context, startHeight, maxHeight uint64) (int, error) {
	log.Tracef("indexBlocks")
	defer log.Tracef("indexBlocks")

	circuitBreaker := false
	if maxHeight != 0 {
		circuitBreaker = true
	}

	blocksProcessed := 0
	for height := startHeight; ; height++ {
		bhs, err := s.db.BlockHeadersByHeight(ctx, height)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				log.Infof("No more blocks at: %v", height)
				break
			}
			return 0, fmt.Errorf("block headers by height %v: %v", height, err)
		}
		eb, err := s.db.BlockByHash(ctx, bhs[0].Hash)
		if err != nil {
			return 0, fmt.Errorf("block by hash %v: %v", height, err)
		}
		b, err := btcutil.NewBlockFromBytes(eb.Block)
		if err != nil {
			ch, _ := chainhash.NewHash(bhs[0].Hash)
			return 0, fmt.Errorf("could not decode block %v %v: %v",
				height, ch, err)
		}
		err = s.fixupCache(ctx, b)
		if err != nil {
			return 0, fmt.Errorf("parse block %v: %v", height, err)
		}

		// XXX MAY NOT TOUCH s.utxos once in this routine! this is by
		// design, do document it.
		err = processTransactions(s.chainParams, b.Transactions(), s.utxos)
		if err != nil {
			// XXX fix errorr after rename
			return 0, fmt.Errorf("xxxparse block %v: %v", height, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(s.utxos) * 100 / s.utxosMax
		if height%10000 == 0 || cp > s.utxosPercentage || blocksProcessed == 1 {
			log.Infof("Height: %v utxo cache %v%%", height, cp)
		}
		if cp > s.utxosPercentage {
			// Set utxosMax to the largest utxo capacity seen
			s.utxosMax = max(len(s.utxos), s.utxosMax)
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

func (s *Server) Indexer(ctx context.Context, height, count uint64) error {
	var maxHeight uint64
	circuitBreaker := false
	if count != 0 {
		circuitBreaker = true
		maxHeight = height + count
	}

	log.Infof("Start indexing at height %v count %v", height, count)
	for {
		start := time.Now()
		blocksProcessed, err := s.indexBlocks(ctx, height, maxHeight)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		utxosCached := len(s.utxos)
		log.Infof("blocks processed %v in %v utxos cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Now().Sub(start), utxosCached,
			s.utxosMax-utxosCached, utxosCached/blocksProcessed)

		// This is where we flush, simulate behavior by deleting utxos
		//for k := range s.utxos {
		//	delete(s.utxos, k)
		//}
		//log.Infof("%v", spew.Sdump(s.utxos))
		start = time.Now()
		err = s.db.BlockTxUpdate(ctx, s.utxos)
		if err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}
		log.Infof("Flushing complete utxos %v took %v",
			utxosCached, time.Now().Sub(start))

		height += uint64(blocksProcessed)

		// Record height in metadata
		var dbHeight [8]byte
		binary.BigEndian.PutUint64(dbHeight[:], height)
		err = s.db.MetadataPut(ctx, IndexHeightKey, dbHeight[:])
		if err != nil {
			return fmt.Errorf("metadata height: %w", err)
		}

		// If set we may have to exit early
		if circuitBreaker {
			log.Infof("Indexed to height: %v", height-1)
			if height >= maxHeight {
				return nil
			}
		}
	}
}
