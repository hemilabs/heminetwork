package tbc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

var IndexHeightKey = []byte("indexheight") // last indexed height key

func parseBlockAndCache(cp *chaincfg.Params, bb []byte, utxos map[tbcd.Outpoint]tbcd.Utxo) (*btcutil.Block, error) {
	b, err := btcutil.NewBlockFromBytes(bb)
	if err != nil {
		return nil, err
	}

	txs := b.Transactions()
	for idx, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if idx == 0 {
				// Skip coinbase inputs
				continue
			}
			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if _, ok := utxos[op]; ok {
				delete(utxos, op)
				continue
			}
			// mark for deletion
			utxos[op] = tbcd.DeleteUtxo
		}
		for outIndex, txOut := range tx.MsgTx().TxOut {
			utxos[tbcd.NewOutpoint(*tx.Hash(), uint32(outIndex))] = tbcd.NewUtxo(
				sha256.Sum256(txOut.PkScript),
				uint64(txOut.Value),
				uint32(outIndex))
		}
	}
	// log.Infof("%v", spew.Sdump(utxos))
	return b, nil
}

func (s *Server) indexBlock(ctx context.Context, height uint64, b *tbcd.Block) error {
	log.Tracef("indexBlock")
	defer log.Tracef("indexBlock")

	_, err := parseBlockAndCache(s.chainParams, b.Block, s.utxos)

	return err
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
			return 0, fmt.Errorf("block headers by height %v: %v", height, err)
		}
		eb, err := s.db.BlockByHash(ctx, bhs[0].Hash)
		if err != nil {
			return 0, fmt.Errorf("block by hash %v: %v", height, err)
		}
		b, err := parseBlockAndCache(s.chainParams, eb.Block, s.utxos)
		if err != nil {
			return 0, fmt.Errorf("parse block %v: %v", height, err)
		}
		_ = b

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
