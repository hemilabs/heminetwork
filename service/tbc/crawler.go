package tbc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

func OutpointFromTx(tx *btcutil.Tx) tbcd.Outpoint {
	return tbcd.NewOutpoint(*tx.Hash(), uint32(tx.Index()))
}

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
			utxos[OutpointFromTx(tx)] = tbcd.NewUtxo(
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

func (s *Server) indexBlocks(ctx context.Context, startHeight uint64) (int, error) {
	log.Tracef("indexBlocks")
	defer log.Tracef("indexBlocks")

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
	}

	return blocksProcessed, nil
}

func (s *Server) indexer(ctx context.Context) error {
	height := uint64(0)
	log.Infof("Start indexing at height %v", height)
	for {
		start := time.Now()
		blocksProcessed, err := s.indexBlocks(ctx, height)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		log.Infof("blocks processed %v in %v utxos cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Now().Sub(start), len(s.utxos),
			s.utxosMax-len(s.utxos), len(s.utxos)/blocksProcessed)

		// This is where we flush, simulate behavior by deleting utxos
		for k := range s.utxos {
			delete(s.utxos, k)
		}

		height += uint64(blocksProcessed)
	}
}
