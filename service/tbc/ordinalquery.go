// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

// On-demand ordinal sat range computation. Walks backward through the
// spending chain via raw blocks and the tx index to derive sat ranges
// at query time instead of precomputing them during indexing.

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// computeSatRanges derives the sat ranges for a given outpoint by
// walking backward through the spending chain. Coinbase transactions
// produce deterministic ranges from the halving schedule; non-coinbase
// transactions require recursive resolution of all input sat ranges
// followed by FIFO redistribution across outputs.
//
// memo caches results within a single query to avoid redundant walks
// when multiple inputs share ancestry.
func (s *Server) computeSatRanges(ctx context.Context, txid chainhash.Hash, vout uint32, memo map[tbcd.Outpoint][]SatRange) ([]SatRange, error) {
	op := tbcd.NewOutpoint(txid, vout)
	if cached, ok := memo[op]; ok {
		return cached, nil
	}

	// Find which block contains this tx.
	blockHash, err := s.g.db.BlockHashByTxId(ctx, txid)
	if err != nil {
		return nil, fmt.Errorf("tx %v not found: %w", txid, err)
	}

	block, err := s.g.db.BlockByHash(ctx, *blockHash)
	if err != nil {
		return nil, fmt.Errorf("block %v: %w", blockHash, err)
	}

	bh, err := s.g.db.BlockHeaderByHash(ctx, *blockHash)
	if err != nil {
		return nil, fmt.Errorf("block header %v: %w", blockHash, err)
	}

	// Find the tx in the block.
	var tx *btcutil.Tx
	for _, t := range block.Transactions() {
		if *t.Hash() == txid {
			tx = t
			break
		}
	}
	if tx == nil {
		return nil, fmt.Errorf("tx %v not in block %v", txid, blockHash)
	}

	if int(vout) >= len(tx.MsgTx().TxOut) {
		return nil, fmt.Errorf("vout %d out of range for tx %v", vout, txid)
	}

	var allInputRanges []SatRange

	if blockchain.IsCoinBase(tx) {
		// Coinbase: subsidy is deterministic. Fee sat computation
		// is deferred — it requires resolving every tx in the block
		// which is expensive for query-time. For now, only subsidy
		// sats are assigned. TODO: compute fee sat ranges on demand.
		subsStart, subsCount := CoinbaseSatRange(uint32(bh.Height))
		allInputRanges = append(allInputRanges, SatRange{
			Start: subsStart,
			Count: subsCount,
		})
	} else {
		// Non-coinbase: resolve each input's sat ranges recursively.
		for _, txIn := range tx.MsgTx().TxIn {
			inRanges, err := s.computeSatRanges(ctx,
				txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index,
				memo)
			if err != nil {
				return nil, fmt.Errorf("input %v: %w",
					txIn.PreviousOutPoint, err)
			}
			allInputRanges = append(allInputRanges, inRanges...)
		}
	}

	// FIFO split across all outputs, caching each one.
	merged := MergeSatRanges(allInputRanges)
	var rangeOffset int
	var satOffset uint64
	for txOutIdx, txOut := range tx.MsgTx().TxOut {
		outOp := tbcd.NewOutpoint(txid, uint32(txOutIdx))
		if txOut.Value == 0 {
			memo[outOp] = nil
			continue
		}
		outRanges, newRangeOffset, newSatOffset := SplitSatRanges(
			merged, rangeOffset, satOffset, uint64(txOut.Value))
		rangeOffset = newRangeOffset
		satOffset = newSatOffset
		memo[outOp] = outRanges
	}

	return memo[op], nil
}
