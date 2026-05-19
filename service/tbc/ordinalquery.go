// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

// On-demand ordinal sat number computation. Traces a single sat
// backward through the spending chain using amounts only (no full
// output range computation). Each step follows one input through
// the FIFO — always linear to a coinbase.

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// satTracer follows a single sat backward through the spending chain.
type satTracer struct {
	s *Server
}

func (t *satTracer) findTx(block *btcutil.Block, txid chainhash.Hash) *btcutil.Tx {
	for _, tx := range block.Transactions() {
		if *tx.Hash() == txid {
			return tx
		}
	}
	return nil
}

// inputValue looks up the value of a specific outpoint.
func (t *satTracer) inputValue(ctx context.Context, txid chainhash.Hash, vout uint32) (uint64, error) {
	blockHash, err := t.s.g.db.BlockHashByTxId(ctx, txid)
	if err != nil {
		return 0, fmt.Errorf("tx %v: %w", txid, err)
	}
	block, err := t.s.g.db.BlockByHash(ctx, *blockHash)
	if err != nil {
		return 0, err
	}
	tx := t.findTx(block, txid)
	if tx == nil {
		return 0, fmt.Errorf("tx %v not in block", txid)
	}
	if vout >= uint32(len(tx.MsgTx().TxOut)) {
		return 0, fmt.Errorf("vout %d out of range", vout)
	}
	return uint64(tx.MsgTx().TxOut[vout].Value), nil
}

// traceSat traces a single sat at the given offset within the given
// output backward through the spending chain to its coinbase origin,
// returning its absolute sat number.
func (t *satTracer) traceSat(ctx context.Context, txid chainhash.Hash, vout uint32, offset uint64) (uint64, error) {
	for depth := 0; ; depth++ {
		if err := ctx.Err(); err != nil {
			return 0, fmt.Errorf("traceSat cancelled at depth %d: %w", depth, err)
		}
		blockHash, err := t.s.g.db.BlockHashByTxId(ctx, txid)
		if err != nil {
			return 0, fmt.Errorf("tx %v: %w", txid, err)
		}

		block, err := t.s.g.db.BlockByHash(ctx, *blockHash)
		if err != nil {
			return 0, err
		}
		bh, err := t.s.g.db.BlockHeaderByHash(ctx, *blockHash)
		if err != nil {
			return 0, err
		}

		tx := t.findTx(block, txid)
		if tx == nil {
			return 0, fmt.Errorf("tx %v not in block", txid)
		}

		if blockchain.IsCoinBase(tx) {
			// Compute FIFO position within coinbase.
			var pos uint64
			for i, txOut := range tx.MsgTx().TxOut {
				if uint32(i) == vout {
					break
				}
				pos += uint64(txOut.Value)
			}
			pos += offset

			// Subsidy check.
			subsStart, subsCount := CoinbaseSatRange(uint32(bh.Height))
			if pos < subsCount {
				return subsStart + pos, nil
			}

			// Fee region. Compute fee amounts per tx (flat lookups).
			feePos := pos - subsCount
			for _, btx := range block.Transactions() {
				if blockchain.IsCoinBase(btx) {
					continue
				}

				var inTotal uint64
				for _, txIn := range btx.MsgTx().TxIn {
					v, err := t.inputValue(ctx,
						txIn.PreviousOutPoint.Hash,
						txIn.PreviousOutPoint.Index)
					if err != nil {
						return 0, fmt.Errorf("fee input: %w", err)
					}
					inTotal += v
				}
				var outTotal uint64
				for _, txOut := range btx.MsgTx().TxOut {
					outTotal += uint64(txOut.Value)
				}
				fee := inTotal - outTotal
				if fee == 0 {
					continue
				}

				if feePos < fee {
					// This sat is from this tx's fee.
					// The fee sat is at the end of this
					// tx's input stream. Fee offset within
					// the tx's total input value:
					// inTotal - fee + feePos = outTotal + feePos
					//
					// FIFO position within this tx's inputs:
					txFifoPos := outTotal + feePos

					// Find which input and at what offset.
					var cum uint64
					for _, txIn := range btx.MsgTx().TxIn {
						v, err := t.inputValue(ctx,
							txIn.PreviousOutPoint.Hash,
							txIn.PreviousOutPoint.Index)
						if err != nil {
							return 0, fmt.Errorf("fee trace: %w", err)
						}
						if cum+v > txFifoPos {
							// This input contains our sat.
							txid = txIn.PreviousOutPoint.Hash
							vout = txIn.PreviousOutPoint.Index
							offset = txFifoPos - cum
							goto next
						}
						cum += v
					}
					return 0, fmt.Errorf("fee sat offset overflow in tx %v", btx.Hash())
				}
				feePos -= fee
			}
			return 0, fmt.Errorf("fee sat offset overflow in block %v", blockHash)
		}

		// Non-coinbase: compute FIFO position, find which input.
		{
			var pos uint64
			for i, txOut := range tx.MsgTx().TxOut {
				if uint32(i) == vout {
					break
				}
				pos += uint64(txOut.Value)
			}
			pos += offset

			// Walk inputs by value to find which one contains this sat.
			var cum uint64
			for _, txIn := range tx.MsgTx().TxIn {
				v, err := t.inputValue(ctx,
					txIn.PreviousOutPoint.Hash,
					txIn.PreviousOutPoint.Index)
				if err != nil {
					return 0, fmt.Errorf("input value: %w", err)
				}
				if cum+v > pos {
					txid = txIn.PreviousOutPoint.Hash
					vout = txIn.PreviousOutPoint.Index
					offset = pos - cum
					goto next
				}
				cum += v
			}
			return 0, fmt.Errorf("sat offset overflow in tx %v", txid)
		}

	next:
	}

	// Unreachable — loop terminates at coinbase or error.
}

// computeInscribedSat derives the sat number for an inscription.
// ComputeInscribedSatPublic is a public wrapper for testing.
func (s *Server) ComputeInscribedSatPublic(ctx context.Context, txid chainhash.Hash, inputIndex uint32) (uint64, error) {
	return s.computeInscribedSat(ctx, txid, inputIndex)
}

func (s *Server) computeInscribedSat(ctx context.Context, txid chainhash.Hash, inputIndex uint32) (uint64, error) {
	blockHash, err := s.g.db.BlockHashByTxId(ctx, txid)
	if err != nil {
		return 0, fmt.Errorf("tx %v: %w", txid, err)
	}

	block, err := s.g.db.BlockByHash(ctx, *blockHash)
	if err != nil {
		return 0, fmt.Errorf("block %v: %w", blockHash, err)
	}

	var tx *btcutil.Tx
	for _, t := range block.Transactions() {
		if *t.Hash() == txid {
			tx = t
			break
		}
	}
	if tx == nil {
		return 0, fmt.Errorf("tx %v not in block", txid)
	}

	if inputIndex >= uint32(len(tx.MsgTx().TxIn)) {
		return 0, fmt.Errorf("input %d out of range", inputIndex)
	}

	prevOut := tx.MsgTx().TxIn[inputIndex].PreviousOutPoint
	tracer := &satTracer{s: s}
	return tracer.traceSat(ctx, prevOut.Hash, prevOut.Index, 0)
}

// computeSatRanges derives sat ranges for an outpoint using the
// full-output approach (subsidy-only at coinbase).
func (s *Server) computeSatRanges(ctx context.Context, txid chainhash.Hash, vout uint32, memo map[tbcd.Outpoint][]SatRange) ([]SatRange, error) {
	c := &satRangeContext{
		s:    s,
		memo: memo,
	}
	return c.compute(ctx, txid, vout)
}

// satRangeContext is for full-output sat range computation (SatRangesByOutpoint RPC).
type satRangeContext struct {
	s    *Server
	memo map[tbcd.Outpoint][]SatRange
}

func (c *satRangeContext) compute(ctx context.Context, txid chainhash.Hash, vout uint32) ([]SatRange, error) {
	op := tbcd.NewOutpoint(txid, vout)
	if cached, ok := c.memo[op]; ok {
		return cached, nil
	}

	if len(c.memo) > 500000 {
		return nil, errors.New("sat range computation exceeded 500k outpoints")
	}

	blockHash, err := c.s.g.db.BlockHashByTxId(ctx, txid)
	if err != nil {
		return nil, fmt.Errorf("tx %v not found: %w", txid, err)
	}

	block, err := c.s.g.db.BlockByHash(ctx, *blockHash)
	if err != nil {
		return nil, fmt.Errorf("block %v: %w", blockHash, err)
	}
	bh, err := c.s.g.db.BlockHeaderByHash(ctx, *blockHash)
	if err != nil {
		return nil, fmt.Errorf("header %v: %w", blockHash, err)
	}

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

	if vout >= uint32(len(tx.MsgTx().TxOut)) {
		return nil, fmt.Errorf("vout %d out of range for tx %v", vout, txid)
	}

	var allInputRanges []SatRange

	if blockchain.IsCoinBase(tx) {
		subsStart, subsCount := CoinbaseSatRange(uint32(bh.Height))
		allInputRanges = append(allInputRanges, SatRange{
			Start: subsStart,
			Count: subsCount,
		})
	} else {
		for _, txIn := range tx.MsgTx().TxIn {
			inRanges, err := c.compute(ctx,
				txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if err != nil {
				return nil, fmt.Errorf("input %v: %w",
					txIn.PreviousOutPoint, err)
			}
			allInputRanges = append(allInputRanges, inRanges...)
		}
	}

	merged := MergeSatRanges(allInputRanges)
	var rangeOffset int
	var satOffset uint64
	for txOutIdx, txOut := range tx.MsgTx().TxOut {
		outOp := tbcd.NewOutpoint(txid, uint32(txOutIdx))
		if txOut.Value == 0 {
			c.memo[outOp] = nil
			continue
		}
		outRanges, newRangeOffset, newSatOffset := SplitSatRanges(
			merged, rangeOffset, satOffset, uint64(txOut.Value))
		rangeOffset = newRangeOffset
		satOffset = newSatOffset
		c.memo[outOp] = outRanges
	}

	return c.memo[op], nil
}
