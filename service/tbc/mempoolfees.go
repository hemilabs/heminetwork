// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"math"
	"sort"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
)

const (
	// Maximum size of a block
	blockMaxWeight int64 = blockchain.MaxBlockWeight // in weight units

	// If a block has less space left than this, it is considered full in fee calculation
	blockFullThreshold int64 = 200000 // in weight units
)

var defaultMinFee = 1.0 // in sats/vbyte

type mempoolBlock struct {
	blockWeight int64     // in weight units
	blockSize   int64     // in vbytes
	medianFee   float64   // median fee of a tx in the block (sats/vbyte)
	txRates     []float64 // rates of txs in block
}

func (mptx *mempoolTx) Fee() int64 {
	return mptx.inValue - mptx.outValue
}

func (mptx *mempoolTx) FeeRate() float64 {
	return float64(mptx.Fee()) / float64(mptx.weight)
}

func medianFee(fees []float64) float64 {
	l := len(fees)
	if l == 0 {
		return 0
	} else if l%2 == 0 {
		return (fees[l/2-1] + fees[l/2]) / 2
	} else {
		return fees[l/2]
	}
}

func (mp *mempool) generateMempoolBlocks(ctx context.Context) (blks []mempoolBlock, err error) {
	if len(mp.txs) == 0 {
		return blks, nil
	}

	// get mempool transactions
	mptxs := make([]*mempoolTx, 0, len(mp.txs))
	for _, mptx := range mp.txs {
		if mptx == nil {
			continue
		}
		mptxs = append(mptxs, mptx)
	}

	// sort transactions by fee rate in descending order
	sort.Slice(mptxs, func(i, j int) bool {
		return mptxs[i].FeeRate() > mptxs[j].FeeRate()
	})

	// create mempool blocks
	mblk := mempoolBlock{
		txRates: make([]float64, 0, len(mptxs)),
	}
	for _, mptx := range mptxs {
		if mblk.blockWeight+mptx.weight > blockMaxWeight && mblk.blockWeight != 0 {
			blks = append(blks, mblk)
			mblk = mempoolBlock{
				txRates: make([]float64, 0, len(mptxs)),
			}
		}
		mblk.txRates = append(mblk.txRates, mptx.FeeRate())
		mblk.blockWeight += mptx.weight
		mblk.blockSize += mptx.size
	}

	// append last block
	if mblk.blockWeight > 0 {
		blks = append(blks, mblk)
	}

	// calculate median fee for each block
	for k, blk := range blks {
		// multiply by 4 to convert from sats/wu to sats/vbyte
		blks[k].medianFee = medianFee(blk.txRates) * 4
	}

	return blks, nil
}

func (mp *mempool) GetRecommendedFees(ctx context.Context) ([]gozer.FeeEstimate, error) {
	mp.mtx.RLock()
	pBlocks, err := mp.generateMempoolBlocks(ctx)
	mp.mtx.RUnlock()
	if err != nil {
		return nil, err
	}

	recFees := make([]gozer.FeeEstimate, 6)
	for k := range 6 {
		recFees[k] = gozer.FeeEstimate{
			Blocks:      uint(k + 1),
			SatsPerByte: defaultMinFee,
		}
	}

	var prevMedianFee float64
	if len(pBlocks) > 0 {
		prevMedianFee = pBlocks[0].medianFee
	}
	for k := range recFees {
		if len(pBlocks) > k {
			prevMedianFee, err = optimizeMedianFee(&pBlocks[k], len(pBlocks) > k+1, prevMedianFee)
			if err != nil {
				return nil, err
			}
			recFees[k].SatsPerByte = math.Max(defaultMinFee, prevMedianFee)
		} else {
			break
		}
	}

	return recFees, nil
}

func optimizeMedianFee(pBlock *mempoolBlock, existsNextBlock bool, previousFee float64) (float64, error) {
	useFee := (pBlock.medianFee + previousFee) / 2

	// If block is half or less than half full
	// we presume the minimum fee is still enough
	if pBlock.blockWeight <= blockMaxWeight/2 {
		return defaultMinFee, nil
	}

	// If block has an acceptable amount of space left
	// and there aren't any more projected blocks after it,
	// slowly ramp up the fee toward the median of the block.
	if pBlock.blockWeight <= blockMaxWeight-blockFullThreshold && !existsNextBlock {
		mult := float64((pBlock.blockWeight - (blockMaxWeight / 2))) / float64(blockMaxWeight/2)
		return math.Max(useFee*mult, defaultMinFee), nil
	}
	return useFee, nil
}
