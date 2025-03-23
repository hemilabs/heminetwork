// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"math"
	"sort"

	"github.com/btcsuite/btcd/blockchain"
)

const (
	// Maximum size of a block
	blockMaxWeight int64 = blockchain.MaxBlockWeight // in weight units

	// If a block has less space than this, it is considered reasonably full
	blockFullThreshold int64 = 200000 // in weight units
)

var defaultMinFee = 1.0 // in sats/vbyte

type mempoolBlock struct {
	blockWeight int64     // in weight units
	blockSize   int64     // in vbytes
	medianFee   float64   // median fee of a tx in the block (sats/vbyte)
	txRates     []float64 // rates of txs in block
}

type RecommendedFees struct {
	fastestFee  float64
	halfHourFee float64
	hourFee     float64
	economyFee  float64
	minimumFee  float64
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

func (mp *mempool) GetRecommendedFees(ctx context.Context) (*RecommendedFees, error) {
	mp.mtx.RLock()
	pBlocks, err := mp.generateMempoolBlocks(ctx)
	mp.mtx.RUnlock()
	if err != nil {
		return nil, err
	}

	recFees := RecommendedFees{
		fastestFee:  defaultMinFee,
		halfHourFee: defaultMinFee,
		hourFee:     defaultMinFee,
		economyFee:  defaultMinFee,
		minimumFee:  defaultMinFee,
	}

	l := len(pBlocks)
	if l < 1 {
		return &recFees, nil
	}

	// calculate increasingly more accurate fees depending on how many
	// txs are in the mempool, and thus how many blocks we can build.
	firstMedianFee, err := optimizeMedianFee(&pBlocks[0], l > 1, pBlocks[0].medianFee)
	if err != nil {
		return nil, err
	}
	recFees.fastestFee = math.Max(defaultMinFee, firstMedianFee)
	if l > 1 {
		secondMedianFee, err := optimizeMedianFee(&pBlocks[1], l > 2, firstMedianFee)
		if err != nil {
			return nil, err
		}
		recFees.halfHourFee = math.Max(defaultMinFee, secondMedianFee)
		if l > 2 {
			thirdMedianFee, err := optimizeMedianFee(&pBlocks[2], l > 3, secondMedianFee)
			if err != nil {
				return nil, err
			}
			recFees.hourFee = math.Max(defaultMinFee, thirdMedianFee)
			recFees.economyFee = math.Max(defaultMinFee, math.Min(2*defaultMinFee, thirdMedianFee))
		}
	}
	return &recFees, nil
}

func optimizeMedianFee(pBlock *mempoolBlock, existsNextBlock bool, previousFee float64) (float64, error) {
	useFee := (pBlock.medianFee + previousFee) / 2

	// If block is half or less than half full
	// we presume the minimum fee is still enough
	if pBlock.blockWeight <= blockMaxWeight/2 {
		return defaultMinFee, nil
	}

	// If block has more space left than the threshold, and there
	// are no more blocks after it, we multiply the fee to
	// prevent our tx from being left out if higher fee txs come in.
	// The multiplier is inversely proportional to the
	// amount of space left in the block.
	if pBlock.blockWeight <= blockMaxWeight-blockFullThreshold && !existsNextBlock {
		mult := (pBlock.blockWeight - blockFullThreshold) / blockFullThreshold
		return math.Max(math.Round(useFee*float64(mult)), defaultMinFee), nil
	}
	return useFee, nil
}
