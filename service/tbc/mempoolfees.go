// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"math"
	"sort"
)

const maxWeight int64 = 4000000 // in weight units

var defaultMinFee = 1.0 // in sats/vbyte

type mempoolBlock struct {
	blockWeight int64   // in weight units
	blockSize   int64   // in vbytes
	nTx         int     // number of transactions in block
	medianFee   float64 // median fee of a tx in the block (sats/vbyte)
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
		return (fees[l/2-1] + fees[l/2+1]) / 2
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
		mptxs = append(mptxs, mptx)
	}

	// sort transactions by fee rate in descending order
	sort.Slice(mptxs, func(i, j int) bool {
		return mptxs[i].FeeRate() > mptxs[j].FeeRate()
	})

	// create mempool blocks
	var mblk mempoolBlock
	feeRates := make([]float64, len(mp.txs))
	for k, mptx := range mptxs {
		feeRates[k] = mptx.FeeRate()
		if mblk.blockWeight+mptx.weight > maxWeight {
			blks = append(blks, mblk)
			mblk = mempoolBlock{}
		}
		mblk.nTx++
		mblk.blockWeight += mptx.weight
		mblk.blockSize += mptx.size
	}

	// append last block
	if mblk.blockWeight > 0 {
		blks = append(blks, mblk)
	}

	// calculate median fee for each block
	offset := 0
	for k, blk := range blks {
		// multiply by 4 to convert from sats/wu to sats/vbyte
		blks[k].medianFee = medianFee(feeRates[offset:offset+blk.nTx]) * 4
		offset += blk.nTx
	}

	return blks, nil
}

func (mp *mempool) GetRecommendedFees(ctx context.Context) (*RecommendedFees, error) {
	pBlocks, err := mp.generateMempoolBlocks(ctx)
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
	if pBlock.blockWeight <= maxWeight/2 {
		return defaultMinFee, nil
	}
	tailOffset := int64(200000)
	if pBlock.blockWeight <= maxWeight-tailOffset && !existsNextBlock {
		mult := float64((pBlock.blockWeight - tailOffset) / tailOffset)
		return math.Max(math.Round(useFee*mult), defaultMinFee), nil
	}
	return useFee, nil
}
