// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type tbcHeaderCtx struct {
	height    int32
	bits      uint32
	ts        int64
	prevBlock chainhash.Hash
	parent    *tbcHeaderCtx

	db tbcd.Database
}

var _ blockchain.HeaderCtx = (*tbcHeaderCtx)(nil)

func (h *tbcHeaderCtx) Height() int32    { return h.height }
func (h *tbcHeaderCtx) Bits() uint32     { return h.bits }
func (h *tbcHeaderCtx) Timestamp() int64 { return h.ts }

func (h *tbcHeaderCtx) Parent() blockchain.HeaderCtx {
	if h.parent != nil {
		return h.parent
	}
	if h.height <= 0 || h.db == nil {
		return nil
	}
	// context.Background: btcd's HeaderCtx interface has no context param.
	bh, err := h.db.BlockHeaderByHash(context.Background(), h.prevBlock)
	if err != nil {
		return nil
	}
	wbh, err := bh.Wire()
	if err != nil {
		return nil
	}
	p := &tbcHeaderCtx{
		height:    int32(bh.Height),
		bits:      wbh.Bits,
		ts:        wbh.Timestamp.Unix(),
		prevBlock: wbh.PrevBlock,
		db:        h.db,
	}
	h.parent = p
	return p
}

func (h *tbcHeaderCtx) RelativeAncestorCtx(distance int32) blockchain.HeaderCtx {
	node := blockchain.HeaderCtx(h)
	for i := int32(0); i < distance && node != nil; i++ {
		node = node.Parent()
	}
	return node
}

type tbcChainCtx struct {
	params *chaincfg.Params
}

var _ blockchain.ChainCtx = (*tbcChainCtx)(nil)

func (c *tbcChainCtx) ChainParams() *chaincfg.Params { return c.params }

func (c *tbcChainCtx) BlocksPerRetarget() int32 {
	return int32(c.params.TargetTimespan / c.params.TargetTimePerBlock)
}

func (c *tbcChainCtx) MinRetargetTimespan() int64 {
	return int64(c.params.TargetTimespan/time.Second) / c.params.RetargetAdjustmentFactor
}

func (c *tbcChainCtx) MaxRetargetTimespan() int64 {
	return int64(c.params.TargetTimespan/time.Second) * c.params.RetargetAdjustmentFactor
}

// VerifyCheckpoint always returns true: tbc handles checkpoints
// independently and calls CheckBlockHeaderContext with skipCheckpoint=true.
func (c *tbcChainCtx) VerifyCheckpoint(height int32, hash *chainhash.Hash) bool {
	return true
}

// FindPreviousCheckpoint returns nil: see VerifyCheckpoint.
func (c *tbcChainCtx) FindPreviousCheckpoint() (blockchain.HeaderCtx, error) {
	return nil, nil
}

// verifyDifficultyRetarget checks that each header in the batch has correct
// difficulty bits according to the retarget rules for the configured network.
func (s *Server) verifyDifficultyRetarget(ctx context.Context, headers []*wire.BlockHeader) error {
	if len(headers) == 0 {
		return nil
	}
	if s.g.chain.PoWNoRetargeting {
		return nil
	}

	chainCtx := &tbcChainCtx{params: s.g.chain}

	// Look up the parent of the first header in the batch.
	pbh, err := s.g.db.BlockHeaderByHash(ctx, headers[0].PrevBlock)
	if err != nil {
		return fmt.Errorf("difficulty verify parent lookup: %w", err)
	}
	pwbh, err := pbh.Wire()
	if err != nil {
		return fmt.Errorf("difficulty verify parent decode: %w", err)
	}

	prev := &tbcHeaderCtx{
		height:    int32(pbh.Height),
		bits:      pwbh.Bits,
		ts:        pwbh.Timestamp.Unix(),
		prevBlock: pwbh.PrevBlock,
		db:        s.g.db,
	}

	for i, hdr := range headers {
		err := blockchain.CheckBlockHeaderContext(hdr, prev,
			blockchain.BFNone, chainCtx, true)
		if err != nil {
			return fmt.Errorf("header %d (height %d) difficulty check: %w",
				i, prev.height+1, err)
		}

		prev = &tbcHeaderCtx{
			height:    int32(pbh.Height) + int32(i) + 1,
			bits:      hdr.Bits,
			ts:        hdr.Timestamp.Unix(),
			prevBlock: hdr.PrevBlock,
			parent:    prev,
			db:        s.g.db,
		}
	}

	return nil
}
