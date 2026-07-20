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

	genesisHeight int32 // height of the chain's genesis (0 for P2P, N for effective genesis)
	ctx           context.Context
	db            tbcd.Database
}

var _ blockchain.HeaderCtx = (*tbcHeaderCtx)(nil)

func (h *tbcHeaderCtx) Height() int32    { return h.height }
func (h *tbcHeaderCtx) Bits() uint32     { return h.bits }
func (h *tbcHeaderCtx) Timestamp() int64 { return h.ts }

func (h *tbcHeaderCtx) Parent() blockchain.HeaderCtx {
	if h.parent != nil {
		return h.parent
	}
	if h.height <= h.genesisHeight || h.db == nil {
		return nil
	}
	bh, err := h.db.BlockHeaderByHash(h.ctx, h.prevBlock)
	if err != nil {
		return nil
	}
	wbh, err := bh.Wire()
	if err != nil {
		return nil
	}
	p := &tbcHeaderCtx{
		height:        int32(bh.Height),
		bits:          wbh.Bits,
		ts:            wbh.Timestamp.Unix(),
		prevBlock:     wbh.PrevBlock,
		genesisHeight: h.genesisHeight,
		ctx:           h.ctx,
		db:            h.db,
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

// verifyHeaderContext checks that each header in the batch passes btcd's
// CheckBlockHeaderContext: difficulty retarget, median-time-past, and version.
func (s *Server) verifyHeaderContext(ctx context.Context, headers []*wire.BlockHeader) error {
	if len(headers) == 0 {
		return nil
	}
	if s.g.chain.PoWNoRetargeting {
		return nil
	}

	chainCtx := &tbcChainCtx{params: s.g.chain}
	var genesisHeight int32
	var blocksPerRetarget int32
	if s.cfg.ExternalHeaderMode {
		genesisHeight = int32(s.cfg.GenesisHeightOffset)
		blocksPerRetarget = chainCtx.BlocksPerRetarget()
	}

	// Look up the parent of the first header in the batch.
	pbh, err := s.g.db.BlockHeaderByHash(ctx, headers[0].PrevBlock)
	if err != nil {
		return fmt.Errorf("header context parent lookup: %w", err)
	}
	pwbh, err := pbh.Wire()
	if err != nil {
		return fmt.Errorf("header context parent decode: %w", err)
	}

	prev := &tbcHeaderCtx{
		height:        int32(pbh.Height),
		bits:          pwbh.Bits,
		ts:            pwbh.Timestamp.Unix(),
		prevBlock:     pwbh.PrevBlock,
		genesisHeight: genesisHeight,
		ctx:           ctx,
		db:            s.g.db,
	}

	for i, hdr := range headers {
		headerHeight := prev.height + 1

		// In ExternalHeaderMode, at a retarget boundary within the
		// first retarget period after the effective genesis, btcd walks
		// back BlocksPerRetarget ancestors but we don't have enough
		// depth — use BFFastAdd to skip difficulty/median-time checks
		// but still verify version.
		flags := blockchain.BFNone
		if s.cfg.ExternalHeaderMode &&
			headerHeight%blocksPerRetarget == 0 &&
			headerHeight-genesisHeight < blocksPerRetarget {
			flags = blockchain.BFFastAdd
		}

		err := blockchain.CheckBlockHeaderContext(hdr, prev,
			flags, chainCtx, true)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("header %d (height %d) context check: %w",
				i, prev.height+1, err)
		}

		prev = &tbcHeaderCtx{
			height:        int32(pbh.Height) + int32(i) + 1,
			bits:          hdr.Bits,
			ts:            hdr.Timestamp.Unix(),
			prevBlock:     hdr.PrevBlock,
			parent:        prev,
			genesisHeight: genesisHeight,
			ctx:           ctx,
			db:            s.g.db,
		}
	}

	return nil
}
