// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

// tbcHeaderCtx adapts a stored block header to btcd's blockchain.HeaderCtx so
// that CheckBlockHeaderContext (difficulty retarget, median-time-past, version)
// can be evaluated against the header chain in our store.
type tbcHeaderCtx struct {
	height    int32
	bits      uint32
	ts        int64
	prevBlock chainhash.Hash
	parent    *tbcHeaderCtx

	genesisHeight int32 // always 0: verifyHeaderContext runs on the P2P path only
	ctx           context.Context
	db            tbcd.Database
	// walkErr records the first store error (other than not found) hit while
	// walking ancestors, so verifyHeaderContext can report it and fail closed.
	walkErr *error
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
		// Not found is the end of the known chain. Anything else is a
		// store fault; treating it as "no parent" truncates the walk and
		// changes the median-time-past and difficulty inputs.
		if !errors.Is(err, database.ErrNotFound) && h.walkErr != nil && *h.walkErr == nil {
			*h.walkErr = err
		}
		return nil
	}
	wbh, err := bh.Wire()
	if err != nil {
		// A record that does not decode is a store fault too.
		if h.walkErr != nil && *h.walkErr == nil {
			*h.walkErr = err
		}
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
		walkErr:       h.walkErr,
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

// VerifyCheckpoint always returns true: tbc handles checkpoints independently
// and calls CheckBlockHeaderContext with skipCheckpoint=true.
func (c *tbcChainCtx) VerifyCheckpoint(height int32, hash *chainhash.Hash) bool {
	return true
}

// FindPreviousCheckpoint returns nil: see VerifyCheckpoint.
func (c *tbcChainCtx) FindPreviousCheckpoint() (blockchain.HeaderCtx, error) {
	return nil, nil
}

// verifyHeaderContext checks that each header in the batch passes btcd's
// CheckBlockHeaderContext: difficulty retarget, median-time-past and block
// version. Without it a peer could insert a min-difficulty header at a height
// that requires far higher difficulty.
//
// It is a no-op on PoWNoRetargeting networks (regtest/localnet).
func (s *Server) verifyHeaderContext(ctx context.Context, headers []*wire.BlockHeader) error {
	if len(headers) == 0 {
		return nil
	}
	if s.chainParams.PoWNoRetargeting {
		return nil
	}

	// This only runs on the P2P handleHeaders path, never in
	// ExternalHeaderMode, so genesis is always height 0 and the full ancestry
	// is available. External header insertion is trusted and not checked here.
	chainCtx := &tbcChainCtx{params: s.chainParams}
	const genesisHeight int32 = 0

	// Look up the parent of the first header in the batch.
	pbh, err := s.db.BlockHeaderByHash(ctx, headers[0].PrevBlock)
	if err != nil {
		return fmt.Errorf("header context parent lookup: %w", err)
	}
	pwbh, err := pbh.Wire()
	if err != nil {
		return fmt.Errorf("header context parent decode: %w", err)
	}

	var walkErr error
	prev := &tbcHeaderCtx{
		height:        int32(pbh.Height),
		bits:          pwbh.Bits,
		ts:            pwbh.Timestamp.Unix(),
		prevBlock:     pwbh.PrevBlock,
		genesisHeight: genesisHeight,
		ctx:           ctx,
		db:            s.db,
		walkErr:       &walkErr,
	}

	for i, hdr := range headers {
		// Defensive; a walk fault on an earlier header already returned.
		walkErr = nil

		// Full ancestry is available, so run the complete check.
		flags := blockchain.BFNone

		if err := blockchain.CheckBlockHeaderContext(hdr, prev,
			flags, chainCtx, true); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A store fault during the ancestor walk can masquerade as a
			// context violation; report the real (store) error.
			if walkErr != nil {
				return fmt.Errorf("header context ancestor walk: %w", walkErr)
			}
			return fmt.Errorf("header %d (height %d) context check: %w",
				i, prev.height+1, err)
		}
		// A truncated walk can also weaken a rule, e.g. median-time-past
		// over fewer ancestors, or the testnet min-difficulty walk falling
		// back to PowLimit. Fail closed if the header passed over a faulted
		// walk.
		if walkErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("header context ancestor walk: %w", walkErr)
		}

		prev = &tbcHeaderCtx{
			height:        int32(pbh.Height) + int32(i) + 1,
			bits:          hdr.Bits,
			ts:            hdr.Timestamp.Unix(),
			prevBlock:     hdr.PrevBlock,
			parent:        prev,
			genesisHeight: genesisHeight,
			ctx:           ctx,
			db:            s.db,
			walkErr:       &walkErr,
		}
	}

	return nil
}
