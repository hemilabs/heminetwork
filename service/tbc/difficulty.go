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

	"github.com/hemilabs/heminetwork/v2/database"
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

// verifyHeaderSanity checks each header in the batch for proof-of-work
// validity and timestamp sanity. These are context-free checks that
// apply to all networks including regtest.
func (s *Server) verifyHeaderSanity(headers []*wire.BlockHeader) error {
	for i, hdr := range headers {
		err := blockchain.CheckBlockHeaderSanity(hdr, s.g.chain.PowLimit,
			s.timeSource, blockchain.BFNone)
		if err != nil {
			return fmt.Errorf("header %d sanity: %w", i, err)
		}
	}
	return nil
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

// ErrCheckpoint is returned when a header contradicts the chain
// checkpoints.
var ErrCheckpoint = errors.New("checkpoint violation")

// checkpointAt returns the checkpoint at height, or nil.
func checkpointAt(height uint64, hha []chaincfg.Checkpoint) *chaincfg.Checkpoint {
	for k := range hha {
		if uint64(hha[k].Height) == height {
			return &hha[k]
		}
	}
	return nil
}

// verifyHeaderCheckpoints rejects a batch of connected headers that
// contradicts the chain checkpoints.  A header at a checkpoint height
// must carry the checkpoint hash, and a header we do not already have
// must not sit at or below the most recent checkpoint our best header
// has passed: that is a fork off a checkpointed part of the chain.
//
// Headers we already have are allowed, so a peer that resends known
// headers (for example after falling back to genesis on an unknown
// locator) is not penalized.
//
// Without this check a peer can feed a valid low-work fork from
// genesis.  Every header in it adds a blocks missing entry that no
// honest peer can serve, and block download stalls on them.
func (s *Server) verifyHeaderCheckpoints(ctx context.Context, headers []*wire.BlockHeader) error {
	if len(headers) == 0 || len(s.g.chain.Checkpoints) == 0 {
		return nil
	}

	pbh, err := s.g.db.BlockHeaderByHash(ctx, headers[0].PrevBlock)
	if err != nil {
		return fmt.Errorf("checkpoint parent lookup: %w", err)
	}
	bhb, err := s.g.db.BlockHeaderBest(ctx)
	if err != nil {
		return fmt.Errorf("checkpoint best: %w", err)
	}
	var floor uint64
	if cp := previousCheckpoint(bhb, s.g.chain.Checkpoints); cp != nil {
		floor = uint64(cp.Height)
	}

	for i, hdr := range headers {
		height := pbh.Height + uint64(i) + 1
		hash := hdr.BlockHash()
		if cp := checkpointAt(height, s.g.chain.Checkpoints); cp != nil &&
			!cp.Hash.IsEqual(&hash) {
			return fmt.Errorf("%w: header %v at height %v, want %v",
				ErrCheckpoint, hash, height, cp.Hash)
		}
		if height > floor {
			continue
		}
		_, err := s.g.db.BlockHeaderByHash(ctx, hash)
		switch {
		case err == nil:
			// Known header, not a new fork.
		case errors.Is(err, database.ErrNotFound):
			return fmt.Errorf("%w: header %v at height %v forks "+
				"below checkpoint height %v", ErrCheckpoint, hash,
				height, floor)
		default:
			return fmt.Errorf("checkpoint header lookup: %w", err)
		}
	}

	return nil
}
