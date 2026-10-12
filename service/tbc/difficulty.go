// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/big"
	"slices"
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

// VerifyCheckpoint always returns true: tbc calls CheckBlockHeaderContext with
// skipCheckpoint=true and enforces checkpoints in verifyHeaderCheckpoints.
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

// ErrCheckpoint is returned when a header batch contradicts the chain
// checkpoints, or builds on stored headers that cannot be on the checkpointed
// chain.
var ErrCheckpoint = errors.New("checkpoint violation")

// checkpointAt returns the checkpoint at height, or nil.
func checkpointAt(height uint64, cps []checkpoint) *checkpoint {
	for k := range cps {
		if cps[k].height == height {
			return &cps[k]
		}
	}
	return nil
}

// hasEnforcedCheckpoints reports whether verifyHeaderCheckpoints has anything
// to enforce, without building the merged list.
func (s *Server) hasEnforcedCheckpoints() bool {
	return (len(s.checkpoints) > 0 && s.checkpoints[0].height > 0) ||
		len(s.chainParams.Checkpoints) > 0
}

// enforcedCheckpoints returns the checkpoints verifyHeaderCheckpoints
// enforces: tbc's list merged with btcd's for the network, sorted high to low.
// btcd's list is denser at low heights, which narrows the window before the
// first checkpoint during IBD. tbc's list alone still drives the locator,
// isCanonical and the datadir identity check.
func (s *Server) enforcedCheckpoints() []checkpoint {
	cps := slices.Clone(s.checkpoints)
	for _, c := range s.chainParams.Checkpoints {
		if c.Height <= 0 || c.Hash == nil || checkpointAt(uint64(c.Height), cps) != nil {
			continue
		}
		cps = append(cps, checkpoint{height: uint64(c.Height), hash: *c.Hash})
	}
	slices.SortFunc(cps, func(a, b checkpoint) int { return cmp.Compare(b.height, a.height) })
	return cps
}

// verifyHeaderCheckpoints rejects a batch of connected headers that
// contradicts the chain checkpoints. A header at a checkpoint height must
// carry the checkpoint hash, and a header we do not already have must not sit
// at or below the highest enforced checkpoint we store at its own height:
// that is a fork off a checkpointed part of the chain.
//
// The floor depends only on which checkpoints we store, not on the best
// header, as with Bitcoin Core's GetLastCheckpoint. A best header on a junk
// fork can therefore neither raise the floor above canonical headers we still
// need nor hold it below checkpoints we already store. A checkpoint stored at
// its height means its whole ancestry is stored, so the floor never rejects an
// honest header. That holds for stores written by binaries that check batch
// contiguity; a store a peer poisoned under a version that did not may need a
// resync.
//
// Headers we already have pass the floor rule, so a peer that resends known
// canonical headers is not penalized. The hash rule applies to every header in
// a checked batch, stored or not, and is relied on: it stops a batch whose
// parent is below the floor from re-entering a fork stored across the floor,
// where the descent guard does not run. A batch whose headers are all stored is not
// checked at all (see handleHeaders). Unlike Core and btcd, the stored chain a
// batch builds on is checked too, but only by height and by a work bound (see
// below), not by ancestry: a fork already stored across a checkpoint height
// can keep growing up to the next enforced checkpoint if it branches at or
// above the floor, or carries enough work, as a PowLimit fork does wherever
// honest difficulty is at PowLimit (mainnet below 32,256, testnet3).
//
// Without this check a peer can feed a low-work fork from genesis that passes
// every other header check. Every header in it adds a blocks-missing entry
// that no honest peer can serve, and block download stalls on them.
// Checkpoints only bound such a fork: one that branches at or above the floor
// is admitted up to the next enforced checkpoint, and without limit once the
// top one is stored. Its entries drain only as their downloads expire. A fork
// starts at the difficulty of the header it branches from and can ease it
// fourfold per retarget, so it is costly only where that is high: on mainnet
// the early IBD gaps are cheap (difficulty is 1 below 32,256), and on testnet3
// the 20-minute min-difficulty rule makes it cheap at any height. Such a fork
// can also become best during IBD and stall header sync. Closing this needs
// minimum chain work.
//
// The floor is read outside the insert, so a concurrent insert can only leave
// it low for a batch, which only loosens the check.
func (s *Server) verifyHeaderCheckpoints(ctx context.Context, headers []*wire.BlockHeader) error {
	if len(headers) == 0 || !s.hasEnforcedCheckpoints() {
		return nil
	}
	cps := s.enforcedCheckpoints()

	pbh, err := s.db.BlockHeaderByHash(ctx, headers[0].PrevBlock)
	if err != nil {
		return fmt.Errorf("checkpoint parent lookup: %w", err)
	}
	// The insert skips the stored headers at the start of the batch and
	// continues from the last one's stored height. Require each to sit at its
	// batch height, so the heights checked below are the ones it assigns. A
	// store written by a version that did not check batch contiguity can hold
	// records at other heights.
	for i, hdr := range headers {
		bh, err := s.db.BlockHeaderByHash(ctx, hdr.BlockHash())
		if errors.Is(err, database.ErrNotFound) {
			break
		}
		if err != nil {
			return fmt.Errorf("checkpoint header lookup: %w", err)
		}
		if want := pbh.Height + uint64(i) + 1; bh.Height != want {
			return fmt.Errorf("%w: header %v stored at height %v, batch puts it at %v",
				ErrCheckpoint, bh.Hash, bh.Height, want)
		}
	}
	var (
		floor   uint64
		floorBH *tbcd.BlockHeader
	)
	for _, cp := range cps { // high to low
		if cp.height == 0 {
			continue
		}
		bh, err := s.db.BlockHeaderByHash(ctx, cp.hash)
		if err == nil {
			if bh.Height == cp.height {
				floor, floorBH = cp.height, bh
				break
			}
			continue
		}
		if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("checkpoint lookup: %w", err)
		}
	}

	// A parent at or above the floor that descends from the floor checkpoint
	// has at least the checkpoint's cumulative work plus PowLimit work per
	// height above it, since every header carries at least PowLimit work. A
	// parent with less is on a fork stored across the floor (by an older
	// binary, or through op-geth's unchecked BlockHeadersInsert) and is not
	// extended. This bounds work and does not prove descent. On a store written
	// by binaries that check PoW and batch contiguity it cannot refuse an
	// honest parent; a store a peer poisoned under one that did not can hold a
	// checkpoint record with wrong cumulative work, and needs a resync.
	if floorBH != nil && pbh.Height >= floor {
		minWork := new(big.Int).SetUint64(pbh.Height - floor)
		minWork.Mul(minWork, blockchain.CalcWork(s.chainParams.PowLimitBits))
		minWork.Add(minWork, &floorBH.Difficulty)
		if pbh.Difficulty.Cmp(minWork) < 0 {
			return fmt.Errorf("%w: parent %v at height %v does not descend "+
				"from checkpoint height %v", ErrCheckpoint, pbh.Hash, pbh.Height, floor)
		}
	}

	for i, hdr := range headers {
		height := pbh.Height + uint64(i) + 1
		cp := checkpointAt(height, cps)
		if cp == nil && height > floor {
			continue // neither rule applies; skip the hash
		}
		hash := hdr.BlockHash()
		if cp != nil && !cp.hash.IsEqual(&hash) {
			return fmt.Errorf("%w: header %v at height %v, want %v",
				ErrCheckpoint, hash, height, cp.hash)
		}
		if height > floor {
			continue
		}
		_, err := s.db.BlockHeaderByHash(ctx, hash)
		switch {
		case err == nil:
			// Known header, not a new fork.
		case errors.Is(err, database.ErrNotFound):
			return fmt.Errorf("%w: header %v at height %v forks below "+
				"checkpoint height %v", ErrCheckpoint, hash, height, floor)
		default:
			return fmt.Errorf("checkpoint header lookup: %w", err)
		}
	}
	return nil
}
