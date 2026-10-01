// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

// TestVerifyHeaderContextAcceptOverFaultedWalkIsRetryable checks that a header
// that passes over a faulted ancestor walk still fails with the ancestor-walk
// error, since a truncated walk can weaken a rule (e.g. median-time-past over
// fewer ancestors). The child is valid against its parent, the only readable
// ancestor; every deeper lookup faults.
func TestVerifyHeaderContextAcceptOverFaultedWalkIsRetryable(t *testing.T) {
	parentWire := &wire.BlockHeader{
		Version:   0x20000000,
		Bits:      0x1a05db8b,
		Timestamp: time.Unix(1600000000, 0),
		PrevBlock: chainhash.Hash{0xaa}, // grandparent: its lookup faults
	}
	parentHash := parentWire.BlockHash()
	db := &ioErrParentDB{parentHash: parentHash, parent: &tbcd.BlockHeader{
		Hash: parentHash, Height: 100000, Header: h2b(parentWire),
	}}
	s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, db: db}

	child := &wire.BlockHeader{
		Version:   0x20000000,
		PrevBlock: parentHash,
		Bits:      0x1a05db8b,                                  // == parent: difficulty passes
		Timestamp: parentWire.Timestamp.Add(600 * time.Second), // after the truncated MTP
	}
	err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{child})
	if err == nil {
		t.Fatal("a header was ACCEPTED over a faulted ancestor walk; it must be retryable")
	}
	if !strings.Contains(err.Error(), "ancestor walk") {
		t.Fatalf("want the retryable ancestor-walk error, got %v", err)
	}
}

// retargetStubDB resolves a hash-linked ancestor window by hash.
type retargetStubDB struct {
	tbcd.Database
	headers map[chainhash.Hash]*tbcd.BlockHeader
}

func (d *retargetStubDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	if bh, ok := d.headers[h]; ok {
		return bh, nil
	}
	return nil, database.NotFoundError("block header not found")
}

// TestVerifyHeaderContextRetargetBoundary stores a full 2016-header window and
// checks that a child at the retarget height is accepted with the retargeted
// bits btcd computes and rejected with the parent's bits. This exercises the
// 2015-ancestor walk in btcd's calcNextRequiredDifficulty.
func TestVerifyHeaderContextRetargetBoundary(t *testing.T) {
	params := &chaincfg.MainNetParams
	const parentBits = uint32(0x1b0404cb) // harder than difficulty-1
	// Keep the timespan inside the min/max retarget clamp so the new bits
	// depend on the first node's timestamp (height 0). A clamped timespan
	// would hide a walk that stops one ancestor short.
	const spacing = int64(600) // seconds/block

	base := time.Unix(1600000000, 0)
	headers := make(map[chainhash.Hash]*tbcd.BlockHeader, 2016)
	var prevHash chainhash.Hash // height 0's PrevBlock; never looked up (genesisHeight=0)
	var parent *wire.BlockHeader
	var parentHash chainhash.Hash
	for h := 0; h <= 2015; h++ {
		var mr chainhash.Hash
		mr[0], mr[1] = byte(h), byte(h>>8)
		wh := &wire.BlockHeader{
			Version:    1,
			PrevBlock:  prevHash,
			MerkleRoot: mr,
			Bits:       parentBits,
			Timestamp:  base.Add(time.Duration(int64(h)*spacing) * time.Second),
			Nonce:      uint32(h),
		}
		hash := wh.BlockHash()
		headers[hash] = &tbcd.BlockHeader{Hash: hash, Height: uint64(h), Header: h2b(wh)}
		prevHash = hash
		parent = wh
		parentHash = hash
	}

	db := &retargetStubDB{headers: headers}
	s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: params, db: db}

	// Expected bits, computed as btcd's calcNextRequiredDifficulty does.
	chainCtx := &tbcChainCtx{params: params}
	actual := int64(2015) * spacing // lastNode(2015).ts - firstNode(0).ts
	adjusted := actual
	if adjusted < chainCtx.MinRetargetTimespan() {
		adjusted = chainCtx.MinRetargetTimespan()
	} else if adjusted > chainCtx.MaxRetargetTimespan() {
		adjusted = chainCtx.MaxRetargetTimespan()
	}
	newTarget := new(big.Int).Mul(blockchain.CompactToBig(parentBits), big.NewInt(adjusted))
	newTarget.Div(newTarget, big.NewInt(int64(params.TargetTimespan/time.Second)))
	if newTarget.Cmp(params.PowLimit) > 0 {
		newTarget.Set(params.PowLimit)
	}
	expectedBits := blockchain.BigToCompact(newTarget)
	if expectedBits == parentBits {
		t.Fatalf("test setup: retarget did not change the bits (%08x); pick a "+
			"spacing that actually retargets", parentBits)
	}

	mkChild := func(bits uint32) []*wire.BlockHeader {
		return []*wire.BlockHeader{{
			Version:   1,
			PrevBlock: parentHash,
			Bits:      bits,
			Timestamp: parent.Timestamp.Add(time.Duration(spacing) * time.Second),
		}}
	}

	// Correct retargeted difficulty at the boundary must be accepted.
	if err := s.verifyHeaderContext(t.Context(), mkChild(expectedBits)); err != nil {
		t.Fatalf("retarget boundary: correctly-retargeted child rejected: %v", err)
	}
	// The parent's un-retargeted bits must be rejected at the boundary.
	if err := s.verifyHeaderContext(t.Context(), mkChild(parentBits)); err == nil {
		t.Fatal("retarget boundary: un-retargeted (parent) bits accepted at a retarget height")
	}
}
