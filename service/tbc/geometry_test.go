// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"strconv"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-test/deep"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/testutil"
)

func makeCheckpoints(start, count int) []chaincfg.Checkpoint {
	checkpoints := make([]chaincfg.Checkpoint, 0, count)
	for i := start; i <= start+count; i++ {
		hash := chainhash.Hash(testutil.FillBytes("hash"+strconv.Itoa(i), 32))
		chk := chaincfg.Checkpoint{Height: int32(i), Hash: &hash}
		checkpoints = append(checkpoints, chk)
	}
	return checkpoints
}

func TestCheckpoints(t *testing.T) {
	const (
		start           = 1
		checkpointCount = 10
	)
	checkpoints := makeCheckpoints(start, checkpointCount)
	for _, ch := range checkpoints {
		bh := tbcd.BlockHeader{Height: uint64(ch.Height)}

		// check previous checkpoint
		expected := &checkpoints[0]
		prev := previousCheckpoint(&bh, checkpoints)
		if diff := deep.Equal(*expected, *prev); len(diff) > 0 {
			t.Fatalf("prev checkpoint diff %d: %v", ch.Height, diff)
		}
		prevHeight := previousCheckpointHeight(bh.Height, checkpoints)
		if prevHeight != uint64(expected.Height) {
			t.Fatalf("prev checkpoint: expected %v, got %v", expected.Height, prevHeight)
		}

		// check next checkpoint
		expected = &checkpoints[len(checkpoints)-1]
		next := nextCheckpoint(&bh, checkpoints)
		if diff := deep.Equal(expected, next); len(diff) > 0 {
			t.Fatalf("next checkpoint diff %d: %v", ch.Height, diff)
		}
	}

	// Exceptions
	bh := tbcd.BlockHeader{Height: uint64(0)}
	prev := previousCheckpoint(&bh, checkpoints)
	if prev != nil {
		t.Fatalf("expect nil, got %v", spew.Sdump(prev))
	}
	prevHeight := previousCheckpointHeight(bh.Height, checkpoints)
	if prevHeight != 0 {
		t.Fatalf("expect 0, got %d", prevHeight)
	}

	bh = tbcd.BlockHeader{Height: uint64(checkpointCount + start + 1)}
	next := nextCheckpoint(&bh, checkpoints)
	if next != nil {
		t.Fatalf("expect nil, got %v", spew.Sdump(next))
	}
}
