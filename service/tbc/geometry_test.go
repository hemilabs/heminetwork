// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
	"github.com/hemilabs/heminetwork/v2/hemi"
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

func insertInChain(ctx context.Context, db tbcd.Database, prevBlockHash chainhash.Hash, height, nonce uint64, l2Keystone *tbcd.Keystone) (chainhash.Hash, error) {
	// t.Logf("prevBlockHash = %v, height = %d", prevBlockHash, h)
	wireHeader := wire.BlockHeader{
		Version: 1,
		Nonce:   uint32(nonce), // something unique so there are no collisions
		Bits:    uint32(0x1d00ffff),
	}
	wireHeader.PrevBlock = prevBlockHash

	msgHeaders := wire.NewMsgHeaders()
	if err := msgHeaders.AddBlockHeader(&wireHeader); err != nil {
		return prevBlockHash, err
	}
	wireBlock := wire.MsgBlock{
		Header: wireHeader,
	}

	block := btcutil.NewBlock(&wireBlock)
	if height == 0 {
		err := db.BlockHeaderGenesisInsert(ctx, wireHeader, 0, nil)
		if err != nil {
			return prevBlockHash, err
		}
	} else {
		_, _, _, _, err := db.BlockHeadersInsert(ctx, msgHeaders, nil)
		if err != nil {
			return prevBlockHash, err
		}
	}

	_, err := db.BlockInsert(ctx, block)
	if err != nil {
		return prevBlockHash, err
	}

	if l2Keystone != nil {
		l2Keystone.BlockHash = *block.Hash()
		kssHash := hemi.L2KeystoneAbrevDeserialize(l2Keystone.AbbreviatedKeystone).Hash()
		if err := db.BlockKeystoneUpdate(ctx, 1, map[chainhash.Hash]tbcd.Keystone{
			*kssHash: *l2Keystone,
		}, *block.Hash()); err != nil {
			return prevBlockHash, err
		}
	}
	prevBlockHash = wireHeader.BlockHash()

	return prevBlockHash, nil
}

func TestIndexLinearity(t *testing.T) {
	const blockCount = 10
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer func() {
		cancel()
	}()

	home := t.TempDir()
	t.Logf("temp: %v", home)

	cfg, err := level.NewConfig("localnet", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := db.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	blockHashes := make([]chainhash.Hash, 0, blockCount)
	var prevBlockHash chainhash.Hash
	for i := range blockCount {
		t.Logf("prevBlockHash = %v, height = %d", prevBlockHash, i)
		lastHash, err := insertInChain(ctx, db, prevBlockHash, uint64(i), uint64(i), nil)
		if err != nil {
			t.Fatal(err)
		}
		prevBlockHash = lastHash
		blockHashes = append(blockHashes, lastHash)
	}

	g := geometryParams{
		db:    db,
		chain: &chaincfg.RegressionNetParams,
	}

	// Check if linear
	lin, err := indexIsLinear(ctx, g, blockHashes[0], blockHashes[len(blockHashes)-1])
	if err != nil {
		t.Fatal(err)
	}
	if lin != 1 {
		t.Fatal("index not linear")
	}

	lin, err = indexIsLinear(ctx, g, blockHashes[len(blockHashes)-1], blockHashes[0])
	if err != nil {
		t.Fatal(err)
	}
	if lin != -1 {
		t.Fatal("index not linear")
	}

	// check if NOT linear
	lastHash, err := insertInChain(ctx, db, blockHashes[len(blockHashes)-2], uint64(blockCount), uint64(blockCount+1), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = indexIsLinear(ctx, g, blockHashes[len(blockHashes)-1], lastHash)
	if !errors.Is(err, NotLinearError("")) {
		t.Fatal(err)
	}
}
