// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
	"github.com/hemilabs/heminetwork/v2/lru"
)

// validateCheckpoints checks that a checkpoint list is sorted high to
// low, ends at genesis, and has no gap larger than CheckpointInterval.
func validateCheckpoints(cps []chaincfg.Checkpoint, genesis *chainhash.Hash) error {
	if len(cps) == 0 {
		return errors.New("no checkpoints")
	}
	last := cps[len(cps)-1]
	if last.Height != 0 || !last.Hash.IsEqual(genesis) {
		return fmt.Errorf("last checkpoint %v %v is not genesis",
			last.Height, last.Hash)
	}
	for i := 1; i < len(cps); i++ {
		hi, lo := cps[i-1].Height, cps[i].Height
		if hi <= lo {
			return fmt.Errorf("checkpoint %v not above %v", hi, lo)
		}
		if hi-lo > CheckpointInterval {
			return fmt.Errorf("gap %v-%v larger than %v", lo, hi,
				CheckpointInterval)
		}
	}
	return nil
}

func TestCheckpointLists(t *testing.T) {
	tests := []struct {
		name    string
		cps     []chaincfg.Checkpoint
		genesis *chainhash.Hash
	}{
		{"mainnet", mainnetCheckpoints, chaincfg.MainNetParams.GenesisHash},
		{"testnet4", testnet4Checkpoints, chaincfg.TestNet4Params.GenesisHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateCheckpoints(tt.cps, tt.genesis); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateCheckpointsRejects(t *testing.T) {
	genesis := chaincfg.MainNetParams.GenesisHash
	other := &chainhash.Hash{0x01}
	tests := []struct {
		name string
		cps  []chaincfg.Checkpoint
	}{
		{"empty", nil},
		{"no genesis", []chaincfg.Checkpoint{{Height: 25000, Hash: other}}},
		{"wrong genesis hash", []chaincfg.Checkpoint{{Height: 0, Hash: other}}},
		{"low to high", []chaincfg.Checkpoint{
			{Height: 0, Hash: other},
			{Height: 25000, Hash: other},
			{Height: 0, Hash: genesis},
		}},
		{"gap too large", []chaincfg.Checkpoint{
			{Height: CheckpointInterval + 1, Hash: other},
			{Height: 0, Hash: genesis},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateCheckpoints(tt.cps, genesis); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestHeaderCacheSize checks that a header cache of HeaderCacheSize
// holds two checkpoint intervals of headers, with the cost the database
// uses, and not one header more.
func TestHeaderCacheSize(t *testing.T) {
	c, err := lru.New[chainhash.Hash, *tbcd.BlockHeader](HeaderCacheSize,
		func(chainhash.Hash, *tbcd.BlockHeader) int {
			return level.BlockHeaderCacheCost
		}, 0)
	if err != nil {
		t.Fatal(err)
	}
	const want = 2 * CheckpointInterval
	for i := range want + 1 {
		var h chainhash.Hash
		binary.BigEndian.PutUint64(h[:], uint64(i))
		c.Put(h, &tbcd.BlockHeader{Height: uint64(i)})
		if i == want-1 && c.Len() != want {
			t.Fatalf("cache holds %v headers, want %v", c.Len(), want)
		}
	}
	if c.Len() != want {
		t.Fatalf("cache holds %v headers after one more, want %v",
			c.Len(), want)
	}
}
