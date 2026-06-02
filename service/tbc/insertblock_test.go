// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

func TestInsertBlockSanityCheck(t *testing.T) {
	s := &Server{
		cfg: &Config{
			BlockSanity: true,
		},
		timeSource: blockchain.NewMedianTime(),
	}
	s.g.chain = &chaincfg.TestNet3Params

	ctx := context.Background()

	// A block with no transactions fails CheckBlockSanity.
	invalidBlock := btcutil.NewBlock(wire.NewMsgBlock(&wire.BlockHeader{}))

	_, err := s.insertBlock(ctx, invalidBlock)
	if err == nil {
		t.Fatal("expected insertBlock to reject invalid block")
	}
	if !strings.Contains(err.Error(), "insert block sanity check") {
		t.Fatalf("expected sanity check error, got: %v", err)
	}
}
