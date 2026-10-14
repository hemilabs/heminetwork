// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/level"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// checkHeaderReaders reads the database like a reader that takes no lock.
// It returns an error when a height entry has no header, or when the
// canonical tip has no height entry.
func checkHeaderReaders(ctx context.Context, db *ldb) error {
	it := db.pool[level.HeightHashDB].NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		height, hash := keyToHeightHash(it.Key())
		if _, err := db.BlockHeaderByHash(ctx, *hash); err != nil {
			return fmt.Errorf("height %v entry %v: %w", height, hash, err)
		}
	}
	if err := it.Error(); err != nil {
		return err
	}

	best, err := db.BlockHeaderBest(ctx)
	if err != nil {
		return fmt.Errorf("best: %w", err)
	}
	ok, err := db.pool[level.HeightHashDB].Has(heightHashToKey(best.Height,
		best.Hash[:]), nil)
	if err != nil {
		return fmt.Errorf("tip height entry: %w", err)
	}
	if !ok {
		return fmt.Errorf("tip %v has no entry at height %v", best.Hash,
			best.Height)
	}
	return nil
}

// TestBlockHeadersInsertCommitOrder checks that no reader can see a height
// entry before its header, or a canonical tip before its height entry,
// between the commits of BlockHeadersInsert.  The commits go to separate
// databases and readers take no lock, so the order of the commits is all
// that protects them.  On testnet4 the indexer read a fork header's height
// entry before the header was committed, and panicked.
func TestBlockHeadersInsertCommitOrder(t *testing.T) {
	ctx := t.Context()
	db := createOrdinalDB(ctx, t)

	genesis := createTestBlock(&chainhash.Hash{}, 0)
	if err := db.BlockHeaderGenesisInsert(ctx, genesis.MsgBlock().Header, 0,
		nil); err != nil {
		t.Fatal(err)
	}
	a := createTestBlock(genesis.Hash(), 1)
	b := createTestBlock(genesis.Hash(), 2) // fork of a, same height
	c := createTestBlock(a.Hash(), 3)       // extends a, moves the tip

	tests := []struct {
		name   string
		header *wire.BlockHeader
		want   tbcd.InsertType
	}{
		{"chain extend", &a.MsgBlock().Header, tbcd.ITChainExtend},
		{"fork at the same height", &b.MsgBlock().Header, tbcd.ITForkExtend},
		{"chain extend past the fork", &c.MsgBlock().Header, tbcd.ITChainExtend},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var commits []string
			headersInsertCommitted = func(name string) {
				commits = append(commits, name)
				if err := checkHeaderReaders(ctx, db); err != nil {
					t.Errorf("after %v commit: %v", name, err)
				}
			}
			t.Cleanup(func() { headersInsertCommitted = nil })

			msg := wire.NewMsgHeaders()
			if err := msg.AddBlockHeader(tt.header); err != nil {
				t.Fatal(err)
			}
			it, _, _, _, err := db.BlockHeadersInsert(ctx, msg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if it != tt.want {
				t.Fatalf("insert type %v, want %v", it, tt.want)
			}
			// Every database the insert writes must have committed
			// through the hook, or the checks above did not run.
			if len(commits) < 3 {
				t.Fatalf("checked after %v, want every commit", commits)
			}
		})
	}
}
