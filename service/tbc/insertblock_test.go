// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// tbcdHeaderAt builds a tbcd.BlockHeader whose serialized header carries the
// given timestamp.
func tbcdHeaderAt(t *testing.T, ts time.Time) *tbcd.BlockHeader {
	t.Helper()
	wh := wire.NewBlockHeader(1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0)
	wh.Timestamp = ts.Truncate(time.Second)
	var b bytes.Buffer
	if err := wh.Serialize(&b); err != nil {
		t.Fatalf("serialize header: %v", err)
	}
	var raw [80]byte
	copy(raw[:], b.Bytes())
	return &tbcd.BlockHeader{Header: raw}
}

// sanityStub is a tbcd.Database that supports the fields insertBlock and
// BlockInsert touch: BlockInsert (the DB write) and BlockHeaderByHash (the
// parent lookup).
type sanityStub struct {
	stubDB
	parent    *tbcd.BlockHeader
	parentErr error
}

func (s sanityStub) BlockInsert(context.Context, *btcutil.Block) (int64, error) {
	return 1, nil
}

func (s sanityStub) BlockHeaderByHash(_ context.Context, _ chainhash.Hash) (*tbcd.BlockHeader, error) {
	if s.parentErr != nil {
		return nil, s.parentErr
	}
	return s.parent, nil
}

// mineRegtestBlock builds a structurally valid regtest block (one coinbase
// tx, matching merkle root) with the given header timestamp and grinds the
// nonce until it satisfies regtest's (trivial) proof of work.
func mineRegtestBlock(t *testing.T, timestamp time.Time) *btcutil.Block {
	t.Helper()
	params := &chaincfg.RegressionNetParams

	cb := wire.NewMsgTx(wire.TxVersion)
	cb.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex),
		SignatureScript:  []byte{0x00, 0x00},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	cb.AddTxOut(&wire.TxOut{Value: 5000000000, PkScript: []byte{0x51}})
	coinbaseTx := btcutil.NewTx(cb)

	merkle := blockchain.CalcMerkleRoot([]*btcutil.Tx{coinbaseTx}, false)
	header := wire.NewBlockHeader(1, params.GenesisHash, &merkle,
		params.PowLimitBits, 0)
	header.Timestamp = timestamp.Truncate(time.Second)

	target := blockchain.CompactToBig(header.Bits)
	for {
		hash := header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			break
		}
		header.Nonce++
	}

	msgBlock := wire.NewMsgBlock(header)
	if err := msgBlock.AddTransaction(cb); err != nil {
		t.Fatalf("add coinbase: %v", err)
	}
	return btcutil.NewBlock(msgBlock)
}

func emptyBlock() *wire.MsgBlock {
	return wire.NewMsgBlock(&wire.BlockHeader{})
}

func TestInsertBlockSanityMatrix(t *testing.T) {
	now := time.Now()
	// 3h ahead: wall clock rejects (>2h) but parent-anchored check accepts.
	futureTime := now.Add(3 * time.Hour)
	// Parent is 2h ahead: the block is only 1h past the parent (within 2h window).
	parentTime_ := now.Add(2 * time.Hour)

	type test struct {
		name    string
		sanity  bool
		block   func(t *testing.T) *btcutil.Block
		wantErr string // "" means expect success
	}

	// insertBlock path: IBD / genesis — uses s.timeSource (wall clock).
	t.Run("insertBlock", func(t *testing.T) {
		tests := []test{
			{
				name:   "sanity on, valid block, normal timestamp",
				sanity: true,
				block:  func(t *testing.T) *btcutil.Block { return mineRegtestBlock(t, now) },
			},
			{
				name:    "sanity on, valid block, far future timestamp",
				sanity:  true,
				block:   func(t *testing.T) *btcutil.Block { return mineRegtestBlock(t, futureTime) },
				wantErr: "insert block sanity check",
			},
			{
				name:    "sanity on, invalid block (no txs)",
				sanity:  true,
				block:   func(t *testing.T) *btcutil.Block { return btcutil.NewBlock(emptyBlock()) },
				wantErr: "insert block sanity check",
			},
			{
				name:   "sanity off, valid block, normal timestamp",
				sanity: false,
				block:  func(t *testing.T) *btcutil.Block { return mineRegtestBlock(t, now) },
			},
			{
				name:   "sanity off, valid block, far future timestamp",
				sanity: false,
				block:  func(t *testing.T) *btcutil.Block { return mineRegtestBlock(t, futureTime) },
			},
			{
				name:   "sanity off, invalid block (no txs)",
				sanity: false,
				block:  func(t *testing.T) *btcutil.Block { return btcutil.NewBlock(emptyBlock()) },
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s := &Server{
					cfg:        &Config{BlockSanity: tt.sanity},
					timeSource: blockchain.NewMedianTime(),
					notifier:   NewNotifier(false),
				}
				s.g.chain = &chaincfg.RegressionNetParams
				s.g.db = sanityStub{parent: tbcdHeaderAt(t, now)}

				_, err := s.insertBlock(t.Context(), tt.block(t), s.timeSource)
				checkErr(t, err, tt.wantErr)
			})
		}
	})

	// BlockInsert path: RPC / API — anchors to parent time.
	t.Run("BlockInsert", func(t *testing.T) {
		parentPresent := func() sanityStub {
			return sanityStub{parent: tbcdHeaderAt(t, parentTime_)}
		}
		parentMissing := func() sanityStub {
			return sanityStub{parentErr: database.NotFoundError("not found")}
		}

		tests := []struct {
			test
			db func() sanityStub
		}{
			{
				test: test{
					name:   "sanity on, valid future block, parent present",
					sanity: true,
					block:  func(t *testing.T) *btcutil.Block { return mineRegtestBlock(t, futureTime) },
				},
				db: parentPresent,
			},
			{
				test: test{
					name:    "sanity on, invalid block (no txs), parent present",
					sanity:  true,
					block:   func(t *testing.T) *btcutil.Block { return btcutil.NewBlock(emptyBlock()) },
					wantErr: "insert block sanity check",
				},
				db: parentPresent,
			},
			{
				test: test{
					name:    "sanity on, valid block, parent missing",
					sanity:  true,
					block:   func(t *testing.T) *btcutil.Block { return mineRegtestBlock(t, now) },
					wantErr: "block insert parent header",
				},
				db: parentMissing,
			},
			{
				test: test{
					name:   "sanity off, valid future block, parent present",
					sanity: false,
					block:  func(t *testing.T) *btcutil.Block { return mineRegtestBlock(t, futureTime) },
				},
				db: parentPresent,
			},
			{
				test: test{
					name:   "sanity off, invalid block, parent present",
					sanity: false,
					block:  func(t *testing.T) *btcutil.Block { return btcutil.NewBlock(emptyBlock()) },
				},
				db: parentPresent,
			},
			{
				test: test{
					name:    "sanity off, valid block, parent missing",
					sanity:  false,
					block:   func(t *testing.T) *btcutil.Block { return mineRegtestBlock(t, now) },
					wantErr: "block insert parent header",
				},
				db: parentMissing,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s := &Server{
					cfg:        &Config{BlockSanity: tt.sanity},
					timeSource: blockchain.NewMedianTime(),
					notifier:   NewNotifier(false),
				}
				s.g.chain = &chaincfg.RegressionNetParams
				s.g.db = tt.db()

				_, err := s.BlockInsert(t.Context(), tt.block(t).MsgBlock())
				checkErr(t, err, tt.wantErr)
			})
		}
	})
}

func checkErr(t *testing.T, err error, wantSubstr string) {
	t.Helper()
	if wantSubstr == "" {
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", wantSubstr)
	}
	if !errors.Is(err, errors.New(wantSubstr)) {
		// errors.Is won't match substrings; use contains.
		if got := err.Error(); len(got) == 0 || !contains(got, wantSubstr) {
			t.Fatalf("expected error containing %q, got: %v", wantSubstr, err)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
