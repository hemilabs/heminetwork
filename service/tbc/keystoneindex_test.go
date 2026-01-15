// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
)

func TestNewKeystoneIndexer(t *testing.T) {
	type testTableItem struct {
		name        string
		hemiGenesis *HashHeight
	}

	testTable := []testTableItem{
		{
			name: "Non-nil hemi genesis",
			hemiGenesis: &HashHeight{
				Hash:      *testutil.String2Hash("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
				Height:    66,
				Timestamp: 9999,
			},
		},
		{
			name:        "nil hemi genesis",
			hemiGenesis: nil,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			indexer := NewKeystoneIndexer(geometryParams{}, 0, false, tti.hemiGenesis).(*keystoneIndexer)

			if tti.hemiGenesis != indexer.genesis {
				t.Fatal("indexer geneis pointer is not the same as the parameter")
			}

			if diff := deep.Equal(tti.hemiGenesis, indexer.genesis); len(diff) != 0 {
				t.Fatalf("different genesis on indexer: %s", diff)
			}
		})
	}
}

// createTestBlockWithKeystone creates a Bitcoin block containing a PoP transaction
// with the given L2Keystone.
func createTestBlockWithKeystone(t *testing.T, blockHeight int32, l2Keystone hemi.L2Keystone) *btcutil.Block {
	t.Helper()

	// Create the PoP transaction with the keystone
	popTx := pop.TransactionL2{
		L2Keystone: hemi.L2KeystoneAbbreviate(l2Keystone),
	}

	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		t.Fatalf("failed to encode PoP transaction: %v", err)
	}

	// Create a coinbase transaction (required for a valid block)
	coinbaseTx := wire.NewMsgTx(wire.TxVersion)
	coinbaseTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: 0xffffffff,
		},
		SignatureScript: []byte{0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x04},
		Sequence:        0xffffffff,
	})
	coinbaseTx.AddTxOut(&wire.TxOut{
		Value:    5000000000,
		PkScript: []byte{0x76, 0xa9, 0x14}, // Simplified P2PKH prefix
	})

	// Create a PoP transaction (non-coinbase) that contains the keystone
	popMsgTx := wire.NewMsgTx(wire.TxVersion)
	// Add a dummy input (not a coinbase)
	popMsgTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash(testutil.FillBytes("prevhash", 32)),
			Index: 0,
		},
		SignatureScript: []byte{0x00},
		Sequence:        0xffffffff,
	})
	// Add output with PoP OP_RETURN data
	popMsgTx.AddTxOut(&wire.TxOut{
		Value:    0,
		PkScript: popTxOpReturn,
	})

	// Create the block header
	prevBlockHash := chainhash.Hash(testutil.FillBytes("prevblock", 32))
	merkleRoot := chainhash.Hash(testutil.FillBytes("merkleroot", 32))
	header := wire.NewBlockHeader(1, &prevBlockHash, &merkleRoot, 0, 0)

	// Create the wire.MsgBlock
	msgBlock := wire.NewMsgBlock(header)
	msgBlock.AddTransaction(coinbaseTx)
	msgBlock.AddTransaction(popMsgTx)

	// Create btcutil.Block and set height
	block := btcutil.NewBlock(msgBlock)
	block.SetHeight(blockHeight)

	return block
}

func TestBlockKeystonesByHash_BlockHeight(t *testing.T) {
	type testCase struct {
		name        string
		blockHeight int32 // BTC block height where PoP tx was mined
	}

	testCases := []testCase{
		{
			name:        "Block height 1000",
			blockHeight: 1000,
		},
		{
			name:        "Block height 1005",
			blockHeight: 1005,
		},
		{
			name:        "High block number",
			blockHeight: 800000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a keystone
			l2Keystone := hemi.L2Keystone{
				Version:            1,
				L1BlockNumber:      1000,
				L2BlockNumber:      100,
				ParentEPHash:       testutil.SHA256([]byte("parent")),
				PrevKeystoneEPHash: testutil.SHA256([]byte("prevks")),
				StateRoot:          testutil.SHA256([]byte("state")),
				EPHash:             testutil.SHA256([]byte("ep")),
			}

			// Create a test block at the specified height with the keystone
			block := createTestBlockWithKeystone(t, tc.blockHeight, l2Keystone)

			// Get the keystone hash for filtering
			keystoneAbrev := hemi.L2KeystoneAbbreviate(l2Keystone)
			keystoneHash := keystoneAbrev.Hash()

			// Call BlockKeystonesByHash
			ktxs := BlockKeystonesByHash(block, keystoneHash)

			// Verify we got exactly one keystone transaction
			if len(ktxs) != 1 {
				t.Fatalf("expected 1 keystone tx, got %d", len(ktxs))
			}

			// Verify BlockHeight is set correctly
			if ktxs[0].BlockHeight != uint(tc.blockHeight) {
				t.Errorf("BlockHeight: expected %d, got %d",
					tc.blockHeight, ktxs[0].BlockHeight)
			}

			// Verify TxIndex is correct (should be 1, as coinbase is at 0)
			if ktxs[0].TxIndex != 1 {
				t.Errorf("TxIndex: expected 1, got %d", ktxs[0].TxIndex)
			}
		})
	}
}

func TestBlockKeystonesByHash_MultipleKeystones(t *testing.T) {
	// Test that multiple keystones in the same block are all returned
	blockHeight := int32(1005)

	// Create two different keystones
	l2Keystone1 := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      1000,
		L2BlockNumber:      100,
		ParentEPHash:       testutil.SHA256([]byte("parent1")),
		PrevKeystoneEPHash: testutil.SHA256([]byte("prevks1")),
		StateRoot:          testutil.SHA256([]byte("state1")),
		EPHash:             testutil.SHA256([]byte("ep1")),
	}

	l2Keystone2 := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      1003,
		L2BlockNumber:      200,
		ParentEPHash:       testutil.SHA256([]byte("parent2")),
		PrevKeystoneEPHash: testutil.SHA256([]byte("prevks2")),
		StateRoot:          testutil.SHA256([]byte("state2")),
		EPHash:             testutil.SHA256([]byte("ep2")),
	}

	// Create PoP transactions for both keystones
	popTx1 := pop.TransactionL2{L2Keystone: hemi.L2KeystoneAbbreviate(l2Keystone1)}
	popTx2 := pop.TransactionL2{L2Keystone: hemi.L2KeystoneAbbreviate(l2Keystone2)}

	popTxOpReturn1, err := popTx1.EncodeToOpReturn()
	if err != nil {
		t.Fatal(err)
	}
	popTxOpReturn2, err := popTx2.EncodeToOpReturn()
	if err != nil {
		t.Fatal(err)
	}

	// Create coinbase transaction
	coinbaseTx := wire.NewMsgTx(wire.TxVersion)
	coinbaseTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0xffffffff},
		SignatureScript:  []byte{0x04, 0x31, 0xdc, 0x00},
		Sequence:         0xffffffff,
	})
	coinbaseTx.AddTxOut(&wire.TxOut{Value: 5000000000, PkScript: []byte{0x76, 0xa9, 0x14}})

	// Create PoP transaction with BOTH keystones
	popMsgTx := wire.NewMsgTx(wire.TxVersion)
	popMsgTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash(testutil.FillBytes("prevhash", 32)),
			Index: 0,
		},
		SignatureScript: []byte{0x00},
		Sequence:        0xffffffff,
	})
	// Add both PoP outputs
	popMsgTx.AddTxOut(&wire.TxOut{Value: 0, PkScript: popTxOpReturn1})
	popMsgTx.AddTxOut(&wire.TxOut{Value: 0, PkScript: popTxOpReturn2})

	// Create block
	prevBlockHash := chainhash.Hash(testutil.FillBytes("prevblock", 32))
	merkleRoot := chainhash.Hash(testutil.FillBytes("merkleroot", 32))
	header := wire.NewBlockHeader(1, &prevBlockHash, &merkleRoot, 0, 0)
	msgBlock := wire.NewMsgBlock(header)
	msgBlock.AddTransaction(coinbaseTx)
	msgBlock.AddTransaction(popMsgTx)

	block := btcutil.NewBlock(msgBlock)
	block.SetHeight(blockHeight)

	// Call BlockKeystonesByHash with nil hash (get all keystones)
	ktxs := BlockKeystonesByHash(block, nil)

	// Should get both keystones
	if len(ktxs) != 2 {
		t.Fatalf("expected 2 keystone txs, got %d", len(ktxs))
	}

	// Verify BlockHeight is set correctly for all
	for _, ktx := range ktxs {
		if ktx.BlockHeight != uint(blockHeight) {
			t.Errorf("expected BlockHeight %d, got %d", blockHeight, ktx.BlockHeight)
		}
	}

	// Verify each keystone can be queried by hash
	keystone1Abrev := hemi.L2KeystoneAbbreviate(l2Keystone1)
	ktxs1 := BlockKeystonesByHash(block, keystone1Abrev.Hash())
	if len(ktxs1) != 1 {
		t.Fatalf("expected 1 tx for keystone1, got %d", len(ktxs1))
	}

	keystone2Abrev := hemi.L2KeystoneAbbreviate(l2Keystone2)
	ktxs2 := BlockKeystonesByHash(block, keystone2Abrev.Hash())
	if len(ktxs2) != 1 {
		t.Fatalf("expected 1 tx for keystone2, got %d", len(ktxs2))
	}
}

func TestBlockKeystonesByHash_FilterByHash(t *testing.T) {
	// Test that filtering by hash returns only the matching keystone
	blockHeight := int32(1010)

	// Create two different keystones
	l2Keystone1 := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      1000,
		L2BlockNumber:      100,
		ParentEPHash:       testutil.SHA256([]byte("parent1")),
		PrevKeystoneEPHash: testutil.SHA256([]byte("prevks1")),
		StateRoot:          testutil.SHA256([]byte("state1")),
		EPHash:             testutil.SHA256([]byte("ep1")),
	}

	l2Keystone2 := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      1005,
		L2BlockNumber:      200,
		ParentEPHash:       testutil.SHA256([]byte("parent2")),
		PrevKeystoneEPHash: testutil.SHA256([]byte("prevks2")),
		StateRoot:          testutil.SHA256([]byte("state2")),
		EPHash:             testutil.SHA256([]byte("ep2")),
	}

	// Create PoP transactions
	popTx1 := pop.TransactionL2{L2Keystone: hemi.L2KeystoneAbbreviate(l2Keystone1)}
	popTx2 := pop.TransactionL2{L2Keystone: hemi.L2KeystoneAbbreviate(l2Keystone2)}

	popTxOpReturn1, _ := popTx1.EncodeToOpReturn()
	popTxOpReturn2, _ := popTx2.EncodeToOpReturn()

	// Create block with both keystones
	coinbaseTx := wire.NewMsgTx(wire.TxVersion)
	coinbaseTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0xffffffff},
		SignatureScript:  []byte{0x04, 0x31, 0xdc, 0x00},
		Sequence:         0xffffffff,
	})
	coinbaseTx.AddTxOut(&wire.TxOut{Value: 5000000000, PkScript: []byte{0x76, 0xa9, 0x14}})

	popMsgTx := wire.NewMsgTx(wire.TxVersion)
	popMsgTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash(testutil.FillBytes("prevhash", 32)),
			Index: 0,
		},
		SignatureScript: []byte{0x00},
		Sequence:        0xffffffff,
	})
	popMsgTx.AddTxOut(&wire.TxOut{Value: 0, PkScript: popTxOpReturn1})
	popMsgTx.AddTxOut(&wire.TxOut{Value: 0, PkScript: popTxOpReturn2})

	prevBlockHash := chainhash.Hash(testutil.FillBytes("prevblock", 32))
	merkleRoot := chainhash.Hash(testutil.FillBytes("merkleroot", 32))
	header := wire.NewBlockHeader(1, &prevBlockHash, &merkleRoot, 0, 0)
	msgBlock := wire.NewMsgBlock(header)
	msgBlock.AddTransaction(coinbaseTx)
	msgBlock.AddTransaction(popMsgTx)

	block := btcutil.NewBlock(msgBlock)
	block.SetHeight(blockHeight)

	// Filter by keystone1 hash
	keystone1Abrev := hemi.L2KeystoneAbbreviate(l2Keystone1)
	keystone1Hash := keystone1Abrev.Hash()

	ktxs := BlockKeystonesByHash(block, keystone1Hash)

	// Should get only one keystone
	if len(ktxs) != 1 {
		t.Fatalf("expected 1 keystone tx, got %d", len(ktxs))
	}

	// Verify BlockHeight is correct
	if ktxs[0].BlockHeight != uint(blockHeight) {
		t.Errorf("expected BlockHeight %d, got %d", blockHeight, ktxs[0].BlockHeight)
	}

	// Filter by keystone2 hash
	keystone2Abrev := hemi.L2KeystoneAbbreviate(l2Keystone2)
	keystone2Hash := keystone2Abrev.Hash()

	ktxs = BlockKeystonesByHash(block, keystone2Hash)

	// Should get only one keystone
	if len(ktxs) != 1 {
		t.Fatalf("expected 1 keystone tx, got %d", len(ktxs))
	}

	// Verify BlockHeight is correct
	if ktxs[0].BlockHeight != uint(blockHeight) {
		t.Errorf("expected BlockHeight %d, got %d", blockHeight, ktxs[0].BlockHeight)
	}
}

func TestBlockKeystonesByHash_NoKeystones(t *testing.T) {
	// Test that a block with no keystones returns empty slice
	blockHeight := int32(1000)

	// Create a block with only coinbase (no PoP transactions)
	coinbaseTx := wire.NewMsgTx(wire.TxVersion)
	coinbaseTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0xffffffff},
		SignatureScript:  []byte{0x04, 0x31, 0xdc, 0x00},
		Sequence:         0xffffffff,
	})
	coinbaseTx.AddTxOut(&wire.TxOut{Value: 5000000000, PkScript: []byte{0x76, 0xa9, 0x14}})

	// Add a regular (non-PoP) transaction
	regularTx := wire.NewMsgTx(wire.TxVersion)
	regularTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash(testutil.FillBytes("prevhash", 32)),
			Index: 0,
		},
		SignatureScript: []byte{0x00},
		Sequence:        0xffffffff,
	})
	// Regular P2PKH output (not OP_RETURN)
	regularTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x76, 0xa9, 0x14}})

	prevBlockHash := chainhash.Hash(testutil.FillBytes("prevblock", 32))
	merkleRoot := chainhash.Hash(testutil.FillBytes("merkleroot", 32))
	header := wire.NewBlockHeader(1, &prevBlockHash, &merkleRoot, 0, 0)
	msgBlock := wire.NewMsgBlock(header)
	msgBlock.AddTransaction(coinbaseTx)
	msgBlock.AddTransaction(regularTx)

	block := btcutil.NewBlock(msgBlock)
	block.SetHeight(blockHeight)

	// Call BlockKeystonesByHash with nil (get all)
	ktxs := BlockKeystonesByHash(block, nil)

	if len(ktxs) != 0 {
		t.Errorf("expected 0 keystone txs, got %d", len(ktxs))
	}
}

func TestBlockKeystonesByHash_NonMatchingFilter(t *testing.T) {
	// Test that filtering by non-existent hash returns empty slice
	blockHeight := int32(1005)

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      1000,
		L2BlockNumber:      100,
		ParentEPHash:       testutil.SHA256([]byte("parent")),
		PrevKeystoneEPHash: testutil.SHA256([]byte("prevks")),
		StateRoot:          testutil.SHA256([]byte("state")),
		EPHash:             testutil.SHA256([]byte("ep")),
	}

	block := createTestBlockWithKeystone(t, blockHeight, l2Keystone)

	// Filter by a non-matching hash
	nonMatchingHash := chainhash.Hash(testutil.FillBytes("nonmatching", 32))
	ktxs := BlockKeystonesByHash(block, &nonMatchingHash)

	if len(ktxs) != 0 {
		t.Errorf("expected 0 keystone txs with non-matching filter, got %d", len(ktxs))
	}
}
