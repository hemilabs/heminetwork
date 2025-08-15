// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"fmt"
	"testing"

	"github.com/hemilabs/heminetwork/hemi"
)

// TestCreateBtcTx tests the CreateBtcTx function
func TestCreateBtcTx(t *testing.T) {
	// Create test data
	btcHeight := uint64(12345)
	l2Keystone := &hemi.L2Keystone{
		Version:            1,
		L2BlockNumber:      100,
		EPHash:             FillOutBytes("ephash", 32),
		ParentEPHash:       FillOutBytes("parentephash", 32),
		StateRoot:          FillOutBytes("stateroot", 32),
		PrevKeystoneEPHash: FillOutBytes("prevkeystoneephash", 32),
	}
	minerPrivateKeyBytes := FillOutBytes("minerkey", 32)

	// Test CreateBtcTx
	txBytes := CreateBtcTx(t, btcHeight, l2Keystone, minerPrivateKeyBytes)

	// Verify that we got a non-empty transaction
	if len(txBytes) == 0 {
		t.Fatal("CreateBtcTx returned empty transaction")
	}

	// Verify that the transaction has a reasonable size
	// Bitcoin transactions typically have a minimum size
	if len(txBytes) < 100 {
		t.Errorf("Transaction seems too small: %d bytes", len(txBytes))
	}
}

// TestGetBtcTxPkScript tests the GetBtcTxPkScript function
func TestGetBtcTxPkScript(t *testing.T) {
	// Create test data
	btcHeight := uint64(12345)
	l2Keystone := &hemi.L2Keystone{
		Version:            1,
		L2BlockNumber:      100,
		EPHash:             FillOutBytes("ephash", 32),
		ParentEPHash:       FillOutBytes("parentephash", 32),
		StateRoot:          FillOutBytes("stateroot", 32),
		PrevKeystoneEPHash: FillOutBytes("prevkeystoneephash", 32),
	}
	minerPrivateKeyBytes := FillOutBytes("minerkey", 32)

	// Test GetBtcTxPkScript
	pkScript := GetBtcTxPkScript(t, btcHeight, l2Keystone, minerPrivateKeyBytes)

	// Verify that we got a non-empty PkScript
	if len(pkScript) == 0 {
		t.Fatal("GetBtcTxPkScript returned empty PkScript")
	}

	// Verify that the PkScript has a reasonable size
	// PkScripts typically have a minimum size
	if len(pkScript) < 20 {
		t.Errorf("PkScript seems too small: %d bytes", len(pkScript))
	}
}

// TestCreateBtcTxWithDifferentHeights tests CreateBtcTx with different block heights
func TestCreateBtcTxWithDifferentHeights(t *testing.T) {
	l2Keystone := &hemi.L2Keystone{
		Version:            1,
		L2BlockNumber:      100,
		EPHash:             FillOutBytes("ephash", 32),
		ParentEPHash:       FillOutBytes("parentephash", 32),
		StateRoot:          FillOutBytes("stateroot", 32),
		PrevKeystoneEPHash: FillOutBytes("prevkeystoneephash", 32),
	}
	minerPrivateKeyBytes := FillOutBytes("minerkey", 32)

	heights := []uint64{0, 1, 100, 1000, 1000000}

	for _, height := range heights {
		t.Run(fmt.Sprintf("height_%d", height), func(t *testing.T) {
			txBytes := CreateBtcTx(t, height, l2Keystone, minerPrivateKeyBytes)
			if len(txBytes) == 0 {
				t.Fatal("CreateBtcTx returned empty transaction")
			}
		})
	}
}

// TestCreateBtcTxWithDifferentKeystones tests CreateBtcTx with different L2 keystones
func TestCreateBtcTxWithDifferentKeystones(t *testing.T) {
	btcHeight := uint64(12345)
	minerPrivateKeyBytes := FillOutBytes("minerkey", 32)

	keystones := []*hemi.L2Keystone{
		{
			Version:            1,
			L2BlockNumber:      100,
			EPHash:             FillOutBytes("ephash1", 32),
			ParentEPHash:       FillOutBytes("parentephash1", 32),
			StateRoot:          FillOutBytes("stateroot1", 32),
			PrevKeystoneEPHash: FillOutBytes("prevkeystoneephash1", 32),
		},
		{
			Version:            2,
			L2BlockNumber:      200,
			EPHash:             FillOutBytes("ephash2", 32),
			ParentEPHash:       FillOutBytes("parentephash2", 32),
			StateRoot:          FillOutBytes("stateroot2", 32),
			PrevKeystoneEPHash: FillOutBytes("prevkeystoneephash2", 32),
		},
	}

	for i, keystone := range keystones {
		t.Run(fmt.Sprintf("keystone_%d", i), func(t *testing.T) {
			txBytes := CreateBtcTx(t, btcHeight, keystone, minerPrivateKeyBytes)
			if len(txBytes) == 0 {
				t.Fatal("CreateBtcTx returned empty transaction")
			}
		})
	}
}

// TestCreateBtcTxWithDifferentKeys tests CreateBtcTx with different private keys
func TestCreateBtcTxWithDifferentKeys(t *testing.T) {
	btcHeight := uint64(12345)
	l2Keystone := &hemi.L2Keystone{
		Version:            1,
		L2BlockNumber:      100,
		EPHash:             FillOutBytes("ephash", 32),
		ParentEPHash:       FillOutBytes("parentephash", 32),
		StateRoot:          FillOutBytes("stateroot", 32),
		PrevKeystoneEPHash: FillOutBytes("prevkeystoneephash", 32),
	}

	keys := [][]byte{
		FillOutBytes("key1", 32),
		FillOutBytes("key2", 32),
		FillOutBytes("key3", 32),
	}

	for i, key := range keys {
		t.Run(fmt.Sprintf("key_%d", i), func(t *testing.T) {
			txBytes := CreateBtcTx(t, btcHeight, l2Keystone, key)
			if len(txBytes) == 0 {
				t.Fatal("CreateBtcTx returned empty transaction")
			}
		})
	}
}
