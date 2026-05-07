// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gozer

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
)

func TestFilterSpent(t *testing.T) {
	h1 := chainhash.HashH([]byte("tx1"))
	h2 := chainhash.HashH([]byte("tx2"))
	h3 := chainhash.HashH([]byte("tx3"))

	utxos := []*tbcapi.MempoolUTXO{
		{TxId: h1, OutIndex: 0, Value: 1000},
		{TxId: h1, OutIndex: 1, Value: 2000},
		{TxId: h2, OutIndex: 0, Value: 3000},
		{TxId: h3, OutIndex: 0, Value: 4000},
	}

	t.Run("no spent", func(t *testing.T) {
		result := FilterSpent(utxos, nil)
		if len(result) != 4 {
			t.Fatalf("got %d, want 4", len(result))
		}
	})

	t.Run("one spent", func(t *testing.T) {
		spent := []tbcapi.OutPoint{{Hash: h1, Index: 0}}
		result := FilterSpent(utxos, spent)
		if len(result) != 3 {
			t.Fatalf("got %d, want 3", len(result))
		}
		for _, u := range result {
			if u.TxId == h1 && u.OutIndex == 0 {
				t.Fatal("spent utxo should be excluded")
			}
		}
	})

	t.Run("multiple spent", func(t *testing.T) {
		spent := []tbcapi.OutPoint{
			{Hash: h1, Index: 0},
			{Hash: h2, Index: 0},
		}
		result := FilterSpent(utxos, spent)
		if len(result) != 2 {
			t.Fatalf("got %d, want 2", len(result))
		}
		var total int64
		for _, u := range result {
			total += int64(u.Value)
		}
		if total != 6000 {
			t.Errorf("total = %d, want 6000", total)
		}
	})

	t.Run("all spent", func(t *testing.T) {
		spent := []tbcapi.OutPoint{
			{Hash: h1, Index: 0},
			{Hash: h1, Index: 1},
			{Hash: h2, Index: 0},
			{Hash: h3, Index: 0},
		}
		result := FilterSpent(utxos, spent)
		if len(result) != 0 {
			t.Fatalf("got %d, want 0", len(result))
		}
	})
}
