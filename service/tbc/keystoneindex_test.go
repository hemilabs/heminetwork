// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"testing"

	"github.com/go-test/deep"

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
