package tbc

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/go-test/deep"
)

func TestNewKeystoneIndexer(t *testing.T) {
	type testTableItem struct {
		name        string
		hemiGenesis *HashHeight
	}

	testTable := []testTableItem{
		testTableItem{
			name: "Non-nil hemi index",
			hemiGenesis: &HashHeight{
				Hash:      *mustNewHashFromStr(t, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
				Height:    66,
				Timestamp: 9999,
			},
		},
		testTableItem{
			name:        "Non-nil hemi index",
			hemiGenesis: nil,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			indexer := NewKeystoneIndexer(geometryParams{}, 0, false, tti.hemiGenesis).(*keystoneIndexer)

			if tti.hemiGenesis != indexer.indexerCommon.genesis {
				t.Fatal("indexer geneis pointer is not the same as the parameter")
			}

			if diff := deep.Equal(tti.hemiGenesis, indexer.indexerCommon.genesis); len(diff) != 0 {
				t.Fatalf("different genesis on indexer: %s", diff)
			}
		})
	}
}

func mustNewHashFromStr(t *testing.T, hash string) *chainhash.Hash {
	ret, err := chainhash.NewHashFromStr(hash)
	if err != nil {
		t.Fatalf("error calling NewHashFromStr: %s", err)
	}

	return ret
}
