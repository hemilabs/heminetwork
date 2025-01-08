package level

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

func intHash(b int) chainhash.Hash {
	return chainhash.Hash{byte(b)}
}

func TestHC(t *testing.T) {

	size := 10
	l := lowIQMapNew(size)

	hs := intHash(0)
	for k := range 2 {
		l.Put(&tbcd.BlockHeader{
			Hash:   hs,
			Height: uint64(k), // using height to differentiate between headers with same hash
		})
	}
	if len(l.m) > 1 {
		t.Fatalf("duplicate headers not excluded by hash")
	}

	if bh, ok := l.Get(&hs); ok {
		if bh.Height != 0 {
			t.Fatalf("existing header overwritten by same hash")
		}
	} else {
		t.Fatalf("failed to retrieve header present in map")
	}

	hs = intHash(1)
	if _, ok := l.Get(&hs); ok {
		t.Fatalf("invalid header retrieved from Map")
	}

	for k := range size + 5 {
		l.Put(&tbcd.BlockHeader{
			Hash: intHash(k),
		})
	}
	if len(l.m) > l.count {
		t.Fatalf("map size exceeded bounds (failed eviction)")
	}

}
