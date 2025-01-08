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
	for range 2 {
		l.Put(&tbcd.BlockHeader{
			Hash: hs,
		})
	}
	if len(l.m) > 1 {
		t.Fatalf("duplicate headers not excluded by hash")
	}

	if _, ok := l.Get(&hs); !ok {
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
