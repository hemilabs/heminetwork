package main

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// EIP7928_BlockAccessListHash checks for EIP-7928 (block-level access lists):
// block headers must carry a blockAccessListHash field.
func EIP7928_BlockAccessListHash(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	number, err := h.client.BlockNumber(h.ctx)
	if err != nil {
		t.Fatalf("fetching block number: %v", err)
	}

	block := h.rawBlock(new(big.Int).SetUint64(number))

	s, ok := block["blockAccessListHash"].(string)
	if !ok {
		t.Fatalf("block %d has no blockAccessListHash: %v", number, block["blockAccessListHash"])
	}
	hash, err := hexutil.Decode(s)
	if err != nil {
		t.Fatalf("decoding blockAccessListHash %q: %v", s, err)
	}
	if len(hash) != 32 {
		t.Fatalf("blockAccessListHash is %d bytes, want 32", len(hash))
	}
}
