package main

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
)

// EIP8024_Exchange checks for EIP-8024 (DUPN, SWAPN and EXCHANGE): EXCHANGE
// (0xe8) with immediate 0x8d decodes to (n, m) = (1, 3) and swaps the 2nd
// and 4th stack items.
func EIP8024_Exchange(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	contract := h.deploy(initcodeFor(nil, []byte{
		0x60, 0x01, // PUSH1 1
		0x60, 0x02, // PUSH1 2
		0x60, 0x03, // PUSH1 3
		0x60, 0x04, // PUSH1 4, stack (top first): 4 3 2 1
		0xe8, 0x8d, // EXCHANGE 1 3, stack (top first): 4 1 2 3
		0x60, 0x00, 0x52, // MSTORE at 0x00
		0x60, 0x20, 0x52, // MSTORE at 0x20
		0x60, 0x40, 0x52, // MSTORE at 0x40
		0x60, 0x60, 0x52, // MSTORE at 0x60
		0x60, 0x80, // PUSH1 0x80
		0x60, 0x00, // PUSH1 0
		0xf3, // RETURN
	}), 1_000_000)

	ret, err := h.client.CallContract(h.ctx, ethereum.CallMsg{
		From: h.from,
		To:   &contract,
	}, nil)
	if err != nil {
		t.Fatalf("calling EXCHANGE contract: %v", err)
	}
	if len(ret) != 4*32 {
		t.Fatalf("returned %d bytes, want %d", len(ret), 4*32)
	}

	want := []int64{4, 1, 2, 3}
	for i, w := range want {
		if got := new(big.Int).SetBytes(ret[i*32 : (i+1)*32]); got.Int64() != w {
			t.Fatalf("stack item %d = %v, want %d (returned %x)", i, got, w, ret)
		}
	}
}
