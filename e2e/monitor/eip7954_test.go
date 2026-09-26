package main

import (
	"crypto/ecdsa"
	"testing"
)

// EIP7954_LargerMaxCodeSize checks for EIP-7954 (max code size increased from
// 24576 to 65536 bytes): a contract one byte over the old limit must deploy.
func EIP7954_LargerMaxCodeSize(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	const codeSize = 24577 // 0x6001, one byte above the old limit

	contract := h.deploy([]byte{
		0x61, 0x60, 0x01, // PUSH2 codeSize
		0x60, 0x00, // PUSH1 0
		0xf3, // RETURN (codeSize zero bytes of fresh memory)
	}, 45_000_000) // EIP-8037 charges 1530 gas per deployed code byte

	code, err := h.client.CodeAt(h.ctx, contract, nil)
	if err != nil {
		t.Fatalf("fetching code: %v", err)
	}
	if len(code) != codeSize {
		t.Fatalf("deployed code size = %d, want %d", len(code), codeSize)
	}
}
