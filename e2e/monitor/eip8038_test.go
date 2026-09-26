package main

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// EIP8038_StorageWriteCost checks for EIP-8038 (state access gas cost
// update): changing an existing non-zero storage slot costs
// COLD_STORAGE_ACCESS (2100) + STORAGE_WRITE (10000), where it previously
// cost 2100 + 2900.
func EIP8038_StorageWriteCost(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	// The constructor sets slot 0 to 1, the runtime changes it to 2.
	contract := h.deploy(initcodeFor(
		[]byte{
			0x60, 0x01, // PUSH1 1
			0x60, 0x00, // PUSH1 0
			0x55, // SSTORE
		},
		[]byte{
			0x60, 0x02, // PUSH1 2
			0x60, 0x00, // PUSH1 0
			0x55, // SSTORE
			0x00, // STOP
		},
	), 1_000_000)

	receipt := h.send(&contract, nil, 500_000)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("call writing storage failed (tx %s)", receipt.TxHash)
	}

	// The transaction base cost of a value transfer to an existing account
	// is 21000 both before and after EIP-2780.
	const minCost = txBaseCost + 2100 + 10000
	if receipt.GasUsed < minCost {
		t.Fatalf("gasUsed = %d, want at least %d", receipt.GasUsed, minCost)
	}
}
