package main

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// EIP8037_NewAccountCost checks for EIP-8037 (state creation gas cost
// increase): deploying a contract must pay for the new account
// (120 * 1530 = 183600 gas) plus 1530 gas per deployed code byte, far more
// than the ~53000 it previously cost.
func EIP8037_NewAccountCost(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	const (
		costPerStateByte    uint64 = 1530
		accountCreationSize uint64 = 120
		minCost                    = (accountCreationSize + 1) * costPerStateByte
	)

	// Deploys a 1 byte runtime (0x00).
	receipt := h.send(nil, []byte{
		0x60, 0x01, // PUSH1 1
		0x60, 0x00, // PUSH1 0
		0xf3, // RETURN
	}, 1_000_000)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("contract deployment failed (tx %s)", receipt.TxHash)
	}
	if receipt.GasUsed < minCost {
		t.Fatalf("gasUsed = %d, want at least %d", receipt.GasUsed, minCost)
	}
}
