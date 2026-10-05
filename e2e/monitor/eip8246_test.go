package main

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// EIP8246_SelfDestructKeepsBalance checks for EIP-8246 (no SELFDESTRUCT
// burn): a contract created with value that self-destructs to itself in the
// same transaction keeps its balance instead of burning it.
func EIP8246_SelfDestructKeepsBalance(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	receipt := h.send(nil, []byte{
		0x30, // ADDRESS
		0xff, // SELFDESTRUCT
	}, 1_000_000)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("self-destructing creation failed (tx %s)", receipt.TxHash)
	}

	balance, err := h.client.BalanceAt(h.ctx, receipt.ContractAddress, receipt.BlockNumber)
	if err != nil {
		t.Fatalf("fetching balance: %v", err)
	}
	// harness.send always transfers a value of 1 wei.
	if balance.Int64() != 1 {
		t.Fatalf("balance of %s = %v, want 1", receipt.ContractAddress, balance)
	}
}
