package main

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// EIP2780_SelfTransferIntrinsic checks for EIP-2780 (reduced intrinsic
// transaction gas): a value transfer to oneself only costs TX_BASE_COST
// (12000), where it previously cost 21000.
func EIP2780_SelfTransferIntrinsic(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	const selfTransferGas uint64 = 12000

	receipt := h.send(&h.from, nil, selfTransferGas)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("self transfer with gas limit %d failed (tx %s)", selfTransferGas, receipt.TxHash)
	}
	if receipt.GasUsed != selfTransferGas {
		t.Fatalf("gasUsed = %d, want %d", receipt.GasUsed, selfTransferGas)
	}
}
