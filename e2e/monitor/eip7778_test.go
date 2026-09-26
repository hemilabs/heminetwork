package main

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// EIP7778_BlockGasIgnoresRefunds checks for EIP-7778 (block gas accounting
// without refunds): for a transaction that earns a storage refund, the block
// gas used counts the gas before the refund, so it is larger than the
// receipt's gas used.
//
// Other transactions in the same block would also count towards the block
// gas used, so the check is only done once the transaction lands in a block
// on its own.
func EIP7778_BlockGasIgnoresRefunds(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	// The constructor sets slot 0 to 1, the runtime clears it again, which
	// earns a storage clear refund.
	initcode := initcodeFor(
		[]byte{
			0x60, 0x01, // PUSH1 1
			0x60, 0x00, // PUSH1 0
			0x55, // SSTORE
		},
		[]byte{
			0x60, 0x00, // PUSH1 0
			0x60, 0x00, // PUSH1 0
			0x55, // SSTORE
			0x00, // STOP
		},
	)

	attempts := 10
	for range attempts {
		contract := h.deploy(initcode, 1_000_000)

		receipt := h.send(&contract, nil, 500_000)
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("call clearing storage failed (tx %s)", receipt.TxHash)
		}

		block := h.rawBlock(receipt.BlockNumber)
		txs, _ := block["transactions"].([]any)
		if len(txs) != 1 {
			t.Logf("block %v has %d transactions, retrying", receipt.BlockNumber, len(txs))
			continue
		}

		blockGasUsed := h.rawBlockUint64(block, "gasUsed")
		if blockGasUsed <= receipt.GasUsed {
			t.Fatalf("block gasUsed = %d, want more than refunded receipt gasUsed %d",
				blockGasUsed, receipt.GasUsed)
		}
		return
	}
	t.Fatalf("transaction never landed in a block on its own after %d attempts", attempts)
}
