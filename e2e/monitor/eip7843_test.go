package main

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// EIP7843_Slotnum checks for EIP-7843 (SLOTNUM opcode): a contract storing
// the result of SLOTNUM (0x4b) must record the slot number of the block the
// call was included in.
func EIP7843_Slotnum(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	contract := h.deploy(initcodeFor(nil, []byte{
		0x4b,       // SLOTNUM
		0x60, 0x00, // PUSH1 0
		0x55, // SSTORE
		0x00, // STOP
	}), 1_000_000)

	receipt := h.send(&contract, nil, 500_000)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("call executing SLOTNUM failed (tx %s)", receipt.TxHash)
	}

	stored, err := h.client.StorageAt(h.ctx, contract, common.Hash{}, receipt.BlockNumber)
	if err != nil {
		t.Fatalf("reading storage: %v", err)
	}

	block := h.rawBlock(receipt.BlockNumber)
	slot := h.rawBlockUint64(block, "slotNumber")

	if got := new(big.Int).SetBytes(stored); got.Cmp(new(big.Int).SetUint64(slot)) != 0 {
		t.Fatalf("SLOTNUM = %v, want block slotNumber %d", got, slot)
	}
}
