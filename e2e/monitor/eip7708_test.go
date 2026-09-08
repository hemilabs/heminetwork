package main

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var (
	// EIP-7708 system log emitter and Transfer(address,address,uint256) topic.
	eip7708LogAddress = common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe")
	eip7708LogTopic   = common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
)

// EIP7708_NativeTransferLog checks for EIP-7708 (ETH transfers emit a log):
// a plain value transfer must produce an ERC-20 style Transfer log emitted by
// the system address.
func EIP7708_NativeTransferLog(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	// Generous limit in case the recipient is still empty and EIP-8037
	// charges for creating it.
	receipt := h.send(&dummyRecipient, nil, 500_000)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("value transfer failed (tx %s)", receipt.TxHash)
	}

	// harness.send always transfers a value of 1 wei.
	wantData := common.BigToHash(big.NewInt(1)).Bytes()
	for _, l := range receipt.Logs {
		if l.Address == eip7708LogAddress &&
			len(l.Topics) == 3 &&
			l.Topics[0] == eip7708LogTopic &&
			l.Topics[1] == common.BytesToHash(h.from.Bytes()) &&
			l.Topics[2] == common.BytesToHash(dummyRecipient.Bytes()) &&
			bytes.Equal(l.Data, wantData) {
			return
		}
	}
	t.Fatalf("no EIP-7708 transfer log in receipt of tx %s (logs: %d)",
		receipt.TxHash, len(receipt.Logs))
}
