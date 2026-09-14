package main

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var accessList = []types.AccessTuple{
	types.AccessTuple{
		Address:     common.HexToAddress("0xed94c848bee8df6bc65456064eee602619b0cea0"),
		StorageKeys: []common.Hash{
			common.HexToHash("0xd18c12b87124f9ceb7e1d3a5d06a5ac92ecab15931417e8d1558d9a263f99d63")
		},
	},
}

func EIP7981_RejectsInsufficientGasLimit(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	accessListBytes := 0
	for _, a := range accessList {
		accessListBytes += 1280
		for range a.StorageKeys {
			accessListBytes += 2048
		}
	}

	data := nonZeroByteData(10_000)
	minRequired := txBaseCost + floorCost(data) + uint64(64*accessListBytes)

	// One gas below the required minimum must be rejected.
	h.sendExpectingRejectionWithAccessList(&dummyRecipient, data, minRequired-1)

	// Sanity check: the same transaction at exactly the required minimum
	// must be accepted and mined successfully.
	receipt := h.send(&dummyRecipient, data, minRequired)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("transaction at exactly the minimum required gas limit (%d) failed (status=%d)",
			minRequired, receipt.Status)
	}
	if receipt.GasUsed != minRequired {
		t.Fatalf("gasUsed = %d, want %d", receipt.GasUsed, minRequired)
	}
}

func (h *harness) sendExpectingRejectionWithAccessList(to *common.Address, data []byte, gasLimit uint64) {
	h.t.Helper()

	nonce, err := h.client.PendingNonceAt(h.ctx, h.from)
	if err != nil {
		h.t.Fatalf("fetching nonce: %v", err)
	}

	tx := types.NewTx(&types.AccessListTx{
		Nonce:      nonce,
		To:         to,
		Value:      big.NewInt(1),
		Gas:        gasLimit,
		GasPrice:   h.gasPrice,
		Data:       data,
		AccessList: accessList,
	})
	signer := types.LatestSignerForChainID(h.chainID)
	signedTx, err := types.SignTx(tx, signer, h.key)
	if err != nil {
		h.t.Fatalf("signing tx: %v", err)
	}

	err = h.client.SendTransaction(h.ctx, signedTx)
	if err == nil {
		h.t.Logf("expected node to reject tx with gas limit %d below the "+
			"EIP-7981 floor, but it was accepted (hash %s)", gasLimit, signedTx.Hash())
	}
	// Rejected before entering the pool: nonce was not consumed.
}
