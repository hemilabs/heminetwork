package main

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var accessList = []types.AccessTuple{
	types.AccessTuple{
		Address: common.HexToAddress("0xed94c848bee8df6bc65456064eee602619b0cea0"),
		StorageKeys: []common.Hash{
			common.HexToHash("0xd18c12b87124f9ceb7e1d3a5d06a5ac92ecab15931417e8d1558d9a263f99d63"),
		},
	},
}

func EIP7981_RejectsInsufficientGasLimit(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	// EIP-7981 data surcharge: 64 gas/byte × 20 bytes per address and
	// 32 bytes per storage key = 1280 and 2048 gas respectively.
	accessListDataCost := 0
	for _, a := range accessList {
		accessListDataCost += 1280
		for range a.StorageKeys {
			accessListDataCost += 2048
		}
	}

	t.Logf("expecting access list total cost to be %d", accessListDataCost)

	data := nonZeroByteData(10_000)
	minRequired := txBaseCost + floorCost(data) + uint64(accessListDataCost)
	t.Log("cost", "minRequired", minRequired, "txBaseCost", txBaseCost, "floorCost", floorCost(data), "accessListCost", uint64(accessListDataCost))

	// One gas below the required minimum must be rejected.
	_, err := h.sendExpectingRejectionWithAccessList(&dummyRecipient, data, minRequired-1)
	if err == nil {
		t.Fatalf("expected an error since gas is blow the minimum required")
	}

	t.Logf("error (expected): %s", err)

	receipt, err := h.sendExpectingRejectionWithAccessList(&dummyRecipient, data, minRequired)
	if err != nil {
		t.Fatalf("received unexpected error: %s", err)
	}

	if receipt.GasUsed != minRequired {
		t.Fatalf("gasUsed = %d, want %d", receipt.GasUsed, minRequired)
	}
}

func (h *harness) sendExpectingRejectionWithAccessList(to *common.Address, data []byte, gasLimit uint64) (*types.Receipt, error) {
	h.t.Helper()

	retries := 10

	for range retries {
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
	
		h.t.Logf("sending transaction %s", signedTx.Hash())
	
		err = h.client.SendTransaction(h.ctx, signedTx)
		if err != nil {
			return nil, err
		}
	
		receipt := waitForTxHashReceiptForSeconds(h.t, h.ctx, h.client, signedTx.Hash(), 13*time.Second)
		if receipt != nil {
			return receipt, nil
		}
	}

	return nil, errors.New("retries exceeded")
}
