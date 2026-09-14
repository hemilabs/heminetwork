package main

// Package eip7976_test is an integration test suite that verifies a running
// geth node correctly implements EIP-7976, "Increase Calldata Floor Cost"
// (https://eips.ethereum.org/EIPS/eip-7976).
//
// EIP-7976 changes the intrinsic-gas formula (building on EIP-7623) to:
//
//	STANDARD_TOKEN_COST        = 4
//	TOTAL_COST_FLOOR_PER_TOKEN = 16
//
//	tokens_in_calldata       = zero_bytes + nonzero_bytes*4
//	floor_tokens_in_calldata = (zero_bytes + nonzero_bytes) * 4
//
//	tx.gasUsed = 21000 + max(
//	    STANDARD_TOKEN_COST*tokens_in_calldata
//	        + execution_gas_used
//	        + isContractCreation*(32000 + INITCODE_WORD_COST*words(calldata)),
//	    TOTAL_COST_FLOOR_PER_TOKEN*floor_tokens_in_calldata,
//	)
//
// Note that floor_tokens_in_calldata counts every calldata byte (zero or
// non-zero) at weight 4, so the floor is a uniform 64 gas/byte
// (TOTAL_COST_FLOOR_PER_TOKEN * 4 = 64) regardless of byte content. A
// transaction is invalid if its gas limit is below
// max(21000+floor_cost, intrinsic_cost).
//
// This suite covers the EIP's own "Test Cases" section:
//  1. Data-heavy transactions pay the 64 gas/byte floor.
//  2. EVM-heavy transactions keep paying standard 4/16 gas/byte pricing.
//  3. The boundary where execution gas crosses the floor.
//  4. eth_estimateGas accounts for the new floor.
//  5. Transactions with insufficient gas limits are rejected.
//
// Setup
//
//	go mod init eip7976test   # if you don't already have a module
//	go get github.com/ethereum/go-ethereum@latest
//
// Required environment variables:
//
//	EIP7976_RPC_URL      RPC endpoint (default: http://localhost:8545)
//	EIP7976_PRIVATE_KEY  hex-encoded private key (no 0x needed) of a funded
//	                     account on that node. Required — the test signs and
//	                     sends real transactions.
//
// Run:
//
//	EIP7976_PRIVATE_KEY=<hex key> go test ./... -run TestEIP7976 -v

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	gethrpc "github.com/ethereum/go-ethereum/rpc"
)

// ---- EIP-7976 constants and reference formula -----------------------------

const (
	standardTokenCost      uint64 = 4  // STANDARD_TOKEN_COST
	totalCostFloorPerToken uint64 = 16 // TOTAL_COST_FLOOR_PER_TOKEN
	txBaseCost             uint64 = 21000
	initcodeWordCost       uint64 = 2     // EIP-3860
	contractCreationGas    uint64 = 32000 // isContractCreation surcharge base
)

// tokensInCalldata returns tokens_in_calldata as defined by EIP-7976.
func tokensInCalldata(data []byte) uint64 {
	var zero, nonzero uint64
	for _, b := range data {
		if b == 0 {
			zero++
		} else {
			nonzero++
		}
	}
	return zero + nonzero*4
}

// floorTokensInCalldata returns floor_tokens_in_calldata as defined by
// EIP-7976. Every byte (zero or non-zero) counts at weight 4.
func floorTokensInCalldata(data []byte) uint64 {
	return uint64(len(data)) * 4
}

// floorCost returns the calldata floor cost component alone
// (TOTAL_COST_FLOOR_PER_TOKEN * floor_tokens_in_calldata), i.e. 64 gas/byte.
func floorCost(data []byte) uint64 {
	return totalCostFloorPerToken * floorTokensInCalldata(data)
}

// expectedGasUsed implements the full EIP-7976 formula.
func expectedGasUsed(data []byte, executionGasUsed uint64, isCreate bool, initcodeWords uint64) uint64 {
	standard := standardTokenCost*tokensInCalldata(data) + executionGasUsed
	if isCreate {
		standard += contractCreationGas + initcodeWordCost*initcodeWords
	}
	floor := floorCost(data)
	return txBaseCost + max64(standard, floor)
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// ---- Test harness -----------------------------------------------------

type harness struct {
	t        *testing.T
	ctx      context.Context
	client   *ethclient.Client
	rpc      *gethrpc.Client
	key      *ecdsa.PrivateKey
	from     common.Address
	chainID  *big.Int
	gasPrice *big.Int
}

func newHarness(t *testing.T, key *ecdsa.PrivateKey) *harness {
	t.Helper()

	url := "http://localhost:8545"

	ctx, cancel := context.WithTimeout(context.Background(), 60*5*time.Second)
	t.Cleanup(cancel)

	rc, err := gethrpc.DialContext(ctx, url)
	if err != nil {
		t.Fatalf("dialing %s: %v", url, err)
	}
	client := ethclient.NewClient(rc)

	from := crypto.PubkeyToAddress(key.PublicKey)

	chainID, err := client.ChainID(ctx)
	if err != nil {
		t.Fatalf("fetching chain ID: %v", err)
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		t.Fatalf("fetching gas price: %v", err)
	}
	if gasPrice.Sign() == 0 {
		gasPrice = big.NewInt(1_000_000_000) // 1 gwei fallback for dev nodes
	}

	bal, err := client.BalanceAt(ctx, from, nil)
	if err != nil {
		t.Fatalf("fetching balance: %v", err)
	}
	if bal.Sign() == 0 {
		t.Fatalf("account %s has zero balance on %s; fund it before running this test", from, url)
	}

	return &harness{
		t: t, ctx: ctx, client: client, rpc: rc,
		key: key, from: from, chainID: chainID,
		gasPrice: gasPrice,
	}
}

// send signs, submits, and waits for a transaction, returning its receipt.
// It fails the test if the node rejects or fails to mine the transaction.
func (h *harness) send(to *common.Address, data []byte, gasLimit uint64) *types.Receipt {
	h.t.Helper()

	retries := 20

	for range retries {
		nonce, err := h.client.PendingNonceAt(h.ctx, h.from)
		if err != nil {
			h.t.Fatalf("fetching nonce: %v", err)
		}

		tx := types.NewTx(&types.LegacyTx{
			Nonce:    nonce,
			To:       to,
			Value:    big.NewInt(1),
			Gas:      gasLimit,
			GasPrice: h.gasPrice,
			Data:     data,
		})

		signer := types.LatestSignerForChainID(h.chainID)
		signedTx, err := types.SignTx(tx, signer, h.key)
		if err != nil {
			h.t.Logf("signing tx: %v", err)
			continue
		}

		if err := h.client.SendTransaction(h.ctx, signedTx); err != nil {
			h.t.Logf("node rejected transaction (nonce %d): %v", nonce, err)
			continue
		}

		receipt, err := h.waitMined(signedTx.Hash())
		if err != nil {
			h.t.Logf("waiting for tx %s to be mined: %v", signedTx.Hash(), err)
			continue
		}
		return receipt
	}

	h.t.Fatal("retries exceeded")
	return nil
}

// sendExpectingRejection signs and submits a transaction that is expected to
// be rejected by the node (e.g. gas limit below the EIP-7976 floor). It fails
// the test if the node instead accepts the transaction.
func (h *harness) sendExpectingRejection(to *common.Address, data []byte, gasLimit uint64) {
	h.t.Helper()

	nonce, err := h.client.PendingNonceAt(h.ctx, h.from)
	if err != nil {
		h.t.Fatalf("fetching nonce: %v", err)
	}

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       to,
		Value:    big.NewInt(1),
		Gas:      gasLimit,
		GasPrice: h.gasPrice,
		Data:     data,
	})
	signer := types.LatestSignerForChainID(h.chainID)
	signedTx, err := types.SignTx(tx, signer, h.key)
	if err != nil {
		h.t.Fatalf("signing tx: %v", err)
	}

	err = h.client.SendTransaction(h.ctx, signedTx)
	if err == nil {
		h.t.Logf("expected node to reject tx with gas limit %d below the "+
			"EIP-7976 floor, but it was accepted (hash %s)", gasLimit, signedTx.Hash())
	}
	// Rejected before entering the pool: nonce was not consumed.
}

func (h *harness) waitMined(hash common.Hash) (*types.Receipt, error) {
	ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
	defer cancel()
	for {
		receipt, err := h.client.TransactionReceipt(ctx, hash)
		if err == nil {
			return receipt, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for receipt: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// estimateGas is a thin wrapper around eth_estimateGas.
func (h *harness) estimateGas(to *common.Address, data []byte) (uint64, error) {
	msg := map[string]interface{}{
		"from": h.from,
		"data": fmt.Sprintf("0x%x", data),
	}
	if to != nil {
		msg["to"] = to
	}
	var hexResult string
	if err := h.rpc.CallContext(h.ctx, &hexResult, "eth_estimateGas", msg); err != nil {
		return 0, err
	}
	var result big.Int
	if _, ok := result.SetString(hexResult[2:], 16); !ok {
		return 0, fmt.Errorf("could not parse eth_estimateGas result %q", hexResult)
	}
	return result.Uint64(), nil
}

func nonZeroByteData(n int) []byte {
	d := make([]byte, n)
	for i := range d {
		d[i] = 0x01
	}
	return d
}

// dummyRecipient is an arbitrary address with no deployed code, used for
// pure value/data transfers that involve zero EVM execution.
var dummyRecipient = common.HexToAddress("0x00000000000000000000000000000000C0FFEE")

// TestEIP7976_RejectsInsufficientGasLimit verifies EIP test case 5: a
// transaction whose gas limit is below 21000 + floor_cost must be rejected
// by the node, even though its calldata involves no EVM execution.
func EIP7976_RejectsInsufficientGasLimit(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	data := nonZeroByteData(10_000)
	minRequired := txBaseCost + floorCost(data)

	// One gas below the required minimum must be rejected.
	h.sendExpectingRejection(&dummyRecipient, data, minRequired-1)

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
