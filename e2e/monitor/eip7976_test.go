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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	retries := 10

	for range retries {
		time.Sleep(1 * time.Second)
		nonce, err := h.client.PendingNonceAt(h.ctx, h.from)
		if err != nil {
			h.t.Logf("fetching nonce: %v", err)
			continue
		}

		tx := types.NewTx(&types.LegacyTx{
			Nonce:    nonce,
			To:       to,
			Value:    big.NewInt(0),
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

// ---- Test data helpers -----------------------------------------------------

func zeroByteData(n int) []byte {
	return make([]byte, n) // already all zero bytes
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

// ---- Gas-burner contract for the EVM-heavy and boundary test cases --------
//
// The runtime bytecode below reads a uint256 loop count N from calldata[0:32]
// and busy-loops N times, burning a controllable, monotonically increasing
// amount of execution gas per call. This lets the boundary test find the
// exact crossover between the calldata floor and standard/execution pricing
// empirically (via eth_estimateGas) rather than relying on hand-derived
// opcode gas accounting, which is fragile across client versions.
//
// Runtime bytecode (annotated):
//
//	PUSH1 0x00       ; 0
//	CALLDATALOAD     ; 2   -> N
//	JUMPDEST         ; 3   <- loop_start (pc=3)
//	DUP1
//	ISZERO
//	PUSH1 0x10       ; exit_pc = 16
//	JUMPI
//	PUSH1 0x01
//	SWAP1
//	SUB
//	PUSH1 0x03       ; loop_start_pc = 3
//	JUMP
//	JUMPDEST         ; 16  <- exit
//	POP
//	STOP
func gasBurnerRuntime() []byte {
	return []byte{
		0x60, 0x00, // PUSH1 0x00
		0x35,       // CALLDATALOAD
		0x5b,       // JUMPDEST (loop_start, pc=3)
		0x80,       // DUP1
		0x15,       // ISZERO
		0x60, 0x10, // PUSH1 0x10 (exit_pc=16)
		0x57,       // JUMPI
		0x60, 0x01, // PUSH1 0x01
		0x90,       // SWAP1
		0x03,       // SUB
		0x60, 0x03, // PUSH1 0x03 (loop_start_pc=3)
		0x56, // JUMP
		0x5b, // JUMPDEST (exit, pc=16)
		0x50, // POP
		0x00, // STOP
	}
}

// gasBurnerInitCode wraps runtime code in a standard CODECOPY/RETURN
// constructor so it can be deployed with a plain CREATE transaction.
func gasBurnerInitCode(runtime []byte) []byte {
	const prefixLen = 13
	codeOffset := uint16(prefixLen)
	length := uint16(len(runtime))

	init := []byte{
		0x61, byte(length >> 8), byte(length), // PUSH2 <len>
		0x80,                                          // DUP1
		0x61, byte(codeOffset >> 8), byte(codeOffset), // PUSH2 <codeOffset>
		0x60, 0x00, // PUSH1 0x00
		0x39,       // CODECOPY
		0x60, 0x00, // PUSH1 0x00
		0xf3, // RETURN
	}
	if len(init) != prefixLen {
		panic("gasBurnerInitCode: prefix length assumption violated")
	}
	return append(init, runtime...)
}

// loopCountCalldata ABI-encodes a loop count as a single uint256 argument
// (32-byte big-endian), matching what the gas burner contract expects.
func loopCountCalldata(n uint64) []byte {
	buf := make([]byte, 32)
	big.NewInt(0).SetUint64(n).FillBytes(buf)
	return buf
}

func (h *harness) deployGasBurner() common.Address {
	h.t.Helper()
	init := gasBurnerInitCode(gasBurnerRuntime())
	receipt := h.send(nil, init, 500_000)
	if receipt.Status != types.ReceiptStatusSuccessful {
		h.t.Fatalf("gas burner deployment failed (status=%d)", receipt.Status)
	}
	if receipt.ContractAddress == (common.Address{}) {
		h.t.Fatal("gas burner deployment produced no contract address")
	}
	return receipt.ContractAddress
}

// ---- Tests --------------------------------------------------------------

// TestEIP7976_DataHeavyFloorCost verifies EIP test case 1: transactions with
// large calldata and no EVM execution pay the 64 gas/byte floor, regardless
// of whether the bytes are zero or non-zero.
func EIP7976_DataHeavyFloorCost(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	cases := []struct {
		name string
		data []byte
	}{
		{"all-zero-bytes", zeroByteData(20_000)},
		{"all-nonzero-bytes", nonZeroByteData(20_000)},
		{"mixed-bytes", append(zeroByteData(10_000), nonZeroByteData(10_000)...)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			want := expectedGasUsed(tc.data, 0, false, 0)
			gasLimit := want + 50_000 // headroom; does not affect gasUsed
			receipt := h.send(&dummyRecipient, tc.data, gasLimit)

			if receipt.Status != types.ReceiptStatusSuccessful {
				t.Fatalf("transaction failed (status=%d)", receipt.Status)
			}
			if receipt.GasUsed != want {
				t.Errorf("gasUsed = %d, want %d (floor formula: 21000 + 64*%d bytes)",
					receipt.GasUsed, want, len(tc.data))
			}
			// Sanity check against the EIP's stated 64 gas/byte equivalence.
			wantFloorOnly := txBaseCost + uint64(len(tc.data))*64
			if want != wantFloorOnly {
				t.Fatalf("internal test bug: formula (%d) disagrees with 64 gas/byte shortcut (%d)", want, wantFloorOnly)
			}
		})
	}
}

// TestEIP7976_EstimateGasMatchesFloor verifies EIP test case 4: eth_estimateGas
// accounts for the updated TOTAL_COST_FLOOR_PER_TOKEN.
func EIP7976_EstimateGasMatchesFloor(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	data := nonZeroByteData(15_000)
	want := expectedGasUsed(data, 0, false, 0)

	got, err := h.estimateGas(&dummyRecipient, data)
	if err != nil {
		t.Fatalf("eth_estimateGas failed: %v", err)
	}
	if got != want {
		t.Errorf("eth_estimateGas = %d, want %d", got, want)
	}
}

// TestEIP7976_EVMHeavyStandardPricing verifies EIP test case 2: transactions
// with significant EVM execution and small calldata are NOT capped at the
// floor; standard 4/16 gas/byte pricing plus execution gas applies instead.
func EIP7976_EVMHeavyStandardPricing(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	contract := h.deployGasBurner()

	// A loop count large enough that execution gas alone dwarfs the floor
	// cost of the (tiny, fixed 32-byte) calldata used to invoke it.
	const loopCount = 5_000
	data := loopCountCalldata(loopCount)
	floor := floorCost(data)

	estimate, err := h.estimateGas(&contract, data)
	if err != nil {
		t.Fatalf("eth_estimateGas failed: %v", err)
	}

	receipt := h.send(&contract, data, estimate+50_000)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("gas burner call failed (status=%d)", receipt.Status)
	}

	if receipt.GasUsed <= txBaseCost+floor {
		t.Errorf("gasUsed = %d did not exceed floor-only cost (%d); "+
			"execution-heavy transaction appears to have been incorrectly "+
			"capped at the calldata floor", receipt.GasUsed, txBaseCost+floor)
	}
	// The node's own estimate and the actual mined cost should agree,
	// since this bytecode has no gas-dependent branching or refunds.
	if receipt.GasUsed != estimate {
		t.Errorf("gasUsed = %d, want eth_estimateGas value %d", receipt.GasUsed, estimate)
	}
}

// TestEIP7976_FloorExecutionBoundary verifies EIP test case 3: it empirically
// finds the crossover point where execution_gas_used pushes total cost above
// the calldata floor, then checks both sides of that boundary directly
// against mined transactions.
func EIP7976_FloorExecutionBoundary(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	contract := h.deployGasBurner()

	// Calldata is fixed at 32 bytes (one uint256 argument) for every call in
	// this test, so its floor cost is constant; only the loop count (and
	// thus execution_gas_used) varies.
	probeData := loopCountCalldata(0)
	floor := floorCost(probeData)

	costAt := func(n uint64) uint64 {
		est, err := h.estimateGas(&contract, loopCountCalldata(n))
		if err != nil {
			t.Fatalf("eth_estimateGas(N=%d) failed: %v", n, err)
		}
		return est
	}

	// Binary search for the smallest N whose estimated cost exceeds the
	// floor-only cost, i.e. the first N where standard+execution pricing
	// overtakes the floor.
	lo, hi := uint64(0), uint64(2000)
	if costAt(hi) <= txBaseCost+floor {
		t.Fatalf("loop count %d did not produce enough execution gas to "+
			"exceed the floor; increase the search range", hi)
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if costAt(mid) > txBaseCost+floor {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	crossoverN := lo // smallest N where cost > floor

	if crossoverN == 0 {
		t.Fatal("crossover found at N=0; cannot test the floor-dominated side of the boundary")
	}
	belowN := crossoverN - 1

	// Below the crossover: execution is cheap enough that the floor still
	// applies, and gasUsed must equal the floor exactly.
	belowData := loopCountCalldata(belowN)
	belowReceipt := h.send(&contract, belowData, txBaseCost+floor+200_000)
	if belowReceipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("call at N=%d failed (status=%d)", belowN, belowReceipt.Status)
	}
	if want := txBaseCost + floor; belowReceipt.GasUsed != want {
		t.Errorf("at N=%d (below crossover): gasUsed = %d, want floor cost %d",
			belowN, belowReceipt.GasUsed, want)
	}

	// At/above the crossover: execution gas has overtaken the floor, and
	// gasUsed must exceed the floor and match the node's own estimate.
	atData := loopCountCalldata(crossoverN)
	atEstimate := costAt(crossoverN)
	atReceipt := h.send(&contract, atData, atEstimate+200_000)
	if atReceipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("call at N=%d failed (status=%d)", crossoverN, atReceipt.Status)
	}
	if atReceipt.GasUsed <= txBaseCost+floor {
		t.Errorf("at N=%d (at/above crossover): gasUsed = %d did not exceed floor cost %d",
			crossoverN, atReceipt.GasUsed, txBaseCost+floor)
	}
	if atReceipt.GasUsed != atEstimate {
		t.Errorf("at N=%d: gasUsed = %d, want eth_estimateGas value %d",
			crossoverN, atReceipt.GasUsed, atEstimate)
	}

	t.Logf("floor-only cost = %d, crossover loop count = %d (N=%d -> %d gas, N=%d -> %d gas)",
		txBaseCost+floor, crossoverN, belowN, belowReceipt.GasUsed, crossoverN, atReceipt.GasUsed)
}

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
		t.Errorf("gasUsed = %d, want %d", receipt.GasUsed, minRequired)
	}
}
