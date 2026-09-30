package main

// Shared helpers for the Glamsterdam (EIP-7773) presence checks in the
// eipNNNN_test.go files.

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// deploy sends a contract-creation transaction and fails the test unless it
// succeeds, returning the address of the new contract.
func (h *harness) deploy(initcode []byte, gasLimit uint64) common.Address {
	h.t.Helper()

	receipt := h.send(nil, initcode, gasLimit)
	if receipt.Status != types.ReceiptStatusSuccessful {
		h.t.Fatalf("contract deployment failed (tx %s)", receipt.TxHash)
	}
	return receipt.ContractAddress
}

// initcodeFor returns initcode that runs prelude and then returns runtime as
// the deployed code. runtime must be at most 255 bytes.
func initcodeFor(prelude, runtime []byte) []byte {
	const copierLen = 11
	offset := len(prelude) + copierLen
	if len(runtime) > 0xff || offset > 0xff {
		panic("initcodeFor: runtime or prelude too long")
	}

	code := append([]byte{}, prelude...)
	code = append(code,
		0x60, byte(len(runtime)), // PUSH1 len(runtime)
		0x80,               // DUP1
		0x60, byte(offset), // PUSH1 offset of runtime in initcode
		0x60, 0x00, // PUSH1 0
		0x39,       // CODECOPY
		0x60, 0x00, // PUSH1 0
		0xf3, // RETURN
	)
	return append(code, runtime...)
}

// rawBlock fetches a block header (without transaction bodies) as raw JSON
// fields, so that fields unknown to the vendored go-ethereum types are kept.
func (h *harness) rawBlock(number *big.Int) map[string]any {
	h.t.Helper()

	var block map[string]any
	if err := h.rpc.CallContext(h.ctx, &block, "eth_getBlockByNumber",
		hexutil.EncodeBig(number), false); err != nil {
		h.t.Fatalf("fetching block %v: %v", number, err)
	}
	if block == nil {
		h.t.Fatalf("block %v not found", number)
	}
	return block
}

// rawBlockUint64 returns a hex quantity field of a block from rawBlock.
func (h *harness) rawBlockUint64(block map[string]any, field string) uint64 {
	h.t.Helper()

	s, ok := block[field].(string)
	if !ok {
		h.t.Fatalf("block field %q missing or not a string: %v", field, block[field])
	}
	v, err := hexutil.DecodeUint64(s)
	if err != nil {
		h.t.Fatalf("decoding block field %q (%q): %v", field, s, err)
	}
	return v
}
