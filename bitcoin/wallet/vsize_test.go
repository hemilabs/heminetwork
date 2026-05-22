// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
)

// makeScript constructs minimal valid scripts for each address type.
// These are structurally valid enough for IsPayTo* classification.

func makeP2PKHScript() []byte {
	// OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
	s := make([]byte, 25)
	s[0] = txscript.OP_DUP
	s[1] = txscript.OP_HASH160
	s[2] = txscript.OP_DATA_20
	// bytes 3..22 are the pubkey hash (zeros are fine for classification)
	s[23] = txscript.OP_EQUALVERIFY
	s[24] = txscript.OP_CHECKSIG
	return s
}

func makeP2WPKHScript() []byte {
	// OP_0 <20-byte witness program>
	s := make([]byte, 22)
	s[0] = txscript.OP_0
	s[1] = txscript.OP_DATA_20
	// bytes 2..21 are the witness program
	return s
}

func makeP2TRScript() []byte {
	// OP_1 <32-byte witness program>
	s := make([]byte, 34)
	s[0] = txscript.OP_1
	s[1] = txscript.OP_DATA_32
	// bytes 2..33 are the witness program
	return s
}

func makeP2SHScript() []byte {
	// OP_HASH160 <20-byte script hash> OP_EQUAL
	s := make([]byte, 23)
	s[0] = txscript.OP_HASH160
	s[1] = txscript.OP_DATA_20
	// bytes 2..21 are the script hash
	s[22] = txscript.OP_EQUAL
	return s
}

// dummyTxOut returns a minimal TxOut for size estimation.
func dummyTxOut() *wire.TxOut {
	return wire.NewTxOut(100000, makeP2PKHScript())
}

func TestEstimateVSize(t *testing.T) {
	txOuts := []*wire.TxOut{dummyTxOut()}

	tests := []struct {
		name      string
		script    []byte
		numInputs int
		// Expected values are computed by calling EstimateVirtualSize
		// directly with the correct input-type slot filled in.
		wantFunc func(n int, outs []*wire.TxOut, changeSize int) int
	}{
		{
			name:      "p2pkh single input",
			script:    makeP2PKHScript(),
			numInputs: 1,
			wantFunc: func(n int, outs []*wire.TxOut, cs int) int {
				return txsizes.EstimateVirtualSize(n, 0, 0, 0, outs, cs)
			},
		},
		{
			name:      "p2pkh multiple inputs",
			script:    makeP2PKHScript(),
			numInputs: 5,
			wantFunc: func(n int, outs []*wire.TxOut, cs int) int {
				return txsizes.EstimateVirtualSize(n, 0, 0, 0, outs, cs)
			},
		},
		{
			name:      "p2wpkh single input",
			script:    makeP2WPKHScript(),
			numInputs: 1,
			wantFunc: func(n int, outs []*wire.TxOut, cs int) int {
				return txsizes.EstimateVirtualSize(0, 0, n, 0, outs, cs)
			},
		},
		{
			name:      "p2wpkh multiple inputs",
			script:    makeP2WPKHScript(),
			numInputs: 3,
			wantFunc: func(n int, outs []*wire.TxOut, cs int) int {
				return txsizes.EstimateVirtualSize(0, 0, n, 0, outs, cs)
			},
		},
		{
			name:      "p2tr single input",
			script:    makeP2TRScript(),
			numInputs: 1,
			wantFunc: func(n int, outs []*wire.TxOut, cs int) int {
				return txsizes.EstimateVirtualSize(0, n, 0, 0, outs, cs)
			},
		},
		{
			name:      "p2tr multiple inputs",
			script:    makeP2TRScript(),
			numInputs: 4,
			wantFunc: func(n int, outs []*wire.TxOut, cs int) int {
				return txsizes.EstimateVirtualSize(0, n, 0, 0, outs, cs)
			},
		},
		{
			name:      "p2sh single input (nested segwit)",
			script:    makeP2SHScript(),
			numInputs: 1,
			wantFunc: func(n int, outs []*wire.TxOut, cs int) int {
				return txsizes.EstimateVirtualSize(0, 0, 0, n, outs, cs)
			},
		},
		{
			name:      "p2sh multiple inputs",
			script:    makeP2SHScript(),
			numInputs: 2,
			wantFunc: func(n int, outs []*wire.TxOut, cs int) int {
				return txsizes.EstimateVirtualSize(0, 0, 0, n, outs, cs)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := estimateVSize(tc.numInputs, tc.script, txOuts)
			want := tc.wantFunc(tc.numInputs, txOuts, len(tc.script))
			if got != want {
				t.Errorf("estimateVSize() = %d, want %d", got, want)
			}
			if got <= 0 {
				t.Errorf("estimateVSize() = %d, expected positive value", got)
			}
		})
	}
}

func TestEstimateVSizeUnknownScript(t *testing.T) {
	txOuts := []*wire.TxOut{dummyTxOut()}

	// Unknown/garbage scripts should fall through to P2PKH (safe overestimate).
	unknownScripts := []struct {
		name   string
		script []byte
	}{
		{"empty script", []byte{}},
		{"single byte", []byte{0xff}},
		{"op_return", []byte{txscript.OP_RETURN, 0x04, 0xde, 0xad, 0xbe, 0xef}},
		{"random garbage", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
	}

	for _, tc := range unknownScripts {
		t.Run(tc.name, func(t *testing.T) {
			got := estimateVSize(1, tc.script, txOuts)
			want := txsizes.EstimateVirtualSize(1, 0, 0, 0, txOuts, len(tc.script))
			if got != want {
				t.Errorf("estimateVSize() = %d, want %d (p2pkh fallback)", got, want)
			}
		})
	}
}

func TestEstimateVSizeWitnessDiscount(t *testing.T) {
	// Verify that witness types produce smaller vsize than legacy for the
	// same number of inputs.  This is the whole point of the fix: if the
	// old EstimateSerializeSize was used, all types would return the same
	// (P2PKH) size.
	txOuts := []*wire.TxOut{dummyTxOut()}
	numInputs := 2

	p2pkh := estimateVSize(numInputs, makeP2PKHScript(), txOuts)
	p2wpkh := estimateVSize(numInputs, makeP2WPKHScript(), txOuts)
	p2tr := estimateVSize(numInputs, makeP2TRScript(), txOuts)

	if p2wpkh >= p2pkh {
		t.Errorf("P2WPKH vsize (%d) should be less than P2PKH (%d)", p2wpkh, p2pkh)
	}
	if p2tr >= p2pkh {
		t.Errorf("P2TR vsize (%d) should be less than P2PKH (%d)", p2tr, p2pkh)
	}
}

func TestEstimateVSizeNilScript(t *testing.T) {
	txOuts := []*wire.TxOut{dummyTxOut()}

	// nil script should not panic — falls through to P2PKH default.
	got := estimateVSize(1, nil, txOuts)
	want := txsizes.EstimateVirtualSize(1, 0, 0, 0, txOuts, 0)
	if got != want {
		t.Errorf("estimateVSize(nil) = %d, want %d", got, want)
	}
}

func TestEstimateVSizeZeroInputs(t *testing.T) {
	txOuts := []*wire.TxOut{dummyTxOut()}

	// Zero inputs should not panic; result is the base tx overhead.
	got := estimateVSize(0, makeP2PKHScript(), txOuts)
	if got <= 0 {
		t.Errorf("estimateVSize(0 inputs) = %d, expected positive", got)
	}
}
