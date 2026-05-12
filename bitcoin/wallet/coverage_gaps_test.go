// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul/memory"
)

// TestUtxoPickerMultipleEmpty verifies the all-utxos-too-small path:
// if the caller's wallet cannot cover amount+fee from any single utxo
// and the running total never reaches the required amount, the
// picker returns "no suitable utxos found".
func TestUtxoPickerMultipleEmpty(t *testing.T) {
	// Request more than the sum of all inputs.
	utxos := []*tbcapi.UTXO{
		{Value: 1000},
		{Value: 2000},
	}
	_, err := UtxoPickerMultiple(10000, 100, utxos)
	if err == nil {
		t.Fatal("expected error when utxos cannot cover amount+fee")
	}
	if !strings.Contains(err.Error(), "no suitable utxos found") {
		t.Fatalf("expected 'no suitable utxos found', got: %v", err)
	}
}

// TestUtxoPickerSingleNoneLargeEnough verifies the per-utxo skip path:
// when no single utxo is large enough, the picker continues past all
// of them and returns the not-found error.
func TestUtxoPickerSingleNoneLargeEnough(t *testing.T) {
	utxos := []*tbcapi.UTXO{
		{Value: 1000},
		{Value: 2000},
		{Value: 3000},
	}
	_, err := UtxoPickerSingle(100000, 100, utxos)
	if err == nil {
		t.Fatal("expected error when no single utxo is large enough")
	}
	if !strings.Contains(err.Error(), "no suitable utxo found") {
		t.Fatalf("expected 'no suitable utxo found', got: %v", err)
	}
}

// TestUtxoPickerSingleFirstFit verifies the picker skips undersized
// utxos and returns the first one large enough.  Exercises the
// skip-too-small continuation branch alongside the successful
// return.
func TestUtxoPickerSingleFirstFit(t *testing.T) {
	utxos := []*tbcapi.UTXO{
		{Value: 500},
		{Value: 999},
		{Value: 50000},  // first one large enough
		{Value: 100000}, // should not be picked
	}
	u, err := UtxoPickerSingle(10000, 100, utxos)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Value != 50000 {
		t.Fatalf("expected first-fit utxo of 50000, got %d", u.Value)
	}
}

// TestTransactionSignPrevOutNotFound verifies TransactionSign
// pre-validates PrevOuts against every input before invoking
// NewTxSigHashes, returning a clean error naming the offending
// input.  Without this guard a caller-supplied incomplete PrevOuts
// panics deep inside witness sighash midstate computation.
func TestTransactionSignPrevOutNotFound(t *testing.T) {
	params := &chaincfg.TestNet3Params
	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("prev-out-not-found"))
	outpoint := wire.NewOutPoint(&fundHash, 0)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{txscript.OP_RETURN}))

	// Intentionally empty PrevOuts — the pre-validation loop
	// should catch this before NewTxSigHashes is reached.
	empty := PrevOuts{}

	err = TransactionSign(params, m, tx, empty)
	if err == nil {
		t.Fatal("expected error when PrevOuts missing input entry")
	}
	if !strings.Contains(err.Error(), "previous out not found") {
		t.Fatalf("expected 'previous out not found', got: %v", err)
	}
	if !strings.Contains(err.Error(), "input 0") {
		t.Fatalf("expected error to name 'input 0', got: %v", err)
	}
}

// TestTransactionSignUnknownP2WPKHKey verifies that TransactionSign
// wraps signP2WPKH failures with the input index and class.  The key
// is missing from zuul so resolveInputSigningKey fails through
// signP2WPKH, which propagates out of TransactionSign.
func TestTransactionSignUnknownP2WPKHKey(t *testing.T) {
	params := &chaincfg.TestNet3Params
	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	// Build a P2WPKH pkScript for a key that zuul does NOT hold.
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("unknown-p2wpkh-key"))
	outpoint := wire.NewOutPoint(&fundHash, 0)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{txscript.OP_RETURN}))

	prev := wire.NewTxOut(50000, pkScript)
	prevOuts := PrevOuts{outpoint.String(): prev}

	err = TransactionSign(params, m, tx, prevOuts)
	if err == nil {
		t.Fatal("expected error when zuul has no key for P2WPKH input")
	}
	if !strings.Contains(err.Error(), "sign p2wpkh input 0") {
		t.Fatalf("expected error to reference 'sign p2wpkh input 0', got: %v",
			err)
	}
	if !errors.Is(err, zuul.ErrKeyDoesntExist) {
		t.Fatalf("expected error to wrap ErrKeyDoesntExist, got: %v", err)
	}
}

// TestTransactionSignUnknownP2TRKey is the P2TR sibling of
// TestTransactionSignUnknownP2WPKHKey: proves the P2TR dispatch arm
// correctly wraps signP2TRKeyPath failures.
func TestTransactionSignUnknownP2TRKey(t *testing.T) {
	params := &chaincfg.TestNet3Params
	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		outputKey.SerializeCompressed()[1:], params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("unknown-p2tr-key"))
	outpoint := wire.NewOutPoint(&fundHash, 0)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{txscript.OP_RETURN}))

	prev := wire.NewTxOut(50000, pkScript)
	prevOuts := PrevOuts{outpoint.String(): prev}

	err = TransactionSign(params, m, tx, prevOuts)
	if err == nil {
		t.Fatal("expected error when zuul has no key for P2TR input")
	}
	if !strings.Contains(err.Error(), "sign p2tr input 0") {
		t.Fatalf("expected error to reference 'sign p2tr input 0', got: %v",
			err)
	}
}

// TestPrevOutsFetcherPanicsOnMalformedKey verifies the defensive
// panic fires when PrevOuts carries an outpoint string the wire
// parser can't decode.  A silent drop would cause NewTxSigHashes to
// deref a nil TxOut later in witness sighash computation.
func TestPrevOutsFetcherPanicsOnMalformedKey(t *testing.T) {
	bad := PrevOuts{
		"this-is-not-a-valid-outpoint-string": wire.NewTxOut(0, nil),
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on malformed outpoint key")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "malformed outpoint key") {
			t.Fatalf("expected panic message about malformed key, got: %s",
				msg)
		}
	}()

	_ = prevOutsFetcher(bad)
}
