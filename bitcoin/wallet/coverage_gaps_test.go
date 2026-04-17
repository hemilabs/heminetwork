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
		{Value: 1_000},
		{Value: 2_000},
	}
	_, err := UtxoPickerMultiple(10_000, 100, utxos)
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
		{Value: 1_000},
		{Value: 2_000},
		{Value: 3_000},
	}
	_, err := UtxoPickerSingle(100_000, 100, utxos)
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
		{Value: 50_000},  // first one large enough
		{Value: 100_000}, // should not be picked
	}
	u, err := UtxoPickerSingle(10_000, 100, utxos)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Value != 50_000 {
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

	prev := wire.NewTxOut(50_000, pkScript)
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

	prev := wire.NewTxOut(50_000, pkScript)
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

// TestTransactionApplyECDSAP2WPKHWrongKey covers the P2WPKH branch
// of pubKeyMatchesAddress — the sibling to
// TestTransactionApplyECDSAWrongKey which exercises the P2PKH
// branch.  Provides a pubkey whose HASH160 does not match the
// witness program in the prev pkScript.
func TestTransactionApplyECDSAP2WPKHWrongKey(t *testing.T) {
	params := &chaincfg.TestNet3Params

	owner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// pkScript is a P2WPKH locked to owner's key.
	ownerHash := btcutil.Hash160(owner.PubKey().SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(ownerHash, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("p2wpkh-wrong-key"))
	outpoint := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
	prev := wire.NewTxOut(50_000, pkScript)

	// Produce a well-formed sigDER so we get past the parse gate.
	sigDER := signWithKeyToDER(wrongKey, chainhash.HashB([]byte("x")))

	// Call with wrongKey's pubkey — must be rejected at the
	// pubKeyMatchesAddress check.
	err = TransactionApplyECDSA(params, tx, 0, prev, wrongKey.PubKey(),
		sigDER, txscript.SigHashAll)
	if err == nil {
		t.Fatal("expected error for wrong pubkey on P2WPKH input")
	}
	if !strings.Contains(err.Error(), "p2wpkh") {
		t.Fatalf("expected error to reference 'p2wpkh', got: %v", err)
	}
}

// TestTransactionApplySchnorrNonDefaultSigHash verifies the witness
// assembly for a taproot input signed with a non-SigHashDefault
// sighash type.  BIP-341 specifies that the sighash byte is
// appended to the 64-byte signature only when the type is not the
// default; a 65-byte witness element is produced.
func TestTransactionApplySchnorrNonDefaultSigHash(t *testing.T) {
	params := &chaincfg.TestNet3Params

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

	fundHash := chainhash.DoubleHashH([]byte("schnorr-nondefault-sighash"))
	outpoint := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)
	sig64 := make([]byte, 64)

	err = TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
		sig64, txscript.SigHashAll)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Witness element 0 must be 65 bytes: 64-byte sig + 1 hashtype.
	if got := len(tx.TxIn[0].Witness[0]); got != 65 {
		t.Fatalf("non-default sighash witness: got %d bytes, want 65",
			got)
	}
	if tx.TxIn[0].Witness[0][64] != byte(txscript.SigHashAll) {
		t.Fatalf("trailing sighash byte: got 0x%02x, want 0x%02x",
			tx.TxIn[0].Witness[0][64], byte(txscript.SigHashAll))
	}
}
