// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
		outputKey.SerializeCompressed()[1:], params,
	)
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
	prev := wire.NewTxOut(50000, pkScript)

	// Produce a well-formed sigDER so we get past the parse gate.
	sigDER := signWithKeyToDER(wrongKey, chainhash.HashB([]byte("x")))

	// Call with wrongKey's pubkey — must be rejected at the
	// pubKeyMatchesAddress check.
	err = TransactionApplyECDSA(params, tx, 0, prev, wrongKey.PubKey(),
		sigDER, txscript.SigHashAll)
	if err == nil {
		t.Fatal("expected error for wrong pubkey on P2WPKH input")
	}
	if !errors.Is(err, ErrPubKeyMismatch) {
		t.Fatalf("expected ErrPubKeyMismatch, got: %v", err)
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
		outputKey.SerializeCompressed()[1:], params,
	)
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

	prev := wire.NewTxOut(50000, pkScript)
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

// TestApplyECDSAP2PKHScriptBuilderError covers the ScriptBuilder
// error return inside applyECDSAP2PKH.  The builder rejects data
// pushes exceeding MaxScriptElementSize (520 bytes).
func TestApplyECDSAP2PKHScriptBuilderError(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("scriptbuilder-error-0000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)
	pubCompressed := priv.PubKey().SerializeCompressed()

	oversizedSig := make([]byte, 521)
	err = applyECDSAP2PKH(params, tx, 0, prev, oversizedSig, pubCompressed)
	if err == nil {
		t.Fatal("expected ScriptBuilder error for oversized data push")
	}
}

// TestPubKeyMatchesAddressExtractError covers the ExtractPkScriptAddrs
// error return in pubKeyMatchesAddress by calling it directly with a
// malformed pkScript.
func TestPubKeyMatchesAddressExtractError(t *testing.T) {
	params := &chaincfg.TestNet3Params
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PubKey().SerializeCompressed()

	// A pkScript with an incomplete pushdata instruction.
	malformed := []byte{txscript.OP_DATA_32}
	err = pubKeyMatchesAddress(params, malformed, pub, false)
	if err == nil {
		t.Fatal("expected error for malformed pkScript")
	}
}

// TestPubKeyMatchesAddressZeroAddrs covers the len(addrs) != 1 branch
// in pubKeyMatchesAddress using an OP_RETURN script which extracts
// zero addresses.
func TestPubKeyMatchesAddressZeroAddrs(t *testing.T) {
	params := &chaincfg.TestNet3Params
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PubKey().SerializeCompressed()

	opReturn, err := txscript.NullDataScript([]byte("no addresses here"))
	if err != nil {
		t.Fatal(err)
	}
	err = pubKeyMatchesAddress(params, opReturn, pub, false)
	if err == nil {
		t.Fatal("expected error for zero-address pkScript")
	}
}

// TestPubKeyMatchesTaprootAddressZeroAddrs covers the len(addrs) != 1
// branch in pubKeyMatchesTaprootAddress.
func TestPubKeyMatchesTaprootAddressZeroAddrs(t *testing.T) {
	params := &chaincfg.TestNet3Params
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	opReturn, err := txscript.NullDataScript([]byte("not taproot"))
	if err != nil {
		t.Fatal(err)
	}
	err = pubKeyMatchesTaprootAddress(params, opReturn, priv.PubKey())
	if err == nil {
		t.Fatal("expected error for zero-address pkScript")
	}
}

// TestTransactionApplyECDSARejectsP2SHP2WPKH verifies that
// TransactionApplyECDSA rejects P2SH-wrapped P2WPKH scripts, which
// are not currently supported.
func TestTransactionApplyECDSARejectsP2SHP2WPKH(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
	wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	// Build P2SH-P2WPKH: the redeem script is the P2WPKH script.
	redeemScript, err := txscript.PayToAddrScript(wpkhAddr)
	if err != nil {
		t.Fatal(err)
	}
	p2shAddr, err := btcutil.NewAddressScriptHash(redeemScript, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(p2shAddr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("p2sh-p2wpkh-reject-000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)
	sigDER := signWithKeyToDER(priv, chainhash.HashB([]byte("x")))

	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, txscript.SigHashAll)
	if err == nil {
		t.Fatal("expected unsupported-script-class error for P2SH-P2WPKH")
	}
	if !errors.Is(err, ErrUnsupportedScript) {
		t.Fatalf("expected ErrUnsupportedScript, got: %v", err)
	}
}

// TestTransactionApplyECDSAIdxZeroNoInputs covers the idx bounds check
// when the transaction has zero inputs.
func TestTransactionApplyECDSAIdxZeroNoInputs(t *testing.T) {
	params := &chaincfg.TestNet3Params
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tx := wire.NewMsgTx(2)
	prev := wire.NewTxOut(50_000, []byte{txscript.OP_RETURN})
	sigDER := signWithKeyToDER(priv, chainhash.HashB([]byte("x")))

	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, txscript.SigHashAll)
	if err == nil {
		t.Fatal("expected out-of-range error for idx=0 with no inputs")
	}
	if !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("expected ErrIndexOutOfRange, got: %v", err)
	}
}

// TestTransactionApplySchnorrRejectsP2WPKH verifies that the schnorr
// path rejects non-taproot script classes.
func TestTransactionApplySchnorrRejectsP2WPKH(t *testing.T) {
	params := &chaincfg.TestNet3Params

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

	fundHash := chainhash.DoubleHashH([]byte("schnorr-rejects-p2wpkh-00000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)
	sig64 := make([]byte, 64)

	err = TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
		sig64, txscript.SigHashDefault)
	if err == nil {
		t.Fatal("expected unsupported-script-class error for P2WPKH")
	}
	if !errors.Is(err, ErrUnsupportedScript) {
		t.Fatalf("expected ErrUnsupportedScript, got: %v", err)
	}
}

// TestVerifyECDSARejectsLongSigHash covers the length guard for
// sighash inputs longer than 32 bytes.
func TestVerifyECDSARejectsLongSigHash(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	longHash := make([]byte, 33)
	sigDER := signWithKeyToDER(priv, chainhash.HashB([]byte("x")))

	err = VerifyECDSA(longHash, sigDER, priv.PubKey())
	if err == nil {
		t.Fatal("expected error for 33-byte sighash")
	}
	if !errors.Is(err, ErrInvalidSigHashLength) {
		t.Fatalf("expected ErrInvalidSigHashLength, got: %v", err)
	}
}

// TestVerifySchnorrRejectsLongInputs checks that VerifySchnorr
// rejects inputs that are 1 byte too long for each parameter.
func TestVerifySchnorrRejectsLongInputs(t *testing.T) {
	cases := []struct {
		name    string
		sigHash []byte
		sig64   []byte
		xOnly   []byte
		want    error
	}{
		{
			"long xOnlyPubKey",
			make([]byte, 32), make([]byte, 64), make([]byte, 33),
			ErrInvalidPubKeyLength,
		},
		{
			"long sigHash",
			make([]byte, 33), make([]byte, 64), make([]byte, 32),
			ErrInvalidSigHashLength,
		},
		{
			"long sig64",
			make([]byte, 32), make([]byte, 65), make([]byte, 32),
			ErrInvalidSigLength,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySchnorr(tc.sigHash, tc.sig64, tc.xOnly)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got: %v", tc.want, err)
			}
		})
	}
}

// TestTransactionApplySchnorrNonDefaultSigHashEngine is the engine-
// verified version of TestTransactionApplySchnorrNonDefaultSigHash:
// signs with SigHashAll, injects, and runs the script engine to
// confirm the 65-byte witness is accepted.
func TestTransactionApplySchnorrNonDefaultSigHashEngine(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params,
	)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("schnorr-nondefault-engine-0000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(fundValue/2, pkScript))

	prev := wire.NewTxOut(fundValue, pkScript)
	prevOuts := PrevOuts{op.String(): prev}

	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	sigRaw, err := txscript.RawTxInTaprootSignature(tx, sigHashes, 0,
		fundValue, pkScript, nil, txscript.SigHashAll, priv)
	if err != nil {
		t.Fatal(err)
	}
	// RawTxInTaprootSignature appends the sighash byte for non-default
	// types; strip it because TransactionApplySchnorr appends its own.
	sig64 := sigRaw[:64]

	err = TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
		sig64, txscript.SigHashAll)
	if err != nil {
		t.Fatalf("TransactionApplySchnorr: %v", err)
	}

	if got := len(tx.TxIn[0].Witness[0]); got != 65 {
		t.Fatalf("witness element 0: got %d bytes, want 65", got)
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected non-default sighash schnorr: %v", err)
	}
}

// TestTransactionApplyECDSAP2WPKHSigHashNone exercises the
// SigHashNone path end-to-end through the script engine.
func TestTransactionApplyECDSAP2WPKHSigHashNone(t *testing.T) {
	params := &chaincfg.TestNet3Params

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

	fundHash := chainhash.DoubleHashH([]byte("sighash-none-p2wpkh-000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(fundValue/2, pkScript))

	prev := wire.NewTxOut(fundValue, pkScript)
	prevOuts := PrevOuts{op.String(): prev}

	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	sigHash, err := txscript.CalcWitnessSigHash(pkScript, sigHashes,
		txscript.SigHashNone, tx, 0, fundValue)
	if err != nil {
		t.Fatal(err)
	}

	sigDER := signWithKeyToDER(priv, sigHash)
	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, txscript.SigHashNone)
	if err != nil {
		t.Fatalf("TransactionApplyECDSA: %v", err)
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected SigHashNone P2WPKH: %v", err)
	}
}

// TestTransactionApplyECDSAP2WPKHSigHashSingle exercises the
// SigHashSingle path end-to-end through the script engine.
func TestTransactionApplyECDSAP2WPKHSigHashSingle(t *testing.T) {
	params := &chaincfg.TestNet3Params

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

	fundHash := chainhash.DoubleHashH([]byte("sighash-single-p2wpkh-0000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(fundValue/2, pkScript))

	prev := wire.NewTxOut(fundValue, pkScript)
	prevOuts := PrevOuts{op.String(): prev}

	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	sigHash, err := txscript.CalcWitnessSigHash(pkScript, sigHashes,
		txscript.SigHashSingle, tx, 0, fundValue)
	if err != nil {
		t.Fatal(err)
	}

	sigDER := signWithKeyToDER(priv, sigHash)
	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, txscript.SigHashSingle)
	if err != nil {
		t.Fatalf("TransactionApplyECDSA: %v", err)
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected SigHashSingle P2WPKH: %v", err)
	}
}

// TestTransactionApplyECDSAP2WPKHSigHashAllAnyOneCanPay exercises
// SigHashAll|SigHashAnyOneCanPay end-to-end through the script engine.
func TestTransactionApplyECDSAP2WPKHSigHashAllAnyOneCanPay(t *testing.T) {
	params := &chaincfg.TestNet3Params

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

	fundHash := chainhash.DoubleHashH([]byte("sighash-acp-p2wpkh-00000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(fundValue/2, pkScript))

	prev := wire.NewTxOut(fundValue, pkScript)
	prevOuts := PrevOuts{op.String(): prev}

	ht := txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	sigHash, err := txscript.CalcWitnessSigHash(pkScript, sigHashes,
		ht, tx, 0, fundValue)
	if err != nil {
		t.Fatal(err)
	}

	sigDER := signWithKeyToDER(priv, sigHash)
	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, ht)
	if err != nil {
		t.Fatalf("TransactionApplyECDSA: %v", err)
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected SigHashAll|AnyOneCanPay P2WPKH: %v", err)
	}
}
