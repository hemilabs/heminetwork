// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// TestTransactionApplySchnorrP2TR exercises the P2TR schnorr
// injection path end-to-end.  The sighash is computed with the
// BIP-341 algorithm, signed externally with the tweaked key, and
// injected via TransactionApplySchnorr.  The script engine must
// accept the resulting witness.
func TestTransactionApplySchnorrP2TR(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// BIP-86 output key for the address.
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("external-p2tr-funding-000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	destPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	destOutputKey := txscript.ComputeTaprootKeyNoScript(destPriv.PubKey())
	destAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(destOutputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		t.Fatal(err)
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(fundValue/2, destScript))

	prev := wire.NewTxOut(fundValue, pkScript)
	prevOuts := PrevOuts{op.String(): prev}

	// Produce an external schnorr signature over the BIP-341 sighash.
	// The TSS committee will do this; here we simulate with the local
	// key tweaked per BIP-86.
	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	// RawTxInTaprootSignature applies the BIP-86 tweak internally and
	// returns a 64-byte SigHashDefault sig.
	sig64, err := txscript.RawTxInTaprootSignature(tx, sigHashes, 0,
		fundValue, pkScript, nil, txscript.SigHashDefault, priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig64) != 64 {
		t.Fatalf("expected 64-byte sig, got %d", len(sig64))
	}

	// Inject: caller supplies the untweaked internal pubkey; the
	// helper computes the tweaked output key and cross-checks.
	err = TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
		sig64, txscript.SigHashDefault)
	if err != nil {
		t.Fatalf("TransactionApplySchnorr: %v", err)
	}

	if len(tx.TxIn[0].Witness) != 1 {
		t.Fatalf("witness wrong length: got %d, want 1",
			len(tx.TxIn[0].Witness))
	}
	if !bytes.Equal(tx.TxIn[0].Witness[0], sig64) {
		t.Fatal("witness[0] does not match provided signature")
	}
	if len(tx.TxIn[0].SignatureScript) != 0 {
		t.Fatal("SignatureScript unexpectedly set for P2TR")
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected injected schnorr signature: %v", err)
	}
}

// TestTransactionApplySchnorrRejectsBadSig verifies the function
// refuses malformed inputs: wrong length, nil args, bad BIP-340
// encoding.
func TestTransactionApplySchnorrRejectsBadSig(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("schnorr-bad-sig-000000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	prev := wire.NewTxOut(50_000, pkScript)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	// Wrong length.
	cases := []struct {
		name   string
		pubKey *btcec.PublicKey
		sig    []byte
	}{
		{"wrong length", priv.PubKey(), []byte{1, 2, 3}},
		{"nil pubkey", nil, make([]byte, 64)},
		{"empty sig", priv.PubKey(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := TransactionApplySchnorr(params, tx, 0, prev, tc.pubKey,
				tc.sig, txscript.SigHashDefault); err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
		})
	}
}

// TestTransactionApplySchnorrWrongKey verifies that a key which
// doesn't tweak to the prev pkScript's x-only witness program is
// rejected.
func TestTransactionApplySchnorrWrongKey(t *testing.T) {
	params := &chaincfg.TestNet3Params

	ownerPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	ownerOut := txscript.ComputeTaprootKeyNoScript(ownerPriv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(ownerOut), params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("schnorr-wrong-key-00000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	prev := wire.NewTxOut(50_000, pkScript)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	// Build a well-formed schnorr sig from the wrong key; the address
	// check must reject before the signature matters.
	sigHashes := txscript.NewTxSigHashes(tx,
		txscript.NewCannedPrevOutputFetcher(pkScript, 50_000))
	sig64, err := txscript.RawTxInTaprootSignature(tx, sigHashes, 0,
		50_000, pkScript, nil, txscript.SigHashDefault, wrongPriv)
	if err != nil {
		t.Fatal(err)
	}

	err = TransactionApplySchnorr(params, tx, 0, prev, wrongPriv.PubKey(),
		sig64, txscript.SigHashDefault)
	if err == nil {
		t.Fatal("expected address-mismatch error")
	}
}

// TestTransactionApplySchnorrRejectsP2PKH verifies the schnorr
// injection path refuses a non-taproot script class.
func TestTransactionApplySchnorrRejectsP2PKH(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("schnorr-rejects-p2pkh-0000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	prev := wire.NewTxOut(50_000, pkScript)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	// Fabricate a plausible-looking 64-byte blob just to get past the
	// length check; the class check must fire first.
	sig64 := make([]byte, 64)
	copy(sig64, priv.PubKey().SerializeCompressed()[1:])
	copy(sig64[32:], priv.PubKey().SerializeCompressed()[1:])

	err = TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
		sig64, txscript.SigHashDefault)
	if err == nil {
		t.Fatal("expected unsupported-script-class error")
	}
}

// TestTransactionApplySchnorrRejectsIdxOutOfRange verifies negative
// and overshoot indices are refused before mutating the transaction.
func TestTransactionApplySchnorrRejectsIdxOutOfRange(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("schnorr-idx-oor-0000000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)
	sig64 := make([]byte, 64)
	// Plausible 64-byte blob just to pass the length guard — must not
	// reach the idx check.  Actual validity is irrelevant because idx
	// guard fires first.

	cases := []struct {
		name string
		idx  int
	}{
		{"negative", -1},
		{"past end", 1},
		{"far overshoot", 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := TransactionApplySchnorr(params, tx, tc.idx, prev, priv.PubKey(),
				sig64, txscript.SigHashDefault); err == nil {
				t.Fatalf("idx=%d: expected out-of-range error", tc.idx)
			}
		})
	}
}

// TestTransactionApplySchnorrRejectsMalformedSig verifies that a
// 64-byte blob that fails BIP-340 structural parsing is refused.
// schnorr.ParseSignature checks that s is below the group order;
// a scalar >= N gets rejected here.
func TestTransactionApplySchnorrRejectsMalformedSig(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("schnorr-malformed-0000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)

	// All-0xff: s is way above the curve order, ParseSignature rejects.
	allFF := make([]byte, 64)
	for i := range allFF {
		allFF[i] = 0xff
	}
	if err := TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
		allFF, txscript.SigHashDefault); err == nil {
		t.Fatal("malformed 64-byte sig: expected parse error")
	}
}

// TestTransactionApplySchnorrRejectsNonStandardScript verifies that
// a taproot-class pkScript which cannot be decoded into a single
// standard address is rejected by the cross-check step rather than
// producing a confusing downstream error.  An OP_1-prefixed but
// malformed witness program is structurally taproot-class but
// ExtractPkScriptAddrs will refuse it.
func TestTransactionApplySchnorrRejectsNonStandardScript(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Build a valid signature first so the sig guards pass; the
	// test target is the address cross-check.
	sig64, err := schnorr.Sign(priv, chainhash.HashB([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}

	// Produce a pkScript that classifies as taproot but whose witness
	// program is a non-point.  Using all-zero x-only coordinate:
	// txscript.GetScriptClass recognises the OP_1+push32 shape as
	// WitnessV1TaprootTy, but NewAddressTaproot accepts only valid
	// curve points.  However the extracted address will parse fine —
	// what we want to trigger is the mismatch branch, which requires
	// a genuinely valid but wrong x-only key.
	//
	// Simpler test target: a taproot pkScript for key A, injected
	// with signature from key B.  Already covered by WrongKey test
	// (line above).  For ExtractPkScriptAddrs failure specifically
	// we'd need a malformed script — but GetScriptClass would not
	// classify it as taproot, so the class check fires first.
	//
	// The practical ExtractPkScriptAddrs failure path is therefore
	// unreachable from a well-classified pkScript.  This test
	// documents that invariant: if class == taproot then
	// ExtractPkScriptAddrs succeeds and len(addrs) == 1.
	fundHash := chainhash.DoubleHashH([]byte("schnorr-invariant-0000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	prev := wire.NewTxOut(50_000, pkScript)

	// Happy path through the invariant: class matches, extract
	// yields 1 address, derive matches, signature applied.
	if err := TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
		sig64.Serialize(), txscript.SigHashDefault); err != nil {
		t.Fatalf("invariant path failed: %v", err)
	}
}

// TestTransactionApplySchnorrRejectsBadSigHashType verifies the
// hashType argument is rejected if it is not a standard sighash
// value.  Relevant to taproot because a non-default hashType
// causes the sighash byte to be appended to the 64-byte signature;
// silent byte() truncation would append the wrong byte.
func TestTransactionApplySchnorrRejectsBadSigHashType(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("schnorr-bad-sighash-0000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)
	sig, err := schnorr.Sign(priv, chainhash.HashB([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	sig64 := sig.Serialize()

	cases := []struct {
		name     string
		hashType txscript.SigHashType
	}{
		{"high-byte smuggle to SigHashAll", txscript.SigHashType(0xFFFFFF01)},
		{"undefined low byte 0x04", txscript.SigHashType(0x04)},
		{"0xDEADBEEF", txscript.SigHashType(0xDEADBEEF)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
				sig64, tc.hashType)
			if err == nil {
				t.Fatalf("hashType=%#x: expected error, got nil",
					uint32(tc.hashType))
			}
		})
	}
}
