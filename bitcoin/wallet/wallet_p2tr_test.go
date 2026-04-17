// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul/memory"
)

// TestSignP2TRKeyPath verifies that a BIP-86 key-path taproot input
// signed via TransactionSign satisfies the script engine.
func TestSignP2TRKeyPath(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = m.PutKey(&zuul.NamedKey{Name: "taproot", PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}

	// Build the BIP-86 P2TR pkScript matching the stored internal key.
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	p2trAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	p2trScript, err := txscript.PayToAddrScript(p2trAddr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("p2tr-keypath-funding-txid-00000"))
	fundOutpoint := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	// Throwaway destination: another P2TR just to keep the output valid.
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
	tx.AddTxIn(wire.NewTxIn(fundOutpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(fundValue/2, destScript))

	prevOuts := PrevOuts{
		fundOutpoint.String(): wire.NewTxOut(fundValue, p2trScript),
	}

	err = TransactionSign(params, m, tx, prevOuts)
	if err != nil {
		t.Fatalf("TransactionSign: %v", err)
	}

	// Key-path witness is a single 64-byte schnorr signature (or 65
	// with a non-default sighash byte appended).
	if len(tx.TxIn[0].Witness) != 1 {
		t.Fatalf("expected 1-element witness, got %d", len(tx.TxIn[0].Witness))
	}
	sigLen := len(tx.TxIn[0].Witness[0])
	if sigLen != 64 && sigLen != 65 {
		t.Fatalf("unexpected schnorr sig length: %d", sigLen)
	}
	if len(tx.TxIn[0].SignatureScript) != 0 {
		t.Fatalf("expected empty SignatureScript for taproot input, got %d bytes",
			len(tx.TxIn[0].SignatureScript))
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("script engine rejected signed P2TR key-path input: %v", err)
	}
}

// TestSignMixedP2PKHAndP2TR proves a transaction mixing a legacy
// P2PKH input with a BIP-86 taproot input signs and verifies
// correctly for both inputs.  This is the shape btcwine's send-
// ordinal transaction takes: a taproot input holding the ordinal
// plus a P2PKH input funding the fee.
func TestSignMixedP2PKHAndP2TR(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	legacyPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	taprootPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := m.PutKey(&zuul.NamedKey{Name: "legacy", PrivateKey: legacyPriv}); err != nil {
		t.Fatal(err)
	}
	if err := m.PutKey(&zuul.NamedKey{Name: "taproot", PrivateKey: taprootPriv}); err != nil {
		t.Fatal(err)
	}

	// Legacy pkScript.
	legacyPKHash := btcutil.Hash160(legacyPriv.PubKey().SerializeCompressed())
	legacyAddr, err := btcutil.NewAddressPubKeyHash(legacyPKHash, params)
	if err != nil {
		t.Fatal(err)
	}
	legacyScript, err := txscript.PayToAddrScript(legacyAddr)
	if err != nil {
		t.Fatal(err)
	}

	// Taproot pkScript.
	taprootKey := txscript.ComputeTaprootKeyNoScript(taprootPriv.PubKey())
	taprootAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey), params)
	if err != nil {
		t.Fatal(err)
	}
	taprootScript, err := txscript.PayToAddrScript(taprootAddr)
	if err != nil {
		t.Fatal(err)
	}

	var h1, h2 chainhash.Hash
	copy(h1[:], []byte("mixed-legacy-input-000000000000000"))
	copy(h2[:], []byte("mixed-taproot-input-00000000000000"))
	op1 := wire.NewOutPoint(&h1, 0)
	op2 := wire.NewOutPoint(&h2, 0)

	const v1 int64 = 50_000 // legacy funding
	const v2 int64 = 10_000 // taproot (ordinal-shaped)

	destScript := taprootScript // send to ourselves for brevity

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op1, nil, nil))
	tx.AddTxIn(wire.NewTxIn(op2, nil, nil))
	tx.AddTxOut(wire.NewTxOut((v1+v2)/2, destScript))

	prevOuts := PrevOuts{
		op1.String(): wire.NewTxOut(v1, legacyScript),
		op2.String(): wire.NewTxOut(v2, taprootScript),
	}

	err = TransactionSign(params, m, tx, prevOuts)
	if err != nil {
		t.Fatalf("TransactionSign: %v", err)
	}

	// Legacy input: SignatureScript only.
	if len(tx.TxIn[0].SignatureScript) == 0 {
		t.Fatal("P2PKH input missing SignatureScript")
	}
	if len(tx.TxIn[0].Witness) != 0 {
		t.Fatalf("P2PKH input unexpectedly has witness")
	}

	// Taproot input: single witness element, no sigScript.
	if len(tx.TxIn[1].Witness) != 1 {
		t.Fatalf("taproot witness wrong length: got %d, want 1",
			len(tx.TxIn[1].Witness))
	}
	if len(tx.TxIn[1].SignatureScript) != 0 {
		t.Fatal("P2TR input unexpectedly has SignatureScript")
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected legacy input: %v", err)
	}
	if err := verifyInput(tx, 1, prevOuts); err != nil {
		t.Fatalf("engine rejected taproot input: %v", err)
	}
}
