// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul/memory"
)

// verifyInput runs the script engine on a single input and returns the
// result.  For witness inputs the engine walks both the witness and
// the prev pkScript and applies BIP-143 sighash verification.
func verifyInput(tx *wire.MsgTx, idx int, prev *wire.TxOut) error {
	flags := txscript.StandardVerifyFlags
	fetcher := txscript.NewCannedPrevOutputFetcher(prev.PkScript, prev.Value)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	vm, err := txscript.NewEngine(prev.PkScript, tx, idx, flags, nil,
		sigHashes, prev.Value, fetcher)
	if err != nil {
		return err
	}
	return vm.Execute()
}

// TestSignP2WPKHInput exercises witness v0 pubkey hash signing through
// the public TransactionSign entry point and verifies the resulting
// witness satisfies the script engine.
func TestSignP2WPKHInput(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = m.PutKey(&zuul.NamedKey{Name: "p2wpkh", PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}

	// Build the P2WPKH pkScript for the previous output.
	pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
	p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	p2wpkhScript, err := txscript.PayToAddrScript(p2wpkhAddr)
	if err != nil {
		t.Fatal(err)
	}

	// Synthesize a funding outpoint; the hash value is arbitrary —
	// the engine only checks signatures against the tx and prev TxOut.
	fundHash := chainhash.DoubleHashH([]byte("test-funding-txid-00000000000000"))
	fundOutpoint := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	// Build a tx that spends the P2WPKH input and sends half to a
	// throwaway P2PKH output.
	destPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	destPKHash := btcutil.Hash160(destPriv.PubKey().SerializeCompressed())
	destAddr, err := btcutil.NewAddressPubKeyHash(destPKHash, params)
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
		fundOutpoint.String(): wire.NewTxOut(fundValue, p2wpkhScript),
	}

	err = TransactionSign(params, m, tx, prevOuts)
	if err != nil {
		t.Fatalf("TransactionSign: %v", err)
	}

	if len(tx.TxIn[0].Witness) != 2 {
		t.Fatalf("expected 2-element witness, got %d", len(tx.TxIn[0].Witness))
	}
	if len(tx.TxIn[0].SignatureScript) != 0 {
		t.Fatalf("expected empty SignatureScript for segwit input, got %d bytes",
			len(tx.TxIn[0].SignatureScript))
	}

	err = verifyInput(tx, 0, prevOuts[fundOutpoint.String()])
	if err != nil {
		t.Fatalf("script engine rejected signed P2WPKH input: %v", err)
	}
}

// TestSignMixedP2PKHAndP2WPKH verifies that a single transaction with
// one P2PKH input and one P2WPKH input, signed by different keys, is
// accepted by the script engine for both inputs.
func TestSignMixedP2PKHAndP2WPKH(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	legacyPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	segwitPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = m.PutKey(&zuul.NamedKey{Name: "legacy", PrivateKey: legacyPriv})
	if err != nil {
		t.Fatal(err)
	}
	err = m.PutKey(&zuul.NamedKey{Name: "segwit", PrivateKey: segwitPriv})
	if err != nil {
		t.Fatal(err)
	}

	legacyPKHash := btcutil.Hash160(legacyPriv.PubKey().SerializeCompressed())
	legacyAddr, err := btcutil.NewAddressPubKeyHash(legacyPKHash, params)
	if err != nil {
		t.Fatal(err)
	}
	legacyScript, err := txscript.PayToAddrScript(legacyAddr)
	if err != nil {
		t.Fatal(err)
	}

	segwitPKHash := btcutil.Hash160(segwitPriv.PubKey().SerializeCompressed())
	segwitAddr, err := btcutil.NewAddressWitnessPubKeyHash(segwitPKHash, params)
	if err != nil {
		t.Fatal(err)
	}
	segwitScript, err := txscript.PayToAddrScript(segwitAddr)
	if err != nil {
		t.Fatal(err)
	}

	var h1, h2 chainhash.Hash
	copy(h1[:], []byte("legacy-funding-input-0000000000000"))
	copy(h2[:], []byte("segwit-funding-input-0000000000000"))
	op1 := wire.NewOutPoint(&h1, 0)
	op2 := wire.NewOutPoint(&h2, 0)

	const v1 int64 = 50_000
	const v2 int64 = 80_000

	// Throwaway destination.
	destPKHash := btcutil.Hash160(legacyPriv.PubKey().SerializeCompressed())
	destAddr, err := btcutil.NewAddressPubKeyHash(destPKHash, params)
	if err != nil {
		t.Fatal(err)
	}
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		t.Fatal(err)
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op1, nil, nil))
	tx.AddTxIn(wire.NewTxIn(op2, nil, nil))
	tx.AddTxOut(wire.NewTxOut((v1+v2)/2, destScript))

	prevOuts := PrevOuts{
		op1.String(): wire.NewTxOut(v1, legacyScript),
		op2.String(): wire.NewTxOut(v2, segwitScript),
	}

	err = TransactionSign(params, m, tx, prevOuts)
	if err != nil {
		t.Fatalf("TransactionSign: %v", err)
	}

	// Legacy input must produce SignatureScript only.
	if len(tx.TxIn[0].SignatureScript) == 0 {
		t.Fatal("P2PKH input missing SignatureScript")
	}
	if len(tx.TxIn[0].Witness) != 0 {
		t.Fatalf("P2PKH input has unexpected witness length %d", len(tx.TxIn[0].Witness))
	}

	// Segwit input must produce Witness only.
	if len(tx.TxIn[1].Witness) != 2 {
		t.Fatalf("P2WPKH witness wrong length: got %d, want 2",
			len(tx.TxIn[1].Witness))
	}
	if len(tx.TxIn[1].SignatureScript) != 0 {
		t.Fatalf("P2WPKH input has SignatureScript: %d bytes",
			len(tx.TxIn[1].SignatureScript))
	}

	if err := verifyInput(tx, 0, prevOuts[op1.String()]); err != nil {
		t.Fatalf("engine rejected P2PKH input: %v", err)
	}
	if err := verifyInput(tx, 1, prevOuts[op2.String()]); err != nil {
		t.Fatalf("engine rejected P2WPKH input: %v", err)
	}
}
