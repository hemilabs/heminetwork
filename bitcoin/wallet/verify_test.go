// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// TestVerifyECDSAValid signs a hash with a known key and confirms
// VerifyECDSA accepts the resulting signature.
func TestVerifyECDSAValid(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hash := chainhash.HashB([]byte("verify-payload"))
	sig := ecdsa.Sign(priv, hash)

	if err := VerifyECDSA(hash, sig.Serialize(), priv.PubKey()); err != nil {
		t.Fatalf("VerifyECDSA rejected a valid signature: %v", err)
	}
}

// TestVerifyECDSAWrongKey confirms the helper rejects a signature
// produced by a different key than the one being verified against.
func TestVerifyECDSAWrongKey(t *testing.T) {
	signer, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hash := chainhash.HashB([]byte("verify-payload"))
	sig := ecdsa.Sign(signer, hash)

	if err := VerifyECDSA(hash, sig.Serialize(), other.PubKey()); err == nil {
		t.Fatal("expected verification failure for wrong key")
	}
}

// TestVerifyECDSAWrongHash confirms that signing h1 and verifying
// against h2 fails.  This catches the common bug of recomputing the
// sighash with different parameters on the verify side.
func TestVerifyECDSAWrongHash(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signedHash := chainhash.HashB([]byte("signed"))
	otherHash := chainhash.HashB([]byte("other"))
	sig := ecdsa.Sign(priv, signedHash)

	if err := VerifyECDSA(otherHash, sig.Serialize(), priv.PubKey()); err == nil {
		t.Fatal("expected verification failure for wrong hash")
	}
}

// TestVerifyECDSARejectsBad checks the structural guards: nil
// pubkey, wrong sighash length, empty signature, malformed DER.
func TestVerifyECDSARejectsBad(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hash := chainhash.HashB([]byte("x"))

	cases := []struct {
		name    string
		sigHash []byte
		sigDER  []byte
		pubKey  *btcec.PublicKey
	}{
		{"nil pubkey", hash, []byte{0x30, 0x00}, nil},
		{"short sighash", []byte{1, 2, 3}, []byte{0x30, 0x00}, priv.PubKey()},
		{"empty sig", hash, nil, priv.PubKey()},
		{"malformed DER", hash, []byte{0xff, 0xff}, priv.PubKey()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyECDSA(tc.sigHash, tc.sigDER, tc.pubKey); err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
		})
	}
}

// TestVerifySchnorrValid signs a hash with a known key (tweaked
// per BIP-86) and confirms VerifySchnorr accepts the resulting
// 64-byte signature against the tweaked x-only output key.
func TestVerifySchnorrValid(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// BIP-86 tweak: nil script root.
	tweaked := txscript.TweakTaprootPrivKey(*priv, nil)

	hash := chainhash.HashB([]byte("taproot-payload"))
	sig, err := schnorr.Sign(tweaked, hash)
	if err != nil {
		t.Fatal(err)
	}

	xOnly := schnorr.SerializePubKey(tweaked.PubKey())
	if err := VerifySchnorr(hash, sig.Serialize(), xOnly); err != nil {
		t.Fatalf("VerifySchnorr rejected a valid signature: %v", err)
	}
}

// TestVerifySchnorrWrongKey confirms a schnorr signature produced
// by one key fails verification against a different x-only pubkey.
func TestVerifySchnorrWrongKey(t *testing.T) {
	signer, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	hash := chainhash.HashB([]byte("taproot-payload"))
	sig, err := schnorr.Sign(signer, hash)
	if err != nil {
		t.Fatal(err)
	}

	otherXOnly := schnorr.SerializePubKey(other.PubKey())
	if err := VerifySchnorr(hash, sig.Serialize(), otherXOnly); err == nil {
		t.Fatal("expected verification failure for wrong key")
	}
}

// TestVerifySchnorrRejectsBad checks the structural guards: wrong
// sighash length, wrong sig length, wrong x-only pubkey length.
func TestVerifySchnorrRejectsBad(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	xOnly := schnorr.SerializePubKey(priv.PubKey())

	hash32 := make([]byte, 32)
	sig64 := make([]byte, 64)

	cases := []struct {
		name    string
		sigHash []byte
		sig     []byte
		pubKey  []byte
	}{
		{"short sighash", []byte{1, 2, 3}, sig64, xOnly},
		{"short sig", hash32, []byte{1, 2, 3}, xOnly},
		{"short pubkey", hash32, sig64, []byte{1, 2, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifySchnorr(tc.sigHash, tc.sig, tc.pubKey); err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
		})
	}
}

// TestVerifySchnorrTaprootAddressRoundTrip is an end-to-end sanity
// check: derive a taproot address from an internal key, sign a hash
// with the tweaked key, then verify using the x-only form of the
// tweaked output key.  This is the verification surface a caller
// uses before handing a TSS signature to TransactionApplySchnorr.
func TestVerifySchnorrTaprootAddressRoundTrip(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	tweaked := txscript.TweakTaprootPrivKey(*priv, nil)

	hash := chainhash.HashB([]byte("round-trip"))
	sig, err := schnorr.Sign(tweaked, hash)
	if err != nil {
		t.Fatal(err)
	}

	xOnly := schnorr.SerializePubKey(outputKey)
	if err := VerifySchnorr(hash, sig.Serialize(), xOnly); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
}

// TestVerifyECDSAGatesTransactionApplyECDSA proves VerifyECDSA sits
// on the real integration path between an external signer and
// TransactionApplyECDSA.  Flow:
//
//  1. Build a P2WPKH input.
//  2. Compute the BIP-143 sighash the external signer will sign.
//  3. Assemble the signature from raw (r, s) via ECDSASigFromRS —
//     the shape hemilabs/x/tss-lib/v3 returns.
//  4. Run VerifyECDSA as the pre-broadcast gate.
//  5. Only on success, inject via TransactionApplyECDSA.
//  6. Confirm the script engine accepts the result.
//
// This is the canonical caller flow the verify helpers were built
// to serve.  A regression in any step — sighash mismatch, DER
// malformation, wrong address binding — fails this test.
func TestVerifyECDSAGatesTransactionApplyECDSA(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubCompressed := priv.PubKey().SerializeCompressed()
	pkHash := btcutil.Hash160(pubCompressed)
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("verify-ecdsa-gate-0000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(fundValue/2, pkScript))

	prev := wire.NewTxOut(fundValue, pkScript)
	prevOuts := PrevOuts{op.String(): prev}

	// Step 2: sighash the external signer signs over.
	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	sigHash, err := txscript.CalcWitnessSigHash(pkScript, sigHashes,
		txscript.SigHashAll, tx, 0, fundValue)
	if err != nil {
		t.Fatal(err)
	}

	// Step 3: produce the signature as raw (r, s), assemble DER via
	// the helper that wraps the TSS output format.
	sig := ecdsa.Sign(priv, sigHash)
	r := sig.R()
	s := sig.S()
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigDER, err := ECDSASigFromRS(rBytes[:], sBytes[:])
	if err != nil {
		t.Fatalf("ECDSASigFromRS: %v", err)
	}

	// Step 4: gate.
	if err := VerifyECDSA(sigHash, sigDER, priv.PubKey()); err != nil {
		t.Fatalf("VerifyECDSA rejected a signature it should have accepted: %v", err)
	}

	// Step 5: inject.
	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, txscript.SigHashAll)
	if err != nil {
		t.Fatalf("TransactionApplyECDSA: %v", err)
	}

	// Step 6: script engine is the ultimate witness.
	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected gated+injected signature: %v", err)
	}
}

// TestVerifyECDSACatchesBadSignatureBeforeApply proves the gate
// rejects a malformed signature before it reaches
// TransactionApplyECDSA.  Without this gate a caller would only
// discover the bad signature at broadcast time.
func TestVerifyECDSACatchesBadSignatureBeforeApply(t *testing.T) {
	signer, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	sigHash := chainhash.HashB([]byte("payload"))

	// Signature produced by the wrong key — common TSS failure mode
	// (wrong keyID requested, committee agreed on a different key).
	sig := ecdsa.Sign(other, sigHash)
	sigDER := sig.Serialize()

	// Gate must reject against the claimed signer's pubkey.
	if err := VerifyECDSA(sigHash, sigDER, signer.PubKey()); err == nil {
		t.Fatal("VerifyECDSA accepted a signature from the wrong key")
	}
}

// TestVerifySchnorrGatesTransactionApplySchnorr is the schnorr
// counterpart: produces a BIP-340 signature over a BIP-341 taproot
// sighash, gates via VerifySchnorr with the tweaked x-only key,
// then injects via TransactionApplySchnorr.  The script engine
// accepts the result when the gate passes.
func TestVerifySchnorrGatesTransactionApplySchnorr(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("verify-schnorr-gate-0000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(fundValue/2, pkScript))

	prev := wire.NewTxOut(fundValue, pkScript)
	prevOuts := PrevOuts{op.String(): prev}

	// Produce signature through the same path a schnorr-TSS coordinator
	// would take: tweak per BIP-86, sign over the BIP-341 sighash.
	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	sig64, err := txscript.RawTxInTaprootSignature(tx, sigHashes, 0,
		fundValue, pkScript, nil, txscript.SigHashDefault, priv)
	if err != nil {
		t.Fatal(err)
	}
	sigHash, err := txscript.CalcTaprootSignatureHash(sigHashes,
		txscript.SigHashDefault, tx, 0, fetcher)
	if err != nil {
		t.Fatal(err)
	}

	tweakedXOnly := schnorr.SerializePubKey(outputKey)

	// Gate.
	if err := VerifySchnorr(sigHash, sig64, tweakedXOnly); err != nil {
		t.Fatalf("VerifySchnorr rejected a signature it should have accepted: %v", err)
	}

	// Inject.
	err = TransactionApplySchnorr(params, tx, 0, prev, priv.PubKey(),
		sig64, txscript.SigHashDefault)
	if err != nil {
		t.Fatalf("TransactionApplySchnorr: %v", err)
	}

	// Engine.
	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected gated+injected schnorr signature: %v", err)
	}
}
