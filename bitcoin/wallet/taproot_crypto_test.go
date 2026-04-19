// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"encoding/hex"
	"strings"
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

// The tests in this file focus on the taproot witness crypto
// introduced by the P2TR key-path signer, the schnorr external-
// signing helpers, and the verify helpers.  Happy paths already
// have coverage in wallet_p2tr_test.go, external_sign_schnorr_test.go,
// and verify_test.go; this file fills in the negative paths that
// exercise the crypto primitives themselves rather than plumbing.

// --- helpers ---------------------------------------------------------

// newP2TRKey returns a fresh private key plus the BIP-86 tweaked
// address and pkScript paying to its output key.  No script
// commitment (nil script root).
func newP2TRKey(t *testing.T, params *chaincfg.Params) (*btcec.PrivateKey, btcutil.Address, []byte) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(outputKey), params)
	if err != nil {
		t.Fatal(err)
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	return priv, addr, script
}

// singleInputTxAt builds a one-input, one-output tx spending
// (fundHash, 0) of value `val` under pkScript, sending half to a
// throwaway P2TR output on the same params.  Returned PrevOuts
// contains the single prevout.
func singleInputTxAt(t *testing.T, params *chaincfg.Params, pkScript []byte, val int64, fundTag string) (*wire.MsgTx, PrevOuts, *wire.OutPoint) {
	t.Helper()

	fundHash := chainhash.DoubleHashH([]byte(fundTag))
	outpoint := wire.NewOutPoint(&fundHash, 0)

	_, _, destScript := newP2TRKey(t, params)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(val/2, destScript))

	prevOuts := PrevOuts{
		outpoint.String(): wire.NewTxOut(val, pkScript),
	}
	return tx, prevOuts, outpoint
}

// --- signP2TRKeyPath negative paths ----------------------------------

// TestSignP2TRKeyPathRejectsTamperedTx confirms the BIP-341 sighash
// algorithm commits to the transaction: changing any committed field
// after signing invalidates the witness.  This is the core guarantee
// callers rely on for taproot — any mutation between sign and broadcast
// is detectable by the verifier.
//
// Covers: signP2TRKeyPath happy path plus script-engine rejection
// across amount, outpoint, and output-value tampering.
func TestSignP2TRKeyPathRejectsTamperedTx(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, pkScript := newP2TRKey(t, params)
	if err := m.PutKey(&zuul.NamedKey{Name: "tap", PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}

	const fundValue int64 = 250_000

	cases := []struct {
		name   string
		tamper func(tx *wire.MsgTx, prevOuts PrevOuts)
	}{
		{
			name: "mutate output value",
			tamper: func(tx *wire.MsgTx, _ PrevOuts) {
				tx.TxOut[0].Value++
			},
		},
		{
			name: "mutate output script",
			tamper: func(tx *wire.MsgTx, _ PrevOuts) {
				tx.TxOut[0].PkScript = append([]byte{}, tx.TxOut[0].PkScript...)
				tx.TxOut[0].PkScript[len(tx.TxOut[0].PkScript)-1] ^= 0x01
			},
		},
		{
			name: "mutate input sequence",
			tamper: func(tx *wire.MsgTx, _ PrevOuts) {
				tx.TxIn[0].Sequence ^= 1
			},
		},
		{
			name: "mutate prev amount (BIP-341 commits to amount)",
			tamper: func(_ *wire.MsgTx, prevOuts PrevOuts) {
				// Taproot sighash (BIP-341) commits to every
				// input's prev-amount; legacy sighash does not.
				// Bumping the prev value by one sat after
				// signing invalidates the witness.
				for k, v := range prevOuts {
					prevOuts[k] = wire.NewTxOut(v.Value+1, v.PkScript)
					break
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, prevOuts, _ := singleInputTxAt(t, params, pkScript,
				fundValue, "tamper-"+tc.name)
			if err := TransactionSign(params, m, tx, prevOuts); err != nil {
				t.Fatalf("TransactionSign: %v", err)
			}
			// Pre-tamper: verify happy path.
			if err := verifyInput(tx, 0, prevOuts); err != nil {
				t.Fatalf("pre-tamper engine failure: %v", err)
			}
			// Re-fetch prev from the possibly-mutated key.
			tc.tamper(tx, prevOuts)
			if err := verifyInput(tx, 0, prevOuts); err == nil {
				t.Fatal("expected engine rejection of tampered tx")
			}
		})
	}
}

// TestSignP2TRKeyPathWrongKey stores key A in zuul under a pkScript
// that actually commits to key B's output key, then invokes
// TransactionSign.  resolveInputSigningKey has no way to notice — it
// looks up by the address extracted from pkScript, which is key B's
// address, which has no entry.  The signer must fail with a key-not-
// found error rather than silently signing with whatever key happens
// to share storage.
//
// Covers: resolveInputSigningKey not-found path (wallet.go:240-242).
func TestSignP2TRKeyPathWrongKey(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}
	keyA, _, _ := newP2TRKey(t, params)
	_, _, scriptB := newP2TRKey(t, params) // key B is not stored

	if err := m.PutKey(&zuul.NamedKey{Name: "A", PrivateKey: keyA}); err != nil {
		t.Fatal(err)
	}

	tx, prevOuts, _ := singleInputTxAt(t, params, scriptB, 50_000, "wrong-key")
	err = TransactionSign(params, m, tx, prevOuts)
	if err == nil {
		t.Fatal("expected key-not-found error")
	}
	if !strings.Contains(err.Error(), "lookup key") {
		t.Fatalf("expected lookup-key error, got: %v", err)
	}
}

// TestResolveInputSigningKeyMalformedPkScript exercises the
// ExtractPkScriptAddrs error path in resolveInputSigningKey.  A
// pkScript containing only OP_RETURN + garbage extracts zero
// addresses on many btcd versions; an intentionally-truncated push
// opcode produces a parse error on all versions.
//
// Covers: resolveInputSigningKey extract-error path (wallet.go:230-232)
// and the zero-addresses guard (wallet.go:233-235).
func TestResolveInputSigningKeyMalformedPkScript(t *testing.T) {
	params := &chaincfg.TestNet3Params
	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		pkScript []byte
	}{
		{
			// OP_DATA_32 followed by fewer than 32 bytes —
			// parser reports a short-push error.
			name:     "truncated push",
			pkScript: append([]byte{0x20}, make([]byte, 10)...),
		},
		{
			// OP_RETURN payload — extracts zero addresses,
			// hitting the len(addrs) != 1 guard.
			name:     "op_return",
			pkScript: []byte{txscript.OP_RETURN, 0x04, 0xde, 0xad, 0xbe, 0xef},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveInputSigningKey(params, m, tc.pkScript)
			if err == nil {
				t.Fatal("expected resolve error")
			}
		})
	}
}

// --- pubKeyMatchesTaprootAddress negative paths ----------------------

// TestPubKeyMatchesTaprootAddressRejectsWrongKey produces a P2TR
// pkScript from one key and calls the helper with a different pubkey.
// The tweaked-pubkey equality check must reject.
//
// Covers: pubKeyMatchesTaprootAddress mismatch path
// (external_sign_schnorr.go mismatch return).
func TestPubKeyMatchesTaprootAddressRejectsWrongKey(t *testing.T) {
	params := &chaincfg.TestNet3Params
	_, _, script := newP2TRKey(t, params)

	other, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	err = pubKeyMatchesTaprootAddress(params, script, other.PubKey())
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected match-failure error, got: %v", err)
	}
}

// TestPubKeyMatchesTaprootAddressRejectsUntweakedKey feeds the helper
// an *untweaked* internal key when the pkScript commits to the
// tweaked output key.  Demonstrates the helper applies BIP-86 tweak
// correctly: a caller who forgets to tweak (or double-tweaks) gets
// a clean error rather than silent divergence.
func TestPubKeyMatchesTaprootAddressRejectsUntweakedKey(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Build a pkScript that commits to the *raw* internal pubkey
	// (not the BIP-86 tweak), so that passing the same raw pubkey
	// to pubKeyMatchesTaprootAddress causes the helper's internal
	// tweak step to over-tweak and mismatch.
	rawXOnly := schnorr.SerializePubKey(priv.PubKey())
	addr, err := btcutil.NewAddressTaproot(rawXOnly, params)
	if err != nil {
		t.Fatal(err)
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	err = pubKeyMatchesTaprootAddress(params, script, priv.PubKey())
	if err == nil {
		t.Fatal("expected mismatch error: raw pkScript vs tweaked-match")
	}
}

// TestPubKeyMatchesTaprootAddressRejectsMalformedPkScript covers the
// ExtractPkScriptAddrs error path (truncated push) and the
// zero-addresses guard (OP_RETURN).
//
// Covers: pubKeyMatchesTaprootAddress extract-error and
// len(addrs) != 1 paths (external_sign_schnorr.go:105-110).
func TestPubKeyMatchesTaprootAddressRejectsMalformedPkScript(t *testing.T) {
	params := &chaincfg.TestNet3Params
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		pkScript []byte
	}{
		{"truncated push", append([]byte{0x20}, make([]byte, 10)...)},
		{"op_return", []byte{txscript.OP_RETURN, 0x04, 0xde, 0xad, 0xbe, 0xef}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pubKeyMatchesTaprootAddress(params, tc.pkScript, priv.PubKey())
			if err == nil {
				t.Fatal("expected error on malformed pkScript")
			}
		})
	}
}

// --- VerifySchnorr crypto parse paths --------------------------------

// TestVerifySchnorrRejectsMalformedSig feeds 64 bytes of
// well-structured garbage: the `r` component is a value not on
// the secp256k1 curve (x >= field prime).  schnorr.ParseSignature
// rejects, so the helper's parse-error branch fires.
//
// Covers: VerifySchnorr ParseSignature error (verify.go:73-75).
func TestVerifySchnorrRejectsMalformedSig(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	xOnly := schnorr.SerializePubKey(priv.PubKey())
	hash := chainhash.HashB([]byte("hash-for-parse-fail"))

	// schnorr sig layout: r (32) || s (32).  Set r to the secp256k1
	// field prime p — explicitly invalid as a curve x-coordinate.
	// Keep s any value < group order (but non-zero) so s-parsing
	// does not short-circuit the r-parse failure.
	sig := make([]byte, 64)
	// p (field prime) big-endian.
	p, err := hex.DecodeString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	if err != nil {
		t.Fatal(err)
	}
	copy(sig[0:32], p)
	sig[63] = 1 // s = 1

	err = VerifySchnorr(hash, sig, xOnly)
	if err == nil {
		t.Fatal("expected parse error for invalid r")
	}
	if !strings.Contains(err.Error(), "parse signature") {
		t.Fatalf("expected parse-signature error, got: %v", err)
	}
}

// TestVerifySchnorrRejectsMalformedPubKey feeds 32 bytes that decode
// as an x-coordinate not on the curve.  schnorr.ParsePubKey rejects,
// so the helper's pubkey-parse branch fires.
//
// Covers: VerifySchnorr ParsePubKey error (verify.go:77-79).
func TestVerifySchnorrRejectsMalformedPubKey(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hash := chainhash.HashB([]byte("hash-for-pubkey-parse-fail"))
	sig, err := schnorr.Sign(priv, hash)
	if err != nil {
		t.Fatal(err)
	}

	// Set x = field prime p: fits in 32 bytes but exceeds the
	// secp256k1 field modulus, so schnorr.ParsePubKey rejects it
	// as an out-of-range x-coordinate before any curve check.
	bad, err := hex.DecodeString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	if err != nil {
		t.Fatal(err)
	}

	err = VerifySchnorr(hash, sig.Serialize(), bad)
	if err == nil {
		t.Fatal("expected parse error for invalid pubkey x-coordinate")
	}
	if !strings.Contains(err.Error(), "parse x-only pubkey") {
		t.Fatalf("expected parse-pubkey error, got: %v", err)
	}
}

// --- Roundtrip end-to-end with external schnorr ---------------------

// TestSchnorrExternalSignRoundTrip simulates the TSS flow end-to-end:
// compute the BIP-341 sighash outside the wallet, sign externally
// with the tweaked key, verify via VerifySchnorr against the tweaked
// x-only output key, then splice the 64-byte sig into the tx via
// TransactionApplySchnorr, and confirm the full witness satisfies
// the script engine.  Also cross-checks that changing any bit of the
// sig causes verifyInput to reject.
func TestSchnorrExternalSignRoundTrip(t *testing.T) {
	params := &chaincfg.TestNet3Params
	priv, _, pkScript := newP2TRKey(t, params)

	tx, prevOuts, _ := singleInputTxAt(t, params, pkScript, 200_000, "roundtrip")

	// External signing: compute sighash, sign with tweaked key.
	tweaked := txscript.TweakTaprootPrivKey(*priv, nil)
	sighashes := txscript.NewTxSigHashes(tx, prevOutsFetcher(prevOuts))
	sigHash, err := txscript.CalcTaprootSignatureHash(sighashes,
		txscript.SigHashDefault, tx, 0, prevOutsFetcher(prevOuts))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(tweaked, sigHash)
	if err != nil {
		t.Fatal(err)
	}
	sig64 := sig.Serialize()

	// VerifySchnorr against the tweaked output key — this is the
	// pre-broadcast check a TSS coordinator performs.
	xOnlyOutput := schnorr.SerializePubKey(tweaked.PubKey())
	if err := VerifySchnorr(sigHash, sig64, xOnlyOutput); err != nil {
		t.Fatalf("VerifySchnorr on freshly-produced sig failed: %v", err)
	}

	// Splice into tx and verify via script engine.
	prev := prevOuts[tx.TxIn[0].PreviousOutPoint.String()]
	if err := TransactionApplySchnorr(params, tx, 0, prev,
		priv.PubKey(), sig64, txscript.SigHashDefault); err != nil {
		t.Fatalf("TransactionApplySchnorr: %v", err)
	}
	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected signed taproot input: %v", err)
	}

	// Negative control: flip one bit of the sig, the engine rejects.
	// We have to restore the witness, flip, splice again, verify.
	sigFlipped := append([]byte{}, sig64...)
	sigFlipped[0] ^= 0x01
	if err := VerifySchnorr(sigHash, sigFlipped, xOnlyOutput); err == nil {
		t.Fatal("VerifySchnorr accepted a bit-flipped signature")
	}
	tx.TxIn[0].Witness = wire.TxWitness{sigFlipped}
	if err := verifyInput(tx, 0, prevOuts); err == nil {
		t.Fatal("engine accepted a bit-flipped taproot signature")
	}
}

// TestSchnorrCrossInputRejectsReplay builds two identical-shape
// transactions with different inputs and confirms that swapping a
// signature from one into the other fails the script engine.  This
// is the cross-input replay defense baked into BIP-341: the taproot
// sighash commits to the input index and all prev-scripts.
func TestSchnorrCrossInputRejectsReplay(t *testing.T) {
	params := &chaincfg.TestNet3Params

	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, pkScript := newP2TRKey(t, params)
	if err := m.PutKey(&zuul.NamedKey{Name: "tap", PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}

	// Two txs spending different outpoints under the same pkScript.
	txA, prevA, _ := singleInputTxAt(t, params, pkScript, 100_000, "replay-A")
	txB, prevB, _ := singleInputTxAt(t, params, pkScript, 100_000, "replay-B")

	if err := TransactionSign(params, m, txA, prevA); err != nil {
		t.Fatal(err)
	}
	if err := TransactionSign(params, m, txB, prevB); err != nil {
		t.Fatal(err)
	}

	// Sanity: each verifies against its own prev.
	if err := verifyInput(txA, 0, prevA); err != nil {
		t.Fatalf("txA self-verify: %v", err)
	}
	if err := verifyInput(txB, 0, prevB); err != nil {
		t.Fatalf("txB self-verify: %v", err)
	}

	// Replay: swap witness from A into B.  Sighash commits to
	// the prev outpoint (via txid), so this must fail.
	if bytes.Equal(txA.TxIn[0].Witness[0], txB.TxIn[0].Witness[0]) {
		t.Fatal("two sighashes produced identical signatures; test premise broken")
	}
	txB.TxIn[0].Witness = txA.TxIn[0].Witness
	if err := verifyInput(txB, 0, prevB); err == nil {
		t.Fatal("engine accepted a cross-tx schnorr replay")
	}
}
