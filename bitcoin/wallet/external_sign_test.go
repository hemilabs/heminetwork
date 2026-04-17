// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestECDSASigFromRSValid verifies the r/s assembly helper produces
// DER output that round-trips through ParseDERSignature.  This is
// the shape tss-lib returns signatures in.
func TestECDSASigFromRSValid(t *testing.T) {
	// Use a known signature: sign a hash with a throwaway key, then
	// split into r and s to round-trip.
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hash := chainhash.HashB([]byte("tss-regression-payload"))
	sig := ecdsa.Sign(priv, hash)

	r := sig.R()
	s := sig.S()
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Assemble via the helper.
	der, err := ECDSASigFromRS(rBytes[:], sBytes[:])
	if err != nil {
		t.Fatalf("ECDSASigFromRS: %v", err)
	}

	// Parsed sig must verify against the original pubkey and hash.
	parsed, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		t.Fatalf("ParseDERSignature: %v", err)
	}
	if !parsed.Verify(hash, priv.PubKey()) {
		t.Fatal("assembled DER signature failed to verify")
	}
}

// TestECDSASigFromRSRejectsBad verifies the helper refuses empty or
// overflow scalars.
func TestECDSASigFromRSRejectsBad(t *testing.T) {
	cases := []struct {
		name string
		r, s []byte
	}{
		{"empty r", nil, []byte{1}},
		{"empty s", []byte{1}, nil},
		{"zero r", make([]byte, 32), []byte{1}},
		{"zero s", []byte{1}, make([]byte, 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ECDSASigFromRS(tc.r, tc.s); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

// TestECDSASigFromRSLowSNormalization verifies the helper emits a
// low-S signature even when the input s is above N/2.  Bitcoin
// consensus rejects high-S signatures under ScriptVerifyLowS; any
// TSS producing high-S output would otherwise be unspendable.
func TestECDSASigFromRSLowSNormalization(t *testing.T) {
	// Build a scalar deliberately above N/2.  The curve order N's
	// upper half starts at (N+1)/2.  We construct s = N-1 which is
	// always > N/2.
	var nMinus1 secp256k1.ModNScalar
	nMinus1.SetInt(1).Negate() // N - 1

	if !nMinus1.IsOverHalfOrder() {
		t.Fatal("test setup: N-1 should be over half order")
	}

	rBytes := []byte{0x42}
	sFull := nMinus1.Bytes()
	der, err := ECDSASigFromRS(rBytes, sFull[:])
	if err != nil {
		t.Fatalf("ECDSASigFromRS: %v", err)
	}

	parsed, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		t.Fatalf("ParseDERSignature: %v", err)
	}
	parsedS := parsed.S()
	if parsedS.IsOverHalfOrder() {
		t.Fatal("serialized signature is not low-S")
	}
}

// signWithKeyToDER signs hash with priv and returns a DER-encoded
// signature (no sighash byte).  Used by injection tests to simulate
// what a TSS coordinator would hand back.
func signWithKeyToDER(priv *btcec.PrivateKey, hash []byte) []byte {
	sig := ecdsa.Sign(priv, hash)
	return sig.Serialize()
}

// TestTransactionApplyECDSAP2PKH exercises the P2PKH injection path
// end-to-end: build a tx with a P2PKH input, compute its sighash,
// sign externally with a known key, inject via TransactionApplyECDSA,
// and confirm the script engine accepts the result.
func TestTransactionApplyECDSAP2PKH(t *testing.T) {
	params := &chaincfg.TestNet3Params

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubCompressed := priv.PubKey().SerializeCompressed()
	pkHash := btcutil.Hash160(pubCompressed)
	addr, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("external-p2pkh-funding-00000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	destPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	destHash := btcutil.Hash160(destPriv.PubKey().SerializeCompressed())
	destAddr, err := btcutil.NewAddressPubKeyHash(destHash, params)
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

	// Compute sighash the way the P2PKH path does.
	sigHash, err := txscript.CalcSignatureHash(pkScript,
		txscript.SigHashAll, tx, 0)
	if err != nil {
		t.Fatal(err)
	}

	sigDER := signWithKeyToDER(priv, sigHash)
	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, txscript.SigHashAll)
	if err != nil {
		t.Fatalf("TransactionApplyECDSA: %v", err)
	}

	if len(tx.TxIn[0].SignatureScript) == 0 {
		t.Fatal("SignatureScript not set")
	}
	if len(tx.TxIn[0].Witness) != 0 {
		t.Fatalf("Witness unexpectedly set for P2PKH: %d elements",
			len(tx.TxIn[0].Witness))
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected injected P2PKH signature: %v", err)
	}
}

// TestTransactionApplyECDSAP2WPKH exercises the P2WPKH injection path
// end-to-end.  BIP-143 sighash is used, matching what a TSS
// coordinator would sign over for a segwit input.
func TestTransactionApplyECDSAP2WPKH(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("external-p2wpkh-funding-0000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	const fundValue int64 = 100_000

	destPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	destHash := btcutil.Hash160(destPriv.PubKey().SerializeCompressed())
	destAddr, err := btcutil.NewAddressPubKeyHash(destHash, params)
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

	// BIP-143 sighash for the P2WPKH input.
	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	sigHash, err := txscript.CalcWitnessSigHash(pkScript, sigHashes,
		txscript.SigHashAll, tx, 0, fundValue)
	if err != nil {
		t.Fatal(err)
	}

	sigDER := signWithKeyToDER(priv, sigHash)
	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, txscript.SigHashAll)
	if err != nil {
		t.Fatalf("TransactionApplyECDSA: %v", err)
	}

	if len(tx.TxIn[0].Witness) != 2 {
		t.Fatalf("witness wrong length: got %d, want 2",
			len(tx.TxIn[0].Witness))
	}
	if len(tx.TxIn[0].SignatureScript) != 0 {
		t.Fatal("SignatureScript unexpectedly set for P2WPKH")
	}
	if !bytes.Equal(tx.TxIn[0].Witness[1], pubCompressed) {
		t.Fatal("witness[1] does not match provided pubkey")
	}

	if err := verifyInput(tx, 0, prevOuts); err != nil {
		t.Fatalf("engine rejected injected P2WPKH signature: %v", err)
	}
}

// TestTransactionApplyECDSAWrongKey verifies the function rejects a
// pubkey that doesn't match the prev pkScript's address.  Without this
// check a caller could build an unspendable transaction at runtime.
func TestTransactionApplyECDSAWrongKey(t *testing.T) {
	params := &chaincfg.TestNet3Params

	ownerPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	pkHash := btcutil.Hash160(ownerPriv.PubKey().SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("wrong-key-funding-0000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(50_000, pkScript))

	prev := wire.NewTxOut(100_000, pkScript)

	sigDER := signWithKeyToDER(wrongPriv, chainhash.HashB([]byte("anything")))
	err = TransactionApplyECDSA(params, tx, 0, prev, wrongPriv.PubKey(),
		sigDER, txscript.SigHashAll)
	if err == nil {
		t.Fatal("expected address-mismatch error")
	}
}

// TestTransactionApplyECDSARejectsP2TR verifies the ECDSA injection
// path refuses P2TR inputs.  Taproot requires schnorr signatures;
// attempting to wire an ECDSA signature into a taproot witness would
// produce an unspendable transaction and warrants an explicit error.
func TestTransactionApplyECDSARejectsP2TR(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("reject-p2tr-funding-00000000000"))
	op := wire.NewOutPoint(&fundHash, 0)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(50_000, pkScript))

	prev := wire.NewTxOut(100_000, pkScript)

	sigDER := signWithKeyToDER(priv, chainhash.HashB([]byte("anything")))
	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		sigDER, txscript.SigHashDefault)
	if err == nil {
		t.Fatal("expected unsupported-script-class error for P2TR")
	}
}

// TestECDSASigFromRSRejectsOverflow verifies the helper refuses
// scalars that equal or exceed the secp256k1 group order.  An
// overflow scalar cannot be reduced mod N without losing
// information, so the helper must return an error rather than
// silently wrap around.
func TestECDSASigFromRSRejectsOverflow(t *testing.T) {
	// N for secp256k1 is
	// 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141.
	// Any scalar >= N triggers the overflow branch in
	// ModNScalar.SetByteSlice.
	n := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
		0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
	}
	// Above N: N itself, N+1, and all-0xff.
	allFF := make([]byte, 32)
	for i := range allFF {
		allFF[i] = 0xff
	}
	nPlus1 := append([]byte{}, n...)
	nPlus1[31]++

	cases := []struct {
		name string
		r, s []byte
	}{
		{"r equals N", n, []byte{1}},
		{"s equals N", []byte{1}, n},
		{"r equals N+1", nPlus1, []byte{1}},
		{"s equals N+1", []byte{1}, nPlus1},
		{"r all-0xff", allFF, []byte{1}},
		{"s all-0xff", []byte{1}, allFF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ECDSASigFromRS(tc.r, tc.s); err == nil {
				t.Fatalf("expected overflow error")
			}
		})
	}
}

// FuzzECDSASigFromRS exercises the r/s assembly helper with random
// byte slices.  The helper must never panic regardless of input:
// every error path returns a Go error rather than crashing.  This
// is Günther's fuzz-required rule — anything that parses input
// gets fuzzed.
func FuzzECDSASigFromRS(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x01}, []byte{0x01})
	f.Add(make([]byte, 32), make([]byte, 32)) // zero-zero
	f.Add(make([]byte, 33), make([]byte, 33)) // oversize
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0xff}, 32))

	f.Fuzz(func(t *testing.T, r, s []byte) {
		// Must not panic for any input.  Errors are fine, crashes
		// are not.  If the helper returns a signature, it must
		// round-trip through ParseDERSignature — anything the
		// helper emits must be valid DER.
		sig, err := ECDSASigFromRS(r, s)
		if err != nil {
			return
		}
		if _, perr := ecdsa.ParseDERSignature(sig); perr != nil {
			t.Fatalf("helper emitted unparseable DER: %v", perr)
		}
	})
}

// TestTransactionApplyECDSARejectsIdxOutOfRange verifies the function
// refuses negative or out-of-bounds input indices before mutating
// the transaction.  Buggy callers passing an index computed from a
// stale copy would otherwise panic on tx.TxIn[idx].
func TestTransactionApplyECDSARejectsIdxOutOfRange(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("idx-oor-funding-00000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)
	sigDER := signWithKeyToDER(priv, chainhash.HashB([]byte("x")))

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
			if err := TransactionApplyECDSA(params, tx, tc.idx, prev, priv.PubKey(),
				sigDER, txscript.SigHashAll); err == nil {
				t.Fatalf("idx=%d: expected out-of-range error", tc.idx)
			}
		})
	}
}

// TestTransactionApplyECDSARejectsEmptyAndMalformedSig verifies the
// guards catch zero-length DER and non-DER bytes before reaching
// the script builder.  A caller whose TSS coordinator returned a
// buffer of the wrong shape would otherwise embed unspendable
// garbage into the witness.
func TestTransactionApplyECDSARejectsEmptyAndMalformedSig(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("bad-sig-funding-00000000000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)

	cases := []struct {
		name   string
		sigDER []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		// Plausible-looking but invalid DER: 0x30 len marker with garbage.
		{"malformed DER", []byte{0x30, 0x02, 0xff, 0xff}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
				tc.sigDER, txscript.SigHashAll); err == nil {
				t.Fatalf("expected error for %s sigDER", tc.name)
			}
		})
	}
}

// TestTransactionApplyECDSARejectsNilArgs verifies the nil-guard
// refuses tx, prev, or pubKey = nil without panicking on deref.
func TestTransactionApplyECDSARejectsNilArgs(t *testing.T) {
	params := &chaincfg.TestNet3Params
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := wire.NewMsgTx(2)
	prev := wire.NewTxOut(1, []byte{txscript.OP_DUP})
	sigDER := signWithKeyToDER(priv, chainhash.HashB([]byte("x")))

	cases := []struct {
		name   string
		tx     *wire.MsgTx
		prev   *wire.TxOut
		pubKey *btcec.PublicKey
	}{
		{"nil tx", nil, prev, priv.PubKey()},
		{"nil prev", tx, nil, priv.PubKey()},
		{"nil pubKey", tx, prev, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := TransactionApplyECDSA(params, tc.tx, 0, tc.prev, tc.pubKey,
				sigDER, txscript.SigHashAll); err == nil {
				t.Fatalf("%s: expected nil-argument error", tc.name)
			}
		})
	}
}

// TestTransactionApplyECDSARejectsBadSigHashType verifies that the
// hashType argument is rejected if it is not a standard sighash
// value.  Silent byte() truncation of uint32 would otherwise let
// an attacker-controlled 0xFFFF_FF01 masquerade as SigHashAll.
func TestTransactionApplyECDSARejectsBadSigHashType(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("bad-sighash-funding-0000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)
	sigDER := signWithKeyToDER(priv, chainhash.HashB([]byte("x")))

	cases := []struct {
		name     string
		hashType txscript.SigHashType
	}{
		// Smuggles low-byte 0x01 (SigHashAll) inside a uint32 that
		// doesn't match any standard sighash.
		{"high-byte smuggle to SigHashAll", txscript.SigHashType(0xFFFFFF01)},
		// 0x04 is below the anyonecanpay bit but not a defined value.
		{"undefined low byte 0x04", txscript.SigHashType(0x04)},
		// AnyoneCanPay with no base sighash is ambiguous.
		{"bare AnyoneCanPay", txscript.SigHashAnyOneCanPay},
		// Truly exotic.
		{"0xDEADBEEF", txscript.SigHashType(0xDEADBEEF)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
				sigDER, tc.hashType)
			if err == nil {
				t.Fatalf("hashType=%#x: expected error, got nil",
					uint32(tc.hashType))
			}
		})
	}
}

// TestTransactionApplyECDSARejectsOversizedSig verifies the length
// cap catches attacker-controlled sigDER buffers before the full
// copy into sigWithHash.  Without the cap, a 1MB sigDER would be
// copied in full before the DER parser ran; the cap short-circuits
// that allocation path.
func TestTransactionApplyECDSARejectsOversizedSig(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("oversized-sig-funding-000000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	prev := wire.NewTxOut(50_000, pkScript)

	// Start with a valid DER signature and pad past the cap.
	validDER := signWithKeyToDER(priv, chainhash.HashB([]byte("x")))
	oversized := make([]byte, 4096)
	copy(oversized, validDER)

	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		oversized, txscript.SigHashAll)
	if err == nil {
		t.Fatal("oversized sigDER: expected length-cap error")
	}
}

// TestTransactionApplyECDSAAcceptsUnverifiedSig documents the
// deliberate design: Apply checks DER structure and address
// binding, but does NOT cryptographically verify the signature.
// A structurally-valid DER signed over the wrong sighash is
// injected successfully by Apply, then rejected by the script
// engine on broadcast.  This separation lets callers drive TSS
// replay or debugging flows without re-signing.  Callers that
// want the crypto check must call VerifyECDSA first (see
// TestVerifyECDSAGatesTransactionApplyECDSA).
func TestTransactionApplyECDSAAcceptsUnverifiedSig(t *testing.T) {
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

	fundHash := chainhash.DoubleHashH([]byte("unverified-sig-funding-00000"))
	op := wire.NewOutPoint(&fundHash, 0)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))
	tx.AddTxOut(wire.NewTxOut(25_000, pkScript))

	prev := wire.NewTxOut(50_000, pkScript)
	prevOuts := PrevOuts{op.String(): prev}

	// Sign an UNRELATED message, not the tx's sighash.  DER is
	// structurally valid, matches the claimed pubkey, but won't
	// verify against the real sighash the engine computes.
	unrelatedDER := signWithKeyToDER(priv, chainhash.HashB([]byte("not the sighash")))

	// Apply accepts it — it only checks structure + address binding.
	err = TransactionApplyECDSA(params, tx, 0, prev, priv.PubKey(),
		unrelatedDER, txscript.SigHashAll)
	if err != nil {
		t.Fatalf("Apply rejected a structurally-valid signature: %v", err)
	}

	// Engine rejects it — the network guards the real correctness.
	if err := verifyInput(tx, 0, prevOuts); err == nil {
		t.Fatal("engine accepted a signature over the wrong message")
	}
}
