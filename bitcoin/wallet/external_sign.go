// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// maxECDSASigDERLen is a generous upper bound on a DER-encoded
// ECDSA signature over secp256k1.  The real maximum is 72 bytes
// (0x30 <len> 0x02 <rLen=33> <r> 0x02 <sLen=33> <s> with leading
// zero bytes for r and s when their high bit is set).  The cap
// gives headroom for encodings we might not have seen while still
// rejecting attacker-controlled buffers that would otherwise be
// copied in full before the DER parser runs.
const maxECDSASigDERLen = 128

// ECDSASigFromRS assembles a DER-encoded ECDSA signature from raw
// big-endian r and s scalar bytes as produced by many threshold
// signature libraries (including hemilabs/x/tss-lib/v3).  The
// signature is normalised to low-S form per BIP-146 before encoding;
// a high-S input is implicitly negated by Serialize so the encoded
// signature is accepted by Bitcoin consensus rules.
//
// Each of r and s is interpreted as a big-endian unsigned integer
// modulo the secp256k1 group order.  A zero scalar or a scalar at
// or above the group order is rejected as invalid.
func ECDSASigFromRS(r, s []byte) ([]byte, error) {
	if len(r) == 0 || len(s) == 0 {
		return nil, fmt.Errorf("empty scalar")
	}

	var rs, ss secp256k1.ModNScalar
	if overflow := rs.SetByteSlice(r); overflow {
		return nil, fmt.Errorf("r overflows group order")
	}
	if rs.IsZero() {
		return nil, fmt.Errorf("r is zero")
	}
	if overflow := ss.SetByteSlice(s); overflow {
		return nil, fmt.Errorf("s overflows group order")
	}
	if ss.IsZero() {
		return nil, fmt.Errorf("s is zero")
	}

	sig := ecdsa.NewSignature(&rs, &ss)
	return sig.Serialize(), nil
}

// TransactionApplyECDSA applies an externally-computed ECDSA signature
// to a single transaction input.  Use this to inject a signature
// produced by an out-of-band signer — a hardware wallet, PSBT flow, or
// a TSS committee — that the wallet cannot sign locally.
//
// sigDER is the DER-encoded signature (without the trailing sighash
// byte); this function appends hashType.  pubKey is the public key
// that produced the signature; for TSS this is the aggregated group
// pubkey.  The function validates that pubKey matches the address
// encoded in prev.PkScript before applying the signature.
//
// For P2PKH inputs, the result is a SignatureScript of the form
//
//	<sigDER||hashType> <pubKeyCompressed>
//
// For P2WPKH inputs, the result is a two-element witness stack
//
//	[ sigDER||hashType , pubKeyCompressed ]
//
// Other script classes are rejected.  P2TR inputs require schnorr
// signatures — use TransactionApplySchnorr.  P2SH-P2WPKH and P2WSH
// are not yet supported.
//
// This function does not verify the signature cryptographically.
// It parses sigDER as DER (catching gross encoding errors) and
// cross-checks pubKey against the address, but never confirms that
// sigDER actually validates over the transaction's sighash.
//
// SECURITY: callers accepting signatures from an untrusted source
// (an unauthenticated RPC, a network path the attacker might
// intercept, a TSS coordinator the wallet cannot authenticate)
// MUST call VerifyECDSA with the correct sighash before calling
// this function.  A malformed signature injected here produces a
// transaction that fails script verification — the network
// rejects it, so no funds are at risk, but downstream components
// that trust a nil return from Apply as "transaction is valid"
// would be misled.  Verification is not done here because the
// sighash depends on the full PrevOuts map which Apply does not
// receive; the caller already has it.
func TransactionApplyECDSA(params *chaincfg.Params, tx *wire.MsgTx, idx int, prev *wire.TxOut, pubKey *btcec.PublicKey, sigDER []byte, hashType txscript.SigHashType) error {
	if tx == nil || prev == nil || pubKey == nil {
		return fmt.Errorf("nil argument")
	}
	if idx < 0 || idx >= len(tx.TxIn) {
		return fmt.Errorf("input index %d out of range (tx has %d inputs)",
			idx, len(tx.TxIn))
	}
	if len(sigDER) == 0 {
		return fmt.Errorf("empty signature")
	}
	if len(sigDER) > maxECDSASigDERLen {
		return fmt.Errorf("signature exceeds max DER length: got %d, max %d",
			len(sigDER), maxECDSASigDERLen)
	}
	if err := validateSigHashType(hashType); err != nil {
		return err
	}

	// Sanity check: ensure sigDER is parseable DER.  This catches
	// gross encoding errors early; full cryptographic verification
	// is a caller choice via VerifyECDSA.
	if _, err := ecdsa.ParseDERSignature(sigDER); err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	pubCompressed := pubKey.SerializeCompressed()

	// Attach sighash byte for script-engine consumption.
	sigWithHash := append([]byte{}, sigDER...)
	sigWithHash = append(sigWithHash, byte(hashType))

	class := txscript.GetScriptClass(prev.PkScript)
	switch class {
	case txscript.PubKeyHashTy:
		return applyECDSAP2PKH(params, tx, idx, prev, sigWithHash, pubCompressed)
	case txscript.WitnessV0PubKeyHashTy:
		return applyECDSAP2WPKH(params, tx, idx, prev, sigWithHash, pubCompressed)
	default:
		return fmt.Errorf("unsupported script class for ECDSA: %v", class)
	}
}

// applyECDSAP2PKH writes a P2PKH SignatureScript of the form
// <sigWithHash> <pubCompressed> and clears any witness.  Cross-checks
// pubCompressed against the address encoded in prev.PkScript.
func applyECDSAP2PKH(params *chaincfg.Params, tx *wire.MsgTx, idx int, prev *wire.TxOut, sigWithHash, pubCompressed []byte) error {
	if err := pubKeyMatchesAddress(params, prev.PkScript, pubCompressed, false); err != nil {
		return fmt.Errorf("p2pkh: %w", err)
	}
	script, err := txscript.NewScriptBuilder().
		AddData(sigWithHash).
		AddData(pubCompressed).
		Script()
	if err != nil {
		return fmt.Errorf("build sigScript: %w", err)
	}
	tx.TxIn[idx].SignatureScript = script
	tx.TxIn[idx].Witness = nil
	return nil
}

// applyECDSAP2WPKH writes a P2WPKH two-element witness stack
// [sigWithHash, pubCompressed] and clears any SignatureScript.
// Cross-checks pubCompressed against the address encoded in
// prev.PkScript.
func applyECDSAP2WPKH(params *chaincfg.Params, tx *wire.MsgTx, idx int, prev *wire.TxOut, sigWithHash, pubCompressed []byte) error {
	if err := pubKeyMatchesAddress(params, prev.PkScript, pubCompressed, true); err != nil {
		return fmt.Errorf("p2wpkh: %w", err)
	}
	tx.TxIn[idx].Witness = wire.TxWitness{sigWithHash, pubCompressed}
	tx.TxIn[idx].SignatureScript = nil
	return nil
}

// pubKeyMatchesAddress verifies that pubCompressed derives to the
// address embedded in pkScript.  For P2PKH and P2WPKH the derived
// pubkey hash (HASH160) must equal the 20-byte hash in the script;
// both forms share the same derivation so one helper covers both.
// segwit selects whether the comparison uses a P2WPKH or P2PKH
// derivation (they match structurally but differ in script wrapping,
// and we use ExtractPkScriptAddrs so params-dependent HRP matches).
func pubKeyMatchesAddress(params *chaincfg.Params, pkScript, pubCompressed []byte, segwit bool) error {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, params)
	if err != nil {
		return fmt.Errorf("extract address: %w", err)
	}
	if len(addrs) != 1 {
		return fmt.Errorf("pkScript extracted %d addresses, expected 1", len(addrs))
	}

	pkHash := btcutil.Hash160(pubCompressed)
	var want btcutil.Address
	if segwit {
		want, err = btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	} else {
		want, err = btcutil.NewAddressPubKeyHash(pkHash, params)
	}
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}

	if addrs[0].EncodeAddress() != want.EncodeAddress() {
		return fmt.Errorf("public key does not match address")
	}
	return nil
}

// validateSigHashType verifies hashType is one of the standard
// Bitcoin sighash values and fits in a single byte.  Silent
// narrowing of txscript.SigHashType (uint32) to byte would convert
// an attacker-controlled 0xFFFF_FF01 to 0x01 (SigHashAll) and embed
// the wrong sighash semantics in the witness.  Reject anything
// unrecognised rather than trusting the low byte.
func validateSigHashType(hashType txscript.SigHashType) error {
	switch hashType {
	case txscript.SigHashDefault,
		txscript.SigHashAll,
		txscript.SigHashNone,
		txscript.SigHashSingle,
		txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
		txscript.SigHashSingle | txscript.SigHashAnyOneCanPay:
		return nil
	}
	return fmt.Errorf("invalid sighash type %#x", uint32(hashType))
}
