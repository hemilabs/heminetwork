// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// TransactionApplySchnorr applies an externally-computed schnorr
// signature to a P2TR key-path input.  Use this to inject a signature
// produced by a schnorr threshold signature scheme (MuSig2, FROST, or
// a schnorr-TSS coordinator) that the wallet cannot sign locally.
//
// params select the network HRP used when rendering addresses for
// the pkScript cross-check.  sig64 is the 64-byte schnorr signature
// per BIP-340.  pubKey is the internal key that produced the
// signature before the taproot tweak; the function computes the
// tweaked output key via ComputeTaprootKeyNoScript and cross-checks
// it against the taproot address decoded from prev.PkScript.
//
// For SigHashDefault (the common case), the witness stack is
//
//	[ sig64 ]
//
// For any other sighash type, the single sighash byte is appended per
// BIP-341.
//
// Only BIP-86 key-path spends are supported through this entry point.
// Script-path spends require additional data (the committed leaf
// script and a control block) and must be assembled by the caller.
//
// This function does not verify the signature cryptographically.
// It enforces BIP-340 structural parsing via schnorr.ParseSignature
// and cross-checks the BIP-86-tweaked pubKey against the address
// but never confirms that sig64 actually validates over the
// transaction's BIP-341 sighash.
//
// SECURITY: callers accepting signatures from an untrusted source
// (an unauthenticated RPC, a network path the attacker might
// intercept, a schnorr-TSS coordinator the wallet cannot
// authenticate) MUST call VerifySchnorr with the correct sighash
// before calling this function.  A malformed signature injected
// here produces a transaction that fails script verification —
// the network rejects it, so no funds are at risk, but downstream
// components that trust a nil return from Apply as "transaction
// is valid" would be misled.
func TransactionApplySchnorr(params *chaincfg.Params, tx *wire.MsgTx, idx int, prev *wire.TxOut, pubKey *btcec.PublicKey, sig64 []byte, hashType txscript.SigHashType) error {
	if tx == nil || prev == nil || pubKey == nil {
		return fmt.Errorf("nil argument")
	}
	if idx < 0 || idx >= len(tx.TxIn) {
		return fmt.Errorf("input index %d out of range (tx has %d inputs)",
			idx, len(tx.TxIn))
	}
	if len(sig64) != 64 {
		return fmt.Errorf("schnorr signature must be 64 bytes, got %d",
			len(sig64))
	}
	if err := validateSigHashType(hashType); err != nil {
		return err
	}

	// Parse to enforce BIP-340 encoding: upper bit of R.x and a few
	// other canonicity rules.  ParseSignature catches encodings that
	// would be rejected by the script engine.
	if _, err := schnorr.ParseSignature(sig64); err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	class := txscript.GetScriptClass(prev.PkScript)
	if class != txscript.WitnessV1TaprootTy {
		return fmt.Errorf("unsupported script class for schnorr: %v", class)
	}

	if err := pubKeyMatchesTaprootAddress(params, prev.PkScript, pubKey); err != nil {
		return fmt.Errorf("p2tr: %w", err)
	}

	witness := sig64
	if hashType != txscript.SigHashDefault {
		witness = append(append([]byte{}, sig64...), byte(hashType))
	}
	tx.TxIn[idx].Witness = wire.TxWitness{witness}
	tx.TxIn[idx].SignatureScript = nil
	return nil
}

// pubKeyMatchesTaprootAddress verifies that applying the BIP-86
// taproot tweak to pubKey produces the same address encoded in
// pkScript.  Using ExtractPkScriptAddrs plus NewAddressTaproot with
// the tweaked x-only key gives two btcutil.Address values with
// params-matched HRPs; equality of their encoded forms proves the
// pkScript commits to this internal key under a nil script root.
func pubKeyMatchesTaprootAddress(params *chaincfg.Params, pkScript []byte, pubKey *btcec.PublicKey) error {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, params)
	if err != nil {
		return fmt.Errorf("extract address: %w", err)
	}
	if len(addrs) != 1 {
		return fmt.Errorf("pkScript extracted %d addresses, expected 1", len(addrs))
	}
	tweaked := txscript.ComputeTaprootKeyNoScript(pubKey)
	want, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tweaked), params)
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}
	if addrs[0].EncodeAddress() != want.EncodeAddress() {
		return fmt.Errorf("public key does not match address")
	}
	return nil
}
