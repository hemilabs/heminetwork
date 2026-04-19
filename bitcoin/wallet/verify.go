// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// VerifyECDSA checks that sigDER is a valid ECDSA signature over
// sigHash under pubKey.  This is a pre-broadcast sanity check for
// externally-computed signatures (hardware wallets, PSBT flows, TSS
// committees) before handing them to TransactionApplyECDSA.
//
// sigDER is DER-encoded without any trailing sighash byte.  sigHash
// is the 32-byte hash the signer produced the signature over; the
// caller is responsible for computing it with the correct sighash
// algorithm (legacy for P2PKH, BIP-143 for P2WPKH).
//
// Returns nil on success.  On failure the error distinguishes
// between parse errors and verification mismatches.
func VerifyECDSA(sigHash, sigDER []byte, pubKey *btcec.PublicKey) error {
	if pubKey == nil {
		return fmt.Errorf("nil pubkey")
	}
	if len(sigHash) != 32 {
		return fmt.Errorf("sighash must be 32 bytes, got %d", len(sigHash))
	}
	if len(sigDER) == 0 {
		return fmt.Errorf("empty signature")
	}
	sig, err := ecdsa.ParseDERSignature(sigDER)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	if !sig.Verify(sigHash, pubKey) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

// VerifySchnorr checks that sig64 is a valid BIP-340 schnorr
// signature over sigHash under xOnlyPubKey.  Use this to sanity-check
// an externally-computed schnorr signature (schnorr-TSS, MuSig2,
// FROST) before handing it to TransactionApplySchnorr.
//
// xOnlyPubKey is the 32-byte x-only public key — typically the
// tweaked taproot output key, not the untweaked internal key.  The
// caller is responsible for applying the BIP-341 tweak before
// verification; for BIP-86 key-path that is
// schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(internal)).
//
// sigHash is the 32-byte BIP-341 taproot sighash the signer produced
// the signature over.
func VerifySchnorr(sigHash, sig64, xOnlyPubKey []byte) error {
	if len(xOnlyPubKey) != 32 {
		return fmt.Errorf("x-only pubkey must be 32 bytes, got %d",
			len(xOnlyPubKey))
	}
	if len(sigHash) != 32 {
		return fmt.Errorf("sighash must be 32 bytes, got %d", len(sigHash))
	}
	if len(sig64) != 64 {
		return fmt.Errorf("schnorr signature must be 64 bytes, got %d",
			len(sig64))
	}
	sig, err := schnorr.ParseSignature(sig64)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	pub, err := schnorr.ParsePubKey(xOnlyPubKey)
	if err != nil {
		return fmt.Errorf("parse x-only pubkey: %w", err)
	}
	if !sig.Verify(sigHash, pub) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}
