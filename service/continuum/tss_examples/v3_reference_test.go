// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build tssexamples

// Package tss_examples contains reference implementations for the
// tss-lib v3 pure round function API.
//
// The v3 API replaces the v2 channel-based NewLocalParty / Start() /
// outCh / endCh pattern with explicit round functions: each round
// takes state + inbound messages and returns outbound messages.
// The caller owns the event loop.
//
// For the old v2 channel-based reference, see
// testdata/v2_channel_reference/.
package tss_examples

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v3/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v3/tss"
)

// TestV3KeygenAndSign demonstrates the v3 round function API for
// ECDSA distributed key generation followed by threshold signing.
//
// This is a 3-party, 2-of-3 threshold scheme.  All parties
// participate in keygen and signing.
func TestV3KeygenAndSign(t *testing.T) {
	const n = 3
	const threshold = 1 // t+1 = 2 signers needed
	ctx := context.Background()

	// ---------------------------------------------------------------
	// Step 1: Generate Paillier pre-parameters for each party.
	// In production these are generated once and stored.
	// ---------------------------------------------------------------
	preParams := make([]keygen.LocalPreParams, n)
	for i := 0; i < n; i++ {
		pp, err := keygen.GeneratePreParams(5 * time.Minute)
		if err != nil {
			t.Fatalf("GeneratePreParams[%d]: %v", i, err)
		}
		preParams[i] = *pp
	}

	// ---------------------------------------------------------------
	// Step 2: Create sorted party IDs and peer context.
	// ---------------------------------------------------------------
	pIDs := tss.GenerateTestPartyIDs(n)
	peerCtx := tss.NewPeerContext(pIDs)

	// ---------------------------------------------------------------
	// Step 3: Keygen Round 1 — each party produces a commitment.
	// ---------------------------------------------------------------
	kgStates := make([]*keygen.KeygenState, n)
	kgR1 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), peerCtx, pIDs[i], n, threshold)
		st, out, err := keygen.Round1(ctx, params, preParams[i])
		if err != nil {
			t.Fatalf("keygen.Round1[%d]: %v", i, err)
		}
		kgStates[i] = st
		kgR1[i] = out.Messages[0]

		// Round 1 exposes the VSS polynomial for SNARK witness
		// extraction.  Not used here but available via out.Poly.
		if out.Poly == nil {
			t.Fatal("Round1 should return Poly")
		}
	}

	// ---------------------------------------------------------------
	// Step 4: Keygen Round 2 — VSS shares + decommitments.
	// Produces both P2P and broadcast messages.
	// ---------------------------------------------------------------
	kgR2P2P := make([][]*tss.Message, n) // [receiver][sender]
	kgR2Bcast := make([]*tss.Message, n) // [sender]
	for i := 0; i < n; i++ {
		kgR2P2P[i] = make([]*tss.Message, n)
	}
	for i := 0; i < n; i++ {
		out, err := keygen.Round2(ctx, kgStates[i], kgR1)
		if err != nil {
			t.Fatalf("keygen.Round2[%d]: %v", i, err)
		}
		for _, msg := range out.Messages {
			pm := msg
			if pm.To == nil {
				kgR2Bcast[i] = pm
			} else {
				for _, to := range pm.To {
					kgR2P2P[to.Index][i] = pm
				}
			}
		}
		// Self-messages stored internally; export for the matrix.
		kgR2P2P[i][i] = kgStates[i].ExportR2P2PSelf()
		if kgR2Bcast[i] == nil {
			kgR2Bcast[i] = kgStates[i].ExportR2BcastSelf()
		}
	}

	// ---------------------------------------------------------------
	// Step 5: Keygen Round 3 — Feldman VSS verification.
	// ---------------------------------------------------------------
	kgR3 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := keygen.Round3(ctx, kgStates[i], kgR2P2P[i], kgR2Bcast)
		if err != nil {
			t.Fatalf("keygen.Round3[%d]: %v", i, err)
		}
		kgR3[i] = out.Messages[0]
	}

	// ---------------------------------------------------------------
	// Step 6: Keygen Round 4 — Paillier proof verification + save.
	// ---------------------------------------------------------------
	saves := make([]keygen.LocalPartySaveData, n)
	for i := 0; i < n; i++ {
		out, err := keygen.Round4(ctx, kgStates[i], kgR3)
		if err != nil {
			t.Fatalf("keygen.Round4[%d]: %v", i, err)
		}
		saves[i] = *out.Save
	}
	t.Logf("keygen complete: ECDSAPub = (%x, %x)",
		saves[0].ECDSAPub.X(), saves[0].ECDSAPub.Y())

	// ---------------------------------------------------------------
	// Step 7: Sign Round 1 — commitment to gamma, w, k shares.
	// ---------------------------------------------------------------
	msgHash := sha256.Sum256([]byte("hello v3 round functions"))
	m := new(big.Int).SetBytes(msgHash[:])

	sigStates := make([]*signing.SigningState, n)
	sigR1P2P := make([][]*tss.Message, n)
	sigR1Bcast := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		sigR1P2P[i] = make([]*tss.Message, n)
	}
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), peerCtx, pIDs[i], n, threshold)
		st, out, err := signing.SignRound1(params, saves[i], m, nil, 0)
		if err != nil {
			t.Fatalf("SignRound1[%d]: %v", i, err)
		}
		sigStates[i] = st
		for _, msg := range out.Messages {
			pm := msg
			if pm.To == nil {
				sigR1Bcast[i] = pm
			} else {
				for _, to := range pm.To {
					sigR1P2P[to.Index][i] = pm
				}
			}
		}
	}

	// ---------------------------------------------------------------
	// Step 8: Sign Round 2 — MtA (multiplicative-to-additive).
	// ---------------------------------------------------------------
	sigR2P2P := make([][]*tss.Message, n)
	for i := 0; i < n; i++ {
		sigR2P2P[i] = make([]*tss.Message, n)
	}
	for i := 0; i < n; i++ {
		out, err := signing.SignRound2(ctx, sigStates[i], sigR1P2P[i], sigR1Bcast)
		if err != nil {
			t.Fatalf("SignRound2[%d]: %v", i, err)
		}
		for _, msg := range out.Messages {
			pm := msg
			for _, to := range pm.To {
				sigR2P2P[to.Index][i] = pm
			}
		}
	}

	// ---------------------------------------------------------------
	// Step 9: Sign Round 3 — compute theta, sigma.
	// ---------------------------------------------------------------
	sigR3 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := signing.SignRound3(ctx, sigStates[i], sigR2P2P[i])
		if err != nil {
			t.Fatalf("SignRound3[%d]: %v", i, err)
		}
		sigR3[i] = out.Messages[0]
	}

	// ---------------------------------------------------------------
	// Step 10: Sign Round 4 — Schnorr proof for gamma.
	// ---------------------------------------------------------------
	sigR4 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := signing.SignRound4(sigStates[i], sigR3)
		if err != nil {
			t.Fatalf("SignRound4[%d]: %v", i, err)
		}
		sigR4[i] = out.Messages[0]
	}

	// ---------------------------------------------------------------
	// Step 11: Sign Round 5 — verify commitments, compute R.
	// ---------------------------------------------------------------
	sigR5 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := signing.SignRound5(sigStates[i], sigR4)
		if err != nil {
			t.Fatalf("SignRound5[%d]: %v", i, err)
		}
		sigR5[i] = out.Messages[0]
	}

	// ---------------------------------------------------------------
	// Step 12: Sign Round 6 — Schnorr proof for blinding.
	// ---------------------------------------------------------------
	sigR6 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := signing.SignRound6(sigStates[i])
		if err != nil {
			t.Fatalf("SignRound6[%d]: %v", i, err)
		}
		sigR6[i] = out.Messages[0]
	}

	// ---------------------------------------------------------------
	// Step 13: Sign Round 7 — verify blinding, commit Ui/Ti.
	// ---------------------------------------------------------------
	sigR7 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := signing.SignRound7(sigStates[i], sigR5, sigR6)
		if err != nil {
			t.Fatalf("SignRound7[%d]: %v", i, err)
		}
		sigR7[i] = out.Messages[0]
	}

	// ---------------------------------------------------------------
	// Step 14: Sign Round 8 — decommit Ui/Ti.
	// ---------------------------------------------------------------
	sigR8 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := signing.SignRound8(sigStates[i])
		if err != nil {
			t.Fatalf("SignRound8[%d]: %v", i, err)
		}
		sigR8[i] = out.Messages[0]
	}

	// ---------------------------------------------------------------
	// Step 15: Sign Round 9 — verify Ui==Ti, reveal si.
	// ---------------------------------------------------------------
	sigR9 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := signing.SignRound9(sigStates[i], sigR7, sigR8)
		if err != nil {
			t.Fatalf("SignRound9[%d]: %v", i, err)
		}
		sigR9[i] = out.Messages[0]
	}

	// ---------------------------------------------------------------
	// Step 16: Finalize — sum partial sigs, verify ECDSA signature.
	// ---------------------------------------------------------------
	for i := 0; i < n; i++ {
		out, err := signing.SignFinalize(sigStates[i], sigR9)
		if err != nil {
			t.Fatalf("SignFinalize[%d]: %v", i, err)
		}

		pk := ecdsa.PublicKey{
			Curve: tss.S256(),
			X:     saves[0].ECDSAPub.X(),
			Y:     saves[0].ECDSAPub.Y(),
		}
		r := new(big.Int).SetBytes(out.Signature.R)
		s := new(big.Int).SetBytes(out.Signature.S)
		if !ecdsa.Verify(&pk, msgHash[:], r, s) {
			t.Fatalf("party %d: ECDSA signature verification failed", i)
		}
		t.Logf("party %d: signature verified (r=%x, s=%x)", i,
			out.Signature.R, out.Signature.S)
	}
}
