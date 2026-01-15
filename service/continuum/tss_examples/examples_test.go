// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package tss_examples contains illustrative tests demonstrating the use of
// tss-lib for distributed key generation, signing, and resharing.
//
// These tests serve as reference implementations showing:
// - Basic keygen and signing workflows
// - Threshold signing with subsets
// - Resharing with disjoint committees
// - Resharing with overlapping committees (using key rotation)
// - Growing/shrinking committees with threshold changes
// - Dead party recovery
//
// The tests use raw tss-lib APIs without additional abstraction layers.
package tss_examples

import (
	"os"
	"testing"

	"github.com/hemilabs/x/tss-lib/v2/tss"
)

// TestKeygen demonstrates basic distributed key generation.
// Creates a 3-of-3 threshold key and verifies all parties have matching public keys.
// Then signs a message and verifies each signature.
func TestKeygen(t *testing.T) {
	curve := curveParams()

	alice := NewPartyIdentity("02alice_pubkey", "Alice")
	bob := NewPartyIdentity("02bob_pubkey", "Bob")
	charlie := NewPartyIdentity("02charlie_pubkey", "Charlie")

	pids := partiesToPids([]*PartyIdentity{alice, bob, charlie})
	threshold := len(pids) - 1 // 3-of-3

	t.Log("=== Keygen: 3-of-3 ===")
	keys, err := doKeygen(t, curve, threshold, pids, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify all keys match
	verifyAllKeysMatch(t, keys)

	// Sign and verify
	t.Log("=== Sign with all parties ===")
	if err := doSignAndVerify(t, curve, threshold, pids, keys, []byte("test message")); err != nil {
		t.Fatal(err)
	}
}

// TestSignSubset demonstrates threshold signing with fewer than all parties.
// Creates a 2-of-3 key and signs with only 2 parties.
func TestSignSubset(t *testing.T) {
	curve := curveParams()

	alice := NewPartyIdentity("02alice_pubkey", "Alice")
	bob := NewPartyIdentity("02bob_pubkey", "Bob")
	charlie := NewPartyIdentity("02charlie_pubkey", "Charlie")

	pids := partiesToPids([]*PartyIdentity{alice, bob, charlie})
	threshold := 1 // 2-of-3

	t.Log("=== Keygen: 2-of-3 ===")
	keys, err := doKeygen(t, curve, threshold, pids, nil)
	if err != nil {
		t.Fatal(err)
	}

	verifyAllKeysMatch(t, keys)
	keyLookup := buildKeyLookup(pids, keys)

	// Sign with full committee
	t.Log("=== Sign with all 3 parties ===")
	if err := doSignAndVerify(t, curve, threshold, pids, keys, []byte("full committee")); err != nil {
		t.Fatal(err)
	}

	// Sign with Alice + Bob only
	t.Log("=== Sign with Alice + Bob only (2-of-3) ===")
	subset1 := partiesToPids([]*PartyIdentity{alice, bob})
	subset1Keys := selectKeys(subset1, keyLookup)
	if err := doSignAndVerify(t, curve, threshold, subset1, subset1Keys, []byte("alice and bob")); err != nil {
		t.Fatal(err)
	}

	// Sign with Bob + Charlie only
	t.Log("=== Sign with Bob + Charlie only (2-of-3) ===")
	subset2 := partiesToPids([]*PartyIdentity{bob, charlie})
	subset2Keys := selectKeys(subset2, keyLookup)
	if err := doSignAndVerify(t, curve, threshold, subset2, subset2Keys, []byte("bob and charlie")); err != nil {
		t.Fatal(err)
	}
}

// TestReshareDisjoint demonstrates resharing to a completely new committee.
// Old and new committees have no common members.
func TestReshareDisjoint(t *testing.T) {
	curve := curveParams()

	// Old committee
	alice := NewPartyIdentity("02alice_pubkey", "Alice")
	bob := NewPartyIdentity("02bob_pubkey", "Bob")
	charlie := NewPartyIdentity("02charlie_pubkey", "Charlie")

	// New committee (completely different)
	dan := NewPartyIdentity("02dan_pubkey", "Dan")
	erin := NewPartyIdentity("02erin_pubkey", "Erin")
	frank := NewPartyIdentity("02frank_pubkey", "Frank")

	oldPids := partiesToPids([]*PartyIdentity{alice, bob, charlie})
	oldThreshold := len(oldPids) - 1 // 3-of-3

	t.Log("=== Keygen: {Alice, Bob, Charlie} 3-of-3 ===")
	oldKeys, err := doKeygen(t, curve, oldThreshold, oldPids, nil)
	if err != nil {
		t.Fatal(err)
	}

	origPubX := verifyAllKeysMatch(t, oldKeys)

	// Sign with old committee
	t.Log("=== Sign with old committee ===")
	if err := doSignAndVerify(t, curve, oldThreshold, oldPids, oldKeys, []byte("old committee")); err != nil {
		t.Fatal(err)
	}

	// Reshare to new committee
	t.Log("=== Reshare: {Alice, Bob, Charlie} -> {Dan, Erin, Frank} ===")
	newPids := partiesToPids([]*PartyIdentity{dan, erin, frank})
	newThreshold := len(newPids) - 1 // 3-of-3

	newKeys, err := doReshare(t, curve, oldThreshold, newThreshold, oldPids, newPids, oldKeys)
	if err != nil {
		t.Fatal(err)
	}

	// Verify public key preserved
	verifyPublicKeyPreserved(t, newKeys, origPubX)
	t.Log("Public key preserved ✓")

	// Sign with new committee
	t.Log("=== Sign with new committee ===")
	if err := doSignAndVerify(t, curve, newThreshold, newPids, newKeys, []byte("new committee")); err != nil {
		t.Fatal(err)
	}
}

// TestReshareWithOverlap demonstrates resharing when some parties remain.
// Uses key rotation to make tss-lib see disjoint committees.
func TestReshareWithOverlap(t *testing.T) {
	curve := curveParams()

	alice := NewPartyIdentity("02alice_pubkey", "Alice")
	bob := NewPartyIdentity("02bob_pubkey", "Bob")
	charlie := NewPartyIdentity("02charlie_pubkey", "Charlie")
	dan := NewPartyIdentity("02dan_pubkey", "Dan")

	oldPids := partiesToPids([]*PartyIdentity{alice, bob, charlie})
	oldThreshold := len(oldPids) - 1 // 3-of-3

	t.Log("=== Keygen: {Alice, Bob, Charlie} 3-of-3 ===")
	oldKeys, err := doKeygen(t, curve, oldThreshold, oldPids, nil)
	if err != nil {
		t.Fatal(err)
	}

	origPubX := verifyAllKeysMatch(t, oldKeys)

	// Sign with old committee
	t.Log("=== Sign with old committee ===")
	if err := doSignAndVerify(t, curve, oldThreshold, oldPids, oldKeys, []byte("old committee")); err != nil {
		t.Fatal(err)
	}

	// Reshare: Alice leaves, Dan joins, Bob & Charlie stay
	t.Log("=== Reshare: {Alice, Bob, Charlie} -> {Bob, Charlie, Dan} ===")
	t.Log("Bob and Charlie rotate their TSSKeys to appear as 'new' parties to tss-lib")

	// CRITICAL: Rotate keys for parties that appear in both committees
	bob.RotateKey()
	charlie.RotateKey()

	newPids := partiesToPids([]*PartyIdentity{bob, charlie, dan})
	newThreshold := len(newPids) - 1 // 3-of-3

	newKeys, err := doReshare(t, curve, oldThreshold, newThreshold, oldPids, newPids, oldKeys)
	if err != nil {
		t.Fatal(err)
	}

	// Verify public key preserved
	verifyPublicKeyPreserved(t, newKeys, origPubX)
	t.Log("Public key preserved ✓")

	// Sign with new committee
	t.Log("=== Sign with new committee ===")
	if err := doSignAndVerify(t, curve, newThreshold, newPids, newKeys, []byte("new committee with overlap")); err != nil {
		t.Fatal(err)
	}
}

// TestReshareGrowCommittee demonstrates growing the committee and changing threshold.
// Goes from 2-of-3 to 3-of-4.
func TestReshareGrowCommittee(t *testing.T) {
	curve := curveParams()

	alice := NewPartyIdentity("02alice_pubkey", "Alice")
	bob := NewPartyIdentity("02bob_pubkey", "Bob")
	charlie := NewPartyIdentity("02charlie_pubkey", "Charlie")
	dan := NewPartyIdentity("02dan_pubkey", "Dan")
	erin := NewPartyIdentity("02erin_pubkey", "Erin")

	// Start with 2-of-3
	oldPids := partiesToPids([]*PartyIdentity{alice, bob, charlie})
	oldThreshold := 1 // 2-of-3

	t.Log("=== Keygen: {Alice, Bob, Charlie} 2-of-3 ===")
	oldKeys, err := doKeygen(t, curve, oldThreshold, oldPids, nil)
	if err != nil {
		t.Fatal(err)
	}

	origPubX := verifyAllKeysMatch(t, oldKeys)

	// Sign with old committee
	t.Log("=== Sign with old committee ===")
	if err := doSignAndVerify(t, curve, oldThreshold, oldPids, oldKeys, []byte("2-of-3 committee")); err != nil {
		t.Fatal(err)
	}

	// Reshare: Grow to 4 parties, change threshold to 3-of-4
	// Alice leaves, Bob & Charlie stay, Dan & Erin join
	t.Log("=== Reshare: {Alice, Bob, Charlie} 2-of-3 -> {Bob, Charlie, Dan, Erin} 3-of-4 ===")

	// Rotate keys for continuing parties
	bob.RotateKey()
	charlie.RotateKey()

	newPids := partiesToPids([]*PartyIdentity{bob, charlie, dan, erin})
	newThreshold := 2 // 3-of-4

	newKeys, err := doReshare(t, curve, oldThreshold, newThreshold, oldPids, newPids, oldKeys)
	if err != nil {
		t.Fatal(err)
	}

	// Verify public key preserved
	verifyPublicKeyPreserved(t, newKeys, origPubX)
	t.Log("Public key preserved ✓")

	// Sign with new committee (need 3 of 4)
	t.Log("=== Sign with new committee (all 4) ===")
	if err := doSignAndVerify(t, curve, newThreshold, newPids, newKeys, []byte("3-of-4 full")); err != nil {
		t.Fatal(err)
	}

	// Sign with subset (3 of 4)
	t.Log("=== Sign with subset (Bob, Charlie, Dan) ===")
	keyLookup := buildKeyLookup(newPids, newKeys)

	// Need to use the rotated keys
	subset := partiesToPids([]*PartyIdentity{bob, charlie, dan})
	subsetKeys := selectKeys(subset, keyLookup)
	if err := doSignAndVerify(t, curve, newThreshold, subset, subsetKeys, []byte("3-of-4 subset")); err != nil {
		t.Fatal(err)
	}
}

// TestDeadPartyRecovery demonstrates recovering when a party goes offline.
// With 2-of-3 threshold, if one party dies, the remaining 2 can still sign
// and reshare to a new committee without the dead party.
func TestDeadPartyRecovery(t *testing.T) {
	curve := curveParams()

	alice := NewPartyIdentity("02alice_pubkey", "Alice")
	bob := NewPartyIdentity("02bob_pubkey", "Bob")
	charlie := NewPartyIdentity("02charlie_pubkey", "Charlie")
	dan := NewPartyIdentity("02dan_pubkey", "Dan")

	// 2-of-3 keygen
	oldPids := partiesToPids([]*PartyIdentity{alice, bob, charlie})
	oldThreshold := 1 // 2-of-3

	t.Log("=== Keygen: {Alice, Bob, Charlie} 2-of-3 ===")
	oldKeys, err := doKeygen(t, curve, oldThreshold, oldPids, nil)
	if err != nil {
		t.Fatal(err)
	}

	origPubX := verifyAllKeysMatch(t, oldKeys)
	keyLookup := buildKeyLookup(oldPids, oldKeys)

	// Sign with all 3
	t.Log("=== Sign with all parties ===")
	if err := doSignAndVerify(t, curve, oldThreshold, oldPids, oldKeys, []byte("all alive")); err != nil {
		t.Fatal(err)
	}

	// Alice dies!
	t.Log("")
	t.Log("=== Alice goes OFFLINE ===")
	t.Log("We still have Bob and Charlie (2 parties).")
	t.Log("Threshold is 2-of-3, so we can still operate!")

	// Sign without Alice (Bob + Charlie)
	t.Log("=== Sign with Bob + Charlie only ===")
	livePids := partiesToPids([]*PartyIdentity{bob, charlie})
	liveKeys := selectKeys(livePids, keyLookup)
	if err := doSignAndVerify(t, curve, oldThreshold, livePids, liveKeys, []byte("alice is dead")); err != nil {
		t.Fatal(err)
	}
	t.Log("Signing without Alice: SUCCESS ✓")

	// Reshare to evict Alice, add Dan
	// Only Bob and Charlie participate from old committee
	t.Log("")
	t.Log("=== Reshare to evict Alice, add Dan ===")
	t.Log("Only Bob and Charlie from old committee participate")

	// Build old pids from LIVE parties only
	bobOld := tss.NewPartyID(bob.PubKey, bob.Name, bob.TSSKey)
	charlieOld := tss.NewPartyID(charlie.PubKey, charlie.Name, charlie.TSSKey)
	liveOldPids := tss.SortPartyIDs([]*tss.PartyID{bobOld, charlieOld})
	liveOldKeys := selectKeys(liveOldPids, keyLookup)

	// Rotate keys for new committee
	bob.RotateKey()
	charlie.RotateKey()

	newPids := partiesToPids([]*PartyIdentity{bob, charlie, dan})
	newThreshold := 1 // Still 2-of-3

	t.Logf("Live old parties: %d (Bob, Charlie)", len(liveOldPids))
	t.Logf("Old threshold: %d (need %d to reshare)", oldThreshold, oldThreshold+1)
	t.Logf("We have %d >= %d, so reshare is possible!", len(liveOldPids), oldThreshold+1)

	newKeys, err := doReshare(t, curve, oldThreshold, newThreshold, liveOldPids, newPids, liveOldKeys)
	if err != nil {
		t.Fatal(err)
	}

	// Verify public key preserved
	verifyPublicKeyPreserved(t, newKeys, origPubX)
	t.Log("Public key preserved ✓")

	// Sign with new committee
	t.Log("=== Sign with new committee {Bob, Charlie, Dan} ===")
	if err := doSignAndVerify(t, curve, newThreshold, newPids, newKeys, []byte("recovered from alice death")); err != nil {
		t.Fatal(err)
	}

	t.Log("")
	t.Log("Dead party recovery: SUCCESS ✓")
}

// TestFullLifecycle demonstrates a complete journey:
// keygen -> sign -> reshare (overlap) -> sign -> reshare (grow) -> sign
func TestFullLifecycle(t *testing.T) {
	curve := curveParams()

	alice := NewPartyIdentity("02alice_pubkey", "Alice")
	bob := NewPartyIdentity("02bob_pubkey", "Bob")
	charlie := NewPartyIdentity("02charlie_pubkey", "Charlie")
	dan := NewPartyIdentity("02dan_pubkey", "Dan")
	erin := NewPartyIdentity("02erin_pubkey", "Erin")

	// Phase 1: Initial keygen 2-of-3
	t.Log("=== Phase 1: Keygen {Alice, Bob, Charlie} 2-of-3 ===")
	pids1 := partiesToPids([]*PartyIdentity{alice, bob, charlie})
	threshold1 := 1 // 2-of-3

	keys1, err := doKeygen(t, curve, threshold1, pids1, nil)
	if err != nil {
		t.Fatal(err)
	}
	origPubX := verifyAllKeysMatch(t, keys1)

	t.Log("=== Phase 1: Sign ===")
	if err := doSignAndVerify(t, curve, threshold1, pids1, keys1, []byte("phase 1")); err != nil {
		t.Fatal(err)
	}

	// Phase 2: Reshare with overlap (Alice leaves, Dan joins)
	t.Log("")
	t.Log("=== Phase 2: Reshare {Alice, Bob, Charlie} -> {Bob, Charlie, Dan} ===")
	bob.RotateKey()
	charlie.RotateKey()

	pids2 := partiesToPids([]*PartyIdentity{bob, charlie, dan})
	threshold2 := 1 // Still 2-of-3

	keys2, err := doReshare(t, curve, threshold1, threshold2, pids1, pids2, keys1)
	if err != nil {
		t.Fatal(err)
	}
	verifyPublicKeyPreserved(t, keys2, origPubX)

	t.Log("=== Phase 2: Sign ===")
	if err := doSignAndVerify(t, curve, threshold2, pids2, keys2, []byte("phase 2")); err != nil {
		t.Fatal(err)
	}

	// Phase 3: Reshare to grow committee (add Erin, change threshold)
	t.Log("")
	t.Log("=== Phase 3: Reshare {Bob, Charlie, Dan} 2-of-3 -> {Bob, Charlie, Dan, Erin} 3-of-4 ===")
	bob.RotateKey()
	charlie.RotateKey()
	dan.RotateKey()

	pids3 := partiesToPids([]*PartyIdentity{bob, charlie, dan, erin})
	threshold3 := 2 // 3-of-4

	keys3, err := doReshare(t, curve, threshold2, threshold3, pids2, pids3, keys2)
	if err != nil {
		t.Fatal(err)
	}
	verifyPublicKeyPreserved(t, keys3, origPubX)

	t.Log("=== Phase 3: Sign ===")
	if err := doSignAndVerify(t, curve, threshold3, pids3, keys3, []byte("phase 3")); err != nil {
		t.Fatal(err)
	}

	t.Log("")
	t.Log("Full lifecycle: SUCCESS ✓")
}

// TestScaleToHundred demonstrates large-scale TSS with 100 participants.
// This test is slow and skipped by default. Run with TSS_SCALE=1.
func TestScaleToHundred(t *testing.T) {
	if os.Getenv("TSS_SCALE") == "" {
		t.Skip("Skipping scale test. Set TSS_SCALE=1 to run.")
	}

	curve := curveParams()

	const numParties = 100
	const threshold = 54 // 55-of-100

	// Load or generate preparams
	preParams := loadOrGeneratePreParams(t, numParties)

	// Create parties
	t.Logf("Creating %d parties...", numParties)
	parties := createParties(numParties)
	pids := partiesToPids(parties)

	// Keygen
	t.Logf("=== Keygen: %d-of-%d ===", threshold+1, numParties)
	keys, err := doKeygen(t, curve, threshold, pids, preParams)
	if err != nil {
		t.Fatal(err)
	}
	verifyAllKeysMatch(t, keys)

	// Sign with exactly threshold+1 parties (55)
	t.Log("=== Sign with 55 parties ===")
	signerParties := parties[:threshold+1]
	signerPids := partiesToPids(signerParties)
	keyLookup := buildKeyLookup(pids, keys)
	signerKeys := selectKeys(signerPids, keyLookup)

	if err := doSignAndVerify(t, curve, threshold, signerPids, signerKeys, []byte("scale test")); err != nil {
		t.Fatal(err)
	}

	t.Log("")
	t.Logf("Scale test (%d-of-%d): SUCCESS ✓", threshold+1, numParties)
}
