// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression suite for H-10: the envelope rate gate counted every envelope against
// ep.Sender before the envelope was authenticated. (A runnable PoC lives in the
// build-tagged h10_poc_demo_test.go.)
//
// Before this fix, decryptPayload did, in order:
//
//	key := ep.Sender.String()                      // attacker-chosen field
//	if count.Add(1) > envelopeRateLimit { drop }   // <-- counted here, before Verify
//	...
//	Verify(hash, ep.Sender, ep.Signature)          // <-- signature checked only after
//	OpenBox(ep, recipientPriv)                      // <-- recipient bound only here
//
// ep.Sender is attacker-chosen until Verify runs, and the signed hash does not cover
// the recipient, so two peers could censor a victim:
//
//   - forged sender: forge envelopes stamped ep.Sender=victim. Each fails Verify, but
//     counting it first exhausts the victim's bucket, so the victim's own traffic is
//     then dropped as "rate limited". Any peer that can reach the target works, since
//     envelopes relay multi-hop.
//   - cross-recipient replay: replay a real victim envelope that was addressed to
//     another node. It passes Verify everywhere but fails OpenBox here; counted before
//     OpenBox it still poisons the victim's bucket.
//
// The fix counts only after both Verify and OpenBox succeed, so only a genuine envelope
// from that sender, addressed to this node, is counted. Same-recipient replay (a
// victim's own envelope to this node, re-injected) still verifies and decrypts and so
// refreshes the bucket; closing that needs a (Sender, Nonce) registry ahead of the gate,
// left to M-10 and not covered here.
//
// Invariants:
//   1. a forged envelope allocates no rate state for the claimed sender [keystone]
//   2. a forged envelope is still rejected after the victim has used the gate
//      (no "seen this sender, skip Verify" shortcut)
//   3. forgeries attributed to a victim do not drop the victim's own traffic
//   4. the budget is per authenticated sender; one cannot exhaust another's
//   5. a genuine sender over the limit is still throttled (the gate is not defanged)
//   6. a validly-signed envelope addressed to another node touches no rate state here
//
// A correct fix touches envelopeRates only after both Verify and OpenBox; a token
// bucket keyed on ep.Sender in the same place is fine too. The gate is per-sender on
// purpose: ep.Sender is the signed originator identity, distinct from the transport peer
// that peerLimiter (in handle()) throttles, and because envelopes are relayed one
// transport peer carries many originators, so peerLimiter cannot throttle a single
// abusive originator on its own. That is what the isolation and still-throttles tests
// pin, so "just delete the gate" fails them. The gate does not bound Verify cost either,
// since an attacker rotates ep.Sender; that is peerLimiter's job, upstream.
//
// The tests are sequential: they tell correct fixes from wrong ones but do not test
// concurrency. A fix that counts before Verify and then undoes it (refund, delete, or a
// shadow map) can pass them yet still censor under concurrency, so that family is ruled
// out by the reasoning above and by review, not by a test. Drops are detected as "no
// payload produced" (got == nil), so any correct design passes regardless of mechanism.

import (
	"testing"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

func newEnvelopeGateServer(t *testing.T) (*Server, []byte) {
	t.Helper()
	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("server secret: %v", err)
	}
	envelopeRates, err := ttl.New(64, true)
	if err != nil {
		t.Fatalf("envelope ttl: %v", err)
	}
	naclPub, err := secret.NaClPublicKey()
	if err != nil {
		t.Fatalf("server nacl pub: %v", err)
	}
	return &Server{secret: secret, envelopeRates: envelopeRates}, naclPub
}

// genuineEnvelope is a real, correctly-signed envelope from `sender` sealed to the
// target's key.
func genuineEnvelope(t *testing.T, sender *Secret, targetPub []byte) *EncryptedPayload {
	t.Helper()
	ep, err := SealBox([]byte(`{"origin_timestamp":1}`), targetPub, sender, PPingRequest)
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	return ep
}

// forgedEnvelope is what an attacker injects: a fully well-formed envelope (real
// ephemeral key, random nonce, real ciphertext, valid 65-byte signature) that the
// attacker signed with its own key, then re-stamped with the victim's identity. Its
// only invalid property is that the signature recovers to the attacker rather than to
// the claimed ep.Sender -- so nothing short of an actual signature verification can
// distinguish it from a genuine envelope (a fix cannot cheaply pre-filter it away).
func forgedEnvelope(t *testing.T, attacker *Secret, targetPub []byte, victimID Identity) *EncryptedPayload {
	t.Helper()
	ep, err := SealBox([]byte(`{"origin_timestamp":1}`), targetPub, attacker, PPingRequest)
	if err != nil {
		t.Fatalf("seal forged envelope: %v", err)
	}
	ep.Sender = victimID // re-attribute to the victim; the attacker's signature stays.
	return ep
}

// TestEnvelopeGateForgedHelperIsWellFormed guards the forgedEnvelope helper that every
// forged-flood test relies on: the same bytes, attributed to their true signer (the
// attacker) instead of the victim, must verify and decode. This confirms the forgery's
// only defect is the sender swap, so no cheap structural check could reject it, and it
// catches a future edit that quietly stops producing a valid envelope (which would make
// the forged tests pass vacuously). Passes while buggy and under any correct fix.
func TestEnvelopeGateForgedHelperIsWellFormed(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}

	// Attribute the attacker's own envelope to the attacker (its true signer): an
	// unmodified, correctly-signed envelope. It must verify and decode.
	ep := forgedEnvelope(t, attacker, targetPub, attacker.Identity)
	got, err := target.decryptPayload(ep)
	if got == nil {
		t.Fatalf("a well-formed envelope attributed to its true signer was rejected (%v): "+
			"the forgery helper is not producing a valid envelope, which would silently "+
			"defang the forged-flood tests", err)
	}
	if _, ok := got.(*PingRequest); !ok {
		t.Fatalf("the attacker's own envelope decoded to %T, want *PingRequest", got)
	}
}

// TestEnvelopeGateForgedEnvelopesTouchNoRateState is the keystone (invariant 1): a flood
// of forged envelopes attributed to a victim must allocate no rate state at all -- no
// bucket for the victim and no recorded drops. This is the most fix-agnostic check: it
// fails while buggy and catches wrong fixes that a "victim still served" test would miss,
// such as one that counts before Verify and then refunds on failure (which leaves a
// bucket behind), or one that allocates a bucket before verifying.
func TestEnvelopeGateForgedEnvelopesTouchNoRateState(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	victim, err := NewSecret()
	if err != nil {
		t.Fatalf("victim secret: %v", err)
	}
	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}

	dropsBefore := target.envRateDrops.Load()
	for i := 0; i < envelopeRateLimit+50; i++ {
		if _, err := target.decryptPayload(forgedEnvelope(t, attacker, targetPub, victim.Identity)); err == nil {
			t.Fatalf("forged envelope %d was accepted: an envelope not signed by the "+
				"claimed sender must never verify", i+1)
		}
	}

	if n := target.envelopeRates.Len(); n != 0 {
		t.Fatalf("forged envelopes allocated %d rate-limit bucket(s): an unverified "+
			"envelope must not touch any sender's rate state. The gate keys on the "+
			"unverified ep.Sender and counts before Verify, so forgeries poison the "+
			"victim's bucket.", n)
	}
	if d := target.envRateDrops.Load() - dropsBefore; d != 0 {
		t.Fatalf("forged envelopes caused %d rate drop(s): unverified envelopes must "+
			"not be counted against any sender.", d)
	}
}

// TestEnvelopeGateForgedSenderCannotCensorVictim is the behavioral censorship
// invariant 3: after a forged flood attributed to the victim, the victim's own
// genuine envelope must still be accepted (not censored). Fails while buggy.
func TestEnvelopeGateForgedSenderCannotCensorVictim(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	victim, err := NewSecret()
	if err != nil {
		t.Fatalf("victim secret: %v", err)
	}
	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}

	// Forge well past the limit (margin avoids any off-by-one / TTL edge).
	for i := 0; i < envelopeRateLimit+50; i++ {
		_, _ = target.decryptPayload(forgedEnvelope(t, attacker, targetPub, victim.Identity))
	}

	got, err := target.decryptPayload(genuineEnvelope(t, victim, targetPub))
	if got == nil {
		t.Fatalf("victim's genuine envelope was dropped (%v) after an attacker forged "+
			"envelopes stamped with the victim's identity: the gate counts forgeries "+
			"against the victim before signature verification, censoring the victim.", err)
	}
	if _, ok := got.(*PingRequest); !ok {
		t.Fatalf("victim's genuine envelope decoded to %T, want *PingRequest", got)
	}
}

// TestEnvelopeGateForgedCannotCensorEstablishedVictim covers a case the cold-victim tests
// above cannot reach: they flood a victim that has never sent traffic, so there is no
// bucket to poison. A victim that has already sent one envelope has a live bucket, and a
// fix that verifies first only for new senders but keeps the pre-count for buckets it has
// already seen would pass every cold-victim test while still poisoning an active victim.
// Here the victim is primed first, then flooded with forgeries against its live bucket. A
// correct fix leaves that bucket untouched; the buggy gate drives it past the limit. Fails
// while buggy.
func TestEnvelopeGateForgedCannotCensorEstablishedVictim(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	victim, err := NewSecret()
	if err != nil {
		t.Fatalf("victim secret: %v", err)
	}
	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}

	// Prime: the victim sends one genuine envelope, establishing its live bucket.
	if got, err := target.decryptPayload(genuineEnvelope(t, victim, targetPub)); got == nil {
		t.Fatalf("victim's priming genuine envelope was rejected (%v)", err)
	}

	// The attacker floods forgeries at the now-established victim bucket. Each fails
	// Verify and must be rejected -- but under the buggy gate each first increments the
	// victim's live bucket toward the limit.
	dropsBefore := target.envRateDrops.Load()
	for i := 0; i < envelopeRateLimit+50; i++ {
		if _, err := target.decryptPayload(forgedEnvelope(t, attacker, targetPub, victim.Identity)); err == nil {
			t.Fatalf("forged envelope %d was accepted against the established victim", i+1)
		}
	}

	// Forgeries must not have driven the victim's own bucket toward the limit ...
	if d := target.envRateDrops.Load() - dropsBefore; d != 0 {
		t.Fatalf("forged envelopes caused %d rate drop(s) against an established victim: "+
			"the gate counts forgeries on the victim's live bucket before Verify. A fix "+
			"that verifies first only for new senders but keeps the pre-Verify count for "+
			"already-seen buckets still censors any active victim.", d)
	}
	// ... and the victim's next genuine envelope must still be accepted.
	got, err := target.decryptPayload(genuineEnvelope(t, victim, targetPub))
	if got == nil {
		t.Fatalf("victim's genuine envelope was dropped (%v) after a forged flood against "+
			"its established bucket: forgeries poisoned the victim's live rate state.", err)
	}
	if _, ok := got.(*PingRequest); !ok {
		t.Fatalf("victim's genuine envelope decoded to %T, want *PingRequest", got)
	}
}

// TestEnvelopeGateForgedRejectedAfterVictimTraffic pins invariant 2: a forgery must be
// rejected even after the victim has legitimately used the gate. This catches a fix that
// caches "already saw this sender, skip Verify" -- a warm cache would then accept a later
// forged ep.Sender=victim, a signature bypass. Passes while buggy and under a correct fix;
// fails only for a Verify-skipping fix.
func TestEnvelopeGateForgedRejectedAfterVictimTraffic(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	victim, err := NewSecret()
	if err != nil {
		t.Fatalf("victim secret: %v", err)
	}
	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}

	// The victim first sends a genuine envelope (warms any per-sender state/cache).
	if got, err := target.decryptPayload(genuineEnvelope(t, victim, targetPub)); got == nil {
		t.Fatalf("victim's own genuine envelope was rejected (%v)", err)
	}

	// A forgery attributed to the victim must still be rejected -- signatures are
	// re-verified per envelope, never trusted from prior genuine traffic.
	if got, _ := target.decryptPayload(forgedEnvelope(t, attacker, targetPub, victim.Identity)); got != nil {
		t.Fatalf("a forged envelope stamped with the victim's identity was accepted "+
			"after the victim sent genuine traffic: the fix is skipping signature "+
			"verification for a 'known' sender -- a signature bypass. got %T", got)
	}
}

// TestEnvelopeGatePerSenderIsolation pins invariant 4: the budget is per
// authenticated sender, so one sender flooding cannot censor another. Fails only for
// a fix that collapses senders into one shared/global bucket.
func TestEnvelopeGatePerSenderIsolation(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	senderA, err := NewSecret()
	if err != nil {
		t.Fatalf("sender A secret: %v", err)
	}
	senderB, err := NewSecret()
	if err != nil {
		t.Fatalf("sender B secret: %v", err)
	}

	var aDropped int
	for i := 0; i < envelopeRateLimit+50; i++ {
		if got, _ := target.decryptPayload(genuineEnvelope(t, senderA, targetPub)); got == nil {
			aDropped++
		}
	}
	if aDropped == 0 {
		t.Fatal("sender A exceeding the limit was not throttled at all -- the gate is not limiting")
	}

	got, err := target.decryptPayload(genuineEnvelope(t, senderB, targetPub))
	if got == nil {
		t.Fatalf("sender B's genuine envelope was dropped (%v) after sender A flooded "+
			"the gate: the rate budget must be per authenticated sender, not shared.", err)
	}
	if _, ok := got.(*PingRequest); !ok {
		t.Fatalf("sender B's envelope decoded to %T, want *PingRequest", got)
	}
}

// TestEnvelopeGateStillRateLimitsGenuineFlood pins invariant 5: a genuine sender
// exceeding the limit must still be throttled -- a fix must not delete or defang the
// gate (raise the limit above any flood, etc.). Drops are detected by "no payload
// produced", so this accepts a hard counter, a token bucket, or a silent-discard fix
// alike, while catching gate removal. Passes both while buggy and under a correct fix.
func TestEnvelopeGateStillRateLimitsGenuineFlood(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	sender, err := NewSecret()
	if err != nil {
		t.Fatalf("sender secret: %v", err)
	}

	var dropped int
	for i := 0; i < envelopeRateLimit+50; i++ {
		if got, _ := target.decryptPayload(genuineEnvelope(t, sender, targetPub)); got == nil {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("a genuine sender well over the rate limit was not throttled at all: a " +
			"fix must still rate-limit genuine over-limit traffic, not remove or defang the gate.")
	}
}

// TestEnvelopeGateReplayedForeignEnvelopeTouchesNoRateState pins invariant 6: a genuine,
// validly-signed envelope the victim sealed to a different recipient -- the kind any relay
// or co-participant holds -- must not touch the victim's rate state when replayed here. It
// passes Verify (the victim did sign those bytes; the signed hash omits the recipient) but
// fails OpenBox (it was not sealed to us), so a correct fix, which counts only after
// OpenBox, never counts it. This catches a fix that verifies first but still counts before
// OpenBox: it closes forged-sender censorship yet leaves cross-recipient replay open.
func TestEnvelopeGateReplayedForeignEnvelopeTouchesNoRateState(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	victim, err := NewSecret()
	if err != nil {
		t.Fatalf("victim secret: %v", err)
	}
	other, err := NewSecret()
	if err != nil {
		t.Fatalf("other-recipient secret: %v", err)
	}
	otherPub, err := other.NaClPublicKey()
	if err != nil {
		t.Fatalf("other nacl pub: %v", err)
	}

	// A genuine victim envelope sealed to `other`, not to us.
	foreign, err := SealBox([]byte(`{"origin_timestamp":1}`), otherPub, victim, PPingRequest)
	if err != nil {
		t.Fatalf("seal foreign envelope: %v", err)
	}

	// Flood well past any plausible hidden threshold (matching LargeForgedFlood),
	// so a pre-OpenBox counter with a raised limit in any structure still trips.
	dropsBefore := target.envRateDrops.Load()
	for i := 0; i < 5*envelopeRateLimit; i++ {
		if _, err := target.decryptPayload(foreign); err == nil {
			t.Fatalf("a foreign-recipient envelope was accepted at iter %d: it was not sealed to us", i+1)
		}
	}

	// Check rate state too, not just drops (matching the keystone): a fix that
	// counts in envelopeRates before OpenBox leaves a bucket even if it refunds or
	// dedups, which this catches; a separate-structure pre-OpenBox counter instead
	// censors the victim under the large flood, caught by the victim-served check.
	if n := target.envelopeRates.Len(); n != 0 {
		t.Fatalf("replayed foreign-recipient envelopes allocated %d rate bucket(s): the gate counts "+
			"(in envelopeRates) before OpenBox binds the envelope to this recipient.", n)
	}
	if d := target.envRateDrops.Load() - dropsBefore; d != 0 {
		t.Fatalf("replayed foreign-recipient envelopes caused %d rate drop(s): the gate counts an "+
			"envelope before OpenBox binds it to this recipient, so a validly-signed envelope addressed "+
			"elsewhere still poisons the victim's bucket (cross-recipient replay censorship).", d)
	}
	got, err := target.decryptPayload(genuineEnvelope(t, victim, targetPub))
	if got == nil {
		t.Fatalf("victim's genuine envelope was dropped (%v) after a foreign-recipient replay flood: "+
			"cross-recipient replay censored the victim.", err)
	}
	if _, ok := got.(*PingRequest); !ok {
		t.Fatalf("victim's genuine envelope decoded to %T, want *PingRequest", got)
	}
}

// TestEnvelopeGateLargeForgedFloodDoesNotCensor hardens the keystone against a fix that
// counts unverified senders in a separate structure (not envelopeRates) with a higher
// limit -- invisible to the keystone's envelopeRates check, and under a small flood also
// to the behavioral tests. A large forged flood, well above any plausible hidden limit,
// must still leave the victim served; a counter that runs before Verify in any structure
// trips under this volume. Drops are detected as "no payload produced", so a hard counter
// or a token bucket both pass. Fails while buggy.
func TestEnvelopeGateLargeForgedFloodDoesNotCensor(t *testing.T) {
	target, targetPub := newEnvelopeGateServer(t)

	victim, err := NewSecret()
	if err != nil {
		t.Fatalf("victim secret: %v", err)
	}
	attacker, err := NewSecret()
	if err != nil {
		t.Fatalf("attacker secret: %v", err)
	}

	for i := 0; i < 5*envelopeRateLimit; i++ {
		if _, err := target.decryptPayload(forgedEnvelope(t, attacker, targetPub, victim.Identity)); err == nil {
			t.Fatalf("forged envelope %d was accepted", i+1)
		}
	}
	got, err := target.decryptPayload(genuineEnvelope(t, victim, targetPub))
	if got == nil {
		t.Fatalf("victim's genuine envelope was dropped (%v) after a %d-envelope forged flood: "+
			"forgeries are being counted (possibly in a non-envelopeRates structure) before "+
			"verification.", err, 5*envelopeRateLimit)
	}
	if _, ok := got.(*PingRequest); !ok {
		t.Fatalf("victim's genuine envelope decoded to %T, want *PingRequest", got)
	}
}
