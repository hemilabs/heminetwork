// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression test for the missing "from == self" check in HandleMessage.
//
// HandleMessage resolves an inbound message's party index from the sender's
// identity but never rejects a message whose sender is the node ITSELF. In a
// collect-based ceremony the round driver fills its own slot directly and
// collects the OTHER n-1 parties' messages by index (msgBuf.collect). A message
// attributed to the node itself, with valid content (so it passes the
// ValidateBasic ingest guard), is accepted into the node's own collector slot,
// consuming one of the n-1 quota slots. collect() then returns "satisfied" while
// a real party's slot is still nil, and the round function (keygen.Round2)
// dereferences that nil message -- a nil-pointer panic in the un-recovered
// ceremony goroutine, which crashes the whole node process.
//
// Each case FAILS while the flaw is present (nil-pointer panic in Round2) and
// PASSES once a self-attributed message can no longer take another party's slot
// -- whether the fix rejects it at ingest (HandleMessage: from == self) or deeper
// (the collector/driver declines to seat a self message). The verdict only ever
// asserts "did not crash", so it is agnostic to fix location.
//
// SCOPE. Every case is 2-party ECDSA keygen with no live peer. That is
// deliberate: with the peer never live, the injected self message is the only
// thing on the collector's channel, so it always steals the slot -- no ordering
// race, no flake, and n-1 == 1 means Round2 hits the nil slot immediately with no
// competing crypto path. The table varies only the WIRE FRAMING of the reflected
// message (broadcast vs p2p) -- the one axis that stays deterministic and
// fail-while-buggy without a live committee, and which proves the crash is driven
// by sender identity, not the framing byte (so a fix keyed only on the broadcast
// flag would not close the hole). Sign, reshare, n>=3, EdDSA and a malformed-self
// case were evaluated and dropped: they need a real key share, a live committee,
// or fail to fail-while-buggy. The shared ingest fix is ceremony-agnostic, so this
// one ceremony pins sign and reshare too.

import (
	"context"
	"testing"
	"time"
)

// captureTransport records the victim's outbound ceremony messages so the test
// can reflect one back to the victim as if the victim itself had sent it. This
// models an on-path relay reflecting a node's own broadcast back to it. Capture
// (not synthesis) is load-bearing: ValidateBasic drops an empty KGRound1Message
// and would let a hand-built bogus one be rejected by Round2 before it reaches the
// nil peer slot -- masking the crash. The victim's genuine broadcast is valid all
// the way through Round2, so the nil slot is the only thing left to panic on.
type captureTransport struct{ sent chan []byte }

func (c *captureTransport) Send(_ Identity, _ CeremonyID, data []byte) error {
	cp := append([]byte(nil), data...)
	select {
	case c.sent <- cp:
	default: // capacity is slack; dropping extras is fine.
	}
	return nil
}

// reframe rewrites the wire framing of a captured message without touching its
// (valid) content, so the reflected copy still parses and clears ValidateBasic.
type reframe func(wire []byte) []byte

// asBroadcast reflects the round-1 broadcast unchanged (baseline reproduction).
func asBroadcast(wire []byte) []byte { return append([]byte(nil), wire...) }

// asP2P flips the broadcast framing byte to unicast and leaves content untouched.
// HandleMessage routes on sender identity and the collector's accept closure keys
// on content type + From.Index -- neither consults the framing byte -- so this
// still steals the self slot and panics while buggy. It guards against a fix that
// special-cases only the broadcast flag.
func asP2P(wire []byte) []byte {
	out := append([]byte(nil), wire...)
	if len(out) > 0 {
		out[0] = msgTypeP2P
	}
	return out
}

// keygenOutcome records exactly how the ceremony goroutine ended: a recovered
// panic (the crash we guard against) and/or the driver's key ID and error, so
// every failure message can name the concrete ending rather than an opaque value.
type keygenOutcome struct {
	panicVal any
	keyID    []byte
	err      error
}

func mustSecret(t *testing.T) *Secret {
	t.Helper()
	s, err := NewSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	return s
}

// newCapturingVictim builds a victim TSS node backed by a real encrypted store
// with embedded preparams and a capturing transport.
func newCapturingVictim(t *testing.T, secret *Secret) (TSS, *captureTransport) {
	t.Helper()
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	loadTestPreParams(t, store.(*fileStore), 0)
	transport := &captureTransport{sent: make(chan []byte, 8)}
	return NewTSS(secret.Identity, store, transport), transport
}

func TestReflectedSelfMessageDoesNotCrashKeygen(t *testing.T) {
	cases := []struct {
		name    string
		reframe reframe
	}{
		{"broadcast-framed self", asBroadcast},
		{"p2p-framed self", asP2P},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runKeygenSelfReflection(t, tc.reframe)
		})
	}
}

// runKeygenSelfReflection builds a 2-party keygen victim, captures its genuine
// round-1 broadcast, reframes it, reflects it back attributed to the victim
// itself (from == self), and asserts the node does not crash.
func runKeygenSelfReflection(t *testing.T, reframe reframe) {
	t.Helper()

	const (
		// captureBound: generous failsafe on the victim producing round 1
		// (preparams are cached, so this is fast). Never a pass signal.
		captureBound = 30 * time.Second
		// settleWindow: once the self message is enqueued, a buggy build consumes it
		// and panics almost immediately (it is the only thing on the channel the
		// collector is already blocked reading). We wait this long for that panic
		// before concluding a fixed build dropped it. It adds latency only to the
		// passing case and is NEVER itself a pass signal -- the verdict is the
		// recovered panic value, not this timeout.
		settleWindow = 500 * time.Millisecond
		// exitBound: failsafe on the fast channel-based cancellation handshake.
		exitBound = 5 * time.Second
	)

	victimSecret := mustSecret(t)
	otherSecret := mustSecret(t)
	victim, transport := newCapturingVictim(t, victimSecret)

	// 2-party keygen; the "other" party is never live, so the only round-1 message
	// the victim's collector can ever seat is the one we inject.
	parties := []Identity{victimSecret.Identity, otherSecret.Identity}
	cid := NewCeremonyID()
	const threshold = 1

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Run the ceremony; the deferred recover models the fact that a real crash --
	// continuum has no recover() -- would take down the process.
	done := make(chan keygenOutcome, 1)
	go func() {
		var res keygenOutcome
		defer func() {
			res.panicVal = recover()
			done <- res
		}()
		res.keyID, res.err = victim.Keygen(ctx, cid, parties, threshold)
	}()

	// Capture the victim's own valid round-1 broadcast.
	var selfMsg []byte
	select {
	case selfMsg = <-transport.sent:
	case res := <-done:
		t.Fatalf("keygen ended before sending its round-1 message "+
			"(panic=%v keyID=%x err=%v); reproduction never armed",
			res.panicVal, res.keyID, res.err)
	case <-time.After(captureBound):
		t.Fatal("victim never sent its round-1 message")
	}
	selfMsg = reframe(selfMsg)

	// Reflect it back, attributed to the victim ITSELF (from == self). The content
	// is genuinely valid, so the ValidateBasic guard cannot drop it -- proving the
	// flaw is distinct from that guard. The ceremony registers itself before it
	// emits round 1, so by the time we captured the broadcast it is already in the
	// map and HandleMessage routes straight to it (no ErrUnknownCeremony window).
	// A fixed HandleMessage returns an error here (rejected at ingest); a fixed
	// collector accepts (nil) but never seats it; a buggy build seats it and arms
	// the nil-slot crash. All three are handled by the single verdict below.
	if herr := victim.HandleMessage(ctx, victimSecret.Identity, cid, selfMsg); herr != nil {
		t.Logf("self-attributed message rejected at ingest: %v", herr)
	}

	// Verdict. ctx is NOT cancelled during this window, so a buggy collector's
	// select has only the self message ready -- cancellation cannot pre-empt the
	// panic. A crash surfaces as a non-nil recover; a clean return before we cancel
	// means the nil-slot path was never exercised (a 2-party keygen cannot
	// legitimately finish with the peer absent), so that too is a hard failure.
	select {
	case res := <-done:
		if res.panicVal != nil {
			t.Fatalf("keygen ceremony crashed on a self-attributed message "+
				"(panic: %v); a message whose sender is the node itself must not "+
				"occupy another party's collector slot", res.panicVal)
		}
		t.Fatalf("keygen returned (keyID=%x err=%v) before consuming the self-"+
			"attributed message; the nil-slot crash path was not exercised",
			res.keyID, res.err)
	case <-time.After(settleWindow):
		// No crash and no premature return: a fixed node refused to seat the self
		// message. Fall through to cancel and require a clean exit.
	}

	// Unblock the still-waiting driver (stuck collecting the never-arriving real
	// party) and require a clean, panic-free exit.
	cancel()
	select {
	case res := <-done:
		if res.panicVal != nil {
			t.Fatalf("keygen crashed after cancellation: %v", res.panicVal)
		}
	case <-time.After(exitBound):
		t.Fatal("keygen did not exit after cancellation")
	}
}
