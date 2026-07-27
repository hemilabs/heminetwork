// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression test for the residual left by the reshare collector bounds-check:
// an IN-RANGE cross-committee party-index collision.
//
// HandleMessage resolves an inbound reshare message's From.Index in whichever
// committee the attacker-controlled cflagFromNew wire bit selects, and the round
// collectors match on Go content type only. The committed bounds-check stops an
// OUT-OF-RANGE index, but a Byzantine NEW-committee member can flip cflagFromNew
// on an old-committee (DGRound1) message so its index resolves in the NEW space;
// when that index is IN RANGE for the oldPC-sized round-1 buffer AND equals an
// overlapping victim's own old-slot, it seizes that slot. The driver then
// overwrites its own slot with selfR1 (tss.go), wasting the seizure and leaving a
// real party's slot nil, and ReshareRound2 dereferences the nil message
// (ecdsa/resharing/round_fn.go) -> nil-pointer panic in the un-recovered ceremony
// goroutine -> node crash.
//
// The bounds-check cannot help here: the seized index is in range. The test FAILS
// while the flaw is present (crash) and PASSES once ingest binds the committee to
// the message's content type (so a DGRound1 with fromNew=1 is rejected and the
// sender can only ever fill its own slot in its own committee).

import (
	"context"
	"sync"
	"testing"
	"time"
)

// reshareIndexOf returns id's sorted party index within a committee, computed
// exactly as the reshare driver does (buildResharePartyContext: new-committee
// keys are XOR'd before sorting).
func reshareIndexOf(t *testing.T, id Identity, parties []Identity, isNew bool) int {
	t.Helper()
	sorted, _, _, _, err := (&tssImpl{}).buildResharePartyContext(parties, isNew)
	if err != nil {
		t.Fatalf("build party context: %v", err)
	}
	for _, p := range sorted {
		if p.Id == id.String() {
			return p.Index
		}
	}
	t.Fatalf("identity %s not found in committee", id)
	return -1
}

func TestReshareCrossCommitteeSlotSeizureCrashesReshare(t *testing.T) {
	const (
		settleWindow = 750 * time.Millisecond
		exitBound    = 10 * time.Second
	)

	// --- Real 2-party keygen so the overlapping victim A holds a key share. ---
	network := NewTSSNetwork(t)
	a := network.AddNode()
	b := network.AddNode()
	oldParties := []Identity{a.id, b.id} // oldPC = 2
	const threshold = 1

	kgCtx, kgCancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer kgCancel()
	keygenCID := NewCeremonyID()
	var wg sync.WaitGroup
	keyIDs := make([][]byte, 2)
	kerr := make([]error, 2)
	for i, n := range []*tssNode{a, b} {
		wg.Add(1)
		go func(i int, n *tssNode) {
			defer wg.Done()
			keyIDs[i], kerr[i] = n.tss.Keygen(kgCtx, keygenCID, oldParties, threshold)
		}(i, n)
	}
	wg.Wait()
	for i, e := range kerr {
		if e != nil {
			t.Fatalf("keygen node %d: %v", i, e)
		}
	}
	keyID := keyIDs[0]

	// --- Pick attacker C (new-only) whose NEW-committee index equals A's OLD
	// index (necessarily < oldPC, so in range). Then a DGRound1 with fromNew=1
	// from C resolves onto A's own old-slot. ---
	aOldIndex := reshareIndexOf(t, a.id, oldParties, false)
	var attacker *Secret
	var newParties []Identity
	for range 4000 {
		c := mustSecret(t)
		np := []Identity{a.id, b.id, c.Identity}
		if reshareIndexOf(t, c.Identity, np, true) == aOldIndex {
			attacker, newParties = c, np
			break
		}
	}
	if attacker == nil {
		t.Fatal("could not find an attacker identity with the target new-index")
	}

	// --- Run ONLY victim A's reshare, with a capturing transport. B and the
	// attacker are not live, so A's collector sees only what we inject. ---
	capture := &captureTransport{sent: make(chan []byte, 16)}
	victim := NewTSS(a.secret.Identity, a.store, capture)

	reshareCID := NewCeremonyID()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		_ = victim.Reshare(ctx, reshareCID, keyID, oldParties, newParties, threshold, threshold)
	}()

	// --- Capture A's own valid round-1 DGRound1 broadcast. ---
	var captured []byte
	select {
	case captured = <-capture.sent:
	case res := <-done:
		t.Fatalf("victim reshare ended before sending round 1: %v", res)
	case <-time.After(60 * time.Second):
		t.Fatal("victim never sent its round-1 message")
	}
	if len(captured) <= wireHeaderLen {
		t.Fatalf("captured reshare message too short: %d bytes", len(captured))
	}
	wireBytes := captured[wireHeaderLen:]

	// --- Reflect it as a cross-committee message: same valid content, but with
	// the fromNew flag set and attributed to the attacker C (from != self). ---
	data := append([]byte{captured[0], cflagToNew | cflagFromNew}, wireBytes...)
	if herr := victim.HandleMessage(ctx, attacker.Identity, reshareCID, data); herr != nil {
		t.Logf("cross-committee message rejected at ingest: %v", herr)
	}

	// --- Verdict: a crash surfaces as a recovered panic; a clean early return
	// means the path was not exercised; a timeout means a fixed ingest dropped it. ---
	select {
	case res := <-done:
		if res != nil {
			t.Fatalf("reshare crashed on an in-range cross-committee slot seizure "+
				"(panic: %v); a reshare message must not be resolved into another "+
				"committee's index space", res)
		}
		t.Fatalf("reshare returned before consuming the injected message; the " +
			"seizure path was not exercised")
	case <-time.After(settleWindow):
		// No crash: a fixed node bound the committee to the content type and
		// refused the cross-committee message. Fall through and require clean exit.
	}

	cancel()
	select {
	case res := <-done:
		if res != nil {
			t.Fatalf("reshare crashed after cancellation: %v", res)
		}
	case <-time.After(exitBound):
		t.Fatal("reshare did not exit after cancellation")
	}
}
