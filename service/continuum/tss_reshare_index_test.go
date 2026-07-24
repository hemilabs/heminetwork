// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression tests for out-of-bounds party indexing in reshare message
// collection.
//
// The flaw: msgBuf.collect / msgBuf.collectDual (tss_round.go) place accepted
// messages with `out[slot] = m` where slot = m.From.Index, with NO bounds check.
// During a reshare there are two independent party-index spaces -- old committee
// [0,oldPC) and new committee [0,newPC) -- and HandleMessage picks which set
// resolves From.Index purely from the attacker-controlled cflagFromNew wire bit,
// while the accept closures discriminate on Go content type only. A new-committee
// member at new-index >= oldPC can send a round-1-typed message with fromNew set;
// it is collected into an oldPC-sized buffer and indexes out of bounds, panicking
// the un-recovered ceremony goroutine -- one participant crashes every node.
//
// Both tests assert the REQUIRED secure behavior, so they FAIL while the flaw is
// present and PASS once it is fixed by either style: a bounds check inside the
// collectors, or validating the committee flag at ingest in HandleMessage.

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	resharing "github.com/hemilabs/x/tss/v3/ecdsa/resharing"
	"github.com/hemilabs/x/tss/v3/tss"
)

// matchContent is an accept closure that matches messages of content type T and
// returns the sender's party index -- exactly what the production reshare
// collectors use (content-type discrimination + m.From.Index).
func matchContent[T any](m *tss.Message) (slot int, ok bool) {
	_, ok = m.Content.(T)
	return m.From.Index, ok
}

// partyIDAt returns a *tss.PartyID with a fixed sorted Index, as SortPartyIDs
// would assign. Only From.Index is load-bearing for the collectors; the id
// strings are cosmetic.
func partyIDAt(id string, index int) *tss.PartyID {
	p := tss.NewPartyID(id, id, big.NewInt(int64(index)+1))
	p.Index = index
	return p
}

// recoverPanic runs fn and returns the value it panicked with, or nil if it
// returned normally. The production collectors run in the ceremony goroutine
// with no recover, so a panic here models a node crash.
func recoverPanic(fn func()) (recovered any) {
	defer func() { recovered = recover() }()
	fn()
	return nil
}

// TestMsgBufCollectorsRejectOutOfRangePartyIndex asserts the root-cause
// invariant directly on the collectors. The accept closures mirror the reshare
// driver's exactly: they discriminate on Go content type and return
// (m.From.Index, ok). When that slot is out of range for the round's party
// count the collector must treat the message as a non-match rather than index
// `out[slot]` out of bounds.
//
// While the flaw is present the collectors do `out[slot] = m` unconditionally
// and panic (FAIL). Once the slot is range-checked they drop the out-of-range
// message and complete using the in-range one (PASS) -- the placement assertion
// proves the guard does not simply swallow everything.
func TestMsgBufCollectorsRejectOutOfRangePartyIndex(t *testing.T) {
	const nParties = 2 // valid slots are 0 and 1; nParties itself is out of range

	t.Run("collect", func(t *testing.T) {
		valid := &tss.Message{From: partyIDAt("honest", 0), Content: &resharing.DGRound1Message{}}
		ch := make(chan *tss.Message, 2)
		// slot == len(out): one past the last valid index. Delivered first, so the
		// OOB slot is hit before the valid one.
		ch <- &tss.Message{From: partyIDAt("attacker", nParties), Content: &resharing.DGRound1Message{}}
		ch <- valid
		b := newMsgBuf(ch)

		var out []*tss.Message
		var err error
		recovered := recoverPanic(func() {
			out, err = b.collect(context.Background(), 1, nParties, matchContent[*resharing.DGRound1Message])
		})
		if recovered != nil {
			t.Fatalf("collect indexed an out-of-range slot and panicked (%v); it "+
				"must treat slot >= nParties as a non-match", recovered)
		}
		if err != nil {
			t.Fatalf("collect returned error: %v", err)
		}
		if out[0] != valid {
			t.Fatal("collect did not place the in-range message at index 0")
		}
	})

	t.Run("collectDual", func(t *testing.T) {
		validA := &tss.Message{From: partyIDAt("honestA", 0), Content: &resharing.DGRound1Message{}}
		ch := make(chan *tss.Message, 3)
		// The attacker message is a type-A message carrying an out-of-range index.
		ch <- &tss.Message{From: partyIDAt("attacker", nParties), Content: &resharing.DGRound1Message{}}
		ch <- validA
		ch <- &tss.Message{From: partyIDAt("honestB", 1), Content: &resharing.DGRound2Message1{}}
		b := newMsgBuf(ch)

		var a []*tss.Message
		var err error
		recovered := recoverPanic(func() {
			a, _, err = b.collectDual(context.Background(), 1, nParties,
				matchContent[*resharing.DGRound1Message], matchContent[*resharing.DGRound2Message1])
		})
		if recovered != nil {
			t.Fatalf("collectDual indexed an out-of-range slot and panicked (%v); "+
				"it must treat slot >= nParties as a non-match", recovered)
		}
		if err != nil {
			t.Fatalf("collectDual returned error: %v", err)
		}
		if a[0] != validA {
			t.Fatal("collectDual did not place the in-range A message at index 0")
		}
	})
}

// reshareOutcome captures how the ceremony goroutine ended: a recovered panic
// (the crash we guard against) and/or the driver's returned error.
type reshareOutcome struct {
	panicVal any
	err      error
}

// TestReshareDoesNotCrashOnCrossCommitteePartyIndex asserts the invariant
// end-to-end through the real continuum stack. A live reshare on a new-only
// victim collects round-1 messages into an oldPC-sized buffer; an attacker that
// is a new-committee member at new-index >= oldPC sends a round-1-typed message
// with the fromNew flag set, so HandleMessage resolves its index in the larger
// new PID set and the collector would index out of bounds.
//
// While the flaw is present the ceremony goroutine panics and this FAILS. Under
// either fix -- a bounds check in the collector, or committee-flag validation at
// ingest -- the message is dropped and the node stays up, so this PASSES.
func TestReshareDoesNotCrashOnCrossCommitteePartyIndex(t *testing.T) {
	const (
		oldPC = 2 // old committee size
		newPC = 3 // new committee size (must exceed oldPC)

		// settleWindow: after the malicious message is enqueued, a buggy build
		// consumes it and panics almost immediately (it is the only thing on a
		// channel the collector is already blocked on). We wait this long for that
		// panic before concluding a fixed build dropped it and re-blocked. It only
		// adds latency to the passing (bounds-check) case; the failing case returns
		// as soon as the panic lands. It is not a pass signal -- see the final read.
		settleWindow = 500 * time.Millisecond
		exitBound    = 5 * time.Second // failsafe upper bound on a clean exit
	)

	// Three new-committee identities, sorted exactly as the reshare driver does
	// via the production buildResharePartyContext(newParties, true) -- no manual
	// replication of the key-rotation/sort -- so the victim stays below oldPC and
	// the attacker at index oldPC even if that derivation ever changes. Sort order
	// is independent of self, so a zero-value tssImpl computes it faithfully.
	newSecrets := make(map[string]*Secret, newPC)
	newParties := make([]Identity, 0, newPC)
	for range newPC {
		s, err := NewSecret()
		if err != nil {
			t.Fatalf("new secret: %v", err)
		}
		newSecrets[s.Identity.String()] = s
		newParties = append(newParties, s.Identity)
	}
	sortedNew, _, _, _, err := (&tssImpl{}).buildResharePartyContext(newParties, true)
	if err != nil {
		t.Fatalf("sort new committee: %v", err)
	}
	victimSecret := newSecrets[sortedNew[0].Id]          // new-index 0     (< oldPC)
	attacker := newSecrets[sortedNew[oldPC].Id].Identity // new-index oldPC (out of range)

	// Old committee: fresh identities disjoint from the new committee, so the
	// victim is new-only and never loads a key share.
	oldParties := make([]Identity, 0, oldPC)
	for range oldPC {
		s, err := NewSecret()
		if err != nil {
			t.Fatalf("new secret: %v", err)
		}
		oldParties = append(oldParties, s.Identity)
	}

	// Build the victim node: real store + embedded preparams, and the package's
	// shared no-op transport since no peers are live.
	store, err := NewTSSStore(t.TempDir(), victimSecret)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	loadTestPreParams(t, store.(*fileStore), 0)
	victim := NewTSS(victimSecret.Identity, store, noopTransport{})

	cid := NewCeremonyID()
	keyID := make([]byte, 16) // arbitrary; a new-only node never loads it

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Run the ceremony: it registers, runs new-committee round 1, then blocks in
	// collect awaiting oldPC round-1 messages. A recovered panic or the returned
	// error is reported on `done` exactly once.
	done := make(chan reshareOutcome, 1)
	go func() {
		var res reshareOutcome
		defer func() {
			res.panicVal = recover()
			done <- res
		}()
		res.err = victim.Reshare(ctx, cid, keyID, oldParties, newParties, 1, 1)
	}()

	// Craft the cross-committee message: a round-1 (DGRound1Message) content the
	// round-1 collector matches, sent with fromNew set so HandleMessage resolves
	// the attacker's index in the larger new PID set. Reshare framing is
	// [broadcast:1][committee_flags:1][wireBytes...].
	wire, err := marshalTSSContent(&resharing.DGRound1Message{})
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}
	data := append([]byte{msgTypeBroadcast, cflagToNew | cflagFromNew}, wire...)

	// Deliver the one malicious message, retrying only until the ceremony
	// registers. herr == nil means it was enqueued for the collector; a
	// non-ErrUnknownCeremony error means HandleMessage refused it at ingest (the
	// committee-flag-validation fix).
	deadline := time.After(exitBound)
	rejectedAtIngest := false
deliver:
	for {
		switch herr := victim.HandleMessage(ctx, attacker, cid, data); {
		case herr == nil:
			break deliver
		case errors.Is(herr, ErrUnknownCeremony):
			// Not registered yet; wait and retry.
		default:
			t.Logf("cross-committee message rejected at ingest: %v", herr)
			rejectedAtIngest = true
			break deliver
		}
		select {
		case res := <-done:
			// Driver ended before we could deliver: a pure setup failure (the
			// collector was never fed, so the OOB path was not exercised).
			t.Fatalf("reshare ended before delivery (panic=%v err=%v); OOB path "+
				"not exercised", res.panicVal, res.err)
		case <-deadline:
			t.Fatal("ceremony never registered; malicious message undeliverable")
		case <-time.After(2 * time.Millisecond):
			// retry
		}
	}

	if !rejectedAtIngest {
		// The message is on the ceremony's inbound channel and the collector is
		// already blocked reading it. A buggy build indexes out of bounds and
		// panics within settleWindow; a bounds-checked build drops the message and
		// re-blocks (no panic). ctx is NOT cancelled during this window, so a buggy
		// collector's select has only the message ready -- cancellation can never
		// pre-empt the panic.
		select {
		case res := <-done:
			if res.panicVal != nil {
				t.Fatalf("reshare ceremony crashed on a cross-committee party index "+
					"(panic: %v); an out-of-range index driven by the attacker-"+
					"controlled committee flag must not index the collector out of "+
					"bounds", res.panicVal)
			}
			// A clean return before we cancelled means the driver never blocked on
			// the malicious message -- the OOB path was not exercised, so passing
			// here would be a false pass.
			t.Fatalf("reshare ended (err=%v) before consuming the malicious "+
				"message; the out-of-bounds path was not exercised", res.err)
		case <-time.After(settleWindow):
			// No panic: a fixed collector consumed and dropped the message. Fall
			// through to cancel and require a clean exit.
		}
	}

	// Unblock the still-waiting driver and require a clean, panic-free exit.
	cancel()
	select {
	case res := <-done:
		if res.panicVal != nil {
			t.Fatalf("reshare ceremony crashed after cancellation (panic: %v)", res.panicVal)
		}
	case <-time.After(exitBound):
		t.Fatal("reshare did not exit after cancellation")
	}
}
