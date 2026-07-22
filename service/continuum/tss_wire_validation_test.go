// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression tests for validation of inbound TSS wire messages.
//
// These assert the REQUIRED secure behavior, so they FAIL while the flaw is
// present and PASS once it is fixed (a permanent guard, not a reproduction).
//
// The flaw: continuum's TSS wire parser (unmarshalTSSContent /
// parseTSSWireMessage in tss_wire.go) decodes attacker-controlled JSON into
// tss-lib content structs WITHOUT calling their ValidateBasic(), and the keygen
// collect() accept closure matches on Go type only. An all-nil *KGRound1Message
// therefore reaches keygen.Round2, which dereferences the nil PaillierPK and
// panics in the un-recovered ceremony goroutine -- one authenticated committee
// member can crash every honest node with a single message.
//
// Invariant under test: a structurally invalid inbound TSS message must be
// rejected at ingest (an error is returned) and must never reach the round
// functions or crash the node.
//
//   TestTSSWireParserRejectsMalformedKGRound1Message
//       Guards the recommended fix site: the wire parser must reject content
//       that fails ValidateBasic. Fast and deterministic.
//
//   TestHandleMessageRejectsMalformedKGRound1Message
//       Guards the ingest boundary end-to-end: HandleMessage on a live ceremony
//       must reject the malformed message, and the ceremony goroutine must not
//       panic.

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/hemilabs/x/tss/v3/tss"
)

// malformedKGRound1Fixtures are fully attacker-controlled wire messages: a
// well-formed continuum envelope naming a real ECDSA keygen type, whose content
// deserializes to an all-nil KGRound1Message. json.Unmarshal of either `null`
// or `{}` into a *KGRound1Message leaves every field (PaillierPK, NTilde, H1,
// H2, ...) nil, which ValidateBasic() rejects. A committee member can send
// either at will.
var malformedKGRound1Fixtures = []struct {
	name string
	wire []byte
}{
	{"null content", []byte(`{"t":"ecdsa.keygen.KGRound1Message","c":null}`)},
	{"empty object content", []byte(`{"t":"ecdsa.keygen.KGRound1Message","c":{}}`)},
}

// malformedKGRound1 is the canonical fixture used by the end-to-end test.
var malformedKGRound1 = malformedKGRound1Fixtures[0].wire

// TestTSSWireParserRejectsMalformedKGRound1Message asserts that continuum's wire
// parser rejects structurally invalid TSS content. The recommended fix validates
// decoded content (ValidateBasic) in unmarshalTSSContent; this guards that layer.
// While the flaw is present parseTSSWireMessage returns the all-nil struct with a
// nil error and this FAILS; once it validates it returns an error and this PASSES.
func TestTSSWireParserRejectsMalformedKGRound1Message(t *testing.T) {
	from := tss.NewPartyID("attacker", "attacker", big.NewInt(1))

	for _, f := range malformedKGRound1Fixtures {
		t.Run(f.name, func(t *testing.T) {
			_, err := parseTSSWireMessage(f.wire, from, true)
			if err == nil {
				t.Fatal("parseTSSWireMessage accepted a malformed KGRound1Message " +
					"whose content fails ValidateBasic; the wire parser must reject " +
					"structurally invalid TSS content")
			}
			t.Logf("wire parser rejected malformed content as required: %v", err)
		})
	}
}

// TestHandleMessageRejectsMalformedKGRound1Message asserts the ingest-boundary
// invariant end-to-end through the real continuum stack: a live Keygen ceremony
// must reject a malformed KGRound1Message delivered via HandleMessage (rather
// than enqueue it for collect -> keygen.Round2), and the ceremony goroutine must
// not crash.
//
// While the flaw is present HandleMessage returns nil (accepts and enqueues the
// message) and this FAILS; once inbound content is validated at or before ingest
// it returns an error, the message never reaches Round2, and this PASSES.
func TestHandleMessageRejectsMalformedKGRound1Message(t *testing.T) {
	network := NewTSSNetwork(t)

	// One real victim node (preparams come from the embedded fixture).
	victim := network.AddNode()

	// The attacker only needs a committee identity; it never runs a ceremony,
	// it just sends one crafted wire message.
	attackerSecret, err := NewSecret()
	if err != nil {
		t.Fatalf("new attacker secret: %v", err)
	}
	attacker := attackerSecret.Identity

	parties := []Identity{victim.id, attacker}
	cid := NewCeremonyID()
	const threshold = 1 // 2 parties, 2-of-2

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	type kgResult struct {
		panicVal any
		err      error
	}
	resCh := make(chan kgResult, 1)
	go func() {
		var res kgResult
		defer func() {
			res.panicVal = recover()
			resCh <- res
		}()
		// Registers the ceremony, runs Round1, then blocks in collect awaiting
		// the peer's round-1 message.
		_, res.err = victim.tss.Keygen(ctx, cid, parties, threshold)
	}()

	// Deliver the malformed message through the production ingest API exactly as
	// a peer would: keygen framing is [broadcast:1][wireBytes...]. Retry only
	// while the ceremony is not yet registered (ErrUnknownCeremony); any other
	// outcome is the ingest decision under test.
	data := append([]byte{msgTypeBroadcast}, malformedKGRound1...)
	var ingestErr error
	accepted := false
deliver:
	for {
		herr := victim.tss.HandleMessage(ctx, attacker, cid, data)
		switch {
		case herr == nil:
			accepted = true
			break deliver
		case errors.Is(herr, ErrUnknownCeremony):
			select {
			case <-ctx.Done():
				t.Fatalf("ceremony never registered before deadline: %v", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		default:
			ingestErr = herr
			break deliver
		}
	}

	// INVARIANT 1: the malformed message must be rejected at ingest, not enqueued.
	if accepted {
		t.Fatal("HandleMessage accepted a malformed KGRound1Message (its content " +
			"fails ValidateBasic) and enqueued it for the ceremony; inbound TSS " +
			"messages must be rejected at ingest so they never reach the round " +
			"functions")
	}
	t.Logf("malformed message rejected at ingest as required: %v", ingestErr)

	// INVARIANT 2: with the message rejected it never reaches keygen.Round2, so
	// the node must stay up. Cancel to unblock the driver (still awaiting a valid
	// round-1 message) and confirm it unwound without panicking.
	cancel()
	select {
	case res := <-resCh:
		if res.panicVal != nil {
			t.Fatalf("ceremony goroutine crashed on the malformed message "+
				"(panic: %v); a rejected message must not reach the round functions",
				res.panicVal)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the ceremony goroutine to unwind")
	}
}
