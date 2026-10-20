// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/hemilabs/x/tss/v3/crypto"
	cmt "github.com/hemilabs/x/tss/v3/crypto/commitments"
	ecdsaKeygen "github.com/hemilabs/x/tss/v3/ecdsa/keygen"
	ecdsaResharing "github.com/hemilabs/x/tss/v3/ecdsa/resharing"
	ecdsaSigning "github.com/hemilabs/x/tss/v3/ecdsa/signing"
	eddsaKeygen "github.com/hemilabs/x/tss/v3/eddsa/keygen"
	eddsaResharing "github.com/hemilabs/x/tss/v3/eddsa/resharing"
	eddsaSigning "github.com/hemilabs/x/tss/v3/eddsa/signing"
	"github.com/hemilabs/x/tss/v3/tss"
)

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	ec := tss.EC()
	pt := crypto.ScalarBaseMult(ec, big.NewInt(42))
	edPt := crypto.ScalarBaseMult(tss.Edwards(), big.NewInt(7))

	tests := []struct {
		name    string
		content any
	}{
		// ecdsa keygen
		{"ecdsa.keygen.KGRound1Message", &ecdsaKeygen.KGRound1Message{
			Commitment: big.NewInt(99),
			NTilde:     big.NewInt(5678),
			H1:         big.NewInt(11),
			H2:         big.NewInt(22),
		}},
		{"ecdsa.keygen.KGRound2Message1", &ecdsaKeygen.KGRound2Message1{Share: big.NewInt(77)}},
		{"ecdsa.keygen.KGRound2Message2", &ecdsaKeygen.KGRound2Message2{}},
		{"ecdsa.keygen.KGRound3Message", &ecdsaKeygen.KGRound3Message{}},
		// ecdsa signing
		{"ecdsa.signing.SignRound1Message1", &ecdsaSigning.SignRound1Message1{C: big.NewInt(100)}},
		{"ecdsa.signing.SignRound1Message2", &ecdsaSigning.SignRound1Message2{Commitment: big.NewInt(300)}},
		{"ecdsa.signing.SignRound2Message", &ecdsaSigning.SignRound2Message{}},
		{"ecdsa.signing.SignRound3Message", &ecdsaSigning.SignRound3Message{}},
		{"ecdsa.signing.SignRound4Message", &ecdsaSigning.SignRound4Message{}},
		{"ecdsa.signing.SignRound5Message", &ecdsaSigning.SignRound5Message{Commitment: big.NewInt(400)}},
		{"ecdsa.signing.SignRound6Message", &ecdsaSigning.SignRound6Message{
			DeCommitment: cmt.HashDeCommitment{big.NewInt(5), big.NewInt(6)},
		}},
		{"ecdsa.signing.SignRound7Message", &ecdsaSigning.SignRound7Message{}},
		{"ecdsa.signing.SignRound8Message", &ecdsaSigning.SignRound8Message{}},
		{"ecdsa.signing.SignRound9Message", &ecdsaSigning.SignRound9Message{S: big.NewInt(500)}},
		// ecdsa resharing
		{"ecdsa.resharing.DGRound1Message", &ecdsaResharing.DGRound1Message{
			ECDSAPub:    pt,
			VCommitment: big.NewInt(88),
			SSID:        []byte("test-ssid"),
		}},
		{"ecdsa.resharing.DGRound2Message1", &ecdsaResharing.DGRound2Message1{
			NTilde: big.NewInt(1111),
			H1:     big.NewInt(2222),
			H2:     big.NewInt(3333),
		}},
		{"ecdsa.resharing.DGRound2Message2", &ecdsaResharing.DGRound2Message2{}},
		{"ecdsa.resharing.DGRound3Message1", &ecdsaResharing.DGRound3Message1{
			Share:      big.NewInt(44),
			ReceiverID: []byte("recv"),
		}},
		{"ecdsa.resharing.DGRound3Message2", &ecdsaResharing.DGRound3Message2{
			VDeCommitment: cmt.HashDeCommitment{big.NewInt(7), big.NewInt(8)},
		}},
		{"ecdsa.resharing.DGRound4Message1", &ecdsaResharing.DGRound4Message1{ReceiverID: []byte("recv2")}},
		{"ecdsa.resharing.DGRound4Message2", &ecdsaResharing.DGRound4Message2{}},
		// eddsa keygen
		{"eddsa.keygen.KGRound1Message", &eddsaKeygen.KGRound1Message{
			Commitment: big.NewInt(55),
		}},
		{"eddsa.keygen.KGRound2Message1", &eddsaKeygen.KGRound2Message1{
			Share:      big.NewInt(33),
			ReceiverID: []byte("ed-recv"),
		}},
		{"eddsa.keygen.KGRound2Message2", &eddsaKeygen.KGRound2Message2{
			DeCommitment: cmt.HashDeCommitment{big.NewInt(9), big.NewInt(10)},
		}},
		// eddsa signing
		{"eddsa.signing.SignRound1Message", &eddsaSigning.SignRound1Message{
			Commitment: big.NewInt(66),
		}},
		{"eddsa.signing.SignRound2Message", &eddsaSigning.SignRound2Message{
			DeCommitment: cmt.HashDeCommitment{big.NewInt(11), big.NewInt(12)},
		}},
		{"eddsa.signing.SignRound3Message", &eddsaSigning.SignRound3Message{
			S: big.NewInt(77),
		}},
		// eddsa resharing
		{"eddsa.resharing.DGRound1Message", &eddsaResharing.DGRound1Message{
			EDDSAPub:    edPt,
			VCommitment: big.NewInt(99),
		}},
		{"eddsa.resharing.DGRound2Message", &eddsaResharing.DGRound2Message{}},
		{"eddsa.resharing.DGRound3Message1", &eddsaResharing.DGRound3Message1{
			Share:      big.NewInt(55),
			ReceiverID: []byte("ed-reshare-recv"),
		}},
		{"eddsa.resharing.DGRound3Message2", &eddsaResharing.DGRound3Message2{
			VDeCommitment: cmt.HashDeCommitment{big.NewInt(13), big.NewInt(14)},
		}},
		{"eddsa.resharing.DGRound4Message", &eddsaResharing.DGRound4Message{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := marshalTSSContent(tt.content)
			if err != nil {
				t.Fatalf("marshal %s: %v", tt.name, err)
			}
			got, err := unmarshalTSSContent(data)
			if err != nil {
				t.Fatalf("unmarshal %s: %v", tt.name, err)
			}
			// The wire key must map back to the exact Go type that
			// went in, not merely to some type unmarshal knows.
			if gotT, wantT := reflect.TypeOf(got), reflect.TypeOf(tt.content); gotT != wantT {
				t.Fatalf("round-trip type = %v, want %v", gotT, wantT)
			}
			// And the decoded value must re-encode to the same
			// bytes, so no field was dropped or renamed on the way.
			again, err := marshalTSSContent(got)
			if err != nil {
				t.Fatalf("re-marshal %s: %v", tt.name, err)
			}
			if !bytes.Equal(again, data) {
				t.Fatalf("re-marshal %s: %s != %s", tt.name, again, data)
			}
		})
	}
}

func TestMarshalNilContent(t *testing.T) {
	_, err := marshalTSSContent(nil)
	if err == nil {
		t.Fatal("expected error for nil content")
	}
}

func TestUnmarshalUnknownType(t *testing.T) {
	_, err := unmarshalTSSContent([]byte(`{"t":"BogusType","c":{}}`))
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestUnmarshalMalformedJSON(t *testing.T) {
	_, err := unmarshalTSSContent([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseTSSWireMessage(t *testing.T) {
	from := tss.NewPartyID("test", "test", big.NewInt(1))
	content := &ecdsaKeygen.KGRound1Message{
		Commitment: big.NewInt(42),
		NTilde:     big.NewInt(200),
		H1:         big.NewInt(10),
		H2:         big.NewInt(20),
	}
	data, err := marshalTSSContent(content)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := parseTSSWireMessage(data, from, true)
	if err != nil {
		t.Fatal(err)
	}
	if msg.From != from {
		t.Fatal("From mismatch")
	}
	if !msg.IsBroadcast {
		t.Fatal("expected broadcast")
	}
	if _, ok := msg.Content.(*ecdsaKeygen.KGRound1Message); !ok {
		t.Fatalf("Content type mismatch: %T", msg.Content)
	}
}

func TestNewContentByTypeExhaustive(t *testing.T) {
	types := []string{
		// ecdsa
		"ecdsa.keygen.KGRound1Message", "ecdsa.keygen.KGRound2Message1",
		"ecdsa.keygen.KGRound2Message2", "ecdsa.keygen.KGRound3Message",
		"ecdsa.signing.SignRound1Message1", "ecdsa.signing.SignRound1Message2",
		"ecdsa.signing.SignRound2Message", "ecdsa.signing.SignRound3Message",
		"ecdsa.signing.SignRound4Message", "ecdsa.signing.SignRound5Message",
		"ecdsa.signing.SignRound6Message", "ecdsa.signing.SignRound7Message",
		"ecdsa.signing.SignRound8Message", "ecdsa.signing.SignRound9Message",
		"ecdsa.resharing.DGRound1Message", "ecdsa.resharing.DGRound2Message1",
		"ecdsa.resharing.DGRound2Message2", "ecdsa.resharing.DGRound3Message1",
		"ecdsa.resharing.DGRound3Message2", "ecdsa.resharing.DGRound4Message1",
		"ecdsa.resharing.DGRound4Message2",
		// eddsa
		"eddsa.keygen.KGRound1Message", "eddsa.keygen.KGRound2Message1",
		"eddsa.keygen.KGRound2Message2",
		"eddsa.signing.SignRound1Message", "eddsa.signing.SignRound2Message",
		"eddsa.signing.SignRound3Message",
		// eddsa resharing
		"eddsa.resharing.DGRound1Message", "eddsa.resharing.DGRound2Message",
		"eddsa.resharing.DGRound3Message1", "eddsa.resharing.DGRound3Message2",
		"eddsa.resharing.DGRound4Message",
	}
	for _, typ := range types {
		if v := newContentByType(typ); v == nil {
			t.Errorf("newContentByType(%q) returned nil", typ)
		}
	}
	if v := newContentByType("Nonexistent"); v != nil {
		t.Error("expected nil for unknown type")
	}
}

func TestReshareContentFromNew(t *testing.T) {
	tests := []struct {
		name    string
		content any
		want    bool
		wantOK  bool
	}{
		// Old committee (rounds 1, 3)
		{"ecdsa.DGRound1", &ecdsaResharing.DGRound1Message{}, false, true},
		{"ecdsa.DGRound3Message1", &ecdsaResharing.DGRound3Message1{}, false, true},
		{"ecdsa.DGRound3Message2", &ecdsaResharing.DGRound3Message2{}, false, true},
		{"eddsa.DGRound1", &eddsaResharing.DGRound1Message{}, false, true},
		{"eddsa.DGRound3Message1", &eddsaResharing.DGRound3Message1{}, false, true},
		{"eddsa.DGRound3Message2", &eddsaResharing.DGRound3Message2{}, false, true},
		// New committee (rounds 2, 4)
		{"ecdsa.DGRound2Message1", &ecdsaResharing.DGRound2Message1{}, true, true},
		{"ecdsa.DGRound2Message2", &ecdsaResharing.DGRound2Message2{}, true, true},
		{"ecdsa.DGRound4Message1", &ecdsaResharing.DGRound4Message1{}, true, true},
		{"ecdsa.DGRound4Message2", &ecdsaResharing.DGRound4Message2{}, true, true},
		{"eddsa.DGRound2", &eddsaResharing.DGRound2Message{}, true, true},
		{"eddsa.DGRound4", &eddsaResharing.DGRound4Message{}, true, true},
		// Non-reshare types
		{"keygen", &ecdsaKeygen.KGRound1Message{}, false, false},
		{"signing", &ecdsaSigning.SignRound1Message1{}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := reshareContentFromNew(tt.content)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("fromNew = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidTSSContentRejectsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input any
	}{
		{"nil", nil},
		{"no ValidateBasic", struct{}{}},
		{"zero KGRound1", &ecdsaKeygen.KGRound1Message{}},
		{"zero SignRound1", &ecdsaSigning.SignRound1Message1{}},
		{"zero DGRound1", &ecdsaResharing.DGRound1Message{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validTSSContent(tt.input) {
				t.Fatal("validTSSContent accepted invalid content")
			}
		})
	}
}

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

// TestMalformedKGRound1FailsValidateBasic is the fast, deterministic core of the
// invariant. The wire parser (parseTSSWireMessage/unmarshalTSSContent) is a pure
// deserializer and accepts these bytes; the security guard lives at ingest
// (HandleMessage), which rejects any parsed content whose ValidateBasic() returns
// false. This confirms the fixtures are exactly that: structurally invalid
// content the ingest guard must drop. If a fixture ever starts passing
// ValidateBasic it no longer models the flaw.
func TestMalformedKGRound1FailsValidateBasic(t *testing.T) {
	from := tss.NewPartyID("attacker", "attacker", big.NewInt(1))

	for _, f := range malformedKGRound1Fixtures {
		t.Run(f.name, func(t *testing.T) {
			msg, err := parseTSSWireMessage(f.wire, from, true)
			if err != nil {
				t.Fatalf("parseTSSWireMessage is a pure deserializer and should "+
					"accept these bytes; got error: %v", err)
			}
			v, ok := msg.Content.(interface{ ValidateBasic() bool })
			if !ok {
				t.Fatalf("content %T has no ValidateBasic method", msg.Content)
			}
			if v.ValidateBasic() {
				t.Fatal("malformed KGRound1Message unexpectedly passed " +
					"ValidateBasic; the fixture no longer models the flaw")
			}
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
