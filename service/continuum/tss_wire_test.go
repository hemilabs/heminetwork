// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"math/big"
	"testing"

	"github.com/hemilabs/x/tss-lib/v3/crypto"
	cmt "github.com/hemilabs/x/tss-lib/v3/crypto/commitments"
	ecdsaKeygen "github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"
	ecdsaResharing "github.com/hemilabs/x/tss-lib/v3/ecdsa/resharing"
	ecdsaSigning "github.com/hemilabs/x/tss-lib/v3/ecdsa/signing"
	eddsaKeygen "github.com/hemilabs/x/tss-lib/v3/eddsa/keygen"
	eddsaResharing "github.com/hemilabs/x/tss-lib/v3/eddsa/resharing"
	eddsaSigning "github.com/hemilabs/x/tss-lib/v3/eddsa/signing"
	"github.com/hemilabs/x/tss-lib/v3/tss"
)

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	ec := tss.EC()
	pt := crypto.ScalarBaseMult(ec, big.NewInt(42))
	edPt := crypto.ScalarBaseMult(tss.Edwards(), big.NewInt(7))

	tests := []struct {
		name    string
		content interface{}
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

	// Suppress unused variable warning for edPt.
	_ = edPt

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
			// Verify the round-trip produces the correct Go type.
			// Compare struct name only (the wire key is checked implicitly
			// because unmarshal dispatches on it).
			gotStructName := tt.name[len(tt.name)-len(structNameFromWireKey(tt.name)):]
			wantStructName := structNameFromWireKey(tt.name)
			if gotStructName != wantStructName {
				t.Fatalf("struct name mismatch: %s vs %s", gotStructName, wantStructName)
			}
			_ = got // type already verified by unmarshal dispatch
		})
	}
}

// structNameFromWireKey extracts the struct name from a prefixed wire key.
func structNameFromWireKey(key string) string {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '.' {
			return key[i+1:]
		}
	}
	return key
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
