// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	ecdsaKeygen "github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"
	ecdsaResharing "github.com/hemilabs/x/tss-lib/v3/ecdsa/resharing"
	ecdsaSigning "github.com/hemilabs/x/tss-lib/v3/ecdsa/signing"
	eddsaKeygen "github.com/hemilabs/x/tss-lib/v3/eddsa/keygen"
	eddsaResharing "github.com/hemilabs/x/tss-lib/v3/eddsa/resharing"
	eddsaSigning "github.com/hemilabs/x/tss-lib/v3/eddsa/signing"
	"github.com/hemilabs/x/tss-lib/v3/tss"
)

// tssWireEnvelope wraps a TSS message Content for wire transport.
// The library does not prescribe a wire format; this is continuum's
// choice — JSON with a type discriminator.
type tssWireEnvelope struct {
	Type    string          `json:"t"`
	Content json.RawMessage `json:"c"`
}

// marshalTSSContent serializes a tss.Message Content to wire bytes.
// The type discriminator includes the protocol prefix (e.g.,
// "ecdsa.keygen.KGRound1Message") to disambiguate identically-named
// types in different packages (ECDSA vs EdDSA keygen).
func marshalTSSContent(content interface{}) ([]byte, error) {
	if content == nil {
		return nil, fmt.Errorf("marshal: nil content")
	}
	t := reflect.TypeOf(content).Elem()
	// Extract "ecdsa/keygen" from "github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"
	pkg := t.PkgPath()
	if idx := strings.Index(pkg, "ecdsa/"); idx >= 0 {
		pkg = pkg[idx:]
	} else if idx := strings.Index(pkg, "eddsa/"); idx >= 0 {
		pkg = pkg[idx:]
	}
	typeName := strings.ReplaceAll(pkg, "/", ".") + "." + t.Name()
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", typeName, err)
	}
	return json.Marshal(tssWireEnvelope{Type: typeName, Content: contentBytes})
}

// unmarshalTSSContent deserializes wire bytes back to a typed Content.
func unmarshalTSSContent(data []byte) (interface{}, error) {
	var env tssWireEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	content := newContentByType(env.Type)
	if content == nil {
		return nil, fmt.Errorf("unknown message type: %s", env.Type)
	}
	if err := json.Unmarshal(env.Content, content); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", env.Type, err)
	}
	return content, nil
}

// newContentByType returns a zero-value pointer for the given type name.
func newContentByType(typeName string) interface{} {
	switch typeName {
	// ecdsa keygen
	case "ecdsa.keygen.KGRound1Message":
		return &ecdsaKeygen.KGRound1Message{}
	case "ecdsa.keygen.KGRound2Message1":
		return &ecdsaKeygen.KGRound2Message1{}
	case "ecdsa.keygen.KGRound2Message2":
		return &ecdsaKeygen.KGRound2Message2{}
	case "ecdsa.keygen.KGRound3Message":
		return &ecdsaKeygen.KGRound3Message{}
	// ecdsa signing
	case "ecdsa.signing.SignRound1Message1":
		return &ecdsaSigning.SignRound1Message1{}
	case "ecdsa.signing.SignRound1Message2":
		return &ecdsaSigning.SignRound1Message2{}
	case "ecdsa.signing.SignRound2Message":
		return &ecdsaSigning.SignRound2Message{}
	case "ecdsa.signing.SignRound3Message":
		return &ecdsaSigning.SignRound3Message{}
	case "ecdsa.signing.SignRound4Message":
		return &ecdsaSigning.SignRound4Message{}
	case "ecdsa.signing.SignRound5Message":
		return &ecdsaSigning.SignRound5Message{}
	case "ecdsa.signing.SignRound6Message":
		return &ecdsaSigning.SignRound6Message{}
	case "ecdsa.signing.SignRound7Message":
		return &ecdsaSigning.SignRound7Message{}
	case "ecdsa.signing.SignRound8Message":
		return &ecdsaSigning.SignRound8Message{}
	case "ecdsa.signing.SignRound9Message":
		return &ecdsaSigning.SignRound9Message{}
	// ecdsa resharing
	case "ecdsa.resharing.DGRound1Message":
		return &ecdsaResharing.DGRound1Message{}
	case "ecdsa.resharing.DGRound2Message1":
		return &ecdsaResharing.DGRound2Message1{}
	case "ecdsa.resharing.DGRound2Message2":
		return &ecdsaResharing.DGRound2Message2{}
	case "ecdsa.resharing.DGRound3Message1":
		return &ecdsaResharing.DGRound3Message1{}
	case "ecdsa.resharing.DGRound3Message2":
		return &ecdsaResharing.DGRound3Message2{}
	case "ecdsa.resharing.DGRound4Message1":
		return &ecdsaResharing.DGRound4Message1{}
	case "ecdsa.resharing.DGRound4Message2":
		return &ecdsaResharing.DGRound4Message2{}
	// eddsa keygen
	case "eddsa.keygen.KGRound1Message":
		return &eddsaKeygen.KGRound1Message{}
	case "eddsa.keygen.KGRound2Message1":
		return &eddsaKeygen.KGRound2Message1{}
	case "eddsa.keygen.KGRound2Message2":
		return &eddsaKeygen.KGRound2Message2{}
	// eddsa signing
	case "eddsa.signing.SignRound1Message":
		return &eddsaSigning.SignRound1Message{}
	case "eddsa.signing.SignRound2Message":
		return &eddsaSigning.SignRound2Message{}
	case "eddsa.signing.SignRound3Message":
		return &eddsaSigning.SignRound3Message{}
	// eddsa resharing
	case "eddsa.resharing.DGRound1Message":
		return &eddsaResharing.DGRound1Message{}
	case "eddsa.resharing.DGRound2Message":
		return &eddsaResharing.DGRound2Message{}
	case "eddsa.resharing.DGRound3Message1":
		return &eddsaResharing.DGRound3Message1{}
	case "eddsa.resharing.DGRound3Message2":
		return &eddsaResharing.DGRound3Message2{}
	case "eddsa.resharing.DGRound4Message":
		return &eddsaResharing.DGRound4Message{}
	default:
		return nil
	}
}

// parseTSSWireMessage reconstructs a *tss.Message from wire bytes.
func parseTSSWireMessage(wireData []byte, from *tss.PartyID, isBroadcast bool) (*tss.Message, error) {
	content, err := unmarshalTSSContent(wireData)
	if err != nil {
		return nil, err
	}
	return &tss.Message{
		From:        from,
		IsBroadcast: isBroadcast,
		Content:     content,
	}, nil
}
