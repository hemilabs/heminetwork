// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"reflect"
	"testing"
)

// TestDispatchMapCompleteness verifies that every incoming payload type
// that handle() could receive has an entry in payloadDispatch.  Types
// that are never received inside handle() (Hello*, outbound responses)
// are excluded.
func TestDispatchMapCompleteness(t *testing.T) {
	// Types that handle() must dispatch.  This is the authoritative
	// list — if a new wire type is added to pt2str, the developer
	// must consciously decide whether it belongs here.
	required := []any{
		(*PingRequest)(nil),
		(*PingResponse)(nil),
		(*PeerNotify)(nil),
		(*PeerListRequest)(nil),
		(*PeerListResponse)(nil),
		(*KeygenRequest)(nil),
		(*SignRequest)(nil),
		(*ReshareRequest)(nil),
		(*TSSMessage)(nil),
		(*EncryptedPayload)(nil),
		(*CeremonyResult)(nil),
		(*PeerListAdminRequest)(nil),
		(*CeremonyStatusRequest)(nil),
		(*CeremonyListRequest)(nil),
		(*BusyResponse)(nil),
	}

	for _, p := range required {
		rt := reflect.TypeOf(p)
		if _, ok := payloadDispatch[rt]; !ok {
			t.Errorf("payloadDispatch missing entry for %v", rt)
		}
	}
}

// TestDispatchMapNoExtras verifies that payloadDispatch contains
// only the expected entries — no stale handlers for removed types.
func TestDispatchMapNoExtras(t *testing.T) {
	expected := map[reflect.Type]bool{
		reflect.TypeOf((*PingRequest)(nil)):           true,
		reflect.TypeOf((*PingResponse)(nil)):          true,
		reflect.TypeOf((*PeerNotify)(nil)):            true,
		reflect.TypeOf((*PeerListRequest)(nil)):       true,
		reflect.TypeOf((*PeerListResponse)(nil)):      true,
		reflect.TypeOf((*KeygenRequest)(nil)):         true,
		reflect.TypeOf((*SignRequest)(nil)):           true,
		reflect.TypeOf((*ReshareRequest)(nil)):        true,
		reflect.TypeOf((*TSSMessage)(nil)):            true,
		reflect.TypeOf((*EncryptedPayload)(nil)):      true,
		reflect.TypeOf((*CeremonyResult)(nil)):        true,
		reflect.TypeOf((*PeerListAdminRequest)(nil)):  true,
		reflect.TypeOf((*CeremonyStatusRequest)(nil)): true,
		reflect.TypeOf((*CeremonyListRequest)(nil)):   true,
		reflect.TypeOf((*BusyResponse)(nil)):          true,
	}
	for rt := range payloadDispatch {
		if !expected[rt] {
			t.Errorf("payloadDispatch has unexpected entry: %v", rt)
		}
	}
}

// TestDispatchUnknownType verifies that dispatchPayload returns false
// (continue) for a type not in the map.
func TestDispatchUnknownType(t *testing.T) {
	dc := &dispatchCtx{}
	// HelloRequest is a wire type but not dispatched (handled in KX).
	exit := dispatchPayload(dc, &HelloRequest{})
	if exit {
		t.Fatal("dispatchPayload returned true for unknown type")
	}
}
