// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Integration coverage complementing the unit anchor in
// gossip_e2e_key_test.go. It drives the REAL gossip dispatch handler
// (handlePeerListResponse) with a real *PeerListResponse -- proving the defect
// through the actual handler (version gate, address validation, addPeer), not
// just addPeer in isolation. No network; fully deterministic.

import (
	"bytes"
	"testing"
)

// gossipPeerList feeds records to the target through the production
// handlePeerListResponse dispatch handler, exactly as a received
// PeerListResponse from `from` would be dispatched. dc.t is unused by this
// handler (it neither reads nor writes the transport), so nil is safe.
func gossipPeerList(t *testing.T, s *Server, from Identity, recs ...PeerRecord) {
	t.Helper()
	ctx := t.Context()
	dc := &dispatchCtx{
		ctx:        ctx,
		sessionCtx: ctx,
		s:          s,
		id:         &from,
	}
	handlePeerListResponse(dc, &PeerListResponse{Peers: recs})
}

func TestGossipHandlerCannotHijackPeerE2EKey(t *testing.T) {
	const peerAddr = "10.0.0.1:9000"

	tests := []struct {
		name           string
		priorHandshake bool
	}{
		{name: "overwrite-handshake-key", priorHandshake: true},
		{name: "first-binding", priorHandshake: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := newPeerKeyServer(t)
			victim, victimPub, victimPriv := naclIdentity(t)
			attacker, attackerPub, attackerPriv := naclIdentity(t)
			if bytes.Equal(victimPub, attackerPub) {
				t.Fatal("victim and attacker derived the same X25519 key")
			}

			var wantRetained []byte
			if tt.priorHandshake {
				installPeerFromHandshake(target, peerRec(victim, victimPub, peerAddr))
				if stored, held := storedPeerNaClPub(t, target, victim); !held || !bytes.Equal(stored, victimPub) {
					t.Fatal("handshake bootstrap: victim's real key was not installed")
				}
				wantRetained = victimPub
			}

			// Attacker gossips the poison through the REAL dispatch handler.
			gossipPeerList(t, target, attacker,
				peerRec(victim, attackerPub, peerAddr))

			assertPeerKeyUnhijacked(t, target, victim, attackerPub, wantRetained, victimPriv, attackerPriv)
		})
	}
}
