// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"testing"
	"time"
)

// TestPendingTSSKeyExchangeWindow guards the coupling between the
// pending-message retention horizon and the pre-registration key
// exchange.  A committee member that finishes ensureCommitteeKeys first
// sends round 1 while a slower node is still inside its own key-exchange
// window (bounded by naclXchgEnsureTimeout).  That raced message must
// survive in the buffer until the slow node registers the ceremony;
// there is no round-message retransmission, so an early drop stalls the
// ceremony until its far longer overall timeout.
func TestPendingTSSKeyExchangeWindow(t *testing.T) {
	// The retention horizon must cover the whole key-exchange window,
	// otherwise a legitimately raced round-1 message ages out before
	// registration.  This assertion fails if either constant regresses.
	if pendingTSSMaxAge < naclXchgEnsureTimeout {
		t.Fatalf("pendingTSSMaxAge (%v) < naclXchgEnsureTimeout (%v): "+
			"raced round-1 messages can age out before the ceremony "+
			"registers", pendingTSSMaxAge, naclXchgEnsureTimeout)
	}

	t.Run("delivered within key-exchange window", func(t *testing.T) {
		p := newPendingTSS()
		cid := NewCeremonyID()
		var from Identity
		if !p.add(cid, from, []byte("round1")) {
			t.Fatal("add refused")
		}

		// Age the message to the far edge of the key-exchange window:
		// older than the historical 5s horizon (which would have
		// dropped it) but still inside naclXchgEnsureTimeout, hence
		// inside pendingTSSMaxAge.
		age := naclXchgEnsureTimeout
		p.mtx.Lock()
		p.byID[cid][0].received = time.Now().Add(-age)
		p.mtx.Unlock()

		live := p.take(cid)
		if len(live) != 1 {
			t.Fatalf("live = %d, want 1: message aged %v was dropped "+
				"despite being within the key-exchange window", len(live), age)
		}
		if n := p.takeExpired(); n != 0 {
			t.Fatalf("expired = %d, want 0", n)
		}
	})

	t.Run("expired past max age", func(t *testing.T) {
		p := newPendingTSS()
		cid := NewCeremonyID()
		var from Identity
		if !p.add(cid, from, []byte("stale")) {
			t.Fatal("add refused")
		}

		p.mtx.Lock()
		p.byID[cid][0].received = time.Now().Add(-(pendingTSSMaxAge + time.Second))
		p.mtx.Unlock()

		live := p.take(cid)
		if len(live) != 0 {
			t.Fatalf("live = %d, want 0: message past pendingTSSMaxAge "+
				"was delivered", len(live))
		}
		if n := p.takeExpired(); n != 1 {
			t.Fatalf("expired = %d, want 1", n)
		}
	})
}
