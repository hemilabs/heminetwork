// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// Regression tests for the round send helpers (tss_round.go).
//
// Two invariants are asserted:
//
//   - sendRound / sendReshareRound must RETURN transport delivery
//     failures rather than swallow them. Every keygen/sign/reshare round
//     collects the other required parties' messages (collect waits for
//     n-1 / every committee slot), so a silently dropped send stalls the
//     ceremony until the long ceremony timeout. Returning the error lets
//     the caller fail promptly.
//
//   - A reshare broadcast must reach only the committees its flags name.
//     An old-only (IsToOldCommittee) broadcast must never be disclosed to
//     new-only committee members, and vice versa.

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/hemilabs/x/tss/v3/crypto"
	resharing "github.com/hemilabs/x/tss/v3/ecdsa/resharing"
	"github.com/hemilabs/x/tss/v3/tss"
)

// recordingTransport records every Send target and optionally returns an
// error for chosen targets, modelling a peer with no deliverable path.
type recordingTransport struct {
	mu      sync.Mutex
	sent    []Identity
	failFor map[Identity]bool
}

func (r *recordingTransport) Send(to Identity, _ CeremonyID, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, to)
	if r.failFor[to] {
		return errors.New("no route to destination")
	}
	return nil
}

func (r *recordingTransport) sentSet() map[Identity]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := make(map[Identity]bool, len(r.sent))
	for _, id := range r.sent {
		s[id] = true
	}
	return s
}

// newTestIdentities returns n fresh identities.
func newTestIdentities(t *testing.T, n int) []Identity {
	t.Helper()
	ids := make([]Identity, 0, n)
	for range n {
		s, err := NewSecret()
		if err != nil {
			t.Fatalf("new secret: %v", err)
		}
		ids = append(ids, s.Identity)
	}
	return ids
}

// testPids builds the sorted PID set and pid.Id->Identity map the same way
// buildPartyContext does, so the ceremony fields match production shape.
func testPids(ids []Identity) (tss.SortedPartyIDs, map[string]Identity) {
	pids := make([]*tss.PartyID, len(ids))
	pidToID := make(map[string]Identity)
	for i, id := range ids {
		s := id.String()
		pids[i] = tss.NewPartyID(s, s, new(big.Int).SetBytes(id[:]))
		pidToID[s] = id
	}
	return tss.SortPartyIDs(pids), pidToID
}

// validReshareContent returns a structurally valid DGRound1Message so the
// send helpers marshal a real payload.
func validReshareContent() *resharing.DGRound1Message {
	return &resharing.DGRound1Message{
		ECDSAPub:    crypto.ScalarBaseMult(tss.S256(), big.NewInt(42)),
		VCommitment: big.NewInt(88),
		SSID:        []byte("tss-round-test"),
	}
}

// TestSendRoundReturnsDeliveryFailure asserts sendRound attempts every
// recipient and returns a non-nil error when a broadcast send fails, so
// the caller aborts instead of hanging on an unsatisfiable collector.
func TestSendRoundReturnsDeliveryFailure(t *testing.T) {
	ids := newTestIdentities(t, 3)
	self, p1, p2 := ids[0], ids[1], ids[2]

	pids, pidToID := testPids(ids)
	c := &ceremony{pids: pids, pidToID: pidToID}

	tr := &recordingTransport{failFor: map[Identity]bool{p2: true}}
	ti := &tssImpl{self: self, transport: tr}

	msg := &tss.Message{To: nil, Content: validReshareContent()} // broadcast
	err := ti.sendRound(c, NewCeremonyID(), []*tss.Message{msg})
	if err == nil {
		t.Fatal("sendRound swallowed a transport failure; it must return it " +
			"so the ceremony fails promptly instead of stalling until timeout")
	}

	got := tr.sentSet()
	if !got[p1] || !got[p2] {
		t.Fatalf("sendRound must attempt every recipient best-effort; sent=%v", got)
	}
	if got[self] {
		t.Fatal("sendRound must not send to self")
	}
}

// TestSendReshareRoundReturnsDeliveryFailure asserts the same contract for
// the p2p reshare path: all required destinations attempted, failures
// returned.
func TestSendReshareRoundReturnsDeliveryFailure(t *testing.T) {
	old := newTestIdentities(t, 2)
	newC := newTestIdentities(t, 2)
	self := newC[0]

	oldPids, oldMap := testPids(old)
	newPids, newMap := testPids(newC)
	pidToID := mergeMaps(oldMap, newMap)
	c := &ceremony{oldPids: oldPids, newPids: newPids, pidToID: pidToID}

	// P2P message addressed to both old members; one has no path.
	tr := &recordingTransport{failFor: map[Identity]bool{old[1]: true}}
	ti := &tssImpl{self: self, transport: tr}

	msg := &tss.Message{
		To:      oldPids, // explicit recipients -> p2p branch
		Content: validReshareContent(),
	}
	err := ti.sendReshareRound(c, NewCeremonyID(), []*tss.Message{msg}, true)
	if err == nil {
		t.Fatal("sendReshareRound swallowed a transport failure; it must return it")
	}
	got := tr.sentSet()
	if !got[old[0]] || !got[old[1]] {
		t.Fatalf("sendReshareRound must attempt every required recipient; sent=%v", got)
	}
}

// TestSendReshareBroadcastHonoursCommitteeFlags asserts a To==nil reshare
// broadcast reaches only the committee its flags name. An old-only
// (IsToOldCommittee) broadcast must not be disclosed to new-only members.
//
// The reshare round functions currently always populate an explicit To, so
// this To==nil broadcast path is not exercised by a live ceremony; the test
// pins the confidentiality contract so the branch cannot silently regress
// to sending old-only traffic to the new committee.
func TestSendReshareBroadcastHonoursCommitteeFlags(t *testing.T) {
	old := newTestIdentities(t, 2)
	newC := newTestIdentities(t, 2) // disjoint from old
	self := newC[0]                 // sender sits on the new committee

	oldPids, oldMap := testPids(old)
	newPids, newMap := testPids(newC)
	pidToID := mergeMaps(oldMap, newMap)
	c := &ceremony{oldPids: oldPids, newPids: newPids, pidToID: pidToID}

	tr := &recordingTransport{}
	ti := &tssImpl{self: self, transport: tr}

	// Old-only broadcast: IsToOldCommittee, no explicit To.
	msg := &tss.Message{
		To:               nil,
		IsBroadcast:      true,
		IsToOldCommittee: true,
		Content:          validReshareContent(),
	}
	if err := ti.sendReshareRound(c, NewCeremonyID(), []*tss.Message{msg}, true); err != nil {
		t.Fatalf("sendReshareRound: %v", err)
	}

	got := tr.sentSet()
	for _, id := range old {
		if !got[id] {
			t.Fatalf("old-only broadcast did not reach old member %v", id)
		}
	}
	for _, id := range newC {
		if got[id] {
			t.Fatalf("old-only broadcast leaked to new-committee member %v; "+
				"IsToOldCommittee must restrict the audience to the old committee", id)
		}
	}
}

func mergeMaps(a, b map[string]Identity) map[string]Identity {
	out := make(map[string]Identity, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
