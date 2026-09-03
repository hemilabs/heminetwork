// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

// A TSSMessage can legitimately arrive before the request that
// registers its ceremony: the coordinator starts producing round
// messages the moment it dispatches, while the KeygenRequest is still
// being routed to the rest of the committee.  Such a message has to be
// held and retried rather than dropped.
//
// Holding it per message does not work.  A retry goroutine per
// arriving message, each pinning its payload for the length of the
// backoff, is an amplifier: the payload is attacker-sized (up to
// TransportMaxSize) and the ceremony ID is attacker-chosen, so an
// authenticated peer sending at its full rate allowance with a fresh
// ceremony ID each time buys hundreds of goroutines and hundreds of
// megabytes for the cost of signing.
//
// pendingTSS replaces that with one buffer, drained on a signal.  The
// TSS engine calls ceremonyRegistered the moment a ceremony becomes
// known to HandleMessage, which is exactly when the buffered messages
// for it can be delivered — no timer, no wasted wakeups, and no tick
// interval added to the latency of a raced message.  Memory is capped
// globally and per ceremony, entries expire on age, and a message
// already queued for a ceremony is not queued twice.
const (
	// pendingTSSMaxAge is how long a message for an unregistered
	// ceremony is retried before it is discarded.  Matches the old
	// backoff horizon: past this the request is not merely in
	// flight, it is not coming.
	pendingTSSMaxAge = 5 * time.Second

	// pendingTSSMaxBytes caps the payload bytes buffered across all
	// ceremonies.
	pendingTSSMaxBytes = 8 << 20 // 8 MiB

	// pendingTSSMaxPerCeremony caps buffered messages for a single
	// ceremony.  A round produces at most one message per committee
	// member, and the committee is bounded by the protocol.
	pendingTSSMaxPerCeremony = 128
)

// pendingTSSMsg is one buffered message awaiting its ceremony.
type pendingTSSMsg struct {
	from     Identity
	data     []byte
	digest   [sha256.Size]byte
	received time.Time
}

// pendingTSS buffers TSSMessages whose ceremony is not yet registered.
// Safe for concurrent use.
type pendingTSS struct {
	mtx     sync.Mutex
	byID    map[CeremonyID][]*pendingTSSMsg
	bytes   int
	expired int // messages dropped past pendingTSSMaxAge, since last read
}

func newPendingTSS() *pendingTSS {
	return &pendingTSS{byID: make(map[CeremonyID][]*pendingTSSMsg)}
}

// add buffers a message for cid.  It reports false when the message
// was dropped: the global byte cap or the per-ceremony message cap is
// reached, or an identical message from the same sender is already
// queued.  data is retained, so the caller must not reuse it.
func (p *pendingTSS) add(cid CeremonyID, from Identity, data []byte) bool {
	return p.addMsg(cid, &pendingTSSMsg{
		from:     from,
		data:     data,
		digest:   sha256.Sum256(data),
		received: time.Now(),
	})
}

// addMsg buffers m, keeping its received stamp so a requeue does not
// refresh the age that expires it.
func (p *pendingTSS) addMsg(cid CeremonyID, m *pendingTSSMsg) bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	// No timer sweeps this buffer, so reclaim here.  A ceremony that
	// never registers must not hold its bytes against everyone else.
	p.expire()

	if p.bytes+len(m.data) > pendingTSSMaxBytes {
		return false
	}
	q := p.byID[cid]
	if len(q) >= pendingTSSMaxPerCeremony {
		return false
	}
	for _, e := range q {
		if e.from == m.from && e.digest == m.digest {
			return false
		}
	}

	p.byID[cid] = append(q, m)
	p.bytes += len(m.data)
	return true
}

// take removes and returns the buffered messages for one ceremony,
// dropping any that are past pendingTSSMaxAge.
func (p *pendingTSS) take(cid CeremonyID) []*pendingTSSMsg {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	q := p.byID[cid]
	if q == nil {
		return nil
	}
	delete(p.byID, cid)

	cutoff := time.Now().Add(-pendingTSSMaxAge)
	live := make([]*pendingTSSMsg, 0, len(q))
	for _, m := range q {
		p.bytes -= len(m.data)
		if m.received.Before(cutoff) {
			p.expired++
			continue
		}
		live = append(live, m)
	}
	return live
}

// expire drops every buffered message past pendingTSSMaxAge and
// reports how many went.  Called from add so a ceremony that never
// registers cannot hold its bytes forever; there is no timer to do it.
func (p *pendingTSS) expire() int {
	cutoff := time.Now().Add(-pendingTSSMaxAge)
	var n int
	for cid, q := range p.byID {
		keep := q[:0]
		for _, m := range q {
			if m.received.Before(cutoff) {
				p.bytes -= len(m.data)
				n++
				continue
			}
			keep = append(keep, m)
		}
		if len(keep) == 0 {
			delete(p.byID, cid)
			continue
		}
		p.byID[cid] = keep
	}
	p.expired += n
	return n
}

// takeExpired returns and resets the running expiry count.
func (p *pendingTSS) takeExpired() int {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	n := p.expired
	p.expired = 0
	return n
}

// len reports the number of buffered messages.  Test and metrics
// helper.
func (p *pendingTSS) len() int {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	var n int
	for _, q := range p.byID {
		n += len(q)
	}
	return n
}

// drainPendingTSS delivers the messages buffered for cid.  Called from
// the TSS engine's ceremonyRegistered hook, on the goroutine running
// the ceremony, once the ceremony is known to HandleMessage.
func (s *Server) drainPendingTSS(ctx context.Context, cid CeremonyID) {
	log.Tracef("drainPendingTSS %v", cid)
	defer log.Tracef("drainPendingTSS %v exit", cid)

	if n := s.pendingTSS.takeExpired(); n > 0 {
		s.tssPendingExpired.Add(int64(n))
		log.Debugf("pendingTSS: discarded %d message(s) past max age", n)
	}

	for _, m := range s.pendingTSS.take(cid) {
		if err := s.tss.HandleMessage(ctx, m.from, cid, m.data); err != nil {
			log.Errorf("tss msg from %s ceremony %s: %v", m.from, cid, err)
		}
	}
}
