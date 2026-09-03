// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/sha256"
	"errors"
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
// pendingTSS replaces that with one buffer and one drain goroutine.
// Memory is capped globally and per ceremony, entries expire on age,
// and a message already queued for a ceremony is not queued twice.
const (
	// pendingTSSMaxAge is how long a message for an unregistered
	// ceremony is retried before it is discarded.  Matches the old
	// backoff horizon: past this the request is not merely in
	// flight, it is not coming.
	pendingTSSMaxAge = 5 * time.Second

	// pendingTSSInterval is the drain tick.  Short enough that the
	// common case — the request lands milliseconds behind the first
	// round message — costs no visible latency.
	pendingTSSInterval = 50 * time.Millisecond

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
	mtx   sync.Mutex
	byID  map[CeremonyID][]*pendingTSSMsg
	bytes int
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

// take removes and returns every buffered message, along with the
// count of entries discarded for exceeding pendingTSSMaxAge.  The
// caller redelivers what it gets back and re-adds anything whose
// ceremony is still unknown.
func (p *pendingTSS) take() (map[CeremonyID][]*pendingTSSMsg, int) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if len(p.byID) == 0 {
		return nil, 0
	}

	cutoff := time.Now().Add(-pendingTSSMaxAge)
	live := make(map[CeremonyID][]*pendingTSSMsg, len(p.byID))
	var expired int
	for cid, q := range p.byID {
		var keep []*pendingTSSMsg
		for _, m := range q {
			if m.received.Before(cutoff) {
				expired++
				continue
			}
			keep = append(keep, m)
		}
		if len(keep) != 0 {
			live[cid] = keep
		}
	}

	p.byID = make(map[CeremonyID][]*pendingTSSMsg)
	p.bytes = 0
	return live, expired
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

// pendingTSSLoop redelivers buffered messages until their ceremony
// exists or they age out.  One goroutine for the whole server,
// started by Run.
func (s *Server) pendingTSSLoop(ctx context.Context) {
	log.Tracef("pendingTSSLoop")
	defer log.Tracef("pendingTSSLoop exit")
	defer s.wg.Done()

	ticker := time.NewTicker(pendingTSSInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.drainPendingTSS(ctx)
	}
}

// drainPendingTSS is the single-shot pass used by pendingTSSLoop.
// Split out so tests can run it without waiting for the ticker.
func (s *Server) drainPendingTSS(ctx context.Context) {
	live, expired := s.pendingTSS.take()
	if expired > 0 {
		s.tssPendingExpired.Add(int64(expired))
		log.Debugf("pendingTSS: discarded %d message(s) past max age",
			expired)
	}

	for cid, q := range live {
		for _, m := range q {
			err := s.tss.HandleMessage(ctx, m.from, cid, m.data)
			switch {
			case err == nil:
			case errors.Is(err, ErrUnknownCeremony):
				// Still not registered; keep waiting.  The
				// original received stamp rides along, so the
				// requeue does not extend its life.
				if !s.pendingTSS.addMsg(cid, m) {
					s.tssPendingDrops.Add(1)
				}
			default:
				log.Errorf("tss msg from %s ceremony %s: %v",
					m.from, cid, err)
			}
		}
	}
}
