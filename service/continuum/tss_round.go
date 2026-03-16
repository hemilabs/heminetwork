// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"fmt"

	"github.com/hemilabs/x/tss-lib/v3/tss"
)

// msgBuf accumulates inbound messages across rounds.  Messages that
// arrive early (from a faster peer in a later round) are kept in
// the buffer until the local node reaches that round.
type msgBuf struct {
	ch  <-chan *tss.Message
	buf []*tss.Message
}

func newMsgBuf(ch <-chan *tss.Message) *msgBuf {
	return &msgBuf{ch: ch}
}

// collect reads n messages that pass accept.  Messages that don't
// match are kept in the buffer for later rounds.  accept returns
// (partyIndex, true) for wanted messages.
func (b *msgBuf) collect(
	ctx context.Context,
	n int,
	nParties int,
	accept func(*tss.Message) (slot int, ok bool),
) ([]*tss.Message, error) {
	out := make([]*tss.Message, nParties)
	got := 0

	// Drain buffer first.
	keep := make([]*tss.Message, 0, len(b.buf))
	for _, m := range b.buf {
		if got < n {
			if slot, ok := accept(m); ok && out[slot] == nil {
				out[slot] = m
				got++
				continue
			}
		}
		keep = append(keep, m)
	}
	b.buf = keep

	// Read from channel until satisfied.
	for got < n {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg := <-b.ch:
			if slot, ok := accept(msg); ok && out[slot] == nil {
				out[slot] = msg
				got++
			} else {
				b.buf = append(b.buf, msg)
			}
		}
	}
	return out, nil
}

// collectDual reads two message types simultaneously.
func (b *msgBuf) collectDual(
	ctx context.Context,
	n int,
	nParties int,
	acceptA func(*tss.Message) (slot int, ok bool),
	acceptB func(*tss.Message) (slot int, ok bool),
) (a, b2 []*tss.Message, err error) {
	a = make([]*tss.Message, nParties)
	b2 = make([]*tss.Message, nParties)
	gotA, gotB := 0, 0

	// Drain buffer first.
	keep := make([]*tss.Message, 0, len(b.buf))
	for _, m := range b.buf {
		matched := false
		if gotA < n {
			if slot, ok := acceptA(m); ok && a[slot] == nil {
				a[slot] = m
				gotA++
				matched = true
			}
		}
		if !matched && gotB < n {
			if slot, ok := acceptB(m); ok && b2[slot] == nil {
				b2[slot] = m
				gotB++
				matched = true
			}
		}
		if !matched {
			keep = append(keep, m)
		}
	}
	b.buf = keep

	for gotA < n || gotB < n {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case msg := <-b.ch:
			matched := false
			if gotA < n {
				if slot, ok := acceptA(msg); ok && a[slot] == nil {
					a[slot] = msg
					gotA++
					matched = true
				}
			}
			if !matched && gotB < n {
				if slot, ok := acceptB(msg); ok && b2[slot] == nil {
					b2[slot] = msg
					gotB++
					matched = true
				}
			}
			if !matched {
				b.buf = append(b.buf, msg)
			}
		}
	}
	return a, b2, nil
}

// sendRound serializes outbound round messages and sends them via
// the transport.  Send errors are logged but not fatal — TSS is
// threshold-based, so the ceremony succeeds as long as t+1 peers
// receive the message.  A missing message causes a collect timeout
// on the receiving end, not silent corruption.
func (t *tssImpl) sendRound(c *ceremony, ceremonyID CeremonyID, msgs []*tss.Message) error {
	for _, msg := range msgs {
		wireData, err := marshalTSSContent(msg.Content)
		if err != nil {
			return fmt.Errorf("marshal content: %w", err)
		}
		if msg.To == nil {
			data := append([]byte{0x01}, wireData...)
			for _, pid := range c.pids {
				if pid.Id == t.self.String() {
					continue
				}
				if err := t.transport.Send(c.pidToID[pid.Id], ceremonyID, data); err != nil {
					log.Debugf("send broadcast %x to %s: %v", ceremonyID, pid.Id, err)
				}
			}
		} else {
			data := append([]byte{0x00}, wireData...)
			for _, dest := range msg.To {
				if err := t.transport.Send(c.pidToID[dest.Id], ceremonyID, data); err != nil {
					log.Debugf("send p2p %x to %s: %v", ceremonyID, dest.Id, err)
				}
			}
		}
	}
	return nil
}

// sendReshareRound serializes outbound reshare round messages with
// committee target flags encoded in the wire format.  Send errors
// are logged but not fatal — TSS is threshold-based, so the ceremony
// succeeds as long as t+1 peers receive the message.
//
// Wire format: [broadcast:1][committee_flags:1][wireBytes]
//
//	bit 0: to old committee
//	bit 1: to new committee
//	bit 2: from new committee (sender key is XORed)
func (t *tssImpl) sendReshareRound(c *ceremony, ceremonyID CeremonyID, msgs []*tss.Message, fromNew bool) error {
	for _, msg := range msgs {
		wireData, err := marshalTSSContent(msg.Content)
		if err != nil {
			return fmt.Errorf("marshal content: %w", err)
		}

		// Build committee flags.
		var cflags byte
		if msg.IsToOldCommittee {
			cflags |= 0x01
		} else if msg.IsToOldAndNewCommittees {
			cflags |= 0x01 | 0x02
		} else {
			// Default: to new committee.
			cflags |= 0x02
		}
		if fromNew {
			cflags |= 0x04
		}

		var bcast byte
		if msg.IsBroadcast {
			bcast = 0x01
		}

		data := make([]byte, 2+len(wireData))
		data[0] = bcast
		data[1] = cflags
		copy(data[2:], wireData)

		if msg.To == nil {
			// Broadcast: send to all unique peers across both
			// committees, skipping self.
			sent := make(map[Identity]bool)
			for _, pid := range c.oldPids {
				id := c.pidToID[pid.Id]
				if sent[id] || id == t.self {
					continue
				}
				sent[id] = true
				if err := t.transport.Send(id, ceremonyID, data); err != nil {
					log.Debugf("send reshare broadcast %x to %s: %v", ceremonyID, id, err)
				}
			}
			for _, pid := range c.newPids {
				id := c.pidToID[pid.Id]
				if sent[id] || id == t.self {
					continue
				}
				sent[id] = true
				if err := t.transport.Send(id, ceremonyID, data); err != nil {
					log.Debugf("send reshare broadcast %x to %s: %v", ceremonyID, id, err)
				}
			}
		} else {
			for _, dest := range msg.To {
				id := c.pidToID[dest.Id]
				if id == t.self {
					continue
				}
				if err := t.transport.Send(id, ceremonyID, data); err != nil {
					log.Debugf("send reshare p2p %x to %s: %v", ceremonyID, id, err)
				}
			}
		}
	}
	return nil
}
