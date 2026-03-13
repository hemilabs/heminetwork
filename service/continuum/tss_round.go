// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"fmt"

	"github.com/hemilabs/x/tss-lib/v2/tss"
)

// msgBuf accumulates inbound messages across rounds.  Messages that
// arrive early (from a faster peer in a later round) are kept in
// the buffer until the local node reaches that round.
type msgBuf struct {
	ch  <-chan tss.ParsedMessage
	buf []tss.ParsedMessage
}

func newMsgBuf(ch <-chan tss.ParsedMessage) *msgBuf {
	return &msgBuf{ch: ch}
}

// collect reads n messages that pass accept.  Messages that don't
// match are kept in the buffer for later rounds.  accept returns
// (partyIndex, true) for wanted messages.
func (b *msgBuf) collect(
	ctx context.Context,
	n int,
	nParties int,
	accept func(tss.ParsedMessage) (slot int, ok bool),
) ([]tss.ParsedMessage, error) {
	out := make([]tss.ParsedMessage, nParties)
	got := 0

	// Drain buffer first.
	var keep []tss.ParsedMessage
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
	acceptA func(tss.ParsedMessage) (slot int, ok bool),
	acceptB func(tss.ParsedMessage) (slot int, ok bool),
) (a, b2 []tss.ParsedMessage, err error) {
	a = make([]tss.ParsedMessage, nParties)
	b2 = make([]tss.ParsedMessage, nParties)
	gotA, gotB := 0, 0

	// Drain buffer first.
	var keep []tss.ParsedMessage
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
// the transport.
func (t *tssImpl) sendRound(c *ceremony, ceremonyID CeremonyID, msgs []tss.Message) error {
	for _, msg := range msgs {
		wireData, _, err := msg.WireBytes()
		if err != nil {
			return fmt.Errorf("wire bytes: %w", err)
		}
		if msg.GetTo() == nil {
			data := append([]byte{0x01}, wireData...)
			for _, pid := range c.pids {
				if pid.Id == t.self.String() {
					continue
				}
				_ = t.transport.Send(c.pidToID[pid.Id], ceremonyID, data)
			}
		} else {
			data := append([]byte{0x00}, wireData...)
			for _, dest := range msg.GetTo() {
				_ = t.transport.Send(c.pidToID[dest.Id], ceremonyID, data)
			}
		}
	}
	return nil
}
