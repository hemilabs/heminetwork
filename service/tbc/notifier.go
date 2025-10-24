// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type Notification struct {
	Type      string
	ID        string
	Timestamp time.Time
	Error     error
}

func (n Notification) Is(target Notification) bool {
	return n.Type == target.Type
}

func (n Notification) String() string {
	return fmt.Sprintf("[%v] %s %s", n.Timestamp, n.Type, n.ID)
}

func NotificationBlock(hash chainhash.Hash) Notification {
	return Notification{
		Type:      "block inserted",
		ID:        hash.String(),
		Timestamp: time.Now(),
	}
}

func NotificationBlockheader(hash chainhash.Hash) Notification {
	return Notification{
		Type:      "blockheader inserted",
		ID:        hash.String(),
		Timestamp: time.Now(),
	}
}

type Notifier struct {
	mtx sync.Mutex

	listeners map[string]*Listener

	// If true, the notifier will block on new messages until the queue for
	// each listener's message channel is unblocked (i.e., read from).
	// This should only be TRUE for test purposes.
	blocking bool
}

type Listener struct {
	id string
	ch chan Notification

	listening atomic.Bool

	ctx      context.Context
	callback func()
}

func (l *Listener) Unsubscribe() {
	l.callback()
}

// Listen blocks until either a message is received by the listener, or
// the passed context expires. Calling Listen from multiple goroutines
// is not safe and will result in a panic.
func (l *Listener) Listen(ctx context.Context) (Notification, error) {
	if !l.listening.CompareAndSwap(false, true) {
		panic("multiple goroutines listening simultaneously")
	}
	defer l.listening.Store(false)

	select {
	case <-ctx.Done():
		return Notification{}, ctx.Err()
	case msg := <-l.ch:
		return msg, nil
	}
}

func NewNotifier(blocking bool) *Notifier {
	n := Notifier{
		listeners: make(map[string]*Listener),
		blocking:  blocking,
	}
	return &n
}

func (n *Notifier) Subscribe(pctx context.Context, capacity uint64) (*Listener, error) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	var nid [16]byte
	for {
		if _, err := io.ReadFull(rand.Reader, nid[:]); err != nil {
			return nil, err
		}
		if _, ok := n.listeners[string(nid[:])]; !ok {
			lctx, cancel := context.WithCancel(pctx)
			l := Listener{
				ch:  make(chan Notification, capacity),
				id:  string(nid[:]),
				ctx: lctx,
			}
			l.callback = func() {
				// Mark listener for deletion even if we block
				// so we skip sending notifications to them
				cancel()

				n.mtx.Lock()
				defer n.mtx.Unlock()

				delete(n.listeners, string(nid[:]))
			}
			n.listeners[string(nid[:])] = &l
			return &l, nil
		}
	}
}

// Notify sends a notification to every listener. If the Notifier
// is blocking, it blocks until every listener can receive the
// notification.
func (n *Notifier) Notify(ctx context.Context, message Notification) error {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	for _, l := range n.listeners {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case l.ch <- message:
		case <-l.block(n.blocking):
		}
	}
	return nil
}

func (l *Listener) block(blocking bool) <-chan struct{} {
	if !blocking {
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		return ch
	}
	return l.ctx.Done()
}
