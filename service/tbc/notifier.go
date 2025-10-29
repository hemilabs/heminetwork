// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type Notification struct {
	Type      string    `json:"type"`
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Error     error     `json:"error,omitempty"`
}

func (n Notification) Is(target Notification) bool {
	return n.Type == target.Type
}

func (n Notification) String() string {
	return fmt.Sprintf("[%v] %s %s", n.Timestamp, n.Type, n.ID)
}

func NotificationBlock(hash chainhash.Hash) Notification {
	return Notification{
		Type:      "block_insert",
		ID:        hash.String(),
		Timestamp: time.Now(),
	}
}

func NotificationBlockheader(hash chainhash.Hash) Notification {
	return Notification{
		Type:      "blockheader_insert",
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

	ctx         context.Context
	unsubscribe func()
}

func (l *Listener) Unsubscribe() {
	l.unsubscribe()
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

func (n *Notifier) HasListeners() bool {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	return len(n.listeners) > 0
}

func (n *Notifier) Subscribe(pctx context.Context, capacity uint64) (*Listener, error) {
	lctx, cancel := context.WithCancel(pctx)
	l := &Listener{
		ch:  make(chan Notification, capacity),
		ctx: lctx,
	}
	l.unsubscribe = func() {
		// Mark listener for deletion even if we block
		// so we skip sending notifications to them.
		cancel()

		n.mtx.Lock()
		defer n.mtx.Unlock()

		delete(n.listeners, l.id)
	}

	n.mtx.Lock()
	defer n.mtx.Unlock()

	for {
		id := genID()
		if _, ok := n.listeners[id]; ok {
			// ID is already used, retry.
			continue
		}
		l.id = id
		n.listeners[id] = l
		return l, nil
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

func genID() string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Errorf("read random: %w", err))
	}
	return hex.EncodeToString(buf)
}
