package tbc

import (
	"context"
	"crypto/rand"
	"io"
	"sync"
)

type notification string

const (
	NotificationBlock       notification = "block inserted"
	NotificationBlockheader notification = "blockheader inserted"
)

type Notifier struct {
	mtx sync.Mutex

	listeners map[string]*Listener

	// Channel capacity for every listener
	capacity uint64

	// If true, the notifier will block on new messages until the queue for
	// each listener's message channel is unblocked (i.e., read from).
	// This should only be TRUE for test purposes.
	blocking bool
}

type Listener struct {
	id       string
	notifier *Notifier
	ch       chan notification

	ctx    context.Context
	cancel context.CancelFunc
}

func (l *Listener) Unsubscribe() {
	l.cancel()

	l.notifier.mtx.Lock()
	defer l.notifier.mtx.Unlock()

	delete(l.notifier.listeners, l.id)
}

func (l *Listener) Listen() <-chan notification {
	return l.ch
}

func NewNotifier(capacity uint64, blocking bool) *Notifier {
	n := Notifier{
		listeners: make(map[string]*Listener),
		capacity:  capacity,
		blocking:  blocking,
	}
	return &n
}

func (n *Notifier) Subscribe(ctx context.Context) (*Listener, error) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	var nid [16]byte
	for {
		if _, err := io.ReadFull(rand.Reader, nid[:]); err != nil {
			return nil, err
		}
		if _, ok := n.listeners[string(nid[:])]; !ok {
			lctx, cancel := context.WithCancel(ctx)
			l := Listener{
				ch:       make(chan notification, n.capacity),
				id:       string(nid[:]),
				notifier: n,
				ctx:      lctx,
				cancel:   cancel,
			}
			n.listeners[string(nid[:])] = &l
			return &l, nil
		}
	}
}

func (n *Notifier) Notify(ctx context.Context, message notification) error {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	for _, l := range n.listeners {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case l.ch <- message:
		case <-l.block():
		}
	}
	return nil
}

func (l *Listener) block() <-chan struct{} {
	if !l.notifier.blocking {
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		return ch
	}
	return l.ctx.Done()
}
