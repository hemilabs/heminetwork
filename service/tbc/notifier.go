// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// maxWatchScripts is the maximum number of ScriptHashes a single
// listener may watch.  Prevents unbounded memory growth from a
// malicious client sending large TxWatch requests.
const maxWatchScripts = 1024

// Notification types.
const (
	NtfnTypeBlockInsert       = "block_insert"
	NtfnTypeBlockheaderInsert = "blockheader_insert"
	NtfnTypeTxMempool         = "tx_mempool"
	NtfnTypeTxConfirmed       = "tx_confirmed"
)

// Notification represents an event delivered to subscribers.
type Notification struct {
	Type      string            `json:"type"`
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Msg       string            `json:"msg"`
	Error     error             `json:"error,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

func (n Notification) Is(target Notification) bool {
	return n.Type == target.Type
}

func (n Notification) String() string {
	return fmt.Sprintf("[%v] %s %s: %s", n.Timestamp, n.Type, n.ID, n.Msg)
}

// ScriptHash extracts the script hash from the notification metadata.
// Returns false if the metadata is missing, malformed, or wrong length.
func (n Notification) ScriptHash() (tbcd.ScriptHash, bool) {
	v, ok := n.Metadata["script_hash"]
	if !ok {
		return tbcd.ScriptHash{}, false
	}
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != len(tbcd.ScriptHash{}) {
		return tbcd.ScriptHash{}, false
	}
	var sh tbcd.ScriptHash
	copy(sh[:], b)
	return sh, true
}

// NotificationBlock creates a block insertion notification.
func NotificationBlock(hash chainhash.Hash) Notification {
	return Notification{
		Type:      NtfnTypeBlockInsert,
		ID:        hash.String(),
		Msg:       "block inserted: " + hash.String(),
		Timestamp: time.Now(),
	}
}

// NotificationBlockheader creates a block header insertion notification.
func NotificationBlockheader(hash chainhash.Hash) Notification {
	return Notification{
		Type:      NtfnTypeBlockheaderInsert,
		ID:        hash.String(),
		Msg:       "blockheader inserted: " + hash.String(),
		Timestamp: time.Now(),
	}
}

func NotificationJob(id string, jobType jobType, status jobStatus) Notification {
	return Notification{
		Type:      string(jobType),
		ID:        id,
		Msg:       string(status),
		Timestamp: time.Now(),
	}
}

func NotificationService(serviceID string, status string) Notification {
	return Notification{
		Type:      "service_update",
		ID:        serviceID,
		Msg:       status,
		Timestamp: time.Now(),
	}
}

// NotificationTxMempool creates a notification for a mempool transaction
// whose output matches the given ScriptHash.
func NotificationTxMempool(txid chainhash.Hash, sh tbcd.ScriptHash) Notification {
	return Notification{
		Type:      NtfnTypeTxMempool,
		ID:        txid.String(),
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"script_hash": hex.EncodeToString(sh[:]),
		},
	}
}

// NotificationTxConfirmed creates a notification for a transaction confirmed
// in a block whose output matches the given ScriptHash.
func NotificationTxConfirmed(txid chainhash.Hash, blockHash chainhash.Hash, height int64, sh tbcd.ScriptHash) Notification {
	return Notification{
		Type:      NtfnTypeTxConfirmed,
		ID:        txid.String(),
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"block_hash":   blockHash.String(),
			"block_height": strconv.FormatInt(height, 10),
			"script_hash":  hex.EncodeToString(sh[:]),
		},
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

	// watchScripts is the set of ScriptHashes this listener cares
	// about for tx_mempool and tx_confirmed notifications.
	// nil means no filtering — receive all notifications.
	watchMtx     sync.RWMutex
	watchScripts map[tbcd.ScriptHash]struct{}
}

func (l *Listener) Unsubscribe() {
	l.unsubscribe()
}

// Watch adds ScriptHashes to this listener's watch set.  Once a
// watch set exists, tx_mempool and tx_confirmed notifications are
// only delivered if the notification's ScriptHash is in the set.
// Block and blockheader notifications are always delivered.
// Returns an error if adding the scripts would exceed maxWatchScripts.
func (l *Listener) Watch(scripts []tbcd.ScriptHash) error {
	l.watchMtx.Lock()
	defer l.watchMtx.Unlock()
	if l.watchScripts == nil {
		l.watchScripts = make(map[tbcd.ScriptHash]struct{}, len(scripts))
	}
	if len(l.watchScripts)+len(scripts) > maxWatchScripts {
		return fmt.Errorf("watch set would exceed maximum of %d", maxWatchScripts)
	}
	for _, sh := range scripts {
		l.watchScripts[sh] = struct{}{}
	}
	return nil
}

// Unwatch removes ScriptHashes from this listener's watch set.
func (l *Listener) Unwatch(scripts []tbcd.ScriptHash) {
	l.watchMtx.Lock()
	defer l.watchMtx.Unlock()
	for _, sh := range scripts {
		delete(l.watchScripts, sh)
	}
}

// accepts returns true if the listener should receive the given
// notification.  Block/blockheader notifications are always accepted.
// tx_mempool and tx_confirmed are only accepted if either the listener
// has no watch filter (watchScripts == nil) or the notification's
// ScriptHash is in the watch set.
func (l *Listener) accepts(n Notification) bool {
	switch n.Type {
	case NtfnTypeTxMempool, NtfnTypeTxConfirmed:
	default:
		return true
	}

	l.watchMtx.RLock()
	defer l.watchMtx.RUnlock()

	if l.watchScripts == nil {
		return true
	}

	sh, ok := n.ScriptHash()
	if !ok {
		return false
	}
	_, found := l.watchScripts[sh]
	return found
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

// Notify sends a notification to every listener that accepts it.
// If the Notifier is blocking, it blocks until every accepting
// listener can receive the notification.
func (n *Notifier) Notify(ctx context.Context, message Notification) error {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	for _, l := range n.listeners {
		if !l.accepts(message) {
			continue
		}
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
