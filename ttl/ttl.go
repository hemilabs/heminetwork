// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package ttl

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("not found")

// ttlGen is the context key for the per-Put generation number.
// The ttl goroutine extracts its generation from ctx.Value and
// compares it against the current map entry to detect stale
// wakeups after a key has been overwritten by a subsequent Put.
type ttlGen struct{}

// value wraps a value stored in the TTL map and includes additional metadata.
type value struct {
	value any

	expired func(context.Context, any, any) // called when TTL expires
	remove  func(context.Context, any, any) // called when removed from map

	timeoutExpired bool // set when this value has expired

	gen uint64 // generation number assigned by Put

	// Value context
	ctx    context.Context
	cancel context.CancelFunc

	// Context used during callbacks.
	callbackContext context.Context
}

// TTL is an opaque structure that stores key/values in an internal map. These
// values have a time-to-live callback function associated with them.
// Depending on configuration either these values are automatically deleted from
// the map on expiration.
type TTL struct {
	mtx sync.Mutex

	autoDelete bool
	gen        uint64 // monotonic generation counter for Put
	m          map[any]*value
}

// New creates a new TTL map with the provided capacity. If autoDelete is set
// then the key will be deleted from the map on either the cancel or timeout
// event.
func New(capacity int, autoDelete bool) (*TTL, error) {
	return &TTL{
		autoDelete: autoDelete,
		m:          make(map[any]*value, capacity),
	}, nil
}

// ttl waits for a timeout or cancel. Should be called as a go routine.
func (tm *TTL) ttl(ctx context.Context, key any) {
	<-ctx.Done()
	err := ctx.Err()
	// unreachable: ctx.Err() is always non-nil after ctx.Done() closes
	if err == nil {
		return
	}

	tm.mtx.Lock()
	defer tm.mtx.Unlock()
	v, ok := tm.m[key]
	if !ok {
		return
	}
	// If a subsequent Put overwrote this key, the current entry
	// has a different generation.  This goroutine is stale — exit
	// without callbacks or deletion.
	if g, _ := ctx.Value(ttlGen{}).(uint64); g != v.gen {
		return
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		// expired
		v.timeoutExpired = true
		if v.expired != nil {
			go v.expired(v.callbackContext, key, v.value)
		}

	case errors.Is(err, context.Canceled):
		// Cancel already fired the remove callback directly;
		// v.remove was nil'd to prevent double-fire.  Nothing
		// to do here except autoDelete cleanup below.
	}

	if tm.autoDelete {
		delete(tm.m, key)
	}
}

// Put inserts the provided key and value into the TTL map. The ttl values
// designates the duration of the validity of this key-value pair. The expired
// function is called when the duration expires and the remove callback is
// called when the key is Canceled.
func (tm *TTL) Put(pctx context.Context, ttl time.Duration, key any, val any, expired func(context.Context, any, any), remove func(context.Context, any, any)) {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	// Cancel the previous entry's context so its goroutine exits
	// promptly.  The generation check in ttl() prevents the stale
	// goroutine from firing callbacks or deleting the new entry.
	if old, ok := tm.m[key]; ok {
		old.cancel()
	}

	tm.gen++
	v := &value{
		value:           val,
		expired:         expired,
		remove:          remove,
		gen:             tm.gen,
		callbackContext: pctx,
	}
	v.ctx, v.cancel = context.WithTimeout(
		context.WithValue(pctx, ttlGen{}, tm.gen), ttl)
	tm.m[key] = v
	go tm.ttl(v.ctx, key)
}

// Get returns the corresponding value for the provided key. It also returns
// true if the value was expired.
func (tm *TTL) Get(key any) (any, bool, error) {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	v, ok := tm.m[key]
	if !ok {
		return nil, false, ErrNotFound
	}
	return v.value, v.timeoutExpired, nil
}

// Cancel aborts the waiting function and calls the remove callback.
// The callback is invoked directly (in a goroutine to avoid blocking
// the caller) rather than delegated to the ttl goroutine, so a
// racing Put cannot swallow it.
func (tm *TTL) Cancel(key any) error {
	tm.mtx.Lock()

	v, ok := tm.m[key]
	if !ok {
		tm.mtx.Unlock()
		return ErrNotFound
	}
	v.cancel()

	if tm.autoDelete {
		delete(tm.m, key)
	}

	// Capture and nil the callback under the lock so the ttl
	// goroutine cannot double-fire it.
	removeFn := v.remove
	v.remove = nil
	cbCtx := v.callbackContext
	val := v.value

	tm.mtx.Unlock()

	if removeFn != nil {
		go removeFn(cbCtx, key, val)
	}
	return nil
}

// delete removes the key from the TTL map and aborts the waiting function. It
// also prevents callbacks from being called. It returns true if the key did
// expire.
// Must be called with the mutex held.
func (tm *TTL) delete(key any) (bool, error) {
	v, ok := tm.m[key]
	if !ok {
		return false, ErrNotFound
	}
	// By deleting the key prior to canceling the value context prevents
	// the expired and remove callbacks from being called.
	delete(tm.m, key)
	v.cancel()

	return v.timeoutExpired, nil
}

// Delete removes the key from the TTL map and aborts the waiting function. It
// also prevents callbacks from being called. It returns true if the key did
// expire.
func (tm *TTL) Delete(key any) (bool, error) {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	return tm.delete(key)
}

// Len returns the length of the TTL map.
func (tm *TTL) Len() int {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	return len(tm.m)
}

// DeleteByValue walks the TTL map and calls delete if the find callback
// returns true. It returns the number of deletes called.
func (tm *TTL) DeleteByValue(find func(any) bool) int {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	var d int
	for k, v := range tm.m {
		if !find(v.value) {
			continue
		}
		_, err := tm.delete(k)
		// unreachable: key came from range over tm.m; delete cannot fail
		if err != nil {
			continue
		}
		d++
	}
	return d
}
