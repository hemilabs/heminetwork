// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package ttl

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/juju/loggo"
)

var (
	logLevel = "INFO"
	log      = loggo.GetLogger("ttl")

	ErrNotFound = errors.New("not found")
)

func init() {
	loggo.ConfigureLoggers(logLevel)
}

// value wraps a value stored in the TTL map and includes additional metadata.
type value struct {
	value any

	expired func(context.Context, any, any) // called when TTL expires
	remove  func(context.Context, any, any) // called when removed from map

	timeoutExpired bool // set when this value has expired

	// Value context
	ctx    context.Context
	cancel context.CancelFunc

	// Context used during callbacks.
	callbackContext context.Context
}

// TTL is an opaque structure that stores key/values in an internal map. These
// values have a time-to-live callback functions associated with them.
// Depending on configuration either these values are automatically deleted from
// the map on expiration.
type TTL struct {
	mtx sync.Mutex

	autoDelete bool
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
	if err == nil {
		return
	}

	tm.mtx.Lock()
	defer tm.mtx.Unlock()
	v, ok := tm.m[key]
	if !ok {
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
		// This is the caller calling cancel
		if v.remove != nil {
			go v.remove(v.callbackContext, key, v.value)
		}
	}

	if tm.autoDelete {
		delete(tm.m, key)
	}
}

// Put inserts the provided key and value into the TTL map. The ttl values
// designates the duration of the validity of this key value pair. The expired
// function is called when the duration expires and the remove callback is
// called when the key is Canceled.
func (tm *TTL) Put(pctx context.Context, ttl time.Duration, key any, val any, expired func(context.Context, any, any), remove func(context.Context, any, any)) {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	v := &value{
		value:           val,
		expired:         expired,
		remove:          remove,
		callbackContext: pctx,
	}
	v.ctx, v.cancel = context.WithTimeout(pctx, ttl)
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
func (tm *TTL) Cancel(key any) error {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	v, ok := tm.m[key]
	if !ok {
		return ErrNotFound
	}
	v.cancel()

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

// Len return the length of the TTL map.
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
		if err != nil {
			continue
		}
		d++
	}
	return d
}
