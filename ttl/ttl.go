// Copyright (c) 2024 Hemi Labs, Inc.
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

type value struct {
	value any

	expired func(any, any) // called when expired
	remove  func(any, any) // called when removed

	// Value context
	ctx    context.Context
	cancel context.CancelFunc
}

type TTL struct {
	mtx sync.Mutex

	m map[any]value
}

func New(capacity int) (*TTL, error) {
	return &TTL{
		m: make(map[any]value, capacity),
	}, nil
}

func (tm *TTL) ttl(ctx context.Context, key any) {
	select {
	case <-ctx.Done():
		switch ctx.Err() {
		case nil:
			// not yet closed

		case context.DeadlineExceeded:
			// expired
			tm.mtx.Lock()
			defer tm.mtx.Unlock()
			v, ok := tm.m[key]
			if !ok {
				return
			}
			if v.expired != nil {
				go v.expired(key, v.value)
			}

			// For now assume we aways want to remove key
			delete(tm.m, key)

		case context.Canceled:
			// This is the caller calling cancel
			tm.mtx.Lock()
			defer tm.mtx.Unlock()
			v, ok := tm.m[key]
			if !ok {
				return
			}
			if v.remove != nil {
				go v.remove(key, v.value)
			}

			// For now assume we aways want to remove key
			delete(tm.m, key)
		}
	}
}

func (tm *TTL) Put(pctx context.Context, ttl time.Duration, key any, val any, expired func(any, any), remove func(any, any)) {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	v := value{
		value:   val,
		expired: expired,
		remove:  remove,
	}
	v.ctx, v.cancel = context.WithTimeout(pctx, ttl)
	tm.m[key] = v
	go tm.ttl(v.ctx, key)
}

func (tm *TTL) Get(key any) (any, error) {
	tm.mtx.Lock()
	defer tm.mtx.Unlock()

	v, ok := tm.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return v.value, nil
}

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
