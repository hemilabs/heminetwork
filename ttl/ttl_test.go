// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package ttl

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

func callback(key any, value any) {
	v, ok := value.(*sync.WaitGroup)
	if !ok {
		panic(fmt.Sprintf("invalid value type: %T", value))
	}
	v.Done()
}

func callbackPanic(key any, value any) {
	panic(fmt.Sprintf("unexpected callback: %v", spew.Sdump(key)))
}

func TestTTLExpire(t *testing.T) {
	count := 10
	tm, err := New(count)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		tm.Put(ctx, time.Second, strconv.Itoa(i), &wg, callback, nil)
	}
	for i := 0; i < count; i++ {
		key := strconv.Itoa(i)
		_, err := tm.Get(key)
		if err != nil {
			t.Fatalf("%v: %v", key, err)
		}
	}

	t.Logf("waiting for timeouts")
	wg.Wait()

	tm.mtx.Lock()
	defer tm.mtx.Unlock()
	if len(tm.m) != 0 {
		t.Fatalf("map not empty: %v", len(tm.m))
	}
}

func TestTTLCancel(t *testing.T) {
	count := 10
	tm, err := New(count)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		tm.Put(ctx, time.Second, strconv.Itoa(i), &wg, callbackPanic, callback)
	}
	for i := 0; i < count; i++ {
		key := strconv.Itoa(i)
		_, err := tm.Get(key)
		if err != nil {
			t.Fatalf("%v: %v", key, err)
		}
		err = tm.Cancel(key)
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Logf("waiting for cancels")
	wg.Wait()

	tm.mtx.Lock()
	defer tm.mtx.Unlock()
	if len(tm.m) != 0 {
		t.Fatalf("map not empty: %v", len(tm.m))
	}
}
