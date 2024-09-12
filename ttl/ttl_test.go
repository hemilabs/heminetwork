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

func callback(ctx context.Context, key any, value any) {
	v, ok := value.(*sync.WaitGroup)
	if !ok {
		panic(fmt.Sprintf("invalid value type: %T", value))
	}
	v.Done()
}

func callbackPanic(ctx context.Context, key any, value any) {
	panic(fmt.Sprintf("unexpected callback: %v", spew.Sdump(key)))
}

func TestTTLExpireAuto(t *testing.T) {
	count := 10
	tm, err := New(count, true)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		tm.Put(ctx, time.Second, strconv.Itoa(i), &wg, callback, nil)
	}
	for i := range count {
		key := strconv.Itoa(i)
		if _, _, err := tm.Get(key); err != nil {
			t.Fatalf("%v: %v", key, err)
		}
	}
	l := tm.Len()
	if l != count {
		t.Fatalf("invalid len got %v want %v", l, count)
	}

	t.Logf("waiting for timeouts")
	wg.Wait()

	l = tm.Len()
	if l != 0 {
		t.Fatalf("invalid len got %v want %v", l, 0)
	}
}

func TestTTLCancelAuto(t *testing.T) {
	count := 10
	tm, err := New(count, true)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		tm.Put(ctx, time.Second, strconv.Itoa(i), &wg, callbackPanic, callback)
	}
	l := tm.Len()
	if l != count {
		t.Fatalf("invalid len got %v want %v", l, count)
	}
	for i := range count {
		key := strconv.Itoa(i)
		if _, _, err := tm.Get(key); err != nil {
			t.Fatalf("%v: %v", key, err)
		}
		if err = tm.Cancel(key); err != nil {
			t.Fatal(err)
		}
	}

	t.Logf("waiting for cancels")
	wg.Wait()

	l = tm.Len()
	if l != 0 {
		t.Fatalf("invalid len got %v want %v", l, 0)
	}
}

func TestTTLExpire(t *testing.T) {
	count := 10
	tm, err := New(count, false)
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
		if _, _, err := tm.Get(key); err != nil {
			t.Fatalf("%v: %v", key, err)
		}
	}
	l := tm.Len()
	if l != count {
		t.Fatalf("invalid len got %v want %v", l, count)
	}

	t.Logf("waiting for timeouts")
	wg.Wait()

	l = tm.Len()
	if l != count {
		t.Fatalf("invalid len got %v want %v", l, count)
	}

	// Check that all items are expired
	for i := 0; i < count; i++ {
		key := strconv.Itoa(i)
		if _, expired, err := tm.Get(key); err != nil {
			t.Fatalf("%v: %v", key, err)
		} else if !expired {
			t.Fatalf("%v: got %v want %v", key, expired, false)
		}
	}
}

func TestTTLCancel(t *testing.T) {
	count := 10
	tm, err := New(count, false)
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
	l := tm.Len()
	if l != count {
		t.Fatalf("invalid len got %v want %v", l, count)
	}
	for i := 0; i < count; i++ {
		key := strconv.Itoa(i)
		if _, _, err := tm.Get(key); err != nil {
			t.Fatalf("%v: %v", key, err)
		}
		if err = tm.Cancel(key); err != nil {
			t.Fatal(err)
		}
	}

	t.Logf("waiting for cancels")
	wg.Wait()

	l = tm.Len()
	if l != count {
		t.Fatalf("invalid len got %v want %v", l, count)
	}
}

func TestTTLDelete(t *testing.T) {
	count := 10
	tm, err := New(count, false)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < count; i++ {
		tm.Put(ctx, time.Second, strconv.Itoa(i), i, callbackPanic,
			callbackPanic)
	}
	l := tm.Len()
	if l != count {
		t.Fatalf("invalid len got %v want %v", l, count)
	}
	for i := 0; i < count; i++ {
		key := strconv.Itoa(i)
		if expired, err := tm.Delete(key); err != nil {
			t.Fatal(err)
		} else if expired {
			t.Fatalf("%v: expired got %v wamted %v", key, expired, false)
		}
	}

	l = tm.Len()
	if l != 0 {
		t.Fatalf("invalid len got %v want %v", l, 0)
	}
}

func TestTTLDeleteByValue(t *testing.T) {
	count := 10
	tm, err := New(count, false)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	x := 1337
	for i := 0; i < count; i++ {
		tm.Put(ctx, time.Second, strconv.Itoa(i), x, callbackPanic,
			callbackPanic)
	}
	l := tm.Len()
	if l != count {
		t.Fatalf("invalid len got %v want %v", l, count)
	}

	dontMatch := func(mv any) bool {
		return x != mv.(int)
	}
	n := tm.DeleteByValue(dontMatch)
	if n != 0 {
		t.Fatalf("invalid dont match deleted count got %v want %v", n, count)
	}

	match := func(mv any) bool {
		return x == mv.(int)
	}
	n = tm.DeleteByValue(match)
	if n != count {
		t.Fatalf("invalid match deleted count got %v want %v", n, count)
	}
}
