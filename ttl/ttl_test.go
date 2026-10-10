// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package ttl

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/davecgh/go-spew/spew"
)

// The timing-dependent tests run inside a synctest bubble.  TTL is a
// clock, so testing it against the real one meant sleeping past real
// deadlines and hoping the callback goroutines had been scheduled by
// the time the assertion ran — slow, and only probably correct.
//
// Inside a bubble time.Sleep advances a fake clock instantly, and
// synctest.Wait blocks until every other goroutine in the bubble is
// durably blocked, which turns "sleep a bit longer than it should
// need" into an exact statement: every callback that was going to run
// has run.  That also closes a latent hole — ttl() launches the
// expired callback *before* it performs the autoDelete, so a test that
// only waited on the callback could observe the map before the delete
// landed.
//
// The pure error-path tests (Get/Cancel/Delete not found) touch
// neither the clock nor a goroutine and are left outside a bubble.

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
	synctest.Test(t, func(t *testing.T) {
		count := 10
		tm, err := New(count, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
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

		// The bubble advances the fake clock past the 1s TTL as
		// soon as every goroutine is durably blocked, so this
		// returns immediately.
		wg.Wait()

		// wg only proves the callbacks ran; ttl() performs the
		// autoDelete after launching them.
		synctest.Wait()

		l = tm.Len()
		if l != 0 {
			t.Fatalf("invalid len got %v want %v", l, 0)
		}
	})
}

func TestTTLCancelAuto(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		count := 10
		tm, err := New(count, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
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

		wg.Wait()
		synctest.Wait()

		l = tm.Len()
		if l != 0 {
			t.Fatalf("invalid len got %v want %v", l, 0)
		}
	})
}

func TestTTLExpire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		count := 10
		tm, err := New(count, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
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

		wg.Wait()
		synctest.Wait()

		l = tm.Len()
		if l != count {
			t.Fatalf("invalid len got %v want %v", l, count)
		}

		// Check that all items are expired
		for i := range count {
			key := strconv.Itoa(i)
			if _, expired, err := tm.Get(key); err != nil {
				t.Fatalf("%v: %v", key, err)
			} else if !expired {
				t.Fatalf("%v: got %v want %v", key, expired, false)
			}
		}
	})
}

func TestTTLCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		count := 10
		tm, err := New(count, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
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

		wg.Wait()
		synctest.Wait()

		l = tm.Len()
		if l != count {
			t.Fatalf("invalid len got %v want %v", l, count)
		}
	})
}

func TestTTLDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		count := 10
		tm, err := New(count, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		for i := range count {
			tm.Put(ctx, time.Second, strconv.Itoa(i), i, callbackPanic,
				callbackPanic)
		}
		l := tm.Len()
		if l != count {
			t.Fatalf("invalid len got %v want %v", l, count)
		}
		for i := range count {
			key := strconv.Itoa(i)
			if expired, err := tm.Delete(key); err != nil {
				t.Fatal(err)
			} else if expired {
				t.Fatalf("%v: expired got %v wanted %v", key, expired, false)
			}
		}

		// Delete cancels each value context; the goroutines must
		// wake, find the key gone and exit without a callback.
		synctest.Wait()

		l = tm.Len()
		if l != 0 {
			t.Fatalf("invalid len got %v want %v", l, 0)
		}
	})
}

func TestTTLDeleteByValue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		count := 10
		tm, err := New(count, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		x := 1337
		for i := range count {
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

		synctest.Wait()
	})
}

func TestGetNotFound(t *testing.T) {
	tm, err := New(1, false)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = tm.Get("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestCancelNotFound(t *testing.T) {
	tm, err := New(1, false)
	if err != nil {
		t.Fatal(err)
	}
	err = tm.Cancel("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	tm, err := New(1, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tm.Delete("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestExpireNilCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		// Put with nil expired callback — must not panic on expiry.
		tm.Put(ctx, 50*time.Millisecond, "key", "val", nil, nil)

		// Advance past the deadline, then drain.
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()

		if tm.Len() != 0 {
			t.Fatalf("expected len 0 after expiry, got %d", tm.Len())
		}
	})
}

func TestCancelNilRemoveCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		// Put with nil remove callback — must not panic on cancel.
		tm.Put(ctx, 10*time.Second, "key", "val", nil, nil)

		if err := tm.Cancel("key"); err != nil {
			t.Fatal(err)
		}

		synctest.Wait()

		if tm.Len() != 0 {
			t.Fatalf("expected len 0 after cancel, got %d", tm.Len())
		}
	})
}

func TestTTLGoroutineKeyAlreadyDeleted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		// Put then immediately Delete — the ttl goroutine will wake up
		// and find the key already gone (!ok path in ttl()).
		tm.Put(ctx, 50*time.Millisecond, "key", "val", callbackPanic, callbackPanic)

		if _, err := tm.Delete("key"); err != nil {
			t.Fatal(err)
		}

		// Let the ttl goroutine run and confirm no panic.
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()

		if tm.Len() != 0 {
			t.Fatalf("expected len 0, got %d", tm.Len())
		}
	})
}

// TestTTLPutRefreshResetsTimer verifies that calling Put with the same
// key resets the TTL.  Before this fix, the old goroutine's timer
// would fire at the original deadline and expire the entry even though
// a refresh had been issued.
func TestTTLPutRefreshResetsTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		expired := make(chan struct{}, 1)
		expiredCB := func(_ context.Context, _ any, _ any) {
			expired <- struct{}{}
		}

		// Initial Put with 200ms TTL.
		tm.Put(ctx, 200*time.Millisecond, "peer", "v1", expiredCB, nil)

		// At 100ms, refresh the key — the timer resets to a fresh
		// 200ms, so the new deadline is 300ms.
		time.Sleep(100 * time.Millisecond)
		tm.Put(ctx, 200*time.Millisecond, "peer", "v2", expiredCB, nil)

		// At 250ms the original deadline has passed.  The entry must
		// still be alive: the stale goroutine has had its chance to
		// run and must have exited on the generation check.
		time.Sleep(150 * time.Millisecond)
		synctest.Wait()
		if tm.Len() != 1 {
			t.Fatalf("entry expired prematurely: len got %d want 1", tm.Len())
		}
		select {
		case <-expired:
			t.Fatal("stale timer fired the expiry callback")
		default:
		}

		// At 350ms the refreshed deadline has passed.
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		select {
		case <-expired:
		default:
			t.Fatal("refreshed expiry callback did not fire")
		}

		// autoDelete has run by now — Wait covers the delete that
		// ttl() performs after launching the callback.
		if tm.Len() != 0 {
			t.Fatalf("expected len 0 after expiry, got %d", tm.Len())
		}
	})
}

// TestTTLPutRefreshOldCallbackNotFired verifies that the expired
// callback from a replaced entry is never invoked.
func TestTTLPutRefreshOldCallbackNotFired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		// First Put — if this callback fires, the test fails.
		tm.Put(ctx, 100*time.Millisecond, "k", "old", callbackPanic, nil)

		// Overwrite before expiry.
		time.Sleep(50 * time.Millisecond)
		var wg sync.WaitGroup
		wg.Add(1)
		tm.Put(ctx, 100*time.Millisecond, "k", &wg, callback, nil)

		// Wait for the NEW entry to expire normally.
		wg.Wait()
		synctest.Wait()

		// If the old callbackPanic fired, we'd have panicked by now.
		if tm.Len() != 0 {
			t.Fatalf("expected len 0, got %d", tm.Len())
		}
	})
}

// TestTTLPutRefreshNoAutoDelete verifies Put-refresh with
// autoDelete=false.  The entry must remain in the map and the old
// expired callback must not fire.
func TestTTLPutRefreshNoAutoDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		expired := make(chan struct{}, 1)
		expiredCB := func(_ context.Context, _ any, _ any) {
			expired <- struct{}{}
		}

		// Old entry — callbackPanic must not fire.
		tm.Put(ctx, 150*time.Millisecond, "k", "old", callbackPanic, nil)

		// Refresh at 75ms; new deadline is 225ms.
		time.Sleep(75 * time.Millisecond)
		tm.Put(ctx, 150*time.Millisecond, "k", "new", expiredCB, nil)

		// At 200ms the old timer would have fired.
		time.Sleep(125 * time.Millisecond)
		synctest.Wait()
		if tm.Len() != 1 {
			t.Fatalf("entry disappeared: len got %d want 1", tm.Len())
		}

		// At 250ms the refreshed timer has fired.
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		select {
		case <-expired:
		default:
			t.Fatal("refreshed expiry callback did not fire")
		}

		// autoDelete=false: entry stays, timeoutExpired flag set.
		v, te, err := tm.Get("k")
		if err != nil {
			t.Fatal(err)
		}
		if !te {
			t.Fatal("expected timeoutExpired=true")
		}
		if v != "new" {
			t.Fatalf("expected refreshed value \"new\", got %q", v)
		}
	})
}

// TestTTLCancelCallbackGuaranteed verifies that Cancel fires the
// remove callback directly, not via the goroutine.  Even if a Put
// races in after Cancel, the remove must have already been captured.
func TestTTLCancelCallbackGuaranteed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		removed := make(chan any, 1)
		removeCB := func(_ context.Context, _ any, val any) {
			removed <- val
		}

		tm.Put(ctx, 10*time.Second, "k", "the-value", callbackPanic, removeCB)

		// Cancel fires remove directly.
		if err := tm.Cancel("k"); err != nil {
			t.Fatal(err)
		}

		synctest.Wait()

		select {
		case v := <-removed:
			if v != "the-value" {
				t.Fatalf("remove got %v, want \"the-value\"", v)
			}
		default:
			t.Fatal("remove callback did not fire")
		}

		// autoDelete: entry should be gone.
		if tm.Len() != 0 {
			t.Fatalf("expected len 0, got %d", tm.Len())
		}
	})
}

// TestTTLCancelCallbackNoAutoDelete verifies Cancel fires remove and
// the entry remains in the map when autoDelete is false.
func TestTTLCancelCallbackNoAutoDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		removed := make(chan any, 1)
		removeCB := func(_ context.Context, _ any, val any) {
			removed <- val
		}

		tm.Put(ctx, 10*time.Second, "k", "val", callbackPanic, removeCB)

		if err := tm.Cancel("k"); err != nil {
			t.Fatal(err)
		}

		synctest.Wait()

		select {
		case v := <-removed:
			if v != "val" {
				t.Fatalf("remove got %v, want \"val\"", v)
			}
		default:
			t.Fatal("remove callback did not fire")
		}

		// autoDelete=false: entry stays.
		if tm.Len() != 1 {
			t.Fatalf("expected len 1, got %d", tm.Len())
		}
	})
}

// TestTTLCancelThenPutRemoveStillFires verifies that even when Put
// races in immediately after Cancel, the remove callback from Cancel
// is guaranteed to fire with the old value.
func TestTTLCancelThenPutRemoveStillFires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		removed := make(chan any, 1)
		removeCB := func(_ context.Context, _ any, val any) {
			removed <- val
		}

		// Old entry with a remove callback.
		tm.Put(ctx, 10*time.Second, "k", "old-val", callbackPanic, removeCB)

		// Cancel then immediately Put — simulates the worst-case race.
		if err := tm.Cancel("k"); err != nil {
			t.Fatal(err)
		}
		tm.Put(ctx, 10*time.Second, "k", "new-val", nil, nil)

		synctest.Wait()

		// The old remove callback must fire with "old-val".
		select {
		case v := <-removed:
			if v != "old-val" {
				t.Fatalf("remove got %v, want \"old-val\"", v)
			}
		default:
			t.Fatal("remove callback did not fire")
		}

		// New entry must still be live.
		if tm.Len() != 1 {
			t.Fatalf("expected len 1, got %d", tm.Len())
		}
		v, _, err := tm.Get("k")
		if err != nil {
			t.Fatal(err)
		}
		if v != "new-val" {
			t.Fatalf("expected new-val, got %v", v)
		}
	})
}

// TestTTLParentCancelFiresRemove covers cancellation that does not come
// through TTL.Cancel.  The context handed to Put is the caller's, so
// cancelling it removes the entry just as Cancel does, and the remove
// callback has to fire — Cancel is the only path that clears it.
func TestTTLParentCancelFiresRemove(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, true)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())

		removed := make(chan any, 1)
		removeCB := func(_ context.Context, _ any, val any) {
			removed <- val
		}

		tm.Put(ctx, 10*time.Second, "k", "the-value", callbackPanic, removeCB)

		cancel()
		synctest.Wait()

		select {
		case v := <-removed:
			if v != "the-value" {
				t.Fatalf("remove got %v, want \"the-value\"", v)
			}
		default:
			t.Fatal("parent cancel dropped the remove callback")
		}
	})
}

// TestTTLParentCancelAfterCancelFiresOnce proves the two cancellation
// paths do not double-fire: TTL.Cancel clears the callback under the
// mutex, so the goroutine woken by the same context cancellation finds
// nothing left to call.
func TestTTLParentCancelAfterCancelFiresOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tm, err := New(1, false)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		var mtx sync.Mutex
		var calls int
		removeCB := func(context.Context, any, any) {
			mtx.Lock()
			calls++
			mtx.Unlock()
		}

		tm.Put(ctx, 10*time.Second, "k", "v", callbackPanic, removeCB)

		if err := tm.Cancel("k"); err != nil {
			t.Fatal(err)
		}

		// Cancel already cancelled the value context; Wait lets the
		// ttl goroutine reach the Canceled branch and exit.
		synctest.Wait()

		mtx.Lock()
		got := calls
		mtx.Unlock()
		if got != 1 {
			t.Fatalf("remove callback fired %d times, want 1", got)
		}
	})
}
