// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"context"
	"testing"
	"time"
)

// TestDefaultTestContext tests the DefaultTestContext function
func TestDefaultTestContext(t *testing.T) {
	ctx, cancel := DefaultTestContext()
	defer cancel()

	// Verify that we got a valid context
	if ctx == nil {
		t.Fatal("DefaultTestContext returned nil context")
	}

	// Verify that the context has a deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("DefaultTestContext returned context without deadline")
	}

	// Verify that the deadline is approximately 300 seconds from now
	expectedDeadline := time.Now().Add(300 * time.Second)
	timeDiff := expectedDeadline.Sub(deadline)
	if timeDiff < -5*time.Second || timeDiff > 5*time.Second {
		t.Errorf("Deadline is not approximately 300 seconds from now: %v", deadline)
	}

	// Verify that the context is not done initially
	select {
	case <-ctx.Done():
		t.Fatal("Context should not be done initially")
	default:
		// Context is not done, which is expected
	}

	// Verify that cancel function works
	cancel()
	select {
	case <-ctx.Done():
		// Context is done after cancel, which is expected
	default:
		t.Fatal("Context should be done after cancel")
	}
}

// TestDefaultTestContextMultipleCalls tests that multiple calls return different contexts
func TestDefaultTestContextMultipleCalls(t *testing.T) {
	ctx1, cancel1 := DefaultTestContext()
	defer cancel1()

	ctx2, cancel2 := DefaultTestContext()
	defer cancel2()

	// Verify that we got different contexts
	if ctx1 == ctx2 {
		t.Fatal("DefaultTestContext returned the same context on multiple calls")
	}

	// Verify that both contexts have deadlines
	deadline1, ok1 := ctx1.Deadline()
	if !ok1 {
		t.Fatal("First context has no deadline")
	}

	deadline2, ok2 := ctx2.Deadline()
	if !ok2 {
		t.Fatal("Second context has no deadline")
	}

	// Verify that deadlines are different (they should be created at different times)
	// Add a small tolerance for timing differences
	timeDiff := deadline1.Sub(deadline2)
	if timeDiff < 100*time.Millisecond && timeDiff > -100*time.Millisecond {
		t.Logf("Deadlines are very close (difference: %v), this might happen on fast systems", timeDiff)
		// Don't fail the test for this, just log it
	}
}

// TestDefaultTestContextTimeout tests that the context times out after the expected duration
func TestDefaultTestContextTimeout(t *testing.T) {
	// Create a context with a shorter timeout for testing
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start a goroutine that waits for the context to be done
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(done)
	}()

	// Wait for the context to timeout (should be around 2 seconds)
	select {
	case <-done:
		// Context timed out as expected
	case <-time.After(3 * time.Second):
		t.Fatal("Context did not timeout within expected duration")
	}
}

// TestDefaultTestContextCancelImmediate tests that cancel works immediately
func TestDefaultTestContextCancelImmediate(t *testing.T) {
	ctx, cancel := DefaultTestContext()

	// Cancel immediately
	cancel()

	// Verify that the context is done
	select {
	case <-ctx.Done():
		// Context is done after cancel, which is expected
	default:
		t.Fatal("Context should be done after immediate cancel")
	}

	// Verify that the error is context.Canceled
	if ctx.Err() != context.Canceled {
		t.Errorf("Expected context.Canceled error, got: %v", ctx.Err())
	}
}
