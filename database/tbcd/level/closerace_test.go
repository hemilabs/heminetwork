// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"sync"
	"testing"
)

// TestAccessAfterCloseErrorsNotPanics verifies that store calls made after
// Close return an error instead of crashing. service/tbc runs goroutines that
// Run does not wait for, so they can still touch the store after dbClose.
func TestAccessAfterCloseErrorsNotPanics(t *testing.T) {
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Accessors read l.pool without the lock, so Close leaves the handles
	// in place and these calls get leveldb.ErrClosed, not a nil handle.
	if _, err := db.BlockHeaderBest(ctx); err == nil {
		t.Error("BlockHeaderBest after Close returned no error")
	}
	// goleveldb hands out an empty iterator carrying ErrClosed after Close,
	// and BlocksMissing surfaces it through it.Error().
	if _, err := db.BlocksMissing(ctx, 16); err == nil {
		t.Error("BlocksMissing after Close returned no error")
	}

	// Close must stay idempotent since the handles stay in the pools.
	if err := db.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil", err)
	}
}

// TestConcurrentReadsRacingCloseDoNotThrow runs readers concurrently with
// Close. Deleting pool entries under unsynchronized readers caused a
// "concurrent map read and map write" fatal error, which recover() cannot
// catch. Under -race this also checks for the data race itself.
func TestConcurrentReadsRacingCloseDoNotThrow(t *testing.T) {
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := t.Context()
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	const readers = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 200 {
				// Errors are expected and fine; a throw is not.
				_, _ = db.BlockHeaderBest(ctx)
			}
		}()
	}

	close(start)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	wg.Wait()
}
