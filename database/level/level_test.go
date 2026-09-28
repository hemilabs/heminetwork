// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"strings"
	"sync"
	"testing"

	"github.com/hemilabs/x/leveldb/leveldb/opt"
	"github.com/juju/loggo/v2"
)

func TestSharedCachesInstalled(t *testing.T) {
	cfg := NewDefaultConfig(t.TempDir())
	cfg.BlockCacheCapacity = 64 * opt.MiB
	cfg.OpenFilesCacheCapacity = 1024
	override := cfg.Options
	override.WriteBuffer = 32 * opt.MiB
	cfg.DBOptions = map[string]opt.Options{OrdinalDB: override}

	db, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if db.blockCacher == nil || db.fileCacher == nil {
		t.Fatal("shared cachers not created")
	}
	// The caller's config must remain untouched: reusing it for a
	// reopen must not resurrect this instance's caches.
	if cfg.Options.BlockCacher != nil || cfg.Options.OpenFilesCacher != nil {
		t.Fatal("caller config was mutated")
	}
	if o := cfg.DBOptions[OrdinalDB]; o.BlockCacher != nil || o.OpenFilesCacher != nil {
		t.Fatal("caller DBOptions were mutated")
	}
	// The private copy carries the shared cachers, base and override.
	if db.cfg.Options.BlockCacher != db.blockCacher ||
		db.cfg.Options.OpenFilesCacher != db.fileCacher {
		t.Fatal("private base options missing shared cachers")
	}
	o := db.cfg.DBOptions[OrdinalDB]
	if o.BlockCacher != db.blockCacher || o.OpenFilesCacher != db.fileCacher {
		t.Fatal("private per-DB override missing shared cachers")
	}
	if o.WriteBuffer != 32*opt.MiB {
		t.Fatalf("per-DB override WriteBuffer clobbered: %d", o.WriteBuffer)
	}
	blockBytes, openFiles := db.CacheCapacities()
	if blockBytes != 64*opt.MiB || openFiles != 1024 {
		t.Fatalf("capacities: got %d/%d", blockBytes, openFiles)
	}

	// Config() must return a caller-shaped config: cachers stripped.
	rc := db.Config()
	if rc.Options.BlockCacher != nil || rc.Options.OpenFilesCacher != nil {
		t.Fatal("Config() leaked shared cachers")
	}
	if ro := rc.DBOptions[OrdinalDB]; ro.BlockCacher != nil || ro.OpenFilesCacher != nil {
		t.Fatal("Config() leaked per-DB shared cachers")
	}

	// Databases must be usable with shared caches and overrides.
	if err := db.pool[OrdinalDB].Put([]byte("k"), []byte("v"), nil); err != nil {
		t.Fatal(err)
	}
	v, err := db.pool[OrdinalDB].Get([]byte("k"), nil)
	if err != nil || string(v) != "v" {
		t.Fatalf("get: %v %q", err, v)
	}
}

// TestSharedCachesReopen proves a close/reopen cycle through Config()
// constructs fresh shared caches instead of resurrecting the previous
// instance's — the upgrade paths reopen exactly this way.
func TestSharedCachesReopen(t *testing.T) {
	cfg := NewDefaultConfig(t.TempDir())
	cfg.BlockCacheCapacity = 16 * opt.MiB
	cfg.OpenFilesCacheCapacity = 512

	db1, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := db1.blockCacher
	rcfg := db1.Config()
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	db2, err := New(t.Context(), &rcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db2.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	if db2.blockCacher == nil || db2.blockCacher == first {
		t.Fatal("reopen did not construct a fresh shared cache")
	}
	blockBytes, openFiles := db2.CacheCapacities()
	if blockBytes != 16*opt.MiB || openFiles != 512 {
		t.Fatalf("reopen capacities: got %d/%d", blockBytes, openFiles)
	}
}

// TestSharedCachesCombinations covers the four capacity combinations.
func TestSharedCachesCombinations(t *testing.T) {
	tests := []struct {
		name       string
		blockBytes int
		openFiles  int
		wantBlock  bool
		wantFiles  bool
	}{
		{"both", 8 * opt.MiB, 128, true, true},
		{"blockOnly", 8 * opt.MiB, 0, true, false},
		{"filesOnly", 0, 128, false, true},
		{"neither", 0, 0, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewDefaultConfig(t.TempDir())
			cfg.BlockCacheCapacity = tt.blockBytes
			cfg.OpenFilesCacheCapacity = tt.openFiles
			db, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}()
			if (db.blockCacher != nil) != tt.wantBlock {
				t.Fatalf("blockCacher: %v, want %v", db.blockCacher != nil, tt.wantBlock)
			}
			if (db.fileCacher != nil) != tt.wantFiles {
				t.Fatalf("fileCacher: %v, want %v", db.fileCacher != nil, tt.wantFiles)
			}
			if cfg.Options.BlockCacher != nil || cfg.Options.OpenFilesCacher != nil {
				t.Fatal("caller config mutated")
			}
			gotBlock, gotFiles := db.CacheCapacities()
			if gotBlock != tt.blockBytes || gotFiles != tt.openFiles {
				t.Fatalf("capacities: %d/%d", gotBlock, gotFiles)
			}
		})
	}
}

// TestSharedCachesRespectExplicit: an explicitly provided cacher wins
// and the shared capacity is honestly reported as not in effect.
func TestSharedCachesRespectExplicit(t *testing.T) {
	cfg := NewDefaultConfig(t.TempDir())
	cfg.BlockCacheCapacity = 8 * opt.MiB
	cfg.OpenFilesCacheCapacity = 512
	private := opt.NewLRU(opt.MiB)
	privateFiles := opt.NewLRU(64)
	cfg.Options.BlockCacher = private
	cfg.Options.OpenFilesCacher = privateFiles

	db, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if db.cfg.Options.BlockCacher != private ||
		db.cfg.Options.OpenFilesCacher != privateFiles {
		t.Fatal("explicitly set cachers must not be overwritten")
	}
	if db.blockCacher != nil || db.fileCacher != nil {
		t.Fatal("shared cachers must not be created alongside explicit ones")
	}
	blockBytes, openFiles := db.CacheCapacities()
	if blockBytes != 0 || openFiles != 0 {
		t.Fatalf("capacities must report not-in-effect: %d/%d", blockBytes, openFiles)
	}
}

// TestOpenDBConsumesOverride proves openDB actually applies per-DB
// overrides by making one database read-only and asserting writes fail
// there while succeeding elsewhere.
func TestOpenDBConsumesOverride(t *testing.T) {
	home := t.TempDir()
	// Create the databases first; a ReadOnly open cannot create.
	cfg := NewDefaultConfig(home)
	db, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	cfg2 := NewDefaultConfig(home)
	ro := cfg2.Options
	ro.ReadOnly = true
	cfg2.DBOptions = map[string]opt.Options{MetadataDB: ro}
	db2, err := New(t.Context(), cfg2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db2.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	if err := db2.pool[MetadataDB].Put([]byte("k"), []byte("v"), nil); err == nil {
		t.Fatal("write to read-only override succeeded; override not consumed")
	}
	if err := db2.pool[OrdinalDB].Put([]byte("k"), []byte("v"), nil); err != nil {
		t.Fatalf("write to non-override database failed: %v", err)
	}
}

// TestFileLimitWarning drives checkFileLimit's warning branch with a
// pool size no realistic RLIMIT_NOFILE can cover and asserts the
// warning is actually emitted.
func TestFileLimitWarning(t *testing.T) {
	var (
		mtx    sync.Mutex
		warned bool
	)
	if err := loggo.RegisterWriter("fdlimit-test", loggo.NewMinimumLevelWriter(
		loggofn(func(entry loggo.Entry) {
			if strings.Contains(entry.Message, "file descriptor limit") {
				mtx.Lock()
				warned = true
				mtx.Unlock()
			}
		}), loggo.WARNING)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := loggo.RemoveWriter("fdlimit-test"); err != nil {
			t.Fatal(err)
		}
	}()

	cfg := NewDefaultConfig(t.TempDir())
	cfg.OpenFilesCacheCapacity = 1 << 40
	db, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	mtx.Lock()
	got := warned
	mtx.Unlock()
	if !got {
		t.Fatal("file descriptor limit warning not emitted")
	}
	// The warning is advisory; opening and using the databases must
	// still work.
	if err := db.pool[MetadataDB].Put([]byte("k"), []byte("v"), nil); err != nil {
		t.Fatal(err)
	}
}

// loggofn adapts a func to loggo.Writer.
type loggofn func(entry loggo.Entry)

func (f loggofn) Write(entry loggo.Entry) { f(entry) }
