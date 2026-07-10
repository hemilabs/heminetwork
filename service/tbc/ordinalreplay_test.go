// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"

	dblevel "github.com/hemilabs/heminetwork/v2/database/level"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
)

// procIO reads Linux /proc/self/io counters: syscall reads, bytes
// through read(2)-family calls, and bytes actually fetched from the
// storage layer (page-cache misses).
func procIO(t *testing.T) (syscr, rchar, readBytes int64) {
	b, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return 0, 0, 0 // non-Linux: deltas report zero
	}
	for _, line := range strings.Split(string(b), "\n") {
		var v int64
		if _, err := fmt.Sscanf(line, "syscr: %d", &v); err == nil {
			syscr = v
		}
		if _, err := fmt.Sscanf(line, "rchar: %d", &v); err == nil {
			rchar = v
		}
		if _, err := fmt.Sscanf(line, "read_bytes: %d", &v); err == nil {
			readBytes = v
		}
	}
	return syscr, rchar, readBytes
}

func dbProps(pr interface {
	LevelDBProperty(dbName, property string) (string, error)
}, dbName string,
) string {
	cached, _ := pr.LevelDBProperty(dbName, "leveldb.cachedblock")
	opened, _ := pr.LevelDBProperty(dbName, "leveldb.openedtables")
	return fmt.Sprintf("%s[cachedblk %s openedtbl %s]", dbName, cached, opened)
}

// TestWindReplay replays specific blocks through windBlock against a
// real database opened read-only: all the wind work — 'O' prefetch,
// parent value fetches, detection, positioning, placement into the
// in-memory cache — with nothing inserted into the database. This is
// the controlled instrument for diagnosing slow blocks: same bytes,
// same database state, repeatable, with per-pass timing (pass 1 =
// cold process caches, pass 2+ = warmed).
//
// Skipped unless TBC_REPLAY_HOME is set. The daemon must be stopped
// (leveldb lock). Environment:
//
//	TBC_REPLAY_HOME     tbcd home (e.g. ~/.tbcd), required
//	TBC_REPLAY_NETWORK  network directory (default mainnet)
//	TBC_REPLAY_HEIGHTS  comma-separated block heights, required
//	TBC_REPLAY_PASSES   replays per height (default 2)
//	TBC_REPLAY_WARM     "0" disables the warm phase (default on)
//
// Per pass the test also reports what the wind READ: syscall count,
// bytes through read(2), bytes actually fetched from disk
// (page-cache misses), and leveldb cached-block/opened-table counts
// for the ordinals and transactions databases.
//
// Fidelity caveat: replaying an already-wound height sees post-wind
// 'O' state (that block's own spends are tombstoned), so transfer
// detection differs from the original wind. Lookup COST is faithful:
// the dominant expense of dense blocks is per-input 'O' misses, and a
// miss costs what a miss costs. Reveals (envelope-driven) replay
// exactly.
func TestWindReplay(t *testing.T) {
	home := os.Getenv("TBC_REPLAY_HOME")
	if home == "" {
		t.Skip("set TBC_REPLAY_HOME to run the replay")
	}
	network := os.Getenv("TBC_REPLAY_NETWORK")
	if network == "" {
		network = "mainnet"
	}
	var heights []uint64
	for _, hs := range strings.Split(os.Getenv("TBC_REPLAY_HEIGHTS"), ",") {
		hs = strings.TrimSpace(hs)
		if hs == "" {
			continue
		}
		h, err := strconv.ParseUint(hs, 10, 32)
		if err != nil {
			t.Fatalf("bad height %q: %v", hs, err)
		}
		heights = append(heights, h)
	}
	if len(heights) == 0 {
		t.Fatal("set TBC_REPLAY_HEIGHTS")
	}
	passes := 2
	if ps := os.Getenv("TBC_REPLAY_PASSES"); ps != "" {
		p, err := strconv.Atoi(ps)
		if err != nil || p < 1 {
			t.Fatalf("bad passes %q", ps)
		}
		passes = p
	}
	warm := os.Getenv("TBC_REPLAY_WARM") != "0"

	ctx := t.Context()
	cfg, err := level.NewConfig(network, home, "2mb", "512mb")
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetReadOnly(true)
	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}()

	var chain *chaincfg.Params
	switch network {
	case "mainnet":
		chain = &chaincfg.MainNetParams
	case "testnet4":
		chain = &chaincfg.TestNet4Params
	default:
		t.Fatalf("unsupported replay network %q", network)
	}

	oi := NewOrdinalIndexer(ctx, geometryParams{db: db, chain: chain},
		OrdinalIndexerConfig{
			CacheLen:             2_000_000,
			Enabled:              true,
			WatermarkGap:         24 * time.Hour,
			OutputValueCacheSize: 256 << 20,
			Warm:                 warm,
		}).(*ordinalIndexer)

	t.Logf("replay: network=%s warm=%v passes=%d heights=%v",
		network, warm, passes, heights)
	for _, height := range heights {
		bhs, err := db.BlockHeadersByHeight(ctx, height)
		if err != nil {
			t.Fatalf("headers %d: %v", height, err)
		}
		hash := bhs[0].Hash
		b, err := db.BlockByHash(ctx, hash)
		if err != nil {
			t.Fatalf("block %d %v: %v", height, hash, err)
		}
		for p := 1; p <= passes; p++ {
			cache := NewOrdinalCache(4_000_000, 0)
			sc0, rc0, rb0 := procIO(t)
			t0 := time.Now()
			err := oi.windBlock(ctx, uint32(height), &hash, b, cache)
			el := time.Since(t0)
			sc1, rc1, rb1 := procIO(t)
			if err != nil {
				t.Fatalf("wind %d pass %d: %v", height, p, err)
			}
			t.Logf("height %d pass %d: %v entries %d warmed %d",
				height, p, el.Round(time.Millisecond), cache.Len(),
				oi.warmedParents)
			t.Logf("  io: %d read syscalls, %s read, %s from disk",
				sc1-sc0, ibytes(rc1-rc0), ibytes(rb1-rb0))
			t.Logf("  db: %s %s", dbProps(db, dblevel.OrdinalDB),
				dbProps(db, dblevel.TransactionsDB))
		}
	}
}

// ibytes renders a byte delta human-readably without pulling humanize
// into the test's assertions.
func ibytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2fGiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2fMiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
