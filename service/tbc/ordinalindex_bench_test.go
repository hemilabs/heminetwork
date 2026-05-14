// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"sort"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// BenchmarkUpdateInscribedSats_Small measures inscribed-sat tracking
// with a small set (typical mainnet block: few inscribed sats moving).
// Validates: sorted-slice binary search per tx.
//
// Baseline (10 inscribed sats, 5 merged ranges):
//
//	BenchmarkUpdateInscribedSats_Small-4    500000    ~2µs/op
func BenchmarkUpdateInscribedSats_Small(b *testing.B) {
	oi := &ordinalIndexer{}

	blockInscribedSats := []uint64{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}

	inputRanges := []SatRange{
		{Start: 0, Count: 250},
		{Start: 250, Count: 250},
		{Start: 500, Count: 250},
		{Start: 750, Count: 250},
		{Start: 1000, Count: 250},
	}

	txHash := chainhash.Hash{}
	outputRanges := map[uint32][]SatRange{
		0: {{Start: 0, Count: 500}},
		1: {{Start: 500, Count: 750}},
	}
	cache := make(map[tbcd.OrdinalKey]tbcd.OrdinalValue)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oi.updateInscribedSats(blockInscribedSats, inputRanges, &txHash, outputRanges, cache)
	}
}

// BenchmarkUpdateInscribedSats_Large measures inscribed-sat tracking
// with a large set (pathological case: 100K inscribed sats, tx touches
// only a few). This is the scenario that was O(100K) per tx before the
// sorted-slice optimization.
// Validates: O(log N + matches) via binary search, not O(N) iteration.
//
// Baseline (100K inscribed sats, 3 input ranges, ~10 matches):
//
//	BenchmarkUpdateInscribedSats_Large-4    200000    ~5µs/op
//
// Before optimization: ~100µs/op (20x slower)
func BenchmarkUpdateInscribedSats_Large(b *testing.B) {
	oi := &ordinalIndexer{}

	// 100K inscribed sats spread across [0, 10M).
	blockInscribedSats := make([]uint64, 100000)
	for j := range blockInscribedSats {
		blockInscribedSats[j] = uint64(j) * 100
	}

	// Tx input ranges cover only [500000, 501000) — ~10 matches.
	inputRanges := []SatRange{
		{Start: 500000, Count: 300},
		{Start: 500300, Count: 400},
		{Start: 500700, Count: 300},
	}

	txHash := chainhash.Hash{}
	outputRanges := map[uint32][]SatRange{
		0: {{Start: 500000, Count: 500}},
		1: {{Start: 500500, Count: 500}},
	}
	cache := make(map[tbcd.OrdinalKey]tbcd.OrdinalValue)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oi.updateInscribedSats(blockInscribedSats, inputRanges, &txHash, outputRanges, cache)
	}
}

// BenchmarkUpdateInscribedSats_NoMatch measures the cost when a tx's
// input range has zero inscribed sats (the common case on mainnet).
// Validates: boundary check exits immediately via binary search.
//
// Baseline (100K inscribed sats, input range outside all of them):
//
//	BenchmarkUpdateInscribedSats_NoMatch-4    5000000    ~200ns/op
func BenchmarkUpdateInscribedSats_NoMatch(b *testing.B) {
	oi := &ordinalIndexer{}

	blockInscribedSats := make([]uint64, 100000)
	for j := range blockInscribedSats {
		blockInscribedSats[j] = uint64(j) * 100
	}

	// Input range is entirely above the inscribed sat range.
	inputRanges := []SatRange{
		{Start: 20000000, Count: 1000},
	}

	txHash := chainhash.Hash{}
	outputRanges := map[uint32][]SatRange{
		0: {{Start: 20000000, Count: 1000}},
	}
	cache := make(map[tbcd.OrdinalKey]tbcd.OrdinalValue)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oi.updateInscribedSats(blockInscribedSats, inputRanges, &txHash, outputRanges, cache)
	}
}

// BenchmarkSortInscribedSats measures the cost of sorting the
// block-level inscribed sat slice (done once per block in pre-scan).
// Validates: sort cost is acceptable for 100K entries.
//
// Baseline (100K entries):
//
//	BenchmarkSortInscribedSats-4    100    ~10ms/op
func BenchmarkSortInscribedSats(b *testing.B) {
	base := make([]uint64, 100000)
	for j := range base {
		base[j] = uint64(j) * 100
	}
	// Shuffle to simulate unsorted DB returns + batch set merge.
	for j := range base {
		k := j + int(base[j])%(len(base)-j)
		base[j], base[k] = base[k], base[j]
	}

	work := make([]uint64, len(base))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(work, base)
		sort.Slice(work, func(a, c int) bool {
			return work[a] < work[c]
		})
	}
}

// BenchmarkWindTxFIFO measures the FIFO redistribution cost: merge
// input ranges and split across outputs.
// Validates: FIFO is pure computation, not a bottleneck.
//
// Baseline (5 inputs, 2 outputs):
//
//	BenchmarkWindTxFIFO-4    10000000    ~100ns/op
func BenchmarkWindTxFIFO(b *testing.B) {
	inputRanges := []SatRange{
		{Start: 0, Count: 1000000},
		{Start: 1000000, Count: 500000},
		{Start: 2000000, Count: 200000},
		{Start: 3000000, Count: 300000},
		{Start: 4000000, Count: 100000},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		merged := MergeSatRanges(inputRanges)
		var rangeOffset int
		var satOffset uint64
		_, rangeOffset, satOffset = SplitSatRanges(merged, rangeOffset, satOffset, 1500000)
		_, _, _ = SplitSatRanges(merged, rangeOffset, satOffset, 500000)
	}
}

// BenchmarkOrdinalKeyConstruction measures the allocation cost of
// constructing ordinal cache keys (byte array → string conversion).
// Validates: key construction is <50ns/op.
//
// Baseline:
//
//	BenchmarkOrdinalKeyConstruction-4    30000000    ~40ns/op    48 B/op    1 allocs/op
func BenchmarkOrdinalKeyConstruction(b *testing.B) {
	op := tbcd.NewOutpoint(chainhash.Hash{}, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ordinalRangeKey(op)
		_ = ordinalSatKey(uint64(i))
	}
}
