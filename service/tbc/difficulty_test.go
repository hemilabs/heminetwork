// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
)

func newDifficultyTestServer(t *testing.T, params *chaincfg.Params) *Server {
	t.Helper()

	home := t.TempDir()
	cfg, err := level.NewConfig("mainnet", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := level.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})

	err = db.BlockHeaderGenesisInsert(t.Context(), params.GenesisBlock.Header, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	return &Server{
		cfg: &Config{},
		g: geometryParams{
			db:    db,
			chain: params,
		},
	}
}

// insertHeaders inserts a slice of wire headers into the DB as a connected chain.
func insertHeaders(t *testing.T, s *Server, headers []*wire.BlockHeader) {
	t.Helper()

	const batchSize = 2000
	for i := 0; i < len(headers); i += batchSize {
		end := i + batchSize
		if end > len(headers) {
			end = len(headers)
		}
		msg := wire.NewMsgHeaders()
		for _, h := range headers[i:end] {
			if err := msg.AddBlockHeader(h); err != nil {
				t.Fatal(err)
			}
		}
		_, _, _, _, err := s.g.db.BlockHeadersInsert(t.Context(), msg, nil)
		if err != nil {
			t.Fatalf("insert batch at offset %d: %v", i, err)
		}
	}
}

// makeChain creates count headers chained from prevBlock with the given bits
// and spacing between timestamps.
func makeChain(count int, prevBlock wire.BlockHeader, bits uint32, spacing time.Duration) []*wire.BlockHeader {
	headers := make([]*wire.BlockHeader, count)
	prevHash := prevBlock.BlockHash()
	prevTs := prevBlock.Timestamp
	for i := range headers {
		hdr := &wire.BlockHeader{
			Version:   1,
			PrevBlock: prevHash,
			Timestamp: prevTs.Add(spacing),
			Bits:      bits,
			Nonce:     uint32(i + 1),
		}
		headers[i] = hdr
		prevHash = hdr.BlockHash()
		prevTs = hdr.Timestamp
	}
	return headers
}

// computeRetargetBits replicates btcd's retarget calculation so we can
// predict what bits block 2016 should have.
func computeRetargetBits(oldBits uint32, actualTimespan int64, params *chaincfg.Params) uint32 {
	targetTimespan := int64(params.TargetTimespan / time.Second)
	minTimespan := targetTimespan / params.RetargetAdjustmentFactor
	maxTimespan := targetTimespan * params.RetargetAdjustmentFactor

	adjusted := actualTimespan
	if adjusted < minTimespan {
		adjusted = minTimespan
	} else if adjusted > maxTimespan {
		adjusted = maxTimespan
	}

	oldTarget := blockchain.CompactToBig(oldBits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(adjusted))
	newTarget.Div(newTarget, big.NewInt(targetTimespan))

	if newTarget.Cmp(params.PowLimit) > 0 {
		newTarget.Set(params.PowLimit)
	}

	return blockchain.BigToCompact(newTarget)
}

func TestVerifyDifficultyRetargetPass(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	headers := makeChain(5, chaincfg.MainNetParams.GenesisBlock.Header,
		chaincfg.MainNetParams.PowLimitBits, 10*time.Minute)

	if err := s.verifyHeaderContext(t.Context(), headers); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
}

func TestVerifyDifficultyRetargetBadBits(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	headers := makeChain(5, chaincfg.MainNetParams.GenesisBlock.Header,
		chaincfg.MainNetParams.PowLimitBits, 10*time.Minute)
	headers[2].Bits = 0x1c00ffff

	if err := s.verifyHeaderContext(t.Context(), headers); err == nil {
		t.Fatal("expected difficulty error for bad bits")
	}
}

func TestVerifyDifficultyRetargetSkipsRegtest(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.RegressionNetParams)

	headers := makeChain(3, chaincfg.RegressionNetParams.GenesisBlock.Header,
		0xdeadbeef, 10*time.Minute)

	if err := s.verifyHeaderContext(t.Context(), headers); err != nil {
		t.Fatalf("regtest should skip check, got: %v", err)
	}
}

func TestVerifyDifficultyRetargetEmpty(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	if err := s.verifyHeaderContext(t.Context(), nil); err != nil {
		t.Fatalf("empty headers should pass, got: %v", err)
	}
}

func TestVerifyDifficultyRetargetMultiBatch(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	bits := chaincfg.MainNetParams.PowLimitBits
	batch1 := makeChain(15, chaincfg.MainNetParams.GenesisBlock.Header,
		bits, 10*time.Minute)
	insertHeaders(t, s, batch1)

	batch2 := makeChain(5, *batch1[len(batch1)-1], bits, 10*time.Minute)
	if err := s.verifyHeaderContext(t.Context(), batch2); err != nil {
		t.Fatalf("cross-batch verification should pass: %v", err)
	}
}

func TestVerifyDifficultyRetargetMedianTime(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header

	batch1 := makeChain(15, genesis, bits, 10*time.Minute)
	insertHeaders(t, s, batch1)

	lastHdr := batch1[len(batch1)-1]
	prevHash := lastHdr.BlockHash()
	badHdr := &wire.BlockHeader{
		Version:   1,
		PrevBlock: prevHash,
		Timestamp: genesis.Timestamp.Add(-1 * time.Hour),
		Bits:      bits,
		Nonce:     999,
	}

	err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{badHdr})
	if err == nil {
		t.Fatal("expected median time error for backdated header")
	}
}

// TestVerifyDifficultyRetargetBoundary exercises the actual retarget
// calculation at block 2016. It builds 2015 headers on top of mainnet
// genesis, then verifies block 2016 with the correctly computed new bits.
func TestVerifyDifficultyRetargetBoundary(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header

	// Build blocks 1-2015 with 8-minute spacing (faster than 10-min
	// target, so difficulty should increase at the retarget).
	pre := makeChain(2015, genesis, bits, 8*time.Minute)
	insertHeaders(t, s, pre)

	// Compute the actual timespan: block[2015].Timestamp - block[0].Timestamp
	actualTimespan := pre[len(pre)-1].Timestamp.Unix() - genesis.Timestamp.Unix()
	expectedBits := computeRetargetBits(bits, actualTimespan, &chaincfg.MainNetParams)
	t.Logf("retarget: actualTimespan=%ds targetTimespan=%ds oldBits=0x%08x newBits=0x%08x",
		actualTimespan, int64(chaincfg.MainNetParams.TargetTimespan/time.Second),
		bits, expectedBits)

	if expectedBits == bits {
		t.Fatal("test setup: expected bits to change at retarget")
	}

	// Block 2016 with correct retarget bits should pass.
	prevHash := pre[len(pre)-1].BlockHash()
	hdr2016 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: prevHash,
		Timestamp: pre[len(pre)-1].Timestamp.Add(10 * time.Minute),
		Bits:      expectedBits,
		Nonce:     1,
	}
	if err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdr2016}); err != nil {
		t.Fatalf("correct retarget bits should pass: %v", err)
	}

	// Block 2016 with old (wrong) bits should fail.
	hdr2016bad := *hdr2016
	hdr2016bad.Bits = bits
	hdr2016bad.Nonce = 2
	if err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{&hdr2016bad}); err == nil {
		t.Fatal("old bits at retarget boundary should be rejected")
	}
}

// TestVerifyDifficultyRetargetBoundaryBatch tests that a batch of headers
// spanning a retarget boundary is verified correctly: blocks before the
// boundary keep old bits, the block at the boundary gets new bits.
func TestVerifyDifficultyRetargetBoundaryBatch(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header
	spacing := 8 * time.Minute

	// Insert blocks 1-2010 into the DB.
	pre := makeChain(2010, genesis, bits, spacing)
	insertHeaders(t, s, pre)

	// Build a batch of 10 headers: blocks 2011-2015 (old bits) + blocks
	// 2016-2020 (new bits). The retarget happens at block 2016.
	lastInserted := pre[len(pre)-1]

	// Blocks 2011-2015: same bits.
	beforeRetarget := makeChain(5, *lastInserted, bits, spacing)

	// Compute the actual timespan as btcd would see it:
	// block[2015].Timestamp - block[0].Timestamp
	block2015Ts := beforeRetarget[len(beforeRetarget)-1].Timestamp
	actualTimespan := block2015Ts.Unix() - genesis.Timestamp.Unix()
	expectedBits := computeRetargetBits(bits, actualTimespan, &chaincfg.MainNetParams)

	// Blocks 2016-2020: new bits.
	afterRetarget := makeChain(5, *beforeRetarget[len(beforeRetarget)-1],
		expectedBits, spacing)

	batch := append(beforeRetarget, afterRetarget...)
	if err := s.verifyHeaderContext(t.Context(), batch); err != nil {
		t.Fatalf("batch spanning retarget boundary should pass: %v", err)
	}

	// Same batch but with wrong bits after the retarget should fail.
	badAfter := makeChain(5, *beforeRetarget[len(beforeRetarget)-1],
		bits, spacing)
	badBatch := append(beforeRetarget, badAfter...)
	if err := s.verifyHeaderContext(t.Context(), badBatch); err == nil {
		t.Fatal("batch with wrong bits after retarget should be rejected")
	}
}

// TestVerifyDifficultyRetargetFork tests that difficulty verification works
// correctly when a fork exists in the database. Two chains diverge before
// the retarget boundary with different block spacings, producing different
// expected difficulties. Headers on each fork must be verified against
// their own chain's ancestors, not the other fork's.
func TestVerifyDifficultyRetargetFork(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header

	// Shared prefix: blocks 1-2000 with 10-minute spacing.
	shared := makeChain(2000, genesis, bits, 10*time.Minute)
	insertHeaders(t, s, shared)
	forkPoint := shared[len(shared)-1]

	// Chain A: blocks 2001-2015 with 5-minute spacing (fast).
	chainA := makeChain(15, *forkPoint, bits, 5*time.Minute)
	insertHeaders(t, s, chainA)

	aTimespan := chainA[len(chainA)-1].Timestamp.Unix() - genesis.Timestamp.Unix()
	aBits := computeRetargetBits(bits, aTimespan, &chaincfg.MainNetParams)

	// Chain B: blocks 2001-2015 with 8-minute spacing (less fast),
	// different nonces to produce different block hashes.
	chainB := make([]*wire.BlockHeader, 15)
	prevHash := forkPoint.BlockHash()
	prevTs := forkPoint.Timestamp
	for i := range chainB {
		hdr := &wire.BlockHeader{
			Version:   1,
			PrevBlock: prevHash,
			Timestamp: prevTs.Add(8 * time.Minute),
			Bits:      bits,
			Nonce:     uint32(10000 + i),
		}
		chainB[i] = hdr
		prevHash = hdr.BlockHash()
		prevTs = hdr.Timestamp
	}
	insertHeaders(t, s, chainB)

	bTimespan := chainB[len(chainB)-1].Timestamp.Unix() - genesis.Timestamp.Unix()
	bBits := computeRetargetBits(bits, bTimespan, &chaincfg.MainNetParams)

	t.Logf("chain A bits: 0x%08x  chain B bits: 0x%08x", aBits, bBits)
	if aBits == bBits {
		t.Fatal("test setup: fork chains should produce different retarget bits")
	}

	// Block 2016 on chain A with chain A's expected bits should pass.
	hdrA := &wire.BlockHeader{
		Version:   1,
		PrevBlock: chainA[len(chainA)-1].BlockHash(),
		Timestamp: chainA[len(chainA)-1].Timestamp.Add(10 * time.Minute),
		Bits:      aBits,
		Nonce:     1,
	}
	if err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdrA}); err != nil {
		t.Fatalf("chain A retarget should pass: %v", err)
	}

	// Block 2016 on chain B with chain B's expected bits should pass.
	hdrB := &wire.BlockHeader{
		Version:   1,
		PrevBlock: chainB[len(chainB)-1].BlockHash(),
		Timestamp: chainB[len(chainB)-1].Timestamp.Add(10 * time.Minute),
		Bits:      bBits,
		Nonce:     1,
	}
	if err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdrB}); err != nil {
		t.Fatalf("chain B retarget should pass: %v", err)
	}

	// Cross-check: chain A's bits on chain B should fail.
	hdrBwrong := *hdrB
	hdrBwrong.Bits = aBits
	hdrBwrong.Nonce = 2
	if err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{&hdrBwrong}); err == nil {
		t.Fatal("chain A bits on chain B should be rejected")
	}

	// Cross-check: chain B's bits on chain A should fail.
	hdrAwrong := *hdrA
	hdrAwrong.Bits = bBits
	hdrAwrong.Nonce = 3
	if err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{&hdrAwrong}); err == nil {
		t.Fatal("chain B bits on chain A should be rejected")
	}
}

// --- E2E tests ---
//
// These exercise the full Server through AddExternalHeaders rather than
// calling verifyHeaderContext directly.

func newE2EDifficultyServer(t *testing.T, network string) *Server {
	t.Helper()

	cfg := NewDefaultConfig()
	cfg.LevelDBHome = t.TempDir()
	cfg.ExternalHeaderMode = true
	cfg.Network = network
	cfg.BlockCacheSize = ""
	cfg.HeaderCacheSize = ""
	cfg.MempoolEnabled = false

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { s.dbClose() })

	stateId := [32]byte{0x01}
	if err := s.ExternalHeaderSetup(t.Context(), stateId[:]); err != nil {
		t.Fatal(err)
	}
	return s
}

func addExternalHeaders(t *testing.T, s *Server, headers []*wire.BlockHeader) (tbcd.InsertType, error) {
	t.Helper()

	const batchSize = 2000
	var lastIT tbcd.InsertType
	for i := 0; i < len(headers); i += batchSize {
		end := i + batchSize
		if end > len(headers) {
			end = len(headers)
		}
		msg := &wire.MsgHeaders{Headers: headers[i:end]}
		stateId := [32]byte{byte(i/batchSize + 2)}
		it, _, _, _, err := s.AddExternalHeaders(t.Context(), msg, stateId[:])
		if err != nil {
			return it, err
		}
		lastIT = it
	}
	return lastIT, nil
}

// TestE2EDifficultyRetargetAccept feeds 2016 mainnet-like headers through
// AddExternalHeaders and verifies that block 2016 with correct retarget
// bits is accepted through the full server stack.
func TestE2EDifficultyRetargetAccept(t *testing.T) {
	s := newE2EDifficultyServer(t, "mainnet")

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header
	spacing := 8 * time.Minute

	// Insert blocks 1-2015.
	pre := makeChain(2015, genesis, bits, spacing)
	if _, err := addExternalHeaders(t, s, pre); err != nil {
		t.Fatalf("inserting pre-retarget headers: %v", err)
	}

	// Compute expected retarget bits.
	actualTimespan := pre[len(pre)-1].Timestamp.Unix() - genesis.Timestamp.Unix()
	expectedBits := computeRetargetBits(bits, actualTimespan, &chaincfg.MainNetParams)

	// Block 2016 with correct bits.
	hdr2016 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: pre[len(pre)-1].BlockHash(),
		Timestamp: pre[len(pre)-1].Timestamp.Add(spacing),
		Bits:      expectedBits,
		Nonce:     1,
	}
	it, err := addExternalHeaders(t, s, []*wire.BlockHeader{hdr2016})
	if err != nil {
		t.Fatalf("block 2016 with correct bits should be accepted: %v", err)
	}
	if it != tbcd.ITChainExtend {
		t.Fatalf("expected ITChainExtend, got %v", it)
	}

	// Verify best height is 2016.
	height, _, err := s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if height != 2016 {
		t.Fatalf("expected best height 2016, got %d", height)
	}
}

// TestE2EDifficultyRetargetReject verifies that AddExternalHeaders rejects
// a header at the retarget boundary with wrong difficulty bits.
func TestE2EDifficultyRetargetReject(t *testing.T) {
	s := newE2EDifficultyServer(t, "mainnet")

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header
	spacing := 8 * time.Minute

	pre := makeChain(2015, genesis, bits, spacing)
	if _, err := addExternalHeaders(t, s, pre); err != nil {
		t.Fatalf("inserting pre-retarget headers: %v", err)
	}

	// Block 2016 with old (wrong) bits.
	hdr2016 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: pre[len(pre)-1].BlockHash(),
		Timestamp: pre[len(pre)-1].Timestamp.Add(spacing),
		Bits:      bits,
		Nonce:     1,
	}
	it, err := addExternalHeaders(t, s, []*wire.BlockHeader{hdr2016})
	if err == nil {
		t.Fatal("block 2016 with wrong bits should be rejected")
	}
	if it != tbcd.ITInvalid {
		t.Fatalf("expected ITInvalid, got %v", it)
	}

	// Best height should still be 2015 — the bad header was not inserted.
	height, _, err := s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if height != 2015 {
		t.Fatalf("expected best height 2015 after rejection, got %d", height)
	}
}

// TestE2EDifficultyFork creates two competing chains through
// AddExternalHeaders with different block timings, verifying that each
// fork's retarget is evaluated independently through the full server.
func TestE2EDifficultyFork(t *testing.T) {
	s := newE2EDifficultyServer(t, "mainnet")

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header

	// Shared prefix: blocks 1-2000.
	shared := makeChain(2000, genesis, bits, 10*time.Minute)
	if _, err := addExternalHeaders(t, s, shared); err != nil {
		t.Fatalf("inserting shared prefix: %v", err)
	}
	forkPoint := shared[len(shared)-1]

	// Chain A: blocks 2001-2015 fast (5min), block 2016 with retarget.
	chainA := makeChain(15, *forkPoint, bits, 5*time.Minute)
	if _, err := addExternalHeaders(t, s, chainA); err != nil {
		t.Fatalf("inserting chain A: %v", err)
	}
	aTimespan := chainA[len(chainA)-1].Timestamp.Unix() - genesis.Timestamp.Unix()
	aBits := computeRetargetBits(bits, aTimespan, &chaincfg.MainNetParams)

	hdrA2016 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: chainA[len(chainA)-1].BlockHash(),
		Timestamp: chainA[len(chainA)-1].Timestamp.Add(10 * time.Minute),
		Bits:      aBits,
		Nonce:     1,
	}
	it, err := addExternalHeaders(t, s, []*wire.BlockHeader{hdrA2016})
	if err != nil {
		t.Fatalf("chain A block 2016 should be accepted: %v", err)
	}
	if it != tbcd.ITChainExtend {
		t.Fatalf("chain A: expected ITChainExtend, got %v", it)
	}

	// Chain B: blocks 2001-2015 slower (8min), different nonces.
	chainB := make([]*wire.BlockHeader, 15)
	prevHash := forkPoint.BlockHash()
	prevTs := forkPoint.Timestamp
	for i := range chainB {
		hdr := &wire.BlockHeader{
			Version:   1,
			PrevBlock: prevHash,
			Timestamp: prevTs.Add(8 * time.Minute),
			Bits:      bits,
			Nonce:     uint32(20000 + i),
		}
		chainB[i] = hdr
		prevHash = hdr.BlockHash()
		prevTs = hdr.Timestamp
	}
	if _, err := addExternalHeaders(t, s, chainB); err != nil {
		t.Fatalf("inserting chain B: %v", err)
	}
	bTimespan := chainB[len(chainB)-1].Timestamp.Unix() - genesis.Timestamp.Unix()
	bBits := computeRetargetBits(bits, bTimespan, &chaincfg.MainNetParams)

	t.Logf("chain A retarget bits: 0x%08x  chain B retarget bits: 0x%08x",
		aBits, bBits)

	// Chain B block 2016 with chain B's bits should be accepted.
	hdrB2016 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: chainB[len(chainB)-1].BlockHash(),
		Timestamp: chainB[len(chainB)-1].Timestamp.Add(10 * time.Minute),
		Bits:      bBits,
		Nonce:     1,
	}
	if _, err := addExternalHeaders(t, s, []*wire.BlockHeader{hdrB2016}); err != nil {
		t.Fatalf("chain B block 2016 should be accepted: %v", err)
	}

	// Chain B block 2016 with chain A's bits should be rejected.
	hdrBwrong := &wire.BlockHeader{
		Version:   1,
		PrevBlock: chainB[len(chainB)-1].BlockHash(),
		Timestamp: chainB[len(chainB)-1].Timestamp.Add(10 * time.Minute),
		Bits:      aBits,
		Nonce:     2,
	}
	if _, err := addExternalHeaders(t, s, []*wire.BlockHeader{hdrBwrong}); err == nil {
		t.Fatal("chain B with chain A's bits should be rejected")
	}
}

// newE2EEffectiveGenesisServer creates an ExternalHeaderMode server with an
// effective genesis at the given height. The genesis block uses mainnet params
// with PowLimitBits.
func newE2EEffectiveGenesisServer(t *testing.T, genesisHeight uint64) (*Server, wire.BlockHeader) {
	t.Helper()

	genesis := wire.BlockHeader{
		Version:   1,
		Timestamp: time.Unix(1231006505, 0), // same as real genesis
		Bits:      chaincfg.MainNetParams.PowLimitBits,
		Nonce:     1,
	}

	cfg := NewDefaultConfig()
	cfg.LevelDBHome = t.TempDir()
	cfg.ExternalHeaderMode = true
	cfg.Network = "mainnet"
	cfg.BlockCacheSize = ""
	cfg.HeaderCacheSize = ""
	cfg.MempoolEnabled = false
	cfg.EffectiveGenesisBlock = &genesis
	cfg.GenesisHeightOffset = genesisHeight
	cfg.GenesisDifficultyOffset = *big.NewInt(1)

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.dbClose() })

	stateId := [32]byte{0x01}
	if err := s.ExternalHeaderSetup(t.Context(), stateId[:]); err != nil {
		t.Fatal(err)
	}
	return s, genesis
}

// TestE2EEffectiveGenesisRetargetMidPeriod verifies header context
// verification when the effective genesis is mid-retarget-period (height
// 1000). The first retarget boundary at height 2016 has insufficient
// ancestor depth (1016 < 2016) so BFFastAdd applies. The second retarget
// at 4032 has enough depth (3032 >= 2016) for full verification.
func TestE2EEffectiveGenesisRetargetMidPeriod(t *testing.T) {
	const genesisHeight = 1000

	s, genesis := newE2EEffectiveGenesisServer(t, genesisHeight)

	bits := chaincfg.MainNetParams.PowLimitBits
	spacing := 10 * time.Minute

	// Heights 1001 through 2015.
	preRetarget1 := makeChain(2016-genesisHeight-1, genesis, bits, spacing)
	if _, err := addExternalHeaders(t, s, preRetarget1); err != nil {
		t.Fatalf("inserting pre-retarget-1 headers: %v", err)
	}

	height, _, err := s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if height != 2015 {
		t.Fatalf("expected best height 2015, got %d", height)
	}

	// Height 2016: first retarget boundary. Only 1016 blocks of ancestor
	// depth (< 2016), so BFFastAdd skips difficulty verification.
	lastPre := preRetarget1[len(preRetarget1)-1]
	hdr2016 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: lastPre.BlockHash(),
		Timestamp: lastPre.Timestamp.Add(spacing),
		Bits:      bits,
		Nonce:     1,
	}
	it, err := addExternalHeaders(t, s, []*wire.BlockHeader{hdr2016})
	if err != nil {
		t.Fatalf("height 2016 should be accepted (BFFastAdd): %v", err)
	}
	if it != tbcd.ITChainExtend {
		t.Fatalf("expected ITChainExtend, got %v", it)
	}
	t.Log("height 2016: accepted with BFFastAdd (insufficient ancestor depth)")

	// Heights 2017 to 4031.
	period2 := makeChain(4032-2016-1, *hdr2016, bits, spacing)
	if _, err := addExternalHeaders(t, s, period2); err != nil {
		t.Fatalf("inserting period-2 headers: %v", err)
	}

	height, _, err = s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if height != 4031 {
		t.Fatalf("expected best height 4031, got %d", height)
	}

	// Height 4032: second retarget. Ancestor depth is 3032 (>= 2016),
	// full verification applies.
	lastPeriod2 := period2[len(period2)-1]
	actualTimespan := lastPeriod2.Timestamp.Unix() - hdr2016.Timestamp.Unix()
	expectedBits := computeRetargetBits(bits, actualTimespan, &chaincfg.MainNetParams)

	hdr4032 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: lastPeriod2.BlockHash(),
		Timestamp: lastPeriod2.Timestamp.Add(spacing),
		Bits:      expectedBits,
		Nonce:     1,
	}
	it, err = addExternalHeaders(t, s, []*wire.BlockHeader{hdr4032})
	if err != nil {
		t.Fatalf("height 4032 with correct bits should be accepted: %v", err)
	}
	if it != tbcd.ITChainExtend {
		t.Fatalf("expected ITChainExtend, got %v", it)
	}
	t.Logf("height 4032: accepted with correct retarget bits 0x%08x", expectedBits)

	// Wrong bits at 4032 — must be rejected.
	hdr4032bad := &wire.BlockHeader{
		Version:   1,
		PrevBlock: lastPeriod2.BlockHash(),
		Timestamp: lastPeriod2.Timestamp.Add(spacing),
		Bits:      bits,
		Nonce:     2,
	}
	it, err = addExternalHeaders(t, s, []*wire.BlockHeader{hdr4032bad})
	if err == nil {
		t.Fatal("height 4032 with wrong bits should be rejected")
	}
	if it != tbcd.ITInvalid {
		t.Fatalf("expected ITInvalid, got %v", it)
	}
	t.Log("height 4032: correctly rejected wrong bits")

	height, _, err = s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if height != 4032 {
		t.Fatalf("expected best height 4032, got %d", height)
	}
}

// TestE2EEffectiveGenesisRetargetAligned verifies the edge case where the
// effective genesis falls exactly on a retarget boundary. In this case, the
// very first header batch starts a new retarget period and should use full
// verification from the start (ancestor depth = blocksPerRetarget at the
// next boundary).
func TestE2EEffectiveGenesisRetargetAligned(t *testing.T) {
	const genesisHeight = 2016 // exactly on a retarget boundary

	s, genesis := newE2EEffectiveGenesisServer(t, genesisHeight)

	bits := chaincfg.MainNetParams.PowLimitBits
	spacing := 10 * time.Minute

	// Build 2015 headers (heights 2017-4031).
	pre := makeChain(2015, genesis, bits, spacing)
	if _, err := addExternalHeaders(t, s, pre); err != nil {
		t.Fatalf("inserting pre-retarget headers: %v", err)
	}

	// Height 4032: retarget boundary. Depth from genesis = 4032-2016 =
	// 2016 which is exactly blocksPerRetarget, so full verification
	// should apply (headerHeight - genesisHeight = 4032-2016 = 2016
	// which is NOT < 2016).
	lastPre := pre[len(pre)-1]
	actualTimespan := lastPre.Timestamp.Unix() - genesis.Timestamp.Unix()
	expectedBits := computeRetargetBits(bits, actualTimespan, &chaincfg.MainNetParams)

	hdr4032 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: lastPre.BlockHash(),
		Timestamp: lastPre.Timestamp.Add(spacing),
		Bits:      expectedBits,
		Nonce:     1,
	}
	it, err := addExternalHeaders(t, s, []*wire.BlockHeader{hdr4032})
	if err != nil {
		t.Fatalf("height 4032 with correct bits should be accepted: %v", err)
	}
	if it != tbcd.ITChainExtend {
		t.Fatalf("expected ITChainExtend, got %v", it)
	}

	// Wrong bits should be rejected.
	hdr4032bad := &wire.BlockHeader{
		Version:   1,
		PrevBlock: lastPre.BlockHash(),
		Timestamp: lastPre.Timestamp.Add(spacing),
		Bits:      bits,
		Nonce:     2,
	}
	it, err = addExternalHeaders(t, s, []*wire.BlockHeader{hdr4032bad})
	if err == nil {
		t.Fatal("height 4032 with wrong bits should be rejected")
	}
	if it != tbcd.ITInvalid {
		t.Fatalf("expected ITInvalid, got %v", it)
	}
	t.Logf("retarget-aligned genesis: correctly verified at height 4032 (bits 0x%08x)", expectedBits)
}

// TestE2EEffectiveGenesisRetargetJustBelow verifies the boundary where the
// effective genesis is one block below a retarget boundary (height 2015).
// The first retarget at height 2016 has depth 2016-2015=1 which is < 2016,
// so BFFastAdd applies. The second retarget at 4032 has depth 2017 >= 2016,
// so full verification applies.
func TestE2EEffectiveGenesisRetargetJustBelow(t *testing.T) {
	const genesisHeight = 2015 // one block below retarget boundary

	s, genesis := newE2EEffectiveGenesisServer(t, genesisHeight)

	bits := chaincfg.MainNetParams.PowLimitBits
	spacing := 10 * time.Minute

	// Height 2016 is only 1 block after genesis — BFFastAdd is required
	// because RelativeAncestorCtx(2015) can't walk back far enough.
	hdr2016 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: genesis.BlockHash(),
		Timestamp: genesis.Timestamp.Add(spacing),
		Bits:      bits,
		Nonce:     1,
	}
	it, err := addExternalHeaders(t, s, []*wire.BlockHeader{hdr2016})
	if err != nil {
		t.Fatalf("height 2016 should be accepted (BFFastAdd, depth=1): %v", err)
	}
	if it != tbcd.ITChainExtend {
		t.Fatalf("expected ITChainExtend, got %v", it)
	}
	t.Log("height 2016: accepted with BFFastAdd (genesis at 2015, depth=1)")

	// Build heights 2017-4031 with consistent bits.
	period2 := makeChain(4032-2016-1, *hdr2016, bits, spacing)
	if _, err := addExternalHeaders(t, s, period2); err != nil {
		t.Fatalf("inserting period-2 headers: %v", err)
	}

	// Height 4032: depth = 4032-2015 = 2017 >= 2016, full verification.
	lastPeriod2 := period2[len(period2)-1]
	actualTimespan := lastPeriod2.Timestamp.Unix() - hdr2016.Timestamp.Unix()
	expectedBits := computeRetargetBits(bits, actualTimespan, &chaincfg.MainNetParams)

	hdr4032 := &wire.BlockHeader{
		Version:   1,
		PrevBlock: lastPeriod2.BlockHash(),
		Timestamp: lastPeriod2.Timestamp.Add(spacing),
		Bits:      expectedBits,
		Nonce:     1,
	}
	it, err = addExternalHeaders(t, s, []*wire.BlockHeader{hdr4032})
	if err != nil {
		t.Fatalf("height 4032 with correct bits should be accepted: %v", err)
	}
	if it != tbcd.ITChainExtend {
		t.Fatalf("expected ITChainExtend, got %v", it)
	}

	// Wrong bits at 4032 should be rejected.
	hdr4032bad := &wire.BlockHeader{
		Version:   1,
		PrevBlock: lastPeriod2.BlockHash(),
		Timestamp: lastPeriod2.Timestamp.Add(spacing),
		Bits:      bits,
		Nonce:     2,
	}
	it, err = addExternalHeaders(t, s, []*wire.BlockHeader{hdr4032bad})
	if err == nil {
		t.Fatal("height 4032 with wrong bits should be rejected")
	}
	if it != tbcd.ITInvalid {
		t.Fatalf("expected ITInvalid, got %v", it)
	}
	t.Logf("genesis at 2015: full verification at 4032 (bits 0x%08x)", expectedBits)
}

// --- Real mainnet E2E tests ---
//
// These use actual Bitcoin mainnet block headers downloaded from the
// network and stored in testdata/mainnet_headers.bin. The file contains
// blocks 1-32260 (genesis is in chaincfg). The first real difficulty
// change is at block 32256 (bits change from 0x1d00ffff to 0x1d00d86a).

const mainnetHeadersFile = "testdata/mainnet_headers.bin"

// loadMainnetHeaders reads the binary header file. The file format is:
// 4-byte LE count followed by count × 80-byte serialized headers.
// Returns headers for mainnet blocks 1..count.
func loadMainnetHeaders(t *testing.T) []*wire.BlockHeader {
	t.Helper()

	data, err := os.ReadFile(mainnetHeadersFile)
	if err != nil {
		t.Skipf("mainnet headers not available: %v "+
			"(run: go run testdata/fetchheaders.go)", err)
	}

	count := int(binary.LittleEndian.Uint32(data[:4]))
	data = data[4:]
	if len(data) != count*80 {
		t.Fatalf("header file corrupt: expected %d bytes, got %d",
			count*80, len(data))
	}

	headers := make([]*wire.BlockHeader, count)
	for i := range headers {
		hdr := &wire.BlockHeader{}
		if err := hdr.Deserialize(bytes.NewReader(data[i*80 : (i+1)*80])); err != nil {
			t.Fatalf("deserialize header at index %d: %v", i, err)
		}
		headers[i] = hdr
	}
	return headers
}

// TestE2ERealMainnetRetarget feeds 32260 real mainnet block headers
// through the full TBC server via AddExternalHeaders, covering the
// first real difficulty retarget at block 32256.
func TestE2ERealMainnetRetarget(t *testing.T) {
	headers := loadMainnetHeaders(t)
	if len(headers) < 32260 {
		t.Skipf("need at least 32260 headers, got %d", len(headers))
	}

	s := newE2EDifficultyServer(t, "mainnet")

	// Insert all 32260 headers in batches through AddExternalHeaders.
	if _, err := addExternalHeaders(t, s, headers[:32260]); err != nil {
		t.Fatalf("inserting real mainnet headers: %v", err)
	}

	// Verify best height.
	height, _, err := s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if height != 32260 {
		t.Fatalf("expected best height 32260, got %d", height)
	}

	// Verify the retarget happened: block 32256 should have different
	// bits than block 32255.
	if headers[32254].Bits == headers[32255].Bits {
		t.Fatalf("retarget sanity check failed: block 32255 bits 0x%08x == block 32256 bits 0x%08x",
			headers[32254].Bits, headers[32255].Bits)
	}
	t.Logf("retarget at height 32256: 0x%08x -> 0x%08x",
		headers[32254].Bits, headers[32255].Bits)
}

// TestE2ERealMainnetRejectBadRetarget loads real mainnet headers up to
// block 32255, then tries to insert a fake block 32256 with the old
// (wrong) difficulty bits. The server should reject it.
func TestE2ERealMainnetRejectBadRetarget(t *testing.T) {
	headers := loadMainnetHeaders(t)
	if len(headers) < 32260 {
		t.Skipf("need at least 32260 headers, got %d", len(headers))
	}

	s := newE2EDifficultyServer(t, "mainnet")

	// Insert blocks 1-32255 (all at difficulty 1).
	if _, err := addExternalHeaders(t, s, headers[:32255]); err != nil {
		t.Fatalf("inserting headers up to 32255: %v", err)
	}

	height, _, err := s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if height != 32255 {
		t.Fatalf("expected height 32255, got %d", height)
	}

	// The real block 32256 has bits 0x1d00d86a. Craft a fake one with
	// the old bits (0x1d00ffff) — this should be rejected.
	real32256 := headers[32255]
	fake32256 := *real32256
	fake32256.Bits = 0x1d00ffff
	fake32256.Nonce = 0xdeadbeef

	it, err := addExternalHeaders(t, s, []*wire.BlockHeader{&fake32256})
	if err == nil {
		t.Fatal("fake block 32256 with old difficulty should be rejected")
	}
	if it != tbcd.ITInvalid {
		t.Fatalf("expected ITInvalid, got %v", it)
	}

	// Now insert the real block 32256 — should succeed.
	if _, err := addExternalHeaders(t, s, []*wire.BlockHeader{real32256}); err != nil {
		t.Fatalf("real block 32256 should be accepted: %v", err)
	}
	height, _, err = s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if height != 32256 {
		t.Fatalf("expected height 32256, got %d", height)
	}
	t.Logf("real block 32256 accepted with bits 0x%08x", real32256.Bits)
}

// --- Negative path tests ---

func TestVerifyDifficultyRetargetUnknownParent(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	hdr := &wire.BlockHeader{
		Version:   1,
		PrevBlock: chainhash.Hash{0xde, 0xad},
		Timestamp: time.Now(),
		Bits:      chaincfg.MainNetParams.PowLimitBits,
		Nonce:     1,
	}

	err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdr})
	if err == nil {
		t.Fatal("should fail when parent hash is not in DB")
	}
	if !strings.Contains(err.Error(), "parent lookup") {
		t.Fatalf("expected parent lookup error, got: %v", err)
	}
}

func TestVerifyDifficultyRetargetTimestampAtMedian(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header

	pre := makeChain(15, genesis, bits, 10*time.Minute)
	insertHeaders(t, s, pre)

	// Header with timestamp exactly equal to the median (not after)
	// should be rejected. Median of blocks 5-15 is block 10's timestamp.
	lastHdr := pre[len(pre)-1]
	medianTs := pre[9].Timestamp
	hdr := &wire.BlockHeader{
		Version:   1,
		PrevBlock: lastHdr.BlockHash(),
		Timestamp: medianTs,
		Bits:      bits,
		Nonce:     1,
	}
	err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdr})
	if err == nil {
		t.Fatal("timestamp at median (not after) should be rejected")
	}
}

func TestVerifyDifficultyRetargetBadBitsMidBatch(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	bits := chaincfg.MainNetParams.PowLimitBits
	genesis := chaincfg.MainNetParams.GenesisBlock.Header

	headers := makeChain(10, genesis, bits, 10*time.Minute)
	// Corrupt bits at position 7 (mid-batch).
	headers[7].Bits = 0x17034567

	err := s.verifyHeaderContext(t.Context(), headers)
	if err == nil {
		t.Fatal("bad bits mid-batch should be rejected")
	}
	if !strings.Contains(err.Error(), "header 7") {
		t.Fatalf("error should identify header index 7, got: %v", err)
	}
}

func TestVerifyDifficultyRetargetBadBitsFirstHeader(t *testing.T) {
	s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

	genesis := chaincfg.MainNetParams.GenesisBlock.Header
	hdr := &wire.BlockHeader{
		Version:   1,
		PrevBlock: genesis.BlockHash(),
		Timestamp: genesis.Timestamp.Add(10 * time.Minute),
		Bits:      0x17034567,
		Nonce:     1,
	}

	err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdr})
	if err == nil {
		t.Fatal("bad bits on first header should be rejected")
	}
	if !strings.Contains(err.Error(), "header 0") {
		t.Fatalf("error should identify header index 0, got: %v", err)
	}
}

func TestE2ERealMainnetRejectEveryBitFlip(t *testing.T) {
	headers := loadMainnetHeaders(t)
	if len(headers) < 32260 {
		t.Skipf("need at least 32260 headers, got %d", len(headers))
	}

	s := newE2EDifficultyServer(t, "mainnet")

	// Insert up to block 32255 (just before the retarget).
	if _, err := addExternalHeaders(t, s, headers[:32255]); err != nil {
		t.Fatalf("inserting headers: %v", err)
	}

	realHeader := headers[32255]

	// Flip each bit in the Bits field and verify rejection.
	for bit := 0; bit < 32; bit++ {
		mutated := *realHeader
		mutated.Bits = realHeader.Bits ^ (1 << bit)
		mutated.Nonce = uint32(bit)

		_, err := addExternalHeaders(t, s, []*wire.BlockHeader{&mutated})
		if err == nil {
			t.Fatalf("bit flip %d: bits 0x%08x should be rejected (real: 0x%08x)",
				bit, mutated.Bits, realHeader.Bits)
		}
	}
}

// --- Fuzz tests ---

func FuzzVerifyDifficultyBits(f *testing.F) {
	// Seed corpus with known values.
	f.Add(chaincfg.MainNetParams.PowLimitBits)
	f.Add(uint32(0x1d00d86a))
	f.Add(uint32(0x17034567))
	f.Add(uint32(0))
	f.Add(uint32(0xFFFFFFFF))

	f.Fuzz(func(t *testing.T, bits uint32) {
		s := newDifficultyTestServer(t, &chaincfg.MainNetParams)
		genesis := chaincfg.MainNetParams.GenesisBlock.Header

		hdr := &wire.BlockHeader{
			Version:   1,
			PrevBlock: genesis.BlockHash(),
			Timestamp: genesis.Timestamp.Add(10 * time.Minute),
			Bits:      bits,
			Nonce:     1,
		}

		err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdr})

		// Only PowLimitBits should pass for block 1 on mainnet.
		if bits == chaincfg.MainNetParams.PowLimitBits {
			if err != nil {
				t.Fatalf("correct bits 0x%08x should pass: %v", bits, err)
			}
		} else {
			if err == nil {
				t.Fatalf("bits 0x%08x should be rejected", bits)
			}
		}
	})
}

func FuzzVerifyDifficultyTimestamp(f *testing.F) {
	genesis := chaincfg.MainNetParams.GenesisBlock.Header

	// Seed: valid timestamp, boundary cases.
	f.Add(genesis.Timestamp.Add(10 * time.Minute).Unix())
	f.Add(genesis.Timestamp.Unix())
	f.Add(genesis.Timestamp.Add(-1 * time.Hour).Unix())
	f.Add(int64(0))
	f.Add(int64(1 << 32))

	f.Fuzz(func(t *testing.T, tsUnix int64) {
		if tsUnix < 0 || tsUnix > 1<<33 {
			t.Skip()
		}

		s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

		hdr := &wire.BlockHeader{
			Version:   1,
			PrevBlock: genesis.BlockHash(),
			Timestamp: time.Unix(tsUnix, 0),
			Bits:      chaincfg.MainNetParams.PowLimitBits,
			Nonce:     1,
		}

		err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdr})

		// Block 1's median time is just genesis (one block), so any
		// timestamp strictly after genesis should pass.
		if tsUnix > genesis.Timestamp.Unix() {
			if err != nil {
				t.Fatalf("timestamp %d (after genesis %d) should pass: %v",
					tsUnix, genesis.Timestamp.Unix(), err)
			}
		} else {
			if err == nil {
				t.Fatalf("timestamp %d (not after genesis %d) should fail",
					tsUnix, genesis.Timestamp.Unix())
			}
		}
	})
}

func FuzzVerifyDifficultyRetargetBits(f *testing.F) {
	f.Add(chaincfg.MainNetParams.PowLimitBits)
	f.Add(uint32(0x1d00d86a))
	f.Add(uint32(0))

	f.Fuzz(func(t *testing.T, bits uint32) {
		s := newDifficultyTestServer(t, &chaincfg.MainNetParams)
		genesis := chaincfg.MainNetParams.GenesisBlock.Header
		spacing := 8 * time.Minute

		pre := makeChain(2015, genesis,
			chaincfg.MainNetParams.PowLimitBits, spacing)
		insertHeaders(t, s, pre)

		actualTimespan := pre[len(pre)-1].Timestamp.Unix() - genesis.Timestamp.Unix()
		expectedBits := computeRetargetBits(
			chaincfg.MainNetParams.PowLimitBits,
			actualTimespan, &chaincfg.MainNetParams)

		hdr := &wire.BlockHeader{
			Version:   1,
			PrevBlock: pre[len(pre)-1].BlockHash(),
			Timestamp: pre[len(pre)-1].Timestamp.Add(spacing),
			Bits:      bits,
			Nonce:     1,
		}

		err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdr})

		if bits == expectedBits {
			if err != nil {
				t.Fatalf("correct retarget bits 0x%08x should pass: %v",
					bits, err)
			}
		} else {
			if err == nil {
				t.Fatalf("bits 0x%08x should be rejected (expected 0x%08x)",
					bits, expectedBits)
			}
		}
	})
}
