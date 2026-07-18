// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"os"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

// The corpus in testdata/mainnet_headers_859303.bin is 3548 consecutive real
// mainnet block headers, heights 859303..862850 inclusive (80 bytes each,
// prefixed with a 4-byte little-endian count). It was captured from a real
// mainnet node and covers the first two difficulty retargets above the Hemi
// mainnet effective genesis.
const offsetGenesisHeadersFile = "testdata/mainnet_headers_859303.bin"

const (
	// offsetGenesisHeight is the real Bitcoin height of the Hemi mainnet
	// effective genesis (see mainnetHemiGenesis). It is NOT a multiple of
	// BlocksPerRetarget (859303 % 2016 == 487), which is the crux of the bug.
	offsetGenesisHeight = 859303
	// offsetGenesisBoundary is the first difficulty retarget boundary above
	// the effective genesis (2016 * 427). Its difficulty is derived from the
	// block 2016 earlier (858816), which is below the effective genesis.
	offsetGenesisBoundary = 860832
	// offsetGenesisTop is the last header in the corpus.
	offsetGenesisTop = 862850
)

// offsetGenesisChainworkHex is the cumulative Bitcoin chainwork at height
// 859303 (getblockheader .chainwork, leading zeroes trimmed). op-geth/hVM
// supplies this as Config.GenesisDifficultyOffset so chainwork accounting
// continues correctly despite the ~859k missing ancestors below genesis.
const offsetGenesisChainworkHex = "8bf76ab85613d9939b3d2ff0"

// offsetGenesisHash is block 859303 (must match mainnetHemiGenesis.Hash).
const offsetGenesisHash = "000000000000000000001d8132106b63876117569713ef4fe89d5a2f1173c66e"

func loadOffsetGenesisHeaders(t *testing.T) []*wire.BlockHeader {
	t.Helper()

	data, err := os.ReadFile(offsetGenesisHeadersFile)
	if err != nil {
		t.Skipf("headers not available: %v", err)
	}
	count := int(binary.LittleEndian.Uint32(data[:4]))
	data = data[4:]
	if len(data) != count*80 {
		t.Fatalf("header file corrupt: expected %d bytes, got %d", count*80, len(data))
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

// newOffsetGenesisServer builds an external-header-mode mainnet server whose
// effective genesis is a real, non-2016-aligned mainnet block (height 859303).
// This mirrors exactly how op-geth/hVM configures the embedded TBC instance on
// mainnet: it anchors at a hardcoded Bitcoin checkpoint rather than syncing
// from height 0.
func newOffsetGenesisServer(t *testing.T, genesis *wire.BlockHeader) *Server {
	t.Helper()

	work, ok := new(big.Int).SetString(offsetGenesisChainworkHex, 16)
	if !ok {
		t.Fatalf("bad chainwork hex %q", offsetGenesisChainworkHex)
	}

	cfg := NewDefaultConfig()
	cfg.LevelDBHome = t.TempDir()
	cfg.Network = "mainnet"
	cfg.ExternalHeaderMode = true
	cfg.BlockCacheSize = ""
	cfg.HeaderCacheSize = ""
	cfg.MempoolEnabled = false
	cfg.EffectiveGenesisBlock = genesis
	cfg.GenesisHeightOffset = offsetGenesisHeight
	cfg.GenesisDifficultyOffset = *work

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

// TestE2ERealMainnetOffsetGenesisRetarget reproduces, with real mainnet data,
// the offset-genesis retarget stall.
//
// It configures TBC exactly as hVM/op-geth does on mainnet: the effective
// genesis is real block 859303, which is NOT a multiple of BlocksPerRetarget
// (859303 % 2016 == 487). It then streams the real headers forward through the
// full Server via AddExternalHeaders.
//
// The first retarget boundary above the effective genesis is block 860832
// (2016*427). btcd's calcNextRequiredDifficulty computes its difficulty from
// firstNode = 860831.RelativeAncestorCtx(2015) = height 858816. Because
// 858816 < 859303, that ancestor is not in the DB and can never be: the
// PrevBlock walk terminates at the effective-genesis node (height 859303 > 0,
// so the height<=0 guard never fires) when BlockHeaderByHash(859302) returns
// NotFound, Parent() returns nil, and calcNextRequiredDifficulty returns
// AssertError("unable to obtain previous retarget block"). verifyHeaderContext
// then rejects a perfectly valid header, and a freshly bootstrapping node can
// never advance past 860832.
//
// This test asserts the CORRECT behavior — every real header through the
// boundary is accepted — so it FAILS on the current code, demonstrating the
// stall. It should pass once verifyHeaderContext handles a retarget boundary
// whose 2016-block ancestor window falls below the effective genesis.
func TestE2ERealMainnetOffsetGenesisRetarget(t *testing.T) {
	headers := loadOffsetGenesisHeaders(t)
	want := offsetGenesisTop - offsetGenesisHeight + 1
	if len(headers) < want {
		t.Skipf("need %d headers (%d..%d), got %d",
			want, offsetGenesisHeight, offsetGenesisTop, len(headers))
	}

	// headers[0] is the effective genesis (block 859303) itself.
	genesis := headers[0]
	if got := genesis.BlockHash().String(); got != offsetGenesisHash {
		t.Fatalf("corpus does not start at block %d: got hash %s, want %s",
			offsetGenesisHeight, got, offsetGenesisHash)
	}

	// Sanity: 860832 is a genuine retarget (difficulty bits change).
	bIdx := offsetGenesisBoundary - offsetGenesisHeight
	if headers[bIdx-1].Bits == headers[bIdx].Bits {
		t.Fatalf("expected a real retarget at height %d, but bits are "+
			"unchanged (0x%08x)", offsetGenesisBoundary, headers[bIdx].Bits)
	}
	t.Logf("effective genesis %d (mod 2016 = %d); real retarget at %d: "+
		"0x%08x -> 0x%08x", offsetGenesisHeight, offsetGenesisHeight%2016,
		offsetGenesisBoundary, headers[bIdx-1].Bits, headers[bIdx].Bits)

	s := newOffsetGenesisServer(t, genesis)

	// The effective genesis was inserted at its real height.
	h, _, err := s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if h != offsetGenesisHeight {
		t.Fatalf("expected effective genesis height %d, got %d",
			offsetGenesisHeight, h)
	}

	// Stream the remaining real headers (859304..862850) forward. This
	// crosses the first retarget boundary at 860832.
	it, err := addExternalHeaders(t, s, headers[1:])
	if err != nil {
		t.Fatalf("streaming real mainnet headers across the first retarget "+
			"boundary (%d) failed: it=%v err=%v\n\n"+
			"This is the offset-genesis stall: block %d derives its "+
			"difficulty from block %d (=%d-2016), which is below the "+
			"effective genesis %d and therefore cannot exist in the DB.",
			offsetGenesisBoundary, it, err, offsetGenesisBoundary,
			offsetGenesisBoundary-2016, offsetGenesisBoundary,
			offsetGenesisHeight)
	}

	// The chain should advance to the top of the corpus.
	h, _, err = s.BlockHeaderBest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if h != offsetGenesisTop {
		t.Fatalf("expected best height %d, got %d", offsetGenesisTop, h)
	}
	t.Logf("accepted all real headers through height %d across retarget %d",
		offsetGenesisTop, offsetGenesisBoundary)
}
