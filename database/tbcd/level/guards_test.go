// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"encoding/binary"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database/level"
)

func guardsDB(t *testing.T, network string) (*ldb, context.Context) {
	t.Helper()
	ctx := t.Context()
	cfg, err := NewConfig(network, t.TempDir(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db, ctx
}

// TestVersionCorruptRecord is the guard a corrupted version. Version() is the FIRST read New() performs,
// so a short or implausible record used to be a panic on the boot path.
func TestVersionCorruptRecord(t *testing.T) {
	db, ctx := guardsDB(t, "testnet3")

	// Sanity: the freshly created store reports a real version.
	v, err := db.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v <= 0 {
		t.Fatalf("unexpected version %v", v)
	}

	// A torn (short) record must be an error, not a panic.
	for _, short := range [][]byte{{}, {0}, {0, 0, 0}, {0, 0, 0, 0, 0, 0, 0}} {
		if err := db.MetadataPut(ctx, versionKey, short); err != nil {
			t.Fatal(err)
		}
		got, err := db.Version(ctx)
		if err == nil {
			t.Fatalf("Version accepted a %d byte record and returned %v", len(short), got)
		}
		if !strings.Contains(err.Error(), "corrupt record") {
			t.Fatalf("unexpected error for %d byte record: %v", len(short), err)
		}
	}

	// A value that cannot be a version must be an error too: int(uint64) is lossy and
	// 0xffffffffffffffff arrives at the caller as -1, which is this function's error sentinel.
	for _, u := range []uint64{math.MaxUint64, math.MaxInt64, math.MaxInt32 + 1} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], u)
		if err := db.MetadataPut(ctx, versionKey, b[:]); err != nil {
			t.Fatal(err)
		}
		got, err := db.Version(ctx)
		if err == nil {
			t.Fatalf("Version accepted %v and returned %v", u, got)
		}
		if !strings.Contains(err.Error(), "implausible") {
			t.Fatalf("unexpected error for %v: %v", u, err)
		}
	}

	// A plausible value must still round-trip.
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], 4)
	if err := db.MetadataPut(ctx, versionKey, b[:]); err != nil {
		t.Fatal(err)
	}
	if got, err := db.Version(ctx); err != nil || got != 4 {
		t.Fatalf("Version() = %v, %v; want 4, nil", got, err)
	}
}

// TestDecodeBlockHeaderLength is the guard on change E4. A record of any length other than
// blockheaderSize must produce the NAMED panic, not an opaque slice panic and not a silently wrong
// header.
func TestDecodeBlockHeaderLength(t *testing.T) {
	for _, n := range []int{0, 1, 87, 88, 119, 121, 200} {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("decodeBlockHeader accepted a %d byte record", n)
				}
				msg, _ := r.(string)
				if !strings.Contains(msg, "decode block header") {
					t.Fatalf("%d bytes: unexpected panic %v", n, r)
				}
			}()
			decodeBlockHeader(make([]byte, n))
		}()
	}

	// The correct length must not panic.
	bh := decodeBlockHeader(make([]byte, blockheaderSize))
	if bh == nil {
		t.Fatal("decodeBlockHeader returned nil for a well-formed record")
	}
}

// TestKeyToHeightHash is the guard on change E5. A malformed key must be REPORTED as malformed so
// both callers can skip it; it used to take the process down.
func TestKeyToHeightHash(t *testing.T) {
	hash := chainhash.Hash{0x01, 0x02, 0x03}
	key := heightHashToKey(1234, hash[:])
	if len(key) != heighthashSize {
		t.Fatalf("heightHashToKey produced %d bytes, want %d", len(key), heighthashSize)
	}

	h, hh, ok := keyToHeightHash(key)
	if !ok {
		t.Fatal("keyToHeightHash rejected a well-formed key")
	}
	if h != 1234 || !hh.IsEqual(&hash) {
		t.Fatalf("round trip failed: %v %v", h, hh)
	}

	// Anything else is debris and must be reported as such.
	for _, n := range []int{0, 1, 8, 9, 32, heighthashSize - 1, heighthashSize + 1, 100} {
		if _, _, ok := keyToHeightHash(make([]byte, n)); ok {
			t.Fatalf("keyToHeightHash accepted a %d byte key", n)
		}
	}
}

// TestBlockHeadersInsertCumulativeWorkBound is the guard on change E6. encodeBlockHeader writes the
// cumulative work with big.Int.FillBytes into a fixed 32-byte field, and FillBytes PANICS rather
// than truncating, so a value wider than that field must be refused with an error first.
func TestBlockHeadersInsertCumulativeWorkBound(t *testing.T) {
	if blockheaderDifficultyBits != (blockheaderSize-88)*8 {
		t.Fatalf("blockheaderDifficultyBits %v does not describe the encoded field",
			blockheaderDifficultyBits)
	}

	db, ctx := guardsDB(t, "testnet3")
	params := &chaincfg.TestNet3Params

	if err := db.BlockHeaderGenesisInsert(ctx, params.GenesisBlock.Header, 0,
		big.NewInt(0)); err != nil {
		t.Fatal(err)
	}

	// CalcWork(0x03000001) is ~2^255, so two of these reach 257 bits.
	mk := func(prev chainhash.Hash, tag byte) *wire.BlockHeader {
		var mr chainhash.Hash
		mr[0] = tag
		return &wire.BlockHeader{
			Version:    1,
			PrevBlock:  prev,
			MerkleRoot: mr,
			Timestamp:  time.Unix(1700000000, 0),
			Bits:       0x03000001,
		}
	}
	h1 := mk(*params.GenesisHash, 0x01)
	h2 := mk(h1.BlockHash(), 0x02)

	msg := wire.NewMsgHeaders()
	for _, h := range []*wire.BlockHeader{h1, h2} {
		if err := msg.AddBlockHeader(h); err != nil {
			t.Fatal(err)
		}
	}

	// This must be an error. Before the bound it was a panic inside FillBytes.
	_, _, _, _, err := db.BlockHeadersInsert(ctx, msg, nil)
	if err == nil {
		t.Fatal("BlockHeadersInsert accepted headers whose cumulative work overflows the field")
	}
	if !strings.Contains(err.Error(), "cumulative difficulty overflow") {
		t.Fatalf("unexpected error: %v", err)
	}

	// The bound is on WIDTH, not on value: a cumulative work of EXACTLY
	// blockheaderDifficultyBits bits still fits the field and must be accepted. CalcWork(0x03000001)
	// is 2^255, whose BitLen is 256, so a single such header sits exactly on the boundary. Getting
	// this comparison off by one would be a silent false reject on a chain that is still encodable.
	if w := blockchain.CalcWork(0x03000001); w.BitLen() != blockheaderDifficultyBits {
		t.Fatalf("fixture drifted: CalcWork(0x03000001).BitLen() = %v, want %v",
			w.BitLen(), blockheaderDifficultyBits)
	}
	db2, ctx2 := guardsDB(t, "testnet3")
	if err := db2.BlockHeaderGenesisInsert(ctx2, params.GenesisBlock.Header, 0,
		big.NewInt(0)); err != nil {
		t.Fatal(err)
	}
	msg2 := wire.NewMsgHeaders()
	if err := msg2.AddBlockHeader(mk(*params.GenesisHash, 0x01)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, n, err := db2.BlockHeadersInsert(ctx2, msg2, nil); err != nil {
		t.Fatalf("a header whose cumulative work is exactly %v bits was rejected: %v",
			blockheaderDifficultyBits, err)
	} else if n != 1 {
		t.Fatalf("inserted %v headers, want 1", n)
	}
}

// TestBlockHeadersInsertRealChainNotRejected is the false-reject half of E6: a normal chain must be
// inserted, i.e. the bound must not fire on plausible work.
func TestBlockHeadersInsertRealChainNotRejected(t *testing.T) {
	db, ctx := guardsDB(t, "testnet3")
	params := &chaincfg.TestNet3Params

	if err := db.BlockHeaderGenesisInsert(ctx, params.GenesisBlock.Header, 0,
		big.NewInt(0)); err != nil {
		t.Fatal(err)
	}

	prev := *params.GenesisHash
	msg := wire.NewMsgHeaders()
	for i := range byte(16) {
		var mr chainhash.Hash
		mr[0] = i + 1
		h := &wire.BlockHeader{
			Version:    1,
			PrevBlock:  prev,
			MerkleRoot: mr,
			Timestamp:  time.Unix(1700000000+int64(i)*600, 0),
			Bits:       params.PowLimitBits,
		}
		if err := msg.AddBlockHeader(h); err != nil {
			t.Fatal(err)
		}
		prev = h.BlockHash()
	}
	if _, _, _, n, err := db.BlockHeadersInsert(ctx, msg, nil); err != nil {
		t.Fatalf("ordinary chain rejected: %v", err)
	} else if n != 16 {
		t.Fatalf("inserted %v headers, want 16", n)
	}
}

// TestTxIndexAmbiguityStillPanics pins a DELIBERATE panic, and the reasoning is the point.
//
// A txid mapping to two blocks is a data condition BIP30 makes real (mainnet 91722/91880 and
// 91812/91842), and this sits on an EVM-reachable path via op-geth's btcTxByTxid family. The
// obvious hardening -- return an error instead of panicking -- was written, MEASURED, and REVERTED,
// because it is a consensus-observable change:
//
//	op-geth core/vm/evm.go runPrecompileGuarded is UNMODIFIED, i.e. deployed. It recovers a panic
//	from an hVM precompile into ErrHVMInvalidPrecompileInput -- a no-op CALL SUCCESS refunding
//	everything above RequiredGas. An ERROR instead falls past btcTxConfirmations' HvmStoreUnusable
//	arm (which matches only leveldb.ErrClosed / net.ErrClosed / context.Canceled) to a bare
//	`return nil, err`, and evm.Call then zeroes the gas.
//
//	Measured, same store, only the module swapped:
//	  OLD (panic): 0x43 -> CALL-SUCCESS, remainingGas=995000
//	  NEW (error): 0x43 -> CALL-FAILURE, ALL GAS BURNED
//
// Two nodes, one upgraded, answer the same EVM call differently. Under Holocene that is a silent
// fork, and it needs no attacker: the full node is given no effective genesis, so its tx index walks
// from block 0 straight through the BIP30 pairs.
//
// So this asserts the PANIC. Changing it to an error is fine ONLY in a release that also maps that
// error to ErrHVMInvalidPrecompileInput at op-geth's 0x43 call site -- in the same commit.
func TestTxIndexAmbiguityStillPanics(t *testing.T) {
	db, ctx := guardsDB(t, "testnet3")
	txDB := db.pool[level.TransactionsDB]

	txid := chainhash.Hash{0xaa}
	blk1 := chainhash.Hash{0x01}
	blk2 := chainhash.Hash{0x02}

	put := func(prefix byte, a, b chainhash.Hash) {
		key := make([]byte, 0, 65)
		key = append(key, prefix)
		key = append(key, a[:]...)
		key = append(key, b[:]...)
		if err := txDB.Put(key, nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	// One block: the ordinary case must still work.
	put('t', txid, blk1)
	got, err := db.BlockHashByTxId(ctx, txid)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsEqual(&blk1) {
		t.Fatalf("BlockHashByTxId = %v, want %v", got, blk1)
	}

	// Two blocks: still a panic, deliberately.
	put('t', txid, blk2)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("BlockHashByTxId no longer panics on an ambiguous txid. If that was " +
				"deliberate it is a CONSENSUS CHANGE -- read this test's doc comment -- and it " +
				"needs a paired op-geth change mapping the new error to " +
				"ErrHVMInvalidPrecompileInput at the 0x43 call site.")
		}
		if msg, ok := r.(string); ok && !strings.Contains(msg, "invalid blocks count") {
			t.Fatalf("panicked with an unexpected message: %v", msg)
		}
	}()
	_, _ = db.BlockHashByTxId(ctx, txid)
}

// TestBlockHeadersByHeightFailsLoudOnMalformedKey pins the deliberate asymmetry between this
// function and BlocksMissing.
//
// BlocksMissing SKIPS a key it cannot decode: the block simply is not requested, which is benign,
// and that function already documents that it may under-report. BlockHeadersByHeight must NOT skip.
// findCommonParent (service/tbc/crawler.go) decides "these headers share a common parent" from this
// function's result, so silently dropping one sibling at a fork height makes it choose the WRONG
// common ancestor and unwind to the wrong place -- quietly, and permanently.
//
// Mutation-verified: change the error return here to `continue` and this fails.
func TestBlockHeadersByHeightFailsLoudOnMalformedKey(t *testing.T) {
	db, ctx := guardsDB(t, "testnet3")

	// A key of the wrong length in the height-index, which is exactly the residue an interrupted
	// multi-instance commit can leave.
	bad := make([]byte, heighthashSize-3)
	binary.BigEndian.PutUint64(bad[0:8], 1)
	if err := db.pool[level.HeightHashDB].Put(bad, []byte{}, nil); err != nil {
		t.Fatal(err)
	}

	_, err := db.BlockHeadersByHeight(ctx, 1)
	if err == nil {
		t.Fatal("BlockHeadersByHeight SKIPPED a malformed height-index key. It must fail loud: " +
			"findCommonParent derives a common ancestor from this result, so dropping one sibling " +
			"at a fork height unwinds the indexers to the wrong block, silently and permanently.")
	}
	if !strings.Contains(err.Error(), "malformed height-index key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestGenesisInsertCumulativeWorkBound is the completeness half of the E6 bound.
//
// BlockHeadersInsert bounds cumulative work before encodeBlockHeader; BlockHeaderGenesisInsert did
// not, and its value comes straight from the embedder via Config.GenesisDifficultyOffset with
// nothing checking it. That is op-geth's BOOT path, so a misconfigured offset was a panic inside
// FillBytes during startup rather than a diagnosable refusal to start.
//
// Not remotely reachable -- it needs a misconfigured embedder or operator -- but a bound that covers
// one of its two writers is not a bound.
//
// Mutation-verified: remove the guard and this test panics with
// "math/big: buffer too small to fit value".
func TestGenesisInsertCumulativeWorkBound(t *testing.T) {
	db, ctx := guardsDB(t, "testnet3")

	hdr := chaincfg.TestNet3Params.GenesisBlock.Header

	// Exactly at the limit: 256 bits fits the 32-byte field and must be accepted.
	ok := new(big.Int).Lsh(big.NewInt(1), uint(blockheaderDifficultyBits)-1)
	if ok.BitLen() != blockheaderDifficultyBits {
		t.Fatalf("fixture: %d bits, want %d", ok.BitLen(), blockheaderDifficultyBits)
	}
	if err := db.BlockHeaderGenesisInsert(ctx, hdr, 0, ok); err != nil {
		t.Fatalf("REGRESSION: a cumulative work of exactly %d bits FITS the field and must be "+
			"accepted; rejecting it is a false reject on the boot path: %v",
			blockheaderDifficultyBits, err)
	}

	// One bit over: must be a clean error, never a panic.
	db2, ctx2 := guardsDB(t, "testnet3")
	over := new(big.Int).Lsh(big.NewInt(1), uint(blockheaderDifficultyBits))
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BlockHeaderGenesisInsert PANICKED on an out-of-range genesis difficulty "+
				"offset (%v) instead of returning an error. This is op-geth's boot path: a "+
				"misconfigured offset should refuse to start with a message, not crash inside "+
				"math/big.", r)
		}
	}()
	if err := db2.BlockHeaderGenesisInsert(ctx2, hdr, 0, over); err == nil {
		t.Fatal("BlockHeaderGenesisInsert accepted a cumulative difficulty wider than the field " +
			"encodeBlockHeader writes it into")
	}
}
