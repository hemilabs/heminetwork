// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/level"
)

// siblingOf builds a distinct child of prev, so several of them all land at
// the same height and the height index ends up naming more than one hash.
func siblingOf(prev chainhash.Hash, bits uint32, tag uint32) *wire.BlockHeader {
	var mr chainhash.Hash
	mr[0] = byte(tag)
	mr[1] = byte(tag >> 8)
	mr[2] = byte(tag >> 16)
	return &wire.BlockHeader{
		Version:    1,
		PrevBlock:  prev,
		MerkleRoot: mr,
		Timestamp:  time.Unix(1700000000, 0),
		Bits:       bits,
	}
}

func headersOf(t *testing.T, hdrs ...*wire.BlockHeader) *wire.MsgHeaders {
	t.Helper()
	m := wire.NewMsgHeaders()
	for _, h := range hdrs {
		if err := m.AddBlockHeader(h); err != nil {
			t.Fatalf("add block header: %v", err)
		}
	}
	return m
}

// TestBlockHeadersInsertNeverPublishesAHeightEntryBeforeItsHeader checks that
// BlockHeadersInsert commits header records before the height index. In the
// reverse order a concurrent BlockHeadersByHeight can resolve an indexed hash
// whose record is not committed yet and return NotFoundError, which the
// indexer error switch in syncBlocks panics on. Records first means a reader
// at worst misses the new sibling.
func TestBlockHeadersInsertNeverPublishesAHeightEntryBeforeItsHeader(t *testing.T) {
	db, ctx := guardsDB(t, "testnet3")
	params := &chaincfg.TestNet3Params

	if err := db.BlockHeaderGenesisInsert(ctx, params.GenesisBlock.Header, 0,
		big.NewInt(0)); err != nil {
		t.Fatal(err)
	}

	// One sibling at height 1 up front, so the height is never legitimately
	// empty and every NotFound the reader sees is the torn window.
	if _, _, _, _, err := db.BlockHeadersInsert(ctx,
		headersOf(t, siblingOf(*params.GenesisHash, params.PowLimitBits, 0)), nil); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	const siblings = 120

	var (
		reads    atomic.Int64
		torn     atomic.Int64
		firstErr atomic.Value
	)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				reads.Add(1)
				if _, err := db.BlockHeadersByHeight(ctx, 1); err != nil {
					torn.Add(1)
					firstErr.CompareAndSwap(nil, err.Error())
				}
			}
		}()
	}

	for i := 1; i <= siblings; i++ {
		h := siblingOf(*params.GenesisHash, params.PowLimitBits, uint32(i))
		if _, _, _, _, err := db.BlockHeadersInsert(ctx, headersOf(t, h), nil); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("sibling %v insert: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	if n := torn.Load(); n != 0 {
		t.Fatalf("BlockHeadersByHeight failed %v times out of %v reads while "+
			"siblings were being inserted at that height (first: %v).\n"+
			"The height index is being committed BEFORE the header records it "+
			"names, so a reader resolves a hash whose record does not exist "+
			"yet. That error reaches syncBlocks' \"default: panic(...)\" -- "+
			"database.NotFoundError is not whitelisted there -- and kills the "+
			"process; across a crash it also leaves the index naming a hash "+
			"the store does not have, which is not re-derivable.",
			n, reads.Load(), firstErr.Load())
	}
	if reads.Load() < int64(siblings) {
		t.Fatalf("only %v reads raced %v inserts; the window was not actually "+
			"exercised", reads.Load(), siblings)
	}
}

// TestBlockHeadersByHeightSurfacesIteratorErrors checks that an iterator
// error is returned as such and not as database.NotFoundError, so a damaged
// store is not mistaken for a height with no headers.
//
// A closed store makes the iterator fail: Close leaves the handles in the
// pool so late calls error instead of segfaulting.
func TestBlockHeadersByHeightSurfacesIteratorErrors(t *testing.T) {
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

	_, err = db.BlockHeadersByHeight(ctx, 1)
	if err == nil {
		t.Fatal("BlockHeadersByHeight on a closed store returned no error")
	}
	var nfe database.NotFoundError
	if errors.As(err, &nfe) {
		t.Fatalf("a failing iterator was reported as %q. A read failure must "+
			"not masquerade as \"not found\": callers treat not-found as "+
			"\"this height does not exist\" and silently carry on with a "+
			"truncated locator against a damaged store.", err)
	}
	if !strings.Contains(err.Error(), "iterator") {
		t.Logf("error does not name the iterator, which is fine as long as it "+
			"is not a not-found: %v", err)
	}
}

// TestBlocksMissingSurfacesIteratorErrors checks the same for BlocksMissing.
// An empty result reads as "nothing is missing", so a swallowed iterator
// error would make an unreadable store look like a fully synced node.
func TestBlocksMissingSurfacesIteratorErrors(t *testing.T) {
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

	bis, err := db.BlocksMissing(ctx, 16)
	if err == nil {
		t.Fatalf("BlocksMissing on a closed store returned (%v, nil). An "+
			"unreadable store must not present as \"nothing is missing\": "+
			"syncBlocks then issues no getdata, blksMissing reports false and "+
			"Synced reports synced, so the node sits still and looks healthy.",
			bis)
	}
}

// TestRawPoolAccessAfterCloseErrorsNotPanics is the l.rawPool counterpart of
// TestAccessAfterCloseErrorsNotPanics, which only exercises l.pool. Close must
// leave the raw block store handle in place too, since BlockHeadersInsert
// reads it and the deferred-header replay can call that after Close.
func TestRawPoolAccessAfterCloseErrorsNotPanics(t *testing.T) {
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

	// Each of these reads l.rawPool[BlocksDB] and must return, not segfault.
	if _, err := db.BlockExistsByHash(ctx, chainhash.Hash{0x01}); err == nil {
		t.Error("BlockExistsByHash after Close returned no error")
	}
	if _, err := db.BlockByHash(ctx, chainhash.Hash{0x02}); err == nil {
		t.Error("BlockByHash after Close returned no error")
	}
	// The insert path the deferred-header replay reaches.
	if _, _, _, _, err := db.BlockHeadersInsert(ctx,
		headersOf(t, siblingOf(chainhash.Hash{0x03}, 0x207fffff, 1)), nil); err == nil {
		t.Error("BlockHeadersInsert after Close returned no error")
	}
}

// TestBlockHeadersInsertShortRecordIsAnErrorNotAPanic checks the length guard
// on the dedupe path, which reads the stored header's height from ebh[0:8]. A
// record shorter than 8 bytes must return an error rather than panic on the
// peer read loop.
func TestBlockHeadersInsertShortRecordIsAnErrorNotAPanic(t *testing.T) {
	db, ctx := guardsDB(t, "testnet3")
	params := &chaincfg.TestNet3Params

	if err := db.BlockHeaderGenesisInsert(ctx, params.GenesisBlock.Header, 0,
		big.NewInt(0)); err != nil {
		t.Fatal(err)
	}

	h := siblingOf(*params.GenesisHash, params.PowLimitBits, 77)
	if _, _, _, _, err := db.BlockHeadersInsert(ctx, headersOf(t, h), nil); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	// Truncate the stored record, as a torn or corrupted write would.
	hash := h.BlockHash()
	bhsDB := db.pool[level.BlockHeadersDB]
	if err := bhsDB.Put(hash[:], []byte{0x01, 0x02, 0x03}, nil); err != nil {
		t.Fatalf("truncate record: %v", err)
	}

	// Re-announcing the header takes the dedupe path, which reads that record.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BlockHeadersInsert PANICKED on a %v-byte header record: "+
				"%v. This runs on the peer read loop and in the deferred-header "+
				"replay, neither of which has a recover(), so a damaged store "+
				"kills the process instead of reporting itself.", 3, r)
		}
	}()
	_, _, _, _, err := db.BlockHeadersInsert(ctx, headersOf(t, h), nil)
	if err == nil {
		t.Fatal("a truncated header record was accepted silently; the store is " +
			"damaged and must say so")
	}
	// The type matters: once op-geth has confirmed the parents are present,
	// it routes a database.NotFoundError to addHeadersCorrupt, which
	// rebuilds the header store, but an untyped error to addHeadersBadBlock,
	// which rejects the block.
	var nfe database.NotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("truncated record must return a typed database.NotFoundError so "+
			"op-geth routes to self-heal, not a false INVALID; got %T: %v", err, err)
	}
}

// TestBlockHeadersByHeightUnderflowDoesNotPanic checks the guard on the
// height+2 wrap. For the top two uint64 heights Limit < Start and goleveldb
// panics slicing its table list. Locator heights such as tip-1000 underflow
// to these values on a low node.
//
// The panic only fires once the HeightHash DB has an sstable at level >= 1,
// so the test must populate and compact first.
func TestBlockHeadersByHeightUnderflowDoesNotPanic(t *testing.T) {
	cfg, err := NewConfig("testnet3", t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	db, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer db.Close()

	// Populate the HeightHash DB and force it to disk so there is a table
	// list for the bad range to slice.
	hhDB := db.pool[level.HeightHashDB]
	for i := range uint64(3000) {
		k := make([]byte, 8)
		binary.BigEndian.PutUint64(k, i)
		if err := hhDB.Put(k, []byte{}, nil); err != nil {
			t.Fatalf("put %v: %v", i, err)
		}
	}
	if err := hhDB.CompactRange(util.Range{}); err != nil {
		t.Fatalf("compact: %v", err)
	}

	for _, h := range []uint64{math.MaxUint64, math.MaxUint64 - 1} {
		if _, err := db.BlockHeadersByHeight(t.Context(), h); err == nil {
			t.Fatalf("height %v: want an error, got nil", h)
		}
	}
}
