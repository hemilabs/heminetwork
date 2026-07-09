// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/hemilabs/x/leveldb/leveldb"
	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/level"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

func createOrdinalDB(ctx context.Context, t *testing.T) *ldb {
	t.Helper()
	home := t.TempDir()
	cfg, err := NewConfig("localnet", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})
	return db
}

// testGetEntry is a test-local helper matching the tbc package's getEntry.
func testGetEntry(cache map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, op tbcd.Outpoint) *tbcd.OrdinalCacheEntry {
	e, ok := cache[op]
	if !ok {
		e = &tbcd.OrdinalCacheEntry{
			Inscriptions: make(map[uint64][]byte),
			Predecessors: make(map[uint64][]byte),
			Aux:          make(map[tbcd.OrdinalKey]tbcd.OrdinalValue),
		}
		cache[op] = e
	}
	return e
}

func TestBlockOrdinalUpdateAndQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)

	txid := chainhash.Hash{0x01, 0x02, 0x03, 0x04}
	blockHash := chainhash.Hash{0xaa, 0xbb, 0xcc}
	satNumber := uint64(5_000_000_000)

	// Build inscription ID: txid(32) + input_index(4 LE).
	var inscID [36]byte
	copy(inscID[:32], txid[:])

	// Inscription value: minimal 41 bytes (sat 8 + blockhash 32 + flags 1).
	inscVal := make([]byte, 41)
	binary.BigEndian.PutUint64(inscVal[0:8], satNumber)
	copy(inscVal[8:40], blockHash[:])

	op := tbcd.NewOutpoint(txid, 0)
	cache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
	entry := testGetEntry(cache, op)

	// 'i': inscription by ID.
	var iKey tbcd.OrdinalKey
	iKey[0] = 'i'
	copy(iKey[1:], inscID[:])
	entry.Aux[iKey] = tbcd.OrdinalValue(inscVal)

	// 'a': sat → inscription.
	var aKey tbcd.OrdinalKey
	aKey[0] = 'a'
	binary.BigEndian.PutUint64(aKey[1:], satNumber)
	copy(aKey[9:], inscID[:])
	entry.Aux[aKey] = tbcd.OrdinalValue(inscID[:])

	// 'n': block → inscription.
	var nKey tbcd.OrdinalKey
	nKey[0] = 'n'
	copy(nKey[1:33], blockHash[:])
	entry.Aux[nKey] = tbcd.OrdinalValue(inscID[:])

	indexHash := chainhash.Hash{0x11, 0x22}
	cloned := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, len(cache))
	for k, v := range cache {
		cloned[k] = v
	}
	if err := db.BlockOrdinalUpdate(ctx, 1, cloned, nil, indexHash); err != nil {
		t.Fatal(err)
	}

	// --- Positive queries ---

	t.Run("OrdinalInscriptionByID positive", func(t *testing.T) {
		got, err := db.OrdinalInscriptionByID(ctx, inscID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 41 {
			t.Fatalf("expected 41 bytes, got %d", len(got))
		}
		gotSat := binary.BigEndian.Uint64(got[0:8])
		if gotSat != satNumber {
			t.Errorf("sat: got %d, want %d", gotSat, satNumber)
		}
	})

	t.Run("OrdinalInscriptionsByBlockHash positive", func(t *testing.T) {
		ids, err := db.OrdinalInscriptionsByBlockHash(ctx, blockHash)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 1 {
			t.Fatalf("expected 1 inscription, got %d", len(ids))
		}
		if ids[0] != inscID {
			t.Errorf("inscription ID mismatch")
		}
	})

	t.Run("OrdinalInscriptionsBySat positive", func(t *testing.T) {
		ids, err := db.OrdinalInscriptionsBySat(ctx, satNumber)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 1 {
			t.Fatalf("expected 1 inscription, got %d", len(ids))
		}
		if ids[0] != inscID {
			t.Errorf("inscription ID mismatch")
		}
	})

	t.Run("BlockHeaderByOrdinalIndex returns error without headers", func(t *testing.T) {
		// BlockHeaderByOrdinalIndex reads the index hash then calls
		// BlockHeaderByHash — without block headers in DB this returns
		// not-found, which is correct behavior.
		_, err := db.BlockHeaderByOrdinalIndex(ctx)
		if err == nil {
			t.Fatal("expected error without block headers")
		}
	})

	// --- Negative queries ---

	t.Run("OrdinalInscriptionByID not found", func(t *testing.T) {
		fakeID := [36]byte{0xde, 0xad}
		_, err := db.OrdinalInscriptionByID(ctx, fakeID)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, database.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("OrdinalInscriptionsByBlockHash empty", func(t *testing.T) {
		fakeHash := chainhash.Hash{0xff, 0xfe}
		ids, err := db.OrdinalInscriptionsByBlockHash(ctx, fakeHash)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 0 {
			t.Errorf("expected 0 inscriptions, got %d", len(ids))
		}
	})

	t.Run("OrdinalInscriptionsBySat empty", func(t *testing.T) {
		ids, err := db.OrdinalInscriptionsBySat(ctx, 999_999_999)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 0 {
			t.Errorf("expected 0 inscriptions, got %d", len(ids))
		}
	})

	// --- InscribedSats range queries ---

	t.Run("OrdinalInscribedSatsInRange hit", func(t *testing.T) {
		sats, err := db.OrdinalInscribedSatsInRange(ctx, satNumber-1, satNumber+1)
		if err != nil {
			t.Fatal(err)
		}
		if len(sats) != 1 || sats[0] != satNumber {
			t.Errorf("expected [%d], got %v", satNumber, sats)
		}
	})

	t.Run("OrdinalInscribedSatsInRange miss", func(t *testing.T) {
		sats, err := db.OrdinalInscribedSatsInRange(ctx, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(sats) != 0 {
			t.Errorf("expected 0 sats, got %d", len(sats))
		}
	})

	t.Run("OrdinalInscribedSatBounds", func(t *testing.T) {
		lo, hi, err := db.OrdinalInscribedSatBounds(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if lo != satNumber || hi != satNumber {
			t.Errorf("bounds: lo=%d hi=%d, want both %d", lo, hi, satNumber)
		}
	})

	// --- Unwind (direction = -1) ---

	t.Run("BlockOrdinalUpdate unwind", func(t *testing.T) {
		// Delete the inscription entry by passing nil value in aux.
		unwindCache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
		unwindEntry := testGetEntry(unwindCache, op)
		unwindEntry.Aux[iKey] = nil // mark for delete
		if err := db.BlockOrdinalUpdate(ctx, -1, unwindCache, nil, chainhash.Hash{}); err != nil {
			t.Fatal(err)
		}
		// Verify it's gone.
		_, err := db.OrdinalInscriptionByID(ctx, inscID)
		if !errors.Is(err, database.ErrNotFound) {
			t.Errorf("expected not-found after unwind, got %v", err)
		}
	})
}

func TestBlockOrdinalUpdateEmptyCache(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)

	// Empty cache should not fail.
	err := db.BlockOrdinalUpdate(ctx, 1, nil, nil, chainhash.Hash{})
	if err != nil {
		t.Fatal(err)
	}
}

// TestDbUpgradeV6 validates the v5 → v6 upgrade that adds the ordinals
// index database. The upgrade must:
//   - create the OrdinalDB LevelDB (happens automatically via openDB);
//   - bump the schema version from 5 to 6;
//   - leave all existing data intact.
func TestDbUpgradeV7(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()
	cfg, err := NewConfig("upgradetest", home, "0mb", "0mb")
	if err != nil {
		t.Fatal(err)
	}

	// Phase 1: open with upgrade skipping, stamp version to 5, close.
	cfg.SetUpgradeOpen(true)
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Seed a survivor row in MetadataDB to verify v6 doesn't wipe
	// existing data.
	survivorKey := []byte("v6-test-survivor")
	survivorVal := []byte("must-survive-upgrade")
	if err := db.MetadataPut(ctx, survivorKey, survivorVal); err != nil {
		t.Fatal(err)
	}

	// Stamp version to 5.
	v5 := make([]byte, 8)
	binary.BigEndian.PutUint64(v5, 6)
	if err := db.MetadataPut(ctx, versionKey, v5); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Phase 2: reopen — the v5→v6 upgrade runs automatically.
	cfg.SetUpgradeOpen(false)
	db2, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("reopen (runs v6): %v", err)
	}
	defer func() {
		if err := db2.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// Assertion 1: version is now 6.
	ver, err := db2.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ver != 7 {
		t.Fatalf("version: got %d, want 7", ver)
	}

	// Assertion 2: survivor data is intact.
	got, err := db2.MetadataGet(ctx, survivorKey)
	if err != nil {
		t.Fatalf("survivor key lost: %v", err)
	}
	if string(got) != string(survivorVal) {
		t.Fatalf("survivor value: got %q, want %q", got, survivorVal)
	}

	// Assertion 3: ordinal DB is functional — can write and read back.
	// Use an 'i' prefix key for a round-trip test.
	var testInscID [36]byte
	testInscID[0] = 0x01
	testInscID[1] = 0x02
	var testIKey tbcd.OrdinalKey
	testIKey[0] = 'i'
	copy(testIKey[1:], testInscID[:])
	upgradeCache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
	upgradeEntry := testGetEntry(upgradeCache, tbcd.NewOutpoint(chainhash.Hash{}, 0))
	upgradeEntry.Aux[testIKey] = tbcd.OrdinalValue([]byte{0xaa, 0xbb})
	if err := db2.BlockOrdinalUpdate(ctx, 1, upgradeCache, nil, chainhash.Hash{}); err != nil {
		t.Fatalf("BlockOrdinalUpdate after upgrade: %v", err)
	}
	got2, err := db2.OrdinalInscriptionByID(ctx, testInscID)
	if err != nil {
		t.Fatalf("OrdinalInscriptionByID after upgrade: %v", err)
	}
	if len(got2) != 2 || got2[0] != 0xaa || got2[1] != 0xbb {
		t.Fatalf("ordinal round-trip after upgrade: got %x", got2)
	}
}

// TestOrdinalInscriptionsByOutpointWithOffset exercises the 'o' tracker
// read path that backs forward FIFO transfer detection. It specifically
// covers multiple inscriptions at one outpoint (distinct offsets), which
// is the case that exposes []byte aliasing if the decoder slices a reused
// loop variable into the result.
func TestOrdinalInscriptionsByOutpointWithOffset(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)

	txid := chainhash.Hash{0xde, 0xad, 0xbe, 0xef}
	op := tbcd.NewOutpoint(txid, 0)

	// Three distinct inscriptions at three distinct offsets in one output.
	// Distinct first bytes so an aliasing bug (all entries pointing at the
	// last decoded value) is caught.
	type want struct {
		offset uint64
		inscID [36]byte
	}
	wants := []want{
		{offset: 0, inscID: [36]byte{0x01}},
		{offset: 100, inscID: [36]byte{0x02}},
		{offset: 999, inscID: [36]byte{0x03}},
	}

	cache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
	entry := testGetEntry(cache, op)
	for _, w := range wants {
		id := w.inscID // copy; do not alias the loop var
		entry.Inscriptions[w.offset] = id[:]
	}
	cloned := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, len(cache))
	for k, v := range cache {
		cloned[k] = v
	}
	if err := db.BlockOrdinalUpdate(ctx, 1, cloned, nil, chainhash.Hash{0x01}); err != nil {
		t.Fatal(err)
	}

	t.Run("WithOffset returns all entries in offset order", func(t *testing.T) {
		got, err := db.OrdinalInscriptionsByOutpointWithOffset(ctx, op)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(wants) {
			t.Fatalf("got %d entries, want %d", len(got), len(wants))
		}
		for i, w := range wants {
			if got[i].Offset != w.offset {
				t.Errorf("entry %d: offset got %d want %d", i, got[i].Offset, w.offset)
			}
			if got[i].InscID != w.inscID {
				t.Errorf("entry %d: inscID got %x want %x", i, got[i].InscID, w.inscID)
			}
		}
	})

	t.Run("ByOutpoint delegates and preserves order", func(t *testing.T) {
		got, err := db.OrdinalInscriptionsByOutpoint(ctx, op)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(wants) {
			t.Fatalf("got %d entries, want %d", len(got), len(wants))
		}
		for i, w := range wants {
			if got[i] != w.inscID {
				t.Errorf("entry %d: inscID got %x want %x", i, got[i], w.inscID)
			}
		}
	})

	t.Run("unknown outpoint returns empty", func(t *testing.T) {
		other := tbcd.NewOutpoint(chainhash.Hash{0x99}, 7)
		got, err := db.OrdinalInscriptionsByOutpointWithOffset(ctx, other)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d entries, want 0", len(got))
		}
	})

	t.Run("malformed value length is rejected", func(t *testing.T) {
		bad := tbcd.NewOutpoint(chainhash.Hash{0x55}, 0)
		badCache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
		badEntry := testGetEntry(badCache, bad)
		badEntry.Inscriptions[0] = []byte{0x01, 0x02} // 2 bytes, not 36
		if err := db.BlockOrdinalUpdate(ctx, 1, badCache, nil, chainhash.Hash{0x02}); err != nil {
			t.Fatal(err)
		}
		_, err := db.OrdinalInscriptionsByOutpointWithOffset(ctx, bad)
		if err == nil {
			t.Fatal("expected error for malformed value length, got nil")
		}
	})
}

// TestBlockOrdinalUpdateAtomicData verifies that index data and work
// queue entries passed to a single BlockOrdinalUpdate land together.
// Before this was one call, the 'o'/'i'/'n' data and the 'w' work queue
// committed in separate LevelDB transactions, so a crash between them
// left the ordinal DB observing a partial block. This test proves both
// maps commit in the same call.
func TestBlockOrdinalUpdateAtomicData(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)

	// Index data: one 'o' entry.
	txid := chainhash.Hash{0xab, 0xcd}
	op := tbcd.NewOutpoint(txid, 0)
	inscID := [36]byte{0x07}
	data := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
	dataEntry := testGetEntry(data, op)
	dataEntry.Inscriptions[0] = inscID[:]

	// Work entry: 'w' + height(4) + seq(2).
	var wKey tbcd.OrdinalWorkKey
	wKey[0] = 'w'
	binary.BigEndian.PutUint32(wKey[1:5], 42)
	binary.BigEndian.PutUint16(wKey[5:7], 0)
	var wVal tbcd.OrdinalWorkValue
	copy(wVal[:36], inscID[:])
	work := map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue{wKey: wVal}

	indexHash := chainhash.Hash{0x11}
	if err := db.BlockOrdinalUpdate(ctx, 1, data, work, indexHash); err != nil {
		t.Fatal(err)
	}

	// Both must be present after the single commit.
	got, err := db.OrdinalInscriptionsByOutpoint(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != inscID {
		t.Fatalf("'o' data not committed: got %v", got)
	}

	entries, err := db.ReadOrdinalWork(ctx, 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Height == 42 && e.InscID == inscID {
			found = true
		}
	}
	if !found {
		t.Fatalf("'w' work entry not committed in same call: got %d entries", len(entries))
	}
}

// TestBlockOrdinalUpdateChunkedBatch shrinks the flush chunk size so a
// single BlockOrdinalUpdate spans many mid-loop chunk writes (both put
// and delete paths), then verifies every record — and the index-hash
// pointer written in the final chunk — survives intact.
func TestBlockOrdinalUpdateChunkedBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)
	db.ordinalBatchChunkSize = 4096
	var flushes int
	innerWrite := db.ordinalTxWrite
	db.ordinalTxWrite = func(tx *leveldb.Transaction, b *leveldb.Batch) error {
		flushes++
		return innerWrite(tx, b)
	}

	const outpoints = 64
	value := func(i int) []byte {
		v := make([]byte, 512)
		for j := range v {
			v[j] = byte(i + 1)
		}
		return v
	}

	cache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
	ops := make([]tbcd.Outpoint, 0, outpoints)
	for i := range outpoints {
		txid := chainhash.Hash{byte(i), 0x77}
		op := tbcd.NewOutpoint(txid, uint32(i))
		ops = append(ops, op)
		e := testGetEntry(cache, op)
		v := value(i)
		e.Inscriptions[uint64(i)] = v
		e.Predecessors[uint64(i)] = v
		e.BigO = v[:40]
		e.BigOSet = true
	}
	workCache := make(map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue)
	for i := range 8 {
		var k tbcd.OrdinalWorkKey
		k[0] = 'w'
		k[1] = byte(i)
		workCache[k] = tbcd.OrdinalWorkValue{0x01}
	}

	indexHash := chainhash.Hash{0xaa}
	if err := db.BlockOrdinalUpdate(ctx, 1, cache, workCache, indexHash); err != nil {
		t.Fatal(err)
	}
	// ~64 outpoints x ~1.7KB of records against a 4096-byte chunk must
	// have produced many chunk writes; assert chunking actually
	// happened so accounting regressions cannot silently degrade this
	// test to a single monolithic write.
	if flushes < 15 {
		t.Fatalf("expected many chunk flushes, got %d", flushes)
	}

	for i, op := range ops {
		located, err := db.OrdinalInscriptionsByOutpointWithOffset(ctx, op)
		if err != nil {
			t.Fatal(err)
		}
		if len(located) != 1 {
			t.Fatalf("op %d: got %d entries, want 1", i, len(located))
		}
		if located[0].Offset != uint64(i) {
			t.Fatalf("op %d: offset %d", i, located[0].Offset)
		}
		if len(located[0].Value) != 512 || located[0].Value[100] != byte(i+1) {
			t.Fatalf("op %d: value corrupted after chunked write", i)
		}
		bigO, err := db.OrdinalBigOByOutpoint(ctx, op)
		if err != nil {
			t.Fatal(err)
		}
		if len(bigO) != 40 || bigO[0] != byte(i+1) {
			t.Fatalf("op %d: 'O' corrupted after chunked write", i)
		}
	}

	// Index-hash pointer must land with the final flush.
	gotHash, err := db.pool[level.OrdinalDB].Get(ordinalIndexHashKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	gh := chainhash.Hash(gotHash)
	if !gh.IsEqual(&indexHash) {
		t.Fatalf("index hash: got %x", gotHash)
	}

	// Second pass: tombstone everything, exercising the delete flush path.
	cache = make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
	for i, op := range ops {
		e := testGetEntry(cache, op)
		e.Inscriptions[uint64(i)] = nil
		e.Predecessors[uint64(i)] = nil
		e.BigO = nil
		e.BigOSet = true
	}
	workCache = make(map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue)
	for i := range 8 {
		var k tbcd.OrdinalWorkKey
		k[0] = 'w'
		k[1] = byte(i)
		workCache[k] = tbcd.OrdinalWorkValueDelete
	}
	if err := db.BlockOrdinalUpdate(ctx, 1, cache, workCache, chainhash.Hash{0xbb}); err != nil {
		t.Fatal(err)
	}
	for i, op := range ops {
		located, err := db.OrdinalInscriptionsByOutpointWithOffset(ctx, op)
		if err != nil {
			t.Fatal(err)
		}
		if len(located) != 0 {
			t.Fatalf("op %d: %d entries survive tombstoning", i, len(located))
		}
		bigO, err := db.OrdinalBigOByOutpoint(ctx, op)
		if err != nil {
			t.Fatal(err)
		}
		if bigO != nil {
			t.Fatalf("op %d: 'O' survives tombstoning", i)
		}
	}
}

// TestBlockOrdinalUpdateInvalidDirection rejects directions other than
// wind (1) and unwind (-1).
func TestBlockOrdinalUpdateInvalidDirection(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)
	if err := db.BlockOrdinalUpdate(ctx, 0, nil, nil, chainhash.Hash{}); err == nil {
		t.Fatal("direction 0 accepted")
	}
}

// TestBlockOrdinalUpdateWriteErrors injects flush failures to verify
// every record loop propagates a chunk-write error, and covers the
// empty-final-flush path.
func TestBlockOrdinalUpdateWriteErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)
	realWrite := db.ordinalTxWrite

	errBoom := errors.New("boom")
	op := tbcd.NewOutpoint(chainhash.Hash{0x42}, 1)
	v := make([]byte, 40)

	mk := func(mut func(e *tbcd.OrdinalCacheEntry)) map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry {
		m := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
		mut(testGetEntry(m, op))
		return m
	}

	// Each case carries TWO records of one kind: flush-before-append
	// means the first append never flushes and the second triggers the
	// failing flush inside that record loop, pinning each loop's error
	// branch. bigO needs two outpoints (one 'O' per entry); indexhash
	// carries one prior record so the index-hash put flushes.
	mk2 := func(mut func(e *tbcd.OrdinalCacheEntry)) map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry {
		m := mk(mut)
		op2 := tbcd.NewOutpoint(chainhash.Hash{0x43}, 2)
		mut(testGetEntry(m, op2))
		return m
	}
	cases := []struct {
		name  string
		data  map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry
		work  map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue
		chunk int
	}{
		{"inscription", mk(func(e *tbcd.OrdinalCacheEntry) { e.Inscriptions[0] = v; e.Inscriptions[1] = v }), nil, 1},
		{"predecessor", mk(func(e *tbcd.OrdinalCacheEntry) { e.Predecessors[0] = v; e.Predecessors[1] = v }), nil, 1},
		{"bigO", mk2(func(e *tbcd.OrdinalCacheEntry) { e.BigO = v; e.BigOSet = true }), nil, 1},
		{"aux", mk(func(e *tbcd.OrdinalCacheEntry) {
			e.Aux[tbcd.OrdinalKey{0x01}] = tbcd.OrdinalValue{0x02}
			e.Aux[tbcd.OrdinalKey{0x03}] = tbcd.OrdinalValue{0x04}
		}), nil, 1},
		{"work", nil, map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue{{0x77}: {0x01}, {0x78}: {0x02}}, 1},
		{"indexhash", nil, map[tbcd.OrdinalWorkKey]tbcd.OrdinalWorkValue{{0x79}: {0x01}}, 1},
		{"finalflush", nil, nil, 1 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db.ordinalBatchChunkSize = tc.chunk
			db.ordinalTxWrite = func(*leveldb.Transaction, *leveldb.Batch) error {
				return errBoom
			}
			err := db.BlockOrdinalUpdate(ctx, 1, tc.data, tc.work, chainhash.Hash{0x99})
			if !errors.Is(err, errBoom) {
				t.Fatalf("want injected error, got %v", err)
			}
		})
	}

	// Restore the writer; with chunk size 1 every record flushes
	// before the next append, so the final flush sees an empty batch
	// (pending==0) and the update must still succeed end to end.
	db.ordinalTxWrite = realWrite
	db.ordinalBatchChunkSize = 1
	data := mk(func(e *tbcd.OrdinalCacheEntry) { e.Inscriptions[7] = v })
	if err := db.BlockOrdinalUpdate(ctx, 1, data, nil, chainhash.Hash{0x99}); err != nil {
		t.Fatal(err)
	}
	located, err := db.OrdinalInscriptionsByOutpointWithOffset(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	if len(located) != 1 || located[0].Offset != 7 {
		t.Fatalf("record lost with chunk size 1: %+v", located)
	}
}

// TestBlockOrdinalUpdateClosedDB covers the transaction-open failure.
func TestBlockOrdinalUpdateClosedDB(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg, err := NewConfig("localnet", t.TempDir(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	err = db.BlockOrdinalUpdate(ctx, 1, nil, nil, chainhash.Hash{})
	if err == nil {
		t.Fatal("closed DB accepted ordinal update")
	}
	if !errors.Is(err, leveldb.ErrClosed) {
		t.Fatalf("want leveldb.ErrClosed, got %v", err)
	}
}

// BenchmarkBlockOrdinalUpdate pins the dense-zone flush shape:
// ~2k outpoints carrying 'o'+'p'+'O'+aux records with multi-hundred
// byte bodies (~8k records/iter). Expected (dev box): ~10ms/op,
// dominated by leveldb transaction writes, zero batch regrowth.
func BenchmarkBlockOrdinalUpdate(b *testing.B) {
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()

	home := b.TempDir()
	cfg, err := NewConfig("localnet", home, "", "")
	if err != nil {
		b.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			b.Fatal(err)
		}
	}()

	mkData := func(seed byte) map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry {
		data := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, 2048)
		body := make([]byte, 512)
		for i := range 2048 {
			var h chainhash.Hash
			h[0], h[1], h[2] = byte(i), byte(i>>8), seed
			op := tbcd.NewOutpoint(h, uint32(i))
			e := testGetEntry(data, op)
			e.Inscriptions[uint64(i)] = body
			e.Predecessors[uint64(i)] = body
			e.BigO = body[:40]
			e.BigOSet = true
			e.Aux[tbcd.OrdinalKey{byte(i), byte(i >> 8), seed}] = body
		}
		return data
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		data := mkData(byte(i)) // maps are consumed per call
		b.StartTimer()
		if err := db.BlockOrdinalUpdate(ctx, 1, data, nil,
			chainhash.Hash{byte(i)}); err != nil {
			b.Fatal(err)
		}
	}
}

// TestBlockOrdinalUpdateDebugStats exercises the post-commit leveldb
// property logging with debug enabled.
func TestBlockOrdinalUpdateDebugStats(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)
	if err := loggo.ConfigureLoggers("level=DEBUG"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// ConfigureLoggers never resets modules it does not name, so
		// the module must be restored explicitly or the whole package
		// keeps running at DEBUG.
		if err := loggo.ConfigureLoggers("level=INFO"); err != nil {
			t.Fatal(err)
		}
	}()

	cache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
	e := testGetEntry(cache, tbcd.NewOutpoint(chainhash.Hash{0x99}, 0))
	e.Inscriptions[0] = make([]byte, 40)
	if err := db.BlockOrdinalUpdate(ctx, 1, cache, nil, chainhash.Hash{0x01}); err != nil {
		t.Fatal(err)
	}
}

// TestOrdinalPopulatorRejectsBigO: the wind prefetch depends on
// BlockOrdinalUpdate being the only 'O' writer; the populator must
// reject 'O'-prefixed keys loudly.
func TestOrdinalPopulatorRejectsBigO(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)
	ordData := map[tbcd.OrdinalKey]tbcd.OrdinalValue{
		{'O', 0x01}: {0x02},
	}
	if err := db.OrdinalPopulatorUpdate(ctx, ordData, nil); err == nil {
		t.Fatal("populator accepted an 'O' key")
	}
}
