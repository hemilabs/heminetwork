// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database"
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

func TestBlockOrdinalUpdateAndQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db := createOrdinalDB(ctx, t)

	txid := chainhash.Hash{0x01, 0x02, 0x03, 0x04}
	outpoint := tbcd.NewOutpoint(txid, 0)
	blockHash := chainhash.Hash{0xaa, 0xbb, 0xcc}
	satNumber := uint64(5_000_000_000)

	// Build inscription ID: txid(32) + input_index(4 LE).
	var inscID [36]byte
	copy(inscID[:32], txid[:])

	// Sat range value: 16 bytes (start 8 + count 8).
	satRangeVal := make([]byte, 16)
	binary.BigEndian.PutUint64(satRangeVal[0:], satNumber)
	binary.BigEndian.PutUint64(satRangeVal[8:], 5_000_000_000)

	// Inscription value: minimal 41 bytes (sat 8 + blockhash 32 + flags 1).
	inscVal := make([]byte, 41)
	binary.BigEndian.PutUint64(inscVal[0:8], satNumber)
	copy(inscVal[8:40], blockHash[:])

	cache := make(map[tbcd.OrdinalKey]tbcd.OrdinalValue)

	// 'r': sat range for outpoint.
	var rKey tbcd.OrdinalKey
	rKey[0] = 'r'
	copy(rKey[1:], outpoint[:])
	cache[rKey] = tbcd.OrdinalValue(satRangeVal)

	// 'i': inscription by ID.
	var iKey tbcd.OrdinalKey
	iKey[0] = 'i'
	copy(iKey[1:], inscID[:])
	cache[iKey] = tbcd.OrdinalValue(inscVal)

	// 's': sat → outpoint.
	var sKey tbcd.OrdinalKey
	sKey[0] = 's'
	binary.BigEndian.PutUint64(sKey[1:], satNumber)
	cache[sKey] = tbcd.OrdinalValue(outpoint[:])

	// 'a': sat → inscription.
	var aKey tbcd.OrdinalKey
	aKey[0] = 'a'
	binary.BigEndian.PutUint64(aKey[1:], satNumber)
	copy(aKey[9:], inscID[:])
	cache[aKey] = tbcd.OrdinalValue(inscID[:])

	// 'n': block → inscription.
	var nKey tbcd.OrdinalKey
	nKey[0] = 'n'
	copy(nKey[1:33], blockHash[:])
	cache[nKey] = tbcd.OrdinalValue(inscID[:])

	indexHash := chainhash.Hash{0x11, 0x22}
	if err := db.BlockOrdinalUpdate(ctx, 1, maps.Clone(cache), indexHash); err != nil {
		t.Fatal(err)
	}

	// --- Positive queries ---

	t.Run("OrdinalSatRangesByOutpoint positive", func(t *testing.T) {
		got, err := db.OrdinalSatRangesByOutpoint(ctx, outpoint)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 16 {
			t.Fatalf("expected 16 bytes, got %d", len(got))
		}
		start := binary.BigEndian.Uint64(got[0:8])
		count := binary.BigEndian.Uint64(got[8:16])
		if start != satNumber || count != 5_000_000_000 {
			t.Errorf("sat range: start=%d count=%d", start, count)
		}
	})

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

	t.Run("OrdinalOutpointBySat positive", func(t *testing.T) {
		op, err := db.OrdinalOutpointBySat(ctx, satNumber)
		if err != nil {
			t.Fatal(err)
		}
		if *op != outpoint {
			t.Errorf("outpoint mismatch: got %x, want %x", op[:], outpoint[:])
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

	t.Run("OrdinalSatRangesByOutpoint not found", func(t *testing.T) {
		fakeOp := tbcd.NewOutpoint(chainhash.Hash{0xde, 0xad}, 99)
		_, err := db.OrdinalSatRangesByOutpoint(ctx, fakeOp)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, database.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

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

	t.Run("OrdinalOutpointBySat not found", func(t *testing.T) {
		_, err := db.OrdinalOutpointBySat(ctx, 999_999_999)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, database.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
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
		// Delete the sat range entry by passing nil value.
		unwindCache := make(map[tbcd.OrdinalKey]tbcd.OrdinalValue)
		unwindCache[rKey] = nil // mark for delete
		if err := db.BlockOrdinalUpdate(ctx, -1, unwindCache, chainhash.Hash{}); err != nil {
			t.Fatal(err)
		}
		// Verify it's gone.
		_, err := db.OrdinalSatRangesByOutpoint(ctx, outpoint)
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
	err := db.BlockOrdinalUpdate(ctx, 1, nil, chainhash.Hash{})
	if err != nil {
		t.Fatal(err)
	}
}
