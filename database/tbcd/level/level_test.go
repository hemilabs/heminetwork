// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/level"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
)

func TestMD(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()
	t.Logf("temp: %v", home)

	cfg, err := NewConfig("testnet3", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := db.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	x := 255
	rows := make([]tbcd.Row, x+1)
	for i := 0; i <= x; i++ {
		y := byte(i)
		rows[i] = tbcd.Row{
			Key:   []byte{y},
			Value: []byte{y, y, y, y},
		}
	}
	err = db.MetadataBatchPut(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}

	qr := make([][]byte, 0, x+1)
	for i := 0; i <= x; i++ {
		qr = append(qr, []byte{byte(i)})
	}
	rrows, err := db.MetadataBatchGet(ctx, true, qr)
	if err != nil {
		t.Fatal(err)
	}
	for k := range rrows {
		if !reflect.DeepEqual(rrows[k], rows[k]) {
			t.Fatalf("expected %v got %v",
				spew.Sdump(rows[k]), spew.Sdump(rrows[k]))
		}
	}

	// fail
	qr = append(qr, []byte{1, 2, 3, 4}) // unknown key
	rrows, err = db.MetadataBatchGet(ctx, true, qr)
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("expected '%v', got '%v'", database.ErrNotFound, err)
	}
	if rrows != nil {
		t.Fatal("expected no return value")
	}

	// don't fail but check error
	rrows, err = db.MetadataBatchGet(ctx, false, qr)
	if err != nil {
		t.Fatal(err)
	}
	if rrows[x+1].Error == nil {
		t.Fatal(err)
	}
	for k := range rrows[:x] {
		if !reflect.DeepEqual(rrows[k], rows[k]) {
			t.Fatalf("expected %v got %v",
				spew.Sdump(rows[k]), spew.Sdump(rrows[k]))
		}
	}

	// Individual put/get
	key := []byte("mysuperkey")
	value := []byte("valuevaluevalue")
	err = db.MetadataPut(ctx, key, value)
	if err != nil {
		t.Fatal(err)
	}
	rv, err := db.MetadataGet(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rv, value) {
		t.Fatalf("got %s, expected %s", rv, value)
	}

	// Delete one
	if err = db.MetadataDel(ctx, key); err != nil {
		t.Fatal(err)
	}
	_, err = db.MetadataGet(ctx, key)
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("expected '%v', got '%v'", database.ErrNotFound, err)
	}

	// Invalid Delete
	err = db.MetadataDel(ctx, key)
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("expected '%v', got '%v'", database.ErrNotFound, err)
	}

	// fail one
	rv, err = db.MetadataGet(ctx, []byte("nope"))
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("expected '%v', got '%v'", database.ErrNotFound, err)
	}
	if rv != nil {
		t.Fatal("expected no return value")
	}
}

func makeKssMap(from uint32, kssList []hemi.L2Keystone, blockHashSeed string) map[chainhash.Hash]tbcd.Keystone {
	kssMap := make(map[chainhash.Hash]tbcd.Keystone)
	for i, l2Keystone := range kssList {
		abrvKs := hemi.L2KeystoneAbbreviate(l2Keystone).Serialize()
		kssMap[*hemi.L2KeystoneAbbreviate(l2Keystone).Hash()] = tbcd.Keystone{
			BlockHash:           chainhash.Hash(testutil.FillBytes(blockHashSeed, 32)),
			AbbreviatedKeystone: abrvKs,
			BlockHeight:         from + uint32(i),
		}
	}
	return kssMap
}

func TestKssEncoding(t *testing.T) {
	keystones := []hemi.L2Keystone{
		{
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytes("parentephash", 32),
			PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
			StateRoot:          testutil.FillBytes("stateroot", 32),
			EPHash:             testutil.FillBytes("ephash", 32),
		}, {
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytes("altparentephash", 32),
			PrevKeystoneEPHash: testutil.FillBytes("altprevkeystoneephash", 32),
			StateRoot:          testutil.FillBytes("altstateroot", 32),
			EPHash:             testutil.FillBytes("altephash", 32),
		},
	}

	altKeystone := hemi.L2Keystone{
		Version:            2,
		L1BlockNumber:      6,
		L2BlockNumber:      64,
		ParentEPHash:       testutil.FillBytes("fakeparentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("fakeprevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("fakestateroot", 32),
		EPHash:             testutil.FillBytes("fakeephash", 32),
	}
	altAbrevKeystone := hemi.L2KeystoneAbbreviate(altKeystone).Serialize()

	kssMap := makeKssMap(0, keystones, "blockhash")
	for _, ks := range kssMap {
		encodedKs := encodeKeystoneToSlice(ks)
		decodedKs := decodeKeystone(encodedKs)

		if !decodedKs.BlockHash.IsEqual(&ks.BlockHash) {
			t.Fatalf("blockhash diff: got %v, expected %v", decodedKs.BlockHash, ks.BlockHash)
		}
		if diff := deep.Equal(decodedKs.AbbreviatedKeystone, ks.AbbreviatedKeystone); len(diff) > 0 {
			t.Fatalf("abrv Ks diff: %s", diff)
		}
	}
	diffKssMap := makeKssMap(0, keystones, "diffblockhash")
	for key, ks := range diffKssMap {
		dks := kssMap[key]
		encodedKs := encodeKeystoneToSlice(dks)
		decodedKs := decodeKeystone(encodedKs)

		if decodedKs.BlockHash.IsEqual(&ks.BlockHash) {
			t.Fatalf("blockhash not diff: got %v, expected %v", decodedKs.BlockHash, ks.BlockHash)
		}

		if diff := deep.Equal(decodedKs.AbbreviatedKeystone, altAbrevKeystone); len(diff) == 0 {
			t.Fatalf("abrv Ks diff: %v", diff)
		}
	}
}

func TestHeightHashIndexing(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		blockNum    = 100
		kssPerBlock = 5
	)

	ks := hemi.L2Keystone{
		Version:            1,
		ParentEPHash:       testutil.FillBytes("v1parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("v1prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("v1stateroot", 32),
		EPHash:             testutil.FillBytes("v1ephash", 32),
	}
	l2Block := 25
	kssMap := make(map[chainhash.Hash]tbcd.Keystone, 0)
	for i := range blockNum {
		ks.L1BlockNumber = uint32(i + 1)
		for range kssPerBlock {
			ks.L2BlockNumber = uint32(l2Block)
			abrvKs := hemi.L2KeystoneAbbreviate(ks).Serialize()
			kssMap[*hemi.L2KeystoneAbbreviate(ks).Hash()] = tbcd.Keystone{
				BlockHash:           chainhash.Hash(testutil.FillBytes("blockhash", 32)),
				AbbreviatedKeystone: abrvKs,
				BlockHeight:         uint32(i + 1),
			}
			l2Block += 25
		}
	}

	home := t.TempDir()
	t.Logf("temp: %v", home)

	cfg, err := NewConfig("testnet3", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := db.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	blockhash := chainhash.Hash{1, 3, 3, 7}
	if err := db.BlockKeystoneUpdate(ctx, 1, kssMap, blockhash); err != nil {
		t.Fatal(err)
	}

	// check each keystone individually
	for hash, ks := range kssMap {
		ksr, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, hash)
		if err != nil {
			t.Fatalf("keystone not in db: %v", err)
		}

		if diff := deep.Equal(*ksr, ks); len(diff) > 0 {
			t.Fatalf("unexpected keystone diff: %s", diff)
		}
	}

	// check each height
	for n := range blockNum {
		kssList, err := db.KeystonesByHeight(ctx, uint32(n), 1)
		if err != nil {
			t.Fatal(err)
		}

		if len(kssList) != kssPerBlock {
			t.Fatalf("unexpected number of keystones: %d", len(kssList))
		}

		for _, k := range kssList {
			if k.BlockHeight != uint32(n+1) {
				t.Fatalf("keystone height mismatch %v, expected %v", k.BlockHeight, n+1)
			}
		}
	}

	// check all heights with positive depth
	kssList, err := db.KeystonesByHeight(ctx, 0, blockNum)
	if err != nil {
		t.Fatal(err)
	}

	if len(kssList) != kssPerBlock*blockNum {
		t.Fatalf("unexpected number of keystones: %d", len(kssList))
	}

	// check all heights with negative depth
	kssList, err = db.KeystonesByHeight(ctx, blockNum+1, -blockNum)
	if err != nil {
		t.Fatal(err)
	}

	if len(kssList) != kssPerBlock*blockNum {
		t.Fatalf("unexpected number of keystones: %d", len(kssList))
	}

	// expected errors
	_, err = db.KeystonesByHeight(ctx, 1, 0)
	if err == nil {
		t.Fatalf("expected 'depth must not be 0' error")
	}

	_, err = db.KeystonesByHeight(ctx, 1, -2)
	if err == nil {
		t.Fatalf("expected 'underflow' error")
	}
}

func TestKeystoneUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	kssList := []hemi.L2Keystone{
		{
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytes("v1parentephash", 32),
			PrevKeystoneEPHash: testutil.FillBytes("v1prevkeystoneephash", 32),
			StateRoot:          testutil.FillBytes("v1stateroot", 32),
			EPHash:             testutil.FillBytes("v1ephash", 32),
		},
		{
			Version:            1,
			L1BlockNumber:      6,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytes("v2parentephash", 32),
			PrevKeystoneEPHash: testutil.FillBytes("v2prevkeystoneephash", 32),
			StateRoot:          testutil.FillBytes("v2stateroot", 32),
			EPHash:             testutil.FillBytes("v2ephash", 32),
		},
		{
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytes("i1parentephash", 32),
			PrevKeystoneEPHash: testutil.FillBytes("i1prevkeystoneephash", 32),
			StateRoot:          testutil.FillBytes("i1stateroot", 32),
			EPHash:             testutil.FillBytes("i1ephash", 32),
		},
		{
			Version:            1,
			L1BlockNumber:      6,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytes("i2parentephash", 32),
			PrevKeystoneEPHash: testutil.FillBytes("i2prevkeystoneephash", 32),
			StateRoot:          testutil.FillBytes("i2stateroot", 32),
			EPHash:             testutil.FillBytes("i2ephash", 32),
		},
	}

	type testTableItem struct {
		name           string
		direction      []int
		preInsertValid bool
		kssMap         map[chainhash.Hash]tbcd.Keystone
		expectedInDB   map[chainhash.Hash]tbcd.Keystone
		expectedOutDB  map[chainhash.Hash]tbcd.Keystone
		expectedError  error
	}

	testTable := []testTableItem{
		{
			name:          "invalidDirection",
			direction:     []int{0},
			expectedOutDB: makeKssMap(5, kssList[:], "blockhash"),
			expectedError: fmt.Errorf("invalid direction: %v", 0),
		},
		{
			name:          "nilMap",
			direction:     []int{-1, 1},
			expectedOutDB: makeKssMap(5, kssList, "blockhash"),
		},
		{
			name:          "emptyMap",
			direction:     []int{-1, 1},
			kssMap:        makeKssMap(5, nil, "blockhash"),
			expectedOutDB: makeKssMap(5, kssList, "blockhash"),
		},

		{
			name:           "duplicateInsert",
			direction:      []int{1},
			expectedError:  nil,
			preInsertValid: true,
			kssMap:         makeKssMap(5, kssList[:2], "blockhash"),
			expectedInDB:   makeKssMap(5, kssList[:2], "blockhash"),
			expectedOutDB:  makeKssMap(5, kssList[2:], "blockhash"),
		},

		{
			name:          "invalidRemove",
			direction:     []int{-1},
			kssMap:        makeKssMap(5, kssList[2:], "blockhash"),
			expectedOutDB: makeKssMap(5, kssList, "blockhash"),
		},
		{
			name:          "validInsert",
			direction:     []int{1},
			kssMap:        makeKssMap(5, kssList[:2], "blockhash"),
			expectedInDB:  makeKssMap(5, kssList[:2], "blockhash"),
			expectedOutDB: makeKssMap(5, kssList[2:], "blockhash"),
		},
		{
			name:          "validRemove",
			direction:     []int{1, -1},
			kssMap:        makeKssMap(5, kssList[2:], "blockhash"),
			expectedOutDB: makeKssMap(5, kssList, "blockhash"),
		},
		{
			name:           "mixedRemove",
			direction:      []int{-1},
			preInsertValid: true,
			kssMap:         makeKssMap(5, kssList, "blockhash"),
			expectedOutDB:  makeKssMap(5, kssList, "blockhash"),
		},
		{
			name:           "mixedInsert",
			direction:      []int{1},
			preInsertValid: true,
			kssMap:         makeKssMap(5, kssList, "blockhash"),
			expectedInDB:   makeKssMap(5, kssList, "blockhash"),
		},
		{
			name:           "invalidBlockhashRemove",
			direction:      []int{-1},
			preInsertValid: true,
			kssMap:         makeKssMap(5, kssList, "fakeblockhash"),
			expectedInDB:   makeKssMap(5, kssList[:2], "blockhash"),
		},
	}

	blockhash := chainhash.Hash{1, 3, 3, 7}
	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			home := t.TempDir()
			t.Logf("temp: %v", home)

			cfg, err := NewConfig("testnet3", home, "", "")
			if err != nil {
				t.Fatal(err)
			}
			db, err := New(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				err := db.Close()
				if err != nil {
					t.Fatal(err)
				}
			}()

			if tti.preInsertValid {
				if err := db.BlockKeystoneUpdate(ctx, 1, makeKssMap(5, kssList[:2], "blockhash"), blockhash); err != nil {
					t.Fatal(err)
				}
			}

			for _, dir := range tti.direction {
				err := db.BlockKeystoneUpdate(ctx, dir, maps.Clone(tti.kssMap), blockhash)
				if diff := deep.Equal(err, tti.expectedError); len(diff) > 0 {
					t.Fatalf("(direction %v) unexpected error diff: %s", dir, diff)
				}
			}

			for v, ks := range tti.expectedInDB {
				_, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, v)
				if err != nil {
					t.Fatalf("keystone not in db: %v", err)
				}

				kssList, err := db.KeystonesByHeight(ctx, ks.BlockHeight-1, 1)
				if err != nil {
					t.Fatal(err)
				}

				if len(kssList) != 1 {
					t.Fatalf("unexpected number of keystons: %d", len(kssList))
				}

				if diff := deep.Equal(ks, kssList[0]); len(diff) > 0 {
					t.Fatalf("unexpected keystone diff: %s", diff)
				}
			}

			for v, ks := range tti.expectedOutDB {
				_, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, v)
				if err == nil {
					t.Fatalf("keystone in db: %v", spew.Sdump(ks))
				} else {
					if !errors.Is(err, database.ErrNotFound) {
						t.Fatalf("expected '%v', got '%v'", database.ErrNotFound, err)
					}
				}
				kssList, err := db.KeystonesByHeight(ctx, ks.BlockHeight-1, 1)
				if err != nil {
					if !errors.Is(err, database.ErrNotFound) {
						t.Fatalf("expected '%v', got '%v'", database.ErrNotFound, err)
					}
				}

				for _, k := range kssList {
					if diff := deep.Equal(ks, k); len(diff) == 0 {
						t.Fatalf("keystone in heighthash db: %v", spew.Sdump(ks))
					}
				}
			}
		})
	}
}

func newKeystone(blockhash *chainhash.Hash, l1, l2 uint32) (*chainhash.Hash, tbcd.Keystone) {
	hks := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      l1,
		L2BlockNumber:      l2,
		ParentEPHash:       testutil.FillBytes("v1parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("v1prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("v1stateroot", 32),
		EPHash:             testutil.FillBytes("v1ephash", 32),
	}
	abrvKs := hemi.L2KeystoneAbbreviate(hks)
	return abrvKs.Hash(), tbcd.Keystone{
		BlockHash:           *blockhash,
		AbbreviatedKeystone: abrvKs.Serialize(),
	}
}

func TestKeystoneDBWindUnwind(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()
	t.Logf("temp: %v", home)

	cfg, err := NewConfig("testnet3", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := db.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	blockhash := chainhash.Hash{0xde, 0xad, 0xbe, 0xef}
	blk1Hash := chainhash.Hash{1}
	k1hash, k1 := newKeystone(&blk1Hash, 1, 2)
	blk2Hash := chainhash.Hash{1}
	k2hash, k2 := newKeystone(&blk2Hash, 2, 3)
	ksm := map[chainhash.Hash]tbcd.Keystone{
		*k1hash: k1,
		*k2hash: k2,
	}
	err = db.BlockKeystoneUpdate(ctx, 1, maps.Clone(ksm), blockhash)
	if err != nil {
		t.Fatal(err)
	}

	// Get keystones back out
	ks1, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *k1hash)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(k1, *ks1) {
		t.Fatalf("%v%v", spew.Sdump(k1), spew.Sdump(*ks1))
	}
	ks2, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *k2hash)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(k2, *ks2) {
		t.Fatalf("%v%v", spew.Sdump(k2), spew.Sdump(*ks2))
	}

	// Unwind
	// Technically don't need to clone ksm here, but do it for coherency
	err = db.BlockKeystoneUpdate(ctx, -1, maps.Clone(ksm), blockhash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *k1hash)
	if err == nil {
		t.Fatal("k1 found")
	}
	_, err = db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *k2hash)
	if err == nil {
		t.Fatal("k2 found")
	}
}

func TestKeystoneDBCache(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()
	t.Logf("temp: %v", home)

	cfg, err := NewConfig("upgradetest", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := db.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	// XXX make these higher when cache fixed
	const (
		kssNum = 1
		cycles = 1
	)

	blockhash := chainhash.Hash{0xba, 0xdc, 0x0f, 0xfe}
	for i := range cycles {
		ksm := make(map[chainhash.Hash]tbcd.Keystone, kssNum)
		for j := range kssNum {
			blkHash := chainhash.Hash{byte(i)}
			ksHash, ks := newKeystone(&blkHash, uint32(j), uint32(j))
			ksm[*ksHash] = ks
		}

		err = db.BlockKeystoneUpdate(ctx, 1, ksm, blockhash)
		if err != nil {
			t.Fatal(err)
		}

		for ksHash, ks := range ksm {
			dks, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, ksHash)
			if err != nil {
				t.Fatal(err)
			}
			if diff := deep.Equal(ks, *dks); len(diff) > 0 {
				t.Fatalf("(cycle %v) unexpected error diff: %v", i, diff)
			}
		}

		err = db.BlockKeystoneUpdate(ctx, -1, ksm, blockhash)
		if err != nil {
			t.Fatal(err)
		}

		for ksHash := range ksm {
			ks, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, ksHash)
			if err == nil {
				t.Fatalf("(cycle %v) deleted keystone found %v", i, spew.Sdump(ks))
			}
		}
	}
}

func TestHeightHashEncoding(t *testing.T) {
	hks := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      1000,
		L2BlockNumber:      100,
		ParentEPHash:       testutil.FillBytes("v1parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("v1prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("v1stateroot", 32),
		EPHash:             testutil.FillBytes("v1ephash", 32),
	}
	hash := *hemi.L2KeystoneAbbreviate(hks).Hash()

	// encode keystone and height
	e := encodeKeystoneHeightHash(hks.L1BlockNumber, hash)

	if e[0] != 'h' {
		t.Fatal("not a height hash index")
	}

	var h [4]byte
	binary.BigEndian.PutUint32(h[:], hks.L1BlockNumber)

	// test encoded height
	if !bytes.Equal(e[1:1+4], h[:]) {
		t.Fatalf("encoded height != kss height (%v != %v)", e[1:1+4], h)
	}
	ehash := testutil.Bytes2Hash(e[5 : 5+32])

	// test encoded hash
	if !ehash.IsEqual(&hash) {
		t.Fatalf("encoded hash != kss hash (%v != %v)", ehash, hash)
	}

	// decode index
	uheight, uhash := decodeKeystoneHeightHash(e[:])

	// test decoded height
	if uheight != hks.L1BlockNumber {
		t.Fatalf("decoded height != kss height (%d != %d)", uheight, hks.L1BlockNumber)
	}

	// test decoded hash
	if !uhash.IsEqual(&hash) {
		t.Fatalf("decoded hash != kss hash (%v != %v)", uhash, hash)
	}
}

func TestDbUpgradeV4Errors(t *testing.T) {
	type testTableItem struct {
		name  string
		key   []byte
		value []byte
		pass  bool
	}

	ks := hemi.L2Keystone{
		Version:            1,
		ParentEPHash:       testutil.FillBytes("v1parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("v1prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("v1stateroot", 32),
		EPHash:             testutil.FillBytes("v1ephash", 32),
	}
	abrevKss := hemi.L2KeystoneAbbreviate(ks)
	fakeHash := testutil.String2Hash("1000000050ff3053ada24e6ad581fa0295297f20a2747d034997ffc899aa931e")
	realHash := testutil.String2Hash("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")

	invalidBlockKss := tbcd.Keystone{
		BlockHash:           *fakeHash,
		BlockHeight:         10,
		AbbreviatedKeystone: abrevKss.Serialize(),
	}
	validKss := tbcd.Keystone{
		BlockHash:           *realHash,
		BlockHeight:         10,
		AbbreviatedKeystone: abrevKss.Serialize(),
	}

	testTable := []testTableItem{
		{
			name:  "invalid blockheader",
			key:   fakeHash[:],
			value: encodeKeystoneToSliceV1(invalidBlockKss),
		},
		{
			name:  "invalid keystone hash",
			key:   realHash[:15],
			value: encodeKeystoneToSliceV1(validKss),
		},
		{
			name: "no errors",
			pass: true,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			home := t.TempDir()
			network := "upgradetest"
			t.Logf("temp: %v", home)

			ctx, cancel := context.WithCancel(t.Context())
			defer func() {
				cancel()
			}()

			cfg, err := NewConfig(network, home, "0mb", "0mb")
			if err != nil {
				t.Fatal(err)
			}

			cfg.SetUpgradeOpen(true)
			dbTemp, err := New(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}

			if err := dbTemp.insertTable(level.KeystonesDB, tti.key, tti.value); err != nil {
				panic(err)
			}

			// Write new version
			v := make([]byte, 8)
			binary.BigEndian.PutUint64(v, 1)
			if err := dbTemp.MetadataPut(ctx, versionKey, v); err != nil {
				t.Fatal(err)
			}

			if err := dbTemp.Close(); err != nil {
				t.Fatal(err)
			}

			cfg.SetUpgradeOpen(false)
			// upgrade
			_, err = New(ctx, cfg)
			if !tti.pass && err == nil {
				t.Fatal("expected error")
			}
			if tti.pass && err != nil {
				t.Fatal(err)
			}

			t.Log(err)
		})
	}
}

func encodeKeystoneV1(ks tbcd.Keystone) (eks [chainhash.HashSize + hemi.L2KeystoneAbrevSize]byte) {
	copy(eks[0:32], ks.BlockHash[:])
	copy(eks[32:], ks.AbbreviatedKeystone[:])
	return eks
}

func encodeKeystoneToSliceV1(ks tbcd.Keystone) []byte {
	eks := encodeKeystoneV1(ks)
	return eks[:]
}

func createTestBlock(prevHash *chainhash.Hash, nonce int64) *btcutil.Block {
	bh := wire.NewBlockHeader(0, prevHash, &chainhash.Hash{}, 0, uint32(nonce))
	bh.Timestamp = time.Unix(nonce, 0)
	bh.Bits = 0x1d00ffff
	block := wire.NewMsgBlock(bh)

	// Add a coinbase transaction
	coinbase := wire.NewMsgTx(1)
	coinbase.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: 0xFFFFFFFF,
		},
		Sequence: 0xFFFFFFFF,
	})
	coinbase.AddTxOut(&wire.TxOut{
		Value: 50 * 100000000, // 50 BTC
	})
	if err := block.AddTransaction(coinbase); err != nil {
		panic(err)
	}

	txHash := coinbase.TxHash()
	bh.MerkleRoot = chainhash.DoubleHashH(txHash[:])

	btcBlock := btcutil.NewBlock(block)
	return btcBlock
}

func createTestMsgHeaders(headers []*tbcd.BlockHeader) *wire.MsgHeaders {
	msgHeaders := wire.NewMsgHeaders()
	for _, bh := range headers {
		wbh, err := bh.Wire()
		if err != nil {
			panic(err)
		}
		if err = msgHeaders.AddBlockHeader(wbh); err != nil {
			panic(err)
		}
	}
	return msgHeaders
}

func insertBlock(ctx context.Context, db *ldb, bh tbcd.BlockHeader) error {
	blk := createTestBlock(bh.ParentHash(), int64(bh.Height))
	h, err := db.BlockInsert(ctx, blk)
	if err != nil {
		return fmt.Errorf("block insert: %w", err)
	}
	if h != int64(bh.Height) {
		return fmt.Errorf("expected height %d, got %d", bh.Height, h)
	}

	// Check if block exists
	exists, err := db.BlockExistsByHash(ctx, *blk.Hash())
	if err != nil {
		return fmt.Errorf("BlockExistsByHash: %w", err)
	}
	if !exists {
		return fmt.Errorf("block %d not found: %s", bh.Height, blk.Hash())
	}

	// Check if we can retrieve block
	retrieved, err := db.BlockByHash(ctx, *blk.Hash())
	if err != nil {
		return fmt.Errorf("BlockByHash: %w", err)
	}
	if !retrieved.Hash().IsEqual(blk.Hash()) {
		return fmt.Errorf("retrieved block hash (%s) != header hash (%s)",
			retrieved.Hash(), blk.Hash())
	}

	return nil
}

func insertBlockHeader(ctx context.Context, db *ldb, prevHash *chainhash.Hash, height, nonce uint64) (tbcd.BlockHeader, tbcd.InsertType, error) {
	blk := createTestBlock(prevHash, int64(nonce))
	bh := &tbcd.BlockHeader{
		Hash:       *blk.Hash(),
		Height:     height,
		Header:     h2b(&blk.MsgBlock().Header),
		Difficulty: *big.NewInt(1),
	}
	bhs := []*tbcd.BlockHeader{bh}
	msgh := createTestMsgHeaders(bhs)
	var (
		it  tbcd.InsertType
		err error
	)
	if prevHash.IsEqual(&chainhash.Hash{}) {
		genesisWire := blk.MsgBlock().Header
		err := db.BlockHeaderGenesisInsert(ctx, genesisWire, 0, big.NewInt(1))
		if err != nil {
			return tbcd.BlockHeader{}, 0, err
		}
		it = tbcd.ITChainExtend
	} else {
		it, _, _, _, err = db.BlockHeadersInsert(ctx, msgh, nil)
		if err != nil {
			return tbcd.BlockHeader{}, 0, err
		}
	}

	// Check if we can retrieve header
	retrieved, err := db.BlockHeaderByHash(ctx, *blk.Hash())
	if err != nil {
		return tbcd.BlockHeader{}, 0, fmt.Errorf("BlockHeaderByHash: %w", err)
	}
	if !retrieved.Hash.IsEqual(blk.Hash()) {
		return tbcd.BlockHeader{}, 0, fmt.Errorf("retrieved header (%s) != header (%s)",
			retrieved.BlockHash(), blk.Hash())
	}

	return *bh, it, nil
}

func createNewDB(t *testing.T, ctx context.Context) (*ldb, func()) {
	home := t.TempDir()
	cfg, err := NewConfig("testnet3", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	discardFunc := func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return db, discardFunc
}

func TestBlockInsertAndRetrieve(t *testing.T) {
	const blkNum uint64 = 10

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, discard := createNewDB(t, ctx)
	defer discard()

	prevHash := &chainhash.Hash{}
	for i := range blkNum {
		bh, it, err := insertBlockHeader(ctx, db, prevHash, i, i)
		if err != nil {
			t.Fatal(err)
		}
		if it != tbcd.ITChainExtend {
			t.Fatalf("expected insert type %d, got %d",
				tbcd.ITChainExtend, it)
		}
		if err = insertBlock(ctx, db, bh); err != nil {
			t.Fatal(err)
		}
		best, err := db.BlockHeaderBest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !best.BlockHash().IsEqual(&bh.Hash) {
			t.Fatalf("hash: got %v, want %v",
				best.BlockHash(), bh.BlockHash())
		}
		if best.Height != bh.Height {
			t.Fatalf("height: got %d, want %d",
				best.Height, bh.Height)
		}
		prevHash = bh.BlockHash()
	}
}

func TestBlockNegative(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, discard := createNewDB(t, ctx)
	defer discard()

	fakeHash := chainhash.Hash{0xFF}
	_, err := db.BlockByHash(ctx, fakeHash)
	if !errors.Is(err, database.ErrBlockNotFound) {
		t.Fatalf("expected error %v, got %v", database.ErrBlockNotFound, err)
	}

	exists, err := db.BlockExistsByHash(ctx, fakeHash)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("expected block not to exist")
	}
}

func TestBlocksMissing(t *testing.T) {
	const blkNum uint64 = 10

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, discard := createNewDB(t, ctx)
	defer discard()

	var (
		err error
		bh  tbcd.BlockHeader
		it  tbcd.InsertType
		bhs = make([]tbcd.BlockHeader, 0, blkNum-1)
	)
	for i := range blkNum {
		bh, it, err = insertBlockHeader(ctx, db, bh.BlockHash(), i, i)
		if err != nil {
			t.Fatal(err)
		}
		if it != tbcd.ITChainExtend {
			t.Fatalf("expected insert type %d, got %d",
				tbcd.ITChainExtend, it)
		}
		if i > 0 && i < blkNum-1 {
			// store most headers for insertion except for genesis
			// and last to manually verify deleting from missing
			// blocks table.
			bhs = append(bhs, bh)
		}
	}

	// Check missing blocks
	missing, err := db.BlocksMissing(ctx, int(blkNum))
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != len(bhs)+1 {
		t.Fatalf("expected %d missing blocks, got %d",
			len(bhs)+1, len(missing))
	}
	if missing[0].Height != 1 {
		t.Fatalf("expected height 1 to be missing, got %d", missing[0].Height)
	}

	// Insert blocks
	for _, bhc := range bhs {
		prevMissing := len(missing)
		if err := insertBlock(ctx, db, bhc); err != nil {
			t.Fatal(err)
		}
		missing, err = db.BlocksMissing(ctx, int(blkNum))
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != prevMissing-1 {
			t.Fatalf("expected %d missing blocks, got %d",
				prevMissing, len(missing)-1)
		}
	}

	// Delete missing block entry
	err = db.BlockMissingDelete(ctx, int64(blkNum)-1, bh.Hash)
	if err != nil {
		t.Fatal(err)
	}
	missing, err = db.BlocksMissing(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("expected no missing blocks, got %d", len(missing))
	}
}

func TestBlockHeadersFork(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, discard := createNewDB(t, ctx)
	defer discard()

	hashes := []*chainhash.Hash{{}}
	for i := range 2 {
		bh, it, err := insertBlockHeader(ctx, db, hashes[i], uint64(i), uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if it != tbcd.ITChainExtend {
			t.Fatalf("expected insert type %d, got %d",
				tbcd.ITChainExtend, it)
		}
		hashes = append(hashes, bh.BlockHash())
	}

	// Create a fork (non-canonical)
	bh, it, err := insertBlockHeader(ctx, db, hashes[1], 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if it != tbcd.ITForkExtend {
		t.Fatalf("expected insert type %d, got %d",
			tbcd.ITForkExtend, it)
	}
	best, err := db.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !best.BlockHash().IsEqual(hashes[2]) {
		t.Fatalf("hash: got %v, want %v", best.BlockHash(), hashes[2])
	}

	// Fork from main chain
	bh, it, err = insertBlockHeader(ctx, db, bh.BlockHash(), 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if it != tbcd.ITChainFork {
		t.Fatalf("expected insert type %d, got %d",
			tbcd.ITChainFork, it)
	}
	best, err = db.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !best.BlockHash().IsEqual(bh.BlockHash()) {
		t.Fatalf("hash: got %v, want %v", best.BlockHash(), bh.BlockHash())
	}
}

func TestBlockHeadersByHeight(t *testing.T) {
	const (
		blkNum  uint64 = 3
		forkNum uint64 = 3
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, discard := createNewDB(t, ctx)
	defer discard()

	gen, _, err := insertBlockHeader(ctx, db, &chainhash.Hash{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Insert N headers per height
	allHashes := make(map[uint64]map[chainhash.Hash]struct{}, blkNum)
	for k := range forkNum {
		hashes := []*chainhash.Hash{gen.BlockHash()}
		for i := range blkNum {
			bh, _, err := insertBlockHeader(ctx, db, hashes[i], i+1, i+k+1)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := allHashes[i+1]; !ok {
				allHashes[i+1] = make(map[chainhash.Hash]struct{}, forkNum)
			}
			allHashes[i+1][*bh.BlockHash()] = struct{}{}
			hashes = append(hashes, bh.BlockHash())
		}
	}

	// Check if retrieved headers match inserted headers
	for i := range blkNum {
		headers, err := db.BlockHeadersByHeight(ctx, i+1)
		if err != nil {
			t.Fatal(err)
		}
		if len(headers) != len(allHashes[i+1]) {
			t.Fatalf("expected %d retrieved headers @ %d, got %d",
				len(headers), i+1, len(allHashes[i+1]))
		}
		for _, h := range headers {
			if _, ok := allHashes[i+1][*h.BlockHash()]; !ok {
				spew.Dump(allHashes)
				t.Fatalf("unexpected header %v @ %d", h.BlockHash(), i+1)
			}
		}
	}
}
