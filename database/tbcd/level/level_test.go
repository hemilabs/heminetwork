package level_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-test/deep"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/hemi"
)

func TestMD(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	home := t.TempDir()
	t.Logf("temp: %v", home)

	cfg := level.NewConfig(home, "128kb", "1m")
	db, err := level.New(ctx, cfg)
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

	qr := make([][]byte, x+1)
	for i := 0; i <= x; i++ {
		y := byte(i)
		qr[i] = []byte{y}
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

	// fail one
	rv, err = db.MetadataGet(ctx, []byte("nope"))
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("expected '%v', got '%v'", database.ErrNotFound, err)
	}
	if rv != nil {
		t.Fatal("expected no return value")
	}
}

func fillOutBytes(prefix string, size int) []byte {
	result := []byte(prefix)
	for len(result) < size {
		result = append(result, '_')
	}
	return result
}

func makeKssMap(kssList []hemi.L2Keystone) map[chainhash.Hash]tbcd.Keystone {
	kssMap := make(map[chainhash.Hash]tbcd.Keystone)
	for _, l2Keystone := range kssList {
		abrvKs := hemi.L2KeystoneAbbreviate(l2Keystone).Serialize()
		kssMap[*hemi.L2KeystoneAbbreviate(l2Keystone).Hash()] = tbcd.Keystone{
			BlockHash:           btcchainhash.Hash(fillOutBytes("blockhash", 32)),
			AbbreviatedKeystone: abrvKs,
		}
	}
	return kssMap
}

func TestKeystoneUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	kssList := []hemi.L2Keystone{
		{
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       fillOutBytes("v1parentephash", 32),
			PrevKeystoneEPHash: fillOutBytes("v1prevkeystoneephash", 32),
			StateRoot:          fillOutBytes("v1stateroot", 32),
			EPHash:             fillOutBytes("v1ephash", 32),
		},
		{
			Version:            1,
			L1BlockNumber:      6,
			L2BlockNumber:      44,
			ParentEPHash:       fillOutBytes("v2parentephash", 32),
			PrevKeystoneEPHash: fillOutBytes("v2prevkeystoneephash", 32),
			StateRoot:          fillOutBytes("v2stateroot", 32),
			EPHash:             fillOutBytes("v2ephash", 32),
		},
		{
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       fillOutBytes("i1parentephash", 32),
			PrevKeystoneEPHash: fillOutBytes("i1prevkeystoneephash", 32),
			StateRoot:          fillOutBytes("i1stateroot", 32),
			EPHash:             fillOutBytes("i1ephash", 32),
		},
		{
			Version:            1,
			L1BlockNumber:      6,
			L2BlockNumber:      44,
			ParentEPHash:       fillOutBytes("i2parentephash", 32),
			PrevKeystoneEPHash: fillOutBytes("i2prevkeystoneephash", 32),
			StateRoot:          fillOutBytes("i2stateroot", 32),
			EPHash:             fillOutBytes("i2ephash", 32),
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
			expectedOutDB: makeKssMap(kssList[:]),
			expectedError: fmt.Errorf("invalid direction: %v", 0),
		},
		{
			name:          "nilMap",
			direction:     []int{-1, 1},
			expectedOutDB: makeKssMap(kssList),
		},
		{
			name:          "emptyMap",
			direction:     []int{-1, 1},
			kssMap:        makeKssMap(nil),
			expectedOutDB: makeKssMap(kssList),
		},

		{
			name:           "duplicateInsert",
			direction:      []int{1},
			expectedError:  nil,
			preInsertValid: true,
			kssMap:         makeKssMap(kssList[:2]),
			expectedInDB:   makeKssMap(kssList[:2]),
			expectedOutDB:  makeKssMap(kssList[2:]),
		},

		{
			name:          "invalidRemove",
			direction:     []int{-1},
			kssMap:        makeKssMap(kssList[2:]),
			expectedOutDB: makeKssMap(kssList),
		},
		{
			name:          "validInsert",
			direction:     []int{1},
			kssMap:        makeKssMap(kssList[:2]),
			expectedInDB:  makeKssMap(kssList[:2]),
			expectedOutDB: makeKssMap(kssList[2:]),
		},
		{
			name:          "validRemove",
			direction:     []int{1, -1},
			kssMap:        makeKssMap(kssList[2:]),
			expectedOutDB: makeKssMap(kssList),
		},
		{
			name:           "mixedRemove",
			direction:      []int{-1},
			preInsertValid: true,
			kssMap:         makeKssMap(kssList),
			expectedOutDB:  makeKssMap(kssList),
		},
		{
			name:           "mixedInsert",
			direction:      []int{1},
			preInsertValid: true,
			kssMap:         makeKssMap(kssList),
			expectedInDB:   makeKssMap(kssList),
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			home := t.TempDir()
			t.Logf("temp: %v", home)

			cfg := level.NewConfig(home, "", "")
			db, err := level.New(ctx, cfg)
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
				if err := db.BlockKeystoneUpdate(ctx, 1, makeKssMap(kssList[:2])); err != nil {
					t.Fatal(err)
				}
			}

			for _, dir := range tti.direction {
				err := db.BlockKeystoneUpdate(ctx, dir, tti.kssMap)
				if diff := deep.Equal(err, tti.expectedError); len(diff) > 0 {
					t.Fatalf("(direction %v) unexpected error diff: %s", dir, diff)
				}
			}

			for v := range tti.expectedInDB {
				_, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, v)
				if err != nil {
					t.Fatalf("keystone not in db: %v", err)
				}
			}

			for k, v := range tti.expectedOutDB {
				_, err := db.BlockKeystoneByL2KeystoneAbrevHash(ctx, k)
				if err == nil {
					t.Fatalf("keystone in db: %v", spew.Sdump(v))
				} else {
					if !errors.Is(err, database.ErrNotFound) {
						t.Fatalf("expected '%v', got '%v'", database.ErrNotFound, err)
					}
				}
			}
		})
	}
}
