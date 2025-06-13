// Copyright (c) 2025 Hemi Labs, Inc.
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
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-test/deep"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/level"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/testutil"
)

func TestMD(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()
	t.Logf("temp: %v", home)

	cfg, err := NewConfig("testnet3", home, "128kb", "1m")
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
		kssList, err := db.KeystonesByHeight(ctx, uint32(n+1), 1)
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
	kssList, err := db.KeystonesByHeight(ctx, 1, blockNum)
	if err != nil {
		t.Fatal(err)
	}

	if len(kssList) != kssPerBlock*blockNum {
		t.Fatalf("unexpected number of keystones: %d", len(kssList))
	}

	// check all heights with negative depth
	kssList, err = db.KeystonesByHeight(ctx, blockNum, -blockNum+1)
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

func TestUpgradeFull(t *testing.T) {
	home := t.TempDir()
	network := "upgradetest"
	t.Logf("temp: %v", home)

	err := testutil.Extract("testdata/testdatabase.tar.gz", home)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
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

	const (
		blockNum    = 7
		kssPerBlock = 5
	)

	// populate v1 db with various keystones
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
		bh, err := dbTemp.BlockHeadersByHeight(ctx, uint64(i+1))
		if err != nil {
			panic(err)
		}
		blkHash := bh[0].Hash
		ks.L1BlockNumber = uint32(i + 1)
		for range kssPerBlock {
			ks.L2BlockNumber = uint32(l2Block)
			abrvKs := hemi.L2KeystoneAbbreviate(ks).Serialize()
			kssMap[*hemi.L2KeystoneAbbreviate(ks).Hash()] = tbcd.Keystone{
				BlockHash:           blkHash,
				AbbreviatedKeystone: abrvKs,
				BlockHeight:         uint32(i + 1),
			}
			l2Block += 25
		}

		if err := dbTemp.v1BlockKeystoneUpdate(kssMap, blkHash); err != nil {
			panic(err)
		}
	}

	if err := dbTemp.Close(); err != nil {
		t.Fatal(err)
	}

	cfg.SetUpgradeOpen(false)

	// begin upgrades
	db, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.BlockHeadersByHeight(ctx, 9)
	if err != nil {
		t.Fatal(err)
	}

	// Pull version from DB
	version, err := db.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Fatalf("expected version 4, got %v", version)
	}

	// version 2 checks

	// Copied from level package because this test can't be run there.
	utxoIndexHashKey := []byte("utxoindexhash")
	txIndexHashKey := []byte("txindexhash")
	keystoneIndexHashKey := []byte("keystoneindexhash")
	// Make sure db no longer has index keys
	_, err = db.MetadataGet(ctx, utxoIndexHashKey)
	if err == nil {
		t.Fatal("expected failure retrieving utxo index hash")
	}
	_, err = db.MetadataGet(ctx, txIndexHashKey)
	if err == nil {
		t.Fatal("expected failure retrieving tx index hash")
	}
	_, err = db.MetadataGet(ctx, keystoneIndexHashKey)
	if err == nil {
		t.Fatal("expected failure retrieving keystone index hash")
	}

	// Make sure we get the expected indexkeys from db
	hash, err := chainhash.NewHashFromStr("0000000050ff3053ada24e6ad581fa0295297f20a2747d034997ffc899aa931e")
	if err != nil {
		panic(err)
	}
	utxobh, err := db.BlockHeaderByUtxoIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !utxobh.Hash.IsEqual(hash) {
		t.Fatal("unexpected utxo hash")
	}

	txbh, err := db.BlockHeaderByTxIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !txbh.Hash.IsEqual(hash) {
		t.Fatal("unexpected tx hash")
	}

	keystonebh, err := db.BlockHeaderByKeystoneIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !keystonebh.Hash.IsEqual(hash) {
		t.Fatal("unexpected keystone hash")
	}

	aks, err := db.KeystonesByHeight(ctx, 10, -9)
	if err != nil {
		t.Fatal(err)
	}

	for h, k := range kssMap {
		var found bool
		for _, ak := range aks {
			if diff := deep.Equal(ak, k); len(diff) > 0 {
				continue
			}
			found = true
		}
		if !found {
			t.Fatalf("missing keystone: %v", h)
		}
	}
}

func TestDbUpgradePipeline(t *testing.T) {
	home := t.TempDir()
	network := "upgradetest"
	t.Logf("temp: %v", home)

	err := testutil.Extract("testdata/testdatabase.tar.gz", home)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer func() {
		cancel()
	}()

	t.Log("Upgrading with move")

	// We are setting the batchSize to exercise restarts.
	SetBatchSize(3)

	// Upgrade database to v3 with move
	cfg, err := NewConfig(network, home, "0mb", "0mb")
	if err != nil {
		t.Fatal(err)
	}

	dbTemp, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Get all db keys
	keys := make([]string, 0, len(dbTemp.DB()))
	for k := range dbTemp.DB() {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Close temporary DB
	if err = dbTemp.Close(); err != nil {
		t.Fatal(err)
	}

	// Rename database $HOME to $HOME.move
	err = os.Rename(cfg.Home, cfg.Home+".move")
	if err != nil {
		t.Fatal(fmt.Errorf("rename destination: %w", err))
	}

	// Open move DB
	cfgMove, err := NewConfig(network, home, "0mb", "0mb")
	if err != nil {
		t.Fatal(err)
	}

	cfgMove.Home = cfgMove.Home + ".move"

	dbMove, err := New(ctx, cfgMove)
	if err != nil {
		t.Fatal(err)
	}

	err = testutil.Extract("testdata/testdatabase.tar.gz", home)
	if err != nil {
		t.Fatal(err)
	}

	// Set mode to copy
	SetMode(false)

	t.Log("Upgrading with copy")

	// Upgrade database to v3 with copy which
	// creates a testnet3.v3 folder
	dbv2, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Open copy DB
	cfgCopy, err := NewConfig(network, home, "0mb", "0mb")
	if err != nil {
		t.Fatal(err)
	}

	cfgCopy.Home = cfgCopy.Home + ".v3"

	dbCopy, err := New(ctx, cfgCopy)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Comparing DBs")

	// Compare all databases
	for _, dbs := range keys {
		a := dbv2.DB()[dbs]
		b := dbMove.DB()[dbs]
		c := dbCopy.DB()[dbs]

		t.Logf("Comparing original records against dbmove (%v)", dbs)
		records, err := cmpDB(a, b)
		if err != nil {
			t.Errorf("found diff in record %v: %v", records, err)
		} else {
			t.Logf("Found no diff in %v records of %v", records, dbs)
		}

		t.Logf("Comparing dbmove records against original (%v)", dbs)
		records, err = cmpDB(b, a)
		if err != nil {
			t.Errorf("found diff in record %v: %v", records, err)
		} else {
			t.Logf("Found no diff in %v records of %v", records, dbs)
		}

		t.Logf("Comparing original records against dbcopy (%v)", dbs)
		records, err = cmpDB(a, c)
		if err != nil {
			t.Errorf("found diff in record %v: %v", records, err)
		} else {
			t.Logf("Found no diff in %v records of %v", records, dbs)
		}

		t.Logf("Comparing dbcopy records against original (%v)", dbs)
		records, err = cmpDB(c, a)
		if err != nil {
			t.Errorf("found diff in record %v: %v", records, err)
		} else {
			t.Logf("Found no diff in %v records of %v", records, dbs)
		}
	}
}

func cmpDB(a, b *leveldb.DB) (int, error) {
	i := a.NewIterator(nil, nil)
	defer func() { i.Release() }()

	records := 0
	for records = 0; i.Next(); records++ {
		v, err := b.Get(i.Key(), nil)
		if err != nil {
			return records, err
		}

		if diff := deep.Equal(i.Value(), v); len(diff) > 0 {
			return records, fmt.Errorf("unexpected diff: %v", diff)
		}
	}
	return records, nil
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

				kssList, err := db.KeystonesByHeight(ctx, ks.BlockHeight, 1)
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
				kssList, err := db.KeystonesByHeight(ctx, ks.BlockHeight, 1)
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

	ehash, err := chainhash.NewHash(e[5 : 5+32])
	if err != nil {
		t.Fatal(err)
	}

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

func (l *ldb) v1BlockKeystoneUpdate(keystones map[chainhash.Hash]tbcd.Keystone, keystoneIndexHash chainhash.Hash) error {
	log.Tracef("BlockKeystoneUpdate")
	defer log.Tracef("BlockKeystoneUpdate exit")

	// keystones
	kssTx, kssCommit, kssDiscard, err := l.startTransaction(level.KeystonesDB)
	if err != nil {
		return fmt.Errorf("keystones open db transaction: %w", err)
	}
	defer kssDiscard()

	kssBatch := new(leveldb.Batch)
	for k, v := range keystones {
		has, _ := kssTx.Has(k[:], nil)
		if !has {
			// Only store unknown keystones
			kssBatch.Put(k[:], encodeKeystoneToSliceV1(v))
		}
	}

	// Store index
	kssBatch.Put(keystoneIndexHashKey, keystoneIndexHash[:])

	// Write keystones batch
	if err = kssTx.Write(kssBatch, nil); err != nil {
		return fmt.Errorf("keystones insert: %w", err)
	}

	// keystones commit
	if err = kssCommit(); err != nil {
		return fmt.Errorf("keystones commit: %w", err)
	}

	return nil
}

func encodeKeystoneV1(ks tbcd.Keystone) (eks [chainhash.HashSize + hemi.L2KeystoneAbrevSize]byte) {
	copy(eks[0:32], ks.BlockHash[:])
	copy(eks[32:], ks.AbbreviatedKeystone[:])
	return
}

func encodeKeystoneToSliceV1(ks tbcd.Keystone) []byte {
	eks := encodeKeystoneV1(ks)
	return eks[:]
}
