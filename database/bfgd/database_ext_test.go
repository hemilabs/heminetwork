// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfgd_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	mathrand "math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/bfgd"
	"github.com/hemilabs/heminetwork/database/bfgd/postgres"
	"github.com/hemilabs/heminetwork/testutil"
)

const testDBPrefix = "bfgdtestdb"

func createTestDB(ctx context.Context, t *testing.T) (bfgd.Database, *sql.DB, func()) {
	t.Helper()

	pgURI := os.Getenv("PGTESTURI")
	if pgURI == "" {
		t.Skip("PGTESTURI environment variable is not set, skipping...")
	}

	var (
		cleanup     func()
		ddb, sdb    *sql.DB
		needCleanup = true
	)
	defer func() {
		if !needCleanup {
			return
		}
		if sdb != nil {
			sdb.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		if ddb != nil {
			ddb.Close()
		}
	}()

	ddb, err := postgres.Connect(ctx, pgURI)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	dbn := mathrand.IntN(999999999)
	dbName := fmt.Sprintf("%v_%d", testDBPrefix, dbn)

	t.Logf("Creating test database %v", dbName)

	qCreateDB := fmt.Sprintf("CREATE DATABASE %v", dbName)
	if _, err := ddb.ExecContext(ctx, qCreateDB); err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup = func() {
		t.Logf("Removing test database %v", dbName)
		qDropDB := fmt.Sprintf("DROP DATABASE %v", dbName)
		if _, err := ddb.ExecContext(ctx, qDropDB); err != nil {
			t.Fatalf("Failed to drop test database: %v", err)
		}
		ddb.Close()
	}

	u, err := url.Parse(pgURI)
	if err != nil {
		t.Fatalf("Failed to parse postgresql URI: %v", err)
	}
	u.Path = dbName

	sdb, err = postgres.Connect(ctx, u.String())
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Load schema.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	applySQLFiles(ctx, t, sdb, filepath.Join(wd, "./scripts/*.sql"))

	db, err := postgres.New(ctx, u.String())
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	needCleanup = false

	return db, sdb, cleanup
}

func applySQLFiles(ctx context.Context, t *testing.T, sdb *sql.DB, path string) {
	t.Helper()

	sqlFiles, err := filepath.Glob(path)
	if err != nil {
		t.Fatalf("Failed to get schema files: %v", err)
	}
	sort.Strings(sqlFiles)
	for _, sqlFile := range sqlFiles {
		t.Logf("Applying SQL file %v", filepath.Base(sqlFile))
		sql, err := os.ReadFile(sqlFile)
		if err != nil {
			t.Fatalf("Failed to read SQL file: %v", err)
		}
		if _, err := sdb.ExecContext(ctx, string(sql)); err != nil {
			t.Fatalf("Failed to execute SQL: %v", err)
		}
	}
}

func TestDatabaseTestData(t *testing.T) {
	ctx := t.Context()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	// Load test data.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	applySQLFiles(ctx, t, sdb, filepath.Join(wd, "./scripts/testdata/*.sql"))
}

func TestDatabasePostgres(t *testing.T) {
	ctx := t.Context()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	// Version, no need to verify because it is explicitly tested on db open
	version, err := db.Version(ctx)
	if err != nil {
		t.Fatalf("Failed to get Version: %v", err)
	}
	t.Logf("db version: %v", version)

	// L2KeystonesInsert
	b1 := [32]byte{1}
	b1Hash := chainhash.DoubleHashB(b1[:])
	ks1 := bfgd.L2Keystone{
		Hash:               b1Hash,
		Version:            1,
		L1BlockNumber:      1,
		L2BlockNumber:      1,
		ParentEPHash:       b1Hash,
		PrevKeystoneEPHash: b1Hash,
		StateRoot:          b1Hash,
		EPHash:             b1Hash,
	}
	b2 := [32]byte{2}
	b2Hash := chainhash.DoubleHashB(b2[:])
	ks2 := bfgd.L2Keystone{
		Hash:               b2Hash,
		Version:            1,
		L1BlockNumber:      2,
		L2BlockNumber:      2,
		ParentEPHash:       b2Hash,
		PrevKeystoneEPHash: b2Hash,
		StateRoot:          b2Hash,
		EPHash:             b2Hash,
	}
	l2ksIn := []bfgd.L2Keystone{ks1, ks2}
	err = db.L2KeystonesInsert(ctx, l2ksIn)
	if err != nil {
		t.Fatalf("Failed to get L2 keystones: %v", err)
	}
	// Get keystones back out
	for k := range l2ksIn {
		l2ksOut, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(l2ksIn[k].Hash))
		if err != nil {
			t.Fatalf("Failed to get L2 keystones: %v", err)
		}
		diff := deep.Equal(*l2ksOut, l2ksIn[k])
		if len(diff) > 0 {
			t.Fatalf("Failed %v to verify keystone got %v, wanted %v%v",
				k, spew.Sdump(*l2ksOut), spew.Sdump(l2ksIn[k]), diff)
		}
	}
	// Most recent
	l2ksOut, err := db.L2KeystonesMostRecentN(ctx, 1, 0)
	if err != nil {
		t.Fatalf("Failed to get most recent L2 keystone: %v", err)
	}
	diff := deep.Equal(l2ksOut[0], l2ksIn[1])
	if len(diff) > 0 {
		t.Fatalf("Failed to verify most recent keystone got %v, wanted %v%v",
			spew.Sdump(l2ksOut[0]), spew.Sdump(l2ksIn[1]), diff)
	}

	// Insert BTC block
	bb1Header := [80]byte{1}
	h := chainhash.DoubleHashB(bb1Header[:])
	var bb1Hash [32]byte
	copy(bb1Hash[:], h)
	bb1In := bfgd.BtcBlock{
		Hash:   database.ByteArray(bb1Hash[:]),
		Header: database.ByteArray(bb1Header[:]),
		Height: 1,
	}
	err = db.BtcBlockInsert(ctx, &bb1In)
	if err != nil {
		t.Fatalf("Failed to insert bitcoin block: %v", err)
	}
	// Get BTC block
	bb1Out, err := db.BtcBlockByHash(ctx, bb1Hash)
	if err != nil {
		t.Fatalf("Failed to get bitcoin block: %v", err)
	}
	diff = deep.Equal(*bb1Out, bb1In)
	if len(diff) > 0 {
		t.Fatalf("Failed to get bitcoin block 1 got %v, want %v%v",
			spew.Sdump(*bb1Out), spew.Sdump(bb1In), diff)
	}
	// Get BTC block height
	height, err := db.BtcBlockHeightByHash(ctx, bb1Hash)
	if err != nil {
		t.Fatalf("Failed to get bitcoin block height: %v", err)
	}
	if height != bb1In.Height {
		t.Fatalf("Failed to get bitcoin block height got %v, want %v",
			height, bb1In.Height)
	}

	// Pop basis insert half
	btcTx := [285]byte{1}
	btcTxHash := chainhash.DoubleHashB(btcTx[:])
	popMinerPublicKey := [63]byte{'1', '2', '3', '4'}
	h = chainhash.DoubleHashB(popMinerPublicKey[:])
	var l2KAH [32]byte
	copy(l2KAH[:], h)
	pbHalfIn := bfgd.PopBasis{
		BtcTxId:             btcTxHash,
		BtcRawTx:            btcTx[:],
		BtcHeaderHash:       bb1Hash[:],
		PopMinerPublicKey:   popMinerPublicKey[:],
		L2KeystoneAbrevHash: l2KAH[:],
	}
	err = db.PopBasisInsertFull(ctx, &pbHalfIn)
	if err != nil {
		t.Fatalf("Failed to insert pop basis: %v", err)
	}

	// Pop basis get half
	pbHalfOut, err := db.PopBasisByL2KeystoneAbrevHash(ctx, l2KAH, true, 0)
	if err != nil {
		t.Fatalf("Failed to get pop basis: %v", err)
	}
	diff = deep.Equal(pbHalfOut[0], pbHalfIn)
	if len(diff) > 0 {
		t.Fatalf("Failed to get l2 half got %v, want %v%v",
			spew.Sdump(pbHalfOut[0]), spew.Sdump(pbHalfIn), diff)
	}
}

// XXX make this generic and table driven for all notifications
type btcBlocksNtfn struct {
	t *testing.T

	cancel context.CancelFunc

	// add expect
	expected *bfgd.BtcBlock
}

func (b *btcBlocksNtfn) handleBtcBlocksNotification(pctx context.Context, table string, action string, payload, payloadOld interface{}) {
	defer b.cancel()
	bb := payload.(*bfgd.BtcBlock)
	if !reflect.DeepEqual(*b.expected, *bb) {
		b.t.Fatalf("expected %v, got %v",
			spew.Sdump(*b.expected), spew.Sdump(*bb))
	}
}

func TestBtcBlockReplaceNotIfSameBlock(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	btcBlock := bfgd.BtcBlock{
		Hash:   testutil.FillBytes("MyHaSh", 32),
		Header: testutil.FillBytes("myHeAdEr", 80),
		Height: 1,
	}

	rowsAffected, err := db.BtcBlockReplace(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 1 {
		t.Fatalf("unexpected rows affected: %d", rowsAffected)
	}

	rowsAffected, err = db.BtcBlockReplace(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 0 {
		t.Fatalf("unexpected rows affected: %d", rowsAffected)
	}

	result, err := db.BtcBlockByHash(ctx, [32]byte(btcBlock.Hash))
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(result, &btcBlock); len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}
}

func TestBtcBlockReplaceIfDifferentBlocks(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	btcBlock := bfgd.BtcBlock{
		Hash:   testutil.FillBytes("MyHaSh", 32),
		Header: testutil.FillBytes("myHeAdEr", 80),
		Height: 1,
	}

	rowsAffected, err := db.BtcBlockReplace(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 1 {
		t.Fatalf("unexpected rows affected: %d", rowsAffected)
	}

	btcBlock.Hash = testutil.FillBytes("differenthash", 32)
	btcBlock.Header = testutil.FillBytes("differentheader", 80)

	rowsAffected, err = db.BtcBlockReplace(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 1 {
		t.Fatalf("unexpected rows affected: %d", rowsAffected)
	}

	result, err := db.BtcBlockByHash(ctx, [32]byte(btcBlock.Hash))
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(result, &btcBlock); len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}
}

func TestBtcBlockNoReplaceIfDifferentBlocksAtDifferentHeights(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	btcBlock := bfgd.BtcBlock{
		Hash:   testutil.FillBytes("MyHaSh", 32),
		Header: testutil.FillBytes("myHeAdEr", 80),
		Height: 1,
	}

	rowsAffected, err := db.BtcBlockReplace(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 1 {
		t.Fatalf("unexpected rows affected: %d", rowsAffected)
	}

	btcBlock.Hash = testutil.FillBytes("differenthash", 32)
	btcBlock.Header = testutil.FillBytes("differentheader", 80)
	btcBlock.Height = 7

	rowsAffected, err = db.BtcBlockReplace(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 1 {
		t.Fatalf("unexpected rows affected: %d", rowsAffected)
	}

	result, err := db.BtcBlockByHash(ctx, [32]byte(testutil.FillBytes("MyHaSh", 32)))
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(result, &bfgd.BtcBlock{
		Hash:   testutil.FillBytes("MyHaSh", 32),
		Header: testutil.FillBytes("myHeAdEr", 80),
		Height: 1,
	}); len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}

	result, err = db.BtcBlockByHash(ctx, [32]byte(btcBlock.Hash))
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(result, &btcBlock); len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}
}

func TestDatabaseNotification(t *testing.T) {
	pctx := t.Context()

	db, sdb, cleanup := createTestDB(pctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	btcBlock := &bfgd.BtcBlock{
		Hash:   testutil.FillBytes("MyHaSh", 32),
		Header: testutil.FillBytes("myHeAdEr", 80),
		Height: 1,
	}
	// Register notification
	ctx, cancel := context.WithTimeout(pctx, 5*time.Second)
	defer cancel()
	b := &btcBlocksNtfn{
		t:        t,
		cancel:   cancel,
		expected: btcBlock,
	}
	payload, _ := bfgd.NotificationPayload(bfgd.NotificationBtcBlocks)
	if err := db.RegisterNotification(ctx, bfgd.NotificationBtcBlocks,
		b.handleBtcBlocksNotification, payload); err != nil {
		t.Fatalf("register notification: %v", err)
	}

	err := db.BtcBlockInsert(ctx, btcBlock)
	if err != nil {
		t.Fatalf("Failed to insert bitcoin block: %v", err)
	}

	// Wait for completion or timeout
	<-ctx.Done()
	if ctx.Err() != context.Canceled {
		t.Fatal(ctx.Err())
	}
}

func defaultTestContext(t *testing.T) (context.Context, func()) {
	return context.WithTimeout(t.Context(), 300*time.Second)
}

func TestL2KeystoneInsertSuccess(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err != nil {
		t.Fatal(err)
	}

	saved, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(l2Keystone.Hash))
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(saved, &l2Keystone)
	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 1 {
		t.Fatalf("unexpected count %d", count)
	}
}

func TestL2KeystoneInsertMultipleSuccess(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	otherL2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhashz", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone, otherL2Keystone})
	if err != nil {
		t.Fatal(err)
	}

	saved, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(l2Keystone.Hash))
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(saved, &l2Keystone)
	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	otherSaved, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(otherL2Keystone.Hash))
	if err != nil {
		t.Fatal(err)
	}

	diff = deep.Equal(otherSaved, &otherL2Keystone)
	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Fatalf("unexpected count %d", count)
	}
}

func TestL2KeystoneInsertIgnoreDuplicates(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	otherL2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhashz", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone, otherL2Keystone})
	if err != nil {
		t.Fatal(err)
	}

	err = db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone, otherL2Keystone})
	if err != nil {
		t.Fatal(err)
	}

	saved, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(l2Keystone.Hash))
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(saved, &l2Keystone)
	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	otherSaved, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(otherL2Keystone.Hash))
	if err != nil {
		t.Fatal(err)
	}

	diff = deep.Equal(otherSaved, &otherL2Keystone)
	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Fatalf("unexpected count %d", count)
	}
}

func TestL2KeystoneInsertInvalidHashLength(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 31),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err == nil || errors.Is(database.ValidationError(""), err) == false {
		t.Fatalf("unexpected error %s", err)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatalf("unexpected count %d", count)
	}
}

func TestL2KeystoneInsertInvalidEPHashLength(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 31),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err == nil || errors.Is(database.ValidationError(""), err) == false {
		t.Fatalf("unexpected error %s", err)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatalf("unexpected count %d", count)
	}
}

func TestL2KeystoneInsertInvalidStateRootLength(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 31),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err == nil || errors.Is(database.ValidationError(""), err) == false {
		t.Fatalf("unexpected error %s", err)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatalf("unexpected count %d", count)
	}
}

func TestL2KeystoneInsertInvalidPrevKeystoneEPHashLength(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 31),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err == nil || errors.Is(database.ValidationError(""), err) == false {
		t.Fatalf("unexpected error %s", err)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatalf("unexpected count %d", count)
	}
}

func TestL2KeystoneInsertInvalidParentEPHashLength(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 31),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err == nil || errors.Is(database.ValidationError(""), err) == false {
		t.Fatalf("unexpected error %s", err)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatalf("unexpected count %d", count)
	}
}

func TestL2KeystoneByAbrevHashNotFound(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	_, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(testutil.FillBytes("doesnotexist", 32)))
	if err == nil || errors.Is(err, database.NotFoundError("")) == false {
		t.Fatalf("unexpected error %s", err)
	}
}

func TestL2KeystoneByAbrevHashFound(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	l2KeystoneSaved, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(l2Keystone.Hash))
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	diff := deep.Equal(l2KeystoneSaved, &l2Keystone)
	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestL2KeystoneInsertMostRecentNMoreThanSaved(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	otherL2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      23,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhashz", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone, otherL2Keystone})
	if err != nil {
		t.Fatal(err)
	}

	l2KeystonesSaved, err := db.L2KeystonesMostRecentN(ctx, 5, 0)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(l2KeystonesSaved, []bfgd.L2Keystone{
		otherL2Keystone,
		l2Keystone,
	})

	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestL2KeystoneInsertMostRecentNFewerThanSaved(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	otherL2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      23,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhashz", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone, otherL2Keystone})
	if err != nil {
		t.Fatal(err)
	}

	l2KeystonesSaved, err := db.L2KeystonesMostRecentN(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(l2KeystonesSaved, []bfgd.L2Keystone{
		otherL2Keystone,
	})

	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestL2KeystoneInsertMostRecentNLimit100(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	var l2BlockNumber uint32 = 100

	toInsert := []bfgd.L2Keystone{}

	for range 101 {
		l2BlockNumber++

		l2Keystone := bfgd.L2Keystone{
			Version:            1,
			L1BlockNumber:      11,
			L2BlockNumber:      l2BlockNumber,
			ParentEPHash:       testutil.FillBytes("parentephash", 32),
			PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
			StateRoot:          testutil.FillBytes("stateroot", 32),
			EPHash:             testutil.FillBytes("ephash", 32),
			Hash:               testutil.FillBytes(fmt.Sprintf("mockhash%d", l2BlockNumber), 32),
		}

		toInsert = append(toInsert, l2Keystone)
	}

	err := db.L2KeystonesInsert(ctx, toInsert)
	if err != nil {
		t.Fatal(err)
	}

	l2KeystonesSaved, err := db.L2KeystonesMostRecentN(ctx, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}

	if len(l2KeystonesSaved) != 100 {
		t.Fatalf("was expected 100 l2keystones, received %d", len(l2KeystonesSaved))
	}
}

func TestL2KeystoneInsertMultipleAtomicFailure(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 31), // this will fail, the insert should thus fail
	}

	otherL2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhashz", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone, otherL2Keystone})
	if err == nil || errors.Is(err, database.ValidationError("")) == false {
		t.Fatalf("insert should have failed but it did not: %s", err)
	}

	count, err := l2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatal("nothing should have been inserted")
	}
}

func TestL2KeystoneInsertDuplicateOK(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	l2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	otherL2Keystone := bfgd.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
		Hash:               testutil.FillBytes("mockhash", 32),
	}

	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone, otherL2Keystone})
	if err != nil {
		t.Fatalf("received unexpected error: %s", err)
	}

	l2Keystones, err := db.L2KeystonesMostRecentN(ctx, 5, 0)
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal([]bfgd.L2Keystone{l2Keystone}, l2Keystones); len(diff) != 0 {
		log.Fatalf("unexpected diff %v", diff)
	}
}

func TestPopBasisInsertNilMerklePath(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	popBasis := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid", 32),
		BtcRawTx:            testutil.FillBytes("btcrawtx", 80),
		PopMinerPublicKey:   []byte("popminerpublickey"),
		L2KeystoneAbrevHash: testutil.FillBytes("l2keystoneabrevhash", 32),
	}

	err := db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	popBasesSaved, err := db.PopBasisByL2KeystoneAbrevHash(
		ctx,
		[32]byte(testutil.FillBytes("l2keystoneabrevhash", 32)),
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(popBasesSaved) != 1 {
		t.Fatalf("unexpected popBasesSaved length: %d", len(popBasesSaved))
	}

	if popBasesSaved[0].BtcMerklePath != nil {
		t.Fatalf(
			"expected nil merkle path, received: %v",
			popBasesSaved[0].BtcMerklePath,
		)
	}
}

func TestPopBasisInsertNotNilMerklePath(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	popBasis := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid", 32),
		BtcRawTx:            testutil.FillBytes("btcrawtx", 80),
		PopMinerPublicKey:   []byte("popminerpublickey"),
		L2KeystoneAbrevHash: testutil.FillBytes("l2keystoneabrevhash", 32),
		BtcMerklePath:       []string{"one", "two"},
	}

	err := db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	popBasesSaved, err := db.PopBasisByL2KeystoneAbrevHash(
		ctx,
		[32]byte(testutil.FillBytes("l2keystoneabrevhash", 32)),
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(popBasesSaved) != 1 {
		t.Fatalf("unexpected popBasesSaved length: %d", len(popBasesSaved))
	}

	if slices.Equal(popBasesSaved[0].BtcMerklePath, []string{"one", "two"}) == false {
		t.Fatalf(
			"unexpected merkle path, received: %v",
			popBasesSaved[0].BtcMerklePath,
		)
	}
}

func TestPopBasisInsertNilMerklePathFromPopM(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	popBasis := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid", 32),
		BtcRawTx:            testutil.FillBytes("btcrawtx", 80),
		PopMinerPublicKey:   []byte("popminerpublickey"),
		L2KeystoneAbrevHash: testutil.FillBytes("l2keystoneabrevhash", 32),
	}

	err := db.PopBasisInsertPopMFields(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	popBasesSaved, err := db.PopBasisByL2KeystoneAbrevHash(
		ctx,
		[32]byte(testutil.FillBytes("l2keystoneabrevhash", 32)),
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(popBasesSaved) != 1 {
		t.Fatalf("unexpected popBasesSaved length: %d", len(popBasesSaved))
	}

	if popBasesSaved[0].BtcMerklePath != nil {
		t.Fatalf(
			"expected nil merkle path, received: %v",
			popBasesSaved[0].BtcMerklePath,
		)
	}
}

func TestPopBasisUpdateNoneExist(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	btcBlock := bfgd.BtcBlock{
		Hash:   testutil.FillBytes("myhash", 32),
		Header: testutil.FillBytes("myheader", 80),
		Height: 1,
	}

	err := db.BtcBlockInsert(ctx, &btcBlock)
	if err != nil {
		t.Fatalf("Failed to insert bitcoin block: %v", err)
	}

	var txIndex uint64 = 2

	popBasis := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid2", 32),
		BtcRawTx:            []byte("btcrawtx2"),
		PopTxId:             testutil.FillBytes("poptxid2", 32),
		L2KeystoneAbrevHash: testutil.FillBytes("l2keystoneabrevhash", 32),
		PopMinerPublicKey:   testutil.FillBytes("popminerpublickey", 32),
		BtcHeaderHash:       btcBlock.Hash,
		BtcTxIndex:          &txIndex,
	}

	rowsAffected, err := db.PopBasisUpdateBTCFields(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 0 {
		t.Fatalf("unexpected number of rows affected %d", rowsAffected)
	}
}

func TestPopBasisUpdateOneExistsWithNonNullBTCFields(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	btcBlock := bfgd.BtcBlock{
		Hash:   testutil.FillBytes("myhash", 32),
		Header: testutil.FillBytes("myheader", 80),
		Height: 1,
	}

	err := db.BtcBlockInsert(ctx, &btcBlock)
	if err != nil {
		t.Fatalf("Failed to insert bitcoin block: %v", err)
	}

	var txIndex uint64 = 2

	popBasis := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid2", 32),
		BtcRawTx:            []byte("btcrawtx2"),
		PopTxId:             testutil.FillBytes("poptxid2", 32),
		L2KeystoneAbrevHash: testutil.FillBytes("l2keystoneabrevhash", 32),
		PopMinerPublicKey:   testutil.FillBytes("popminerpublickey", 32),
		BtcHeaderHash:       btcBlock.Hash,
		BtcTxIndex:          &txIndex,
	}

	err = db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	var txIndex2 uint64 = 3

	popBasis2 := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid2", 32),
		BtcRawTx:            []byte("btcrawtx2"),
		PopTxId:             testutil.FillBytes("poptxid2", 32),
		L2KeystoneAbrevHash: testutil.FillBytes("l2keystoneabrevhash", 32),
		PopMinerPublicKey:   testutil.FillBytes("popminerpublickey", 32),
		BtcHeaderHash:       btcBlock.Hash,
		BtcTxIndex:          &txIndex2,
	}

	rowsAffected, err := db.PopBasisUpdateBTCFields(ctx, &popBasis2)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 0 {
		t.Fatalf("unexpected number of rows affected %d", rowsAffected)
	}

	popBases, err := db.PopBasisByL2KeystoneAbrevHash(
		ctx,
		[32]byte(testutil.FillBytes("l2keystoneabrevhash", 32)),
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(popBases, []bfgd.PopBasis{
		popBasis,
	})

	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	err = db.PopBasisInsertFull(ctx, &popBasis2)
	if err != nil {
		t.Fatal(err)
	}

	popBases, err = db.PopBasisByL2KeystoneAbrevHash(
		ctx,
		[32]byte(testutil.FillBytes("l2keystoneabrevhash", 32)),
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	sortFn := func(a, b bfgd.PopBasis) int {
		if *a.BtcTxIndex < *b.BtcTxIndex {
			return -1
		}

		return 1
	}

	slices.SortFunc(popBases, sortFn)

	diff = deep.Equal(popBases, []bfgd.PopBasis{
		popBasis,
		popBasis2,
	})

	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestPopBasisUpdateOneExistsWithNullBTCFields(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	btcBlock := bfgd.BtcBlock{
		Hash:   testutil.FillBytes("myhash", 32),
		Header: testutil.FillBytes("myheader", 80),
		Height: 1,
	}

	err := db.BtcBlockInsert(ctx, &btcBlock)
	if err != nil {
		t.Fatalf("Failed to insert bitcoin block: %v", err)
	}

	popBasis := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid2", 32),
		BtcRawTx:            []byte("btcrawtx2"),
		L2KeystoneAbrevHash: testutil.FillBytes("l2keystoneabrevhash", 32),
		PopMinerPublicKey:   testutil.FillBytes("popminerpublickey", 32),
		PopTxId:             nil,
		BtcHeaderHash:       nil,
		BtcTxIndex:          nil,
		BtcMerklePath:       nil,
	}

	err = db.PopBasisInsertPopMFields(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	var txIndex uint64 = 3

	popBasis2 := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid2", 32),
		BtcRawTx:            []byte("btcrawtx2"),
		PopTxId:             testutil.FillBytes("poptxid2", 32),
		L2KeystoneAbrevHash: testutil.FillBytes("l2keystoneabrevhash", 32),
		PopMinerPublicKey:   testutil.FillBytes("popminerpublickey", 32),
		BtcHeaderHash:       btcBlock.Hash,
		BtcTxIndex:          &txIndex,
	}

	rowsAffected, err := db.PopBasisUpdateBTCFields(ctx, &popBasis2)
	if err != nil {
		t.Fatal(err)
	}

	if rowsAffected != 1 {
		t.Fatalf("unexpected number of rows affected %d", rowsAffected)
	}

	popBases, err := db.PopBasisByL2KeystoneAbrevHash(
		ctx,
		[32]byte(testutil.FillBytes("l2keystoneabrevhash", 32)),
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(popBases, []bfgd.PopBasis{
		popBasis2,
	})

	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestPublications(t *testing.T) {
	type testTableItem struct {
		name            string
		heightPattern   []int
		expectedHeights []int
	}

	testTable := []testTableItem{
		{
			name:            "height in order",
			heightPattern:   []int{1, 2, 3, 4},
			expectedHeights: []int{4, 3, 2, 1},
		},
		{
			name:            "height in order unconfirmed",
			heightPattern:   []int{1, 2, -1, 4}, // use -1 to indicate unconfirmed
			expectedHeights: []int{-1, 4, 2, 1},
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := defaultTestContext(t)
			defer cancel()

			db, sdb, cleanup := createTestDB(ctx, t)
			defer func() {
				db.Close()
				sdb.Close()
				cleanup()
			}()

			l2BlockNumber := uint32(1000)

			lastHash := []byte{}
			for _, height := range tti.heightPattern {
				// if the block is unconfirmed, ensure we use a high
				// l2 block number so it doesn't inherit the effective
				// height of a confirmed one
				l2BlockNumberTmp := l2BlockNumber
				if height == -1 {
					l2BlockNumberTmp += 100000
				}

				onChainBlocksTmp := createBtcBlocksAtStaticHeight(ctx, t, db, 1, true, height, lastHash, l2BlockNumberTmp)
				lastHash = onChainBlocksTmp[0].Hash
				l2BlockNumber++
			}

			bfs, err := db.L2BTCFinalityMostRecent(ctx, 100, 999999999)
			if err != nil {
				t.Fatal(err)
			}

			for _, v := range bfs {
				t.Logf("height is %d", v.BTCPubHeight)
			}

			for i := range tti.expectedHeights {
				if int64(tti.expectedHeights[i]) != bfs[i].BTCPubHeight {
					t.Fatalf("height mismatch at index %d (block %d): %d != %d", i, bfs[i].L2Keystone.L2BlockNumber, tti.expectedHeights[i], bfs[i].BTCPubHeight)
				}
			}
		})
	}
}

func TestL2BtcFinalitiesByL2Keystone(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	createBtcBlocksAtStartingHeight(ctx, t, db, 2, true, 8987, []byte{}, 646464)

	l2Keystones, err := db.L2KeystonesMostRecentN(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	firstKeystone := l2Keystones[0]

	finalities, err := db.L2BTCFinalityByL2KeystoneAbrevHash(
		ctx,
		[]database.ByteArray{firstKeystone.Hash},
		999999999999,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(finalities) != 1 {
		t.Fatalf("received unexpected number of finalities: %d", len(finalities))
	}

	diff := deep.Equal(firstKeystone, finalities[0].L2Keystone)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	if finalities[0].BTCPubHeight != 8988 {
		t.Fatalf("incorrect height %d", finalities[0].BTCPubHeight)
	}
}

func TestL2BtcFinalitiesByL2KeystoneWithCutoff(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	createBtcBlocksAtStartingHeight(ctx, t, db, 2, true, 8987, []byte{}, 646464)

	l2Keystones, err := db.L2KeystonesMostRecentN(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	finalities, err := db.L2BTCFinalityByL2KeystoneAbrevHash(
		ctx,
		[]database.ByteArray{l2Keystones[0].Hash, l2Keystones[1].Hash},
		int64(l2Keystones[1].L2BlockNumber),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(finalities) != 1 {
		t.Fatalf("received unexpected number of finalities: %d", len(finalities))
	}

	diff := deep.Equal(l2Keystones[1], finalities[0].L2Keystone)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	if finalities[0].EffectiveHeight != 8987 {
		t.Fatalf("incorrect effective height %d", finalities[0].EffectiveHeight)
	}
}

func TestL2BtcFinalitiesByL2KeystoneWithCutoffReverseMining(t *testing.T) {
	// if a newer keystone gets mined before an older
	// one, take that into account with effective height

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	createBtcBlocksAtStartingHeightReverseMining(ctx, t, db, 2, true, 8987, []byte{}, 646464)

	l2Keystones, err := db.L2KeystonesMostRecentN(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	finalities, err := db.L2BTCFinalityByL2KeystoneAbrevHash(
		ctx,
		[]database.ByteArray{l2Keystones[0].Hash, l2Keystones[1].Hash},
		int64(l2Keystones[1].L2BlockNumber),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(finalities) != 1 {
		t.Fatalf("received unexpected number of finalities: %d", len(finalities))
	}

	diff := deep.Equal(l2Keystones[1], finalities[0].L2Keystone)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	if finalities[0].EffectiveHeight != 8988 {
		t.Fatalf("incorrect effective height %d", finalities[0].EffectiveHeight)
	}
}

func TestL2BtcFinalitiesByL2KeystoneNotPublishedHeight(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	createBtcBlocksAtStaticHeight(ctx, t, db, 1, true, -1, []byte{}, 646464)

	l2Keystones, err := db.L2KeystonesMostRecentN(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	firstKeystone := l2Keystones[0]

	finalities, err := db.L2BTCFinalityByL2KeystoneAbrevHash(
		ctx,
		[]database.ByteArray{firstKeystone.Hash},
		99999999999,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(finalities) != 1 {
		t.Fatalf("received unexpected number of finalities: %d", len(finalities))
	}

	diff := deep.Equal(firstKeystone, finalities[0].L2Keystone)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	if finalities[0].BTCPubHeight != -1 {
		t.Fatalf("incorrect height %d", finalities[0].BTCPubHeight)
	}
}

type BtcTransactionBroadcastRequest struct {
	TxId         string
	SerializedTx []byte
}

func TestBtcTransactionBroadcastRequestInsert(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := sdb.QueryContext(ctx, "SELECT tx_id, serialized_tx FROM btc_transaction_broadcast_request")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	result := BtcTransactionBroadcastRequest{}
	count := 0

	for rows.Next() {
		err = rows.Scan(&result.TxId, &result.SerializedTx)
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if rows.Err() != nil {
		t.Fatalf("rows: %v", err)
	}

	if count != 1 {
		t.Fatalf("unexpected number of rows %d", count)
	}

	diff := deep.Equal(result, BtcTransactionBroadcastRequest{
		TxId:         txId,
		SerializedTx: serializedTx,
	})

	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestBtcTransactionBroadcastRequestGetNext(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(serializedTx, savedSerializedTx) {
		t.Fatalf("slices to do match: %v != %v", serializedTx, savedSerializedTx)
	}
}

func TestBtcTransactionBroadcastRequestGetNextMultiple(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	serializedTx2 := []byte("blahblahblah2")
	txId2 := "myid2"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	err = db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx2, txId2)
	if err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(serializedTx, savedSerializedTx) {
		t.Fatalf("slices to do match: %v != %v", serializedTx, savedSerializedTx)
	}

	savedSerializedTx2, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(serializedTx2, savedSerializedTx2) {
		t.Fatalf("slices to do match: %v != %v", serializedTx2, savedSerializedTx2)
	}

	savedSerializedTx3, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if savedSerializedTx3 != nil {
		t.Fatal("expected nil value")
	}
}

func TestBtcTransactionBroadcastRequestGetNextBefore10Minutes(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(serializedTx, savedSerializedTx) {
		t.Fatalf("slices to do match: %v != %v", serializedTx, savedSerializedTx)
	}

	// we should have set the fields on the last get, should not be able to
	// get and process twice
	savedSerializedTx, err = db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if savedSerializedTx != nil {
		t.Fatal("expected a nil response")
	}
}

func TestBtcTransactionBroadcastRequestGetNextRetry(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(serializedTx, savedSerializedTx) {
		t.Fatalf("slices to do match: %v != %v", serializedTx, savedSerializedTx)
	}

	_, err = sdb.ExecContext(ctx, "UPDATE btc_transaction_broadcast_request SET next_broadcast_attempt_at = NOW()")
	if err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err = db.BtcTransactionBroadcastRequestGetNext(ctx, false)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(serializedTx, savedSerializedTx) {
		t.Fatalf("slices to do match: %v != %v", serializedTx, savedSerializedTx)
	}
}

func TestBtcTransactionBroadcastRequestGetNextAfter2Hours(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sdb.ExecContext(ctx, "UPDATE btc_transaction_broadcast_request SET created_at = NOW() - INTERVAL '31 minutes'")
	if err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if savedSerializedTx != nil {
		t.Fatal("expected nil value")
	}
}

func TestBtcTransactionBroadcastRequestGetNextAlreadyBroadcast(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sdb.ExecContext(ctx, "UPDATE btc_transaction_broadcast_request SET broadcast_at = NOW()")
	if err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if savedSerializedTx != nil {
		t.Fatal("expected nil response")
	}
}

func TestBtcTransactionBroadcastRequestConfirmBroadcast(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	err = db.BtcTransactionBroadcastRequestConfirmBroadcast(ctx, txId)
	if err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if savedSerializedTx != nil {
		t.Fatal("expected nil response")
	}
}

func TestBtcTransactionBroadcastRequestTrimTooNew(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sdb.ExecContext(ctx, "UPDATE btc_transaction_broadcast_request SET created_at = NOW() - INTERVAL '29 minutes'")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.BtcTransactionBroadcastRequestTrim(ctx); err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if savedSerializedTx == nil {
		t.Fatal("expected a saved tx")
	}
}

func TestBtcTransactionBroadcastRequestTrim(t *testing.T) {
	ctx, cancel := defaultTestContext(t)
	defer cancel()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	serializedTx := []byte("blahblahblah")
	txId := "myid"

	err := db.BtcTransactionBroadcastRequestInsert(ctx, serializedTx, txId)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sdb.ExecContext(ctx, "UPDATE btc_transaction_broadcast_request SET created_at = NOW() - INTERVAL '61 minutes'")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.BtcTransactionBroadcastRequestTrim(ctx); err != nil {
		t.Fatal(err)
	}

	savedSerializedTx, err := db.BtcTransactionBroadcastRequestGetNext(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	if savedSerializedTx != nil {
		t.Fatal("tx should have been trimmed")
	}
}

func createBtcBlock(ctx context.Context, t *testing.T, db bfgd.Database, count int, chain bool, height int, lastHash []byte, l2BlockNumber uint32) bfgd.BtcBlock {
	header := make([]byte, 80)
	hash := make([]byte, 32)
	l2KeystoneAbrevHash := make([]byte, 32)
	parentEpHash := make([]byte, 32)
	prevKeystoneEpHash := make([]byte, 32)
	stateRoot := make([]byte, 32)
	epHash := make([]byte, 32)
	btcTxId := make([]byte, 32)
	btcRawTx := make([]byte, 32)
	popMinerPublicKey := make([]byte, 32)

	_, err := rand.Read(header)
	if err != nil {
		t.Fatal(err)
	}

	_, err = rand.Read(hash)
	if err != nil {
		t.Fatal(err)
	}

	_, err = rand.Read(l2KeystoneAbrevHash)
	if err != nil {
		t.Fatal(err)
	}

	_, err = rand.Read(btcTxId)
	if err != nil {
		t.Fatal(err)
	}

	if chain {
		// create the chain using lastHash if it is set (len > 0),
		// if it is not set, we are on the tip
		if len(lastHash) != 0 {
			for k := 4; (k - 4) < 32; k++ {
				header[k] = lastHash[k-4]
			}
		}
	}

	t.Logf(
		"inserting with height %d and L2BlockNumber %d hash %s",
		height, l2BlockNumber, hex.EncodeToString(hash))

	btcBlock := bfgd.BtcBlock{
		Header: header,
		Hash:   hash,
		Height: uint64(height),
	}

	l2Keystone := bfgd.L2Keystone{
		Hash:               l2KeystoneAbrevHash,
		ParentEPHash:       parentEpHash,
		PrevKeystoneEPHash: prevKeystoneEpHash,
		StateRoot:          stateRoot,
		EPHash:             epHash,
		L2BlockNumber:      l2BlockNumber,
	}

	popBasis := bfgd.PopBasis{
		BtcTxId:             btcTxId,
		BtcRawTx:            btcRawTx,
		BtcHeaderHash:       hash,
		L2KeystoneAbrevHash: l2KeystoneAbrevHash,
		PopMinerPublicKey:   popMinerPublicKey,
	}

	if height == -1 {
		err = db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
		if err != nil {
			t.Fatal(err)
		}

		err = db.PopBasisInsertPopMFields(ctx, &popBasis)
		if err != nil {
			t.Fatal(err)
		}

		return bfgd.BtcBlock{}
	}

	err = db.BtcBlockInsert(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	err = db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err != nil {
		t.Fatal(err)
	}

	err = db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	return btcBlock
}

func createBtcBlocksAtStaticHeight(ctx context.Context, t *testing.T, db bfgd.Database, count int, chain bool, height int, lastHash []byte, l2BlockNumber uint32) []bfgd.BtcBlock {
	blocks := []bfgd.BtcBlock{}

	for range count {
		btcBlock := createBtcBlock(
			ctx,
			t,
			db,
			count,
			chain,
			height,
			lastHash,
			l2BlockNumber,
		)
		blocks = append(blocks, btcBlock)
		updateFinalityForBtcBlock(t, ctx, db, &btcBlock, uint32(btcBlock.Height))
		lastHash = btcBlock.Hash
	}

	return blocks
}

func createBtcBlocksAtStartingHeightReverseMining(ctx context.Context, t *testing.T, db bfgd.Database, count int, chain bool, height int, lastHash []byte, l2BlockNumber uint32) []bfgd.BtcBlock {
	blocks := []bfgd.BtcBlock{}

	for range count {
		btcBlock := createBtcBlock(
			ctx,
			t,
			db,
			count,
			chain,
			height,
			lastHash,
			l2BlockNumber,
		)
		updateFinalityForBtcBlock(t, ctx, db, &btcBlock, uint32(btcBlock.Height))
		blocks = append(blocks, btcBlock)
		height++
		l2BlockNumber--
		lastHash = btcBlock.Hash
	}

	return blocks
}

func updateFinalityForBtcBlock(t *testing.T, ctx context.Context, db bfgd.Database, block *bfgd.BtcBlock, height uint32) {
	// some tests don't care about a btc block hash, fill it out here so it doesn't error
	if len(block.Hash) == 0 {
		block.Hash = testutil.FillBytes(fmt.Sprintf("%d", height), 32)
	}

	if err := db.BtcBlockUpdateKeystones(ctx, [32]byte(block.Hash), uint64(height), math.MaxInt64); err != nil {
		t.Fatal(err)
	}
}

func createBtcBlocksAtStartingHeight(ctx context.Context, t *testing.T, db bfgd.Database, count int, chain bool, height int, lastHash []byte, l2BlockNumber uint32) []bfgd.BtcBlock {
	blocks := []bfgd.BtcBlock{}

	for range count {
		btcBlock := createBtcBlock(
			ctx,
			t,
			db,
			count,
			chain,
			height,
			lastHash,
			l2BlockNumber,
		)
		blocks = append(blocks, btcBlock)
		updateFinalityForBtcBlock(t, ctx, db, &btcBlock, uint32(btcBlock.Height))
		height++
		l2BlockNumber++
		lastHash = btcBlock.Hash
	}

	return blocks
}

func l2KeystonesCount(ctx context.Context, db *sql.DB) (int, error) {
	const selectCount = `SELECT COUNT(*) FROM l2_keystones;`

	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, err
	}

	defer conn.Close()

	var count int
	if err := conn.QueryRowContext(ctx, selectCount).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}
