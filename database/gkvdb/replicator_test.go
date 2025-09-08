// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/kelindar/binary"
)

// XXX antonio, add gob test and run benchmarks so that we can decide between
// gob and kelindar.

func TestJournalEncoding(t *testing.T) {
	jop := &Operation{
		Op:    OpDel,
		Table: "table",
		Key:   []byte("key"),
		Value: []byte("value"),
	}
	e, err := binary.Marshal(jop)
	if err != nil {
		t.Fatal(err)
	}
	var d Operation
	err = binary.Unmarshal(e, &d)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*jop, d) {
		t.Fatal("not equal")
	}
}

func TestJournalStream(t *testing.T) {
	maxItems := 199

	var b bytes.Buffer
	encoder := binary.NewEncoder(&b)
	for i := 0; i < maxItems; i++ {
		err := encoder.Encode(&Operation{
			Op:    OpDel,
			Table: "table",
			Key:   []byte("key" + strconv.Itoa(i)),
			Value: []byte("value" + strconv.Itoa(i)),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	d := binary.NewDecoder(&b)
	for i := 0; ; i++ {
		jop := Operation{} // Yes, always allocate
		err := d.Decode(&jop)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if i != maxItems {
					t.Fatalf("i != maxItems, %v != %v", i, maxItems)
				}
				break
			}
			t.Fatal(err)
		}
		jopExected := Operation{
			Op:    OpDel,
			Table: "table",
			Key:   []byte("key" + strconv.Itoa(i)),
			Value: []byte("value" + strconv.Itoa(i)),
		}
		if !reflect.DeepEqual(jopExected, jop) {
			t.Fatal("not equal")
		}
	}
}

func tableCount(ctx context.Context, db Database, table string) (int, error) {
	it, err := db.NewIterator(ctx, table)
	if err != nil {
		return 0, err
	}
	i := 0
	for it.Next(ctx) {
		i++
	}
	it.Close(ctx)
	return i, nil
}

func tableDel(ctx context.Context, db Database, table string, batchCount int) (int, error) {
	it, err := db.NewIterator(ctx, table)
	if err != nil {
		return 0, err
	}
	bat, err := db.NewBatch(ctx)
	if err != nil {
		return 0, fmt.Errorf("new batch: err")
	}
	i := 0
	for it.Next(ctx) {
		if i < batchCount {
			bat.Del(ctx, table, it.Key(ctx))
		} else {
			err := db.Del(ctx, table, it.Key(ctx))
			if err != nil {
				return 0, fmt.Errorf("del %v: %w", i, err)
			}
		}
		i++
	}
	it.Close(ctx)
	err = db.Update(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Write(ctx, bat)
	})
	if err != nil {
		return 0, fmt.Errorf("commit batch: %w", err)
	}
	return i, nil
}

func tablePut(ctx context.Context, db Database, table string, offset, batchCount, putCount int) error {
	bat, err := db.NewBatch(ctx)
	if err != nil {
		return fmt.Errorf("new batch: err")
	}
	for i := range batchCount {
		key, value := generateKV(i + offset)
		bat.Put(ctx, table, key, value)
	}
	for i := range putCount {
		key, value := generateKV(i + batchCount + offset)
		err := db.Put(ctx, table, key, value)
		if err != nil {
			return fmt.Errorf("put %v: %w", i, err)
		}
	}
	err = db.Update(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Write(ctx, bat)
	})
	if err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

func createReplicator(t *testing.T, policy Policy, home, srcType, dstType string, tables []string) (Database, Database) {
	// Create destination database
	var dbDestination Database
	switch dstType {
	case "mongo":
		homeDestination := os.Getenv("MONGO_TEST_URI")
		if homeDestination == "" {
			t.Skip("mongo URI not set")
		}
		cfg := DefaultMongoConfig(homeDestination, tables)
		cfg.DropTables = true
		dbs, err := NewMongoDB(cfg)
		if err != nil {
			t.Fatal(err)
		}
		dbDestination = dbs
	default:
		homeDestination := filepath.Join(home, "destination")
		dbs, err := NewLevelDB(DefaultLevelConfig(homeDestination, tables))
		if err != nil {
			t.Fatal(err)
		}
		dbDestination = dbs
	}

	// Create source database
	var dbSource Database
	switch srcType {
	case "mongo":
		panic("not yet source mongo")
	default:
		homeSource := filepath.Join(home, "source")
		dbs, err := NewLevelDB(DefaultLevelConfig(homeSource, tables))
		if err != nil {
			panic(err)
		}
		dbSource = dbs
	}

	// Create replicator database
	homeJournal := filepath.Join(home, "journal")
	rcfg := DefaultReplicatorConfig(homeJournal, policy)
	db, err := NewReplicatorDB(rcfg, dbSource, dbDestination)
	if err != nil {
		t.Fatal(err)
	}

	return db, dbDestination
}

func generateKV(n int) ([]byte, []byte) {
	offset := 10000
	k := fmt.Append([]byte{}, strconv.Itoa(n))
	v := fmt.Append([]byte{}, strconv.Itoa(n+offset))
	return k, v
}

const (
	// n of records per table
	maxPuts = 50

	// n of batched (put / del) operations
	batchCount = maxPuts - manualCount

	// n of unbatched (put / del) operations
	manualCount = maxPuts / 10
)

func TestReplicateDirect(t *testing.T) {
	home := t.TempDir()
	tables := []string{"table1", "table2"}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// First create source and destination
	db, dbDestination := createReplicator(t, Direct, home, "level", "level", tables)

	if err := db.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	// Individual Puts
	recordsPerTable := make([]int, len(tables))
	for k, table := range tables {
		err := tablePut(ctx, db, table, 0, batchCount, manualCount)
		if err != nil {
			t.Fatal(err)
		}
		recordsPerTable[k] = maxPuts
		t.Logf("%v: %v records inserted", table, maxPuts)
	}

	// Verify that we have them in the replicator db (really the source)
	// and in the destination db.
	for _, table := range tables {
		for i := range maxPuts {
			key, expectedValue := generateKV(i)

			// Get out of source
			value, err := db.Get(ctx, table, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, value) {
				t.Fatal("not equal")
			}

			// Now fish it out of destination.
			dValue, err := dbDestination.Get(ctx, table, []byte(strconv.Itoa(i)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, dValue) {
				t.Fatal("not equal")
			}
		}
		t.Logf("%v: %v records verified", table, maxPuts)
	}

	// Empty tables and verify deletes
	for k, table := range tables {
		// Iterate over table and assert it matches source
		c, err := tableCount(ctx, dbDestination, table)
		if err != nil {
			t.Fatal(err)
		}
		if c != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v",
				tables[k], c, recordsPerTable[k])
		}
		t.Logf("%v: pre-delete count of %d in src == dst", table, c)

		// Empty table
		x, err := tableDel(ctx, db, table, batchCount)
		if err != nil {
			t.Fatal(err)
		}
		if x != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v", table, x, recordsPerTable[k])
		}
		recordsPerTable[k] = 0
		t.Logf("%v: %v record deleted", table, x)

		// Iterate over table and assert it matches source
		for tb := range tables {
			j, err := tableCount(ctx, dbDestination, tables[tb])
			if err != nil {
				t.Fatal(err)
			}
			if j != recordsPerTable[tb] {
				t.Fatalf("%v: got %v wanted %v",
					tables[tb], x, recordsPerTable[tb])
			}
			t.Logf("post-delete count of %d for %v in src == dst", recordsPerTable[tb], tables[tb])
		}
	}
}

func TestReplicateLazy(t *testing.T) {
	home := t.TempDir()
	tables := []string{"table1", "table2"}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// First create source and destination
	db, dbDestination := createReplicator(t, Lazy, home, "level", "level", tables)

	if err := db.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	// Individual Puts
	recordsPerTable := make([]int, len(tables))
	for k, table := range tables {
		err := tablePut(ctx, db, table, 0, batchCount, manualCount)
		if err != nil {
			t.Fatal(err)
		}
		recordsPerTable[k] = maxPuts
		t.Logf("%v: %v records inserted", table, maxPuts)
	}
	for !db.(*replicatorDB).flushed(ctx) {
		time.Sleep(time.Millisecond)
	}

	// Verify that we have them in the replicator db (really the source)
	// and in the destination db.
	for _, table := range tables {
		for i := range maxPuts {
			key, expectedValue := generateKV(i)

			// Get out of source
			value, err := db.Get(ctx, table, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, value) {
				t.Fatal("not equal")
			}

			// Now fish it out of destination.
			dValue, err := dbDestination.Get(ctx, table, []byte(strconv.Itoa(i)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, dValue) {
				t.Fatal("not equal")
			}
		}
		t.Logf("%v: %v records verified", table, maxPuts)
	}

	// Empty tables and verify deletes
	for k, table := range tables {
		// Iterate over table and assert it matches source
		c, err := tableCount(ctx, dbDestination, table)
		if err != nil {
			t.Fatal(err)
		}
		if c != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v",
				tables[k], c, recordsPerTable[k])
		}
		t.Logf("%v: pre-delete count of %d in src == dst", table, c)

		// Empty table
		x, err := tableDel(ctx, db, table, batchCount)
		if err != nil {
			t.Fatal(err)
		}
		if x != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v", table, x, recordsPerTable[k])
		}
		recordsPerTable[k] = 0
		t.Logf("%v: %v record deleted", table, x)

		for !db.(*replicatorDB).flushed(ctx) {
			time.Sleep(time.Millisecond)
		}

		// Iterate over table and assert it matches source
		for tb := range tables {
			j, err := tableCount(ctx, dbDestination, tables[tb])
			if err != nil {
				t.Fatal(err)
			}
			if j != recordsPerTable[tb] {
				t.Fatalf("%v: got %v wanted %v",
					tables[tb], x, recordsPerTable[tb])
			}
			t.Logf("post-delete count of %d for %v in src == dst", recordsPerTable[tb], tables[tb])
		}
	}
}

func TestReplicateDirectBadTarget(t *testing.T) {
	home := t.TempDir()
	tables := []string{"table1", "table2"}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// First create source and destination
	db, dbDestination := createReplicator(t, Direct, home, "level", "level", tables)

	if err := db.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	// Force close target so that replication fails.
	err := dbDestination.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Put a value and expect failure
	i := 1337
	valueOffset := 10000
	err = db.Put(ctx, tables[0], []byte(strconv.Itoa(i)),
		[]byte(strconv.Itoa(i+valueOffset)))
	if !errors.Is(err, ErrSinkUnavailable) {
		t.Fatal(err)
	}

	// Now close everything and reopen replicator and the missed put must
	// be replayed.
	err = db.Close(ctx)
	if !errors.Is(err, ErrDBClosed) {
		t.Fatal(err)
	}

	err = db.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// See if we replicated the missing key/val
	value, err := dbDestination.Get(ctx, tables[0], []byte(strconv.Itoa(i)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, []byte(strconv.Itoa(i+valueOffset))) {
		t.Fatal("not equal")
	}

	// Make sure journal is empty.
	it, err := db.(*replicatorDB).jdb.NewRange(ctx, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for it.Next(ctx) {
		if bytes.Equal(lastSequenceID, it.Key(ctx)) {
			continue
		}
		t.Fatalf("found unflushed journal: %v", spew.Sdump(it.Key(ctx)))
	}
}

func TestReplicateRetry(t *testing.T) {
	home := t.TempDir()
	tables := []string{"table1", "table2"}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// First create source and destination
	db, dbDestination := createReplicator(t, Lazy, home, "level", "level", tables)

	if err := db.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			if !errors.Is(err, ErrDBClosed) {
				t.Fatal(err)
			}
		}
	}()

	// Individual Puts
	maxPuts := 50
	maxTxs := 100

	stopDB := false
	for tx := range maxTxs {
		for _, table := range tables {
			err := tablePut(ctx, db, table, maxPuts*tx, maxPuts, 0)
			if err != nil && !stopDB {
				t.Fatal("expected error")
			}
		}
		// Stop destination db half way through
		if tx >= maxTxs/3 && !stopDB {
			stopDB = true
			if err := dbDestination.Close(ctx); err != nil {
				t.Fatal(err)
			}
			t.Log("destination db stopped")
		}
	}

	// Restart db
	time.Sleep(time.Second)
	if err := dbDestination.Open(ctx); err != nil {
		t.Fatal(err)
	}
	// poke sink since this test uses external stimuli
	db.(*replicatorDB).sinkC <- struct{}{}
	t.Log("destination db restarted")

	for !db.(*replicatorDB).flushed(ctx) {
		time.Sleep(time.Millisecond)
	}

	// Verify that we have them in the replicator db (really the source)
	// and in the destination db.
	for _, table := range tables {
		for i := range maxPuts * maxTxs {
			key, expectedValue := generateKV(i)

			// Get out of source
			value, err := db.Get(ctx, table, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, value) {
				t.Fatal("not equal")
			}

			// Now fish it out of destination.
			dValue, err := dbDestination.Get(ctx, table, []byte(strconv.Itoa(i)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, dValue) {
				t.Fatal("not equal")
			}
		}
	}
}

func TestReplicateOnStartup(t *testing.T) {
	home := t.TempDir()
	tables := []string{"table1", "table2"}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// First create source and destination
	db, dbDestination := createReplicator(t, Lazy, home, "level", "level", tables)

	if err := db.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	// Close destination early to prevent replay
	if err := dbDestination.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// Individual Puts
	maxPuts := 50
	maxTxs := 100

	// These all fail, but since no one listens for
	// the error when using Lazy policy, it will
	// keep adding new Txs and creating Journals.
	for tx := range maxTxs {
		for _, table := range tables {
			err := tablePut(ctx, db, table, maxPuts*tx, maxPuts, 0)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	// Restart Replicator
	if err := db.Close(ctx); err == nil {
		t.Fatal("expected err")
	}
	if err := db.Open(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("db restarted")

	for !db.(*replicatorDB).flushed(ctx) {
		time.Sleep(time.Millisecond)
	}

	// Verify that we have them in the replicator db (really the source)
	// and in the destination db.
	for _, table := range tables {
		for i := range maxPuts * maxTxs {
			key, expectedValue := generateKV(i)

			// Get out of source
			value, err := db.Get(ctx, table, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, value) {
				t.Fatal("not equal")
			}

			// Now fish it out of destination.
			dValue, err := dbDestination.Get(ctx, table, []byte(strconv.Itoa(i)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, dValue) {
				t.Fatal("not equal")
			}
		}
	}
}

func TestReplicateLevelMongo(t *testing.T) {
	home := t.TempDir()
	tables := []string{"table1", "table2"}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// First create source and destination
	db, dbDestination := createReplicator(t, Lazy, home, "level", "mongo", tables)

	if err := db.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	// Individual Puts
	recordsPerTable := make([]int, len(tables))
	for k, table := range tables {
		err := tablePut(ctx, db, table, 0, batchCount, manualCount)
		if err != nil {
			t.Fatal(err)
		}
		recordsPerTable[k] = maxPuts
		t.Logf("%v: %v records inserted", table, maxPuts)
	}
	for !db.(*replicatorDB).flushed(ctx) {
		time.Sleep(time.Millisecond)
	}

	// Verify that we have them in the replicator db (really the source)
	// and in the destination db.
	for _, table := range tables {
		for i := range maxPuts {
			key, expectedValue := generateKV(i)

			// Get out of source
			value, err := db.Get(ctx, table, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, value) {
				t.Fatal("not equal")
			}

			// Now fish it out of destination.
			dValue, err := dbDestination.Get(ctx, table, []byte(strconv.Itoa(i)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedValue, dValue) {
				t.Fatal("not equal")
			}
		}
		t.Logf("%v: %v records verified", table, maxPuts)
	}

	// Empty tables and verify deletes
	for k, table := range tables {
		// Iterate over table and assert it matches source
		c, err := tableCount(ctx, dbDestination, table)
		if err != nil {
			t.Fatal(err)
		}
		if c != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v",
				tables[k], c, recordsPerTable[k])
		}
		t.Logf("%v: pre-delete count of %d in src == dst", table, c)

		// Empty table
		x, err := tableDel(ctx, db, table, batchCount)
		if err != nil {
			t.Fatal(err)
		}
		if x != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v", table, x, recordsPerTable[k])
		}
		recordsPerTable[k] = 0
		t.Logf("%v: %v record deleted", table, x)

		for !db.(*replicatorDB).flushed(ctx) {
			time.Sleep(time.Millisecond)
		}

		// Iterate over table and assert it matches source
		for tb := range tables {
			j, err := tableCount(ctx, dbDestination, tables[tb])
			if err != nil {
				t.Fatal(err)
			}
			if j != recordsPerTable[tb] {
				t.Fatalf("%v: got %v wanted %v",
					tables[tb], x, recordsPerTable[tb])
			}
			t.Logf("post-delete count of %d for %v in src == dst", recordsPerTable[tb], tables[tb])
		}
	}
}
