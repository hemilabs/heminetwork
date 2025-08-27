package gkvdb

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/kelindar/binary"
)

// XXX antonio, add gob test and run benchmarks so that we can decide between
// gob and kelindar.

func TestJournalEncoding(t *testing.T) {
	jop := &journalOp{
		Op:    opDel,
		Table: "table",
		Key:   []byte("key"),
		Value: []byte("value"),
	}
	e, err := binary.Marshal(jop)
	if err != nil {
		t.Fatal(err)
	}
	var d journalOp
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
		err := encoder.Encode(&journalOp{
			Op:    opDel,
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
		jop := journalOp{} // Yes, always allocate
		err := d.Decode(&jop)
		if err != nil {
			if err == io.EOF {
				if i != maxItems {
					t.Fatalf("i != maxItems, %v != %v", i, maxItems)
				}
				break
			}
			t.Fatal(err)
		}
		jopExected := journalOp{
			Op:    opDel,
			Table: "table",
			Key:   []byte("key" + strconv.Itoa(i)),
			Value: []byte("value" + strconv.Itoa(i)),
		}
		if !reflect.DeepEqual(jopExected, jop) {
			t.Fatal("not equal")
		}
	}
}

func TestReplicateDirect(t *testing.T) {
	// First create source and destination
	home := t.TempDir()
	tables := []string{"table1", "table2"}
	homeSource := filepath.Join(home, "source")
	dbSource, err := NewLevelDB(DefaultLevelConfig(homeSource, tables))
	if err != nil {
		t.Fatal(err)
	}
	homeDestination := filepath.Join(home, "destination")
	dbDestination, err := NewLevelDB(DefaultLevelConfig(homeDestination, tables))
	if err != nil {
		t.Fatal(err)
	}

	// Create replicator database
	homeJournal := filepath.Join(home, "journal")
	rcfg := DefaultReplicatorConfig(homeJournal, Direct)
	db, err := NewReplicatorDB(rcfg, dbSource, dbDestination)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	err = db.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Individual Puts
	maxPuts := 1337
	valueOffset := 10000
	recordsPerTable := make([]int, len(tables))
	for i := 0; i < maxPuts; i++ {
		tx := i % len(tables)
		table := tables[tx]
		// t.Logf("%v %v", table, i)
		err := db.Put(ctx, table, []byte(strconv.Itoa(i)),
			[]byte(strconv.Itoa(i+valueOffset)))
		if err != nil {
			t.Fatal(err)
		}
		recordsPerTable[tx]++
	}

	// Verify that we have them in the replicator db (really the source)
	// and in the destination db.
	for i := 0; i < maxPuts; i++ {
		tx := i % len(tables)
		table := tables[tx]
		// t.Logf("%v %v", table, i)
		value, err := db.Get(ctx, table, []byte(strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		expectedValue := []byte(strconv.Itoa(i + valueOffset))
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

	// Iterate over all tables and count records to compare to source
	for k := range tables {
		it, err := dbDestination.NewIterator(ctx, tables[k])
		if err != nil {
			t.Fatal(err)
		}
		x := 0
		for it.Next(ctx) {
			x++
		}
		it.Close(ctx)
		if x != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v",
				tables[k], x, recordsPerTable[k])
		}
	}

	// Empty table1
	it, err := db.NewIterator(ctx, tables[0])
	if err != nil {
		t.Fatal(err)
	}
	x := 0
	for it.Next(ctx) {
		err := db.Del(ctx, tables[0], it.Key(ctx))
		if err != nil {
			t.Fatal(err)
		}
		x++
	}
	it.Close(ctx)
	if x != recordsPerTable[0] {
		t.Fatalf("%v: got %v wanted %v", tables[0], x, recordsPerTable[0])
	}

	// Iterate over destination in destination and make sure we have 0 and N records.
	recordsPerTable[0] = 0
	for k := range tables {
		it, err := dbDestination.NewIterator(ctx, tables[k])
		if err != nil {
			t.Fatal(err)
		}
		x := 0
		for it.Next(ctx) {
			x++
		}
		it.Close(ctx)
		if x != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v",
				tables[k], x, recordsPerTable[k])
		}
	}

	// Empty table2
	it, err = db.NewIterator(ctx, tables[1])
	if err != nil {
		t.Fatal(err)
	}
	x = 0
	for it.Next(ctx) {
		err := db.Del(ctx, tables[1], it.Key(ctx))
		if err != nil {
			t.Fatal(err)
		}
		x++
	}
	it.Close(ctx)
	if x != recordsPerTable[1] {
		t.Fatalf("%v: got %v wanted %v", tables[1], x, recordsPerTable[1])
	}

	// Iterate over destination in destination and make sure we have 0 and 0 records.
	recordsPerTable[1] = 0
	for k := range tables {
		it, err := dbDestination.NewIterator(ctx, tables[k])
		if err != nil {
			t.Fatal(err)
		}
		x := 0
		for it.Next(ctx) {
			x++
		}
		it.Close(ctx)
		if x != recordsPerTable[k] {
			t.Fatalf("%v: got %v wanted %v",
				tables[k], x, recordsPerTable[k])
		}
	}
}
