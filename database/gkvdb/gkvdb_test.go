package gkvdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

func dbputs(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		value := sha256.Sum256(key[:])
		table := tables[i%len(tables)]
		err := db.Put(ctx, table, key[:], value[:])
		if err != nil {
			return fmt.Errorf("put %v: %v", table, i)
		}
	}
	return nil
}

func dbgets(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		table := tables[i%len(tables)]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		valueExpected := sha256.Sum256(key[:])
		value, err := db.Get(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("get %v: %v %v", table, i, err)
		}
		if !bytes.Equal(value, valueExpected[:]) {
			return fmt.Errorf("get unequal %v: %v", table, i)
		}
	}
	return nil
}

func dbhas(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		table := tables[i%len(tables)]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		has, err := db.Has(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("has %v: %v %v", table, i, err)
		}
		if !has {
			return fmt.Errorf("has %v: %v", table, i)
		}
	}
	return nil
}

func dbdels(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		table := tables[i%len(tables)]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		err := db.Del(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("del %v: %v %v", table, i, err)
		}
	}
	return nil
}

func dbhasNegative(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		table := tables[i%len(tables)]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		has, err := db.Has(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("has %v: %v %v", table, i, err)
		}
		if has {
			return fmt.Errorf("has %v: %v", table, i)
		}
	}
	return nil
}

func dbgetsNegative(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		table := tables[i%len(tables)]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		_, err := db.Get(ctx, table, key[:])
		if !errors.Is(err, ErrKeyNotFound) {
			return fmt.Errorf("get expected not found error %v: %v %v", table, i, err)
		}
	}
	return nil
}

func dbhasOdds(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		table := tables[i%len(tables)]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		has, err := db.Has(ctx, table, key[:])
		if i%2 == 0 {
			// Assert we don't have evens
			if err != nil {
				return fmt.Errorf("odds has %v: %v %v", table, i, err)
			}
			if has {
				return fmt.Errorf("odds has %v: %v", table, i)
			}
		} else {
			if err != nil {
				return fmt.Errorf("odds has %v: %v %v", table, i, err)
			}
			if !has {
				return fmt.Errorf("odds has %v: %v", table, i)
			}
		}
	}
	return nil
}

func txputs(ctx context.Context, tx Transaction, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		value := sha256.Sum256(key[:])
		table := tables[i%len(tables)]
		err := tx.Put(ctx, table, key[:], value[:])
		if err != nil {
			return fmt.Errorf("tx put %v: %v", table, i)
		}
	}
	return nil
}

func txdelsEven(ctx context.Context, tx Transaction, tables []string, insertCount int) error {
	for i := 0; i < insertCount; i++ {
		table := tables[i%len(tables)]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		if i%2 == 0 {
			err := tx.Del(ctx, table, key[:])
			if err != nil {
				return fmt.Errorf("del %v: %v %v", table, i, err)
			}
		} else {
			// Assert odd record exist
			valueExpected := sha256.Sum256(key[:])
			value, err := tx.Get(ctx, table, key[:])
			if err != nil {
				return fmt.Errorf("even get %v: %v %v", table, i, err)
			}
			if !bytes.Equal(value, valueExpected[:]) {
				return fmt.Errorf("even get unequal %v: %v", table, i)
			}
		}
	}
	return nil
}

func TestGKVDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 13*time.Second)
	defer cancel()
	home := t.TempDir()

	tableCount := 5
	tables := make([]string, 0, tableCount)
	for i := 0; i < tableCount; i++ {
		tables = append(tables, fmt.Sprintf("table%v", i))
	}

	cfg := DefaultNutsConfig(home, tables)
	db, err := NewNutsDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := db.Close(ctx)
		if err != nil {
			panic(err)
		}
	}()

	// Puts
	insertCount := 10000
	err = dbputs(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Get
	err = dbgets(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Has
	err = dbhas(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Del
	err = dbdels(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Has negative
	err = dbhasNegative(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Get negative
	err = dbgetsNegative(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Transaction Rollback
	tx, err := db.Begin(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	err = txputs(ctx, tx, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = dbhasNegative(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Transaction Commit
	tx, err = db.Begin(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	err = txputs(ctx, tx, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = dbgets(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Transaction delete even records
	tx, err = db.Begin(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	err = txdelsEven(ctx, tx, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = dbhasOdds(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Iterate over remaining records
	on := 1 // Table to test
	it, err := db.NewIterator(ctx, tables[on])
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = it.Close(ctx)
		if err != nil {
			panic(err)
		}
	}()
	i := 0
	for it.Next(ctx) {
		// t.Logf("table %s key %x value %x", tables[on], it.Key(ctx), it.Value(ctx))
		i++
	}
	if insertCount/len(tables)/2 != i {
		t.Fatalf("invalid number of records: got %v wanted %v",
			insertCount/len(tables)/2, i)
	}
}

func TestIterator(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 13*time.Second)
	defer cancel()
	home := t.TempDir()

	table := "mytable"
	tables := []string{table}
	cfg := DefaultNutsConfig(home, tables)
	db, err := NewNutsDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := db.Close(ctx)
		if err != nil {
			panic(err)
		}
	}()

	recordCount := 10 // We test a byte so do not overflow it
	for i := 0; i < recordCount; i++ {
		err := db.Put(ctx, table, []byte{uint8(i)}, []byte{uint8(i)})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify that Next returns the first record.
	it1, err := db.NewIterator(ctx, table)
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for it1.Next(ctx) {
		i++
	}
	defer func() {
		err = it1.Close(ctx)
		if err != nil {
			panic(err)
		}
	}()

	// Verify that Next returns the Next record after a seek.
	it2, err := db.NewIterator(ctx, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = it2.Close(ctx)
		if err != nil {
			panic(err)
		}
	}()
	if !it2.Seek(ctx, []byte{1}) {
		t.Fatal("seek 1")
	}
	if !it2.Next(ctx) {
		t.Fatal("next")
	}
	if !bytes.Equal(it2.Key(ctx), []byte{2}) {
		t.Fatalf("not equal seek, got %v wanted %v", it2.Key(ctx), []byte{2})
	}
	// Verify First while here
	if !it2.First(ctx) {
		t.Fatal("first")
	}
	if !bytes.Equal(it2.Key(ctx), []byte{uint8(0)}) {
		t.Fatalf("not equal first, got %v wanted %v", it2.Key(ctx), []byte{0})
	}
	// Verify Last while here
	if !it2.Last(ctx) {
		t.Fatal("last")
	}
	if !bytes.Equal(it2.Key(ctx), []byte{uint8(recordCount - 1)}) {
		t.Fatalf("not equal last, got %v wanted %v",
			it2.Key(ctx), []byte{uint8(recordCount - 1)})
	}
}
