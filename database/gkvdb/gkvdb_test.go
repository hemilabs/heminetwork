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

func TestGKVDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 13*time.Second)
	defer cancel()
	home := t.TempDir()

	tableCount := 5
	tables := make([]string, tableCount)
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
	for i := 0; i < insertCount; i++ {
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		value := sha256.Sum256(key[:])
		table := tables[i%tableCount]
		err := db.Put(ctx, table, key[:], value[:])
		if err != nil {
			t.Fatalf("put %v: %v", table, i)
		}
	}

	// Get
	for i := 0; i < insertCount; i++ {
		table := tables[i%tableCount]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		valueExpected := sha256.Sum256(key[:])
		value, err := db.Get(ctx, table, key[:])
		if err != nil {
			t.Fatalf("get %v: %v %v", table, i, err)
		}
		if !bytes.Equal(value, valueExpected[:]) {
			t.Fatalf("get unequal %v: %v", table, i)
		}
	}

	// Has
	for i := 0; i < insertCount; i++ {
		table := tables[i%tableCount]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		has, err := db.Has(ctx, table, key[:])
		if err != nil {
			t.Fatalf("has %v: %v %v", table, i, err)
		}
		if !has {
			t.Fatalf("has %v: %v", table, i)
		}
	}

	// Del
	for i := 0; i < insertCount; i++ {
		table := tables[i%tableCount]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		err := db.Del(ctx, table, key[:])
		if err != nil {
			t.Fatalf("del %v: %v %v", table, i, err)
		}
	}

	// Has negative
	for i := 0; i < insertCount; i++ {
		table := tables[i%tableCount]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		has, err := db.Has(ctx, table, key[:])
		if err != nil {
			t.Fatalf("has %v: %v %v", table, i, err)
		}
		if has {
			t.Fatalf("has %v: %v", table, i)
		}
	}

	// Get negative
	for i := 0; i < insertCount; i++ {
		table := tables[i%tableCount]
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], uint64(i))
		_, err := db.Get(ctx, table, key[:])
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("get expected not found error %v: %v %v", table, i, err)
		}
	}
}
