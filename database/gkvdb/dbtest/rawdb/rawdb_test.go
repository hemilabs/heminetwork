// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package rawdb

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func testRawDB(t *testing.T, dbs string) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()
	remove := true
	defer func() {
		if !remove {
			t.Logf("did not remove home: %v", home)
			return
		}

		if err := os.RemoveAll(home); err != nil {
			panic(err)
		}
	}()

	blockSize := int64(4096)
	rdb, err := New(&Config{DB: dbs, Home: home, MaxSize: blockSize})
	if err != nil {
		t.Fatal(err)
	}
	err = rdb.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := rdb.Close(ctx)
		if err != nil {
			panic(err)
		}
	}()

	if dbs != "mongo" {
		// Open again and expect locked failure
		rdb2, err := New(&Config{DB: dbs, Home: home, MaxSize: blockSize})
		if err != nil {
			t.Fatal(err)
		}
		err = rdb2.Open(ctx)
		if err == nil {
			t.Fatal("expected locked db")
		}
	}

	key := []byte("key")
	data := []byte("hello, world!")
	err = rdb.Insert(ctx, key, data)
	if err != nil {
		t.Fatalf("%T %v", err, err)
	}
	KEY := []byte("KEY")
	DATA := []byte("HELLO, WORLD!")
	err = rdb.Insert(ctx, KEY, DATA)
	if err != nil {
		t.Fatal(err)
	}

	// Get data out again
	dataRead, err := rdb.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, dataRead) {
		t.Fatal("data not identical")
	}
	dataRead, err = rdb.Get(ctx, KEY)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(DATA, dataRead) {
		t.Fatal("data not identical")
	}

	// Overflow to next file
	overflowData := make([]byte, int(blockSize)-len(data)-len(DATA)+1)
	for k := range overflowData {
		overflowData[k] = uint8(k)
	}
	overflowKey := []byte("overflow")
	err = rdb.Insert(ctx, overflowKey, overflowData)
	if err != nil {
		t.Fatal(err)
	}
	overflowRead, err := rdb.Get(ctx, overflowKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(overflowData, overflowRead) {
		t.Fatal("overflow data not identical")
	}
}

func TestRawDBS(t *testing.T) {
	dbs := []string{"badger", "level", "pebble", "bitcask", "bunt", "nuts"}
	for _, v := range dbs {
		log.Infof("testing: %v", v)
		testRawDB(t, v)
	}
}

func TestRemoteDBS(t *testing.T) {
	if os.Getenv(DefaultMongoEnvURI) == "" {
		t.Logf("%v env variable not set, skipping test", DefaultMongoEnvURI)
		t.Skip()
	}
	testRawDB(t, "mongo")
}
