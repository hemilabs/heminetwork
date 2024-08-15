// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package rawdb

import (
	"bytes"
	"os"
	"testing"
)

func TestRawDB(t *testing.T) {
	home, err := os.MkdirTemp("", "rawdb")
	if err != nil {
		t.Fatal(err)
	}
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
	rdb, err := New(home, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	err = rdb.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := rdb.Close()
		if err != nil {
			panic(err)
		}
	}()

	// Open again and expect locked failure
	rdb2, err := New(home, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	err = rdb2.Open()
	if err == nil {
		t.Fatal("expected locked db")
	}

	key := []byte("key")
	data := []byte("hello, world!")
	err = rdb.Insert(key, data)
	if err != nil {
		t.Fatal(err)
	}
	KEY := []byte("KEY")
	DATA := []byte("HELLO, WORLD!")
	err = rdb.Insert(KEY, DATA)
	if err != nil {
		t.Fatal(err)
	}

	// Get data out again
	dataRead, err := rdb.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, dataRead) {
		t.Fatal("data not identical")
	}
	dataRead, err = rdb.Get(KEY)
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
	err = rdb.Insert(overflowKey, overflowData)
	if err != nil {
		t.Fatal(err)
	}
	overflowRead, err := rdb.Get(overflowKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(overflowData, overflowRead) {
		t.Fatal("overflow data not identical")
	}
}
