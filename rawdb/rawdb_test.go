// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package rawdb

import (
	"bytes"
	"os"
	"testing"
)

func TestRawDB(t *testing.T) {
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
	rdb, err := New(&Config{Home: home, MaxSize: blockSize})
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
	rdb2, err := New(&Config{Home: home, MaxSize: blockSize})
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

func TestGetRange(t *testing.T) {
	rdb, err := New(&Config{Home: t.TempDir(), MaxSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if err := rdb.Open(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rdb.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	key := []byte("blockkey000000000000000000000000")
	value := make([]byte, 1000)
	for i := range value {
		value[i] = byte(i)
	}
	if err := rdb.Insert(key, value); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		off     uint32
		length  uint32
		wantErr bool
	}{
		{"interior", 100, 250, false},
		{"prefix", 0, 1, false},
		{"exactEnd", 900, 100, false},
		{"whole", 0, 1000, false},
		{"empty", 500, 0, false},
		{"emptyAtEnd", 1000, 0, false},
		{"pastEnd", 900, 101, true},
		{"offsetPastEnd", 1000, 1, true},
		{"overflowSum", 4294967295, 4294967295, true},
		{"overflowWrapSmall", 4294967295, 1001, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rdb.GetRange(key, tt.off, tt.length)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected range error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := value[tt.off : tt.off+tt.length]
			if !bytes.Equal(got, want) {
				t.Fatalf("range %d+%d: got %x want %x",
					tt.off, tt.length, got, want)
			}
		})
	}

	// Missing key surfaces the index error.
	if _, err := rdb.GetRange([]byte("nosuchkey0000000000000000000000"), 0, 1); err == nil {
		t.Fatal("expected not found")
	}

	// Get must remain the whole value.
	whole, err := rdb.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole, value) {
		t.Fatal("Get no longer returns whole value")
	}

	// A second value sits at a nonzero file offset (values append),
	// pinning the base-offset + range-offset pread arithmetic.
	key2 := []byte("blockkey000000000000000000000001")
	value2 := make([]byte, 500)
	for i := range value2 {
		value2[i] = byte(255 - i)
	}
	if err := rdb.Insert(key2, value2); err != nil {
		t.Fatal(err)
	}
	got2, err := rdb.GetRange(key2, 100, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, value2[100:150]) {
		t.Fatal("ranged read at nonzero file offset returned wrong bytes")
	}
}

// TestNewRejectsOversizedMaxSize: coordinates are uint32; a larger
// file cap would truncate them at write time.
func TestNewRejectsOversizedMaxSize(t *testing.T) {
	if _, err := New(&Config{Home: t.TempDir(), MaxSize: 1 << 33}); err == nil {
		t.Fatal("MaxSize above uint32 accepted")
	}
}

// Expected (dev box): Get of a 4MB value ~440us/op ~4MB/op; GetRange
// of 300B ~2.5us/op ~800B/op — the ranged read is the regression
// tripwire for the whole-block -> pread conversion.
func BenchmarkRawDBRead(b *testing.B) {
	rdb, err := New(&Config{Home: b.TempDir(), MaxSize: 8 << 20})
	if err != nil {
		b.Fatal(err)
	}
	if err := rdb.Open(); err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := rdb.Close(); err != nil {
			b.Fatal(err)
		}
	}()
	key := []byte("benchkey000000000000000000000000")
	value := make([]byte, 4<<20)
	if err := rdb.Insert(key, value); err != nil {
		b.Fatal(err)
	}

	b.Run("GetWhole4MB", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := rdb.Get(key); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("GetRange300B", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := rdb.GetRange(key, 1<<20, 300); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("GetRange300BParallel", func(b *testing.B) {
		b.ReportAllocs()
		b.SetParallelism(16)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := rdb.GetRange(key, 1<<20, 300); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}
