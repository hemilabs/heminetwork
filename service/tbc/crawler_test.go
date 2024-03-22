package tbc

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/database/tbcd/level"
)

func TestIndex(t *testing.T) {
	logLevel := "INFO"
	loggo.ConfigureLoggers(logLevel)
	s, err := NewServer(&Config{
		Network: "testnet3",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Open db.
	s.cfg.LevelDBHome = "~/.tbcd"
	s.db, err = level.New(ctx, filepath.Join(s.cfg.LevelDBHome, s.cfg.Network))
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()

	start := time.Now()
	err = s.indexer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("done at %v", time.Now().Sub(start))
}

func TestUtxo(t *testing.T) {
	t.Skip()

	dc := &spew.ConfigState{
		DisableMethods: true,
	}

	utxos := make(map[Outpoint]Utxo, 100)
	hash := sha256.Sum256([]byte("Hello, world!"))
	index := uint32(1)
	op := NewOutpoint(hash, index)
	hash2 := sha256.Sum256([]byte("Hello, world!2"))
	op2 := NewOutpoint(hash2, index)
	utxo := Utxo{}
	utxos[op] = utxo
	utxos[op2] = utxo
	t.Logf("%v", dc.Sdump(utxos))
	t.Logf("%v", len(op.String()))

	for k := range utxos {
		t.Logf("%T", k)
	}

	type myt [2]byte
	var m myt
	m[0] = 1
	t.Logf("%T", m)
	t.Logf("%x", m)
	t.Logf("%v", len(m))

	var mx myt
	mx[0] = 2
	mm := make(map[myt]int)
	mm[m] = 1234
	mm[mx] = 5678
	t.Logf("%v", dc.Sdump(mm))

	t.Logf("%v", spew.Sdump(utxos))
}

// Test the various mapsizes
// run with go test -v -bench . -benchmem -run=BenchmarkMap
func allocateMap(size int) map[Outpoint]Utxo {
	m := make(map[Outpoint]Utxo, size)
	for i := 0; i < size; i++ {
		m[Outpoint{}] = Utxo{}
	}
	return m
}

func BenchmarkMap10(b *testing.B) {
	for i := 0; i < b.N; i++ {
		allocateMap(10)
	}
}

func BenchmarkMap100(b *testing.B) {
	for i := 0; i < b.N; i++ {
		allocateMap(100)
	}
}

func BenchmarkMap10000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		allocateMap(10000)
	}
}

func BenchmarkMap100000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		allocateMap(100000)
	}
}

// BenchmarkMap1000000 seems to indicate that 1 million utxos use about
// 182714418 bytes which is about 174MB on linux/arm64.
// Or, about 183 per cache entry. 100 bytes for the key and value (36+44) and
// 83 in overhead.
func BenchmarkMap1000000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		allocateMap(1e6)
	}
}
