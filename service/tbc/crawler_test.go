package tbc

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

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

	err = s.indexBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
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
