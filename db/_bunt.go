package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tidwall/buntdb"
)

var _ Database = (*buntDB)(nil)

var buntOpen bool // XXX kill this horrible hack

type BuntConfig struct {
	Home string
}

func DefaultBuntConfig(home string) *BuntConfig {
	return &BuntConfig{
		Home: home,
	}
}

type buntDB struct {
	db *buntdb.DB

	cfg *BuntConfig
}

func NewBuntDB(cfg *BuntConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &buntDB{
		cfg: cfg,
	}

	return bdb, nil
}

func (b *buntDB) Open(_ context.Context) error {
	if buntOpen {
		return fmt.Errorf("already open")
	}
	err := os.MkdirAll(b.cfg.Home, 0o700)
	if err != nil {
		return err
	}
	dbfile := filepath.Join(b.cfg.Home, "bunt.db")
	bdb, err := buntdb.Open(dbfile)
	if err != nil {
		return err
	}
	b.db = bdb
	buntOpen = true // XXX hack and shit
	return nil
}

func (b *buntDB) Close(_ context.Context) error {
	defer func() { buntOpen = false }()
	return b.db.Close()
}

func (b *buntDB) Del(_ context.Context, table string, key []byte) error {
	err := b.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(string(NewCompositeKey(table, key)))
		return err
	})
	if err != nil {
		if errors.Is(err, buntdb.ErrNotFound) {
			return ErrKeyNotFound
		}
		return err
	}
	return err
}

func (b *buntDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	_, err := b.Get(nil, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (b *buntDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	var value []byte
	err := b.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(string(NewCompositeKey(table, key)))
		if err != nil {
			return err
		}
		value = []byte(val)
		return nil
	})
	if err != nil {
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

func (b *buntDB) Put(_ context.Context, table string, key, value []byte) error {
	err := b.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(string(NewCompositeKey(table, key)),
			string(value), nil)
		return err
	})
	return err
}

func (b *buntDB) Last(ctx context.Context, table string) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("not yet")
}
