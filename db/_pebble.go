package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
)

var _ Database = (*pebbleDB)(nil)

type PebbleConfig struct {
	Home string
}

func DefaultPebbleConfig(home string) *PebbleConfig {
	return &PebbleConfig{
		Home: home,
	}
}

type pebbleDB struct {
	db *pebble.DB

	cfg *PebbleConfig
}

func NewPebbleDB(cfg *PebbleConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &pebbleDB{
		cfg: cfg,
	}

	return bdb, nil
}

func (b *pebbleDB) Open(_ context.Context) error {
	if b.db != nil {
		return nil // XXX return already open?
	}
	ldb, err := pebble.Open(b.cfg.Home, &pebble.Options{
		Levels: []pebble.LevelOptions{
			{Compression: pebble.NoCompression},
		},
	})
	if err != nil {
		return err
	}
	b.db = ldb
	return nil
}

func (b *pebbleDB) Close(_ context.Context) error {
	return b.db.Close()
}

func (b *pebbleDB) Del(_ context.Context, table string, key []byte) error {
	return b.db.Delete(NewCompositeKey(table, key), nil)
}

func (b *pebbleDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	_, err := b.Get(nil, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (b *pebbleDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	value, closer, err := b.db.Get(NewCompositeKey(table, key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	v := make([]byte, len(value))
	copy(v, value)
	err = closer.Close()
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (b *pebbleDB) Put(_ context.Context, table string, key, value []byte) error {
	return b.db.Set(NewCompositeKey(table, key), value, nil)
}

func (b *pebbleDB) Last(ctx context.Context, table string) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("not yet")
}
