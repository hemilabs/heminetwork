package db

import (
	"context"
	"errors"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var _ Database = (*levelDB)(nil)

type LevelConfig struct {
	Home string
}

func DefaultLevelConfig(home string) *LevelConfig {
	return &LevelConfig{
		Home: home,
	}
}

type levelDB struct {
	db *leveldb.DB

	cfg *LevelConfig
}

func NewLevelDB(cfg *LevelConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &levelDB{
		cfg: cfg,
	}

	return bdb, nil
}

func (b *levelDB) Open(_ context.Context) error {
	if b.db != nil {
		return nil // XXX return already open?
	}
	ldb, err := leveldb.OpenFile(b.cfg.Home, &opt.Options{
		BlockCacheEvictRemoved: true,
		Compression:            opt.NoCompression,
	})
	if err != nil {
		return err
	}
	b.db = ldb
	return nil
}

func (b *levelDB) Close(_ context.Context) error {
	return b.db.Close()
}

func (b *levelDB) Del(_ context.Context, key []byte) error {
	return b.db.Delete(key, nil)
}

func (b *levelDB) Has(_ context.Context, key []byte) (bool, error) {
	return b.db.Has(key, nil)
}

func (b *levelDB) Get(_ context.Context, key []byte) ([]byte, error) {
	value, err := b.db.Get(key, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

func (b *levelDB) Put(_ context.Context, key, value []byte) error {
	return b.db.Put(key, value, nil)
}
