package db

import (
	"context"
	"errors"

	"go.mills.io/bitcask/v2"
)

var _ Database = (*bitcaskDB)(nil)

type BitcaskConfig struct {
	Home string
}

func DefaultBitcaskConfig(home string) *BitcaskConfig {
	return &BitcaskConfig{
		Home: home,
	}
}

type bitcaskDB struct {
	db *bitcask.Bitcask

	cfg *BitcaskConfig
}

func NewBitcaskDB(cfg *BitcaskConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &bitcaskDB{
		cfg: cfg,
	}

	return bdb, nil
}

func (b *bitcaskDB) Open(_ context.Context) error {
	if b.db != nil {
		return nil // XXX return already open?
	}
	opts := []bitcask.Option{
		bitcask.WithMaxKeySize(128),
		bitcask.WithMaxValueSize(8_000_000),
	}
	bdb, err := bitcask.Open(b.cfg.Home, opts...)
	if err != nil {
		return err
	}
	b.db = bdb
	return nil
}

func (b *bitcaskDB) Close(_ context.Context) error {
	return b.db.Close()
}

func (b *bitcaskDB) Del(_ context.Context, key []byte) error {
	return b.db.Delete(key)
}

func (b *bitcaskDB) Has(_ context.Context, key []byte) (bool, error) {
	return b.db.Has(key), nil
}

func (b *bitcaskDB) Get(_ context.Context, key []byte) ([]byte, error) {
	value, err := b.db.Get(key)
	if err != nil {
		if errors.Is(err, bitcask.ErrKeyNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

func (b *bitcaskDB) Put(_ context.Context, key, value []byte) error {
	return b.db.Put(key, value)
}
