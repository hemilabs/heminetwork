package db

import (
	"context"
	"errors"
	"fmt"

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

func (b *bitcaskDB) Del(_ context.Context, table string, key []byte) error {
	return b.db.Delete(bitcask.Key(NewCompositeKey(table, key)))
}

func (b *bitcaskDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	return b.db.Has(bitcask.Key(NewCompositeKey(table, key))), nil
}

func (b *bitcaskDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	value, err := b.db.Get(bitcask.Key(NewCompositeKey(table, key)))
	if err != nil {
		if errors.Is(err, bitcask.ErrKeyNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

func (b *bitcaskDB) Put(_ context.Context, table string, key, value []byte) error {
	return b.db.Put(bitcask.Key(NewCompositeKey(table, key)), value)
}

func (b *bitcaskDB) Last(ctx context.Context, table string) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("not yet")
}
