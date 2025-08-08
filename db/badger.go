package db

import (
	"context"
	"errors"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

var _ Database = (*badgerDB)(nil)

type BadgerConfig struct {
	Home string
}

func DefaultBadgerConfig(home string) *BadgerConfig {
	return &BadgerConfig{
		Home: home,
	}
}

type badgerDB struct {
	db  *badger.DB
	opt *badger.Options

	cfg *BadgerConfig
}

func NewBadgerDB(cfg *BadgerConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	opt := badger.DefaultOptions(cfg.Home).WithLoggingLevel(badger.ERROR).WithCompression(options.None)
	bdb := &badgerDB{
		cfg: cfg,
		opt: &opt,
	}

	return bdb, nil
}

func (b *badgerDB) Open(_ context.Context) error {
	if b.db != nil {
		return nil // XXX return already open?
	}
	db, err := badger.Open(*b.opt)
	if err != nil {
		return err
	}
	b.db = db
	return nil
}

func (b *badgerDB) Close(_ context.Context) error {
	return b.db.Close()
}

func (b *badgerDB) Del(_ context.Context, key []byte) error {
	err := b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrKeyNotFound
		}
		return err
	}
	return nil
}

func (b *badgerDB) Has(_ context.Context, key []byte) (bool, error) {
	_, err := b.Get(nil, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (b *badgerDB) Get(_ context.Context, key []byte) ([]byte, error) {
	var val []byte
	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		val, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return val, nil
}

func (b *badgerDB) Put(_ context.Context, key, value []byte) error {
	err := b.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
	if err != nil {
		return err
	}
	return nil
}
