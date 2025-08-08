package db

import (
	"context"
	"errors"

	"github.com/nutsdb/nutsdb"
)

var _ Database = (*nutsDB)(nil)

type NutsConfig struct {
	Home string
}

func DefaultNutsConfig(home string) *NutsConfig {
	return &NutsConfig{
		Home: home,
	}
}

type nutsDB struct {
	db *nutsdb.DB

	cfg *NutsConfig
}

func NewNutsDB(cfg *NutsConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &nutsDB{
		cfg: cfg,
	}

	return bdb, nil
}

func (b *nutsDB) Open(_ context.Context) error {
	if b.db != nil {
		return nil // XXX return already open?
	}
	// XXX no compression
	ndb, err := nutsdb.Open(nutsdb.DefaultOptions, nutsdb.WithDir(b.cfg.Home))
	if err != nil {
		return err
	}
	err = ndb.Update(func(tx *nutsdb.Tx) error {
		return tx.NewBucket(nutsdb.DataStructureBTree, "bucket1")
	})
	if err != nil {
		return err
	}
	b.db = ndb
	return nil
}

func (b *nutsDB) Close(_ context.Context) error {
	return b.db.Close()
}

func (b *nutsDB) Del(_ context.Context, key []byte) error {
	err := b.db.View(
		func(tx *nutsdb.Tx) error {
			bucket := "bucket1"
			_, err := tx.ValueLen(bucket, key)
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, nutsdb.ErrKeyNotFound) {
			return ErrKeyNotFound
		}
		return err
	}
	return nil
}

func (b *nutsDB) Has(_ context.Context, key []byte) (bool, error) {
	_, err := b.Get(nil, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (b *nutsDB) Get(_ context.Context, key []byte) ([]byte, error) {
	var value []byte
	err := b.db.View(func(tx *nutsdb.Tx) error {
		key := key
		bucket := "bucket1"
		var err error
		value, err = tx.Get(bucket, key)
		if err != nil {
			return err
		}
		// XXX do we need to copy value?
		return nil
	})
	if err != nil {
		if errors.Is(err, nutsdb.ErrKeyNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

func (b *nutsDB) Put(_ context.Context, key, value []byte) error {
	err := b.db.Update(
		func(tx *nutsdb.Tx) error {
			key := key
			val := value
			bucket := "bucket1"
			if err := tx.Put(bucket, key, val, 0); err != nil {
				return err
			}
			return nil
		})
	return err
}
