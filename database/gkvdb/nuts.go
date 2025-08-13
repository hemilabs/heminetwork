// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/juju/loggo"
	"github.com/nutsdb/nutsdb"
)

const logLevel = "INFO"

var log = loggo.GetLogger("nutsdb")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

// Assert required inteerfaces
var (
	_ Database    = (*nutsDB)(nil)
	_ Transaction = (*nutsTX)(nil)
)

type NutsConfig struct {
	Home   string
	Tables []string
}

func DefaultNutsConfig(home string, tables []string) *NutsConfig {
	if len(tables) == 0 {
		tables = []string{"toplevel"}
	}
	return &NutsConfig{
		Home:   home,
		Tables: tables,
	}
}

type nutsDB struct {
	gkvdb *nutsdb.DB

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
	log.Tracef("open")

	if b.gkvdb != nil {
		return nil // XXX return already open?
	}
	// XXX no compression
	ndb, err := nutsdb.Open(nutsdb.DefaultOptions, nutsdb.WithDir(b.cfg.Home))
	if err != nil {
		return err
	}
	err = ndb.Update(func(tx *nutsdb.Tx) error {
		for _, table := range b.cfg.Tables {
			err := tx.NewBucket(nutsdb.DataStructureBTree, table)
			if err != nil {
				return fmt.Errorf("could not create table: %v", table)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	b.gkvdb = ndb
	return nil
}

func (b *nutsDB) Close(_ context.Context) error {
	return b.gkvdb.Close()
}

func (b *nutsDB) Del(_ context.Context, table string, key []byte) error {
	err := b.gkvdb.View(
		func(tx *nutsdb.Tx) error {
			_, err := tx.ValueLen(table, key)
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

func (b *nutsDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	_, err := b.Get(nil, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (b *nutsDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	var value []byte
	err := b.gkvdb.View(func(tx *nutsdb.Tx) error {
		key := key
		val, err := tx.Get(table, key)
		if err != nil {
			return err
		}
		value = make([]byte, len(val))
		copy(value, val)
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

func (b *nutsDB) Put(_ context.Context, table string, key, value []byte) error {
	err := b.gkvdb.Update(
		func(tx *nutsdb.Tx) error {
			key := key
			val := value
			err := tx.Put(table, key, val, 0)
			if err != nil {
				if nutsdb.IsBucketNotFound(err) {
					panic(err)
				}
				return err
			}
			return nil
		})
	return err
}

//	func (b *nutsDB) View(ctx context.Context, callback func(ctx context.Context, tx *Transaction) error) error {
//		itx, err := b.gkvdb.Begin(false)
//		if err != nil {
//			return err
//		}
//		err = callback(ctx, &Transaction{tx: itx})
//		if err != nil {
//			if rberr := itx.Rollback(); err != nil {
//				return fmt.Errorf("rollback: %w", rberr)
//			}
//			return err
//		}
//		return itx.Commit()
//	}
func (b *nutsDB) Begin(ctx context.Context, write bool) (Transaction, error) {
	return &nutsTX{}, nil
}

// Transactions

type nutsTX struct{}

var errNutsNotYet = errors.New("not yet")

func (tx *nutsTX) Del(ctx context.Context, table string, key []byte) error {
	return errNutsNotYet
}

func (tx *nutsTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	return false, errNutsNotYet
}

func (tx *nutsTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	return nil, errNutsNotYet
}

func (tx *nutsTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	return errNutsNotYet
}

func (tx *nutsTX) Commit(ctx context.Context) error {
	return errNutsNotYet
}

func (tx *nutsTX) Rollback(ctx context.Context) error {
	return errNutsNotYet
}
