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

// Translate nutsb errors into gkvdb errors
func xerr(err error) error {
	switch {
	case errors.Is(err, nutsdb.ErrKeyNotFound):
		err = ErrKeyNotFound
	}
	return err
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
	return &NutsConfig{
		Home:   home,
		Tables: tables,
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
	if len(cfg.Tables) == 0 {
		// nutsdb requires the creation of tables.
		return nil, fmt.Errorf("must provide table names")
	}
	bdb := &nutsDB{
		cfg: cfg,
	}

	return bdb, nil
}

func (b *nutsDB) Open(_ context.Context) error {
	log.Tracef("open")

	if b.db != nil {
		return nil // XXX return already open?
	}
	// XXX no compression
	ndb, err := nutsdb.Open(nutsdb.DefaultOptions, nutsdb.WithDir(b.cfg.Home))
	if err != nil {
		return err
	}
	err = ndb.Update(func(tx *nutsdb.Tx) error {
		for _, table := range b.cfg.Tables {
			// XXX add mechanism to pass in the datastructure type
			err := tx.NewBucket(nutsdb.DataStructureBTree, table)
			if err != nil {
				return fmt.Errorf("could not create table: %v", table)
			}
		}
		return nil
	})
	if err != nil {
		return xerr(err)
	}
	b.db = ndb
	return nil
}

func (b *nutsDB) Close(_ context.Context) error {
	return xerr(b.db.Close())
}

func (b *nutsDB) Del(_ context.Context, table string, key []byte) error {
	return b.db.Update(func(tx *nutsdb.Tx) error {
		return xerr(tx.Delete(table, key))
	})
}

func (b *nutsDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	_, err := b.Get(nil, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (b *nutsDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	var value []byte = nil
	err := b.db.View(func(tx *nutsdb.Tx) error {
		key := key
		val, err := tx.Get(table, key)
		if err != nil {
			return xerr(err)
		}
		// nutsdb unfortunately invalidates value outside of the transaction
		value = make([]byte, len(val))
		copy(value, val)
		return nil
	})
	return value, xerr(err)
}

func (b *nutsDB) Put(_ context.Context, table string, key, value []byte) error {
	err := b.db.Update(
		func(tx *nutsdb.Tx) error {
			key := key
			val := value
			err := tx.Put(table, key, val, 0)
			if err != nil {
				return err
			}
			return nil
		})
	return xerr(err)
}

//	func (b *nutsDB) View(ctx context.Context, callback func(ctx context.Context, tx *Transaction) error) error {
//		itx, err := b.db.Begin(false)
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
func (b *nutsDB) Begin(_ context.Context, write bool) (Transaction, error) {
	tx, err := b.db.Begin(write)
	if err != nil {
		return nil, err
	}
	return &nutsTX{
		db: b.db, // XXX do we need this?
		tx: tx,
	}, nil
}

// Transactions

type nutsTX struct {
	db *nutsdb.DB
	tx *nutsdb.Tx
}

func (tx *nutsTX) Del(ctx context.Context, table string, key []byte) error {
	return xerr(tx.tx.Delete(table, key))
}

func (tx *nutsTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	_, err := tx.Get(nil, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (tx *nutsTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	value, err := tx.tx.Get(table, key)
	return value, xerr(err)
}

func (tx *nutsTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	return xerr(tx.tx.Put(table, key, value, 0))
}

func (tx *nutsTX) Commit(ctx context.Context) error {
	return xerr(tx.tx.Commit())
}

func (tx *nutsTX) Rollback(ctx context.Context) error {
	return xerr(tx.tx.Rollback())
}
