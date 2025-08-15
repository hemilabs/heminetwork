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
	return err == nil, xerr(err)
}

func (b *nutsDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	var value []byte = nil
	err := b.db.View(func(tx *nutsdb.Tx) error {
		val, err := tx.Get(table, key)
		if err != nil {
			return err
		}
		// nutsdb unfortunately invalidates value outside of the transaction
		value = make([]byte, len(val))
		copy(value, val)
		return nil
	})
	return value, xerr(err)
}

func (b *nutsDB) Put(_ context.Context, table string, key, value []byte) error {
	return xerr(b.db.Update(func(tx *nutsdb.Tx) error {
		return tx.Put(table, key, value, 0)
	}))
}

func (b *nutsDB) Begin(_ context.Context, write bool) (Transaction, error) {
	tx, err := b.db.Begin(write)
	if err != nil {
		return nil, xerr(err)
	}
	return &nutsTX{
		// db: b.db, // XXX do we need this?
		tx: tx,
	}, nil
}

// execute runs a transaction and commits or rolls it back depending on errors.
// It does not perform error translation meaning that the caller must handle
// that prior to returning to the caller.
func (b *nutsDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
	itx, err := b.Begin(ctx, write)
	if err != nil {
		return err
	}
	err = callback(ctx, itx)
	if err != nil {
		if rberr := itx.Rollback(ctx); rberr != nil {
			return fmt.Errorf("rollback: callback: %v -> %w", err, rberr)
		}
		return err
	}
	return itx.Commit(ctx)
}

func (b *nutsDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return xerr(b.execute(ctx, false, callback))
}

func (b *nutsDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return xerr(b.execute(ctx, true, callback))
}

func (b *nutsDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	tx, err := b.Begin(ctx, false)
	if err != nil {
		return nil, xerr(err)
	}
	return &nutsIterator{
		table: table,
		tx:    tx,
		it: nutsdb.NewIterator(tx.(*nutsTX).tx, table,
			nutsdb.IteratorOptions{Reverse: false}),
	}, nil
}

func (b *nutsDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	tx, err := b.Begin(ctx, false)
	if err != nil {
		return nil, xerr(err)
	}
	return &nutsRange{
		table: table,
		tx:    tx,
		ntx:   tx.(*nutsTX).nutsTx(),
		start: start,
		end:   end,
	}, nil
}

// Transactions

type nutsTX struct {
	// db *nutsdb.DB
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
	return err == nil, xerr(err)
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

func (tx *nutsTX) nutsTx() *nutsdb.Tx {
	return tx.tx
}

// Iterations
type nutsIterator struct {
	table string
	tx    Transaction
	it    *nutsdb.Iterator
	r     *Range

	first bool
}

func (ni *nutsIterator) First(_ context.Context) bool {
	return ni.it.Rewind()
}

func (ni *nutsIterator) Last(_ context.Context) bool {
	key, err := ni.tx.(*nutsTX).nutsTx().GetMaxKey(ni.table)
	if err != nil {
		log.Errorf("last: %v", err)
		return false
	}
	return ni.Seek(nil, key)
}

func (ni *nutsIterator) Next(_ context.Context) bool {
	// The first next should be the first record.
	if !ni.first {
		ni.first = true
		return ni.it.Rewind()
	}
	return ni.it.Next()
}

func (ni *nutsIterator) Seek(_ context.Context, key []byte) bool {
	ni.first = true
	return ni.it.Seek(key)
}

func (ni *nutsIterator) Key(_ context.Context) []byte {
	return ni.it.Key()
}

func (ni *nutsIterator) Value(_ context.Context) []byte {
	v, _ := ni.it.Value()
	return v
}

func (ni *nutsIterator) Close(ctx context.Context) error {
	return ni.tx.Commit(ctx)
}

// Ranges
type nutsRange struct {
	table string
	tx    Transaction
	ntx   *nutsdb.Tx
	start []byte
	end   []byte

	cursor []byte // Current key
}

func (nr *nutsRange) First(_ context.Context) bool {
	//log.Infof("first: %v", spew.Sdump(nr.start))
	// v, err := nr.ntx.GetRange(nr.table, nr.start, 0, 8)
	// v, err := nr.ntx.PrefixScan(nr.table, nr.start, 0, 1)
	// v, err := nr.ntx.RangeScan(nr.table, nr.start, nil)
	//if err != nil {
	//	log.Errorf("range first: %v", err)
	//	return false
	//}
	//log.Infof("got %v", spew.Sdump(v))
	//if len(v) != 1 {
	//	return false
	//}
	//nr.cursor = make([]byte, len(v[0]))
	//copy(nr.cursor, v[0])
	return false
	return true
}

func (nr *nutsRange) Close(ctx context.Context) error {
	return nr.tx.Commit(ctx)
}

//func (ni *nutsIterator) Range(ctx context.Context) error {
//	spew.Dump(ni.tx.(*nutsTX).nutsTx().RangeScan(ni.table, ni.r.Start, ni.r.End))
//	return nil
//}
