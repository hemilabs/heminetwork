// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/juju/loggo"
	"github.com/nutsdb/nutsdb"
)

const logLevel = "INFO"

var log = loggo.GetLogger("db")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

// Assert required interfaces
var (
	_ Batch       = (*nutsBatch)(nil)
	_ Database    = (*nutsDB)(nil)
	_ Iterator    = (*nutsIterator)(nil)
	_ Range       = (*nutsRange)(nil)
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
		return ErrDBOpen
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
	err := b.db.Update(func(tx *nutsdb.Tx) error {
		return xerr(tx.Delete(table, key))
	})
	if errors.Is(err, ErrKeyNotFound) {
		return nil
	}
	return err
}

// XXX the tx.Has() function should be used,
// but it doesn't seem to be working
func (b *nutsDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	_, err := b.Get(ctx, table, key)
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
			return fmt.Errorf("rollback: callback: %w -> %w", err, rberr)
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
	nr := &nutsRange{
		table:  table,
		tx:     tx,
		ntx:    tx.(*nutsTX).tx,
		start:  start,
		end:    end,
		cursor: -1, // first key when next called
	}
	keys, _, err := nr.ntx.RangeScanEntries(nr.table, nr.start, nr.end, true, false)
	if err != nil {
		// Kill tx
		if cerr := tx.Commit(ctx); cerr != nil {
			log.Errorf("commit error: %v", cerr)
		}
		return nil, xerr(err)
	}
	nr.keys = keys
	return nr, nil
}

func (b *nutsDB) NewBatch(ctx context.Context) (Batch, error) {
	return &nutsBatch{}, nil
}

func (b *nutsDB) DumpTable(ctx context.Context, table string, target io.Writer) error {
	return ErrNotSuported
}

func (b *nutsDB) RestoreTable(ctx context.Context, table string, source io.Reader) error {
	return ErrNotSuported
}

// Transactions

type nutsTX struct {
	tx *nutsdb.Tx
}

func (tx *nutsTX) Del(ctx context.Context, table string, key []byte) error {
	err := xerr(tx.tx.Delete(table, key))
	if errors.Is(err, ErrKeyNotFound) {
		return nil
	}
	return err
}

func (tx *nutsTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	_, err := tx.Get(ctx, table, key)
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

func (tx *nutsTX) Write(ctx context.Context, b Batch) error {
	return errors.New("not yet nuts")
}

// Iterations
type nutsIterator struct {
	table string
	tx    Transaction
	it    *nutsdb.Iterator

	first bool
}

func (ni *nutsIterator) First(_ context.Context) bool {
	return ni.it.Rewind()
}

func (ni *nutsIterator) Last(ctx context.Context) bool {
	key, err := ni.tx.(*nutsTX).tx.GetMaxKey(ni.table)
	if err != nil {
		log.Errorf("last: %v", err)
		return false
	}
	return ni.Seek(ctx, key)
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

func (ni *nutsIterator) Close(ctx context.Context) {
	err := ni.tx.Commit(ctx)
	if err != nil {
		log.Errorf("iterator close: %v", err)
	}
}

// Ranges
type nutsRange struct {
	table string
	tx    Transaction
	ntx   *nutsdb.Tx
	start []byte
	end   []byte

	keys   [][]byte
	cursor int // Current key
}

func (nr *nutsRange) First(_ context.Context) bool {
	if len(nr.keys) == 0 {
		return false
	}
	nr.cursor = 0
	return true
}

func (nr *nutsRange) Last(_ context.Context) bool {
	if len(nr.keys) == 0 {
		return false
	}
	nr.cursor = len(nr.keys) - 1
	return true
}

func (nr *nutsRange) Next(_ context.Context) bool {
	if len(nr.keys) == 0 {
		return false
	}
	if nr.cursor < len(nr.keys)-1 {
		nr.cursor++
		return true
	}
	return false
}

func (nr *nutsRange) Key(ctx context.Context) []byte {
	return nr.keys[nr.cursor]
}

func (nr *nutsRange) Value(ctx context.Context) []byte {
	value, err := nr.tx.Get(ctx, nr.table, nr.keys[nr.cursor])
	if err != nil {
		// meh, this should not happen
		log.Errorf("value %v", err)
		return nil
	}
	return value
}

func (nr *nutsRange) Close(ctx context.Context) {
	err := nr.tx.Commit(ctx)
	if err != nil {
		log.Errorf("range close: %v", err)
	}
}

// Batches

type nutsBatch struct{}

func (nb *nutsBatch) Del(ctx context.Context, table string, key []byte) {
}

func (nb *nutsBatch) Put(ctx context.Context, table string, key, value []byte) {
}

func (nb *nutsBatch) Reset(ctx context.Context) {
}
