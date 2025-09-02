// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

// Assert required interfaces
var (
	_ Batch       = (*badgerBatch)(nil)
	_ Database    = (*badgerDB)(nil)
	_ Iterator    = (*badgerIterator)(nil)
	_ Range       = (*badgerRange)(nil)
	_ Transaction = (*badgerTX)(nil)
)

type BadgerConfig struct {
	Home   string
	Tables []string
}

func DefaultBadgerConfig(home string, tables []string) *BadgerConfig {
	return &BadgerConfig{
		Home:   home,
		Tables: tables,
	}
}

type badgerDB struct {
	db     *badger.DB
	opt    *badger.Options
	tables map[string]struct{}
	cfg    *BadgerConfig
}

func NewBadgerDB(cfg *BadgerConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	opt := badger.DefaultOptions(cfg.Home).WithLoggingLevel(badger.ERROR).WithCompression(options.None)
	bdb := &badgerDB{
		cfg:    cfg,
		opt:    &opt,
		tables: make(map[string]struct{}, len(cfg.Tables)),
	}
	for _, v := range cfg.Tables {
		if _, ok := bdb.tables[v]; ok {
			return nil, ErrDuplicateTable
		}
		bdb.tables[v] = struct{}{}
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

func (b *badgerDB) Del(_ context.Context, table string, key []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	err := b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(NewCompositeKey(table, key))
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	}
	return nil
}

func (b *badgerDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := b.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	_, err := b.Get(ctx, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (b *badgerDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	var val []byte
	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(NewCompositeKey(table, key))
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

func (b *badgerDB) Put(_ context.Context, table string, key, value []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	err := b.db.Update(func(txn *badger.Txn) error {
		return txn.Set(NewCompositeKey(table, key), value)
	})
	if err != nil {
		return err
	}
	return nil
}

func (b *badgerDB) Begin(_ context.Context, write bool) (Transaction, error) {
	tx := b.db.NewTransaction(write)
	return &badgerTX{
		db: b,
		tx: tx,
	}, nil
}

func (b *badgerDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
	tx, err := b.Begin(ctx, write)
	if err != nil {
		return err
	}
	err = callback(ctx, tx)
	if err != nil {
		if cerr := tx.Rollback(ctx); cerr != nil {
			return fmt.Errorf("rollback %w: %w", cerr, err)
		}
		return err
	}
	return tx.Commit(ctx)
}

func (b *badgerDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, false, callback)
}

func (b *badgerDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, true, callback)
}

func (b *badgerDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	tx := b.db.NewTransaction(false)
	opts := badger.DefaultIteratorOptions
	it := tx.NewIterator(opts)
	it.Rewind()
	return &badgerIterator{
		table: table,
		it:    it,
	}, nil
}

func (b *badgerDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	tx := b.db.NewTransaction(false)
	opts := badger.DefaultIteratorOptions
	opts.Prefix = []byte(table + ":")
	it := tx.NewIterator(opts)
	it.Rewind()
	return &badgerIterator{
		table: table,
		it:    it,
	}, nil
}

func (b *badgerDB) NewBatch(ctx context.Context) (Batch, error) {
	return &badgerBatch{}, nil
}

func (b *badgerDB) DumpTable(ctx context.Context, table string, target io.Writer) error {
	return ErrNotSuported
}

func (b *badgerDB) RestoreTable(ctx context.Context, table string, target io.Reader) error {
	return ErrNotSuported
}

// Transactions

type badgerTX struct {
	db *badgerDB
	tx *badger.Txn
}

func (tx *badgerTX) Del(ctx context.Context, table string, key []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Delete(NewCompositeKey(table, key)))
}

func (tx *badgerTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	_, err := tx.Get(ctx, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, xerr(err)
}

func (tx *badgerTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	item, err := tx.tx.Get(NewCompositeKey(table, key))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	val, err := item.ValueCopy(nil)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (tx *badgerTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Set(NewCompositeKey(table, key), value))
}

func (tx *badgerTX) Commit(ctx context.Context) error {
	return xerr(tx.tx.Commit())
}

func (tx *badgerTX) Rollback(ctx context.Context) error {
	tx.tx.Discard()
	return nil
}

func (tx *badgerTX) Write(ctx context.Context, b Batch) error {
	return errors.New("not yet badger")
}

// Iterations
type badgerIterator struct {
	table string
	it    *badger.Iterator
	first bool
}

func (ni *badgerIterator) First(_ context.Context) bool {
	ni.it.Rewind()
	return ni.it.Valid()
}

// XXX Not yet
func (ni *badgerIterator) Last(_ context.Context) bool {
	return false
}

func (ni *badgerIterator) Next(_ context.Context) bool {
	if !ni.first {
		ni.first = true
		ni.it.Rewind()
	} else {
		ni.it.Next()
	}
	return ni.it.Valid()
}

func (ni *badgerIterator) Seek(_ context.Context, key []byte) bool {
	ni.first = true
	ni.it.Seek(NewCompositeKey(ni.table, key))
	return ni.it.Valid()
}

func (ni *badgerIterator) Key(_ context.Context) []byte {
	return KeyFromComposite(ni.table, ni.it.Item().KeyCopy(nil))
}

func (ni *badgerIterator) Value(_ context.Context) []byte {
	val, err := ni.it.Item().ValueCopy(nil)
	if err != nil {
		log.Errorf("value: %v", err)
		return nil
	}
	return val
}

func (ni *badgerIterator) Close(ctx context.Context) {
	ni.it.Close()
}

// Ranges
type badgerRange struct {
	table string
	tx    *badger.Txn
	it    *badger.Iterator
}

func (nr *badgerRange) First(_ context.Context) bool {
	nr.it.Rewind()
	return !nr.it.Valid()
}

// XXX not yet
func (nr *badgerRange) Last(_ context.Context) bool {
	return false
}

func (nr *badgerRange) Next(_ context.Context) bool {
	nr.it.Next()
	return nr.it.Valid()
}

func (nr *badgerRange) Key(ctx context.Context) []byte {
	return KeyFromComposite(nr.table, nr.it.Item().KeyCopy(nil))
}

func (nr *badgerRange) Value(ctx context.Context) []byte {
	val, err := nr.it.Item().ValueCopy(nil)
	if err != nil {
		log.Errorf("value: %v", err)
		return nil
	}
	return val
}

func (nr *badgerRange) Close(ctx context.Context) {
	nr.it.Close()
	nr.tx.Discard()
}

// Batches

type badgerBatch struct{}

func (nb *badgerBatch) Del(ctx context.Context, table string, key []byte) {
}

func (nb *badgerBatch) Put(ctx context.Context, table string, key, value []byte) {
}

func (nb *badgerBatch) Reset(ctx context.Context) {
}
