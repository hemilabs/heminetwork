// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"

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

	// kinda sucks but we must force
	// multiple write txs to block
	txMtx sync.Mutex
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
	db, err := badger.Open(*b.opt)
	if err != nil {
		return xerr(err)
	}
	b.db = db
	return nil
}

func (b *badgerDB) Close(_ context.Context) error {
	return xerr(b.db.Close())
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
		return xerr(err)
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
		return nil, xerr(err)
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
		return xerr(err)
	}
	return nil
}

func (b *badgerDB) Begin(_ context.Context, write bool) (Transaction, error) {
	if write {
		b.txMtx.Lock()
	}
	tx := b.db.NewTransaction(write)
	return &badgerTX{
		db:    b,
		tx:    tx,
		write: write,
	}, nil
}

func (b *badgerDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
	tx, err := b.Begin(ctx, write)
	if err != nil {
		return xerr(err)
	}
	err = callback(ctx, tx)
	if err != nil {
		if cerr := tx.Rollback(ctx); cerr != nil {
			return fmt.Errorf("rollback %w: %w", cerr, err)
		}
		return xerr(err)
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
	opts.Prefix = NewCompositeKey(table, nil)
	it := tx.NewIterator(opts)
	it.Rewind()

	// Reverse iterate to get the last item.
	// Since iterators use a snapshot from their creation,
	// the value should always remain the same.
	opts.Reverse = true
	revIt := tx.NewIterator(opts)
	defer revIt.Close()

	revIt.Seek(NewCompositeKey(table, []byte{0xff}))
	if !revIt.ValidForPrefix(opts.Prefix) {
		it.Close()
		tx.Discard()
		return nil, errors.New("empty iterator")
	}

	it.Seek(revIt.Item().KeyCopy(nil))
	if !it.ValidForPrefix(opts.Prefix) {
		it.Close()
		tx.Discard()
		return nil, errors.New("empty iterator")
	}
	lastKey := revIt.Item().KeyCopy(nil)

	return &badgerIterator{
		table:   table,
		tx:      tx,
		it:      it,
		lastKey: lastKey,
	}, nil
}

func (b *badgerDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	tx := b.db.NewTransaction(false)

	opts := badger.DefaultIteratorOptions
	opts.Prefix = NewCompositeKey(table, nil)
	it := tx.NewIterator(opts)
	it.Rewind()

	// Reverse iterate to get the last item.
	// Since iterators use a snapshot from their creation,
	// the value should always remain the same.
	opts.Reverse = true
	revIt := tx.NewIterator(opts)
	defer revIt.Close()

	// XXX this is terrible, fix this
	endKey := NewCompositeKey(table, end)
	revIt.Seek(endKey)
	if !revIt.ValidForPrefix(opts.Prefix) {
		it.Close()
		tx.Discard()
		return nil, errors.New("empty range")
	}
	if bytes.Compare(revIt.Item().Key(), endKey) >= 0 {
		revIt.Next()
		if !revIt.ValidForPrefix(opts.Prefix) {
			it.Close()
			tx.Discard()
			return nil, errors.New("empty range")
		}
	}

	lastKey := revIt.Item().KeyCopy(nil)
	return &badgerRange{
		tx:      tx,
		it:      it,
		table:   table,
		prefix:  opts.Prefix,
		start:   NewCompositeKey(table, start),
		lastKey: lastKey,
	}, nil
}

func (b *badgerDB) NewBatch(ctx context.Context) (Batch, error) {
	return &badgerBatch{wb: new(list.List)}, nil
}

// Transactions

type badgerTX struct {
	db    *badgerDB
	tx    *badger.Txn
	write bool
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
	return err == nil, err
}

func (tx *badgerTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	item, err := tx.tx.Get(NewCompositeKey(table, key))
	if err != nil {
		return nil, xerr(err)
	}
	val, err := item.ValueCopy(nil)
	if err != nil {
		return nil, xerr(err)
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
	if tx.write {
		defer tx.db.txMtx.Unlock()
	}
	return xerr(tx.tx.Commit())
}

func (tx *badgerTX) Rollback(ctx context.Context) error {
	if tx.write {
		defer tx.db.txMtx.Unlock()
	}
	tx.tx.Discard()
	return nil
}

func (tx *badgerTX) Write(ctx context.Context, b Batch) error {
	bb, ok := b.(*badgerBatch)
	if !ok {
		return fmt.Errorf("unexpected batch type: %T", b)
	}
	for e := bb.wb.Front(); e != nil; e = e.Next() {
		f, ok := e.Value.(batchFunc)
		if !ok {
			return fmt.Errorf("unexpected batch element type %T", e.Value)
		}
		if err := f(ctx, tx); err != nil {
			return xerr(err)
		}
	}
	return nil
}

// Iterations
type badgerIterator struct {
	lastKey []byte
	table   string

	tx    *badger.Txn
	it    *badger.Iterator
	first bool
}

func (ni *badgerIterator) First(_ context.Context) bool {
	ni.it.Rewind()
	return ni.it.Valid()
}

func (ni *badgerIterator) Last(ctx context.Context) bool {
	ni.it.Seek(ni.lastKey)
	return ni.it.Valid()
}

func (ni *badgerIterator) Next(ctx context.Context) bool {
	if !ni.first {
		ni.first = true
		return ni.First(ctx)
	}
	ni.it.Next()
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
	ni.tx.Discard()
}

// Ranges
type badgerRange struct {
	tx    *badger.Txn
	it    *badger.Iterator
	table string

	prefix  []byte
	start   []byte
	lastKey []byte

	first bool
}

func (nr *badgerRange) First(_ context.Context) bool {
	nr.it.Seek(nr.start)
	if bytes.Compare(nr.it.Item().Key(), nr.lastKey) > 0 {
		return false
	}
	return nr.it.ValidForPrefix(nr.prefix)
}

func (nr *badgerRange) Last(_ context.Context) bool {
	nr.it.Seek(nr.lastKey)
	if bytes.Compare(nr.it.Item().Key(), nr.lastKey) > 0 {
		return false
	}
	return nr.it.ValidForPrefix(nr.prefix)
}

func (nr *badgerRange) Next(ctx context.Context) bool {
	if !nr.first {
		nr.first = true
		return nr.First(ctx)
	}
	nr.it.Next()
	if bytes.Compare(nr.it.Item().Key(), nr.lastKey) > 0 {
		return false
	}
	return nr.it.ValidForPrefix(nr.prefix)
}

func (nr *badgerRange) Key(ctx context.Context) []byte {
	key := nr.it.Item().KeyCopy(nil)
	belowLimit := bytes.Compare(key, nr.lastKey) <= 0
	valid := nr.it.ValidForPrefix(nr.prefix)
	if belowLimit && valid {
		return KeyFromComposite(nr.table, key)
	}
	return nil
}

func (nr *badgerRange) Value(ctx context.Context) []byte {
	val, err := nr.it.Item().ValueCopy(nil)
	if err != nil {
		log.Errorf("get value: %v", err)
		return nil
	}
	return val
}

func (nr *badgerRange) Close(ctx context.Context) {
	nr.it.Close()
	nr.tx.Discard()
}

// Batches

type badgerBatch struct {
	wb *list.List // elements of type batchFunc
}

func (nb *badgerBatch) Del(ctx context.Context, table string, key []byte) {
	var act batchFunc = func(ctx context.Context, tx Transaction) error {
		return tx.Del(ctx, table, key)
	}
	nb.wb.PushBack(act)
}

func (nb *badgerBatch) Put(ctx context.Context, table string, key, value []byte) {
	var act batchFunc = func(ctx context.Context, tx Transaction) error {
		return tx.Put(ctx, table, key, value)
	}
	nb.wb.PushBack(act)
}

func (nb *badgerBatch) Reset(ctx context.Context) {
	nb.wb.Init()
}
