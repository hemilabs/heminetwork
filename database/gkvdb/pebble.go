// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/cockroachdb/pebble"
)

// Assert required interfaces
var (
	_ Batch       = (*pebbleBatch)(nil)
	_ Database    = (*pebbleDB)(nil)
	_ Iterator    = (*pebbleIterator)(nil)
	_ Range       = (*pebbleRange)(nil)
	_ Transaction = (*pebbleTX)(nil)
)

type PebbleConfig struct {
	Home   string
	Tables []string
}

func DefaultPebbleConfig(home string, tables []string) *PebbleConfig {
	return &PebbleConfig{
		Home:   home,
		Tables: tables,
	}
}

type pebbleDB struct {
	db *pebble.DB

	tables map[string]struct{}

	cfg *PebbleConfig
}

func NewPebbleDB(cfg *PebbleConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &pebbleDB{
		cfg:    cfg,
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

func (b *pebbleDB) Open(_ context.Context) error {
	if b.db != nil {
		return ErrDBOpen
	}
	ldb, err := pebble.Open(b.cfg.Home, &pebble.Options{
		Levels: []pebble.LevelOptions{
			{Compression: pebble.NoCompression},
		},
	})
	if err != nil {
		return err
	}
	b.db = ldb
	return nil
}

func (b *pebbleDB) Close(_ context.Context) error {
	return b.db.Close()
}

func (b *pebbleDB) Del(_ context.Context, table string, key []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return b.db.Delete(NewCompositeKey(table, key), nil)
}

func (b *pebbleDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := b.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	_, err := b.Get(ctx, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (b *pebbleDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	value, closer, err := b.db.Get(NewCompositeKey(table, key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	defer func() {
		err = closer.Close()
		if err != nil {
			log.Errorf("close closer: %v", err)
		}
	}()
	v := make([]byte, len(value))
	copy(v, value)
	return v, nil
}

func (b *pebbleDB) Put(_ context.Context, table string, key, value []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return b.db.Set(NewCompositeKey(table, key), value, nil)
}

// / XXX Since pebbleDB doesn't have transactions, we must use batches to
// emulate the behavior. However, having reads in a pebble batch is MORE
// expensive than write only, so we should reconsider using
// NewIndexedBatch (read/write) and use NewBatch (write only).
func (b *pebbleDB) Begin(_ context.Context, write bool) (Transaction, error) {
	tx := b.db.NewIndexedBatch()
	return &pebbleTX{
		db: b,
		tx: tx,
	}, nil
}

func (b *pebbleDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
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

func (b *pebbleDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, false, callback)
}

func (b *pebbleDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, true, callback)
}

func (b *pebbleDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	iter, err := b.db.NewIterWithContext(ctx, nil)
	if err != nil {
		return nil, err
	}

	// set iterator to before first value
	iter.SeekLT([]byte{})

	return &pebbleIterator{
		table: table,
		it:    iter,
	}, nil
}

func (b *pebbleDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	iter, err := b.db.NewIterWithContext(ctx, &pebble.IterOptions{
		LowerBound: NewCompositeKey(table, start),
		UpperBound: NewCompositeKey(table, end),
	})
	if err != nil {
		return nil, err
	}

	// set iterator to before first value
	iter.SeekLT([]byte{})

	return &pebbleRange{
		table: table,
		it:    iter,
		start: start,
		end:   end,
	}, nil
}

func (b *pebbleDB) NewBatch(ctx context.Context) (Batch, error) {
	return &pebbleBatch{db: b, wb: b.db.NewBatch()}, nil
}

func (b *pebbleDB) DumpTable(ctx context.Context, table string, target io.Writer) error {
	return ErrNotSuported
}

func (b *pebbleDB) RestoreTable(ctx context.Context, table string, source io.Reader) error {
	return ErrNotSuported
}

// Transactions

// PebbleDB doesn't have transactions, so emulate behavior
// Using batches.
type pebbleTX struct {
	db *pebbleDB
	tx *pebble.Batch
}

func (tx *pebbleTX) Del(ctx context.Context, table string, key []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Delete(NewCompositeKey(table, key), nil))
}

func (tx *pebbleTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	_, err := tx.Get(ctx, table, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, xerr(err)
}

func (tx *pebbleTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	val, closer, err := tx.tx.Get(NewCompositeKey(table, key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	defer func() {
		err = closer.Close() // XXX check for nil?
		if err != nil {
			log.Errorf("close closer: %v", err)
		}
	}()
	// pebbleDB unfortunately invalidates value outside of the batch
	value := make([]byte, len(val))
	copy(value, val)
	return value, nil
}

func (tx *pebbleTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Set(NewCompositeKey(table, key), value, nil))
}

func (tx *pebbleTX) Commit(ctx context.Context) error {
	return xerr(tx.tx.Commit(nil))
}

func (tx *pebbleTX) Rollback(ctx context.Context) error {
	tx.tx.Close()
	return nil
}

func (tx *pebbleTX) Write(ctx context.Context, b Batch) error {
	return tx.tx.Apply(b.(*pebbleBatch).wb, nil)
}

// Iterations
type pebbleIterator struct {
	table string
	it    *pebble.Iterator
}

// This has to be called prior to iterating
func (ni *pebbleIterator) First(_ context.Context) bool {
	return ni.it.First()
}

func (ni *pebbleIterator) Last(_ context.Context) bool {
	return ni.it.Last()
}

func (ni *pebbleIterator) Next(_ context.Context) bool {
	return ni.it.Next()
}

func (ni *pebbleIterator) Seek(_ context.Context, key []byte) bool {
	return ni.it.SeekGE(NewCompositeKey(ni.table, key))
}

func (ni *pebbleIterator) Key(_ context.Context) []byte {
	return KeyFromComposite(ni.table, ni.it.Key())
}

func (ni *pebbleIterator) Value(_ context.Context) []byte {
	return ni.it.Value()
}

func (ni *pebbleIterator) Close(ctx context.Context) {
	if err := ni.it.Close(); err != nil {
		log.Errorf("iterator close: %v", err)
	}
}

// Ranges
type pebbleRange struct {
	table string
	it    *pebble.Iterator
	start []byte
	end   []byte
}

func (nr *pebbleRange) First(_ context.Context) bool {
	return nr.it.First()
}

func (nr *pebbleRange) Last(_ context.Context) bool {
	return nr.it.Last()
}

func (nr *pebbleRange) Next(_ context.Context) bool {
	return nr.it.Next()
}

func (nr *pebbleRange) Key(ctx context.Context) []byte {
	return KeyFromComposite(nr.table, nr.it.Key())
}

func (nr *pebbleRange) Value(ctx context.Context) []byte {
	return nr.it.Value()
}

func (nr *pebbleRange) Close(ctx context.Context) {
	if err := nr.it.Close(); err != nil {
		log.Errorf("range close: %v", err)
	}
}

// Batches

type pebbleBatch struct {
	db *pebbleDB
	wb *pebble.Batch
}

func (nb *pebbleBatch) Del(ctx context.Context, table string, key []byte) {
	if _, ok := nb.db.tables[table]; !ok {
		log.Errorf("%s: %v", table, ErrTableNotFound)
		return
	}
	if err := nb.wb.Delete(NewCompositeKey(table, key), nil); err != nil {
		log.Errorf("delete %v: %v", table, key)
	}
}

func (nb *pebbleBatch) Put(ctx context.Context, table string, key, value []byte) {
	if _, ok := nb.db.tables[table]; !ok {
		log.Errorf("%s: %v", table, ErrTableNotFound)
		return
	}
	if err := nb.wb.Set(NewCompositeKey(table, key), value, nil); err != nil {
		log.Errorf("set %v: %v %v", table, key, value)
	}
}

func (nb *pebbleBatch) Reset(ctx context.Context) {
	nb.wb.Reset()
}
