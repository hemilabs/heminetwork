// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"go.mills.io/bitcask/v2"
)

// Assert required interfaces
var (
	_ Batch       = (*bitcaskBatch)(nil)
	_ Database    = (*bitcaskDB)(nil)
	_ Iterator    = (*bitcaskIterator)(nil)
	_ Range       = (*bitcaskRange)(nil)
	_ Transaction = (*bitcaskTX)(nil)
)

type BitcaskConfig struct {
	Home   string
	Tables []string
}

func DefaultBitcaskConfig(home string, tables []string) *BitcaskConfig {
	return &BitcaskConfig{
		Home:   home,
		Tables: tables,
	}
}

type bitcaskDB struct {
	db *bitcask.Bitcask

	tables map[string]struct{}

	cfg *BitcaskConfig

	// kinda sucks but we must force
	// multiple write txs to block
	txMtx sync.Mutex
}

func NewBitcaskDB(cfg *BitcaskConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &bitcaskDB{
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

func (b *bitcaskDB) Open(_ context.Context) error {
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
	return xerr(b.db.Close())
}

// Utility

func (b *bitcaskDB) k2b(table string, key []byte) bitcask.Key {
	return bitcask.Key(NewCompositeKey(table, key))
}

func (b *bitcaskDB) Del(_ context.Context, table string, key []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return b.db.Delete(b.k2b(table, key))
}

func (b *bitcaskDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	if _, ok := b.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	return b.db.Has(b.k2b(table, key)), nil
}

func (b *bitcaskDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	value, err := b.db.Get(b.k2b(table, key))
	if err != nil {
		if errors.Is(err, bitcask.ErrKeyNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

func (b *bitcaskDB) Put(_ context.Context, table string, key, value []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return b.db.Put(b.k2b(table, key), value)
}

func (b *bitcaskDB) Begin(_ context.Context, write bool) (Transaction, error) {
	if write {
		b.txMtx.Lock()
	}
	tx := b.db.Transaction()
	return &bitcaskTX{
		db:    b,
		tx:    tx,
		write: write,
	}, nil
}

func (b *bitcaskDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
	tx, err := b.Begin(ctx, write)
	if err != nil {
		return err
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

func (b *bitcaskDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return xerr(b.execute(ctx, false, callback))
}

func (b *bitcaskDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return xerr(b.execute(ctx, true, callback))
}

func (b *bitcaskDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}

	it := b.db.Iterator()

	// Reverse iterate to get the last item.
	// Since iterators use a snapshot from their creation,
	// the value should always remain the same.
	revIt := b.db.Iterator(bitcask.Reverse())
	defer revIt.Close()

	item, err := revIt.SeekPrefix(b.k2b(table, nil))
	if err != nil || !bytes.HasPrefix(item.Key(), NewCompositeKey(table, nil)) {
		return nil, fmt.Errorf("empty iterator")
	}
	lastKey := item.Key()

	return &bitcaskIterator{
		lastKey: lastKey,
		table:   table,
		db:      b,
		it:      it,
	}, nil
}

func (b *bitcaskDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}

	it := b.db.Iterator()

	// Reverse iterate to get the last item.
	// Since iterators use a snapshot from their creation,
	// the value should always remain the same.
	revIt := b.db.Iterator(bitcask.Reverse())
	defer revIt.Close()

	endKey := NewCompositeKey(table, end)
	startKey := NewCompositeKey(table, start)
	item, err := revIt.SeekPrefix(b.k2b(table, nil))
	if err != nil {
		return nil, fmt.Errorf("empty range")
	}
	for bytes.Compare(item.Key(), endKey) >= 0 {
		item, err = revIt.Next()
		if err != nil || bytes.Compare(item.Key(), startKey) < 0 {
			return nil, fmt.Errorf("no last key: %w", err)
		}
	}
	lastKey := item.Key()

	return &bitcaskRange{
		start:   NewCompositeKey(table, start),
		lastKey: lastKey,
		table:   table,
		db:      b,
		it:      it,
	}, nil
}

func (b *bitcaskDB) NewBatch(ctx context.Context) (Batch, error) {
	return &bitcaskBatch{db: b, wb: b.db.Batch()}, nil
}

// Transactions

type bitcaskTX struct {
	db    *bitcaskDB
	tx    *bitcask.Txn
	write bool
}

func (tx *bitcaskTX) Del(ctx context.Context, table string, key []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Delete(tx.db.k2b(table, key)))
}

func (tx *bitcaskTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	has := tx.tx.Has(tx.db.k2b(table, key))
	return has, nil
}

func (tx *bitcaskTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	value, err := tx.tx.Get(tx.db.k2b(table, key))
	return value, xerr(err)
}

func (tx *bitcaskTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Put(tx.db.k2b(table, key), value))
}

func (tx *bitcaskTX) Commit(ctx context.Context) error {
	if tx.write {
		defer tx.db.txMtx.Unlock()
	}
	return xerr(tx.tx.Commit())
}

func (tx *bitcaskTX) Rollback(ctx context.Context) error {
	if tx.write {
		defer tx.db.txMtx.Unlock()
	}
	tx.tx.Discard()
	return nil
}

func (tx *bitcaskTX) Write(ctx context.Context, b Batch) error {
	bb, ok := b.(*bitcaskBatch)
	if !ok {
		return fmt.Errorf("unexpected batch type: %T", b)
	}
	// No need to validate if table is valid since that is
	// already done in the batch put / del methods
	for _, entry := range bb.wb.Entries() {
		// put
		if entry.Value != nil {
			if err := tx.tx.Put(entry.Key, entry.Value); err != nil {
				return xerr(err)
			}
			continue
		}
		// del
		if err := tx.tx.Delete(entry.Key); err != nil {
			return xerr(err)
		}
	}
	return nil
}

// Iterations

type bitcaskIterator struct {
	table string
	db    *bitcaskDB
	it    *bitcask.Iterator

	lastKey []byte
	cur     *bitcask.Item

	first bool
}

func (bi *bitcaskIterator) resetIterator(prefix bitcask.Key) (*bitcask.Item, error) {
	bi.it.Close()
	it := bi.db.db.Iterator()
	item, err := it.SeekPrefix(prefix)
	if err != nil {
		return nil, err
	}
	bi.it = it
	return item, nil
}

func (bi *bitcaskIterator) First(_ context.Context) bool {
	var err error
	bi.cur, err = bi.resetIterator(bi.db.k2b(bi.table, nil))
	return err == nil
}

func (bi *bitcaskIterator) Last(ctx context.Context) bool {
	var err error
	bi.cur, err = bi.resetIterator(bi.lastKey)
	return err == nil
}

func (bi *bitcaskIterator) Next(ctx context.Context) bool {
	if !bi.first {
		bi.first = true
		return bi.First(ctx)
	}
	var err error
	bi.cur, err = bi.it.Next()
	return err == nil
}

func (bi *bitcaskIterator) Seek(ctx context.Context, key []byte) bool {
	bi.first = true
	var err error
	if bytes.Compare(bi.Key(ctx), key) > 0 {
		bi.cur, err = bi.resetIterator(bi.db.k2b(bi.table, nil))
		if err != nil {
			return false
		}
	}
	for bytes.Compare(bi.Key(ctx), key) < 0 {
		bi.cur, err = bi.it.Next()
		if err != nil {
			return false
		}
	}
	return true
}

func (bi *bitcaskIterator) Key(_ context.Context) []byte {
	if bi.cur != nil && bi.cur.Key() != nil {
		return KeyFromComposite(bi.table, bi.cur.Key())
	}
	return nil
}

func (bi *bitcaskIterator) Value(_ context.Context) []byte {
	if bi.cur != nil {
		return bi.cur.Value()
	}
	return nil
}

func (bi *bitcaskIterator) Close(ctx context.Context) {
	bi.it.Close() // ignore error, it's a noop
}

// Range

type bitcaskRange struct {
	table string
	db    *bitcaskDB
	it    *bitcask.Iterator

	start   []byte
	lastKey []byte
	cur     *bitcask.Item

	first bool
}

func (br *bitcaskRange) resetIterator(prefix bitcask.Key) (*bitcask.Item, error) {
	br.it.Close()
	it := br.db.db.Iterator()
	item, err := it.SeekPrefix(prefix)
	if err != nil {
		return nil, err
	}
	br.it = it
	return item, nil
}

func (br *bitcaskRange) First(ctx context.Context) bool {
	var err error
	br.cur, err = br.resetIterator(br.db.k2b(br.table, nil))
	if err != nil {
		return false
	}
	for bytes.Compare(br.cur.Key(), br.start) < 0 {
		br.cur, err = br.it.Next()
		if err != nil || bytes.Compare(br.cur.Key(), br.lastKey) > 0 {
			return false
		}
	}
	return true
}

func (br *bitcaskRange) Last(ctx context.Context) bool {
	var err error
	br.cur, err = br.resetIterator(br.lastKey)
	return err == nil
}

func (br *bitcaskRange) Next(ctx context.Context) bool {
	if !br.first {
		br.first = true
		return br.First(ctx)
	}
	var err error
	br.cur, err = br.it.Next()
	if err != nil || bytes.Compare(br.cur.Key(), br.lastKey) > 0 {
		return false
	}
	return true
}

func (br *bitcaskRange) Key(_ context.Context) []byte {
	if br.cur != nil && br.cur.Key() != nil {
		return KeyFromComposite(br.table, br.cur.Key())
	}
	return nil
}

func (br *bitcaskRange) Value(_ context.Context) []byte {
	if br.cur != nil {
		return br.cur.Value()
	}
	return nil
}

func (br *bitcaskRange) Close(ctx context.Context) {
	br.it.Close() // ignore error, it's a noop
}

// Batches

type bitcaskBatch struct {
	db *bitcaskDB
	wb *bitcask.Batch
}

func (nb *bitcaskBatch) Del(ctx context.Context, table string, key []byte) {
	if _, ok := nb.db.tables[table]; !ok {
		log.Errorf("%s: %v", table, ErrTableNotFound)
		return
	}
	if _, err := nb.wb.Delete(nb.db.k2b(table, key)); err != nil {
		log.Errorf("batch delele: %v", err)
	}
}

func (nb *bitcaskBatch) Put(ctx context.Context, table string, key, value []byte) {
	if _, ok := nb.db.tables[table]; !ok {
		log.Errorf("%s: %v", table, ErrTableNotFound)
		return
	}
	if _, err := nb.wb.Put(nb.db.k2b(table, key), value); err != nil {
		log.Errorf("batch put: %v", err)
	}
}

func (nb *bitcaskBatch) Reset(ctx context.Context) {
	nb.wb.Clear()
}
