// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tidwall/buntdb"
)

// Assert required interfaces
var (
	_ Batch       = (*buntBatch)(nil)
	_ Database    = (*buntDB)(nil)
	_ Iterator    = (*buntIterator)(nil)
	_ Range       = (*buntIterator)(nil)
	_ Transaction = (*buntTX)(nil)
)

type BuntConfig struct {
	Home   string
	Tables []string
}

func DefaultBuntConfig(home string, tables []string) *BuntConfig {
	return &BuntConfig{
		Home:   home,
		Tables: tables,
	}
}

type buntDB struct {
	db *buntdb.DB

	tables map[string]struct{}

	cfg *BuntConfig

	// buntdb doesn't care if you try to re-open
	// an already open db file
	mtx  sync.Mutex
	open bool
}

func NewBuntDB(cfg *BuntConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &buntDB{
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

func (b *buntDB) Open(_ context.Context) error {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	if b.open {
		return ErrDBOpen
	}

	dbfile := filepath.Join(b.cfg.Home, "bunt.db")
	bdb, err := buntdb.Open(dbfile)
	if err != nil {
		return err
	}
	b.db = bdb
	b.open = true
	return nil
}

func (b *buntDB) Close(_ context.Context) error {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	if !b.open {
		return ErrDBClosed
	}

	if err := xerr(b.db.Close()); err != nil {
		return err
	}
	b.open = false
	return nil
}

func (b *buntDB) Del(pctx context.Context, table string, key []byte) error {
	return b.Update(pctx, func(ctx context.Context, tx Transaction) error {
		return tx.Del(ctx, table, key)
	})
}

func (b *buntDB) Has(pctx context.Context, table string, key []byte) (bool, error) {
	var has bool
	err := b.View(pctx, func(ctx context.Context, tx Transaction) error {
		ihas, innerErr := tx.Has(ctx, table, key)
		has = ihas
		return innerErr
	})
	return has, err
}

func (b *buntDB) Get(pctx context.Context, table string, key []byte) ([]byte, error) {
	var value []byte
	err := b.View(pctx, func(ctx context.Context, tx Transaction) error {
		val, innerErr := tx.Get(ctx, table, key)
		value = val
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return value, err
}

func (b *buntDB) Put(pctx context.Context, table string, key, value []byte) error {
	return b.Update(pctx, func(ctx context.Context, tx Transaction) error {
		return tx.Put(ctx, table, key, value)
	})
}

func (b *buntDB) Begin(_ context.Context, write bool) (Transaction, error) {
	tx, err := b.db.Begin(write)
	if err != nil {
		return nil, xerr(err)
	}
	return &buntTX{
		db: b,
		tx: tx,
	}, nil
}

func (b *buntDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
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
	if write {
		return tx.Commit(ctx)
	}
	return tx.Rollback(ctx)
}

func (b *buntDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return xerr(b.execute(ctx, false, callback))
}

func (b *buntDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return xerr(b.execute(ctx, true, callback))
}

func (b *buntDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	tx, err := b.Begin(ctx, false)
	if err != nil {
		return nil, err
	}

	btx, ok := tx.(*buntTX)
	if !ok {
		if err := tx.Rollback(ctx); err != nil {
			return nil, fmt.Errorf("close iterator: %w", err)
		}
		return nil, fmt.Errorf("unexpected TX type: %T", tx)
	}

	start, end := BytesPrefix(NewCompositeKey(table, nil))
	return &buntIterator{
		table: table,
		tx:    btx,
		start: string(start),
		end:   string(end),
	}, nil
}

func (b *buntDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	tx, err := b.Begin(ctx, false)
	if err != nil {
		return nil, err
	}

	btx, ok := tx.(*buntTX)
	if !ok {
		if err := tx.Rollback(ctx); err != nil {
			return nil, fmt.Errorf("close iterator: %w", err)
		}
		return nil, fmt.Errorf("unexpected TX type: %T", tx)
	}

	return &buntIterator{
		table: table,
		tx:    btx,
		start: string(NewCompositeKey(table, start)),
		end:   string(NewCompositeKey(table, end)),
	}, nil
}

func (b *buntDB) NewBatch(ctx context.Context) (Batch, error) {
	return &buntBatch{wb: new(list.List)}, nil
}

// Transactions

type buntTX struct {
	db *buntDB
	tx *buntdb.Tx
}

func (tx *buntTX) Del(ctx context.Context, table string, key []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	_, err := tx.tx.Delete(string(NewCompositeKey(table, key)))
	err = xerr(err)
	if errors.Is(err, ErrKeyNotFound) {
		return nil
	}
	return err
}

func (tx *buntTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	_, err := tx.Get(ctx, table, key)
	err = xerr(err)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (tx *buntTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	val, err := tx.tx.Get(string(NewCompositeKey(table, key)))
	if err != nil {
		return nil, xerr(err)
	}
	return []byte(val), nil
}

func (tx *buntTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	_, _, err := tx.tx.Set(string(NewCompositeKey(table, key)),
		string(value), nil)
	return xerr(err)
}

func (tx *buntTX) Commit(ctx context.Context) error {
	return xerr(tx.tx.Commit())
}

func (tx *buntTX) Rollback(ctx context.Context) error {
	return xerr(tx.tx.Rollback())
}

func (tx *buntTX) Write(ctx context.Context, b Batch) error {
	bb, ok := b.(*buntBatch)
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
type buntIterator struct {
	table string
	tx    *buntTX

	start string
	end   string

	cur   string
	first bool
}

func (bi *buntIterator) First(ctx context.Context) bool {
	pkey := KeyFromComposite(bi.table, []byte(bi.start))
	return bi.Seek(ctx, pkey)
}

func (bi *buntIterator) Last(_ context.Context) bool {
	bi.cur = ""
	err := bi.tx.tx.DescendRange("", bi.end, bi.start, func(key, value string) bool {
		if strings.Compare(key, bi.end) < 0 {
			bi.cur = key
			return false
		}
		return true
	})
	if err != nil {
		log.Errorf("%v", err)
		return false
	}
	return bi.cur != ""
}

func (bi *buntIterator) Next(ctx context.Context) bool {
	if !bi.first {
		bi.first = true
		return bi.First(ctx)
	}
	var next bool
	err := bi.tx.tx.AscendRange("", bi.cur, bi.end, func(key, value string) bool {
		if strings.Compare(key, bi.cur) > 0 {
			bi.cur = key
			next = true
			return false
		}
		return true
	})
	if err != nil {
		log.Errorf("%v", err)
		return false
	}
	if !next {
		bi.cur = ""
	}
	return bi.cur != ""
}

func (bi *buntIterator) Seek(_ context.Context, key []byte) bool {
	bi.first = true
	bi.cur = ""
	pkey := NewCompositeKey(bi.table, key)
	err := bi.tx.tx.AscendRange("", string(pkey), bi.end, func(k, value string) bool {
		bi.cur = k
		return false
	})
	if err != nil {
		log.Errorf("%v", err)
		return false
	}
	return bi.cur != ""
}

func (bi *buntIterator) Key(_ context.Context) []byte {
	return KeyFromComposite(bi.table, []byte(bi.cur))
}

func (bi *buntIterator) Value(ctx context.Context) []byte {
	key := KeyFromComposite(bi.table, []byte(bi.cur))
	val, err := bi.tx.Get(ctx, bi.table, key)
	if err != nil {
		log.Errorf("%v", err)
		return nil
	}
	return val
}

func (bi *buntIterator) Close(ctx context.Context) {
	if err := bi.tx.Rollback(ctx); err != nil {
		log.Errorf("%v", err)
	}
}

// Range

// Bunt Ranges are an instantiation of buntIterator using the
// NewRange constructor, rather than NewIterator.

// Batches

type buntBatch struct {
	wb *list.List // elements of type batchFunc
}

func (nb *buntBatch) Del(ctx context.Context, table string, key []byte) {
	var act batchFunc = func(ctx context.Context, tx Transaction) error {
		return tx.Del(ctx, table, key)
	}
	nb.wb.PushBack(act)
}

func (nb *buntBatch) Put(ctx context.Context, table string, key, value []byte) {
	var act batchFunc = func(ctx context.Context, tx Transaction) error {
		return tx.Put(ctx, table, key, value)
	}
	nb.wb.PushBack(act)
}

func (nb *buntBatch) Reset(ctx context.Context) {
	nb.wb.Init()
}
