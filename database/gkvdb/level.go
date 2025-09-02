// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Assert required interfaces
var (
	_ Batch       = (*levelBatch)(nil)
	_ Database    = (*levelDB)(nil)
	_ Iterator    = (*levelIterator)(nil)
	_ Range       = (*levelRange)(nil)
	_ Transaction = (*levelTX)(nil)
)

type LevelConfig struct {
	Home   string
	Tables []string
}

func DefaultLevelConfig(home string, tables []string) *LevelConfig {
	return &LevelConfig{
		Home:   home,
		Tables: tables,
	}
}

type levelDB struct {
	db *leveldb.DB

	tables map[string]struct{}

	cfg *LevelConfig
}

func NewLevelDB(cfg *LevelConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &levelDB{
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

func (b *levelDB) Open(_ context.Context) error {
	if b.db != nil {
		return ErrDBOpen
	}
	ldb, err := leveldb.OpenFile(b.cfg.Home, &opt.Options{
		BlockCacheEvictRemoved: true,
		Compression:            opt.NoCompression,
	})
	if err != nil {
		return xerr(err)
	}
	b.db = ldb
	return nil
}

func (b *levelDB) Close(_ context.Context) error {
	return xerr(b.db.Close())
}

func (b *levelDB) Del(_ context.Context, table string, key []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(b.db.Delete(NewCompositeKey(table, key), nil))
}

func (b *levelDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	if _, ok := b.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	has, err := b.db.Has(NewCompositeKey(table, key), nil)
	return has, xerr(err)
}

func (b *levelDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	value, err := b.db.Get(NewCompositeKey(table, key), nil)
	if err != nil {
		return nil, xerr(err)
	}
	return value, nil
}

func (b *levelDB) Put(_ context.Context, table string, key, value []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(b.db.Put(NewCompositeKey(table, key), value, nil))
}

func (b *levelDB) Begin(_ context.Context, write bool) (Transaction, error) {
	tx, err := b.db.OpenTransaction()
	if err != nil {
		return nil, xerr(err)
	}
	return &levelTX{
		db: b,
		tx: tx,
	}, nil
}

func (b *levelDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
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

func (b *levelDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return xerr(b.execute(ctx, false, callback))
}

func (b *levelDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return xerr(b.execute(ctx, true, callback))
}

func (b *levelDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	r := util.BytesPrefix(NewCompositeKey(table, []byte{}))
	return &levelIterator{
		table: table,
		it:    b.db.NewIterator(r, nil),
	}, nil
}

func (b *levelDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	return &levelRange{
		table: table,
		it: b.db.NewIterator(&util.Range{
			Start: NewCompositeKey(table, start),
			Limit: NewCompositeKey(table, end),
		}, nil),
		start: start,
		end:   end,
	}, nil
}

func (b *levelDB) NewBatch(ctx context.Context) (Batch, error) {
	return &levelBatch{db: b, wb: new(leveldb.Batch)}, nil
}

func (b *levelDB) DumpTables(ctx context.Context, tables []string, target Encoder) error {
	log.Infof("dude, make these tables read only")

	for _, table := range tables {
		it, err := b.NewIterator(ctx, table)
		if err != nil {
			return err
		}
		for it.Next(ctx) {
			op := Operation{
				Op:    OpPut,
				Table: table,
				Key:   it.Key(ctx),
				Value: it.Value(ctx),
			}
			err := target.Encode(op)
			if err != nil {
				it.Close(ctx)
				return err
			}
		}
		it.Close(ctx)
	}

	return nil
}

func (b *levelDB) Restore(ctx context.Context, source Decoder) error {
	batch, err := b.NewBatch(ctx)
	if err != nil {
		return err
	}

	for {
		var op Operation
		err := source.Decode(&op)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		switch op.Op {
		case OpPut:
			batch.Put(ctx, op.Table, op.Key, op.Value)
		case OpDel:
			batch.Del(ctx, op.Table, op.Key)
		}
	}
	err = b.Update(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Write(ctx, batch)
	})
	if err != nil {
		return err
	}

	return nil
}

// Transactions

type levelTX struct {
	db *levelDB
	tx *leveldb.Transaction
}

func (tx *levelTX) Del(ctx context.Context, table string, key []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Delete(NewCompositeKey(table, key), nil))
}

func (tx *levelTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	has, err := tx.tx.Has(NewCompositeKey(table, key), nil)
	return has, xerr(err)
}

func (tx *levelTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	value, err := tx.tx.Get(NewCompositeKey(table, key), nil)
	return value, xerr(err)
}

func (tx *levelTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Put(NewCompositeKey(table, key), value, nil))
}

func (tx *levelTX) Commit(ctx context.Context) error {
	return xerr(tx.tx.Commit())
}

func (tx *levelTX) Rollback(ctx context.Context) error {
	tx.tx.Discard()
	return nil
}

func (tx *levelTX) Write(ctx context.Context, b Batch) error {
	return xerr(tx.tx.Write(b.(*levelBatch).wb, nil))
}

// Iterations
type levelIterator struct {
	table string
	it    iterator.Iterator
}

func (ni *levelIterator) First(_ context.Context) bool {
	return ni.it.First()
}

func (ni *levelIterator) Last(_ context.Context) bool {
	return ni.it.Last()
}

func (ni *levelIterator) Next(_ context.Context) bool {
	return ni.it.Next()
}

func (ni *levelIterator) Seek(_ context.Context, key []byte) bool {
	return ni.it.Seek(NewCompositeKey(ni.table, key))
}

func (ni *levelIterator) Key(_ context.Context) []byte {
	return KeyFromComposite(ni.table, ni.it.Key())
}

func (ni *levelIterator) Value(_ context.Context) []byte {
	return ni.it.Value()
}

func (ni *levelIterator) Close(ctx context.Context) {
	ni.it.Release()
}

// Ranges
type levelRange struct {
	table string
	it    iterator.Iterator
	start []byte
	end   []byte
}

func (nr *levelRange) First(_ context.Context) bool {
	return nr.it.First()
}

func (nr *levelRange) Last(_ context.Context) bool {
	return nr.it.Last()
}

func (nr *levelRange) Next(_ context.Context) bool {
	return nr.it.Next()
}

func (nr *levelRange) Key(ctx context.Context) []byte {
	return KeyFromComposite(nr.table, nr.it.Key())
}

func (nr *levelRange) Value(ctx context.Context) []byte {
	return nr.it.Value()
}

func (nr *levelRange) Close(ctx context.Context) {
	nr.it.Release()
}

// Batches

type levelBatch struct {
	db *levelDB
	wb *leveldb.Batch
}

func (nb *levelBatch) Del(ctx context.Context, table string, key []byte) {
	if _, ok := nb.db.tables[table]; !ok {
		log.Errorf("%s: %v", table, ErrTableNotFound)
		return
	}
	nb.wb.Delete(NewCompositeKey(table, key))
}

func (nb *levelBatch) Put(ctx context.Context, table string, key, value []byte) {
	if _, ok := nb.db.tables[table]; !ok {
		log.Errorf("%s: %v", table, ErrTableNotFound)
		return
	}
	nb.wb.Put(NewCompositeKey(table, key), value)
}

func (nb *levelBatch) Reset(ctx context.Context) {
	nb.wb.Reset()
}
