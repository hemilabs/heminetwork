package gkvdb

import (
	"context"
	"errors"
	"fmt"

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
		return nil // XXX return already open?
	}
	ldb, err := leveldb.OpenFile(b.cfg.Home, &opt.Options{
		BlockCacheEvictRemoved: true,
		Compression:            opt.NoCompression,
	})
	if err != nil {
		return err
	}
	b.db = ldb
	return nil
}

func (b *levelDB) Close(_ context.Context) error {
	return b.db.Close()
}

func (b *levelDB) Del(_ context.Context, table string, key []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return b.db.Delete(NewCompositeKey(table, key), nil)
}

func (b *levelDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	if _, ok := b.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	return b.db.Has(NewCompositeKey(table, key), nil)
}

func (b *levelDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	value, err := b.db.Get(NewCompositeKey(table, key), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

func (b *levelDB) Put(_ context.Context, table string, key, value []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return b.db.Put(NewCompositeKey(table, key), value, nil)
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
			return fmt.Errorf("rollback %v: %w", cerr, err)
		}
		return err
	}
	return tx.Commit(ctx)
}

func (b *levelDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, false, callback)
}

func (b *levelDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, true, callback)
}

func (b *levelDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	return &levelIterator{
		table: table,
		it:    b.db.NewIterator(&util.Range{}, nil),
	}, nil
}

func (b *levelDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	return nil, fmt.Errorf("not yet")
}

func (b *levelDB) NewBatch(ctx context.Context) (Batch, error) {
	return &levelBatch{wb: new(leveldb.Batch)}, nil
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
	return tx.tx.Write(b.(*levelBatch).wb, nil)
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

func (ni *levelIterator) Close(ctx context.Context) error {
	ni.it.Release()
	return nil
}

// Ranges
type levelRange struct {
	table string
	tx    Transaction
	start []byte
	end   []byte

	keys   [][]byte
	cursor int // Current key
}

func (nr *levelRange) First(_ context.Context) bool {
	if len(nr.keys) == 0 {
		return false
	}
	nr.cursor = 0
	return true
}

func (nr *levelRange) Last(_ context.Context) bool {
	if len(nr.keys) == 0 {
		return false
	}
	nr.cursor = len(nr.keys) - 1
	return true
}

func (nr *levelRange) Next(_ context.Context) bool {
	if len(nr.keys) == 0 {
		return false
	}
	if nr.cursor < len(nr.keys)-1 {
		nr.cursor++
		return true
	}
	return false
}

func (nr *levelRange) Key(ctx context.Context) []byte {
	return nr.keys[nr.cursor]
}

func (nr *levelRange) Value(ctx context.Context) []byte {
	value, err := nr.tx.Get(ctx, nr.table, nr.keys[nr.cursor])
	if err != nil {
		// meh, this should not happen
		log.Errorf("value %v", err)
		return nil
	}
	return value
}

func (nr *levelRange) Close(ctx context.Context) error {
	return nr.tx.Commit(ctx)
}

// Batches

type levelBatch struct {
	wb *leveldb.Batch
}

func (nb *levelBatch) Del(ctx context.Context, table string, key []byte) {
	nb.wb.Delete(NewCompositeKey(table, key))
}

func (nb *levelBatch) Put(ctx context.Context, table string, key, value []byte) {
	nb.wb.Put(NewCompositeKey(table, key), value)
}

func (nb *levelBatch) Reset(ctx context.Context) {
	nb.wb.Reset()
}
