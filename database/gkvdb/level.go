package gkvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var _ Database = (*levelDB)(nil)

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
	if key == nil {
		return ErrInvalidKey
	}
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	return b.db.Delete(NewCompositeKey(table, key), nil)
}

func (b *levelDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	if key == nil {
		return false, ErrInvalidKey
	}
	if _, ok := b.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	return b.db.Has(NewCompositeKey(table, key), nil)
}

func (b *levelDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}
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
	if key == nil {
		return ErrInvalidKey
	}
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

func (b *levelDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return fmt.Errorf("not yet")
}

func (b *levelDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return fmt.Errorf("not yet")
}

func (b *levelDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	return nil, fmt.Errorf("not yet")
}

func (b *levelDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	return nil, fmt.Errorf("not yet")
}

func (b *levelDB) NewBatch(ctx context.Context) (Batch, error) {
	return nil, fmt.Errorf("not yet")
}

// Transactions

type levelTX struct {
	db *levelDB
	tx *leveldb.Transaction
}

func (tx *levelTX) Del(ctx context.Context, table string, key []byte) error {
	if key == nil {
		return ErrInvalidKey
	}
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	return xerr(tx.tx.Delete(NewCompositeKey(table, key), nil))
}

func (tx *levelTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if key == nil {
		return false, ErrInvalidKey
	}
	if _, ok := tx.db.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	has, err := tx.tx.Has(NewCompositeKey(table, key), nil)
	return has, xerr(err)
}

func (tx *levelTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}
	if _, ok := tx.db.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	value, err := tx.tx.Get(NewCompositeKey(table, key), nil)
	return value, xerr(err)
}

func (tx *levelTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	if key == nil {
		return ErrInvalidKey
	}
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
