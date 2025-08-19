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
	Home string
}

func DefaultLevelConfig(home string) *LevelConfig {
	return &LevelConfig{
		Home: home,
	}
}

type levelDB struct {
	db *leveldb.DB

	cfg *LevelConfig
}

func NewLevelDB(cfg *LevelConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &levelDB{
		cfg: cfg,
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
	return b.db.Delete(NewCompositeKey(table, key), nil)
}

func (b *levelDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	return b.db.Has(NewCompositeKey(table, key), nil)
}

func (b *levelDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
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
	return b.db.Put(NewCompositeKey(table, key), value, nil)
}

func (b *levelDB) Begin(_ context.Context, write bool) (Transaction, error) {
	tx, err := b.db.OpenTransaction()
	if err != nil {
		return nil, xerr(err)
	}
	return &levelTX{
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
	return nil, fmt.Errorf("not yet")
}

func (b *levelDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	return nil, fmt.Errorf("not yet")
}

func (b *levelDB) NewBatch(ctx context.Context) (Batch, error) {
	return nil, fmt.Errorf("not yet")
}

// Transactions

type levelTX struct {
	tx *leveldb.Transaction
}

func (tx *levelTX) Del(ctx context.Context, table string, key []byte) error {
	return xerr(tx.tx.Delete(NewCompositeKey(table, key), nil))
}

func (tx *levelTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	has, err := tx.tx.Has(NewCompositeKey(table, key), nil)
	return has, xerr(err)
}

func (tx *levelTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	value, err := tx.tx.Get(NewCompositeKey(table, key), nil)
	return value, xerr(err)
}

func (tx *levelTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	return xerr(tx.tx.Put(NewCompositeKey(table, key), value, nil))
}

func (tx *levelTX) Commit(ctx context.Context) error {
	return xerr(tx.tx.Commit())
}

func (tx *levelTX) Rollback(ctx context.Context) error {
	tx.tx.Discard()
	return nil
}
