package gkvdb

import (
	"context"
	"os"
	"path/filepath"

	"github.com/guycipher/btree"
)

// Assert required interfaces
var (
	_ Batch       = (*btreeBatch)(nil)
	_ Database    = (*btreeDB)(nil)
	_ Iterator    = (*btreeIterator)(nil)
	_ Range       = (*btreeRange)(nil)
	_ Transaction = (*btreeTX)(nil)
)

type BtreeConfig struct {
	Home   string
	Tables []string
}

func DefaultBtreeConfig(home string, tables []string) *BtreeConfig {
	return &BtreeConfig{
		Home:   home,
		Tables: tables,
	}
}

func NewBtreeDB(cfg *BtreeConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &btreeDB{
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

// Database
type btreeDB struct {
	cfg    *BtreeConfig
	tables map[string]struct{}

	db *btree.BTree
}

func (db *btreeDB) Open(context.Context) error {
	bt, err := btree.Open(filepath.Join(db.cfg.Home, "btree.db"),
		os.O_CREATE|os.O_RDWR, 0o600, 3)
	if err != nil {
		return err
	}
	db.db = bt
	return nil
}

func (db *btreeDB) Close(context.Context) error {
	return db.db.Close()
}

func (db *btreeDB) Del(ctx context.Context, table string, key []byte) error {
	return db.db.Delete(NewCompositeKey(table, key))
}

func (db *btreeDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	// XXX implement proper has
	if _, err := db.Get(ctx, table, key); err != nil {
		return false, nil
	}
	return true, nil
}

func (db *btreeDB) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	value, err := db.db.Get(NewCompositeKey(table, key))
	if err != nil {
		return nil, err
	}
	// XXX btree can return multiples, deal with this instead of returning
	// index 0.
	return value.V[0], nil
}

func (db *btreeDB) Put(ctx context.Context, table string, key []byte, value []byte) error {
	return ErrDummy
}

func (db *btreeDB) Begin(ctx context.Context, write bool) (Transaction, error) {
	return &btreeTX{}, nil
}

func (db *btreeDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return ErrDummy
}

func (db *btreeDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return ErrDummy
}

func (db *btreeDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	return &btreeIterator{}, nil
}

func (db *btreeDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	return &btreeRange{}, nil
}

func (db *btreeDB) NewBatch(ctx context.Context) (Batch, error) {
	return &btreeBatch{}, nil
}

// Batch
type btreeBatch struct{}

func (*btreeBatch) Del(ctx context.Context, table string, key []byte)        {}
func (*btreeBatch) Put(ctx context.Context, table string, key, value []byte) {}
func (*btreeBatch) Reset(ctx context.Context)                                {}

// Iterator
type btreeIterator struct{}

func (it *btreeIterator) First(ctx context.Context) bool {
	return false
}

func (it *btreeIterator) Last(ctx context.Context) bool {
	return false
}

func (it *btreeIterator) Next(ctx context.Context) bool {
	return false
}

func (it *btreeIterator) Seek(ctx context.Context, key []byte) bool {
	return false
}

func (it *btreeIterator) Key(ctx context.Context) []byte {
	return nil
}

func (it *btreeIterator) Value(ctx context.Context) []byte {
	return nil
}

func (it *btreeIterator) Close(ctx context.Context) {}

// Range
type btreeRange struct{}

func (r *btreeRange) First(ctx context.Context) bool {
	return false
}

func (r *btreeRange) Last(ctx context.Context) bool {
	return false
}

func (r *btreeRange) Next(ctx context.Context) bool {
	return false
}

func (r *btreeRange) Key(ctx context.Context) []byte {
	return nil
}

func (r *btreeRange) Value(ctx context.Context) []byte {
	return nil
}

func (r *btreeRange) Close(ctx context.Context) {}

// Transaction
type btreeTX struct{}

func (tx *btreeTX) Del(ctx context.Context, table string, key []byte) error {
	return ErrDummy
}

func (tx *btreeTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	return false, ErrDummy
}

func (tx *btreeTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	return nil, ErrDummy
}

func (tx *btreeTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	return ErrDummy
}

func (tx *btreeTX) Commit(ctx context.Context) error {
	return ErrDummy
}

func (tx *btreeTX) Rollback(ctx context.Context) error {
	return ErrDummy
}

func (tx *btreeTX) Write(ctx context.Context, b Batch) error {
	return ErrDummy
}
