package gkvdb

import (
	"context"
	"errors"
)

// Assert required interfaces
var (
	_ Batch       = (*dummyBatch)(nil)
	_ Database    = (*dummyDB)(nil)
	_ Iterator    = (*dummyIterator)(nil)
	_ Range       = (*dummyRange)(nil)
	_ Transaction = (*dummyTX)(nil)

	ErrDummy = errors.New("dummy")
)

type DummyConfig struct {
	Home   string
	Tables []string
}

func DefaultDummyConfig(home string, tables []string) *DummyConfig {
	return &DummyConfig{
		Home:   home,
		Tables: tables,
	}
}

func NewDummyDB(cfg *DummyConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	ddb := &dummyDB{
		cfg:    cfg,
		tables: make(map[string]struct{}, len(cfg.Tables)),
	}
	for _, v := range cfg.Tables {
		if _, ok := ddb.tables[v]; ok {
			return nil, ErrDuplicateTable
		}
		ddb.tables[v] = struct{}{}
	}

	return ddb, nil
}

// Database
type dummyDB struct {
	cfg    *DummyConfig
	tables map[string]struct{}
}

func (db *dummyDB) Open(context.Context) error {
	return ErrDummy
}

func (db *dummyDB) Close(context.Context) error {
	return ErrDummy
}

func (db *dummyDB) Del(ctx context.Context, table string, key []byte) error {
	return ErrDummy
}

func (db *dummyDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	return false, ErrDummy
}

func (db *dummyDB) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	return nil, ErrDummy
}

func (db *dummyDB) Put(ctx context.Context, table string, key []byte, value []byte) error {
	return ErrDummy
}

func (db *dummyDB) Begin(ctx context.Context, write bool) (Transaction, error) {
	return &dummyTX{}, nil
}

func (db *dummyDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return ErrDummy
}

func (db *dummyDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return ErrDummy
}

func (db *dummyDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	return &dummyIterator{}, nil
}

func (db *dummyDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	return &dummyRange{}, nil
}

func (db *dummyDB) NewBatch(ctx context.Context) (Batch, error) {
	return &dummyBatch{}, nil
}

// Batch
type dummyBatch struct{}

func (*dummyBatch) Del(ctx context.Context, table string, key []byte)        {}
func (*dummyBatch) Put(ctx context.Context, table string, key, value []byte) {}
func (*dummyBatch) Reset(ctx context.Context)                                {}

// Iterator
type dummyIterator struct{}

func (it *dummyIterator) First(ctx context.Context) bool {
	return false
}

func (it *dummyIterator) Last(ctx context.Context) bool {
	return false
}

func (it *dummyIterator) Next(ctx context.Context) bool {
	return false
}

func (it *dummyIterator) Seek(ctx context.Context, key []byte) bool {
	return false
}

func (it *dummyIterator) Key(ctx context.Context) []byte {
	return nil
}

func (it *dummyIterator) Value(ctx context.Context) []byte {
	return nil
}

func (it *dummyIterator) Close(ctx context.Context) {}

// Range
type dummyRange struct{}

func (r *dummyRange) First(ctx context.Context) bool {
	return false
}

func (r *dummyRange) Last(ctx context.Context) bool {
	return false
}

func (r *dummyRange) Next(ctx context.Context) bool {
	return false
}

func (r *dummyRange) Key(ctx context.Context) []byte {
	return nil
}

func (r *dummyRange) Value(ctx context.Context) []byte {
	return nil
}

func (r *dummyRange) Close(ctx context.Context) {}

// Transaction
type dummyTX struct{}

func (tx *dummyTX) Del(ctx context.Context, table string, key []byte) error {
	return ErrDummy
}

func (tx *dummyTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	return false, ErrDummy
}

func (tx *dummyTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	return nil, ErrDummy
}

func (tx *dummyTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	return ErrDummy
}

func (tx *dummyTX) Commit(ctx context.Context) error {
	return ErrDummy
}

func (tx *dummyTX) Rollback(ctx context.Context) error {
	return ErrDummy
}

func (tx *dummyTX) Write(ctx context.Context, b Batch) error {
	return ErrDummy
}
