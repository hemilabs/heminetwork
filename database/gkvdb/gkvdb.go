// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"context"
	"errors"
)

type Database interface {
	Open(context.Context) error
	Close(context.Context) error

	// Basic KV
	Del(ctx context.Context, table string, key []byte) error
	Has(ctx context.Context, table string, key []byte) (bool, error)
	Get(ctx context.Context, table string, key []byte) ([]byte, error)
	Put(ctx context.Context, table string, key []byte, value []byte) error

	// Transactions
	Begin(ctx context.Context, write bool) (Transaction, error)
	Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error
	View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error

	// Iterators, exist inside a Transaction
	NewIterator(ctx context.Context, table string) (Iterator, error)
	NewRange(ctx context.Context, table string, start, end []byte) (Range, error)

	// Batches
	// Import([]Batch) // XXX this should be a reader as well

	// Backup
	// DumpAll()
	// DumpBucket()
}

// CompositeKey is used by backends that do not support the concept of tables
// and thus must create a composite key to emulate this functionality.
type CompositeKey []byte

func NewCompositeKey(table string, key []byte) CompositeKey {
	if len(table) == 0 {
		return CompositeKey(key)
	}
	// A composite key is encoded as follows: table:key
	ck := make([]byte, len(table)+len(key)+1)
	copy(ck[0:], []byte(table))
	ck[len(table)] = byte(':')
	copy(ck[len(table)+1:], key)
	return CompositeKey(ck)
}

// Transactions

type Transaction interface {
	Del(ctx context.Context, table string, key []byte) error
	Has(ctx context.Context, table string, key []byte) (bool, error)
	Get(ctx context.Context, table string, key []byte) ([]byte, error)
	Put(ctx context.Context, table string, key []byte, value []byte) error

	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Batches
type Operation int

const (
	OPPut Operation = 1
	OPDel Operation = 2
)

// Batch is used to replay large datasets into the database.
type Batch struct {
	Op    Operation
	Table string
	Key   []byte
	Value []byte
}

// Iterator is a generic database iterator that only supports minimal
// functionality. It is NOT concurrency safe and there are no guarantees about
// the life-cycle of the returned key and value outside of the iterator or even
// upon a seek type operation. It is wise to make a copy of key/value for use
// outside the iterator loop.
//
// Next is special as in that on first use it returns the first record.
//
// Typical use is as follows:
// ```
//
//	it, _ := NewIterator()
//	for it.Next() {
//		// Do things
//	}
//
// ```
// Several backends do not work that way thus it is be emulated in the various
// implementations.
type Iterator interface {
	First(ctx context.Context) bool
	Last(ctx context.Context) bool
	Next(ctx context.Context) bool
	Seek(ctx context.Context, key []byte) bool

	Key(ctx context.Context) []byte
	Value(ctx context.Context) []byte

	Close(ctx context.Context) error
}

var (
	ErrKeyNotFound   = errors.New("key not found")
	ErrInvalidConfig = errors.New("invalid config")
)

// Range
type Range interface {
	First(ctx context.Context) bool

	Close(ctx context.Context) error
}

/*
	bucket:key:value

	transactions:txid:tx

	wishlist
		buckets
		transactions
		snapshots
*/
