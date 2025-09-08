// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrDBClosed       = errors.New("database is closed")
	ErrDBOpen         = errors.New("database already open")
	ErrDuplicateTable = errors.New("duplicate table")
	ErrInvalidConfig  = errors.New("invalid config")
	ErrInvalidRange   = errors.New("invalid or empty range")
	ErrKeyNotFound    = errors.New("key not found")
	ErrTableNotFound  = errors.New("table not found")
	ErrNotSuported    = errors.New("not supported")
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
	// XXX I am kind of the opinion that we need a prefix index as well;
	// maybe that can be achieved with Iterator as well. Think about this.

	// Batches
	NewBatch(ctx context.Context) (Batch, error)
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

func KeyFromComposite(table string, key []byte) []byte {
	if table == "" {
		return key
	}
	// XXX antonio, add test cases for this. We must allow "" and make sure
	// we crash if something bad comes in.
	if len(table)+1 > len(key) {
		panic(fmt.Sprintf("fix your code %v > %v", len(table)+1, len(key)))
	}
	return key[len(table)+1:]
}

// Transactions

// Transactions are read-only or read-write. A read-only transaction is a
// snapshot of the database/table tuple and will not change for the duration of
// the transaction. A read-write transaction has the same guarantees as the
// read-only transaction however now one can also modify data. Transaction are
// taken on the entire database but the snapshot view is on a single table. One
// should take great care to make transactions as short lived as possible.
// Transactions make no guarantees about the returned key/value pairs. It's up
// to the caller to copy returned values as needed outside of the transaction.
//
// The following idiom is considered best practice:
// ```
//
//	tx, _ := db.Begin(ctx, false)
//	value, _ := tx.Get(ctx, []byte{"mykey")
//	rv := make([]byte, len(value))
//	copy(rv, value)
//	tx.Commit(ctx)
//	fmt.Printf("value: %x\n", rv)
//
// ```
//
// Note, the caller must call Commit or Rollback on ALL open transactions.
// Failure to do so may end up in programs not being able to exit due to
// pending unfinished transactions.
//
// View and Update are convenience wrappers that take a callback for
// read-only and read-write transactions respectively.
type Transaction interface {
	Del(ctx context.Context, table string, key []byte) error
	Has(ctx context.Context, table string, key []byte) (bool, error)
	Get(ctx context.Context, table string, key []byte) ([]byte, error)
	Put(ctx context.Context, table string, key []byte, value []byte) error

	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	Write(ctx context.Context, b Batch) error
}

// Batches

// The following idiom is considered best practice:
// ```
//
//	db.Update(ctx, func((ctx context.Context, tx Transaction) {
//		b := NewBatch(ctx)
//		b.Put(ctx, table, []byte{"mykey", nil)
//		b.Del(ctx, table, []byte{"delkey")
//		return tx.Write(ctx, b)
//	}))
//
// ```
type Batch interface {
	Del(ctx context.Context, table string, key []byte)
	Put(ctx context.Context, table string, key, value []byte)
	Reset(ctx context.Context)
}

// batchFunc serves as an element for a list of transaction
// operations inside certain batch type to be executed by a Tx
type batchFunc func(context.Context, Transaction) error

// Iterator is a generic database iterator that only supports minimal
// functionality. It is NOT concurrency safe and there are no guarantees about
// the life-cycle of the returned key and value outside of the iterator or even
// upon a seek type operation. It is wise to make a copy of key/value for use
// outside the iterator loop. Close must be called upon completion.
//
// Next is special as in that on first use it returns the first record.
//
// Typical use is as follows:
// ```
//
//	it, _ := NewIterator(ctx, table)
//	for it.Next() {
//		// Do things
//	}
//	it.Close(ctx)
//
// ```
type Iterator interface {
	First(ctx context.Context) bool
	Last(ctx context.Context) bool
	Next(ctx context.Context) bool
	Seek(ctx context.Context, key []byte) bool

	Key(ctx context.Context) []byte
	Value(ctx context.Context) []byte

	Close(ctx context.Context)
}

// Range is a generic database bound iterator that only supports minimal
// functionality. It is NOT concurrency safe and there are no guarantees about
// the life-cycle of the returned key and value outside of the iterator or even
// upon a seek type operation. It is wise to make a copy of key/value for use
// outside the iterator loop. Close must be called upon completions since it
// lives inside a read-only database transaction and thus may prevent the
// program from exiting.
//
// Next is special as in that on first use it returns the first record.
//
// Note that `start` is included in the range and `end` is NOT. This may seem
// odd but it uses standard 0 based indexing where the terminator is 'less
// than'.
//
// Typical use is as follows:
// ```
//
//	ir, _ := NewRange(ctx, table, start, end)
//	for ir.Next(ctx) {
//		// Do things
//	}
//	ir.Close(ctx)
//
// ```
// Several backends do not work that way thus it is be emulated in the various
// implementations.
type Range interface {
	First(ctx context.Context) bool
	Last(ctx context.Context) bool
	Next(ctx context.Context) bool

	Key(ctx context.Context) []byte
	Value(ctx context.Context) []byte

	Close(ctx context.Context)
}

// Copyright (c) 2014, Suryandaru Triandana <syndtr@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// BytesPrefix returns key range that satisfy the given prefix.
// This only applicable for the standard 'bytes comparer'.
func BytesPrefix(prefix []byte) ([]byte, []byte) {
	var limit []byte
	for i := len(prefix) - 1; i >= 0; i-- {
		c := prefix[i]
		if c < 0xff {
			limit = make([]byte, i+1)
			copy(limit, prefix)
			limit[i] = c + 1
			break
		}
	}
	return prefix, limit
}
