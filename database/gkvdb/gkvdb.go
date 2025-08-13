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

	// Iterators
	// XXX should work only in Transactions?
	// Range()

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
	OPInv Operation = 0
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

type Iterator struct{}

var (
	ErrKeyNotFound   = errors.New("key not found")
	ErrInvalidConfig = errors.New("invalid config")
)

/*
	bucket:key:value

	transactions:txid:tx

	wishlist
		buckets
		transactions
		snapshots
*/
