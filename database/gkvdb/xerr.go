// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"errors"

	"github.com/cockroachdb/pebble"
	"github.com/dgraph-io/badger/v4"
	"github.com/nutsdb/nutsdb"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/tidwall/buntdb"
	bolterrs "go.etcd.io/bbolt/errors"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Translate specific dbs' errors into gkvdb errors
func xerr(err error) error {
	switch {
	// badger
	case errors.Is(err, badger.ErrDBClosed):
		err = ErrDBClosed
	case errors.Is(err, badger.ErrKeyNotFound):
		err = ErrKeyNotFound

	// bbolt
	case errors.Is(err, bolterrs.ErrDatabaseNotOpen):
		err = ErrDBClosed
	case errors.Is(err, bolterrs.ErrKeyRequired):
		err = nil

	// bunt
	case errors.Is(err, buntdb.ErrNotFound):
		err = ErrKeyNotFound

	// leveldb
	case errors.Is(err, leveldb.ErrClosed):
		err = ErrDBClosed
	case errors.Is(err, leveldb.ErrNotFound):
		err = ErrKeyNotFound

	// mongo
	case errors.Is(err, mongo.ErrNoDocuments):
		err = ErrKeyNotFound

	// nutsdb
	case errors.Is(err, nutsdb.ErrKeyNotFound):
		err = ErrKeyNotFound
	case errors.Is(err, nutsdb.ErrRangeScan):
		err = ErrInvalidRange
	case errors.Is(err, nutsdb.ErrBucketNotExist),
		errors.Is(err, nutsdb.ErrorBucketNotExist):
		err = ErrTableNotFound
	case errors.Is(err, nutsdb.ErrDBClosed):
		err = ErrDBClosed
	case errors.Is(err, nutsdb.ErrKeyEmpty):
		err = nil

	// pebble
	case errors.Is(err, pebble.ErrClosed):
		err = ErrDBClosed
	case errors.Is(err, pebble.ErrNotFound):
		err = ErrKeyNotFound
	}
	return err
}
