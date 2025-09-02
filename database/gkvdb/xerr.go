// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"errors"

	"github.com/nutsdb/nutsdb"
	"github.com/syndtr/goleveldb/leveldb"
)

// Translate nutsb errors into gkvdb errors
func xerr(err error) error {
	switch {
	// leveldb
	case errors.Is(err, leveldb.ErrClosed):
		err = ErrDBClosed
	case errors.Is(err, leveldb.ErrNotFound):
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
		return nil
	}
	return err
}
