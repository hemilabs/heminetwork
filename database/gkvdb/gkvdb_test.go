// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"slices"

	"github.com/hemilabs/heminetwork/v2/database/gkvdb"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/errgroup"
)

func newKey(i int) []byte {
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], uint32(i))
	return key[:]
}

func newVal(i int) []byte {
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], uint64(i))
	return value[:]
}

func dbputs(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		err := db.Put(ctx, table, newKey(i), newVal(i))
		if err != nil {
			return fmt.Errorf("put %v in %v: %w", i, table, err)
		}
	}
	return nil
}

// XXX test if you can read it back
func dbputEmpty(ctx context.Context, db gkvdb.Database, tables []string) error {
	for _, table := range tables {
		err := db.Put(ctx, table, nil, nil)
		if err != nil {
			return fmt.Errorf("put empty key %v: %w", table, err)
		}
	}
	return nil
}

func dbputInvalidTable(ctx context.Context, db gkvdb.Database, table string) error {
	err := db.Put(ctx, table, newKey(0), nil)
	if !errors.Is(err, gkvdb.ErrTableNotFound) {
		return fmt.Errorf("put expected not found error %v: %w", table, err)
	}
	return nil
}

func dbputDuplicate(ctx context.Context, db gkvdb.Database, table string, insertCount int) error {
	for i := range insertCount {
		key := newKey(0)
		value := newVal(i)
		err := db.Put(ctx, table, key, value)
		if err != nil {
			return fmt.Errorf("put %v: %v", table, i)
		}
		rv, err := db.Get(ctx, table, key)
		if err != nil {
			return fmt.Errorf("get %v: %v %w", table, i, err)
		}
		if !bytes.Equal(rv, value) {
			return fmt.Errorf("get unequal %v: %v", table, i)
		}
	}
	return nil
}

func dbgets(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		value, err := db.Get(ctx, table, newKey(i))
		if err != nil {
			return fmt.Errorf("get %v: %v %w", table, i, err)
		}
		if !bytes.Equal(value, newVal(i)) {
			return fmt.Errorf("get unequal %v: %v", table, i)
		}
	}
	return nil
}

func dbgetInvalidTable(ctx context.Context, db gkvdb.Database, table string) error {
	_, err := db.Get(ctx, table, newKey(0))
	if !errors.Is(err, gkvdb.ErrTableNotFound) {
		return fmt.Errorf("get expected not found error %v: %w", table, err)
	}
	return nil
}

func dbhas(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		has, err := db.Has(ctx, table, newKey(i))
		if err != nil {
			return fmt.Errorf("has %v: %v %w", table, i, err)
		}
		if !has {
			return fmt.Errorf("has %v: %v", table, i)
		}
	}
	return nil
}

func dbhasInvalidTable(ctx context.Context, db gkvdb.Database, table string) error {
	has, err := db.Has(ctx, table, newKey(0))
	if !errors.Is(err, gkvdb.ErrTableNotFound) {
		return fmt.Errorf("has expected not found error %v: %w", table, err)
	}
	if has {
		return fmt.Errorf("expected not has %v: %v", table, 0)
	}
	return nil
}

func dbdels(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		err := db.Del(ctx, table, newKey(i))
		if err != nil {
			return fmt.Errorf("del %v: %v %w", table, i, err)
		}
	}
	return nil
}

func dbdelInvalidKey(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		err := db.Del(ctx, table, newKey(i))
		if err != nil {
			return fmt.Errorf("del invalid key %v: %v %w", table, i, err)
		}
	}
	return nil
}

func dbdelInvalidTable(ctx context.Context, db gkvdb.Database, table string) error {
	err := db.Del(ctx, table, newKey(0))
	if !errors.Is(err, gkvdb.ErrTableNotFound) {
		return fmt.Errorf("del expected not found error %v: %w", table, err)
	}
	return nil
}

func dbhasNegative(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		has, err := db.Has(ctx, table, newKey(i))
		if err != nil {
			return fmt.Errorf("has %v: %v %w", table, i, err)
		}
		if has {
			return fmt.Errorf("has %v: %v", table, i)
		}
	}
	return nil
}

func dbgetsNegative(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		_, err := db.Get(ctx, table, newKey(i))
		if !errors.Is(err, gkvdb.ErrKeyNotFound) {
			return fmt.Errorf("get expected not found error %v: %v %w", table, i, err)
		}
	}
	return nil
}

func dbhasOdds(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		has, err := db.Has(ctx, table, newKey(i))
		if i%2 == 0 {
			// Assert we don't have evens
			if err != nil {
				return fmt.Errorf("odds has %v: %v %w", table, i, err)
			}
			if has {
				return fmt.Errorf("odds has %v: %v", table, i)
			}
		} else {
			if err != nil {
				return fmt.Errorf("odds has %v: %v %w", table, i, err)
			}
			if !has {
				return fmt.Errorf("odds has %v: %v", table, i)
			}
		}
	}
	return nil
}

func txputEmpty(ctx context.Context, tx gkvdb.Transaction, tables []string) error {
	for _, table := range tables {
		err := tx.Put(ctx, table, nil, nil)
		if err != nil {
			return fmt.Errorf("tx put empty %v: %w", table, err)
		}
	}
	return nil
}

func txputInvalidTable(ctx context.Context, tx gkvdb.Transaction, table string) error {
	err := tx.Put(ctx, table, newKey(0), nil)
	if !errors.Is(err, gkvdb.ErrTableNotFound) {
		return fmt.Errorf("tx put expected not found error %v: %w", table, err)
	}
	return nil
}

// This fails if we try to access the changes made using a tx put
// with a tx get after, and it returns the new value
// func txputDuplicate(ctx context.Context, tx gkvdb.Transaction, table string, insertCount int) error {
// 	for i := range insertCount {
// 		var key [4]byte
// 		var value [8]byte
// 		binary.BigEndian.PutUint32(key[:], uint32(0))
// 		binary.BigEndian.PutUint64(value[:], uint64(i))
// 		err := tx.Put(ctx, table, key[:], value[:])
// 		if err != nil {
// 			return fmt.Errorf("put %v: %v", table, i)
// 		}
// 		rv, err := tx.Get(ctx, table, key[:])
// 		if err != nil {
// 			return fmt.Errorf("get %v: %v %w", table, i, err)
// 		}
// 		if i != 0 && bytes.Equal(rv, value[:]) {
// 			return fmt.Errorf("get equal %v: expect %d, got %d", table, value, rv)
// 		}
// 	}
// 	return nil
// }

func txputs(ctx context.Context, tx gkvdb.Transaction, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		err := tx.Put(ctx, table, newKey(i), newVal(i))
		if err != nil {
			return fmt.Errorf("tx put %v in %v: %w", i, table, err)
		}
	}
	return nil
}

func txdelsEven(ctx context.Context, tx gkvdb.Transaction, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		key := newKey(i)
		if i%2 == 0 {
			err := tx.Del(ctx, table, key)
			if err != nil {
				return fmt.Errorf("del %v: %v %w", table, i, err)
			}
		} else {
			// Assert odd record exist
			value, err := tx.Get(ctx, table, key)
			if err != nil {
				return fmt.Errorf("even get %v: %v %w", table, i, err)
			}
			if !bytes.Equal(value, newVal(i)) {
				return fmt.Errorf("even get unequal %v: %v", table, i)
			}
		}
	}
	return nil
}

func txdelInvalidKey(ctx context.Context, tx gkvdb.Transaction, table string) error {
	err := tx.Del(ctx, table, newKey(0))
	if err != nil {
		return fmt.Errorf("del invalid key %v: %w", table, err)
	}
	return nil
}

func dbBasic(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	// Already Open
	if err := db.Open(ctx); err == nil {
		return errors.New("expected already open error")
	}

	// Put Empty
	err := dbputEmpty(ctx, db, tables)
	if err != nil {
		return fmt.Errorf("dbputEmpty: %w", err)
	}

	// Put Invalid Table
	err = dbputInvalidTable(ctx, db, fmt.Sprintf("table%d", len(tables)))
	if err != nil {
		return fmt.Errorf("dbputInvalidTable: %w", err)
	}

	// Put Duplicate
	err = dbputDuplicate(ctx, db, tables[0], insertCount)
	if err != nil {
		return fmt.Errorf("dbputDuplicate: %w", err)
	}

	// Puts
	err = dbputs(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbputs: %w", err)
	}

	// Get Invalid Table
	err = dbgetInvalidTable(ctx, db, fmt.Sprintf("table%d", len(tables)))
	if err != nil {
		return fmt.Errorf("dbgetInvalidTable: %w", err)
	}

	// Get
	err = dbgets(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbgets: %w", err)
	}

	// Has Invalid Table
	err = dbhasInvalidTable(ctx, db, fmt.Sprintf("table%d", len(tables)))
	if err != nil {
		return fmt.Errorf("dbgetInvalidTable: %w", err)
	}

	// Has
	err = dbhas(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbhas: %w", err)
	}

	// Del
	err = dbdels(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbdels: %w", err)
	}

	// Del Invalid Table
	err = dbdelInvalidTable(ctx, db, fmt.Sprintf("table%d", len(tables)))
	if err != nil {
		return fmt.Errorf("dbdelInvalidTable: %w", err)
	}

	// Del Invalid Key
	err = dbdelInvalidKey(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbdelInvalidKey: %w", err)
	}

	// Has negative
	err = dbhasNegative(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbhasNegative: %w", err)
	}

	// Get negative
	err = dbgetsNegative(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbgetsNegative: %w", err)
	}

	return nil
}

// Transaction Rollback
func dbTransactionsRollback(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	tx, err := db.Begin(ctx, true)
	if err != nil && !errors.Is(err, gkvdb.ErrDBClosed) {
		return fmt.Errorf("db begin: %w", err)
	}
	defer func() {
		if err != nil {
			err = tx.Rollback(ctx)
			if err != nil {
				panic(fmt.Errorf("tx rollback: %w", err))
			}
		}
	}()
	err = txputs(ctx, tx, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbgetsNegative: %w", err)
	}
	err = tx.Rollback(ctx)
	if err != nil {
		return fmt.Errorf("tx rollback: %w", err)
	}
	err = dbhasNegative(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbgetsNegative: %w", err)
	}
	return nil
}

// Transaction Commit
func dbTransactionsCommit(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	tx, err := db.Begin(ctx, true)
	if err != nil {
		return fmt.Errorf("db begin: %w", err)
	}
	defer func() {
		if err != nil {
			err = tx.Rollback(ctx)
			if err != nil && !errors.Is(err, gkvdb.ErrDBClosed) {
				panic(fmt.Errorf("tx rollback: %w", err))
			}
		}
	}()
	err = txputs(ctx, tx, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbgetsNegative: %w", err)
	}
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("tx commit: %w", err)
	}
	err = dbgets(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbgetsNegative: %w", err)
	}

	return nil
}

// Transaction Multiple Write
func dbTransactionsMultipleWrite(ctx context.Context, db gkvdb.Database, table string, txCount int) error {
	last := txCount + 1
	key := newKey(0)
	err := db.Put(ctx, table, key, newVal(last))
	if err != nil {
		return fmt.Errorf("initial put")
	}
	eg, ctx := errgroup.WithContext(ctx)
	for i := range txCount {
		eg.Go(func() error {
			tx, err := db.Begin(ctx, true)
			if err != nil {
				return fmt.Errorf("tx%d - db begin: %w", i, err)
			}
			defer func() {
				if err != nil {
					err = tx.Rollback(ctx)
					if err != nil && !errors.Is(err, gkvdb.ErrDBClosed) {
						panic(fmt.Errorf("tx%d - tx rollback: %w", i, err))
					}
				}
			}()
			// see if value set by last tx matches "last"
			ve := newVal(last)
			rv, err := tx.Get(ctx, table, key)
			if err != nil {
				return fmt.Errorf("tx%d - get: %w", i, err)
			}
			if !bytes.Equal(rv, ve) {
				return fmt.Errorf("tx%d - expected %v, got %v", i, ve, rv)
			}

			// set value and "last" to "i"
			ve = newVal(i)
			err = tx.Put(ctx, table, key, ve)
			if err != nil {
				return fmt.Errorf("tx put %v in %v: %w", i, table, err)
			}
			// this should work and doesn't race because write txs
			// are meant to block on creation if one already exists
			last = i
			err = tx.Commit(ctx)
			if err != nil {
				return fmt.Errorf("tx%d - tx commit: %w", i, err)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

// Transaction delete even records
func dbTransactionsDelete(ctx context.Context, db gkvdb.Database, tables []string, insertCount int) error {
	tx, err := db.Begin(ctx, true)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			err = tx.Rollback(ctx)
			if err != nil && !errors.Is(err, gkvdb.ErrDBClosed) {
				panic(fmt.Errorf("tx rollback: %w", err))
			}
		}
	}()
	err = txdelsEven(ctx, tx, tables, insertCount)
	if err != nil {
		return fmt.Errorf("txdelsEven: %w", err)
	}
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("tx commit: %w", err)
	}
	err = dbhasOdds(ctx, db, tables, insertCount)
	if err != nil {
		return fmt.Errorf("dbhasOdds: %w", err)
	}

	return nil
}

// Transaction test expected errors
func dbTransactionsErrors(ctx context.Context, db gkvdb.Database, tables []string) error {
	tx, err := db.Begin(ctx, true)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			err = tx.Rollback(ctx)
			if err != nil && !errors.Is(err, gkvdb.ErrDBClosed) {
				panic(fmt.Errorf("tx rollback: %w", err))
			}
		}
	}()
	err = txputEmpty(ctx, tx, tables)
	if err != nil {
		return fmt.Errorf("txputEmpty: %w", err)
	}
	err = txputInvalidTable(ctx, tx, fmt.Sprintf("table%d", len(tables)))
	if err != nil {
		return fmt.Errorf("txputInvalidTable: %w", err)
	}
	err = txdelInvalidKey(ctx, tx, tables[0])
	if err != nil {
		return fmt.Errorf("txdelInvalidKey: %w", err)
	}
	// err = txputDuplicate(ctx, tx, tables[0], insertCount)
	// if err != nil {
	// 	return fmt.Errorf("txputDuplicate: %w", err)
	// }
	err = tx.Rollback(ctx)
	if err != nil {
		return fmt.Errorf("tx rollback: %w", err)
	}

	return nil
}

func dbIterateNext(ctx context.Context, db gkvdb.Database, table string, recordCount int) error {
	it, err := db.NewIterator(ctx, table)
	if err != nil {
		return err
	}
	defer it.Close(ctx)

	// Next
	i := 0
	for it.Next(ctx) {
		key := it.Key(ctx)
		val := it.Value(ctx)
		if !bytes.Equal(key, newKey(i)) {
			return fmt.Errorf("next unequal key: got %v, expected %v", key, newKey(i))
		}
		if !bytes.Equal(val, newVal(i)) {
			return fmt.Errorf("next unequal value: got %v, expected %v", val, newVal(i))
		}
		i++
	}
	if recordCount != i {
		return fmt.Errorf("found %d records, expected %d", i, recordCount)
	}
	return nil
}

func dbIterateFirstLast(ctx context.Context, db gkvdb.Database, table string, recordCount int) error {
	it, err := db.NewIterator(ctx, table)
	if err != nil {
		return err
	}
	defer it.Close(ctx)

	// First
	if !it.First(ctx) {
		return errors.New("first")
	}
	key := it.Key(ctx)
	val := it.Value(ctx)
	if !bytes.Equal(key, newKey(0)) {
		return fmt.Errorf("first unequal key: got %v, expected %v", key, newKey(0))
	}
	if !bytes.Equal(val, newVal(0)) {
		return fmt.Errorf("first unequal value: got %v, expected %v", val, newVal(0))
	}

	// Last
	if !it.Last(ctx) {
		return errors.New("last")
	}
	key = it.Key(ctx)
	val = it.Value(ctx)
	if !bytes.Equal(key, newKey(recordCount-1)) {
		return fmt.Errorf("last unequal key: got %v, expected %v", key, newKey(recordCount-1))
	}
	if !bytes.Equal(val, newVal(recordCount-1)) {
		return fmt.Errorf("last unequal value: got %v, expected %v", val, newVal(recordCount-1))
	}

	return nil
}

func dbIterateSeek(ctx context.Context, db gkvdb.Database, table string, recordCount int) error {
	it, err := db.NewIterator(ctx, table)
	if err != nil {
		return err
	}
	defer it.Close(ctx)

	// Seek even
	for i := range recordCount {
		if i%2 == 0 {
			expectedKey := newKey(i)
			if !it.Seek(ctx, expectedKey) {
				return fmt.Errorf("seek %v", expectedKey)
			}
			key := it.Key(ctx)
			val := it.Value(ctx)
			if !bytes.Equal(key, expectedKey) {
				return fmt.Errorf("seek unequal key: got %v, expected %v",
					key, expectedKey)
			}
			if !bytes.Equal(val, newVal(i)) {
				return fmt.Errorf("seek unequal value: got %v, expected %v",
					val, newVal(i))
			}
		}
	}

	// Verify that Next returns the Next record after a seek.
	if !it.Seek(ctx, newKey(1)) {
		return errors.New("seek 1")
	}
	if !it.Next(ctx) {
		return errors.New("next")
	}
	if !bytes.Equal(it.Key(ctx), newKey(2)) {
		return fmt.Errorf("not equal seek, got %v wanted %v", it.Key(ctx), newKey(2))
	}

	return nil
}

func dbIterateConcurrentWrites(ctx context.Context, db gkvdb.Database, table string, recordCount int) error {
	it, err := db.NewIterator(ctx, table)
	if err != nil {
		return err
	}
	defer it.Close(ctx)

	err = db.Put(ctx, table, []byte{uint8(recordCount)}, []byte{uint8(recordCount)})
	if err != nil {
		return fmt.Errorf("put [%v,%v]: %w", recordCount, recordCount, err)
	}

	// Next
	i := 0
	for it.Next(ctx) {
		key := it.Key(ctx)
		val := it.Value(ctx)
		expected := []byte{uint8(i)}
		if !bytes.Equal(key, expected) {
			return fmt.Errorf("next unequal key: got %v, expected %v", key, expected)
		}
		if !bytes.Equal(val, expected) {
			return fmt.Errorf("next unequal value: got %v, expected %v", val, expected)
		}
		i++
	}
	if recordCount != i {
		return fmt.Errorf("found %d records, expected %d", i, recordCount)
	}
	return nil
}

func dbRange(ctx context.Context, db gkvdb.Database, tables []string, total int) error {
	frac := total / 4
	start := frac
	end := frac * 3
	for _, table := range tables {
		s := newKey(start)
		e := newKey(end)

		it, err := db.NewRange(ctx, table, s, e)
		if err != nil {
			return fmt.Errorf("new range: %w", err)
		}
		i := 0
		for it.Next(ctx) {
			if !bytes.Equal(it.Key(ctx), newKey(start+i)) {
				return fmt.Errorf("invalid key got %v wanted %v",
					it.Key(ctx), newKey(start+i))
			}
			if !bytes.Equal(it.Value(ctx), newVal(start+i)) {
				return fmt.Errorf("invalid value got %x wanted %x",
					it.Value(ctx), newVal(start+i))
			}
			i++
		}
		if i != end-start {
			return fmt.Errorf("invalid record count got %v want %v", i, end-start)
		}
		it.Close(ctx)
	}
	return nil
}

func dbRangeFirstLast(ctx context.Context, db gkvdb.Database, tables []string, total int) error {
	frac := total / 4
	start := frac
	// Test with end outside and inside
	// values inserted into the dbs
	for _, end := range []int{total + start, frac * 3} {
		for _, table := range tables {
			s := newKey(start)
			e := newKey(end)

			it, err := db.NewRange(ctx, table, s, e)
			if err != nil {
				return fmt.Errorf("new range: %w", err)
			}

			// First
			if !it.First(ctx) {
				return errors.New("first")
			}
			key := it.Key(ctx)
			val := it.Value(ctx)
			if !bytes.Equal(key, newKey(start)) {
				return fmt.Errorf("first unequal key: got %v, expected %v", key, newKey(start))
			}
			if !bytes.Equal(val, newVal(start)) {
				return fmt.Errorf("first unequal value: got %v, expected %v", val, newVal(start))
			}

			// Last
			if !it.Last(ctx) {
				return errors.New("last")
			}
			key = it.Key(ctx)
			val = it.Value(ctx)
			expectedKey := newKey(min(total-1, end-1))
			expectedVal := newVal(min(total-1, end-1))
			if !bytes.Equal(key, expectedKey) {
				return fmt.Errorf("last unequal key: got %v, expected %v", key, expectedKey)
			}
			if !bytes.Equal(val, expectedVal) {
				return fmt.Errorf("last unequal value: got %v, expected %v", val, expectedVal)
			}

			it.Close(ctx)
		}
	}
	return nil
}

func dbBatch(ctx context.Context, db gkvdb.Database, table string, recordCount int) error {
	// Stuff a bunch of records into the same table to validate that
	// everything is executed as expected.
	b, err := db.NewBatch(ctx)
	if err != nil {
		return fmt.Errorf("new batch: %w", err)
	}

	for i := range recordCount {
		// Emulate user records "userXXXX"
		var key [8]byte
		copy(key[:], fmt.Appendf(nil, "user%04v", i))
		value := make([]byte, len(key)*2)
		copy(value[len(key):], key[:])
		b.Put(ctx, table, key[:], value)

		// Emulate user records "passXXXX"
		var pkey [8]byte
		copy(pkey[:], fmt.Appendf(nil, "pass%04v", i))
		eval := fmt.Appendf(nil, "thisisapassword%v", i)
		b.Put(ctx, table, pkey[:], eval)

		// Emulate avatar records "avatarXXXX"
		akey := fmt.Appendf(nil, "avatar%d", i)
		aval := fmt.Appendf(nil, "thisisavatar%d", i)
		b.Put(ctx, table, akey, aval)
	}
	err = db.Update(ctx, func(ctx context.Context, tx gkvdb.Transaction) error {
		return tx.Write(ctx, b)
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	// Read everything back and create a batch to delete all keys.
	it, err := db.NewIterator(ctx, table)
	if err != nil {
		return fmt.Errorf("new iterator: %w", err)
	}
	defer it.Close(ctx)

	bd, err := db.NewBatch(ctx)
	if err != nil {
		return fmt.Errorf("new batch: %w", err)
	}
	i := 0
	for it.Next(ctx) {
		key := slices.Clone(it.Key(ctx))
		bd.Del(ctx, table, key)
		i++
	}
	if i != recordCount*3 {
		return fmt.Errorf("invalid record count got %v, wanted %v", i, recordCount*3)
	}
	// Close iterator so that we don't block
	it.Close(ctx)

	err = db.Update(ctx, func(ctx context.Context, txn gkvdb.Transaction) error {
		return txn.Write(ctx, bd)
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	return nil
}

func dbBatchNoop(ctx context.Context, db gkvdb.Database, table string) error {
	b, err := db.NewBatch(ctx)
	if err != nil {
		return fmt.Errorf("new batch: %w", err)
	}

	// Invalid del should be noop
	b.Del(ctx, table, newKey(0))

	// valid put
	validKey := newKey(1)
	b.Put(ctx, table, validKey, newVal(1))

	err = db.Update(ctx, func(ctx context.Context, tx gkvdb.Transaction) error {
		return tx.Write(ctx, b)
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	_, err = db.Get(ctx, table, validKey)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	return nil
}

type TestTableItem struct {
	name   string
	dbFunc func(home string, tables []string) gkvdb.Database
}

func getDBs() []TestTableItem {
	dbs := []TestTableItem{
		{
			name: "badgerDB",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				cfg := gkvdb.DefaultBadgerConfig(home, tables)
				db, err := gkvdb.NewBadgerDB(cfg)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
		{
			name: "bbolt",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				cfg := gkvdb.DefaultBoltConfig(home, tables)
				db, err := gkvdb.NewBoltDB(cfg)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
		{
			name: "bitcask",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				cfg := gkvdb.DefaultBitcaskConfig(home, tables)
				db, err := gkvdb.NewBitcaskDB(cfg)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
		{
			name: "buntdb",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				cfg := gkvdb.DefaultBuntConfig(home, tables)
				db, err := gkvdb.NewBuntDB(cfg)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
		{
			name: "levelDB",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				cfg := gkvdb.DefaultLevelConfig(home, tables)
				db, err := gkvdb.NewLevelDB(cfg)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
		{
			name: "nutsDB",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				cfg := gkvdb.DefaultNutsConfig(home, tables)
				db, err := gkvdb.NewNutsDB(cfg)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
		{
			name: "pebbleDB",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				cfg := gkvdb.DefaultPebbleConfig(home, tables)
				db, err := gkvdb.NewPebbleDB(cfg)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
		{
			name: "replicator-direct",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				home1 := filepath.Join(home, "1")
				cfg1 := gkvdb.DefaultLevelConfig(home1, tables)
				db1, err := gkvdb.NewLevelDB(cfg1)
				if err != nil {
					panic(err)
				}
				home2 := filepath.Join(home, "2")
				cfg2 := gkvdb.DefaultLevelConfig(home2, tables)
				db2, err := gkvdb.NewLevelDB(cfg2)
				if err != nil {
					panic(err)
				}
				journalHome := filepath.Join(home, "journal")
				rcfg := gkvdb.DefaultReplicatorConfig(journalHome, gkvdb.Direct)
				db, err := gkvdb.NewReplicatorDB(rcfg, db1, db2)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
		{
			name: "replicator-lazy",
			dbFunc: func(home string, tables []string) gkvdb.Database {
				home1 := filepath.Join(home, "1")
				cfg1 := gkvdb.DefaultLevelConfig(home1, tables)
				db1, err := gkvdb.NewLevelDB(cfg1)
				if err != nil {
					panic(err)
				}
				home2 := filepath.Join(home, "2")
				cfg2 := gkvdb.DefaultLevelConfig(home2, tables)
				db2, err := gkvdb.NewLevelDB(cfg2)
				if err != nil {
					panic(err)
				}
				journalHome := filepath.Join(home, "journal")
				rcfg := gkvdb.DefaultReplicatorConfig(journalHome, gkvdb.Lazy)
				db, err := gkvdb.NewReplicatorDB(rcfg, db1, db2)
				if err != nil {
					panic(err)
				}
				return db
			},
		},
	}

	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI != "" {
		dbs = append(dbs,
			TestTableItem{
				name: "mongodb",
				dbFunc: func(home string, tables []string) gkvdb.Database {
					cfg := gkvdb.MongoConfig{
						URI:        mongoURI,
						Tables:     tables,
						DropTables: true,
					}
					db, err := gkvdb.NewMongoDB(&cfg)
					if err != nil {
						panic(err)
					}
					return db
				},
			},
		)
	}

	return dbs
}

func mongoReopen(tables []string) gkvdb.Database {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI != "" {
		cfg := gkvdb.MongoConfig{
			URI:        mongoURI,
			Tables:     tables,
			DropTables: true,
		}
		db, err := gkvdb.NewMongoDB(&cfg)
		if err != nil {
			panic(err)
		}
		return db
	}
	return nil
}

func prepareTestSuite(t *testing.T, ctx context.Context, tableCount, insert int, tti TestTableItem) (gkvdb.Database, []string) {
	home := t.TempDir()

	tables := make([]string, 0, tableCount)
	for i := range tableCount {
		tables = append(tables, fmt.Sprintf("table%v", i))
	}

	db := tti.dbFunc(home, tables)
	err := db.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for _, table := range tables {
		for i := range insert {
			err := db.Put(ctx, table, newKey(i), newVal(i))
			if err != nil {
				t.Fatal(fmt.Errorf("put [%v,%v]: %w", i, i, err))
			}
		}
	}

	return db, tables
}

func TestGKVDB(t *testing.T) {
	testTable := getDBs()
	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			const insertCount = 10
			t.Run("basic", func(t *testing.T) {
				db, tables := prepareTestSuite(t, ctx, 5, 0, tti)
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err := dbBasic(ctx, db, tables, insertCount); err != nil {
					t.Fatal(err)
				}
			})

			t.Run("transactions", func(t *testing.T) {
				db, tables := prepareTestSuite(t, ctx, 5, 0, tti)
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err := dbTransactionsRollback(ctx, db, tables, insertCount); err != nil {
					t.Errorf("dbTransactionsRollback: %v", err)
					t.Fail()
				}
				if err := dbTransactionsCommit(ctx, db, tables, insertCount); err != nil {
					t.Errorf("dbTransactionsCommit: %v", err)
					t.Fail()
				}
				if err := dbTransactionsDelete(ctx, db, tables, insertCount); err != nil {
					t.Errorf("dbTransactionsDelete: %v", err)
					t.Fail()
				}
				if err := dbTransactionsErrors(ctx, db, tables); err != nil {
					t.Errorf("dbTransactionsErrors: %v", err)
					t.Fail()
				}
				if err := dbTransactionsMultipleWrite(ctx, db, tables[0], 5); err != nil {
					t.Errorf("dbTransactionsMultipleWrite: %v", err)
					t.Fail()
				}
			})

			t.Run("iterator", func(t *testing.T) {
				db, tables := prepareTestSuite(t, ctx, 3, insertCount, tti)
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				for _, table := range tables {
					if err := dbIterateNext(ctx, db, table, insertCount); err != nil {
						t.Errorf("dbIterateNext: %v", err)
						t.Fail()
					}
					if err := dbIterateFirstLast(ctx, db, table, insertCount); err != nil {
						t.Errorf("dbIterateFirstLast: %v", err)
						t.Fail()
					}
					if err := dbIterateSeek(ctx, db, table, insertCount); err != nil {
						t.Errorf("dbIterateSeek: %v", err)
						t.Fail()
					}
				}
			})

			t.Run("range", func(t *testing.T) {
				db, tables := prepareTestSuite(t, ctx, 3, insertCount, tti)
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err := dbRange(ctx, db, tables, insertCount); err != nil {
					t.Fatal(err)
				}
				if err := dbRangeFirstLast(ctx, db, tables, insertCount); err != nil {
					t.Fatal(err)
				}
			})

			t.Run("batch", func(t *testing.T) {
				db, tables := prepareTestSuite(t, ctx, 1, 0, tti)
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err := dbBatch(ctx, db, tables[0], 10); err != nil {
					t.Fatal(err)
				}
				if err := dbBatchNoop(ctx, db, tables[0]); err != nil {
					t.Fatal(err)
				}
			})

			t.Run("reopen", func(t *testing.T) {
				db, tables := prepareTestSuite(t, ctx, 1, 0, tti)
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if tti.name == "mongodb" {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}

					db = mongoReopen(tables)
					err = db.Open(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}

				if err := dbOpenCloseOpen(ctx, db, tables[0]); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func BenchmarkGKVDBPut(b *testing.B) {
	testTable := getDBs()
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()
	for _, tti := range testTable {
		for _, insertCount := range []int{1, 10, 100, 1000, 10000, 100000} {
			benchName := fmt.Sprintf("%v/%v", tti.name, insertCount)
			b.Run(benchName, func(b *testing.B) {
				home := b.TempDir()

				table := "table0"
				tables := []string{table}

				db := tti.dbFunc(home, tables)
				err := db.Open(ctx)
				if err != nil {
					b.Fatal(err)
				}
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						b.Fatal(err)
					}
				}()

				bt, err := db.NewBatch(ctx)
				if err != nil {
					b.Fatal(err)
				}
				for i := range insertCount {
					bt.Put(ctx, table, []byte{uint8(i)}, []byte{uint8(i)})
				}

				for b.Loop() {
					err = db.Update(ctx, func(ctx context.Context, tx gkvdb.Transaction) error {
						return tx.Write(ctx, bt)
					})
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestDumpRestorePipeline(t *testing.T) {
	home := t.TempDir()

	tableCount := 5
	tables := make([]string, 0, tableCount)
	for i := range tableCount {
		tables = append(tables, fmt.Sprintf("table%v", i))
	}

	cfg := gkvdb.DefaultLevelConfig(home, tables)
	db, err := gkvdb.NewLevelDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err = db.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := db.Close(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}()

	// Puts
	insertCount := 18999
	err = dbputs(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Get
	err = dbgets(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Dump
	var b bytes.Buffer
	zw, _ := zstd.NewWriter(&b)
	je := json.NewEncoder(zw)
	err = gkvdb.DumpTables(ctx, db, tables, je)
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// Restore, del first
	err = dbdels(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}
	err = dbhas(ctx, db, tables, insertCount)
	if err == nil {
		t.Fatal("wtf")
	}
	gkvdb.DefaultMaxRestoreChunk = 4096 // Many chunks
	zr, _ := zstd.NewReader(&b)
	jd := json.NewDecoder(zr)
	err = gkvdb.Restore(ctx, db, jd)
	if err != nil {
		t.Fatal(err)
	}
	err = dbhas(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}
	err = dbgets(ctx, db, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}
}

func dbOpenCloseOpen(ctx context.Context, db gkvdb.Database, table string) error {
	// Open again expect fail
	err := db.Open(ctx)
	if err == nil {
		return errors.New("db open: expected error")
	}
	err = db.Put(ctx, table, []byte("xxx"), []byte("yyy"))
	if err != nil {
		return fmt.Errorf("db put: %w", err)
	}
	_, err = db.Get(ctx, table, []byte("xxx"))
	if err != nil {
		return fmt.Errorf("db get: %w", err)
	}
	err = db.Close(ctx)
	if err != nil {
		return fmt.Errorf("db close: %w", err)
	}
	err = db.Open(ctx)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}
	_, err = db.Get(ctx, table, []byte("xxx"))
	if err != nil {
		return fmt.Errorf("db get 2: %w", err)
	}

	return nil
}

func TestCopy(t *testing.T) {
	home := t.TempDir()

	tableCount := 5
	tables := make([]string, 0, tableCount)
	for i := range tableCount {
		tables = append(tables, fmt.Sprintf("table%v", i))
	}

	srcCfg := gkvdb.DefaultLevelConfig(filepath.Join(home, "source"), tables)
	source, err := gkvdb.NewLevelDB(srcCfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err = source.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := source.Close(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}()

	// Puts
	insertCount := 18999
	err = dbputs(ctx, source, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Get
	err = dbgets(ctx, source, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}

	// Destination
	dstCfg := gkvdb.DefaultLevelConfig(filepath.Join(home, "destination"), tables)
	destination, err := gkvdb.NewLevelDB(dstCfg)
	if err != nil {
		t.Fatal(err)
	}
	err = destination.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := destination.Close(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}()

	gkvdb.Verbose = true
	gkvdb.DefaultMaxRestoreChunk = 16384 // Many chunks
	err = gkvdb.Copy(ctx, source, destination, tables)
	if err != nil {
		t.Fatal(err)
	}

	// Get and has destination
	err = dbhas(ctx, destination, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}
	err = dbgets(ctx, destination, tables, insertCount)
	if err != nil {
		t.Fatal(err)
	}
}

// TODO tests
// iterator / range concurrent put / del (for reverse reliant iters)
// iterator / range no keys
// insert large key / value
// tx ordered operations
// consider making multiple write txs not block
