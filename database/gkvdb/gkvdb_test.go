package gkvdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/sync/errgroup"
)

func dbputs(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := range insertCount {
		var key [4]byte
		var value [8]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		binary.BigEndian.PutUint64(value[:], uint64(i))
		table := tables[i%len(tables)]
		err := db.Put(ctx, table, key[:], value[:])
		if err != nil {
			return fmt.Errorf("put %v: %v", table, i)
		}
	}
	return nil
}

func dbputEmpty(ctx context.Context, db Database, tables []string) error {
	for _, table := range tables {
		err := db.Put(ctx, table, nil, nil)
		if err != nil {
			return fmt.Errorf("put empty key %v: %w", table, err)
		}
	}
	return nil
}

func dbputInvalidTable(ctx context.Context, db Database, table string) error {
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], uint32(0))
	err := db.Put(ctx, table, key[:], nil)
	if !errors.Is(err, ErrTableNotFound) {
		return fmt.Errorf("put expected not found error %v: %v", table, err)
	}
	return nil
}

func dbputDuplicate(ctx context.Context, db Database, table string, insertCount int) error {
	for i := range insertCount {
		var key [4]byte
		var value [8]byte
		binary.BigEndian.PutUint32(key[:], uint32(0))
		binary.BigEndian.PutUint64(value[:], uint64(i))
		err := db.Put(ctx, table, key[:], value[:])
		if err != nil {
			return fmt.Errorf("put %v: %v", table, i)
		}
		rv, err := db.Get(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("get %v: %v %v", table, i, err)
		}
		if !bytes.Equal(rv, value[:]) {
			return fmt.Errorf("get unequal %v: %v", table, i)
		}
	}
	return nil
}

func dbgets(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		var key [4]byte
		var valueExpected [8]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		binary.BigEndian.PutUint64(valueExpected[:], uint64(i))
		value, err := db.Get(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("get %v: %v %v", table, i, err)
		}
		if !bytes.Equal(value, valueExpected[:]) {
			return fmt.Errorf("get unequal %v: %v", table, i)
		}
	}
	return nil
}

func dbgetInvalidTable(ctx context.Context, db Database, table string) error {
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], uint32(0))
	_, err := db.Get(ctx, table, key[:])
	if !errors.Is(err, ErrTableNotFound) {
		return fmt.Errorf("get expected not found error %v: %v", table, err)
	}
	return nil
}

func dbhas(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		has, err := db.Has(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("has %v: %v %v", table, i, err)
		}
		if !has {
			return fmt.Errorf("has %v: %v", table, i)
		}
	}
	return nil
}

func dbhasInvalidTable(ctx context.Context, db Database, table string) error {
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], uint32(0))
	has, err := db.Has(ctx, table, key[:])
	if !errors.Is(err, ErrTableNotFound) {
		return fmt.Errorf("has expected not found error %v: %v", table, err)
	}
	if has {
		return fmt.Errorf("expected not has %v: %v", table, 0)
	}
	return nil
}

func dbdels(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		err := db.Del(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("del %v: %v %v", table, i, err)
		}
	}
	return nil
}

func dbdelInvalidKey(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		err := db.Del(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("del invalid key %v: %v %w", table, i, err)
		}
	}
	return nil
}

func dbdelInvalidTable(ctx context.Context, db Database, table string) error {
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], uint32(0))
	err := db.Del(ctx, table, key[:])
	if !errors.Is(err, ErrTableNotFound) {
		return fmt.Errorf("del expected not found error %v: %w", table, err)
	}
	return nil
}

func dbhasNegative(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		has, err := db.Has(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("has %v: %v %v", table, i, err)
		}
		if has {
			return fmt.Errorf("has %v: %v", table, i)
		}
	}
	return nil
}

func dbgetsNegative(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		_, err := db.Get(ctx, table, key[:])
		if !errors.Is(err, ErrKeyNotFound) {
			return fmt.Errorf("get expected not found error %v: %v %v", table, i, err)
		}
	}
	return nil
}

func dbhasOdds(ctx context.Context, db Database, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		has, err := db.Has(ctx, table, key[:])
		if i%2 == 0 {
			// Assert we don't have evens
			if err != nil {
				return fmt.Errorf("odds has %v: %v %v", table, i, err)
			}
			if has {
				return fmt.Errorf("odds has %v: %v", table, i)
			}
		} else {
			if err != nil {
				return fmt.Errorf("odds has %v: %v %v", table, i, err)
			}
			if !has {
				return fmt.Errorf("odds has %v: %v", table, i)
			}
		}
	}
	return nil
}

func txputEmpty(ctx context.Context, tx Transaction, tables []string) error {
	for _, table := range tables {
		err := tx.Put(ctx, table, nil, nil)
		if err != nil {
			return fmt.Errorf("tx put empty %v: %w", table, err)
		}
	}
	return nil
}

func txputInvalidTable(ctx context.Context, tx Transaction, table string) error {
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], uint32(0))
	err := tx.Put(ctx, table, key[:], nil)
	if !errors.Is(err, ErrTableNotFound) {
		return fmt.Errorf("tx put expected not found error %v: %v", table, err)
	}
	return nil
}

// This fails if we try to access the changes made using a tx put
// with a tx get after, and it returns the new value
func txputDuplicate(ctx context.Context, tx Transaction, table string, insertCount int) error {
	for i := range insertCount {
		var key [4]byte
		var value [8]byte
		binary.BigEndian.PutUint32(key[:], uint32(0))
		binary.BigEndian.PutUint64(value[:], uint64(i))
		err := tx.Put(ctx, table, key[:], value[:])
		if err != nil {
			return fmt.Errorf("put %v: %v", table, i)
		}
		rv, err := tx.Get(ctx, table, key[:])
		if err != nil {
			return fmt.Errorf("get %v: %v %v", table, i, err)
		}
		if i != 0 && bytes.Equal(rv, value[:]) {
			return fmt.Errorf("get equal %v: expect %d, got %d", table, value, rv)
		}
	}
	return nil
}

func txputs(ctx context.Context, tx Transaction, tables []string, insertCount int) error {
	for i := range insertCount {
		var key [4]byte
		var value [8]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		binary.BigEndian.PutUint64(value[:], uint64(i))
		table := tables[i%len(tables)]
		err := tx.Put(ctx, table, key[:], value[:])
		if err != nil {
			return fmt.Errorf("tx put %v: %v", table, i)
		}
	}
	return nil
}

func txdelsEven(ctx context.Context, tx Transaction, tables []string, insertCount int) error {
	for i := range insertCount {
		table := tables[i%len(tables)]
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		if i%2 == 0 {
			err := tx.Del(ctx, table, key[:])
			if err != nil {
				return fmt.Errorf("del %v: %v %v", table, i, err)
			}
		} else {
			// Assert odd record exist
			var valueExpected [8]byte
			binary.BigEndian.PutUint64(valueExpected[:], uint64(i))
			value, err := tx.Get(ctx, table, key[:])
			if err != nil {
				return fmt.Errorf("even get %v: %v %v", table, i, err)
			}
			if !bytes.Equal(value, valueExpected[:]) {
				return fmt.Errorf("even get unequal %v: %v", table, i)
			}
		}
	}
	return nil
}

func txdelInvalidKey(ctx context.Context, tx Transaction, table string) error {
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], uint32(0))
	err := tx.Del(ctx, table, key[:])
	if err != nil {
		return fmt.Errorf("del invalid key %v: %w", table, err)
	}
	return nil
}

func dbBasic(ctx context.Context, db Database, tables []string, insertCount int) error {
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
func dbTransactionsRollback(ctx context.Context, db Database, tables []string, insertCount int) error {
	tx, err := db.Begin(ctx, true)
	if err != nil && !errors.Is(err, ErrDBClosed) {
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
func dbTransactionsCommit(ctx context.Context, db Database, tables []string, insertCount int) error {
	tx, err := db.Begin(ctx, true)
	if err != nil {
		return fmt.Errorf("db begin: %w", err)
	}
	defer func() {
		if err != nil {
			err = tx.Rollback(ctx)
			if err != nil && !errors.Is(err, ErrDBClosed) {
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
// This will race for PebbleDB since it doesn't have real
// transactions, and instead must rely on batches.
func dbTransactionsMultipleWrite(ctx context.Context, db Database, table string, txCount int) error {
	last := txCount + 1
	var key [4]byte
	var val [8]byte
	binary.BigEndian.PutUint32(key[:], uint32(0))
	binary.BigEndian.PutUint64(val[:], uint64(last))
	err := db.Put(ctx, table, key[:], val[:])
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
					if err != nil && !errors.Is(err, ErrDBClosed) {
						panic(fmt.Errorf("tx%d - tx rollback: %w", i, err))
					}
				}
			}()
			// see if value set by last tx matches "last"
			var ve [8]byte
			binary.BigEndian.PutUint64(ve[:], uint64(last))
			rv, err := tx.Get(ctx, table, key[:])
			if err != nil {
				return fmt.Errorf("tx%d - get: %w", i, err)
			}
			if !bytes.Equal(rv, ve[:]) {
				return fmt.Errorf("tx%d - expected %v, got %v", i, ve[:], rv)
			}

			// set value and "last" to "i"
			binary.BigEndian.PutUint64(ve[:], uint64(i))
			err = tx.Put(ctx, table, key[:], ve[:])
			if err != nil {
				return fmt.Errorf("tx put %v: %v", table, i)
			}
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
func dbTransactionsDelete(ctx context.Context, db Database, tables []string, insertCount int) error {
	tx, err := db.Begin(ctx, true)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			err = tx.Rollback(ctx)
			if err != nil && !errors.Is(err, ErrDBClosed) {
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
func dbTransactionsErrors(ctx context.Context, db Database, tables []string, insertCount int) error {
	tx, err := db.Begin(ctx, true)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			err = tx.Rollback(ctx)
			if err != nil && !errors.Is(err, ErrDBClosed) {
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

func dbIterate(ctx context.Context, db Database, table string, recordCount int) error {
	for i := range recordCount {
		err := db.Put(ctx, table, []byte{uint8(i)}, []byte{uint8(i)})
		if err != nil {
			return err
		}
	}

	// Verify that Next returns the first record.
	it1, err := db.NewIterator(ctx, table)
	if err != nil {
		return err
	}
	i := 0
	for it1.Next(ctx) {
		i++
	}
	defer func() {
		it1.Close(ctx)
	}()

	// Verify that Next returns the Next record after a seek.
	it2, err := db.NewIterator(ctx, table)
	if err != nil {
		return err
	}
	defer func() {
		it2.Close(ctx)
	}()

	if !it2.Seek(ctx, []byte{1}) {
		return errors.New("seek 1")
	}
	if !it2.Next(ctx) {
		return errors.New("next")
	}
	if !bytes.Equal(it2.Key(ctx), []byte{2}) {
		return fmt.Errorf("not equal seek, got %v wanted %v", it2.Key(ctx), []byte{2})
	}
	// Verify First while here
	if !it2.First(ctx) {
		return errors.New("first")
	}
	if !bytes.Equal(it2.Key(ctx), []byte{uint8(0)}) {
		return fmt.Errorf("not equal first, got %v wanted %v", it2.Key(ctx), []byte{0})
	}
	// Verify Last while here
	if !it2.Last(ctx) {
		return errors.New("last")
	}
	if !bytes.Equal(it2.Key(ctx), []byte{uint8(recordCount - 1)}) {
		return fmt.Errorf("not equal last, got %v wanted %v",
			it2.Key(ctx), []byte{uint8(recordCount - 1)})
	}

	return nil
}

func dbRange(ctx context.Context, db Database, table string, recordCount int) error {
	// Stuff a bunch of records into the same table to validate that ranges
	// don't over or underflow.
	for i := 0; i < recordCount; i++ {
		// Emulate user records "userXXXX"
		var key [8]byte
		copy(key[:], []byte(fmt.Sprintf("user%04v", i)))
		value := make([]byte, len(key)*2)
		copy(value[len(key):], key[:])
		err := db.Put(ctx, table, key[:], value)
		if err != nil {
			return fmt.Errorf("put %v %v: %w", table, key, err)
		}

		// Emulate user records "passXXXX"
		var pkey [8]byte
		copy(pkey[:], []byte{'p', 'a', 's', 's'})
		binary.BigEndian.PutUint32(pkey[4:], uint32(i))
		err = db.Put(ctx, table, pkey[:], nil)
		if err != nil {
			return fmt.Errorf("put %v %v: %w", table, key, err)
		}

		// Emulate avatar records "avatarXXXX"
		var akey [10]byte
		copy(akey[:], []byte{'a', 'v', 'a', 't', 'a', 'r'})
		binary.BigEndian.PutUint32(akey[6:], uint32(i))
		err = db.Put(ctx, table, akey[:], nil)
		if err != nil {
			return fmt.Errorf("put %v %v: %w", table, key, err)
		}
	}

	// Verify all records were inserted
	var start [8]byte
	var end [8]byte
	copy(start[:], []byte(fmt.Sprintf("user%04v", 0)))
	copy(end[:], []byte(fmt.Sprintf("user%04v", recordCount)))

	it, err := db.NewRange(ctx, table, start[:], end[:])
	if err != nil {
		return fmt.Errorf("new range: %w", err)
	}
	defer func() {
		it.Close(ctx)
	}()
	i := 0
	for it.Next(ctx) {
		expectedKey := []byte(fmt.Sprintf("user%04d", i))
		if !bytes.Equal(it.Key(ctx), expectedKey) {
			return fmt.Errorf("invalid key got %v wanted %v",
				spew.Sdump(it.Key(ctx)), spew.Sdump(expectedKey))
		}
		expectedValue := make([]byte, len(expectedKey)*2)
		copy(expectedValue[len(expectedKey):], expectedKey)
		if !bytes.Equal(it.Value(ctx), expectedValue) {
			return fmt.Errorf("invalid value got %x wanted %x", it.Value(ctx), expectedValue)
		}
		i++
	}
	if i != recordCount {
		return fmt.Errorf("invalid record count got %v want %v", i, recordCount)
	}

	return nil
}

func TestGKVDB(t *testing.T) {
	type TestTableItem struct {
		name   string
		dbFunc func(home string, tables []string) Database
	}

	testTable := []TestTableItem{
		// {
		// 	name: "nutsDB",
		// 	dbFunc: func(home string, tables []string) Database {
		// 		cfg := DefaultNutsConfig(home, tables)
		// 		db, err := NewNutsDB(cfg)
		// 		if err != nil {
		// 			t.Fatal(err)
		// 		}
		// 		return db
		// 	},
		// },
		{
			name: "levelDB",
			dbFunc: func(home string, tables []string) Database {
				cfg := DefaultLevelConfig(home, tables)
				db, err := NewLevelDB(cfg)
				if err != nil {
					t.Fatal(err)
				}
				return db
			},
		},
		{
			name: "pebbleDB",
			dbFunc: func(home string, tables []string) Database {
				cfg := DefaultPebbleConfig(home, tables)
				db, err := NewPebbleDB(cfg)
				if err != nil {
					t.Fatal(err)
				}
				return db
			},
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 13*time.Second)
			defer cancel()

			// Puts
			insertCount := 100
			t.Run("basic", func(t *testing.T) {
				home := t.TempDir()

				tableCount := 5
				tables := make([]string, 0, tableCount)
				for i := range tableCount {
					tables = append(tables, fmt.Sprintf("table%v", i))
				}

				db := tti.dbFunc(home, tables)
				err := db.Open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err = dbBasic(ctx, db, tables, insertCount); err != nil {
					t.Fatal(err)
				}
			})

			t.Run("transactions", func(t *testing.T) {
				home := t.TempDir()

				tableCount := 5
				tables := make([]string, 0, tableCount)
				for i := range tableCount {
					tables = append(tables, fmt.Sprintf("table%v", i))
				}

				db := tti.dbFunc(home, tables)
				err := db.Open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err = dbTransactionsRollback(ctx, db, tables, insertCount); err != nil {
					t.Fatal(fmt.Errorf("dbTransactionsRollback: %w", err))
				}
				if err = dbTransactionsCommit(ctx, db, tables, insertCount); err != nil {
					t.Fatal(fmt.Errorf("dbTransactionsCommit: %w", err))
				}
				if err = dbTransactionsDelete(ctx, db, tables, insertCount); err != nil {
					t.Fatal(fmt.Errorf("dbTransactionsDelete: %w", err))
				}
				if err = dbTransactionsErrors(ctx, db, tables, insertCount); err != nil {
					t.Fatal(fmt.Errorf("dbTransactionsErrors: %w", err))
				}
				if err = dbTransactionsMultipleWrite(ctx, db, tables[0], 5); err != nil {
					t.Fatal(fmt.Errorf("dbTransactionsErrors: %w", err))
				}
			})

			t.Run("iterator", func(t *testing.T) {
				home := t.TempDir()

				table := "mytable"
				tables := []string{table}

				db := tti.dbFunc(home, tables)

				err := db.Open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err = dbIterate(ctx, db, table, 10); err != nil {
					t.Fatal(err)
				}
			})

			t.Run("range", func(t *testing.T) {
				home := t.TempDir()

				table := "mytable"
				tables := []string{table}

				db := tti.dbFunc(home, tables)

				err := db.Open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err = dbRange(ctx, db, table, 10); err != nil {
					t.Fatal(err)
				}
			})

			t.Run("batch", func(t *testing.T) {
				home := t.TempDir()

				table := "users"
				tables := []string{table}

				db := tti.dbFunc(home, tables)

				err := db.Open(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					err := db.Close(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}()

				if err = dbBatch(ctx, db, table, 10); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func dbBatch(ctx context.Context, db Database, table string, recordCount int) error {
	// Stuff a bunch of records into the same table to validate that
	// everything is executed as expected.
	b, err := db.NewBatch(ctx)
	if err != nil {
		return fmt.Errorf("new batch: %w", err)
	}

	for i := 0; i < recordCount; i++ {
		// Emulate user records "userXXXX"
		var key [8]byte
		copy(key[:], []byte(fmt.Sprintf("user%04v", i)))
		value := make([]byte, len(key)*2)
		copy(value[len(key):], key[:])
		b.Put(ctx, table, key[:], value)

		// Emulate user records "passXXXX"
		var pkey [8]byte
		copy(pkey[:], []byte(fmt.Sprintf("pass%04v", i)))
		eval := []byte(fmt.Sprintf("thisisapassword%v", i))
		b.Put(ctx, table, pkey[:], eval)

		// Emulate avatar records "avatarXXXX"
		akey := []byte(fmt.Sprintf("avatar%d", i))
		aval := []byte(fmt.Sprintf("thisisavatar%d", i))
		b.Put(ctx, table, akey, aval)
	}
	err = db.Update(ctx, func(ctx context.Context, tx Transaction) error {
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

	// XXX nutsb has a huge limitation. We cannot iterate and perform
	// actions on a WriteBatch. This is an odd decision but the net is it
	// deadlocks the reads and writes (iterator rlocks then the del/put
	// locks thus deadlocking).
	//
	// The solution must come from within nuts because there is a need to
	// atomic read some shit and perform a write. Maybe the answer is using
	// nutsdb.Tx.CommitWith(). Investigate this.
	// For now use a shitty raceable non-atomic test.
	//
	// In addition to shity mutex use, we cannot do this either in tests:
	//
	// NewIterator()
	// t.Fatal()
	//
	// This will deadlock on the defer db.Close because of outstanding
	// transactions that haven't been closed.
	i := 0
	bd, err := db.NewBatch(ctx)
	if err != nil {
		return fmt.Errorf("new batch: %w", err)
	}

	for it.Next(ctx) {
		key := append([]byte{}, it.Key(ctx)...)
		// XXX can't do this with nutsdb
		bd.Del(ctx, table, key)
		i++
	}
	if i != recordCount*3 {
		return fmt.Errorf("invalid record count got %v, wanted %v", i, recordCount*3)
	}

	err = db.Update(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Write(ctx, b)
	})
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	// Close iterator so that we don't block
	it.Close(ctx)

	return nil
}
