// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hemilabs/heminetwork/database/level"
)

var batchSize = 100000

// copyOrMoveTable copies or moves a table record by record from a to b. If
// move is true the record is deleted from a after being copied to b.
func copyOrMoveTable(ctx context.Context, move bool, a, b *leveldb.DB) (int, error) {
	i := a.NewIterator(nil, nil)
	defer func() { i.Release() }()

	r := 0
	batchA := leveldb.MakeBatch(batchSize) // delete batch
	batchB := leveldb.MakeBatch(batchSize) // copy batch
	for {
		// See if we were interrupted
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		default:
		}

		start := time.Now()

		records := 0
		for records = 0; i.Next() && records < batchSize; records++ {
			// Create batches to speed things up a bit.
			batchB.Put(i.Key(), i.Value())
			if move {
				batchA.Delete(i.Key())
			}
		}
		r += records

		if err := b.Write(batchB, nil); err != nil {
			return r, fmt.Errorf("batch write b: %w", err)
		}
		batchB.Reset()

		if move {
			// Delete destination records
			if err := a.Write(batchA, nil); err != nil {
				return r, fmt.Errorf("batch write a: %w", err)
			}
			batchA.Reset()
		}

		log.Infof("  records moved: %v, %v in %v", records, r, time.Since(start))

		if records == 0 {
			break
		}
	}
	return r, i.Error()
}

func (l *ldb) insertTable(dbname string, key, value []byte) error {
	db := l.pool[dbname]
	if db == nil {
		return fmt.Errorf("invalid db: %v", db)
	}
	return db.Put(key, value, nil)
}

func (l *ldb) deleteTable(dbname string, key []byte) error {
	db := l.pool[dbname]
	if db == nil {
		return fmt.Errorf("invalid db: %v", db)
	}
	return db.Delete(key, nil)
}

// v2 upgrade the database from v1 to v2.
// Changes:
// Move utxoindexhash, txindexhash and keystoneindexhash from metadata database
// to their respective index databases.
func (l *ldb) v2(ctx context.Context) error {
	log.Tracef("v2")
	defer log.Tracef("v2 exit")

	log.Infof("Upgrading database from v1 to v2")

	// update outputs index hash
	utxoH, err := l.MetadataGet(ctx, utxoIndexHashKey)
	if err == nil {
		err := l.insertTable(level.OutputsDB, utxoIndexHashKey, utxoH)
		if err != nil {
			return fmt.Errorf("insert table %v: %w", level.OutputsDB, err)
		}
		err = l.deleteTable(level.MetadataDB, utxoIndexHashKey)
		if err != nil {
			return fmt.Errorf("delete table %v: %w", level.OutputsDB, err)
		}
	}

	// update transaction index hash
	txH, err := l.MetadataGet(ctx, txIndexHashKey)
	if err == nil {
		err := l.insertTable(level.TransactionsDB, txIndexHashKey, txH)
		if err != nil {
			return fmt.Errorf("insert table %v: %w", level.TransactionsDB, err)
		}
		err = l.deleteTable(level.MetadataDB, txIndexHashKey)
		if err != nil {
			return fmt.Errorf("delete table %v: %w", level.TransactionsDB, err)
		}
	}

	// update keystone index hash
	keystoneH, err := l.MetadataGet(ctx, keystoneIndexHashKey)
	if err == nil {
		err := l.insertTable(level.KeystonesDB, keystoneIndexHashKey, keystoneH)
		if err != nil {
			return fmt.Errorf("insert table %v: %w", level.KeystonesDB, err)
		}
		err = l.deleteTable(level.MetadataDB, keystoneIndexHashKey)
		if err != nil {
			return fmt.Errorf("delete table %v: %w", level.KeystonesDB, err)
		}
	}

	// Write new version
	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, 2)
	return l.MetadataPut(ctx, versionKey, v)
}

// v3 upgrade the database from v2 to v3.
// Changes:
// Move databases from compressed to uncompressed state.
func (l *ldb) v3(ctx context.Context) error {
	log.Tracef("v3")
	defer log.Tracef("v3 exit")

	log.Infof("Upgrading database from v2 to v3")
	// example code on how to move databases
	// sort database names
	keys := make([]string, 0, len(l.pool))
	for k := range l.pool {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// copy config and create database destination.
	dcfg := *l.cfg
	dcfg.Home = dcfg.Home + ".v3"
	dst, err := New(ctx, &dcfg)
	if err != nil {
		return fmt.Errorf("open destination database: %w", err)
	}

	// copy all databases
	for _, dbs := range keys {
		// See if we were interrupted
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Infof("Moving database: %v", dbs)
		a := l.pool[dbs]
		b := dst.DB()[dbs]
		n, err := copyOrMoveTable(ctx, false, a, b)
		if err != nil {
			return fmt.Errorf("move database %v: %w", dbs, err)
		}
		log.Infof("Database %v records moved: %v", dbs, n)
	}

	//// Write new version
	//v := make([]byte, 8)
	//binary.BigEndian.PutUint64(v, 3)
	//return l.MetadataPut(ctx, versionKey, v)
	return fmt.Errorf("not yet")
}
