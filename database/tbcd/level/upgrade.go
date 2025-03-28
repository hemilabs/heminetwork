// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/level"
)

// marco: I decided against copying tables to move them from compressed to
// uncompressed during the v2 to v3 upgrade. The copy function on the other
// hand is pretty nifty o we are keeping it here commented out until the day we
// need it.

//var batchSize = 10000
//
//// copyOrMoveTable copies or moves a table record by record from a to b. If
//// move is true the record is deleted from a after being copied to b.
//func copyOrMoveTable(move bool, a, b *leveldb.DB) (int, error) {
//	i := a.NewIterator(nil, nil)
//	defer func() { i.Release() }()
//
//	r := 0
//	batchA := leveldb.MakeBatch(batchSize) // delete batch
//	batchB := leveldb.MakeBatch(batchSize) // copy batch
//	for {
//		records := 0
//		for records = 0; i.Next() && records < batchSize; records++ {
//			// Create batches to speed things up a bit.
//			batchB.Put(i.Key(), i.Value())
//			if move {
//				batchA.Delete(i.Key())
//			}
//		}
//		r += records
//
//		if err := b.Write(batchB, nil); err != nil {
//			return r, fmt.Errorf("batch write b: %w", err)
//		}
//		batchB.Reset()
//
//		if move {
//			// Delete destination records
//			if err := a.Write(batchA, nil); err != nil {
//				return r, fmt.Errorf("batch write a: %w", err)
//			}
//			batchA.Reset()
//		}
//		if records == 0 {
//			break
//		}
//	}
//	return r, i.Error()
//}
//
// example code on how to move databases
//	// sort database names
//	keys := make([]string, 0, len(l.pool))
//	for k := range l.pool {
//		keys = append(keys, k)
//	}
//	sort.Strings(keys)
//
//	// copy all databases
//	for _, dbs := range keys {
//		log.Infof("Moving database: %v", dbs)
//		a := l.pool[dbs]
//		b := d.DB()[dbs]
//		n, err := copyOrMoveTable(false, a, b)
//		if err != nil {
//			return fmt.Errorf("move database %v: %w", dbs, err)
//		}
//		log.Infof("Database %v records moved: %v", dbs, n)
//	}

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
// Add compression flag to the metadata database. Original v2 databases were
// compressed by default. We use this flag to warn the user that the database
// is used in mixed mode and a resync is recommended. The code to do this
// automatically is super painful.
func (l *ldb) v3(ctx context.Context) error {
	log.Tracef("v3")
	defer log.Tracef("v3 exit")

	log.Infof("Upgrading database from v2 to v3")

	// Make sure compression flag does not exist
	_, err := l.MetadataGet(ctx, CompressionKey)
	if !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("expected compression flag to not exist: %w", err)
	}

	// Since we are upgrading from v2 we know this is a compressed db.
	err = l.MetadataPut(ctx, CompressionKey, []byte{0})
	if err != nil {
		return fmt.Errorf("could not write compresion flag: %w", err)
	}

	// Write new version
	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, 3)
	return l.MetadataPut(ctx, versionKey, v)
}
