// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hemilabs/heminetwork/database/level"
	"github.com/hemilabs/heminetwork/rawdb"

	cp "github.com/otiai10/copy"
)

var (
	upgradeVerbose = false
	batchSize      = 100000

	modeMove = false
)

func SetMode(move bool) {
	modeMove = move
}

// copyOrMoveTable copies or moves a table record by record from a to b. If
// move is true the record is deleted from a after being copied to b.
func copyOrMoveTable(ctx context.Context, move bool, a, b *leveldb.DB, dbname string, filter map[string]string) (int, error) {
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
			if filter != nil {
				// skip filtered records
				k, v := filter[string(i.Key())]
				if v && dbname == k {
					log.Infof("  Skip: %v %s", k, i.Key())
					continue
				}
			}
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

		if upgradeVerbose {
			log.Infof("  records moved: %v, %v in %v",
				records, r, time.Since(start))
		}

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
//
// Note that modeMove is a test flag only! We should not be copying data in
// production, only moving data.
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
	log.Infof("open upgrade db: %v", dcfg.Home)
	dst, err := New(ctx, &dcfg)
	if err != nil {
		return fmt.Errorf("open destination database: %w", err)
	}

	// filter is a map of [key] dbname
	filter := map[string]string{
		string(versionKey): level.MetadataDB,
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
		n, err := copyOrMoveTable(ctx, modeMove, a, b, dbs, filter)
		if err != nil {
			return fmt.Errorf("move database %v: %w", dbs, err)
		}
		log.Infof("Database %v records moved: %v", dbs, n)
	}

	// copy rawdb, this is a bit trickier because we want to recreate the
	// index and copy the raw block data.
	rkeys := make([]string, 0, len(l.rawPool))
	for k := range l.rawPool {
		rkeys = append(rkeys, k)
	}
	sort.Strings(rkeys)
	for _, dbs := range rkeys {
		// See if we were interrupted
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Infof("Moving raw database: %v", dbs)

		a := l.rawPool[dbs].DB()
		b := dst.RawDB()[dbs].DB()
		n, err := copyOrMoveTable(ctx, modeMove, a, b, dbs, filter)
		if err != nil {
			return fmt.Errorf("move raw database %v: %w", dbs, err)
		}
		log.Infof("Raw database %v records moved: %v", dbs, n)

		srcdir := filepath.Join(l.cfg.Home, dbs, rawdb.DataDir)
		dstdir := filepath.Join(dcfg.Home, dbs, rawdb.DataDir)
		if modeMove {
			// Move raw data, we must recreate the dir because
			// os.Rename fails otherwise.
			log.Infof("  Moving raw data: %v -> %v", srcdir, dstdir)
			err := os.Remove(dstdir)
			if err != nil {
				return fmt.Errorf("remove raw data %v: %w", dbs, err)
			}
			err = os.Rename(srcdir, dstdir)
			if err != nil {
				return fmt.Errorf("move raw data %v: %w", dbs, err)
			}
		} else {
			// Copy raw data
			log.Infof("  Copying raw data: %v -> %v", srcdir, dstdir)
			err := cp.Copy(srcdir, dstdir)
			if err != nil {
				return fmt.Errorf("copy raw data %v: %w", dbs, err)
			}
		}

	}

	// Write version to destination and close the database.
	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, 3)
	err = dst.MetadataPut(ctx, versionKey, v)
	if err != nil {
		return fmt.Errorf("destination metadata version put: %v", err)
	}
	err = dst.Close()
	if err != nil {
		return fmt.Errorf("destination close: %v", err)
	}

	// If we get here and are in copy mode, we can exit.
	if modeMove {
		// Close source
		err = l.Close()
		if err != nil {
			return fmt.Errorf("source close: %v", err)
		}

		tmpdir := l.cfg.Home + ".v2"
		// Rename source directory to $HOME.v2
		log.Infof("Rename source %v -> %v", l.cfg.Home, tmpdir)

		// Rename destination directory to $HOME
		log.Infof("Rename destination %v -> %v", dcfg.Home, l.cfg.Home)

		// Delete $HOME.v2
		log.Infof("Delete original source %v", tmpdir)

		// Reopen database and replace pools in l
		log.Infof("Reopen database %v", l.cfg.Home)
	}

	return fmt.Errorf("not yet")
}
