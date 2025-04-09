// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mitchellh/go-homedir"
	cp "github.com/otiai10/copy"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/hemilabs/heminetwork/database/level"
	"github.com/hemilabs/heminetwork/rawdb"
)

var (
	upgradeVerbose = true
	batchSize      = 25_000_000    // move twentyfive million records per batch
	chunkSize      = 1_000_000_000 // 1GB

	modeMove = true
)

func SetMode(move bool) {
	modeMove = move
}

func SetBatchSize(size int) {
	batchSize = size
}

type CMResult struct {
	Records int        // Number of records
	Skipped int        // Number of records skipped
	Size    int        // Total amount of data
	Range   util.Range // Start and Limit of operation
}

//func dumpDB(ctx context.Context, a *leveldb.DB) error {
//	i := a.NewIterator(&util.Range{Start: nil, Limit: nil}, nil)
//	defer func() { i.Release() }()
//
//	for records := 0; i.Next(); records++ {
//		log.Infof("%04v: %x", records, i.Key())
//	}
//	return i.Error()
//}

func copyOrMoveChunk(ctx context.Context, move bool, a, b *leveldb.DB, dbname string, filter map[string]string, first []byte) (*CMResult, error) {
	skipOne := false
	if !move && first != nil {
		// When copying skip one record since incoming first is the
		// last compacted record and thus we will loop forever.
		skipOne = true
	}
	i := a.NewIterator(&util.Range{Start: first, Limit: nil}, nil)
	defer func() { i.Release() }()

	// skip first record record during copy to preven infinite loops.
	var cmr CMResult
	if skipOne {
		if !i.Next() {
			return &cmr, i.Error()
		}
	}

	start := time.Now()

	batchA := leveldb.MakeBatch(batchSize) // delete batch
	batchB := leveldb.MakeBatch(batchSize) // copy batch

	var records int
	for records = 0; i.Next(); records++ {
		// See if we were interrupted
		select {
		case <-ctx.Done():
			return &cmr, ctx.Err()
		default:
		}

		key := bytes.Clone(i.Key())
		val := bytes.Clone(i.Value())
		if filter != nil {
			// skip filtered records
			k, v := filter[string(key)]
			if v && dbname == k {
				log.Infof("  Skip: %v %s", k, key)
				cmr.Skipped++
				continue
			}
		}
		// Create batches to speed things up a bit.
		batchB.Put(key, val)
		if move {
			batchA.Delete(key)
		}

		// Always keep track of range
		if records == 0 {
			cmr.Range.Start = key
		} else {
			cmr.Range.Limit = key
		}

		// update stats
		cmr.Size += len(key) + len(val)

		if cmr.Size > chunkSize || records >= batchSize {
			break
		}
	}
	cmr.Records += records - cmr.Skipped

	if err := b.Write(batchB, nil); err != nil {
		return &cmr, fmt.Errorf("batch write b: %w", err)
	}
	batchB.Reset() // Help gc

	if move {
		// Delete destination records
		if err := a.Write(batchA, nil); err != nil {
			return &cmr, fmt.Errorf("batch write a: %w", err)
		}
		batchA.Reset() // Help gc
	}

	if upgradeVerbose {
		verb := "moved"
		if !move {
			verb = "copy"
		}
		log.Infof("  Records %v: %v %v took %v",
			verb,
			humanize.Comma(int64(cmr.Records)),
			humanize.Bytes(uint64(cmr.Size)), time.Since(start))
	}

	return &cmr, i.Error()
}

func _copyOrMoveTable(ctx context.Context, move bool, a, b *leveldb.DB, dbname string, filter map[string]string) (int, error) {
	var first []byte
	total := 0
	for {
		cmr, err := copyOrMoveChunk(ctx, move, a, b, dbname, filter, first)
		if err != nil {
			return 0, fmt.Errorf("chunk: %w", err)
		}
		total += cmr.Records

		// Compact once we wrote chunkSize data or on exit.
		if move {
			// Compact db to free space on disk
			ct := time.Now()
			log.Infof("  Compacting %v: records %v %v",
				dbname, humanize.Comma(int64(cmr.Records)),
				humanize.Bytes(uint64(cmr.Size)))
			err := a.CompactRange(cmr.Range)
			if err != nil {
				return 0, fmt.Errorf("compaction: %w", err)
			}
			log.Infof("  Compacting took %v", time.Since(ct))
		}

		// This is a bit of a shitty terminator but what happens during
		// copy is that when the database has exactly one record Limit
		// is NOT set.
		if cmr.Records == 0 || cmr.Range.Limit == nil {
			break
		}

		first = cmr.Range.Limit
	}

	return total, nil
}

// copyOrMoveTable copies or moves a table record by record from a to b. If
// move is true the record is deleted from a after being copied to b.
// This function verifies that indeed all records have been moved and will
// restart the copy/move if it didn't.
func copyOrMoveTable(ctx context.Context, move bool, a, b *leveldb.DB, dbname string, filter map[string]string) (int, error) {
	// XXX verify source table is empty on move
	return _copyOrMoveTable(ctx, move, a, b, dbname, filter)
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
	var err error
	dcfg := *l.cfg
	dcfg.Home, err = homedir.Expand(dcfg.Home + ".v3")
	if err != nil {
		return fmt.Errorf("destination expand: %w", err)
	}
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

		// peers database is unused, just drop it.
		if dbs == "peers" {
			continue
		}

		log.Infof("Moving database: %v", dbs)

		a := l.pool[dbs]
		b := dst.DB()[dbs]
		n, err := copyOrMoveTable(ctx, modeMove, a, b, dbs, filter)
		if err != nil {
			return fmt.Errorf("move database %v: %w", dbs, err)
		}
		log.Infof("Database %v records moved: %v",
			dbs, humanize.Comma(int64(n)))
	}

	// copy rawdb, this is a bit trickier because we want to recreate the
	// index and copy the raw block data.
	rkeys := make([]string, 0, len(l.rawPool))
	for k := range l.rawPool {
		rkeys = append(rkeys, k)
	}
	sort.Strings(rkeys)
	cpOpt := cp.Options{
		PreserveTimes:     true,
		PreserveOwner:     true,
		PermissionControl: cp.PerservePermission,
	}
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

		srcdir, err := homedir.Expand(filepath.Join(l.cfg.Home, dbs, rawdb.DataDir))
		if err != nil {
			return fmt.Errorf("expand source dir: %w", err)
		}
		dstdir, err := homedir.Expand(filepath.Join(dcfg.Home, dbs, rawdb.DataDir))
		if err != nil {
			return fmt.Errorf("expand destination dir: %w", err)
		}
		if modeMove {
			// Move raw data, we must recreate the dir because
			// os.Rename fails otherwise.
			// XXX this needs to be redone, too error prone durig restarts.
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
			err := cp.Copy(srcdir, dstdir, cpOpt)
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
		return fmt.Errorf("destination metadata version put: %w", err)
	}
	err = dst.Close()
	if err != nil {
		return fmt.Errorf("destination close: %w", err)
	}

	// If we get here and are in copy mode, we can exit.
	if modeMove {
		// Close source
		err = l.Close()
		if err != nil {
			return fmt.Errorf("source close: %w", err)
		}

		home, err := homedir.Expand(l.cfg.Home)
		if err != nil {
			return fmt.Errorf("expand home dir: %w", err)
		}
		tmpdir := home + ".v2"
		// Rename source directory to $HOME.v2
		log.Infof("Rename source %v -> %v", home, tmpdir)
		err = os.Rename(home, tmpdir)
		if err != nil {
			return fmt.Errorf("rename source: %w", err)
		}

		// Rename destination directory to $HOME
		log.Infof("Rename destination %v -> %v", dcfg.Home, home)
		err = os.Rename(dcfg.Home, home)
		if err != nil {
			return fmt.Errorf("rename destination: %w", err)
		}

		// Delete $HOME.v2
		log.Infof("Delete original source %v", tmpdir)
		err = os.RemoveAll(tmpdir)
		if err != nil {
			return fmt.Errorf("remove source: %w", err)
		}
	} else {
		err = l.MetadataPut(ctx, versionKey, v)
		if err != nil {
			return fmt.Errorf("source metadata version put: %w", err)
		}
		// Close source
		err = l.Close()
		if err != nil {
			return fmt.Errorf("source close: %w", err)
		}
	}

	return nil
}
