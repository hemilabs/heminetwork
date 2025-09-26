// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"sync"

	"github.com/hemilabs/larry/larry"
	"github.com/hemilabs/larry/larry/multi"
	"github.com/hemilabs/larry/larry/rawdb"
	"github.com/juju/loggo/v2"
	"github.com/mitchellh/go-homedir"

	"github.com/hemilabs/heminetwork/v2/database"
)

const (
	logLevel = "INFO"

	BlockHeadersDB   = "blockheaders"
	BlocksMissingDB  = "blocksmissing"
	MetadataDB       = "metadata"
	KeystonesDB      = "keystones"
	HeightHashDB     = "heighthash"
	OutputsDB        = "outputs"
	TransactionsDB   = "transactions"
	ZKDB             = "zkindex"
	ZKOutpointsDB    = "zkoutpoints"
	ZKSpendableOutDB = "zkspendableout"
	ZKSpentOutDB     = "zkspentout"
	ZKSpentTxDB      = "zkspenttx"

	BlocksDB = "blocks" // raw database
)

var log = loggo.GetLogger("level")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type RawPool map[string]*rawdb.RawDB

type Database struct {
	mtx     sync.RWMutex
	pool    larry.Database // database pool
	rawPool RawPool        // raw database pool

	home   string
	tables map[string]string
}

var _ database.Database = (*Database)(nil)

func (l *Database) Close(ctx context.Context) error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	l.mtx.Lock()
	defer l.mtx.Unlock()

	var errSeen error

	for k, v := range l.rawPool {
		if err := v.Close(ctx); err != nil {
			// do continue, leveldb does not like unfresh shutdowns
			log.Errorf("close %v: %v", k, err)
			errSeen = errors.Join(errSeen, err)
		}
		delete(l.rawPool, k)
	}

	if err := l.pool.Close(ctx); err != nil {
		log.Errorf("close pool: %v", err)
		errSeen = errors.Join(errSeen, err)
	}

	return errSeen
}

func (l *Database) DB() larry.Database {
	log.Tracef("DB")
	defer log.Tracef("DB exit")

	l.mtx.RLock()
	defer l.mtx.RUnlock()
	return l.pool
}

func (l *Database) RawDB() RawPool {
	log.Tracef("RawDB")
	defer log.Tracef("RawDB exit")

	l.mtx.RLock()
	defer l.mtx.RUnlock()
	return maps.Clone(l.rawPool)
}

func (l *Database) Tables() map[string]string {
	log.Tracef("Tables")
	defer log.Tracef("Tables exit")

	l.mtx.RLock()
	defer l.mtx.RUnlock()
	return maps.Clone(l.tables)
}

func (l *Database) openRawDB(ctx context.Context, name string, blockSize int64) error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	dir := filepath.Join(l.home, name)
	rcfg := rawdb.NewDefaultConfig(dir)
	rcfg.DB = "level"
	rcfg.MaxSize = blockSize
	rdb, err := rawdb.New(rcfg)
	if err != nil {
		return fmt.Errorf("rawdb new %v: %w", name, err)
	}
	err = rdb.Open(ctx)
	if err != nil {
		return fmt.Errorf("rawdb open %v: %w", name, err)
	}
	l.rawPool[name] = rdb

	return nil
}

func New(ctx context.Context, home string) (*Database, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	// Care must be taken to not shadow err and l in this function. The
	// defer will overwrite those if an unwind condition occurs.

	h, err := homedir.Expand(home)
	if err != nil {
		return nil, fmt.Errorf("home dir: %w", err)
	}

	poolMap := map[string]string{
		BlockHeadersDB:   "level",
		BlocksMissingDB:  "level",
		MetadataDB:       "level",
		KeystonesDB:      "level",
		HeightHashDB:     "level",
		OutputsDB:        "level",
		TransactionsDB:   "level",
		ZKOutpointsDB:    "level",
		ZKSpendableOutDB: "level",
		ZKSpentOutDB:     "level",
		ZKSpentTxDB:      "level",
		ZKDB:             "level",
	}

	// MultiDB makes the directory path for home
	mcfg := multi.DefaultMultiConfig(home, poolMap)
	pool, err := multi.NewMultiDB(mcfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Open(ctx); err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}

	l := &Database{
		home:    h,
		pool:    pool,
		rawPool: make(RawPool),
		tables:  poolMap,
	}

	unwind := true
	defer func() {
		if unwind {
			cerr := l.Close(ctx)
			if cerr != nil {
				log.Debugf("new unwind exited with: %v", cerr)
				err = errors.Join(err, cerr)
			}
			clear(l.rawPool)
			l = nil // Reset l
		}
	}()

	// Blocks database is special
	err = l.openRawDB(ctx, BlocksDB, rawdb.DefaultMaxFileSize)
	if err != nil {
		return nil, fmt.Errorf("rawdb %v: %w", BlocksDB, err)
	}

	unwind = false // Everything is good, do not unwind.

	// The defer above will set/reset these values.
	return l, err
}
