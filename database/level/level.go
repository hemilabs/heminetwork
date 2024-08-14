// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/juju/loggo"
	"github.com/mitchellh/go-homedir"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/rawdb"
)

const (
	logLevel = "INFO"

	BlockHeadersDB  = "blockheaders"
	BlocksMissingDB = "blocksmissing"
	MetadataDB      = "metadata"
	HeightHashDB    = "heighthash"
	PeersDB         = "peers"
	OutputsDB       = "outputs"
	TransactionsDB  = "transactions"

	BlocksDB = "blocks" // raw database

	versionKey      = "version"
	databaseVersion = 1
)

var log = loggo.GetLogger("level")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type Pool map[string]*leveldb.DB

type RawPool map[string]*rawdb.RawDB

type Database struct {
	mtx     sync.RWMutex
	pool    Pool    // database pool
	rawPool RawPool // raw database pool

	home string // leveldb toplevel database directory
}

var _ database.Database = (*Database)(nil)

func (l *Database) Close() error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	l.mtx.Lock()
	defer l.mtx.Unlock()

	var errSeen error

	for k, v := range l.rawPool {
		if err := v.Close(); err != nil {
			// do continue, leveldb does not like unfresh shutdowns
			log.Errorf("close %v: %v", k, err)
			errSeen = errors.Join(errSeen, err)
		}
	}

	for k, v := range l.pool {
		if err := v.Close(); err != nil {
			// do continue, leveldb does not like unfresh shutdowns
			log.Errorf("close %v: %v", k, err)
			errSeen = errors.Join(errSeen, err)
		}
	}

	return errSeen
}

func (l *Database) DB() Pool {
	log.Tracef("DB")
	defer log.Tracef("DB exit")

	return l.pool
}

func (l *Database) RawDB() RawPool {
	log.Tracef("RawDB")
	defer log.Tracef("RawDB exit")

	return l.rawPool
}

func (l *Database) RegisterNotification(ctx context.Context, n database.NotificationName, f database.NotificationCallback, payload any) error {
	log.Tracef("RegisterNotification")
	defer log.Tracef("RegisterNotification exit")

	return errors.New("unsupported")
}

func (l *Database) UnregisterNotification(n database.NotificationName) error {
	log.Tracef("UnregisterNotification")
	defer log.Tracef("UnregisterNotification exit")

	return errors.New("unsupported")
}

func (l *Database) openDB(name string, options *opt.Options) error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	bhs := filepath.Join(l.home, name)
	bhsDB, err := leveldb.OpenFile(bhs, options)
	if err != nil {
		return fmt.Errorf("leveldb open %v: %w", name, err)
	}
	l.pool[name] = bhsDB

	return nil
}

func (l *Database) openRawDB(name string, blockSize int64) error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	dir := filepath.Join(l.home, name)
	rdb, err := rawdb.New(dir, blockSize)
	if err != nil {
		return fmt.Errorf("rawdb new %v: %w", name, err)
	}
	err = rdb.Open()
	if err != nil {
		return fmt.Errorf("rawdb open %v: %w", name, err)
	}
	l.rawPool[name] = rdb

	return nil
}

func (l *Database) Version(ctx context.Context) (int, error) {
	mdDB := l.pool[MetadataDB]
	value, err := mdDB.Get([]byte(versionKey), nil)
	if err != nil {
		return -1, fmt.Errorf("version: %w", err)
	}
	var dbVersion uint64
	dbVersion = binary.BigEndian.Uint64(value)

	return int(dbVersion), nil
}

func New(ctx context.Context, home string, version int) (*Database, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	h, err := homedir.Expand(home)
	if err != nil {
		return nil, fmt.Errorf("home dir: %w", err)
	}
	err = os.MkdirAll(h, 0o0700)
	if err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	l := &Database{
		home:    h,
		pool:    make(Pool),
		rawPool: make(RawPool),
	}

	unwind := true
	defer func() {
		if unwind {
			log.Errorf("new unwind exited with: %v", l.Close())
		}
	}()

	err = l.openDB(BlockHeadersDB, nil)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", BlockHeadersDB, err)
	}
	err = l.openDB(BlocksMissingDB, nil)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", BlocksMissingDB, err)
	}
	err = l.openDB(HeightHashDB, nil)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", HeightHashDB, err)
	}
	err = l.openDB(PeersDB, nil)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", PeersDB, err)
	}
	err = l.openDB(OutputsDB, nil)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", OutputsDB, err)
	}
	err = l.openDB(TransactionsDB, nil)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", TransactionsDB, err)
	}

	// Blocks database is special
	err = l.openRawDB(BlocksDB, rawdb.DefaultMaxFileSize)
	if err != nil {
		return nil, fmt.Errorf("rawdb %v: %w", BlocksDB, err)
	}

	// Treat metadata special so that we can insert some stuff.
	err = l.openDB(MetadataDB, &opt.Options{ErrorIfMissing: true})
	if errors.Is(err, fs.ErrNotExist) {
		err = l.openDB(MetadataDB, &opt.Options{ErrorIfMissing: false})
		if err != nil {
			return nil, fmt.Errorf("leveldb initial %v: %w", MetadataDB, err)
		}
		versionData := make([]byte, 8)
		binary.BigEndian.PutUint64(versionData, databaseVersion)
		err = l.pool[MetadataDB].Put([]byte(versionKey), versionData, nil)
	}
	// Check metadata error
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", MetadataDB, err)
	}
	dbVersion, err := l.Version(ctx)
	if err != nil {
		return nil, err
	}
	if dbVersion != version {
		return nil, fmt.Errorf("invalid version: wanted %v got %v",
			dbVersion, version)
	}

	unwind = false

	return l, nil
}
