// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"errors"
	"fmt"
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
	KeystonesDB     = "keystones"
	HeightHashDB    = "heighthash"
	OutputsDB       = "outputs"
	TransactionsDB  = "transactions"

	BlocksDB = "blocks" // raw database
)

var log = loggo.GetLogger("level")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Pool map[string]*leveldb.DB

type RawPool map[string]*rawdb.RawDB

type Database struct {
	mtx     sync.RWMutex
	pool    Pool    // database pool
	rawPool RawPool // raw database pool

	cfg *Config
}

type Config struct {
	Home    string
	Options opt.Options
}

func NewDefaultConfig(home string) *Config {
	return &Config{
		Home: home, // leveldb toplevel database directory
		Options: opt.Options{
			BlockCacheEvictRemoved: true, // Do yourself a favor and leave this one alone
			Compression:            opt.NoCompression,
		},
	}
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
		delete(l.rawPool, k)
	}

	for k, v := range l.pool {
		if err := v.Close(); err != nil {
			// do continue, leveldb does not like unfresh shutdowns
			log.Errorf("close %v: %v", k, err)
			errSeen = errors.Join(errSeen, err)
		}
		delete(l.pool, k)
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

func (l *Database) openDB(name string) error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	bhs := filepath.Join(l.cfg.Home, name)
	bhsDB, err := leveldb.OpenFile(bhs, &l.cfg.Options)
	if err != nil {
		return fmt.Errorf("leveldb open %v: %w", name, err)
	}
	l.pool[name] = bhsDB

	return nil
}

func (l *Database) openRawDB(name string, blockSize int64) error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	dir := filepath.Join(l.cfg.Home, name)
	rdb, err := rawdb.New(&rawdb.Config{Home: dir, MaxSize: blockSize})
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

func New(ctx context.Context, cfg *Config) (*Database, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	if cfg == nil {
		return nil, errors.New("must provide database config")
	}

	// Care must be taken to not shadow err and l in this function. The
	// defer will overwrite those if an unwind condition occurs.

	h, err := homedir.Expand(cfg.Home)
	if err != nil {
		return nil, fmt.Errorf("home dir: %w", err)
	}
	err = os.MkdirAll(h, 0o0700)
	if err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	cfg.Home = h

	l := &Database{
		cfg:     cfg,
		pool:    make(Pool),
		rawPool: make(RawPool),
	}

	unwind := true
	defer func() {
		if unwind {
			cerr := l.Close()
			if cerr != nil {
				log.Debugf("new unwind exited with: %v", cerr)
				err = errors.Join(err, cerr)
			}
			clear(l.pool)
			clear(l.rawPool)
			l = nil // Reset l
		}
	}()

	// Open all databases
	err = l.openDB(BlockHeadersDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", BlockHeadersDB, err)
	}
	err = l.openDB(BlocksMissingDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", BlocksMissingDB, err)
	}
	err = l.openDB(HeightHashDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", HeightHashDB, err)
	}
	err = l.openDB(OutputsDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", OutputsDB, err)
	}
	err = l.openDB(TransactionsDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", TransactionsDB, err)
	}
	err = l.openDB(KeystonesDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", KeystonesDB, err)
	}
	err = l.openDB(MetadataDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", MetadataDB, err)
	}

	// Blocks database is special
	err = l.openRawDB(BlocksDB, rawdb.DefaultMaxFileSize)
	if err != nil {
		return nil, fmt.Errorf("rawdb %v: %w", BlocksDB, err)
	}

	unwind = false // Everything is good, do not unwind.

	// The defer above will set/reset these values.
	return l, err
}
