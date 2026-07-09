// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"

	"github.com/hemilabs/x/leveldb/leveldb"
	"github.com/hemilabs/x/leveldb/leveldb/filter"
	"github.com/hemilabs/x/leveldb/leveldb/opt"
	"github.com/juju/loggo/v2"
	"github.com/mitchellh/go-homedir"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/rawdb"
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
	ZKDB            = "zkindex"
	OrdinalDB       = "ordinals"

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

	// Shared caches, owned here so their capacity comes from exactly
	// one place and their lifecycle follows the Database. When set,
	// every leveldb (base options and per-DB overrides) uses these
	// instead of private per-DB caches.
	blockCacher opt.Cacher // shared block cache (bytes)
	fileCacher  opt.Cacher // shared table file handle cache (count)

	cfg *Config
}

type Config struct {
	Home    string
	Options opt.Options

	// DBOptions overrides Options for the named database. Entries are
	// typically a copy of Options with write/compaction fields changed.
	// New installs the shared cachers into every entry that does not
	// explicitly set its own, so no database ends up with a private
	// unmanaged cache by accident.
	DBOptions map[string]opt.Options

	// BlockCacheCapacity is the size in bytes of one block cache
	// shared by ALL databases; hot databases claim capacity from the
	// common pool. 0 leaves each database on its private leveldb
	// default (8 MiB each).
	BlockCacheCapacity int

	// OpenFilesCacheCapacity is the number of table file handles
	// shared by ALL databases. 0 leaves each database on its private
	// leveldb default (500 each).
	OpenFilesCacheCapacity int
}

func NewDefaultConfig(home string) *Config {
	return &Config{
		Home: home, // leveldb toplevel database directory
		Options: opt.Options{
			BlockCacheEvictRemoved: true, // Do yourself a favor and leave this one alone
			Compression:            opt.NoCompression,
			Filter:                 filter.NewBloomFilter(10),
			// XXX investigate if this has adverse affect on memory
			// use and i it helps performance at all. ZK indexer
			// may simply be too big for cache to matters.
			// OpenFilesCacheCapacity: 2000,
			// BlockCacheCapacity: 64 * opt.MiB,
			// WriteBuffer:        64 * opt.MiB,
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

	l.mtx.RLock()
	defer l.mtx.RUnlock()
	return maps.Clone(l.pool)
}

func (l *Database) RawDB() RawPool {
	log.Tracef("RawDB")
	defer log.Tracef("RawDB exit")

	l.mtx.RLock()
	defer l.mtx.RUnlock()
	return maps.Clone(l.rawPool)
}

// Config returns a copy of the database configuration with the shared
// cachers installed by New stripped out, so that reusing the returned
// value for a reopen constructs fresh caches instead of resurrecting
// this instance's.
// XXX this remains a band-aid; the other interfaces inside opt.Options
// (Filter, Comparer) are shared references, not deep copies.  Safe
// today because nothing mutates them after open, but a proper fix
// would be to stop duplicating pool/rawPool on ldb and use the
// embedded Database directly.
func (l *Database) Config() Config {
	c := *l.cfg
	c.DBOptions = maps.Clone(c.DBOptions)
	if c.Options.BlockCacher != nil && c.Options.BlockCacher == l.blockCacher {
		c.Options.BlockCacher = nil
	}
	if c.Options.OpenFilesCacher != nil && c.Options.OpenFilesCacher == l.fileCacher {
		c.Options.OpenFilesCacher = nil
	}
	for name, o := range c.DBOptions {
		if o.BlockCacher != nil && o.BlockCacher == l.blockCacher {
			o.BlockCacher = nil
		}
		if o.OpenFilesCacher != nil && o.OpenFilesCacher == l.fileCacher {
			o.OpenFilesCacher = nil
		}
		c.DBOptions[name] = o
	}
	return c
}

func (l *Database) openDB(name string) error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	opts := l.cfg.Options
	if o, ok := l.cfg.DBOptions[name]; ok {
		opts = o
	}
	bhs := filepath.Join(l.cfg.Home, name)
	bhsDB, err := leveldb.OpenFile(bhs, &opts)
	if err != nil {
		return fmt.Errorf("leveldb open %v: %w", name, err)
	}
	l.pool[name] = bhsDB

	return nil
}

// installSharedCaches creates the shared caches from the configured
// capacities and installs them into the base options and every per-DB
// override that does not explicitly provide its own cacher. This keeps
// all leveldb cache memory owned and sized in one place.
func (l *Database) installSharedCaches() {
	if l.cfg.BlockCacheCapacity > 0 {
		if l.cfg.Options.BlockCacher == nil {
			l.blockCacher = opt.NewLRU(l.cfg.BlockCacheCapacity)
			l.cfg.Options.BlockCacher = l.blockCacher
		} else {
			// An explicitly provided cacher wins; report the
			// shared capacity as not in effect.
			l.cfg.BlockCacheCapacity = 0
		}
	}
	if l.cfg.OpenFilesCacheCapacity > 0 {
		if l.cfg.Options.OpenFilesCacher == nil {
			l.fileCacher = opt.NewLRU(l.cfg.OpenFilesCacheCapacity)
			l.cfg.Options.OpenFilesCacher = l.fileCacher
		} else {
			l.cfg.OpenFilesCacheCapacity = 0
		}
	}
	for name, o := range l.cfg.DBOptions {
		if l.blockCacher != nil && o.BlockCacher == nil {
			o.BlockCacher = l.blockCacher
		}
		if l.fileCacher != nil && o.OpenFilesCacher == nil {
			o.OpenFilesCacher = l.fileCacher
		}
		l.cfg.DBOptions[name] = o
	}
}

// fdHeadroom is the file descriptor allowance reserved for everything
// outside the shared table pool: rawdb block files, per-database
// journals and manifests, and network sockets.
const fdHeadroom = 1024

// checkFileLimit warns loudly when the process file descriptor limit
// cannot cover the shared table file pool plus headroom. The failure
// mode being prevented surfaces hours later as "too many open files"
// on unrelated read paths.
func (l *Database) checkFileLimit() {
	if l.cfg.OpenFilesCacheCapacity <= 0 {
		return
	}
	limit, ok := nofileLimit()
	if !ok {
		// Unreachable on unix in practice: Getrlimit(RLIMIT_NOFILE)
		// does not fail with a valid address. Kept for the non-unix
		// stub and defensive symmetry; not testable without fault
		// injection.
		return
	}
	want := uint64(l.cfg.OpenFilesCacheCapacity) + fdHeadroom
	if limit < want {
		log.Warningf("file descriptor limit %d below open files "+
			"cache %d + headroom %d; raise RLIMIT_NOFILE or expect "+
			"'too many open files' failures", limit,
			l.cfg.OpenFilesCacheCapacity, fdHeadroom)
	}
}

// CacheCapacities returns the shared cache capacities in effect:
// block cache in bytes and table file handles. A zero means the
// corresponding cache is not shared (disabled, or an explicit cacher
// was provided) and each database uses its private leveldb default.
func (l *Database) CacheCapacities() (blockCacheBytes, openFiles int) {
	return l.cfg.BlockCacheCapacity, l.cfg.OpenFilesCacheCapacity
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

	// Work on a private copy: installing shared cachers must not
	// mutate the caller's configuration. Reusing a Config across a
	// close/reopen cycle would otherwise resurrect the previous
	// instance's caches instead of constructing fresh ones.
	cfgCopy := *cfg
	cfgCopy.DBOptions = maps.Clone(cfg.DBOptions)
	l := &Database{
		cfg:     &cfgCopy,
		pool:    make(Pool),
		rawPool: make(RawPool),
	}
	l.installSharedCaches()
	l.checkFileLimit()

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
	err = l.openDB(ZKDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", ZKDB, err)
	}
	err = l.openDB(OrdinalDB)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", OrdinalDB, err)
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
