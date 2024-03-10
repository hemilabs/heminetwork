// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/hemilabs/heminetwork/database"
	"github.com/juju/loggo"
	"github.com/mitchellh/go-homedir"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	logLevel = "INFO"

	PeersDB         = "peers"
	BlockHeadersDB  = "blockheaders"
	BlocksMissingDB = "blocksmissing"
	BlocksDB        = "blocks"
)

var log = loggo.GetLogger("level")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type (
	Pool     map[string]*leveldb.DB
	Database struct {
		mtx sync.RWMutex
		wg  sync.WaitGroup // Wait group for notification handler exit

		pool Pool // database pool

		ntfn map[database.NotificationName]int // Notification handlers
		home string                            // leveld toplevel database directory
	}
)

var _ database.Database = (*Database)(nil)

func (l *Database) Close() error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	var errSeen error // XXX return last error for now
	for k, v := range l.pool {
		err := v.Close()
		if err != nil {
			// do continue, leveldb does not like unfresh shutdowns
			log.Errorf("close %v: %v", k, err)
			errSeen = err
		}
	}

	return errSeen
}

func (l *Database) DB() Pool {
	log.Tracef("DB")
	defer log.Tracef("DB exit")

	return l.pool
}

func (l *Database) RegisterNotification(ctx context.Context, n database.NotificationName, f database.NotificationCallback, payload any) error {
	log.Tracef("RegisterNotification")
	defer log.Tracef("RegisterNotification exit")

	return fmt.Errorf("RegisterNotification")
}

func (l *Database) UnregisterNotification(n database.NotificationName) error {
	log.Tracef("UnregisterNotification")
	defer log.Tracef("UnregisterNotification exit")

	return fmt.Errorf("UnregisterNotification")
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
		home: h,
		pool: make(Pool),
	}

	// XXX missing version

	// XXX unwind open on error exit

	// Peers table
	err = l.openDB(PeersDB, nil)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", PeersDB, err)
	}
	err = l.openDB(BlockHeadersDB, &opt.Options{
		BlockCacheCapacity: 256 * opt.MiB,
	})
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", PeersDB, err)
	}
	err = l.openDB(BlocksMissingDB, &opt.Options{
		BlockCacheCapacity: 256 * opt.MiB,
	})
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", PeersDB, err)
	}
	err = l.openDB(BlocksDB, nil)
	if err != nil {
		return nil, fmt.Errorf("leveldb %v: %w", PeersDB, err)
	}

	// XXX unwind open on error exit, no really, unwind

	return l, nil
}
