// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package rawdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/juju/loggo"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	logLevel = "INFO"

	indexDir = "index"
	DataDir  = "data"

	DefaultMaxFileSize = 256 * 1024 * 1024 // 256MB file max; will never be bigger.
)

var (
	log             = loggo.GetLogger("rawdb")
	lastFilenameKey = []byte("lastfilename")
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type RawDB struct {
	mtx sync.RWMutex

	cfg *Config

	index *leveldb.DB
	open  bool
}

type Config struct {
	Home    string
	MaxSize int64
}

func NewDefaultConfig(home string) *Config {
	return &Config{
		Home:    home,
		MaxSize: DefaultMaxFileSize,
	}
}

func New(cfg *Config) (*RawDB, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	if cfg == nil {
		return nil, errors.New("must provide config")
	}

	if cfg.MaxSize < 4096 {
		return nil, fmt.Errorf("invalid max size: %v", cfg.MaxSize)
	}

	return &RawDB{
		cfg: cfg,
	}, nil
}

func (r *RawDB) Open() error {
	log.Tracef("Open")
	defer log.Tracef("Open exit")

	r.mtx.Lock()
	defer r.mtx.Unlock()

	if r.open {
		return errors.New("already open")
	}

	err := os.MkdirAll(filepath.Join(r.cfg.Home, DataDir), 0o0700)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	r.index, err = leveldb.OpenFile(filepath.Join(r.cfg.Home, indexDir), &opt.Options{
		BlockCacheEvictRemoved: true,
		Compression:            opt.NoCompression,
	})
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	r.open = true

	return nil
}

func (r *RawDB) Close() error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	r.mtx.Lock()
	defer r.mtx.Unlock()

	err := r.index.Close()
	if err != nil {
		return err
	}
	r.open = false

	// Don't set r.index to nil since that races during shutdown. Just let
	// the commands error out with ErrClose.

	return nil
}

// DB returns the underlying index database.
// You should probably not be calling this! It is used for external database
// upgrades.
func (r *RawDB) DB() *leveldb.DB {
	return r.index
}

func (r *RawDB) Has(key []byte) (bool, error) {
	log.Tracef("Has")
	defer log.Tracef("Has exit")

	return r.index.Has(key, nil)
}

func (r *RawDB) Insert(key, value []byte) error {
	log.Tracef("Insert")
	defer log.Tracef("Insert exit")

	if int64(len(value)) > r.cfg.MaxSize {
		return fmt.Errorf("length exceeds maximum length: %v > %v",
			len(value), r.cfg.MaxSize)
	}

	// Assert we do not have this key stored yet.
	if ok, err := r.index.Has(key, nil); ok {
		return errors.New("key already exists")
	} else if err != nil {
		return err
	}

	r.mtx.Lock()
	defer r.mtx.Unlock()

	tries := 0
	for {
		// This should not happen, but we must ensure we aren't spinning.
		if tries > 1 {
			return errors.New("could not determine last filename")
		}

		lfe, err := r.index.Get(lastFilenameKey, nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				lfe = []byte{0, 0, 0, 0}
			} else {
				return err
			}
		}
		last := binary.BigEndian.Uint32(lfe)
		lastFilename := filepath.Join(r.cfg.Home, DataDir,
			fmt.Sprintf("%010v", last))

		// determine if data fits.
		fh, err := os.OpenFile(lastFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer func() {
			// Close all files we opened along the way.
			err := fh.Close()
			if err != nil {
				log.Errorf("close %v: %v", lastFilename, err)
			}
		}()
		if fi, err := fh.Stat(); err != nil {
			return err
		} else if fi.Size()+int64(len(value)) > r.cfg.MaxSize {
			last++
			lastData := make([]byte, 8)
			binary.BigEndian.PutUint32(lastData, last)
			err = r.index.Put(lastFilenameKey, lastData, nil)
			if err != nil {
				return err
			}
			tries++
			continue
		} else {
			// Encoded coordinates.
			c := make([]byte, 4+4+4)
			binary.BigEndian.PutUint32(c[0:4], last)
			binary.BigEndian.PutUint32(c[4:8], uint32(fi.Size()))
			binary.BigEndian.PutUint32(c[8:12], uint32(len(value)))

			// Append value to latest file.
			n, err := fh.Write(value)
			if err != nil {
				return err
			}
			if n != len(value) {
				return fmt.Errorf("partial write, data corruption: %v != %v", n, len(value))
			}

			// Write coordinates
			err = r.index.Put(key, c, nil)
			if err != nil {
				return err
			}

			return nil
		}
	}
}

func (r *RawDB) Get(key []byte) ([]byte, error) {
	log.Tracef("Get: %x", key)
	defer log.Tracef("Get exit: %x", key)

	c, err := r.index.Get(key, nil)
	if err != nil {
		return nil, err
	}
	if len(c) != 12 {
		// Should not happen.
		return nil, errors.New("invalid coordinates")
	}
	filename := filepath.Join(r.cfg.Home, DataDir, fmt.Sprintf("%010v",
		binary.BigEndian.Uint32(c[0:4])))
	offset := binary.BigEndian.Uint32(c[4:8])
	size := binary.BigEndian.Uint32(c[8:12])
	f, err := os.OpenFile(filename, os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			log.Errorf("close: %v", err)
		}
	}()

	data := make([]byte, size)
	n, err := f.ReadAt(data, int64(offset))
	if err != nil {
		return nil, err
	}
	if n != int(size) {
		return nil, errors.New("invalid read size")
	}

	return data, nil
}
