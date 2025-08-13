// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hemilabs/heminetwork/v2/database/gkvdb"
	"github.com/hemilabs/heminetwork/v2/database/gkvdb/dbtest/rawdb"
)

func _main() error {
	bs := flag.Int("blocksize", 4096, "block size default 4096")
	mb := flag.Int("maxblocks", 1000, "number of blocks, default 1000")
	dbs := flag.String("db", "", "badger, bitcask, bunt, level, nuts or pebble")
	test := flag.String("test", "", "rawdb (split key/value), direct (direct access)")
	flag.Parse()

	if *dbs == "" || *test == "" {
		return errors.New("must provide -db and -test")
	}

	blockSize := *bs
	maxBlocks := *mb

	value := make([]byte, blockSize)
	_, err := rand.Read(value)
	if err != nil {
		return err
	}

	var (
		ddb gkvdb.Database
		rdb *rawdb.RawDB
	)
	action := fmt.Sprintf("%v-%v", *dbs, *test)
	home := action

	switch action {
	case "level-rawdb", "badger-rawdb", "pebble-rawdb", "bitcask-rawdb", "bunt-rawdb", "nuts-rawdb", "mongo-rawdb":
		rdb, err = rawdb.New(&rawdb.Config{
			DB:      *dbs,
			Home:    home,
			MaxSize: rawdb.DefaultMaxFileSize,
		})
		if err != nil {
			return err
		}

	// case "badger-direct":
	//	cfg := db.DefaultBadgerConfig(home)
	//	ddb, err = db.NewBadgerDB(cfg)
	//	if err != nil {
	//		return err
	//	}

	// case "level-direct":
	//	cfg := db.DefaultLevelConfig(home)
	//	ddb, err = db.NewLevelDB(cfg)
	//	if err != nil {
	//		return err
	//	}

	// case "pebble-direct":
	//	cfg := db.DefaultPebbleConfig(home)
	//	ddb, err = db.NewPebbleDB(cfg)
	//	if err != nil {
	//		return err
	//	}

	// case "bitcask-direct":
	//	cfg := db.DefaultBitcaskConfig(home)
	//	ddb, err = db.NewBitcaskDB(cfg)
	//	if err != nil {
	//		return err
	//	}

	// case "bunt-direct":
	//	cfg := db.DefaultBuntConfig(home)
	//	ddb, err = db.NewBuntDB(cfg)
	//	if err != nil {
	//		return err
	//	}

	case "nuts-direct":
		cfg := gkvdb.DefaultNutsConfig(home, []string{"mytable"})
		ddb, err = gkvdb.NewNutsDB(cfg)
		if err != nil {
			return err
		}

	// case "mongo-direct":
	//	cfg := db.DefaultMongoConfig(os.Getenv(rawdb.DefaultMongoEnvURI),
	//		[]string{"mytable"})
	//	ddb, err = db.NewMongoDB(cfg)
	//	if err != nil {
	//		return err
	//	}

	default:
		return fmt.Errorf("invalid action: %v", action)
	}

	fi, err := os.Stat(action)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if fi != nil {
		if fi.IsDir() {
			log.Printf("Removing %v", action)
			err = os.RemoveAll(action)
			if err != nil {
				return err
			}
			log.Printf("Syncing...")
			unix.Sync()
			time.Sleep(3 * time.Second) // Give sync a chance
		} else {
			return fmt.Errorf("not a directory: %v", action)
		}
	}

	log.Printf("Starting %v", action)
	overall := time.Now()
	ctx := context.Background()

	if ddb != nil {
		err = ddb.Open(ctx)
		if err != nil {
			return err
		}
	} else {
		err = rdb.Open()
		if err != nil {
			return err
		}
	}

	switch *test {
	case "direct":
		// insert blocks
		start := time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			err := ddb.Put(ctx, "", key[:], value)
			if err != nil {
				return err
			}
		}
		log.Printf("%v inserts: %v size %v duration: %v",
			action, maxBlocks, maxBlocks*blockSize, time.Since(start))

		// retrievals
		start = time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			_, err := ddb.Get(ctx, "", key[:])
			if err != nil {
				return err
			}
		}
		log.Printf("%v gets: %v size %v duration: %v",
			action, maxBlocks, maxBlocks*blockSize, time.Since(start))

		// Deletes
		start = time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			err := ddb.Del(ctx, "", key[:])
			if err != nil {
				return err
			}
		}
		log.Printf("%v deletes: %v size %v duration: %v",
			action, maxBlocks, maxBlocks*blockSize, time.Since(start))

	case "rawdb":
		// insert blocks
		start := time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			err := rdb.Insert(key[:], value)
			if err != nil {
				return err
			}
		}
		log.Printf("%v inserts: %v size %v duration: %v",
			action, maxBlocks, maxBlocks*blockSize, time.Since(start))
		// retrievals
		start = time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			v, err := rdb.Get(key[:])
			if err != nil {
				return err
			}
			_ = v
		}
		log.Printf("%v gets: %v size %v duration: %v",
			action, maxBlocks, maxBlocks*blockSize, time.Since(start))
	}

	if ddb != nil {
		err = ddb.Close(ctx)
		if err != nil {
			return err
		}
	} else {
		err = rdb.Close()
		if err != nil {
			return err
		}
	}

	log.Printf("overall duration %v (ctrl-c to exit)", time.Since(overall))
	<-ctx.Done()
	return nil
}

func main() {
	err := _main()
	if err != nil {
		panic(err)
	}
}
