package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"log"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/v2/db"
	"github.com/hemilabs/heminetwork/v2/rawdb"
	"github.com/hemilabs/heminetwork/v2/rawdbbadger"
)

//type Database interface {
//	Open(context.Context) error
//	Close(context.Context) error
//
//	Get(context.Context, []byte) ([]byte, error)
//	Put(context.Context, []byte, []byte) error
//}
//
//type BadgerConfig struct {
//	Home string
//}
//
//type badgerDB struct {
//	db  *badger.DB
//	opt *badger.Options
//
//	cfg *BadgerConfig
//}
//
//var _ Database = (*badgerDB)(nil)
//
//func (b *badgerDB) Open(_ context.Context) error {
//	if b.db != nil {
//		return nil // XXX return already open?
//	}
//	db, err := badger.Open(*b.opt)
//	if err != nil {
//		return err
//	}
//	b.db = db
//	return nil
//}
//
//func (b *badgerDB) Close(_ context.Context) error {
//	return b.db.Close()
//}
//
//func (b *badgerDB) Get(_ context.Context, key []byte) ([]byte, error) {
//	var val []byte
//	err := b.db.View(func(txn *badger.Txn) error {
//		item, err := txn.Get(key)
//		if err != nil {
//			return err
//		}
//		val, err = item.ValueCopy(nil)
//		return err
//	})
//	if err != nil {
//		return nil, err // XXX return generic
//	}
//	return val, nil
//}
//
//func (b *badgerDB) Put(_ context.Context, key, value []byte) error {
//	err := b.db.Update(func(txn *badger.Txn) error {
//		return txn.Set(key, value)
//	})
//	if err != nil {
//		return err // return generic
//	}
//	return nil
//}
//
//func DefaultBadgerConfig(home string) *BadgerConfig {
//	return &BadgerConfig{
//		Home: home,
//	}
//}

//var ErrInvalidConfig = errors.New("invalid config")
//
//func NewBadgerDB(cfg *BadgerConfig) (Database, error) {
//	if cfg == nil {
//		return nil, ErrInvalidConfig
//	}
//	opt := badger.DefaultOptions(cfg.Home).WithLoggingLevel(badger.ERROR).WithCompression(options.None)
//	db := &badgerDB{
//		cfg: cfg,
//		opt: &opt,
//	}
//
//	return db, nil
//}

func __main() error {
	blockSize := 4_000
	maxBlocks := 1000
	value := make([]byte, int(blockSize))
	_, err := rand.Read(value)
	if err != nil {
		return err
	}

	dbs := flag.String("db", "level", "level or badger")
	flag.Parse()

	log.Printf("Starting %v", *dbs)
	overall := time.Now()
	ctx := context.Background()

	switch *dbs {
	case "rawdblevel":
		home := "rawdblevel-test"
		rdb, err := rawdb.New(&rawdb.Config{Home: home, MaxSize: int64(blockSize)})
		if err != nil {
			return err
		}
		err = rdb.Open()
		if err != nil {
			return err
		}

		// insert 1000 blocks
		start := time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			err := rdb.Insert(key[:], value)
			if err != nil {
				return err
			}
		}
		log.Printf("rawdb inserts: %v size %v duration: %v",
			maxBlocks, maxBlocks*blockSize, time.Since(start))

		// 1000 retrievals
		start = time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			_, err := rdb.Get(key[:])
			if err != nil {
				return err
			}
		}
		log.Printf("rawdb gets: %v size %v duration: %v",
			maxBlocks, maxBlocks*blockSize, time.Since(start))
		err = rdb.Close()
		if err != nil {
			return err
		}

	case "rawdbbadger":
		home := "rawdbbadger-test"
		rdb, err := rawdbbadger.New(&rawdbbadger.Config{Home: home, MaxSize: int64(blockSize)})
		if err != nil {
			return err
		}
		err = rdb.Open()
		if err != nil {
			return err
		}

		// insert 1000 blocks
		start := time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			err := rdb.Insert(key[:], value)
			if err != nil {
				return err
			}
		}
		log.Printf("rawdbbadger inserts: %v size %v duration: %v",
			maxBlocks, maxBlocks*blockSize, time.Since(start))

		// 1000 retrievals
		start = time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			_, err := rdb.Get(key[:])
			if err != nil {
				return err
			}
		}
		log.Printf("rawdbbadger gets: %v size %v duration: %v",
			maxBlocks, maxBlocks*blockSize, time.Since(start))
		err = rdb.Close()
		if err != nil {
			return err
		}

	case "badger":
		cfg := db.DefaultBadgerConfig("badger-test")
		db, err := db.NewBadgerDB(cfg)
		if err != nil {
			return err
		}
		err = db.Open(ctx)
		if err != nil {
			return err
		}
		// insert 1000 blocks
		start := time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			err := db.Put(ctx, key[:], value)
			if err != nil {
				return err
			}
		}
		log.Printf("badger inserts: %v size %v duration: %v",
			maxBlocks, maxBlocks*blockSize, time.Since(start))
		// 1000 retrievals
		start = time.Now()
		for i := 0; i < maxBlocks; i++ {
			var key [4]byte
			binary.BigEndian.PutUint32(key[:], uint32(i))
			v, err := db.Get(ctx, key[:])
			if err != nil {
				return err
			}
			_ = v
		}
		log.Printf("badger gets: %v size %v duration: %v",
			maxBlocks, maxBlocks*blockSize, time.Since(start))
		err = db.Close(ctx)
		if err != nil {
			return err
		}
	}

	log.Printf("overall duration %v", time.Since(overall))
	<-ctx.Done()
	return nil
}

func _main() error {
	ctx := context.Background()
	cfg := db.DefaultBadgerConfig("badgerdb")
	db, err := db.NewBadgerDB(cfg)
	if err != nil {
		return err
	}
	err = db.Open(ctx)
	if err != nil {
		return err
	}

	err = db.Put(ctx, []byte("hello"), []byte("world"))
	if err != nil {
		return err
	}
	val, err := db.Get(ctx, []byte("hello"))
	if err != nil {
		return err
	}
	spew.Dump(val)

	return db.Close(ctx)
	//dir, err := os.MkdirTemp("", "badger-test")
	//if err != nil {
	//	return err
	//}
	//log.Printf("dir: %v", dir)

	//db, err := badger.Open(badger.DefaultOptions(dir).WithLoggingLevel(badger.ERROR))
	//if err != nil {
	//	return err
	//}

	//// Insert
	//err = db.Update(func(txn *badger.Txn) error {
	//	err := txn.Set([]byte("answer"), []byte("42"))
	//	return err
	//})
	//if err != nil {
	//	return err
	//}

	//// Get
	//var val []byte
	//err = db.View(func(txn *badger.Txn) error {
	//	item, err := txn.Get([]byte("answer"))
	//	if err != nil {
	//		return err
	//	}
	//	val, err = item.ValueCopy(nil)
	//	return err
	//})
	//if err != nil {
	//	return err
	//}
	//spew.Dump(val)

	// return db.Close()
}

func main() {
	err := __main()
	if err != nil {
		panic(err)
	}
}
