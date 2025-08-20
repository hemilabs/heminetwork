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
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dustin/go-humanize"

	"github.com/hemilabs/heminetwork/v2/db"
	"github.com/hemilabs/heminetwork/v2/rawdb"
)

var numCPU = float64(runtime.NumCPU())

func cpuUsage(elapsed time.Duration, user, sys int64) float64 {
	return (float64(elapsed) / (float64(user) + float64(sys))) / numCPU
}

func getProcessCPUTime() (int64, int64, int64) {
	var rusage syscall.Rusage
	err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage)
	if err != nil {
		panic(err)
	}
	user := rusage.Utime.Nano()
	system := rusage.Stime.Nano()
	return user, system, rusage.Maxrss
}

func printStats(prefix string, i int, elapsed time.Duration) {
	user, sys, rss := getProcessCPUTime()
	if i == 0 {
		log.Printf("%velapsed %v peak memory %v user %v sys %v %%cpu %.1f",
			prefix, elapsed, humanize.IBytes(uint64(rss*1024)),
			time.Duration(user), time.Duration(sys),
			cpuUsage(elapsed, user, sys))
		return
	}
	log.Printf("%vrecords %v elapsed %v peak memory %v user %v sys %v %%cpu %.1f",
		prefix, i, elapsed, humanize.IBytes(uint64(rss*1024)),
		time.Duration(user), time.Duration(sys),
		cpuUsage(elapsed, user, sys))
}

func HandleSignals(ctx context.Context, cancel context.CancelFunc, callback func(os.Signal)) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()

	select {
	case <-ctx.Done():
	case s := <-signalChan: // First signal, cancel context.
		if callback != nil {
			callback(s) // Do whatever caller wants first.
			cancel()
		}
	}
	<-signalChan // Second signal, hard exit.
	os.Exit(2)
}

func _main() error {
	ks := flag.Int("keysize", 32, "key size default 32")
	bs := flag.Int("blocksize", 120, "block size default 120")
	mb := flag.Int("maxblocks", 1000, "number of blocks, default 1000")
	dbs := flag.String("db", "", "badger, bitcask, bunt, level, nuts or pebble")
	test := flag.String("test", "", "rawdb (split key/value), direct (direct access)")
	flag.Parse()

	if *dbs == "" || *test == "" {
		return errors.New("must provide -db and -test")
	}

	blockSize := *bs
	maxBlocks := *mb

	value := make([]byte, int(blockSize))
	_, err := rand.Read(value)
	if err != nil {
		return err
	}

	var (
		ddb db.Database
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

	case "level-direct":
		cfg := db.DefaultLevelConfig(home)
		ddb, err = db.NewLevelDB(cfg)
		if err != nil {
			return err
		}

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
		cfg := db.DefaultNutsConfig(home, []string{""})
		ddb, err = db.NewNutsDB(cfg)
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

	// Make option
	if false {
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
	}

	ctx, cancel := context.WithCancel(context.Background())
	go HandleSignals(ctx, cancel, func(s os.Signal) {
		log.Printf("received signal: %s", s)
	})

	overall := time.Now()
	printStats("Start of Day ", 0, time.Since(overall))

	var startCount int
	if ddb != nil {
		err = ddb.Open(ctx)
		if err != nil {
			return err
		}
		var value []byte
		lastKey, value, err := ddb.Last(ctx, "")
		if err != nil {
			if !errors.Is(err, db.ErrKeyNotFound) {
				return err
			}
		} else {
			startCount = int(binary.BigEndian.Uint32(lastKey)) + 1
		}
		log.Printf("startCount: %v %v %v", startCount, len(value), err)
	} else {
		err = rdb.Open()
		if err != nil {
			return err
		}
	}
	defer func() {
		if ddb != nil {
			err = ddb.Close(ctx)
			if err != nil {
				panic(err)
			}
		}
		if rdb != nil {
			err = rdb.Close()
			if err != nil {
				panic(err)
			}
		}
	}()
	printStats("Database open ", 0, time.Since(overall))

	switch *test {
	case "direct":
		var start time.Time
		// insert blocks
		log.Printf("Starting direct test at %v to %v key %v val %v total %v",
			humanize.Comma(int64(startCount)),
			humanize.Comma(int64(maxBlocks)), *ks, len(value),
			humanize.IBytes(uint64(maxBlocks*(*ks+len(value)))),
		)
		start = time.Now()
		recordsInserted := 0
		for i := startCount; i < maxBlocks; i++ {
			key := make([]byte, *ks)
			binary.BigEndian.PutUint32(key[:], uint32(i))
			err := ddb.Put(ctx, "", key, value)
			if err != nil {
				return err
			}
			// log.Printf("%v: put %x", i, key)
			recordsInserted++

			if i%10000 == 0 {
				printStats("", i, time.Since(start))
				select {
				case <-ctx.Done():
					return nil
				default:
				}
			}
		}
		printStats("Inserted ", recordsInserted, time.Since(start))

		// ddb.All(ctx, "")

		if false {
			// retrievals
			start = time.Now()
			for i := 0; i < maxBlocks; i++ {
				key := make([]byte, *ks)
				binary.BigEndian.PutUint32(key, uint32(i))
				_, err := ddb.Get(ctx, "", key)
				if err != nil {
					return fmt.Errorf("%x: get %w", key, err)
				}
				// log.Printf("%v: get %x", i, key)
			}
			printStats("Gets ", recordsInserted, time.Since(start))
		}

		if true {
			// Has
			start = time.Now()
			for i := 0; i < maxBlocks; i++ {
				key := make([]byte, *ks)
				binary.BigEndian.PutUint32(key, uint32(i))
				has, err := ddb.Has(ctx, "", key)
				if err != nil {
					return fmt.Errorf("%x: has %w", key, err)
				}
				if !has {
					return fmt.Errorf("%x: has bool", key)
				}
				// log.Printf("%v: has %x", i, key)
			}
			printStats("Has ", recordsInserted, time.Since(start))
		}

		if false {
			// Deletes
			start = time.Now()
			for i := 0; i < maxBlocks; i++ {
				key := make([]byte, *ks)
				binary.BigEndian.PutUint32(key, uint32(i))
				err := ddb.Del(ctx, "", key)
				if err != nil {
					return fmt.Errorf("%x: del %w", key, err)
				}
				// log.Printf("%v: del %x", i, key)
			}
			printStats("Deletes ", recordsInserted, time.Since(start))
		}

	case "rawdb":
		// insert blocks
		key := make([]byte, *ks)
		start := time.Now()
		for i := 0; i < maxBlocks; i++ {
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
	start := time.Now()
	if ddb != nil {
		err = ddb.Close(ctx)
		if err != nil {
			return err
		}
		ddb = nil
	}
	if rdb != nil {
		err = rdb.Close()
		if err != nil {
			return err
		}
		rdb = nil
	}
	printStats("Closed database ", 0, time.Since(start))

	printStats("Overal ", 0, time.Since(overall))
	<-ctx.Done()
	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}
