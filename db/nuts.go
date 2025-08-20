package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/nutsdb/nutsdb"
)

// Assert required inteerfaces
var (
	_ Database    = (*nutsDB)(nil)
	_ Transaction = (*nutsTX)(nil)
)

type NutsConfig struct {
	Home   string
	Tables []string
}

func DefaultNutsConfig(home string, tables []string) *NutsConfig {
	if len(tables) == 0 {
		tables = []string{"toplevel"}
	}
	return &NutsConfig{
		Home:   home,
		Tables: tables,
	}
}

type nutsDB struct {
	db *nutsdb.DB

	cfg *NutsConfig
}

func NewNutsDB(cfg *NutsConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &nutsDB{
		cfg: cfg,
	}

	return bdb, nil
}

func (b *nutsDB) Open(_ context.Context) error {
	if b.db != nil {
		return nil // XXX return already open?
	}
	// XXX no compression
	ndb, err := nutsdb.Open(nutsdb.DefaultOptions,
		nutsdb.WithDir(b.cfg.Home),
		nutsdb.WithSyncEnable(false),
		nutsdb.WithGCWhenClose(true),
		// nutsdb.WithRWMode(nutsdb.FileIO),
		nutsdb.WithRWMode(nutsdb.MMap),
		nutsdb.WithEntryIdxMode(nutsdb.HintKeyAndRAMIdxMode), // cache keys
		// nutsdb.WithEntryIdxMode(nutsdb.HintKeyValAndRAMIdxMode), // cache keys and data
		nutsdb.WithHintKeyAndRAMIdxCacheSize(1_000_000),
	)
	if err != nil {
		return err
	}
	err = ndb.Update(func(tx *nutsdb.Tx) error {
		for _, table := range b.cfg.Tables {
			if tx.ExistBucket(nutsdb.DataStructureBTree, table) {
				continue
			}
			err := tx.NewBucket(nutsdb.DataStructureBTree, table)
			if err != nil {
				return fmt.Errorf("could not create table (%v): %w",
					table, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	b.db = ndb
	return nil
}

func (b *nutsDB) Close(_ context.Context) error {
	return b.db.Close()
}

func (b *nutsDB) Del(_ context.Context, table string, key []byte) error {
	err := b.db.Update(
		func(tx *nutsdb.Tx) error {
			err := tx.Delete(table, key)
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, nutsdb.ErrKeyNotFound) {
			return ErrKeyNotFound
		}
		return err
	}
	return nil
}

func (b *nutsDB) Has(_ context.Context, table string, key []byte) (bool, error) {
	//_, err := b.Get(nil, table, key)
	//if errors.Is(err, ErrKeyNotFound) {
	//	return false, nil
	//}
	//return err == nil, err
	err := b.db.View(func(tx *nutsdb.Tx) error {
		_, err := tx.ValueLen(table, key)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, nutsdb.ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *nutsDB) Get(_ context.Context, table string, key []byte) ([]byte, error) {
	var value []byte
	err := b.db.View(func(tx *nutsdb.Tx) error {
		val, err := tx.Get(table, key)
		if err != nil {
			return err
		}
		value = make([]byte, len(val))
		copy(value, val)
		return nil
	})
	if err != nil {
		if errors.Is(err, nutsdb.ErrKeyNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

func (b *nutsDB) Put(_ context.Context, table string, key, value []byte) error {
	err := b.db.Update(
		func(tx *nutsdb.Tx) error {
			err := tx.Put(table, key, value, 0)
			if err != nil {
				//if nutsdb.IsBucketNotFound(err) {
				//	err := tx.NewBucket(nutsdb.DataStructureBTree, table)
				//	if err != nil {
				//		return err
				//	}
				//	return tx.Put(table, key, value, 0)
				//}
				return err
			}
			return nil
		})
	return err
}

func (b *nutsDB) Last(ctx context.Context, table string) ([]byte, []byte, error) {
	var key, value []byte
	err := b.db.View(func(tx *nutsdb.Tx) error {
		k, err := tx.GetMaxKey(table)
		if err != nil {
			return err
		}

		val, err := tx.Get(table, k)
		if err != nil {
			return err
		}

		key = make([]byte, len(k))
		copy(key, k)
		value = make([]byte, len(val))
		copy(value, val)

		return nil
	})
	if err != nil {
		if errors.Is(err, nutsdb.ErrKeyNotFound) {
			return nil, nil, ErrKeyNotFound
		}
		return nil, nil, err
	}
	return key, value, nil
}

//func (b *nutsDB) All(ctx context.Context, table string) {
//	b.db.View(func(tx *nutsdb.Tx) error {
//		k, v, err := tx.GetAll(table)
//		if err != nil {
//			panic(err)
//		}
//		for x := range v {
//			log.Infof("%v: %x", x, k[x])
//		}
//		return nil
//	})
//}

//	func (b *nutsDB) View(ctx context.Context, callback func(ctx context.Context, tx *Transaction) error) error {
//		itx, err := b.db.Begin(false)
//		if err != nil {
//			return err
//		}
//		err = callback(ctx, &Transaction{tx: itx})
//		if err != nil {
//			if rberr := itx.Rollback(); err != nil {
//				return fmt.Errorf("rollback: %w", rberr)
//			}
//			return err
//		}
//		return itx.Commit()
//	}
func (b *nutsDB) Begin(ctx context.Context, write bool) (Transaction, error) {
	return &nutsTX{}, nil
}

// Transactions

type nutsTX struct{}

var nutsNotYet = errors.New("not yet")

func (tx *nutsTX) Del(ctx context.Context, table string, key []byte) error {
	return nutsNotYet
}

func (tx *nutsTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	return false, nutsNotYet
}

func (tx *nutsTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	return nil, nutsNotYet
}

func (tx *nutsTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	return nutsNotYet
}

func (tx *nutsTX) Commit(ctx context.Context) error {
	return nutsNotYet
}

func (tx *nutsTX) Rollback(ctx context.Context) error {
	return nutsNotYet
}
