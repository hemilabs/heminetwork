// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/level"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/juju/loggo"
	"github.com/syndtr/goleveldb/leveldb"
)

// XXX before committing this conver json to gob

// Locking order:
//	BlockHeaders
// 	BlocksMissing
// 	Blocks

const (
	ldbVersion = 1

	logLevel = "INFO"
	verbose  = false

	bhsLastKey = "last"
)

var log = loggo.GetLogger("level")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type ldb struct {
	mtx                       sync.Mutex
	blocksMissingCacheEnabled bool
	blocksMissingCache        map[string]*cacheEntry // XXX purge and manages cache size

	// XXX remove this
	peersGood map[string]struct{}
	peersBad  map[string]struct{}

	*level.Database
	pool level.Pool
}

var _ tbcd.Database = (*ldb)(nil)

func New(ctx context.Context, home string) (*ldb, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	ld, err := level.New(ctx, home, ldbVersion)
	if err != nil {
		return nil, err
	}
	log.Debugf("tbcdb database version: %v", ldbVersion)
	l := &ldb{
		Database:                  ld,
		pool:                      ld.DB(),
		blocksMissingCacheEnabled: true, // XXX make setting
		blocksMissingCache:        make(map[string]*cacheEntry, 1024),
		peersGood:                 make(map[string]struct{}, 1000),
		peersBad:                  make(map[string]struct{}, 1000),
	}

	return l, nil
}

type (
	discardFunc func()
	commitFunc  func() error
)

func (l *ldb) startTransaction(db string) (*leveldb.Transaction, commitFunc, discardFunc, error) {
	bhsDB := l.pool[db]
	tx, err := bhsDB.OpenTransaction()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%v open tansaction: %w", db, err)
	}
	d := true
	discard := &d
	df := func() {
		if *discard {
			log.Debugf("discarding transaction: %v", db)
			tx.Discard()
		}
	}
	cf := func() error {
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("%v discard: %w", db, err)
		}
		*discard = false
		return nil
	}

	return tx, cf, df, nil
}

func (l *ldb) BlockHeaderByHash(ctx context.Context, hash []byte) (*tbcd.BlockHeader, error) {
	log.Tracef("BlockHeaderByHash")
	defer log.Tracef("BlockHeaderByHash exit")

	// It stands to reason that this code does not need a trasaction. The
	// caller code will either receive or not receice an answer. It does
	// not seem likely to be racing higher up in the stack.

	bhsDB := l.pool[level.BlockHeadersDB]
	jbh, err := bhsDB.Get(hash, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, database.NotFoundError(fmt.Sprintf("block header not found: %x", hash))
		}
		return nil, fmt.Errorf("block header get: %w", err)
	}
	var bh tbcd.BlockHeader
	err = json.Unmarshal(jbh, &bh)
	if err != nil {
		return nil, fmt.Errorf("block headers unmarshal: %w", err)
	}

	return &bh, nil

	//bhsDB := l.pool[level.BlockHeadersDB]
	//tx, err := bhsDB.OpenTransaction()
	//if err != nil {
	//	return nil, fmt.Errorf("block headers by hash transaction: %w", err)
	//}
	//discard := true
	//defer func() {
	//	if discard {
	//		log.Debugf("BlockHeadersByHash discarding transaction")
	//		tx.Discard()
	//	}
	//}()

	//// Get last record
	//j, err := tx.Get(hash, nil)
	//if err != nil {
	//	if err == leveldb.ErrNotFound {
	//		return nil, database.NotFoundError(fmt.Sprintf("header not found: %x", hash))
	//	}
	//	return nil, fmt.Errorf("block headers by hash: %w", err)
	//}
	//var bh tbcd.BlockHeader
	//err = json.Unmarshal(j, &bh)
	//if err != nil {
	//	return nil, fmt.Errorf("block headers by hash unmarshal: %w", err)
	//}

	//err = tx.Commit()
	//if err != nil {
	//	return nil, fmt.Errorf("block headers by hash: %w", err)
	//}

	// discard = false

	// return &bh, nil
}

func (l *ldb) BlockHeadersBest(ctx context.Context) ([]tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersBest")
	defer log.Tracef("BlockHeadersBest exit")

	// This function is a bit of a crapshoot. It will receive many calls
	// and thus it is racing by definition. Avoid the lock and let the
	// caller serialize the response.

	// XXX this code does not handle multiple "best" block headers.

	bhsDB := l.pool[level.BlockHeadersDB]
	// Get last record
	jbh, err := bhsDB.Get([]byte(bhsLastKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return []tbcd.BlockHeader{}, nil
		}
		return nil, fmt.Errorf("block headers best: %w", err)
	}
	var bh tbcd.BlockHeader
	err = json.Unmarshal(jbh, &bh)
	if err != nil {
		return nil, fmt.Errorf("block headers best unmarshal: %w", err)
	}
	return []tbcd.BlockHeader{bh}, nil

	//tx, err := bhsDB.OpenTransaction()
	//if err != nil {
	//	return nil, fmt.Errorf("block headers best transaction: %w", err)
	//}
	//discard := true
	//defer func() {
	//	if discard {
	//		log.Debugf("BlockHeadersBest discarding transaction")
	//		tx.Discard()
	//	}
	//}()

	//// Get last record
	//j, err := tx.Get([]byte(bhsLastKey), nil)
	//if err != nil {
	//	if err == leveldb.ErrNotFound {
	//		return []tbcd.BlockHeader{}, nil
	//	}
	//	return nil, fmt.Errorf("block headers best: %w", err)
	//}
	//var bh tbcd.BlockHeader
	//err = json.Unmarshal(j, &bh)
	//if err != nil {
	//	return nil, fmt.Errorf("block headers best unmarshal: %w", err)
	//}

	//err = tx.Commit()
	//if err != nil {
	//	return nil, fmt.Errorf("block headers best: %w", err)
	//}

	// discard = false

	// return []tbcd.BlockHeader{bh}, nil
}

// heightHashToKey generates a sortable key from height and hash. With this key
// we can iterate over the block headers table and see what block records are
// missing.
func heightHashToKey(height uint64, hash []byte) []byte {
	if len(hash) != chainhash.HashSize {
		panic(fmt.Sprintf("invalid hash size: %v", len(hash)))
	}
	key := make([]byte, 8+1+chainhash.HashSize)
	binary.BigEndian.PutUint64(key[0:8], height)
	copy(key[9:], hash)
	return key
}

// keyToHeightHash reverses the process of heightHashToKey.
func keyToHeightHash(key []byte) (uint64, []byte) {
	if len(key) != 8+1+chainhash.HashSize {
		panic(fmt.Sprintf("invalid key size: %v", len(key)))
	}
	hash := make([]byte, chainhash.HashSize) // must make copy!
	copy(hash, key[9:])
	return binary.BigEndian.Uint64(key[0:8]), hash
}

func (l *ldb) BlockHeadersInsert(ctx context.Context, bhs []tbcd.BlockHeader) error {
	log.Tracef("BlockHeadersInsert")
	defer log.Tracef("BlockHeadersInsert exit")

	if len(bhs) == 0 {
		return fmt.Errorf("block headers insert: no block headers to insert")
	}

	// block headers
	bhsTx, bhsCommit, bhsDiscard, err := l.startTransaction(level.BlockHeadersDB)
	if err != nil {
		return fmt.Errorf("block headers open transaction: %w", err)
	}
	defer bhsDiscard()

	// Make sure we are not inserting the same blocks
	has, err := bhsTx.Has(bhs[0].Hash, nil)
	if err != nil {
		return fmt.Errorf("block headers insert has: %v", err)
	}
	if has {
		return database.DuplicateError("block headers insert duplicate")
	}

	// blocks missing
	bmTx, bmCommit, bmDiscard, err := l.startTransaction(level.BlocksMissingDB)
	if err != nil {
		return fmt.Errorf("blocks missing open transaction: %w", err)
	}
	defer bmDiscard()

	// Insert missing blocks and block headers
	var lastRecord []byte
	bmBatch := new(leveldb.Batch)
	bhsBatch := new(leveldb.Batch)
	for k := range bhs {
		// Height 0 is genesis, we do not want a missing block record for that.
		if bhs[k].Height != 0 {
			// Insert a synthesized height_hash key that serves as
			// an index to see which blocks are missing.
			bmBatch.Put(heightHashToKey(bhs[k].Height, bhs[k].Hash[:]), []byte{})
		}

		// XXX reason about pre processing JSON. Due to the caller code
		// being heavily reentrant the odds are not good that encoding
		// would only happens once. The downside is that this encoding
		// happens in the database transaction and is thus locked.

		// Insert JSON encoded block header record
		bhs[k].CreatedAt = database.NewTimestamp(time.Now())
		bhj, err := json.Marshal(bhs[k])
		if err != nil {
			return fmt.Errorf("json marshal %v: %w", k, err)
		}
		bhsBatch.Put(bhs[k].Hash, bhj)
		lastRecord = bhj
	}

	// Insert last height into block headers XXX this does not deal with forks
	bhsBatch.Put([]byte(bhsLastKey), lastRecord)

	// Write missing blocks batch
	err = bmTx.Write(bmBatch, nil)
	if err != nil {
		return fmt.Errorf("blocks missing insert: %w", err)
	}

	// Write block headers batch
	err = bhsTx.Write(bhsBatch, nil)
	if err != nil {
		return fmt.Errorf("block headers insert: %w", err)
	}

	// blocks missing commit
	err = bmCommit()
	if err != nil {
		return fmt.Errorf("blocks missing commit: %w", err)
	}

	// block headers commit
	err = bhsCommit()
	if err != nil {
		return fmt.Errorf("block headers commit: %w", err)
	}

	return nil

	//// Open the block headers database transaction early to block db
	//bhsDB := l.pool[level.BlockHeadersDB]
	//bhsTx, err := bhsDB.OpenTransaction()
	//if err != nil {
	//	return fmt.Errorf("block headers open transaction: %w", err)
	//}
	//bhsDiscard := true
	//defer func() {
	//	if bhsDiscard {
	//		log.Debugf("BlockHeadersInsert discarding transaction: %v",
	//			len(bhs))
	//		bhsTx.Discard()
	//	}
	//}()

	//// Open the blocks missing database transaction early to block db
	//bmDB := l.pool[level.BlocksMissingDB]
	//bmTx, err := bmDB.OpenTransaction()
	//if err != nil {
	//	return fmt.Errorf("blocks missing open transaction: %w", err)
	//}
	//bmDiscard := true
	//defer func() {
	//	if bmDiscard {
	//		log.Debugf("BlockHeadersInsert discarding transaction: %v",
	//			len(bhs)) // Yes, bhs, this is not a bug.
	//		bmTx.Discard()
	//	}
	//}()

	//// Make sure we are not inserting the same blocks
	//has, err := bhsTx.Has(bhs[0].Hash, nil)
	//if err != nil {
	//	return fmt.Errorf("block headers insert has: %v", err)
	//}
	//if has {
	//	return database.DuplicateError("block headers insert duplicate")
	//}

	//// Insert missing blocks and block headers
	//var lastRecord []byte
	//bmBatch := new(leveldb.Batch)
	//bhsBatch := new(leveldb.Batch)
	//for k := range bhs {
	//	// Height 0 is genesis, we do not want a missing block record for that.
	//	if bhs[k].Height != 0 {
	//		// Insert a synthesized height_hash key that serves as
	//		// an index to see which blocks are missing.
	//		bmBatch.Put(heightHashToKey(bhs[k].Height, bhs[k].Hash[:]), []byte{})
	//	}

	//	// Insert JSON encoded block header record
	//	bhs[k].CreatedAt = database.NewTimestamp(time.Now())
	//	bhj, err := json.Marshal(bhs[k])
	//	if err != nil {
	//		return fmt.Errorf("json marshal %v: %w", k, err)
	//	}
	//	bhsBatch.Put(bhs[k].Hash, bhj)
	//	lastRecord = bhj
	//}

	//// Insert last height into block headers XXX this does not deal with forks
	//bhsBatch.Put([]byte(bhsLastKey), lastRecord)

	//// Write missing blocks batch
	//err = bmTx.Write(bmBatch, nil)
	//if err != nil {
	//	return fmt.Errorf("blocks missing insert: %w", err)
	//}

	//// Write block headers batch
	//err = bhsTx.Write(bhsBatch, nil)
	//if err != nil {
	//	return fmt.Errorf("block headers insert: %w", err)
	//}

	//// Reverse order commit missing blocks.
	//// If this is committed and the block headers fail, that is ok. It will
	//// simply be overwritten later.
	//err = bmTx.Commit()
	//if err != nil {
	//	return fmt.Errorf("blocks missing commit: %w", err)
	//}
	//bmDiscard = false

	//// Commit block headers table
	//err = bhsTx.Commit()
	//if err != nil {
	//	return fmt.Errorf("block headers commit: %w", err)
	//}
	//bhsDiscard = false

	// return nil
}

type cacheEntry struct {
	height    uint64
	timestamp time.Time
}

// XXX return hash and height only
func (l *ldb) BlocksMissing(ctx context.Context, count int) ([]tbcd.BlockIdentifier, error) {
	log.Tracef("BlocksMissing")
	defer log.Tracef("BlocksMissing exit")

	// This is a read only call and it can be run without a transaction.
	// False positives may be returned to the caller and it should mostly
	// handle that. If a block is inserted multiple time it will be silently
	// ignored.

	var blockCacheLen, x int
	bmDB := l.pool[level.BlocksMissingDB]
	bis := make([]tbcd.BlockIdentifier, 0, count)
	it := bmDB.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		bh := tbcd.BlockIdentifier{}
		bh.Height, bh.Hash = keyToHeightHash(it.Key())
		bis = append(bis, bh)

		// cache the reply
		if l.blocksMissingCacheEnabled {
			l.mtx.Lock()
			l.blocksMissingCache[string(bh.Hash)] = &cacheEntry{
				height:    bh.Height,
				timestamp: time.Now(),
			}
			blockCacheLen = len(l.blocksMissingCache)
			l.mtx.Unlock()
		}

		x++
		if x >= count {
			break
		}
	}

	log.Debugf("BlocksMissing returning %v cached %v", len(bis), blockCacheLen)

	return bis, nil

	// bmDB := l.pool[level.BlocksMissingDB]
	// bmTx, err := bmDB.OpenTransaction()
	// if err != nil {
	// 	return nil, fmt.Errorf("blocks missing open transaction: %w", err)
	// }
	// bmDiscard := true
	// defer func() {
	// 	if bmDiscard {
	// 		log.Debugf("BlocksMissing discarding transaction")
	// 		bmTx.Discard()
	// 	}
	// }()

	// x := 0
	// bis := make([]tbcd.BlockIdentifier, 0, count)
	// it := bmTx.NewIterator(nil, nil)
	// defer it.Release()
	// for it.Next() {
	// 	bh := tbcd.BlockIdentifier{}
	// 	bh.Height, bh.Hash = keyToHeightHash(it.Key())
	// 	bis = append(bis, bh)

	// 	// cache the reply
	// 	if l.blocksMissingCacheEnabled {
	// 		l.mtx.Lock()
	// 		l.blocksMissingCache[string(bh.Hash)] = &cacheEntry{
	// 			height:    bh.Height,
	// 			timestamp: time.Now(),
	// 		}
	// 		l.mtx.Unlock()
	// 	}

	// 	x++
	// 	if x >= count {
	// 		break
	// 	}
	// }

	// err = bmTx.Commit()
	// if err != nil {
	// 	return nil, fmt.Errorf("blocks missing commit: %w", err)
	// }
	// bmDiscard = false

	// return bis, nil
}

func (l *ldb) BlockInsert(ctx context.Context, b *tbcd.Block) (int64, error) {
	log.Tracef("BlockInsert")
	defer log.Tracef("BlockInsert exit")

	// Try cache first
	var ce *cacheEntry
	if l.blocksMissingCacheEnabled {
		// XXX explain here why using string(b.Hash) is acceptable
		l.mtx.Lock()
		ce = l.blocksMissingCache[string(b.Hash)]
		l.mtx.Unlock()

		defer func() {
			// purge cache as well
			l.mtx.Lock()
			delete(l.blocksMissingCache, string(b.Hash))
			bmcl := len(l.blocksMissingCache)
			l.mtx.Unlock()
			// XXX string b.Hash is shit
			log.Debugf("BlockInsert cached %v", bmcl)
		}()
	}

	// Determine block height either from cache or the database.
	var bh tbcd.BlockHeader

	// If cache entry is not found grab it from the database.
	if ce == nil {
		// Open the block headers database transaction
		bhsDB := l.pool[level.BlockHeadersDB]
		bhj, err := bhsDB.Get(b.Hash[:], nil)
		if err != nil {
			if err == leveldb.ErrNotFound {
				return -1, database.NotFoundError(fmt.Sprintf(
					"block insert block header not found: %x",
					b.Hash))
			}
			return -1, fmt.Errorf("block insert block header: %w", err)
		}
		err = json.Unmarshal(bhj, &bh)
		if err != nil {
			return -1, fmt.Errorf("block insert unmarshal: %w", err)
		}
	} else {
		bh.Height = ce.height
		bh.Hash = b.Hash
	}

	// Insert block without transaction, if it succeeds and the missing
	// does not it will be simply redone.
	bDB := l.pool[level.BlocksDB]
	has, err := bDB.Has(b.Hash[:], nil)
	if err != nil {
		return -1, fmt.Errorf("block insert has: %v", err)
	}
	if !has {
		// Insert block since we do not have it yet
		bj, err := json.Marshal(b)
		if err != nil {
			return -1, fmt.Errorf("blocks insert marshal: %v", err)
		}
		err = bDB.Put(b.Hash[:], bj, nil)
		if err != nil {
			return -1, fmt.Errorf("blocks insert put: %v", err)
		}
	}

	// XXX It may be possible to remove the transaction for bmTx as well
	// since the only risk would be duplicate work. Reason about this some more.

	//// blocks missing transaction
	//bmTx, bmCommit, bmDiscard, err := l.startTransaction(level.BlocksMissingDB)
	//if err != nil {
	//	return -1, fmt.Errorf("blocks missing open transaction: %w", err)
	//}
	//defer bmDiscard()

	// Remove block identifier from blocks missing
	key := heightHashToKey(bh.Height, bh.Hash)
	bmDB := l.pool[level.BlocksMissingDB]
	err = bmDB.Delete(key, nil)
	if err != nil {
		// Ignore not found
		if err == leveldb.ErrNotFound {
			log.Errorf("block insert delete from missing: %v", err)
		} else {
			return -1, fmt.Errorf("block insert delete from missing: %v", err)
		}
	}

	//// blocks missing commit
	//err = bmCommit()
	//if err != nil {
	//	return -1, fmt.Errorf("block missing commit: %w", err)
	//}

	// XXX think about Height type; why are we forced to mix types?
	return int64(bh.Height), nil

	//var (
	//	bhsTx      *leveldb.Transaction
	//	err        error
	//	bhsDiscard bool
	//)
	//if ce == nil {
	//	// Open the block headers database transaction
	//	bhsDB := l.pool[level.BlockHeadersDB]
	//	bhsTx, err = bhsDB.OpenTransaction()
	//	if err != nil {
	//		return -1, fmt.Errorf("block headers open transaction: %w", err)
	//	}
	//	bhsDiscard = true
	//	defer func() {
	//		if bhsDiscard {
	//			log.Debugf("BlockInsert discarding transaction")
	//			bhsTx.Discard()
	//		}
	//	}()
	//}

	//// Open the blocks missing database transaction
	//bmDB := l.pool[level.BlocksMissingDB]
	//bmTx, err := bmDB.OpenTransaction()
	//if err != nil {
	//	return -1, fmt.Errorf("blocks missing open transaction: %w", err)
	//}
	//bmDiscard := true
	//defer func() {
	//	if bmDiscard {
	//		log.Debugf("BlockInsert block missing discarding transaction")
	//		bmTx.Discard()
	//	}
	//}()

	//// Open the blocks database transaction
	//bDB := l.pool[level.BlocksDB]
	//bTx, err := bDB.OpenTransaction()
	//if err != nil {
	//	return -1, fmt.Errorf("blocks open transaction: %w", err)
	//}
	//bDiscard := true
	//defer func() {
	//	if bDiscard {
	//		log.Debugf("BlockInsert discarding transaction")
	//		bTx.Discard()
	//	}
	//}()

	//// Determine block height
	//var bh tbcd.BlockHeader
	//if ce == nil {
	//	bhj, err := bhsTx.Get(b.Hash[:], nil)
	//	if err != nil {
	//		if err == leveldb.ErrNotFound {
	//			return -1, database.NotFoundError(fmt.Sprintf("block header not found: %x", b.Hash))
	//		}
	//		return -1, fmt.Errorf("block insert block header: %w", err)
	//	}
	//	err = json.Unmarshal(bhj, &bh)
	//	if err != nil {
	//		return -1, fmt.Errorf("block insert unmarshal: %w", err)
	//	}
	//} else {
	//	bh.Height = ce.height
	//	bh.Hash = b.Hash
	//}

	//// Remove block identifier from blocks missing
	//key := heightHashToKey(bh.Height, bh.Hash)
	//err = bmTx.Delete(key, nil)
	//if err != nil {
	//	// Ignore not found
	//	if err == leveldb.ErrNotFound {
	//		log.Errorf("block insert delete from missing: %v", err)
	//	} else {
	//		return -1, fmt.Errorf("block insert delete from missing: %v", err)
	//	}
	//}

	//// Insert block
	//bj, err := json.Marshal(b)
	//if err != nil {
	//	return -1, fmt.Errorf("block insert marshal: %v", err)
	//}
	//err = bTx.Put(b.Hash[:], bj, nil)
	//if err != nil {
	//	return -1, fmt.Errorf("block insert put: %v", err)
	//}

	//// Reverse order unlock
	//err = bTx.Commit()
	//if err != nil {
	//	return -1, fmt.Errorf("block commit: %w", err)
	//}
	//bDiscard = false

	//err = bmTx.Commit()
	//if err != nil {
	//	return -1, fmt.Errorf("blocks missing commit: %w", err)
	//}
	//bmDiscard = false

	//if ce == nil {
	//	err = bhsTx.Commit()
	//	if err != nil {
	//		return -1, fmt.Errorf("blocks headers commit: %w", err)
	//	}
	//	bhsDiscard = false
	//}

	//// XXX think about Height type; why are we forced to mix types?
	//return int64(bh.Height), nil
}

func (l *ldb) PeersInsert(ctx context.Context, peers []tbcd.Peer) error {
	log.Tracef("PeersInsert")
	defer log.Tracef("PeersInsert exit")

	l.mtx.Lock()
	defer l.mtx.Unlock()

	for k := range peers {
		p := peers[k]
		a := net.JoinHostPort(p.Host, p.Port)
		if len(a) < 7 {
			// 0.0.0.0
			continue
		}
		if strings.HasPrefix(a, "[") {
			// XXX skip v6 for now with crude test
			continue
		}
		if _, ok := l.peersBad[a]; ok {
			// Skip bad peers
			continue
		}
		if _, ok := l.peersGood[a]; ok {
			// Not strictly needed to skip but this os working pseudode code
			continue
		}

		l.peersGood[a] = struct{}{}
	}

	return nil

	//if len(peers) == 0 {
	//	return fmt.Errorf("peers insert: no peers to insert")
	//}

	//// Open the block peers database
	//peersDB := l.pool[level.PeersDB]
	//peersTx, err := peersDB.OpenTransaction()
	//if err != nil {
	//	return fmt.Errorf("peers open transaction: %w", err)
	//}
	//peersDiscard := true
	//defer func() {
	//	if peersDiscard {
	//		log.Debugf("PeersInsert discarding transaction: %v", len(peers))
	//		peersTx.Discard()
	//	}
	//}()

	//// Insert/update missing peers.
	//peersBatch := new(leveldb.Batch)
	//for k := range peers {
	//	address := net.JoinHostPort(peers[k].Host, peers[k].Port)
	//	if ok, err := peersTx.Has([]byte(address), nil); err == nil && ok {
	//		continue
	//	}

	//	// Insert JSON encoded peer record
	//	peers[k].CreatedAt = database.NewTimestamp(time.Now())
	//	peerj, err := json.Marshal(peers[k])
	//	if err != nil {
	//		return fmt.Errorf("json marshal %v: %w", k, err)
	//	}
	//	peersBatch.Put([]byte(address), peerj)
	//}

	//// Write peers batch
	//err = peersTx.Write(peersBatch, nil)
	//if err != nil {
	//	return fmt.Errorf("peers insert: %w", err)
	//}

	//// Commit peers table
	//err = peersTx.Commit()
	//if err != nil {
	//	return fmt.Errorf("peers commit: %w", err)
	//}
	//peersDiscard = false

	// return nil
}

func (l *ldb) PeerDelete(ctx context.Context, host, port string) error {
	log.Tracef("PeerDelete")
	defer log.Tracef("PeerDelete exit")

	l.mtx.Lock()
	defer l.mtx.Unlock()

	a := net.JoinHostPort(host, port)
	if len(a) < 7 {
		// 0.0.0.0
		return nil
	}
	if strings.HasPrefix(a, "[") {
		// XXX skip v6 for now with crude test
		return nil
	}

	if _, ok := l.peersGood[a]; ok {
		delete(l.peersGood, a)
		l.peersBad[a] = struct{}{}
	}
	return nil

	//// Open the block peers database
	//peersDB := l.pool[level.PeersDB]
	//peersTx, err := peersDB.OpenTransaction()
	//if err != nil {
	//	return fmt.Errorf("peers delete transaction: %w", err)
	//}
	//peersDiscard := true
	//defer func() {
	//	if peersDiscard {
	//		log.Debugf("PeerDelete discarding transaction: %v", address)
	//		peersTx.Discard()
	//	}
	//}()

	//err = peersTx.Delete([]byte(address), nil)
	//if err != nil {
	//	return fmt.Errorf("peers delete: %w", err)
	//}

	//// Commit peers table
	//err = peersTx.Commit()
	//if err != nil {
	//	return fmt.Errorf("peers commit: %w", err)
	//}
	//peersDiscard = false

	// return nil
}

func (l *ldb) PeersRandom(ctx context.Context, count int) ([]tbcd.Peer, error) {
	log.Tracef("PeersRandom")

	x := 0
	peers := make([]tbcd.Peer, 0, count)

	l.mtx.Lock()
	allGoodPeers := len(l.peersGood)
	allBadPeers := len(l.peersBad)
	for k := range l.peersGood {
		h, p, err := net.SplitHostPort(k)
		if err != nil {
			continue
		}
		peers = append(peers, tbcd.Peer{Host: h, Port: p})
		x++
		if x >= count {
			break
		}
	}
	l.mtx.Unlock()

	log.Tracef("PeersRandom exit %v (good %v bad %v)", len(peers),
		allGoodPeers, allBadPeers)

	return peers, nil

	//// XXX For now return peers in order and let the stack above deal with it.

	//// Open the block peers database
	//peersDB := l.pool[level.PeersDB]
	//peersTx, err := peersDB.OpenTransaction()
	//if err != nil {
	//	return nil, fmt.Errorf("peers random transaction: %w", err)
	//}
	//peersDiscard := true
	//defer func() {
	//	if peersDiscard {
	//		log.Debugf("PeersRandom discarding transaction: %v", count)
	//		peersTx.Discard()
	//	}
	//}()

	//// Read a record and skip some
	//x := 0
	//peers := make([]tbcd.Peer, 0, count)
	//it := peersTx.NewIterator(nil, nil)
	//defer it.Release()
	//for it.Next() {
	//	var peer tbcd.Peer
	//	err := json.Unmarshal(it.Value(), &peer)
	//	if err != nil {
	//		return nil, fmt.Errorf("peers random unmarshal: %w", err)
	//	}
	//	peers = append(peers, peer)

	//	x++
	//	if x >= count {
	//		break
	//	}
	//}
	//log.Tracef(spew.Sdump(peers))

	//// Commit peers table
	//err = peersTx.Commit()
	//if err != nil {
	//	return nil, fmt.Errorf("peers random commit: %w", err)
	//}
	//peersDiscard = false

	// return peers, nil
}
