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
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Locking order:
//	BlockHeaders
// 	BlocksMissing
// 	HeightHash
// 	Blocks

const (
	ldbVersion = 1

	logLevel = "INFO"
	verbose  = false

	bhsLastKey = "last"

	minPeersRequired = 64 // minimum number of peers in good map before cache is purged
)

var log = loggo.GetLogger("level")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type ldb struct {
	mtx                       sync.Mutex
	blocksMissingCacheEnabled bool
	blocksMissingCache        map[string]*cacheEntry // XXX purge and manages cache size

	// maybe remove this because it eats a bit of memory
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
}

func (l *ldb) BlockHeadersByHeight(ctx context.Context, height uint64) ([]tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersByHeight")
	defer log.Tracef("BlockHeadersByHeight exit")

	bhs := make([]tbcd.BlockHeader, 0, 4)
	start := make([]byte, 8)
	binary.BigEndian.PutUint64(start, height)
	limit := make([]byte, 8)
	binary.BigEndian.PutUint64(limit, height+2)

	hhDB := l.pool[level.HeightHashDB]
	it := hhDB.NewIterator(&util.Range{Start: start, Limit: limit}, nil)
	defer it.Release()
	for it.Next() {
		fh, hash := keyToHeightHash(it.Key())
		if fh != height {
			// all done
			break
		}
		bh, err := l.BlockHeaderByHash(ctx, hash)
		if err != nil {
			return nil, fmt.Errorf("headers by height: %w", err)
		}
		bhs = append(bhs, *bh)
	}
	return bhs, nil
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

	// height hash
	hhTx, hhCommit, hhDiscard, err := l.startTransaction(level.HeightHashDB)
	if err != nil {
		return fmt.Errorf("height hash open transaction: %w", err)
	}
	defer hhDiscard()

	// Insert missing blocks and block headers
	var lastRecord []byte
	hhBatch := new(leveldb.Batch)
	bmBatch := new(leveldb.Batch)
	bhsBatch := new(leveldb.Batch)
	for k := range bhs {
		hhKey := heightHashToKey(bhs[k].Height, bhs[k].Hash[:])
		// Height 0 is genesis, we do not want a missing block record for that.
		if bhs[k].Height != 0 {
			// Insert a synthesized height_hash key that serves as
			// an index to see which blocks are missing.
			bmBatch.Put(hhKey, []byte{})
		}

		// Store height_hash for future reference
		hhBatch.Put(hhKey, []byte{})

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

	// Write height hash batch
	err = hhTx.Write(hhBatch, nil)
	if err != nil {
		return fmt.Errorf("height hash batch: %w", err)
	}

	// Write missing blocks batch
	err = bmTx.Write(bmBatch, nil)
	if err != nil {
		return fmt.Errorf("blocks missing batch: %w", err)
	}

	// Write block headers batch
	err = bhsTx.Write(bhsBatch, nil)
	if err != nil {
		return fmt.Errorf("block headers insert: %w", err)
	}

	// height hash commit
	err = hhCommit()
	if err != nil {
		return fmt.Errorf("height hash commit: %w", err)
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

	// It's possible to remove the transaction for bm without a transaction
	// as well since the only risk would be duplicate work. Reason about
	// this some more.

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
	// XXX think about Height type; why are we forced to mix types?
	return int64(bh.Height), nil
}

func (l *ldb) BlockByHash(ctx context.Context, hash []byte) (*tbcd.Block, error) {
	log.Tracef("BlockByHash")
	defer log.Tracef("BlockByHash exit")

	bDB := l.pool[level.BlocksDB]
	jbh, err := bDB.Get(hash, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, database.NotFoundError(fmt.Sprintf("block not found: %x", hash))
		}
		return nil, fmt.Errorf("block get: %w", err)
	}
	var b tbcd.Block
	err = json.Unmarshal(jbh, &b)
	if err != nil {
		return nil, fmt.Errorf("block unmarshal: %w", err)
	}

	return &b, nil
}

func (l *ldb) PeersInsert(ctx context.Context, peers []tbcd.Peer) error {
	log.Tracef("PeersInsert")
	defer log.Tracef("PeersInsert exit")

	l.mtx.Lock()
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
	allGoodPeers := len(l.peersGood)
	allBadPeers := len(l.peersBad)
	l.mtx.Unlock()

	log.Debugf("PeersInsert exit %v good %v bad %v",
		len(peers), allGoodPeers, allBadPeers)

	return nil
}

func (l *ldb) PeerDelete(ctx context.Context, host, port string) error {
	log.Tracef("PeerDelete")
	defer log.Tracef("PeerDelete exit")

	a := net.JoinHostPort(host, port)
	if len(a) < 7 {
		// 0.0.0.0
		return nil
	}

	l.mtx.Lock()
	if _, ok := l.peersGood[a]; ok {
		delete(l.peersGood, a)
		l.peersBad[a] = struct{}{}
	}

	// Crude hammer to reset good/bad state of peers
	if len(l.peersGood) < minPeersRequired {
		// Kill all peers to force caller to reseed. This happens when
		// network is down for a while and all peers are moved into
		// bad map.
		l.peersGood = make(map[string]struct{}, 1000)
		l.peersBad = make(map[string]struct{}, 1000)
		log.Tracef("peer cache purged")
	}

	allGoodPeers := len(l.peersGood)
	allBadPeers := len(l.peersBad)

	l.mtx.Unlock()

	log.Debugf("PeerDelete exit good %v bad %v", allGoodPeers, allBadPeers)

	return nil
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

	log.Debugf("PeersRandom exit %v (good %v bad %v)", len(peers),
		allGoodPeers, allBadPeers)

	// XXX For now return peers in order and let the stack above deal with it.
	return peers, nil
}
