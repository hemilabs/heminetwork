// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/level"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

// Locking order:
//
//	BlockHeaders
//	BlocksMissing
//	HeightHash
//	Blocks
//
//	Balances
//	Utxos

const (
	ldbVersion = 1

	logLevel = "INFO"
	verbose  = false

	bhsLastKey = "last"

	minPeersRequired = 64 // minimum number of peers in good map before cache is purged
)

type IteratorError error

var log = loggo.GetLogger("level")

var ErrIterator = IteratorError(errors.New("iteration error"))

func init() {
	loggo.ConfigureLoggers(logLevel)
}

func b2h(header []byte) (*wire.BlockHeader, error) {
	var bh wire.BlockHeader
	err := bh.Deserialize(bytes.NewReader(header))
	if err != nil {
		return nil, fmt.Errorf("deserialize block header: %w", err)
	}
	return &bh, nil
}

func headerHash(header []byte) *chainhash.Hash {
	h, err := b2h(header)
	if err != nil {
		panic(err)
	}
	hash := h.BlockHash()
	return &hash
}

func headerParentHash(header []byte) *chainhash.Hash {
	h, err := b2h(header)
	if err != nil {
		panic(err)
	}
	return &h.PrevBlock
}

type ldb struct {
	mtx                       sync.Mutex
	blocksMissingCacheEnabled bool                   // XXX verify this code in tests
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

func (l *ldb) MetadataGet(ctx context.Context, key []byte) ([]byte, error) {
	log.Tracef("MetadataGet")
	defer log.Tracef("MetadataGet exit")

	mdDB := l.pool[level.MetadataDB]
	v, err := mdDB.Get(key, nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		return nil, database.NotFoundError(fmt.Sprintf("key not found: %v",
			string(key)))
	}
	return v, err
}

func (l *ldb) MetadataPut(ctx context.Context, key, value []byte) error {
	log.Tracef("MetadataPut")
	defer log.Tracef("MetadataPut exit")

	mdDB := l.pool[level.MetadataDB]
	return mdDB.Put(key, value, nil)
}

func (l *ldb) BlockHeaderByHash(ctx context.Context, hash []byte) (*tbcd.BlockHeader, error) {
	log.Tracef("BlockHeaderByHash")
	defer log.Tracef("BlockHeaderByHash exit")

	// It stands to reason that this code does not need a trasaction. The
	// caller code will either receive or not receice an answer. It does
	// not seem likely to be racing higher up in the stack.

	bhsDB := l.pool[level.BlockHeadersDB]
	ebh, err := bhsDB.Get(hash, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError(fmt.Sprintf("block header not found: %x", hash))
		}
		return nil, fmt.Errorf("block header get: %w", err)
	}
	return decodeBlockHeader(ebh), nil
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
	if len(bhs) == 0 {
		return nil, database.NotFoundError("block headers not found")
	}
	return bhs, nil
}

func (l *ldb) BlockHeaderBest(ctx context.Context) (*tbcd.BlockHeader, error) {
	log.Tracef("BlockHeaderBest")
	defer log.Tracef("BlockHeaderBest exit")

	// This function is a bit of a crapshoot. It will receive many calls
	// and thus it is racing by definition. Avoid the lock and let the
	// caller serialize the response.

	bhsDB := l.pool[level.BlockHeadersDB]
	// Get last record
	ebh, err := bhsDB.Get([]byte(bhsLastKey), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError("best block header not found")
		}
		return nil, fmt.Errorf("block headers best: %w", err)
	}
	return decodeBlockHeader(ebh), nil
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

// encodeBlockHeader encodes a database block header as
// [height,header,difficulty] or [8+80+32] bytes. The hash is the leveldb table
// key.
func encodeBlockHeader(height uint64, header [80]byte, difficulty *big.Int) (ebhr [120]byte) {
	binary.BigEndian.PutUint64(ebhr[0:8], height)
	copy(ebhr[8:88], header[:])
	difficulty.FillBytes(ebhr[88:120])
	return
}

// decodeBlockHeader reverse the process of encodeBlockHeader.
// XXX should we have a function that does not call the expensive headerHash function?
func decodeBlockHeader(ebh []byte) *tbcd.BlockHeader {
	// copy the values to prevent slicing reentrancy problems.
	var (
		header [80]byte
	)
	copy(header[:], ebh[8:88])
	bh := &tbcd.BlockHeader{
		Hash:   headerHash(header[:])[:],
		Height: binary.BigEndian.Uint64(ebh[0:8]),
		Header: header[:],
	}
	(&bh.Difficulty).SetBytes(ebh[88:])
	return bh
}

// XXX this really is onlu use to insert genesis. Maybe make it a bit less db
// tx or whatnot.
func (l *ldb) BlockHeaderInsert(ctx context.Context, height uint64, bh [80]byte) error {
	log.Tracef("BlockHeaderInsert")
	defer log.Tracef("BlockHeaderInsert exit")

	wbh, err := b2h(bh[:])
	if err != nil {
		return fmt.Errorf("block header insert b2h: %w", err)
	}
	bhash := wbh.BlockHash()

	// block headers
	bhsTx, bhsCommit, bhsDiscard, err := l.startTransaction(level.BlockHeadersDB)
	if err != nil {
		return fmt.Errorf("block header open transaction: %w", err)
	}
	defer bhsDiscard()

	// Make sure we are not inserting the same blocks
	has, err := bhsTx.Has(bhash[:], nil)
	if err != nil {
		return fmt.Errorf("block header insert has: %w", err)
	}
	if has {
		return database.DuplicateError("block header insert duplicate")
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

	// Insert height hash, missing, block header
	hhBatch := new(leveldb.Batch)
	bmBatch := new(leveldb.Batch)
	bhBatch := new(leveldb.Batch)

	hhKey := heightHashToKey(height, bhash[:])
	hhBatch.Put(hhKey, []byte{})
	if height != 0 {
		// XXX this is too magical and asumes genesis has been inserted
		bmBatch.Put(hhKey, []byte{})
	}
	ebh := encodeBlockHeader(height, bh, new(big.Int)) // XXX this is not correct
	bhBatch.Put(bhash[:], ebh[:])

	bhBatch.Put([]byte(bhsLastKey), ebh[:]) // XXX this is not correct

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
	err = bhsTx.Write(bhBatch, nil)
	if err != nil {
		return fmt.Errorf("block header insert: %w", err)
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
		return fmt.Errorf("block header commit: %w", err)
	}

	return nil
}

// BlockHeadersInsert decodes and inserts the passed blockheaders into the
// database. Additionally it updates the hight/hash and missing blocks table as
// well.  On return it informs the caller about potential forking situations.
// This call uses the database to prevent reentrancy.
func (l *ldb) BlockHeadersInsert(ctx context.Context, bhs [][80]byte) (tbcd.InsertType, *tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersInsert")
	defer log.Tracef("BlockHeadersInsert exit")

	if len(bhs) == 0 {
		return tbcd.ITInvalid, nil,
			errors.New("block headers insert: no block headers to insert")
	}

	// Ensure we can connect these blockheaders prior to starting database
	// transaction. This also obtains the starting cumulative difficulty
	// and  height.
	wbh, err := b2h(bhs[0][:])
	if err != nil {
		return tbcd.ITInvalid, nil,
			fmt.Errorf("block headers insert b2h: %w", err)
	}
	pbh, err := l.BlockHeaderByHash(ctx, wbh.PrevBlock[:])
	if err != nil {
		return tbcd.ITInvalid, nil, fmt.Errorf("block headers insert: %w", err)
	}

	// block headers
	bhsTx, bhsCommit, bhsDiscard, err := l.startTransaction(level.BlockHeadersDB)
	if err != nil {
		return tbcd.ITInvalid, nil,
			fmt.Errorf("block headers open transaction: %w", err)
	}
	defer bhsDiscard()

	// Make sure we are not inserting the same blocks
	bhash := wbh.BlockHash()
	has, err := bhsTx.Has(bhash[:], nil)
	if err != nil {
		return tbcd.ITInvalid, nil,
			fmt.Errorf("block headers insert has: %w", err)
	}
	if has {
		return tbcd.ITInvalid, nil,
			database.DuplicateError("block headers insert duplicate")
	}

	// blocks missing
	bmTx, bmCommit, bmDiscard, err := l.startTransaction(level.BlocksMissingDB)
	if err != nil {
		return tbcd.ITInvalid, nil,
			fmt.Errorf("blocks missing open transaction: %w", err)
	}
	defer bmDiscard()

	// height hash
	hhTx, hhCommit, hhDiscard, err := l.startTransaction(level.HeightHashDB)
	if err != nil {
		return tbcd.ITInvalid, nil,
			fmt.Errorf("height hash open transaction: %w", err)
	}
	defer hhDiscard()

	// retrieve best record
	var lastRecord []byte
	bbh, err := bhsTx.Get([]byte(bhsLastKey), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return tbcd.ITInvalid, nil,
				database.NotFoundError("best block header not found")
		}
		return tbcd.ITInvalid, nil, fmt.Errorf("best block header: %v", err)
	}
	bestBH := decodeBlockHeader(bbh)

	// Fork is set to true if the first blockheader does not connect to the
	// canonical blockheader.
	fork := !bytes.Equal(wbh.PrevBlock[:], bestBH.Hash[:])

	// Insert missing blocks and block headers
	hhBatch := new(leveldb.Batch)
	bmBatch := new(leveldb.Batch)
	bhsBatch := new(leveldb.Batch)

	cdiff := &pbh.Difficulty
	height := pbh.Height
	// XXX if we zap the blockheaders table we should only
	// insert *if* block indeed does not exist

	for k, bh := range bhs {
		// The first element is skipped, as it is pre-decoded.
		if k != 0 {
			wbh, err = b2h(bh[:])
			if err != nil {
				return tbcd.ITInvalid, nil,
					fmt.Errorf("block headers insert b2h: %w", err)
			}
			bhash = wbh.BlockHash()
		}

		// pre set values because we start with previous value
		height++
		cdiff = new(big.Int).Add(cdiff, blockchain.CalcWork(wbh.Bits))

		// Store height_hash for future reference
		hhKey := heightHashToKey(height, bhash[:])
		hhBatch.Put(hhKey, []byte{})

		// Insert a synthesized height_hash key that serves as an index
		// to see which blocks are missing.
		// XXX should we always insert or should we verify prior to insert?
		bmBatch.Put(hhKey, []byte{})

		// XXX reason about pre encoding. Due to the caller code being
		// heavily reentrant the odds are not good that encoding would
		// only happens once. The downside is that this encoding
		// happens in the database transaction and is thus locked.

		// Encode block header as [hash][height,header,cdiff] or,
		// [32][8+80+32] bytes
		ebh := encodeBlockHeader(height, bh, cdiff)
		bhsBatch.Put(bhash[:], ebh[:])
		lastRecord = ebh[:]
	}

	// Insert last height into block headers if the new cumulative
	// difficulty exceeds the prior difficulty.
	var it tbcd.InsertType
	switch cdiff.Cmp(&bestBH.Difficulty) {
	case -1:
		// Extend fork, fork did not overcome difficulty
		bhsBatch.Put([]byte(bhsLastKey), lastRecord)
		it = tbcd.ITChainFork

		// XXX should we return old best block header here?
		// That way the caller can do best vs previous best diff.
		log.Debugf("(%v) -1: %v < %v", height, cdiff, bestBH.Difficulty)
	case 0:
		// Extend fork to the same exact difficulty
		it = tbcd.ITForkExtend
		log.Debugf("(%v) 0: %v = %v", height, cdiff, bestBH.Difficulty)
	case 1:
		log.Debugf("(%v) 1: %v > %v", height, cdiff, bestBH.Difficulty)
		// log.Infof("%v", spew.Sdump(bestBH.Hash[:]))
		// log.Infof("%v", spew.Sdump(firstHash))
		// Extend current best tip
		bhsBatch.Put([]byte(bhsLastKey), lastRecord)
		// pick the right return value based on ancestorA
		if fork { // bytes.Equal(firstHash[:], bestBH.Hash[:]) {
			it = tbcd.ITChainFork
		} else {
			it = tbcd.ITChainExtend
		}
	default:
		panic("impossible cmp")
	}

	// Create artificial last block header to return to caller.
	// Note that this *can be* a fork!
	var header [80]byte
	copy(header[:], bhs[len(bhs)-1][:])
	lbh := &tbcd.BlockHeader{
		Hash:       bhash[:],
		Height:     height,
		Header:     header[:],
		Difficulty: *cdiff,
	}

	// Write height hash batch
	err = hhTx.Write(hhBatch, nil)
	if err != nil {
		return tbcd.ITInvalid, nil, fmt.Errorf("height hash batch: %w", err)
	}

	// Write missing blocks batch
	err = bmTx.Write(bmBatch, nil)
	if err != nil {
		return tbcd.ITInvalid, nil, fmt.Errorf("blocks missing batch: %w", err)
	}

	// Write block headers batch
	err = bhsTx.Write(bhsBatch, nil)
	if err != nil {
		return tbcd.ITInvalid, nil, fmt.Errorf("block headers insert: %w", err)
	}

	// height hash commit
	err = hhCommit()
	if err != nil {
		return tbcd.ITInvalid, nil, fmt.Errorf("height hash commit: %w", err)
	}

	// blocks missing commit
	err = bmCommit()
	if err != nil {
		return tbcd.ITInvalid, nil, fmt.Errorf("blocks missing commit: %w", err)
	}

	// block headers commit
	err = bhsCommit()
	if err != nil {
		return tbcd.ITInvalid, nil, fmt.Errorf("block headers commit: %w", err)
	}

	return it, lbh, nil
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
			// XXX we MUST bind this map but for now let it be piggy
			if _, ok := l.blocksMissingCache[string(bh.Hash)]; !ok {
				l.blocksMissingCache[string(bh.Hash)] = &cacheEntry{
					height:    bh.Height,
					timestamp: time.Now(),
				}
			}
			blockCacheLen = len(l.blocksMissingCache)
			l.mtx.Unlock()
		}
		// if blockCacheLen >= 128 {
		//	log.Tracef("max cache %v", blockCacheLen)
		//	break
		// }

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
	var bh *tbcd.BlockHeader

	// If cache entry is not found grab it from the database.
	if ce == nil {
		// Open the block headers database transaction
		bhsDB := l.pool[level.BlockHeadersDB]
		ebh, err := bhsDB.Get(b.Hash, nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				return -1, database.NotFoundError(fmt.Sprintf(
					"block insert block header not found: %v",
					b.Hash))
			}
			return -1, fmt.Errorf("block insert block header: %w", err)
		}
		bh = decodeBlockHeader(ebh)
	} else {
		bh = &tbcd.BlockHeader{
			Height: ce.height,
			Hash:   b.Hash,
		}
	}

	// Insert block without transaction, if it succeeds and the missing
	// does not it will be simply redone.
	bDB := l.pool[level.BlocksDB]
	has, err := bDB.Has(b.Hash, nil)
	if err != nil {
		return -1, fmt.Errorf("block insert has: %w", err)
	}
	if !has {
		// Insert block since we do not have it yet
		err = bDB.Put(b.Hash, b.Block, nil)
		if err != nil {
			return -1, fmt.Errorf("blocks insert put: %w", err)
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
		if errors.Is(err, leveldb.ErrNotFound) {
			log.Errorf("block insert delete from missing: %v", err)
		} else {
			return -1, fmt.Errorf("block insert delete from missing: %w", err)
		}
	}
	// XXX think about Height type; why are we forced to mix types?
	return int64(bh.Height), nil
}

func (l *ldb) BlockByHash(ctx context.Context, hash []byte) (*tbcd.Block, error) {
	log.Tracef("BlockByHash")
	defer log.Tracef("BlockByHash exit")

	bDB := l.pool[level.BlocksDB]
	eb, err := bDB.Get(hash, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			ch, _ := chainhash.NewHash(hash)
			return nil, database.NotFoundError(fmt.Sprintf("block not found: %v", ch))
		}
		return nil, fmt.Errorf("block get: %w", err)
	}
	return &tbcd.Block{
		Hash:  hash,
		Block: eb,
	}, nil
}

func (l *ldb) BlocksByTxId(ctx context.Context, txId tbcd.TxId) ([]tbcd.BlockHash, error) {
	log.Tracef("BlocksByTxId")
	defer log.Tracef("BlocksByTxId exit")

	blocks := make([]tbcd.BlockHash, 0, 2)
	txDB := l.pool[level.TransactionsDB]
	var txid [33]byte
	txid[0] = 't'
	copy(txid[1:], txId[:])
	it := txDB.NewIterator(util.BytesPrefix(txid[:]), nil)
	defer it.Release()
	for it.Next() {
		block, err := tbcd.NewBlockHashFromBytes(it.Key()[33:])
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	if err := it.Error(); err != nil {
		return nil, fmt.Errorf("blocks by id iterator: %w", err)
	}
	if len(blocks) == 0 {
		ch, _ := chainhash.NewHash(txId[:])
		return nil, database.NotFoundError(fmt.Sprintf("tx not found: %v", ch))
	}

	return blocks, nil
}

func (l *ldb) SpendOutputsByTxId(ctx context.Context, txId tbcd.TxId) ([]tbcd.SpendInfo, error) {
	log.Tracef("SpendOutputByOutpoint")
	defer log.Tracef("SpendOutputByOutpoint exit")

	si := make([]tbcd.SpendInfo, 0, 2)
	txDB := l.pool[level.TransactionsDB]
	var key [1 + 32]byte
	key[0] = 's'
	copy(key[1:], txId[:])
	it := txDB.NewIterator(&util.Range{Start: key[:]}, nil)
	defer it.Release()
	for it.Next() {
		if !bytes.Equal(it.Key()[1:33], key[1:33]) {
			break
		}
		var s tbcd.SpendInfo
		copy(s.TxId[:], it.Value()[0:32])
		copy(s.BlockHash[:], it.Key()[37:])
		s.InputIndex = binary.BigEndian.Uint32(it.Value()[32:36])
		si = append(si, s)
	}
	if err := it.Error(); err != nil {
		return nil, fmt.Errorf("blocks by id iterator: %w", err)
	}
	if len(si) == 0 {
		ch, _ := chainhash.NewHash(txId[:])
		return nil, database.NotFoundError(fmt.Sprintf("not found %v", ch))
	}

	return si, nil
}

func (l *ldb) ScriptHashByOutpoint(ctx context.Context, op tbcd.Outpoint) (*tbcd.ScriptHash, error) {
	log.Tracef("ScriptHashByOutpoint")
	defer log.Tracef("ScriptHashByOutpoint exit")

	uDB := l.pool[level.OutputsDB]
	scriptHash, err := uDB.Get(op[:], nil)
	if err != nil {
		return nil, fmt.Errorf("script hash by outpoint: %w", err)
	}

	sh, err := tbcd.NewScriptHashFromBytes(scriptHash)
	return &sh, err
}

func (l *ldb) BalanceByScriptHash(ctx context.Context, sh tbcd.ScriptHash) (uint64, error) {
	log.Tracef("BalanceByScriptHash")
	defer log.Tracef("BalanceByScriptHash exit")

	var (
		start   [33]byte
		balance uint64
	)
	start[0] = 'h'
	copy(start[1:], sh[:])
	oDB := l.pool[level.OutputsDB]
	it := oDB.NewIterator(util.BytesPrefix(start[:]), nil)
	defer it.Release()
	for it.Next() {
		balance += binary.BigEndian.Uint64(it.Value())
	}
	if err := it.Error(); err != nil {
		return 0, IteratorError(err)
	}

	return balance, nil
}

func (l *ldb) UtxosByScriptHash(ctx context.Context, sh tbcd.ScriptHash, start uint64, count uint64) ([]tbcd.Utxo, error) {
	log.Tracef("UtxosByScriptHash")
	defer log.Tracef("UtxosByScriptHash exit")

	var prefix [33]byte
	utxos := make([]tbcd.Utxo, 0, 32)
	prefix[0] = 'h'
	copy(prefix[1:], sh[:])
	oDB := l.pool[level.OutputsDB]
	it := oDB.NewIterator(util.BytesPrefix(prefix[:]), nil)
	defer it.Release()
	skip := start
	for it.Next() {
		if skip > 0 {
			skip--
			continue
		}
		index := binary.BigEndian.Uint32(it.Key()[65:])
		value := binary.BigEndian.Uint64(it.Value())
		var txId tbcd.TxId
		copy(txId[:], it.Key()[33:65])
		utxos = append(utxos, tbcd.NewUtxo(txId, value, index))

		if len(utxos) >= int(count) {
			break
		}
	}
	if err := it.Error(); err != nil {
		return nil, IteratorError(err)
	}

	return utxos, nil
}

func (l *ldb) BlockUtxoUpdate(ctx context.Context, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	log.Tracef("BlockUtxoUpdate")
	defer log.Tracef("BlockUtxoUpdate exit")

	// outputs
	outsTx, outsCommit, outsDiscard, err := l.startTransaction(level.OutputsDB)
	if err != nil {
		return fmt.Errorf("outputs open db transaction: %w", err)
	}
	defer outsDiscard()

	outsBatch := new(leveldb.Batch)
	for op, utxo := range utxos {
		// op is already 'u' tx_id idx

		var hop [69]byte // 'h' script_hash tx_id tx_output_idx
		hop[0] = 'h'
		copy(hop[1:33], utxo.ScriptHashSlice())
		copy(hop[33:65], op.TxId())
		copy(hop[65:], utxo.OutputIndexBytes())

		if utxo.IsDelete() {
			// Delete balance and utxos
			outsBatch.Delete(op[:][:])
			outsBatch.Delete(hop[:])
		} else {
			// Add utxo to balance and utxos
			outsBatch.Put(op[:], utxo.ScriptHashSlice())
			outsBatch.Put(hop[:], utxo.ValueBytes())
		}
		// XXX this probably should be done by the caller but we do it
		// here to lower memory pressure as large gobs of data are
		// written to disk.
		delete(utxos, op)
	}

	// Write outputs batch
	err = outsTx.Write(outsBatch, nil)
	if err != nil {
		return fmt.Errorf("outputs insert: %w", err)
	}

	// outputs commit
	err = outsCommit()
	if err != nil {
		return fmt.Errorf("outputs commit: %w", err)
	}

	return nil
}

func (l *ldb) BlockTxUpdate(ctx context.Context, txs map[tbcd.TxKey]*tbcd.TxValue) error {
	log.Tracef("BlockTxUpdate")
	defer log.Tracef("BlockTxUpdate exit")

	// transactions
	txsTx, txsCommit, txsDiscard, err := l.startTransaction(level.TransactionsDB)
	if err != nil {
		return fmt.Errorf("transactions open db transaction: %w", err)
	}
	defer txsDiscard()

	txsBatch := new(leveldb.Batch)
	for k, v := range txs {
		// cache is being emptied so we can slice it here.
		var key, value []byte
		switch k[0] {
		case 't':
			key = k[0:65]
			value = nil

		case 's':
			key = k[:]
			value = v[:]
		default:
			return fmt.Errorf("invalid cache entry: %v", spew.Sdump(k))
		}

		txsBatch.Put(key, value)
		// log.Infof("%v:%v", spew.Sdump(key), spew.Sdump(value))
		// // XXX this probably should be done by the caller but we do it
		// // here to lower memory pressure as large gobs of data are
		// // written to disk.
		delete(txs, k)
	}

	// Write transactions batch
	err = txsTx.Write(txsBatch, nil)
	if err != nil {
		return fmt.Errorf("transactions insert: %w", err)
	}

	// transactions commit
	err = txsCommit()
	if err != nil {
		return fmt.Errorf("transactions commit: %w", err)
	}

	return nil
}

func (l *ldb) PeersStats(ctx context.Context) (int, int) {
	log.Tracef("PeersInsert")
	defer log.Tracef("PeersInsert exit")

	l.mtx.Lock()
	defer l.mtx.Unlock()
	return len(l.peersGood), len(l.peersBad)
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
