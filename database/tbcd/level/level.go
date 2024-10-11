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
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	lru "github.com/hashicorp/golang-lru/v2"
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
//	UTXOs

const (
	ldbVersion = 1

	logLevel = "INFO"
	verbose  = false

	bhsCanonicalTipKey = "canonicaltip"
)

type IteratorError error

var log = loggo.GetLogger("level")

var ErrIterator = IteratorError(errors.New("iteration error"))

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type ldb struct {
	mtx sync.Mutex

	*level.Database
	pool    level.Pool
	rawPool level.RawPool

	blockCache *lru.Cache[chainhash.Hash, *btcutil.Block] // block cache

	// Block Header cache. Note that it is only primed during reads. Doing
	// this during writes would be relatively expensive at nearly no gain.
	headerCache *lowIQMap

	cfg *Config
}

var _ tbcd.Database = (*ldb)(nil)

func h2b(wbh *wire.BlockHeader) [80]byte {
	var b bytes.Buffer
	err := wbh.Serialize(&b)
	if err != nil {
		panic(err)
	}
	var bh [80]byte
	copy(bh[:], b.Bytes())
	return bh
}

func b2h(header []byte) (*wire.BlockHeader, error) {
	var bh wire.BlockHeader
	if err := bh.Deserialize(bytes.NewReader(header)); err != nil {
		return nil, fmt.Errorf("deserialize block header: %w", err)
	}
	return &bh, nil
}

// headerHash return the block hash from a raw block header.
func headerHash(header []byte) *chainhash.Hash {
	h, err := b2h(header)
	if err != nil {
		panic(err)
	}
	hash := h.BlockHash()
	return &hash
}

type Config struct {
	Home             string // home directory
	BlockCache       int    // number of blocks to cache
	BlockheaderCache int    // number of blocks headers to cache
}

func NewConfig(home string) *Config {
	return &Config{
		Home:             home, // require user to set home.
		BlockCache:       250,  // max 4GB on mainnet
		BlockheaderCache: 1e6,  // Cache all blockheaders on mainnet
	}
}

func New(ctx context.Context, cfg *Config) (*ldb, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	ld, err := level.New(ctx, cfg.Home, ldbVersion)
	if err != nil {
		return nil, err
	}

	l := &ldb{
		Database: ld,
		pool:     ld.DB(),
		rawPool:  ld.RawDB(),
		cfg:      cfg,
	}

	if cfg.BlockCache > 0 {
		l.blockCache, err = lru.New[chainhash.Hash, *btcutil.Block](cfg.BlockCache)
		if err != nil {
			return nil, fmt.Errorf("couldn't setup block cache: %w", err)
		}
		log.Infof("block cache: %v", cfg.BlockCache)
	} else {
		log.Infof("block cache: DISABLED")
	}
	if cfg.BlockheaderCache > 0 {
		l.headerCache = lowIQMapNew(cfg.BlockheaderCache)

		log.Infof("blockheader cache: %v", cfg.BlockheaderCache)
	} else {
		log.Infof("blockheader cache: DISABLED")
	}

	log.Infof("tbcdb database version: %v", ldbVersion)

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
		if err = tx.Commit(); err != nil {
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

func (l *ldb) BlockHeaderByHash(ctx context.Context, hash *chainhash.Hash) (*tbcd.BlockHeader, error) {
	log.Tracef("BlockHeaderByHash")
	defer log.Tracef("BlockHeaderByHash exit")

	if l.cfg.BlockheaderCache > 0 {
		// Try cache first
		if b, ok := l.headerCache.Get(hash); ok {
			return b, nil
		}
	}

	// It stands to reason that this code does not need a trasaction. The
	// caller code will either receive or not receice an answer. It does
	// not seem likely to be racing higher up in the stack.

	bhsDB := l.pool[level.BlockHeadersDB]
	ebh, err := bhsDB.Get(hash[:], nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError(fmt.Sprintf("block header not found: %v", hash))
		}
		return nil, fmt.Errorf("block header get: %w", err)
	}
	bh := decodeBlockHeader(ebh)

	// Insert into cache, roughly 150 byte cost.
	if l.cfg.BlockheaderCache > 0 {
		l.headerCache.Put(bh)
	}

	return bh, nil
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
	ebh, err := bhsDB.Get([]byte(bhsCanonicalTipKey), nil)
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
func keyToHeightHash(key []byte) (uint64, *chainhash.Hash) {
	hash, err := chainhash.NewHash(key[9:])
	if err != nil {
		panic(fmt.Sprintf("chain hash new: %v", len(key)))
	}
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
	bh := &tbcd.BlockHeader{
		Hash:   *headerHash(ebh[8:88]),
		Height: binary.BigEndian.Uint64(ebh[0:8]),
	}
	// copy the values to prevent slicing reentrancy problems.
	copy(bh.Header[:], ebh[8:88])
	(&bh.Difficulty).SetBytes(ebh[88:])
	return bh
}

func (l *ldb) BlockHeaderGenesisInsert(ctx context.Context, wbh *wire.BlockHeader) error {
	log.Tracef("BlockHeaderGenesisInsert")
	defer log.Tracef("BlockHeaderGenesisInsert exit")

	// block headers
	bhsTx, bhsCommit, bhsDiscard, err := l.startTransaction(level.BlockHeadersDB)
	if err != nil {
		return fmt.Errorf("block header open transaction: %w", err)
	}
	defer bhsDiscard()

	// Make sure we are not inserting the same blocks
	bhash := wbh.BlockHash()
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

	hhKey := heightHashToKey(0, bhash[:])
	hhBatch.Put(hhKey, []byte{})
	cdiff := big.NewInt(0)
	cdiff = new(big.Int).Add(cdiff, blockchain.CalcWork(wbh.Bits))
	ebh := encodeBlockHeader(0, h2b(wbh), cdiff)
	bhBatch.Put(bhash[:], ebh[:])

	bhBatch.Put([]byte(bhsCanonicalTipKey), ebh[:])

	// Write height hash batch
	if err = hhTx.Write(hhBatch, nil); err != nil {
		return fmt.Errorf("height hash batch: %w", err)
	}

	// Write missing blocks batch
	if err = bmTx.Write(bmBatch, nil); err != nil {
		return fmt.Errorf("blocks missing batch: %w", err)
	}

	// Write block headers batch
	if err = bhsTx.Write(bhBatch, nil); err != nil {
		return fmt.Errorf("block header insert: %w", err)
	}

	// height hash commit
	if err = hhCommit(); err != nil {
		return fmt.Errorf("height hash commit: %w", err)
	}

	// blocks missing commit
	if err = bmCommit(); err != nil {
		return fmt.Errorf("blocks missing commit: %w", err)
	}

	// block headers commit
	if err = bhsCommit(); err != nil {
		return fmt.Errorf("block header commit: %w", err)
	}

	return nil
}

// BlockHeadersInsert decodes and inserts the passed blockheaders into the
// database. Additionally it updates the hight/hash and missing blocks table as
// well.  On return it informs the caller about potential forking situations
// and always returns the canonical and last inserted blockheader, which may be
// the same.
// This call uses the database to prevent reentrancy.
func (l *ldb) BlockHeadersInsert(ctx context.Context, bhs *wire.MsgHeaders) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	log.Tracef("BlockHeadersInsert")
	defer log.Tracef("BlockHeadersInsert exit")

	if len(bhs.Headers) == 0 {
		return tbcd.ITInvalid, nil, nil, 0,
			errors.New("block headers insert: invalid")
	}

	// block headers
	bhsTx, bhsCommit, bhsDiscard, err := l.startTransaction(level.BlockHeadersDB)
	if err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("block headers open transaction: %w", err)
	}
	defer bhsDiscard()

	// Ensure we can connect these blockheaders. This also obtains the
	// starting cumulative difficulty and height.
	//
	// Iterate over the block headers and skip block headers we already
	// have in the database. Rely on caching to make this not suck terribly.
	var x int
	for _, rbh := range bhs.Headers {
		bhash := rbh.BlockHash()
		has, err := bhsTx.Has(bhash[:], nil)
		if err != nil {
			return tbcd.ITInvalid, nil, nil, 0,
				fmt.Errorf("block headers insert has: %w", err)
		}
		if !has {
			break
		}
		x++
	}
	bhs.Headers = bhs.Headers[x:]
	if len(bhs.Headers) == 0 {
		return tbcd.ITInvalid, nil, nil, 0,
			database.DuplicateError("block headers insert duplicate")
	}

	// Obtain current and previous blockheader.
	wbh := bhs.Headers[0]
	pbh, err := l.BlockHeaderByHash(ctx, &wbh.PrevBlock)
	if err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("block headers insert: %w", err)
	}

	// blocks missing
	bmTx, bmCommit, bmDiscard, err := l.startTransaction(level.BlocksMissingDB)
	if err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("blocks missing open transaction: %w", err)
	}
	defer bmDiscard()

	// height hash
	hhTx, hhCommit, hhDiscard, err := l.startTransaction(level.HeightHashDB)
	if err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("height hash open transaction: %w", err)
	}
	defer hhDiscard()

	// retrieve best/canonical block header
	bbh, err := bhsTx.Get([]byte(bhsCanonicalTipKey), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return tbcd.ITInvalid, nil, nil, 0,
				database.NotFoundError("best block header not found")
		}
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("best block header: %w", err)
	}
	bestBH := decodeBlockHeader(bbh)

	// Fork is set to true if the first blockheader does not connect to the
	// canonical blockheader.
	fork := !bytes.Equal(wbh.PrevBlock[:], bestBH.Hash[:])
	if fork {
		b, _ := chainhash.NewHash(bestBH.Hash[:])
		log.Debugf("=== FORK ===")
		log.Debugf("blockheader hash: %v", wbh.BlockHash())
		log.Debugf("previous hash   : %v", wbh.PrevBlock)
		log.Debugf("previous height : %v", pbh.Height)
		log.Debugf("best hash       : %v", b)
		log.Debugf("best height     : %v", bestBH.Height)
		log.Debugf("--- FORK ---")
	}

	// Insert missing blocks and block headers
	hhBatch := new(leveldb.Batch)
	bmBatch := new(leveldb.Batch)
	bhsBatch := new(leveldb.Batch)

	cdiff := &pbh.Difficulty
	height := pbh.Height
	var (
		bhash           chainhash.Hash
		lastBlockHeader [80]byte
		lastRecord      []byte
	)
	for _, bh := range bhs.Headers {
		// The first element is skipped, as it is pre-decoded.
		wbh = bh
		bhash = wbh.BlockHash()

		// pre set values because we start with previous value
		height++
		cdiff = new(big.Int).Add(cdiff, blockchain.CalcWork(wbh.Bits))

		// Store height_hash for future reference
		hhKey := heightHashToKey(height, bhash[:])
		hhBatch.Put(hhKey, []byte{}) // XXX nil?

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
		lastBlockHeader = h2b(bh)
		ebh := encodeBlockHeader(height, lastBlockHeader, cdiff)
		bhsBatch.Put(bhash[:], ebh[:])
		lastRecord = ebh[:]
	}

	cbh := &tbcd.BlockHeader{
		Hash:       bhash,
		Height:     height,
		Difficulty: *cdiff,
		Header:     lastBlockHeader,
	}
	lbh := cbh

	// XXX: Reason about needing to check fork flag. For now keep it here to
	//  distinguish between certain fork and maybe fork paths.
	var it tbcd.InsertType
	if fork {
		// Insert last height into block headers if the new cumulative
		// difficulty exceeds the prior difficulty.
		switch cdiff.Cmp(&bestBH.Difficulty) {
		case -1, 0:
			// Extend fork, fork did not overcome difficulty
			it = tbcd.ITForkExtend

			// XXX should we return old best block header here?
			// That way the caller can do best vs previous best diff.
			log.Debugf("(%v) : %v <= %v", height, cdiff, bestBH.Difficulty)
			cbh = bestBH

		case 1:
			log.Debugf("(%v) 1: %v > %v", height, cdiff, bestBH.Difficulty)
			// log.Infof("%v", spew.Sdump(bestBH.Hash[:]))
			// log.Infof("%v", spew.Sdump(firstHash))
			// pick the right return value based on ancestor
			bhsBatch.Put([]byte(bhsCanonicalTipKey), lastRecord)
			it = tbcd.ITChainFork

		default:
			panic("bug: impossible cmp value")
		}
	} else {
		// Extend current best tip
		bhsBatch.Put([]byte(bhsCanonicalTipKey), lastRecord)
		it = tbcd.ITChainExtend
	}

	// Write height hash batch
	if err = hhTx.Write(hhBatch, nil); err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("height hash batch: %w", err)
	}

	// Write missing blocks batch
	if err = bmTx.Write(bmBatch, nil); err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("blocks missing batch: %w", err)
	}

	// Write block headers batch
	if err = bhsTx.Write(bhsBatch, nil); err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("block headers insert: %w", err)
	}

	// height hash commit
	if err = hhCommit(); err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("height hash commit: %w", err)
	}

	// blocks missing commit
	if err = bmCommit(); err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("blocks missing commit: %w", err)
	}

	// block headers commit
	if err = bhsCommit(); err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("block headers commit: %w", err)
	}

	return it, cbh, lbh, len(bhs.Headers), nil
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

		x++
		if x >= count {
			break
		}
	}

	log.Debugf("BlocksMissing returning %v cached %v", len(bis), blockCacheLen)

	return bis, nil
}

func (l *ldb) BlockInsert(ctx context.Context, b *btcutil.Block) (int64, error) {
	log.Tracef("BlockInsert")
	defer log.Tracef("BlockInsert exit")

	bh, err := l.BlockHeaderByHash(ctx, b.Hash())
	if err != nil {
		return -1, fmt.Errorf("block header by hash: %w", err)
	}

	bDB := l.rawPool[level.BlocksDB]
	has, err := bDB.Has(b.Hash()[:])
	if err != nil {
		return -1, database.DuplicateError("block insert: exists")
	}
	if !has {
		raw, err := b.Bytes()
		if err != nil {
			return -1, fmt.Errorf("blocks encode: %w", err)
		}
		// Insert block since we do not have it yet
		if err = bDB.Insert(b.Hash()[:], raw); err != nil {
			return -1, fmt.Errorf("blocks insert put: %w", err)
		}
		if l.cfg.BlockCache > 0 {
			l.blockCache.Add(*b.Hash(), b)
		}
	}

	// Remove block identifier from blocks missing
	key := heightHashToKey(bh.Height, bh.Hash[:])
	bmDB := l.pool[level.BlocksMissingDB]
	if err = bmDB.Delete(key, nil); err != nil {
		// Ignore not found, it was deleted prior to this call.
		if !errors.Is(err, leveldb.ErrNotFound) {
			return -1, fmt.Errorf("block insert delete from missing: %w", err)
		}
	}

	return int64(bh.Height), nil
}

func (l *ldb) BlockMissingDelete(ctx context.Context, height int64, hash *chainhash.Hash) error {
	log.Tracef("BlockMissingDelete")
	defer log.Tracef("BlockMissingDelete exit")

	key := heightHashToKey(uint64(height), hash[:])
	bmDB := l.pool[level.BlocksMissingDB]
	if err := bmDB.Delete(key, nil); err != nil {
		// Ignore not found, it was deleted prior to this call.
		if !errors.Is(err, leveldb.ErrNotFound) {
			return fmt.Errorf("block missing delete: %w", err)
		}
	}
	return nil
}

func (l *ldb) BlockByHash(ctx context.Context, hash *chainhash.Hash) (*btcutil.Block, error) {
	log.Tracef("BlockByHash")
	defer log.Tracef("BlockByHash exit")

	if l.cfg.BlockCache > 0 {
		// Try cache first
		if cb, ok := l.blockCache.Get(*hash); ok {
			return cb, nil
		}
	}

	bDB := l.rawPool[level.BlocksDB]
	eb, err := bDB.Get(hash[:])
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError(fmt.Sprintf("block not found: %v", hash))
		}
		return nil, fmt.Errorf("block get: %w", err)
	}
	b, err := btcutil.NewBlockFromBytes(eb)
	if err != nil {
		panic(fmt.Errorf("block decode data corruption: %w", err))
	}
	if l.cfg.BlockCache > 0 {
		l.blockCache.Add(*hash, b)
	}
	return b, nil
}

func (l *ldb) BlockHashByTxId(ctx context.Context, txId *chainhash.Hash) (*chainhash.Hash, error) {
	log.Tracef("BlockHashByTxId")
	defer log.Tracef("BlockHashByTxId exit")

	blocks := make([]*chainhash.Hash, 0, 2)
	txDB := l.pool[level.TransactionsDB]
	var txid [33]byte
	txid[0] = 't'
	copy(txid[1:], txId[:])
	it := txDB.NewIterator(util.BytesPrefix(txid[:]), nil)
	defer it.Release()
	for it.Next() {
		block, err := chainhash.NewHash(it.Key()[33:])
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	if err := it.Error(); err != nil {
		return nil, fmt.Errorf("blocks by id iterator: %w", err)
	}
	switch len(blocks) {
	case 0:
		return nil, database.NotFoundError(fmt.Sprintf("tx not found: %v", txId))
	case 1:
		return blocks[0], nil
	default:
		panic(fmt.Sprintf("invalid blocks count %v: %v",
			len(blocks), spew.Sdump(blocks)))
	}
}

func (l *ldb) SpentOutputsByTxId(ctx context.Context, txId *chainhash.Hash) ([]tbcd.SpentInfo, error) {
	log.Tracef("SpentOutputByOutpoint")
	defer log.Tracef("SpentOutputByOutpoint exit")

	si := make([]tbcd.SpentInfo, 0, 2)
	txDB := l.pool[level.TransactionsDB]
	var key [1 + 32]byte
	key[0] = 's'
	copy(key[1:], txId[:])
	it := txDB.NewIterator(&util.Range{Start: key[:]}, nil)
	defer it.Release()
	for it.Next() {
		if !bytes.Equal(it.Key()[:33], key[:]) {
			continue
		}
		var (
			s   tbcd.SpentInfo
			err error
		)
		s.TxId, err = chainhash.NewHash(it.Value()[0:32])
		if err != nil {
			return nil, fmt.Errorf("new tx id: %w", err)
		}
		s.BlockHash, err = chainhash.NewHash(it.Key()[37:])
		if err != nil {
			return nil, fmt.Errorf("new block hash: %w", err)
		}
		s.InputIndex = binary.BigEndian.Uint32(it.Value()[32:36])
		si = append(si, s)
	}
	if err := it.Error(); err != nil {
		return nil, fmt.Errorf("blocks by id iterator: %w", err)
	}
	if len(si) == 0 {
		return nil, database.NotFoundError(fmt.Sprintf("not found %v", txId))
	}

	return si, nil
}

func (l *ldb) BlockInTxIndex(ctx context.Context, hash *chainhash.Hash) (bool, error) {
	log.Tracef("BlockInTxIndex")
	defer log.Tracef("BlockInTxIndex exit")

	blocks := make([]*chainhash.Hash, 0, 2)
	txDB := l.pool[level.TransactionsDB]
	var blkid [33]byte
	blkid[0] = 'b'
	copy(blkid[1:], hash[:])
	it := txDB.NewIterator(util.BytesPrefix(blkid[:]), nil)
	defer it.Release()
	for it.Next() {
		block, err := chainhash.NewHash(it.Key()[33:])
		if err != nil {
			return false, err
		}
		blocks = append(blocks, block)
	}
	if err := it.Error(); err != nil {
		return false, fmt.Errorf("blocks by id iterator: %w", err)
	}
	switch len(blocks) {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		panic(fmt.Sprintf("invalid blocks count %v: %v",
			len(blocks), spew.Sdump(blocks)))
	}
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
		var txId chainhash.Hash
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

func (l *ldb) BlockUtxoUpdate(ctx context.Context, direction int, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	log.Tracef("BlockUtxoUpdate")
	defer log.Tracef("BlockUtxoUpdate exit")

	if !(direction == 1 || direction == -1) {
		return fmt.Errorf("invalid direction: %v", direction)
	}

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

		// The cache is updated in a way that makes the direction
		// irrelevant.
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
	if err = outsTx.Write(outsBatch, nil); err != nil {
		return fmt.Errorf("outputs insert: %w", err)
	}

	// outputs commit
	if err = outsCommit(); err != nil {
		return fmt.Errorf("outputs commit: %w", err)
	}

	return nil
}

func (l *ldb) BlockTxUpdate(ctx context.Context, direction int, txs map[tbcd.TxKey]*tbcd.TxValue) error {
	log.Tracef("BlockTxUpdate")
	defer log.Tracef("BlockTxUpdate exit")

	if !(direction == 1 || direction == -1) {
		return fmt.Errorf("invalid direction: %v", direction)
	}

	// transactions
	txsTx, txsCommit, txsDiscard, err := l.startTransaction(level.TransactionsDB)
	if err != nil {
		return fmt.Errorf("transactions open db transaction: %w", err)
	}
	defer txsDiscard()

	block := make([]byte, 33)
	block[0] = 'b'
	var blk []byte
	bm := make(map[string]struct{}, len(txs))
	defer clear(bm)

	txsBatch := new(leveldb.Batch)
	for k, v := range txs {
		// cache is being emptied so we can slice it here.
		var key, value []byte
		switch k[0] {
		case 't':
			key = k[0:65]
			value = nil

			// insert block hash to determine if it was indexed later
			if _, ok := bm[string(k[33:65])]; !ok {
				bm[string(k[33:65])] = struct{}{}
				copy(block[1:], k[33:65])
				blk = block
			} else {
				blk = nil
			}
		case 's':
			key = k[:]
			value = v[:]

			// don't insert block
			blk = nil
		default:
			return fmt.Errorf("invalid cache entry: %v", spew.Sdump(k))
		}
		switch direction {
		case -1:
			txsBatch.Delete(key)
			if blk != nil {
				txsBatch.Delete(blk)
			}
		case 1:
			txsBatch.Put(key, value)
			if blk != nil {
				txsBatch.Put(blk, nil)
			}
		}

		// XXX this probably should be done by the caller but we do it
		// here to lower memory pressure as large gobs of data are
		// written to disk.
		delete(txs, k)
	}

	// Write transactions batch
	if err = txsTx.Write(txsBatch, nil); err != nil {
		return fmt.Errorf("transactions insert: %w", err)
	}

	// transactions commit
	if err = txsCommit(); err != nil {
		return fmt.Errorf("transactions commit: %w", err)
	}

	return nil
}
