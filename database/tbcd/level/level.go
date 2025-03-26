// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/dustin/go-humanize"
	"github.com/juju/loggo"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/level"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/hemi"
)

// Locking order:
//	The theory here is to order these in somewhat "usage" order and to keep
//	them from interacting too much. Metadata goes first because it is
//	almost never used but may interact wildly.
//
//	Metadata	XXX debate this
//	BlockHeaders
//	BlocksMissing
//	HeightHash
//	Blocks
//
//	Balances
//	UTXOs

const (
	ldbVersion = 2

	logLevel = "INFO"
	verbose  = false

	bhsCanonicalTipKey = "canonicaltip"

	heighthashSize  = 8 + 1 + chainhash.HashSize
	blockheaderSize = 120
	keystoneSize    = chainhash.HashSize + hemi.L2KeystoneAbrevSize
)

type IteratorError error

var (
	log = loggo.GetLogger("level")

	Welcome = true

	ErrIterator = IteratorError(errors.New("iteration error"))

	noStats tbcd.CacheStats

	versionKey = []byte("version")

	utxoIndexHashKey     = []byte("utxoindexhash")     // last indexed utxo block hash
	txIndexHashKey       = []byte("txindexhash")       // last indexed tx block hash
	keystoneIndexHashKey = []byte("keystoneindexhash") // last indexed keystone block hash
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type ldb struct {
	*level.Database
	pool    level.Pool
	rawPool level.RawPool

	blockCache *lowIQLRU

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
	Home                 string // home directory
	BlockCacheSize       string // size of block cache
	BlockheaderCacheSize string // size of block header cache
	blockCacheSize       int    // parsed size of block cache
	blockheaderCacheSize int    // parsed size of block header cache
}

func NewConfig(home, blockheaderCacheSizeS, blockCacheSizeS string) *Config {
	if blockheaderCacheSizeS == "" {
		blockheaderCacheSizeS = "0"
	}
	blockheaderCacheSize, err := humanize.ParseBytes(blockheaderCacheSizeS)
	if err != nil {
		panic(err)
	}
	if blockheaderCacheSize > math.MaxInt64 {
		panic("invalid blockheaderCacheSize")
	}

	if blockCacheSizeS == "" {
		blockCacheSizeS = "0"
	}
	blockCacheSize, err := humanize.ParseBytes(blockCacheSizeS)
	if err != nil {
		panic(err)
	}
	if blockCacheSize > math.MaxInt64 {
		panic("invalid blockCacheSize")
	}

	return &Config{
		Home:                 home, // require user to set home.
		BlockCacheSize:       blockCacheSizeS,
		blockCacheSize:       int(blockCacheSize),
		BlockheaderCacheSize: blockheaderCacheSizeS,
		blockheaderCacheSize: int(blockheaderCacheSize),
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

	welcome := make([]string, 0, 10)
	if cfg.blockCacheSize > 0 {
		l.blockCache, err = lowIQLRUSizeNew(cfg.blockCacheSize)
		if err != nil {
			return nil, fmt.Errorf("couldn't setup block cache: %w", err)
		}
		welcome = append(welcome, fmt.Sprintf("block cache: %v",
			humanize.Bytes(uint64(cfg.blockCacheSize))))
	} else {
		welcome = append(welcome, "Block cache: DISABLED")
	}
	if cfg.blockheaderCacheSize > 0 {
		l.headerCache, err = lowIQMapSizeNew(cfg.blockheaderCacheSize)
		if err != nil {
			return nil, fmt.Errorf("couldn't setup block header cache: %w", err)
		}
		welcome = append(welcome, fmt.Sprintf("blockheader cache: %v",
			humanize.Bytes(uint64(cfg.blockheaderCacheSize))))
	} else {
		welcome = append(welcome, "Blockheader cache: DISABLED")
	}

	if Welcome {
		for k := range welcome {
			log.Infof("%v", welcome[k])
		}
	}

	// Upgrade database
	for {
		dbVersion, err := l.Version(ctx)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				// New database, insert version.
				v := make([]byte, 8)
				binary.BigEndian.PutUint64(v, ldbVersion)
				if err := l.MetadataPut(ctx, versionKey, v); err != nil {
					return nil, err
				}
				dbVersion = ldbVersion
			} else {
				return nil, err
			}
		}
		switch dbVersion {
		case 1:
			// Upgrade to v2
			err = l.v2(ctx)
		default:
			if ldbVersion == dbVersion {
				if Welcome {
					log.Infof("tbcdb database version: %v",
						ldbVersion)
				}
				return l, nil
			}
			return nil, fmt.Errorf("invalid version: wanted %v got %v",
				ldbVersion, dbVersion)
		}
		// Check error
		if err != nil {
			return nil, fmt.Errorf("could not upgrade db from version %v: %w",
				dbVersion, err)
		}
	}
}

type (
	discardFunc func()
	commitFunc  func() error
)

func (l *ldb) startTransaction(db string) (*leveldb.Transaction, commitFunc, discardFunc, error) {
	bhsDB := l.pool[db]
	tx, err := bhsDB.OpenTransaction()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%v open transaction: %w", db, err)
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
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%v commit: %w", db, err)
		}
		*discard = false
		return nil
	}

	return tx, cf, df, nil
}

func (l *ldb) transactionBatchGet(ctx context.Context, t *leveldb.Transaction, allOrNone bool, keys [][]byte) ([]tbcd.Row, error) {
	log.Tracef("transactionBatchGet")
	defer log.Tracef("transactionBatchGet exit")

	rows := make([]tbcd.Row, len(keys))
	for k := range keys {
		value, err := t.Get(keys[k], nil)
		if err != nil && allOrNone {
			if errors.Is(err, leveldb.ErrNotFound) {
				return nil, database.NotFoundError(fmt.Sprintf("%s: %v",
					string(keys[k]), err))
			}
			return nil, fmt.Errorf("%s: %w", string(keys[k]), err)
		}
		if errors.Is(err, leveldb.ErrNotFound) {
			// overload err
			err = database.NotFoundError(err.Error())
		}
		rows[k] = tbcd.Row{Key: keys[k], Value: value, Error: err}
	}
	return rows, nil
}

func (l *ldb) Version(ctx context.Context) (int, error) {
	mdDB := l.pool[level.MetadataDB]
	value, err := mdDB.Get(versionKey, nil)
	if err != nil {
		return -1, fmt.Errorf("version: %w", err)
	}
	dbVersion := binary.BigEndian.Uint64(value)

	return int(dbVersion), nil
}

func (l *ldb) MetadataDel(ctx context.Context, key []byte) error {
	log.Tracef("MetadataDel")
	defer log.Tracef("MetadataDel exit")

	mdDB, mdCommit, mdDiscard, err := l.startTransaction(level.MetadataDB)
	if err != nil {
		return fmt.Errorf("metadata open db transaction: %w", err)
	}
	defer mdDiscard()

	ok, err := mdDB.Has(key, nil)
	if err != nil {
		return database.NotFoundError(err.Error())
	}
	if !ok {
		return database.NotFoundError("not found")
	}

	mdBatch := new(leveldb.Batch)
	mdBatch.Delete(key)

	// Transaction write
	if err := mdDB.Write(mdBatch, nil); err != nil {
		return fmt.Errorf("metadata write: %w", err)
	}

	// Transaction commit
	if err = mdCommit(); err != nil {
		return fmt.Errorf("transactions commit: %w", err)
	}

	return nil
}

func (l *ldb) MetadataGet(ctx context.Context, key []byte) ([]byte, error) {
	log.Tracef("MetadataGet")
	defer log.Tracef("MetadataGet exit")

	// Metadata transaction, we do this to simply lock the table.
	mdDB, _, mdDiscard, err := l.startTransaction(level.MetadataDB)
	if err != nil {
		return nil, fmt.Errorf("metadata open db transaction: %w", err)
	}
	defer mdDiscard()

	rows, err := l.transactionBatchGet(ctx, mdDB, true, [][]byte{key})
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("unexpected rows length: %v", len(rows))
	}
	return rows[0].Value, err
}

func (l *ldb) MetadataBatchGet(ctx context.Context, allOrNone bool, keys [][]byte) ([]tbcd.Row, error) {
	log.Tracef("MetadataBatchGet")
	defer log.Tracef("MetadataBatchGet exit")

	// Metadata transaction, we do this to simply lock the table.
	mdDB, _, mdDiscard, err := l.startTransaction(level.MetadataDB)
	if err != nil {
		return nil, fmt.Errorf("metadata open db transaction: %w", err)
	}
	defer mdDiscard()

	return l.transactionBatchGet(ctx, mdDB, allOrNone, keys)
}

func (l *ldb) BlockKeystoneByL2KeystoneAbrevHash(ctx context.Context, abrevhash chainhash.Hash) (*tbcd.Keystone, error) {
	log.Tracef("BlockKeystoneByL2KeystoneAbrevHash")
	defer log.Tracef("BlockKeystoneByL2KeystoneAbrevHash exit")

	kssDB := l.pool[level.KeystonesDB]
	eks, err := kssDB.Get(abrevhash.CloneBytes(), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError(fmt.Sprintf("l2 keystone not found: %v", abrevhash))
		}
		return nil, fmt.Errorf("l2 keystone get: %w", err)
	}

	ks := decodeKeystone(eks)
	return &ks, nil
}

// BatchAppend appends rows to batch b.
func BatchAppend(ctx context.Context, b *leveldb.Batch, rows []tbcd.Row) {
	log.Tracef("BatchAppend")
	defer log.Tracef("BatchAppend exit")

	for k := range rows {
		b.Put(rows[k].Key, rows[k].Value)
	}
}

func (l *ldb) MetadataBatchPut(ctx context.Context, rows []tbcd.Row) error {
	log.Tracef("MetadataBatchPut")
	defer log.Tracef("MetadataBatchPut exit")

	// Metadata transaction
	mdDB, mdCommit, mdDiscard, err := l.startTransaction(level.MetadataDB)
	if err != nil {
		return fmt.Errorf("metadata open db transaction: %w", err)
	}
	defer mdDiscard()

	mdBatch := new(leveldb.Batch)
	BatchAppend(ctx, mdBatch, rows)

	// Transaction write
	if err := mdDB.Write(mdBatch, nil); err != nil {
		return fmt.Errorf("metadata write: %w", err)
	}

	// Transaction commit
	if err = mdCommit(); err != nil {
		return fmt.Errorf("metadata commit: %w", err)
	}

	return nil
}

func (l *ldb) MetadataPut(ctx context.Context, key, value []byte) error {
	log.Tracef("MetadataPut")
	defer log.Tracef("MetadataPut exit")

	// Metadata transaction
	mdDB, mdCommit, mdDiscard, err := l.startTransaction(level.MetadataDB)
	if err != nil {
		return fmt.Errorf("metadata open db transaction: %w", err)
	}
	defer mdDiscard()

	mdBatch := new(leveldb.Batch)
	BatchAppend(ctx, mdBatch, []tbcd.Row{{Key: key, Value: value}})
	// Transaction write
	if err := mdDB.Write(mdBatch, nil); err != nil {
		return fmt.Errorf("metadata write: %w", err)
	}

	// Transaction commit
	if err = mdCommit(); err != nil {
		return fmt.Errorf("transactions commit: %w", err)
	}

	return nil
}

func (l *ldb) BlockHeaderByHash(ctx context.Context, hash chainhash.Hash) (*tbcd.BlockHeader, error) {
	log.Tracef("BlockHeaderByHash")
	defer log.Tracef("BlockHeaderByHash exit")

	if l.cfg.blockheaderCacheSize > 0 {
		// Try cache first
		if b, ok := l.headerCache.Get(hash); ok {
			return b, nil
		}
	}

	// It stands to reason that this code does not need a transaction. The
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
	if l.cfg.blockheaderCacheSize > 0 {
		l.headerCache.Put(*bh)
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
		bh, err := l.BlockHeaderByHash(ctx, *hash)
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
	key := make([]byte, heighthashSize)
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
func encodeBlockHeader(height uint64, header [80]byte, difficulty *big.Int) (ebhr [blockheaderSize]byte) {
	binary.BigEndian.PutUint64(ebhr[0:8], height)
	copy(ebhr[8:88], header[:])
	difficulty.FillBytes(ebhr[88:blockheaderSize])
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

func (l *ldb) BlockHeaderGenesisInsert(ctx context.Context, wbh wire.BlockHeader, height uint64, diff *big.Int) error {
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

	// Genesis insert can be called with an effective genesis block at a particular height
	// and with a particular cumulative difficulty which is guaranteed canonical (protocol
	// assumes this effective genesis block will never fork), allowing a header-only TBC
	// instance to maintain Bitcoin consensus starting from a non-genesis block rather
	// than requiring all historical state which is irrelevant to conesnsus assuming the
	// effective genesis block is never forked.
	hhKey := heightHashToKey(height, bhash[:])
	hhBatch.Put(hhKey, []byte{})

	// Handle the default case where the passed-in block is actually the genesis
	cdiff := blockchain.CalcWork(wbh.Bits)

	// If an effective starting difficulty is supplied and is not set to zero, then use it
	// instead (used for external header mode). In the event that an effective genesis block
	// is supplied but the cumulative difficulty is not set, the difficulty of that
	// effective genesis block (set above) will be retained, which has no effect on local
	// consensus determination but will not permit direct comparison of cumulative difficulty
	// against the full chain, only relative comparisons between cumulative difficulties of
	// blocks on top of the same effective genesis block are guaranteed valid.
	if diff != nil && diff.Cmp(big.NewInt(0)) > 0 {
		cdiff = diff
	}
	ebh := encodeBlockHeader(height, h2b(&wbh), cdiff)
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

// BlockHeadersRemove decodes and removes the passed blockheaders into the
// database. Additionally it updates the canonical height/hash.
// On return it informs the caller about the removal type which is self-evident
// from the headers and post-removal canonical tip passed in as a convenience,
// as well as the header the batch of headers was removed from which is now
// the tip of that particular chain.
//
// The caller of this function must pass in the tipAfterRemoval which they
// *know* to be the correct canonical tip after removal of the passed-in blocks.
// This is critical to ensure that an operator of a TBC instance in External
// Header mode can set a specific header as canonical in the event that removal
// of header(s) results in a split tip where two or more headers are all at
// the highest cumulative difficulty and TBC would otherwise have to choose one
// without knowing what the upstream consumer considered canonical.
//
// This function is only intended to be used on a database which is used by
// an instance of TBC running in External Header mode, where the header consensus
// view needs to be walked back to account for information no longer being
// known by an upstream consumer. For example, an L2 reorg could remove Bitcoin
// consensus information from the L2 protocol's knowledge, so the External Header
// mode TBC instance needs to represent Bitcoin consensus knowledge of the L2
// protocol at the older tip height so that the full indexed TBC instance can
// be moved to the correct indexed state to return queries that are consistent
// with the L2's view of Bitcoin at that previous L2 block, otherwise L2 nodes
// that processed the reorg versus L2 nodes that were always on the reorged-onto
// chain could have a state divergence since queries against TBC would not be
// deterministic between both types of nodes.
//
// All of the headers passed to the remove function must exist in the database.
//
// Headers must be ordered from lowest height to highest and must be contiguous,
// meaning if header 0 is at height H, header N-1 must be at height H+N and for
// each header N its previous block hash must be the hash of header N-1.
//
// The last header in the array must be the current tip of its chain (whether
// canonical or fork); in other words the database must not have knowledge of
// any headers who reference the last header as their previous block as this removal
// would result in a dangling orphan chain segment in the database. A block can have
// multiple children and calling this function with non-contiguous (non-linear)
// blocks is not allowed, but this is correct behavior as removing chunks of
// headers in the reverse order they were originally added will ensure that
// a header being removed only has a maximum of one child (which must be included
// in the headers passed to this function).
//
// For example given a chain:
//
//	_______/-[2a]-[3a]-[4a]
//
// [ G]-[ 1]-[2b]-[3b]-[4b]-[5b]
//
//	____________\-[3c]-[4c]-[5c]-[6c]
//
// Where the tip is [6c], the next removal could for example be:
//
//	[3a]-[4a]
//	[3b]-[4b]-[5b]
//	[5c]-[6c] (and pass in tipAfterRemoval=[5b])
//
// But the next removal could not for example be:
//
//	[2a]-[3a] // Leaves [4a] dangling
//	[2b]-[3b]-[4b]-[5b] // Leaves "c" fork dangling
//
// The upstream user of a TBC instance in External Header mode is expected
// to always remove chunks of headers in the opposite order they were
// originally added. While this is not checked explicitly, failure to do so
// can result in these types of dangling chain scenarios. In the above example,
// block [2b] must have been added at or before the time of adding [3b] and [3c].
//
// It could have either been:
// Update #1: ADD [2b]-[3b]-[4b]-[5b]
// Update #2: ADD [3c]-[4c]-[5c]-[6c]
// OR
// Update #1: ADD [2b]-[3c]-[4c]-[5c]-[6c]
// Update #2: ADD [3b]-[4b]-[5b]
// (Or some similar order where some of the higher b/c blocks were added back
// and forth between the chains or split into multiple smaller updates.)
//
// Assuming the upstream caller needs to remove the entire b and c chains:
//
// If it was the first order, then we would expect upstream caller to first
// remove [3c]-...-[6c] (undo update #2), and then remove [2b]-...-[5b] (undo
// update #1), which would never leave a chain dangling.
//
// Similarly, if it was the second order, then we would expect upstream caller
// to first remove [3b]-...-[5b] (undo update #2), and then remove [2b]-...-[6c]
// (undo update #1) which would also never leave a chain dangling.
//
// If the upstream caller removed [2b]-...-[5b] first, then they did not
// remove headers in the same order that they added them, because it would
// have been impossible to originally add [2b] after adding [3c].
//
// Calling this function with the incorrect tipAfterRemoval WILL FAIL as that
// indicates incorrect upstream behavior.
//
// If any of the above requirements are not true, this function will return
// an error. If this function returns an error, no changes have been made to
// the underlying database state as all validity checks are done before db
// modifications are applied.
//
// If an upstreamCursor is provided, it is updated atomically in the database
// along with the state transition of removing the block headers.
func (l *ldb) BlockHeadersRemove(ctx context.Context, bhs *wire.MsgHeaders, tipAfterRemoval *wire.BlockHeader, batchHook tbcd.BatchHook) (tbcd.RemoveType, *tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersRemove")
	defer log.Tracef("BlockHeadersRemove exit")

	if len(bhs.Headers) == 0 {
		return tbcd.RTInvalid, nil,
			errors.New("block headers remove: no block headers to remove")
	}

	// XXX this function looks broken; this looks ike everything should
	// happen inside the database transaction.

	// Metadata
	mdTx, mdCommit, mdDiscard, err := l.startTransaction(level.MetadataDB)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("metadata open transaction: %w", err)
	}
	defer mdDiscard()

	// Block headers
	bhsTx, bhsCommit, bhsDiscard, err := l.startTransaction(level.BlockHeadersDB)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to start block headers leveldb transaction, err: %w", err)
	}
	defer bhsDiscard()

	// height hash
	hhTx, hhCommit, hhDiscard, err := l.startTransaction(level.HeightHashDB)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to start height hash leveldb transaction, err: %w", err)
	}
	defer hhDiscard()

	// <MAXMADNESS>

	// Get current canonical tip for later use
	originalCanonicalTip, err := l.BlockHeaderBest(ctx)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to get canonical tip from db, err: %w", err)
	}

	headersParsed := bhs.Headers

	// Looking up each full header (with height and cumulative difficulty)
	// in the next check; store so that later we have the data to create deletion
	// keys.
	fullHeadersFromDb := make([]*tbcd.BlockHeader, len(headersParsed))
	// Check that each header exists in the database, and that no header
	// to remove has a child unless that child is also going to be removed;
	// no dangling chains will be left. Also check that none of the blocks
	// to be removed match the tip the caller wants to be canonical after
	// the removal.
	tipAfterRemovalHash := tipAfterRemoval.BlockHash()
	for i := 0; i < len(headersParsed); i++ {
		headerToCheck := headersParsed[i]
		hash := headerToCheck.BlockHash()

		// Ensure that the header which should be canonical after removal is not one
		// of the blocks to remove
		if tipAfterRemovalHash.IsEqual(&hash) {
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: cannot remove header with hash %s when that is supposed to be"+
					" the tip after removal", hash.String())
		}

		// Get full header that has height in it for the block to remove we are checking
		fullHeader, err := l.BlockHeaderByHash(ctx, hash)
		if err != nil {
			return 0, nil,
				fmt.Errorf("block headers remove: cannot find header with hash %s in database, err: %w",
					hash.String(), err)
		}

		// Save the full header from database (with height and cumulative difficulty)
		fullHeadersFromDb[i] = fullHeader
		nextHeight := fullHeader.Height + 1

		// Get all headers from the database that could possibly be children
		potentialChildren, err := l.BlockHeadersByHeight(ctx, nextHeight)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				// No blocks at nextHeight in database. We could check that we are at
				// the end of our headers array, but continuing here is fine because
				// that will be detected on the next iteration.
				continue
			}
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: cannot get potential children at height %d "+
					"from database, err: %w", nextHeight, err)
		}

		// Check all potential children. If one has our header to remove's hash as their
		// previous block, then make sure it is in the removal list. Two or more cannot
		// be in our removal list because they would have failed contiguous check prior.
		for j := 0; j < len(potentialChildren); j++ {
			toCheck := potentialChildren[j]
			parent := toCheck.ParentHash()
			if !bytes.Equal(parent[:], hash[:]) {
				// Not a child of header to remove
				continue
			}

			// This is a child of the header we are going to remove, make sure it is
			// also going to be removed.
			if i == (len(headersParsed) - 1) {
				// We do not have another header in our removal list, meaning it would
				// be left dangling.
				return tbcd.RTInvalid, nil,
					fmt.Errorf("block headers remove: want to remove header with hash %s but it is the "+
						"last header in our removal list, and database has a child header with hash %s which "+
						"would be left dangling", hash.String(), toCheck.BlockHash().String())
			}

			// This check will always fail if there are two children which claim the
			// current header as a child, as one of them will not match the next
			// header to remove, which is the only block which could be the removed
			// child.
			nextBlockToRemove := headersParsed[i+1].BlockHash()
			if !nextBlockToRemove.IsEqual(toCheck.BlockHash()) {
				// The header of the confirmed child does not match the next header to
				// remove, meaning it would be left dangling.
				return tbcd.RTInvalid, nil,
					fmt.Errorf("block headers remove: want to remove header with hash %s, but database "+
						"has a child header with hash %s which would be left dangling", hash.String(),
						toCheck.BlockHash().String())
			}
		}
	}

	// Ensure that the tip which the caller claims should be canonical after the
	// removal is a valid block in the database.
	tipAfterRemovalFromDb, err := l.BlockHeaderByHash(ctx, tipAfterRemovalHash)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: cannot find tip after removal header with hash %s "+
				"in database, err: %w", tipAfterRemovalHash.String(), err)
	}

	//
	for i := 0; i < len(fullHeadersFromDb); i++ {
		// This should be impossible since above loop should have errored when
		// getting header, but extra sanity.
		if fullHeadersFromDb[i] == nil {
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: unexpected internal error, header with hash %s at position "+
					"%d in headers to remove was not retrieved from database", headersParsed[i].BlockHash().String(), i)
		}

		// Reconstitute the 80-byte header retrieved from the database for
		// additional sanity checks
		dbHeaderReconstituted, err := b2h(fullHeadersFromDb[i].Header[:])
		if err != nil {
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: unexpected error parsing header %x, err: %w",
					fullHeadersFromDb[i].Header[:], err)
		}

		// Check that the raw header we retrieved from the database matches the
		// header we expected to move as an additional sanity check.
		dbHeaderReconstitutedHash := dbHeaderReconstituted.BlockHash()
		expectedHash := headersParsed[i].BlockHash()
		if !expectedHash.IsEqual(&dbHeaderReconstitutedHash) {
			// Recalculated hash of header from database doesn't match header of
			// block, this should also be impossible but extra sanity.
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: unexpected internal error, header with hash %s at position %d"+
					" in headers to remove does not match header %x with hash %s retrieved from db",
					expectedHash.String(), i, fullHeadersFromDb[i].Header[:], expectedHash.String())
		}
	}

	mdBatch := new(leveldb.Batch)
	bhsBatch := new(leveldb.Batch)
	hhBatch := new(leveldb.Batch)

	var bhCacheBatch []*chainhash.Hash
	if l.cfg.blockheaderCacheSize > 0 {
		// cache batch to delete blockheaders
		bhCacheBatch = make([]*chainhash.Hash, 0, len(headersParsed))
	}

	// Insert each block header deletion into the batch (for header itself and
	// height-header association)
	for i := 0; i < len(headersParsed); i++ {
		// Delete header i
		bhash := headersParsed[i].BlockHash()
		fh := fullHeadersFromDb[i]
		// Make db delete batch
		bhsBatch.Delete(bhash[:])

		// Remove from header cache as well in a batch
		if l.cfg.blockheaderCacheSize > 0 {
			bhCacheBatch = append(bhCacheBatch, &bhash)
		}

		// Delete height mapping for header i
		hhKey := heightHashToKey(fh.Height, bhash[:])
		hhBatch.Delete(hhKey)
	}
	if l.cfg.blockheaderCacheSize > 0 {
		// Delete right away. Cache can always be rehydrated.
		l.headerCache.PurgeBatch(bhCacheBatch)
	}

	// Insert updated canonical tip after removal of the provided block headers
	tipAfterRemovalEncoded := h2b(tipAfterRemoval)
	tipEbh := encodeBlockHeader(tipAfterRemovalFromDb.Height, tipAfterRemovalEncoded, &tipAfterRemovalFromDb.Difficulty)
	bhsBatch.Put([]byte(bhsCanonicalTipKey), tipEbh[:])

	// XXX move upstreamStateId from here to right before Commit

	// Get parent block from database
	// XXX verify l. here instead of using the bh transaction to get the hash
	parentToRemovalSet, err := l.BlockHeaderByHash(ctx, headersParsed[0].PrevBlock)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: cannot find previous header (with hash %s) to lowest header"+
				" removed (whth hash %s) in database, err: %w",
				headersParsed[0].PrevBlock.String(), headersParsed[0].BlockHash().String(), err)
	}

	originalCanonicalTipHash := originalCanonicalTip.BlockHash()
	heaviestRemovedBlockHash := headersParsed[len(headersParsed)-1].BlockHash()

	//nolint:ineffassign // tbcd.RTInvalid is being used as the default.
	removalType := tbcd.RTInvalid
	if tipAfterRemovalHash.IsEqual(&parentToRemovalSet.Hash) {
		// Canonical tip set by caller is the parent to the blocks removed
		removalType = tbcd.RTChainDescend
	} else if tipAfterRemovalHash.IsEqual(originalCanonicalTipHash) {
		// Canonical tip did not change, meaning blocks we removed were on a non-canonical chain
		removalType = tbcd.RTForkDescend
	} else if originalCanonicalTipHash.IsEqual(&heaviestRemovedBlockHash) {
		// The original canonical tip was a block we removed, but parent to removal set is
		// not the new canonical per first condition, therefore we descended the canonical
		// chain far enough that a previous fork is now canonical
		removalType = tbcd.RTChainFork
	} else {
		// This should never happen, one of the above three conditions must be true.
		// Do this before the end of function so we don't apply database changes.
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: none of the chain geometry checks applies to this removal")
	}

	// </MAXMADNESS>

	// Call post hook if set.
	if batchHook != nil {
		dbBatches := map[string]tbcd.Batch{
			level.MetadataDB:     {Batch: mdBatch},
			level.BlockHeadersDB: {Batch: bhsBatch},
			level.HeightHashDB:   {Batch: hhBatch},
		}
		err := batchHook(ctx, dbBatches)
		if err != nil {
			return tbcd.RTInvalid, nil, fmt.Errorf("post hook: %w", err)
		}
	}

	// Write height hash batch
	err = hhTx.Write(hhBatch, nil)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to write height hash batch: %w", err)
	}

	// Write block headers batch
	err = bhsTx.Write(bhsBatch, nil)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to write block headers batch: %w", err)
	}

	// Write metadata batch
	err = mdTx.Write(mdBatch, nil)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to write metadata batch: %w", err)
	}

	// height hash commit
	if err = hhCommit(); err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to commit height hash modifications: %w", err)
	}

	// block headers commit
	if err = bhsCommit(); err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to commit block header modifications: %w", err)
	}

	// metadata commit
	if err = mdCommit(); err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("metadata commit: %w", err)
	}

	return removalType, parentToRemovalSet, nil
}

// BlockHeadersInsert decodes and inserts the passed blockheaders into the
// database. Additionally it updates the hight/hash and missing blocks table as
// well.  On return it informs the caller about potential forking situations
// and always returns the canonical and last inserted blockheader, which may be
// the same.
// This call uses the database to prevent reentrancy.
func (l *ldb) BlockHeadersInsert(ctx context.Context, bhs *wire.MsgHeaders, batchHook tbcd.BatchHook) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	log.Tracef("BlockHeadersInsert")
	defer log.Tracef("BlockHeadersInsert exit")

	if bhs == nil || len(bhs.Headers) == 0 {
		return tbcd.ITInvalid, nil, nil, 0,
			errors.New("block headers insert: invalid")
	}

	// Metadata
	mdTx, mdCommit, mdDiscard, err := l.startTransaction(level.MetadataDB)
	if err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("metadata open transaction: %w", err)
	}
	defer mdDiscard()

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
	pbh, err := l.BlockHeaderByHash(ctx, wbh.PrevBlock)
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

	// blocks
	blocksDB := l.rawPool[level.BlocksDB]

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
	mdBatch := new(leveldb.Batch)

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
		ok, err := hhTx.Has(hhKey, nil)
		if err != nil {
			return tbcd.ITInvalid, nil, nil, 0,
				fmt.Errorf("height hash has: %w", err)
		} else if !ok {
			hhBatch.Put(hhKey, []byte{})
		}

		// Insert a synthesized height_hash key that serves as an index
		// to see which blocks are missing.
		ok, err = blocksDB.Has(hhKey)
		if err != nil {
			return tbcd.ITInvalid, nil, nil, 0,
				fmt.Errorf("blocks has: %w", err)
		} else if !ok {
			bmBatch.Put(hhKey, []byte{})
		}

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

	// Call post hook if set.
	if batchHook != nil {
		dbBatches := map[string]tbcd.Batch{
			level.MetadataDB:      {Batch: mdBatch},
			level.BlockHeadersDB:  {Batch: bhsBatch},
			level.BlocksMissingDB: {Batch: bmBatch},
			level.HeightHashDB:    {Batch: hhBatch},
		}
		err := batchHook(ctx, dbBatches)
		if err != nil {
			return tbcd.ITInvalid, nil, nil, 0,
				fmt.Errorf("post hook: %w", err)
		}
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

	// Write metadata batch
	if err = mdTx.Write(mdBatch, nil); err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("metadata insert: %w", err)
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

	// metadata commit
	if err = mdCommit(); err != nil {
		return tbcd.ITInvalid, nil, nil, 0,
			fmt.Errorf("metadata commit: %w", err)
	}

	return it, cbh, lbh, len(bhs.Headers), nil
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

	bh, err := l.BlockHeaderByHash(ctx, *b.Hash())
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
		if l.cfg.blockCacheSize > 0 {
			l.blockCache.Put(*b.Hash(), raw)
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

func (l *ldb) BlockMissingDelete(ctx context.Context, height int64, hash chainhash.Hash) error {
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

func (l *ldb) BlockByHash(ctx context.Context, hash chainhash.Hash) (*btcutil.Block, error) {
	log.Tracef("BlockByHash")
	defer log.Tracef("BlockByHash exit")

	// get from cache
	var (
		eb  []byte
		err error
	)
	if l.cfg.blockCacheSize > 0 {
		// Try cache first
		eb, _ = l.blockCache.Get(hash)
	}

	// get from db
	if eb == nil {
		bDB := l.rawPool[level.BlocksDB]
		eb, err = bDB.Get(hash[:])
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				return nil, database.BlockNotFoundError{Hash: hash}
			}
			return nil, fmt.Errorf("block get: %w", err)
		}
		if l.cfg.blockCacheSize > 0 {
			l.blockCache.Put(hash, eb)
		}
	}
	// if we get here eb MUST exist
	b, err := btcutil.NewBlockFromBytes(eb)
	if err != nil {
		panic(fmt.Errorf("block decode data corruption: %v %w", hash, err))
	}
	return b, nil
}

func (l *ldb) BlockExistsByHash(ctx context.Context, hash chainhash.Hash) (bool, error) {
	log.Tracef("BlockExistsByHash")
	defer log.Tracef("BlockExistsByHash exit")

	if l.cfg.blockCacheSize > 0 {
		// Try cache first
		if ok := l.blockCache.Has(hash); ok {
			return true, nil
		}
	}

	bDB := l.rawPool[level.BlocksDB]
	ok, err := bDB.Has(hash[:])
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("check block exists: %w", err)
	}
	return ok, nil
}

func (l *ldb) BlockHashByTxId(ctx context.Context, txId chainhash.Hash) (*chainhash.Hash, error) {
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

func (l *ldb) SpentOutputsByTxId(ctx context.Context, txId chainhash.Hash) ([]tbcd.SpentInfo, error) {
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

func (l *ldb) BlockInTxIndex(ctx context.Context, hash chainhash.Hash) (bool, error) {
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

func (l *ldb) ScriptHashesByOutpoint(ctx context.Context, ops []*tbcd.Outpoint, result func(tbcd.Outpoint, tbcd.ScriptHash) error) error {
	log.Tracef("ScriptHashesByOutpoint")
	defer log.Tracef("ScriptHashesByOutpoint exit")

	uDB := l.pool[level.OutputsDB]

	for k := range ops {
		scriptHash, err := uDB.Get(ops[k][:], nil)
		if err != nil {
			// not found, skip
			continue
		}
		sh, err := tbcd.NewScriptHashFromBytes(scriptHash)
		if err != nil {
			return fmt.Errorf("script hash %x: %w", ops[k], err)
		}
		if err = result(*ops[k], sh); err != nil {
			return fmt.Errorf("script hashes callback %x: %w", ops[k], err)
		}
	}

	return nil
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

		if uint64(len(utxos)) >= count {
			break
		}
	}
	if err := it.Error(); err != nil {
		return nil, IteratorError(err)
	}

	return utxos, nil
}

func (l *ldb) UtxosByScriptHashCount(ctx context.Context, sh tbcd.ScriptHash) (uint64, error) {
	log.Tracef("UtxosByScriptHashCount")
	defer log.Tracef("UtxosByScriptHashCount exit")

	var prefix [33]byte
	prefix[0] = 'h'
	copy(prefix[1:], sh[:])
	oDB := l.pool[level.OutputsDB]
	it := oDB.NewIterator(util.BytesPrefix(prefix[:]), nil)
	defer it.Release()
	var x uint64
	for it.Next() {
		x++
	}
	if err := it.Error(); err != nil {
		return 0, IteratorError(err)
	}

	return x, nil
}

func (l *ldb) BlockUtxoUpdate(ctx context.Context, direction int, utxos map[tbcd.Outpoint]tbcd.CacheOutput, utxoIndexHash chainhash.Hash) error {
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
			outsBatch.Delete(op[:])
			outsBatch.Delete(hop[:])
		} else {
			// Add utxo to balance and utxos
			outsBatch.Put(op[:], utxo.ScriptHashSlice())
			outsBatch.Put(hop[:], utxo.ValueBytes())
		}

		// Empty out cache.
		delete(utxos, op)
	}

	// Store index
	outsBatch.Put(utxoIndexHashKey, utxoIndexHash[:])

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

func (l *ldb) BlockTxUpdate(ctx context.Context, direction int, txs map[tbcd.TxKey]*tbcd.TxValue, txIndexHash chainhash.Hash) error {
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

		// Empty out cache.
		delete(txs, k)
	}

	// Store index
	txsBatch.Put(txIndexHashKey, txIndexHash[:])

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

// encodeKeystone encodes a database keystone as
// [blockhash,abbreviated keystone] or [32+76] bytes. The abbreviated keystone
// hash is the leveldb table key.
func encodeKeystone(ks tbcd.Keystone) (eks [keystoneSize]byte) {
	copy(eks[0:32], ks.BlockHash[:])
	copy(eks[32:], ks.AbbreviatedKeystone[:])
	return
}

func encodeKeystoneToSlice(ks tbcd.Keystone) []byte {
	eks := encodeKeystone(ks)
	return eks[:]
}

// decodeKeystone reverse the process of encodeKeystone.
func decodeKeystone(eks []byte) (ks tbcd.Keystone) {
	bh, err := chainhash.NewHash(eks[0:32])
	if err != nil {
		panic(err) // Can't happen
	}
	ks.BlockHash = *bh
	// copy the values to prevent slicing reentrancy problems.
	copy(ks.AbbreviatedKeystone[:], eks[32:])
	return ks
}

func (l *ldb) BlockKeystoneUpdate(ctx context.Context, direction int, keystones map[chainhash.Hash]tbcd.Keystone, keystoneIndexHash chainhash.Hash) error {
	log.Tracef("BlockKeystoneUpdate")
	defer log.Tracef("BlockKeystoneUpdate exit")

	if !(direction == 1 || direction == -1) {
		return fmt.Errorf("invalid direction: %v", direction)
	}

	// keystones
	kssTx, kssCommit, kssDiscard, err := l.startTransaction(level.KeystonesDB)
	if err != nil {
		return fmt.Errorf("keystones open db transaction: %w", err)
	}
	defer kssDiscard()

	kssBatch := new(leveldb.Batch)
	for k, v := range keystones {
		// I will punch the first person that tells me to use continue
		// in this loop in the larynx.
		switch direction {
		case -1:
			eks, err := kssTx.Get(k[:], nil)
			if err == nil {
				ks := decodeKeystone(eks)
				// Only delete keystone if it is in the
				// previously found block.
				if ks.BlockHash.IsEqual(&v.BlockHash) {
					kssBatch.Delete(k[:])
				}
			}
		case 1:
			has, _ := kssTx.Has(k[:], nil)
			if !has {
				// Only store unknown keystones
				kssBatch.Put(k[:], encodeKeystoneToSlice(v))
			}
		}

		// Empty out cache.
		delete(keystones, k)
	}

	// Store index
	kssBatch.Put(keystoneIndexHashKey, keystoneIndexHash[:])

	// Write keystones batch
	if err = kssTx.Write(kssBatch, nil); err != nil {
		return fmt.Errorf("keystones insert: %w", err)
	}

	// keystones commit
	if err = kssCommit(); err != nil {
		return fmt.Errorf("keystones commit: %w", err)
	}

	return nil
}

func (l *ldb) BlockHeaderByKeystoneIndex(ctx context.Context) (*tbcd.BlockHeader, error) {
	kssTx, _, kssDiscard, err := l.startTransaction(level.KeystonesDB)
	if err != nil {
		return nil, fmt.Errorf("keystones open db transaction: %w", err)
	}
	defer kssDiscard()

	hash, err := kssTx.Get(keystoneIndexHashKey, nil)
	if err != nil {
		nerr := fmt.Errorf("keystone get: %w", err)
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError(nerr.Error())
		}
		return nil, nerr
	}
	ch, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("new hash: %w", err)
	}
	return l.BlockHeaderByHash(ctx, *ch)
}

func (l *ldb) BlockHeaderByUtxoIndex(ctx context.Context) (*tbcd.BlockHeader, error) {
	utxoTx, _, utxoDiscard, err := l.startTransaction(level.OutputsDB)
	if err != nil {
		return nil, fmt.Errorf("utxos open db transaction: %w", err)
	}
	defer utxoDiscard()

	hash, err := utxoTx.Get(utxoIndexHashKey, nil)
	if err != nil {
		nerr := fmt.Errorf("utxo get: %w", err)
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError(nerr.Error())
		}
		return nil, nerr
	}
	ch, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("new hash: %w", err)
	}
	return l.BlockHeaderByHash(ctx, *ch)
}

func (l *ldb) BlockHeaderByTxIndex(ctx context.Context) (*tbcd.BlockHeader, error) {
	txTx, _, txDiscard, err := l.startTransaction(level.TransactionsDB)
	if err != nil {
		return nil, fmt.Errorf("txs open db transaction: %w", err)
	}
	defer txDiscard()

	hash, err := txTx.Get(txIndexHashKey, nil)
	if err != nil {
		nerr := fmt.Errorf("tx get: %w", err)
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError(nerr.Error())
		}
		return nil, nerr
	}
	ch, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("new hash: %w", err)
	}
	return l.BlockHeaderByHash(ctx, *ch)
}

func (l *ldb) BlockHeaderCacheStats() tbcd.CacheStats {
	if l.cfg.blockheaderCacheSize == 0 {
		return noStats
	}
	return l.headerCache.Stats()
}

func (l *ldb) BlockCacheStats() tbcd.CacheStats {
	if l.cfg.blockCacheSize == 0 {
		return noStats
	}
	return l.blockCache.Stats()
}
