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
	"github.com/btcsuite/btcd/wire"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
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

	bhsCanonicalTipKey = "canonicaltip"
	upstreamStateIdKey = "upstreamstateid"

	minPeersRequired = 64 // minimum number of peers in good map before cache is purged
)

type IteratorError error

var log = loggo.GetLogger("level")

var ErrIterator = IteratorError(errors.New("iteration error"))

func init() {
	loggo.ConfigureLoggers(logLevel)
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
	ebh, err := bhsDB.Get([]byte(bhsCanonicalTipKey), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError("best block header not found")
		}
		return nil, fmt.Errorf("block headers best: %w", err)
	}
	return decodeBlockHeader(ebh), nil
}

func (l *ldb) UpstreamStateId(ctx context.Context) (*[32]byte, error) {
	log.Tracef("UpstreamStateId")
	defer log.Tracef("UpstreamStateId exit")

	bhsDB := l.pool[level.BlockHeadersDB]
	// Get last record
	upstreamStateId, err := bhsDB.Get([]byte(upstreamStateIdKey), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, database.NotFoundError("upstream state id not found")
		}
		return nil, fmt.Errorf("upstream state id: %w", err)
	}

	var ret [32]byte
	copy(ret[0:32], upstreamStateId[0:32])

	return &ret, nil
}

func (l *ldb) SetUpstreamStateId(ctx context.Context, upstreamStateId *[32]byte) error {
	log.Tracef("SetUpstreamStateId")
	defer log.Tracef("SetUpstreamStateId exit")

	if upstreamStateId == nil {
		return fmt.Errorf("cannot explicitly set upstream state id with a nil upstreamStateId")
	}

	// block headers
	bhsTx, bhsCommit, bhsDiscard, err := l.startTransaction(level.BlockHeadersDB)
	if err != nil {
		return fmt.Errorf("block header open transaction: %w", err)
	}
	defer bhsDiscard()

	bhBatch := new(leveldb.Batch)

	bhBatch.Put([]byte(upstreamStateIdKey), upstreamStateId[:])

	// Write block headers batch
	if err = bhsTx.Write(bhBatch, nil); err != nil {
		return fmt.Errorf("block header insert: %w", err)
	}

	// block headers commit
	if err = bhsCommit(); err != nil {
		return fmt.Errorf("block header commit: %w", err)
	}

	return nil
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
		Hash:   tbcd.HeaderHash(header[:])[:],
		Height: binary.BigEndian.Uint64(ebh[0:8]),
		Header: header[:],
	}
	(&bh.Difficulty).SetBytes(ebh[88:])
	return bh
}

func (l *ldb) BlockHeaderGenesisInsert(ctx context.Context, bh [80]byte) error {
	log.Tracef("BlockHeaderGenesisInsert")
	defer log.Tracef("BlockHeaderGenesisInsert exit")

	wbh, err := tbcd.B2H(bh[:])
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

	hhKey := heightHashToKey(0, bhash[:])
	hhBatch.Put(hhKey, []byte{})
	cdiff := big.NewInt(0)
	cdiff = new(big.Int).Add(cdiff, blockchain.CalcWork(wbh.Bits))
	ebh := encodeBlockHeader(0, bh, cdiff)
	bhBatch.Put(bhash[:], ebh[:])

	bhBatch.Put([]byte(bhsCanonicalTipKey), ebh[:])
	bhBatch.Put([]byte(upstreamStateIdKey), tbcd.DefaultUpstreamStateId[:])

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
// deterministic.
//
// All of the headers passed to the remove function must exist in the database.
//
// Headers must be ordered from lowest height to highest and must be contiguous,
// meaning if header 0 is at height H, header N-1 must be at height H+N-1 and for
// each header N its previous block hash must be the hash of header N-1.
//
// The last header in the array must be the current tip of its chain (whether
// canonical or fork); in other words the database must not have knowledge of
// any headers who reference header N as their previous block as this removal
// would result in a dangling orphan header in the database. A block can have
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
// Where the tip is [6c], the next removal could be:
//
//	[3a]-[4a]
//	[3b]-[4b]-[5b]
//	[5c]-[6c] (and pass in tipAfterRemoval=[5b])
//
// But the next removal could not be:
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
// and forth between the chains or split into multiple smaller updates.
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
// XXX: In future consider tracking all chain tips and being able to detect
// if tipAfterRemoval isn't one of the headers with highest known cumulative
// difficulty; this should never happen if this function is called correctly
// based on upstream state changes but would serve to correctly detect
// incorrect usage. This would NOT be to provide functionality as no use of this
// method should ever have to find canonical tip itself, just an extra sanity
// check.
//
// If any of the above requirements are not true, this function will return
// an error. If this function returns an error, no changes have been made to
// the underlying database state as all validity checks are done before db
// modifications are applied.
//
// If an upstreamCursor is provided, it is updated atomically in the database
// along with the state transition of removing the block headers.
func (l *ldb) BlockHeadersRemove(ctx context.Context, bhs [][80]byte, tipAfterRemoval [80]byte, upstreamStateId *[32]byte) (tbcd.RemoveType, *tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersRemove")
	defer log.Tracef("BlockHeadersRemove exit")

	if len(bhs) == 0 {
		return tbcd.RTInvalid, nil,
			errors.New("block headers remove: no block headers to remove")
	}

	// Get current canonical tip for later use
	originalCanonicalTip, err := l.BlockHeaderBest(ctx)
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to get canonical tip from db, err: %w", err)
	}

	// Parse the raw bytes headers into structures we can get parts from easily,
	// and in doing so check that all of them can pass basic parsing
	headersParsed := make([]*wire.BlockHeader, len(bhs))
	for i, bh := range bhs {
		headerParsed, err := tbcd.B2H(bh[:])
		if err != nil {
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: header %x at height %d could not be parsed", bh, i)
		}
		headersParsed[i] = headerParsed
	}

	tipAfterRemovalParsed, err := tbcd.B2H(tipAfterRemoval[:])
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: tip after removal header %x could not be parsed",
				tipAfterRemoval[:])
	}

	// Should be impossible but sanity check that we have the same number of parsed and raw headers
	if len(bhs) != len(headersParsed) {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unexpected internal error,"+
				" %d headers provided but only %d parsed", len(bhs), len(headersParsed))
	}

	// Make sure all passed in headers are contiguous / linear
	if len(headersParsed) > 1 {
		for i := len(headersParsed) - 1; i > 0; i-- {
			prevHash := headersParsed[i].PrevBlock
			prevHashCalc := headersParsed[i-1].BlockHash()
			if !bytes.Equal(prevHash[:], prevHashCalc[:]) {
				return tbcd.RTInvalid, nil,
					fmt.Errorf("block headers remove: header %x (hash: %x) does not connect to previous"+
						" header to remove %x (hash: %x)", bhs[i][:], headersParsed[i].BlockHash(),
						bhs[i-1][:], prevHashCalc)
			}
		}
	}

	// Looking up each full header (with height and cumulative difficulty)
	// in the next check; store so that later we have the data to create deletion
	// keys.
	fullHeadersFromDb := make([]*tbcd.BlockHeader, len(headersParsed))

	// Check that each header exists in the database, and that no header
	// to remove has a child unless that child is also going to be removed;
	// no dangling chains will be left. Also check that none of the blocks
	// to be removed match the tip the caller wants to be canonical after
	// the removal
	for i := 0; i < len(headersParsed); i++ {
		headerToCheck := headersParsed[i]
		hash := headerToCheck.BlockHash()

		if bytes.Equal(bhs[i][:], tipAfterRemoval[:]) {
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: cannot remove header %x when that is supposed to be the "+
					"tip after removal", bhs[i][:])
		}

		// Get full header that has height in it
		fullHeader, err := l.BlockHeaderByHash(ctx, hash[:])
		if err != nil {
			return tbcd.RTUnknownBlock, nil,
				fmt.Errorf("block headers remove: cannot find header %x (hash: %x) in database, err: %w",
					bhs[i][:], hash, err)
		}
		fullHeadersFromDb[i] = fullHeader
		nextHeight := fullHeader.Height + 1

		// Get all headers that could possibly be children
		potentialChildren, err := l.BlockHeadersByHeight(ctx, nextHeight)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				// No blocks at nextHeight in database. We could check that we are at
				// the end of our headers array, but continuing here is fine because
				// that will be detected on the next iteration anyway.
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
				return tbcd.RTChainDangling, nil,
					fmt.Errorf("block headers remove: want to remove header %x (hash: %x) but it is the "+
						"last header in our removal list, and database has a child header %x (hash: %x) which "+
						"would be left dangling",
						bhs[i][:], hash[:], toCheck.Header[:], toCheck.Hash[:])
			}
			if !bytes.Equal(toCheck.Header, bhs[i+1][:]) {
				// The header of the confirmed child does not match the next header to
				// remove, meaning it would be left dangling.
				return tbcd.RTChainDangling, nil,
					fmt.Errorf("block headers remove: want to remove header %x (hash: %x), but database "+
						"has a child header %x (hash: %x) which would be left dangling",
						bhs[i][:], hash[:], toCheck.Header[:], toCheck.Hash[:])
			}
		}
	}

	if fullHeadersFromDb[0].Height == 0 {
		// Cannot remove the genesis block. Note in header-only mode this might not be the
		// actual genesis block of the chain, but rather the first block header on which
		// header-only consensus is being run.
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: cannot remove genesis header %x (hash: %x)",
				bhs[0][:], headersParsed[0].BlockHash())
	}

	tipAfterRemovalHash := tipAfterRemovalParsed.BlockHash()
	tipAfterRemovalFromDb, err := l.BlockHeaderByHash(ctx, tipAfterRemovalHash[:])
	if err != nil {
		return tbcd.RTUnknownTip, nil,
			fmt.Errorf("block headers remove: cannot find tip after removal header %x "+
				"(hash: %x) in database, err: %w", tipAfterRemoval[:], tipAfterRemovalHash, err)
	}

	for i := 0; i < len(fullHeadersFromDb); i++ {
		// This should be impossible since above loop should have errored when getting header, but extra sanity.
		if fullHeadersFromDb[i] == nil {
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: unexpected internal error, header %x at position %d in "+
					"headers to remove was not retrieved from database", bhs[i][:], i)
		}
		if !bytes.Equal(fullHeadersFromDb[i].Header[:], bhs[i][:]) {
			// Header from database doesn't match header of block, this should also be impossible but extra sanity.
			return tbcd.RTInvalid, nil,
				fmt.Errorf("block headers remove: unexpected internal error, header %x at position %d in "+
					"headers to remove does not match header %x retrieved from db", bhs[i][:], i,
					fullHeadersFromDb[i].Header[:])
		}
	}

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

	bhsBatch := new(leveldb.Batch)
	hhBatch := new(leveldb.Batch)

	// Insert each block header deletion into the batch
	for i := 0; i < len(headersParsed); i++ {
		// Delete header i
		bhash := headersParsed[i].BlockHash()
		fh := fullHeadersFromDb[i]
		bhsBatch.Delete(bhash[:])

		// Delete height mapping for header i
		hhKey := heightHashToKey(fh.Height, bhash[:])
		hhBatch.Delete(hhKey)
	}

	// Insert updated canonical tip after removal of the provided block headers
	tipEbh := encodeBlockHeader(tipAfterRemovalFromDb.Height, tipAfterRemoval, &tipAfterRemovalFromDb.Difficulty)
	bhsBatch.Put([]byte(bhsCanonicalTipKey), tipEbh[:])

	if upstreamStateId != nil {
		bhsBatch.Put([]byte(upstreamStateIdKey), upstreamStateId[:])
	} else {
		bhsBatch.Put([]byte(upstreamStateIdKey), tbcd.DefaultUpstreamStateId[:])
	}

	// Get parent block from database
	parentToRemovalSet, err := l.BlockHeaderByHash(ctx, headersParsed[0].PrevBlock[:])
	if err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: cannot find previous header (hash: %x) to lowest header"+
				" removed %x (hash: %x) in database, err: %w",
				headersParsed[0].PrevBlock[:], bhs[0][:], headersParsed[0].BlockHash(), err)
	}

	removalType := tbcd.RTInvalid
	if bytes.Equal(parentToRemovalSet.Header[:], tipAfterRemoval[:]) {
		// Canonical tip set by caller is the parent to the blocks removed
		removalType = tbcd.RTChainDescend
	} else if bytes.Equal(originalCanonicalTip.Header[:], tipAfterRemoval[:]) {
		// Canonical tip did not change, meaning blocks we removed were on a non-canonical chain
		removalType = tbcd.RTForkDescend
	} else if bytes.Equal(originalCanonicalTip.Header[:], bhs[len(bhs)-1][:]) {
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

	// Write height hash batch
	if err = hhTx.Write(hhBatch, nil); err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to write height hash batch: %w", err)
	}

	// Write block headers batch
	if err = bhsTx.Write(bhsBatch, nil); err != nil {
		return tbcd.RTInvalid, nil,
			fmt.Errorf("block headers remove: unable to write block headers batch: %w", err)
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

	return removalType, parentToRemovalSet, nil
}

// BlockHeadersInsert decodes and inserts the passed blockheaders into the
// database. Additionally it updates the hight/hash and missing blocks table as
// well.  On return it informs the caller about potential forking situations
// and always returns the canonical and last inserted blockheader, which may be
// the same.
// This call uses the database to prevent reentrancy.
func (l *ldb) BlockHeadersInsert(ctx context.Context, bhs [][80]byte, upstreamStateId *[32]byte) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersInsert")
	defer log.Tracef("BlockHeadersInsert exit")

	// XXX at start of day lastRecord contains the last canonical
	// downloaded blockheader. Thus if it is on a fork it will not ask for
	// headers on what the network may be doing. Not sure how to handle
	// that right now but leaving a note.

	if len(bhs) == 0 {
		return tbcd.ITInvalid, nil, nil,
			errors.New("block headers insert: no block headers to insert")
	}

	// Ensure we can connect these blockheaders prior to starting database
	// transaction. This also obtains the starting cumulative difficulty
	// and  height.
	wbh, err := tbcd.B2H(bhs[0][:])
	if err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("block headers insert b2h: %w", err)
	}
	pbh, err := l.BlockHeaderByHash(ctx, wbh.PrevBlock[:])
	if err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("block headers insert: %w", err)
	}

	// block headers
	bhsTx, bhsCommit, bhsDiscard, err := l.startTransaction(level.BlockHeadersDB)
	if err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("block headers open transaction: %w", err)
	}
	defer bhsDiscard()

	// Make sure we are not inserting the same blocks
	bhash := wbh.BlockHash()
	has, err := bhsTx.Has(bhash[:], nil)
	if err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("block headers insert has: %w", err)
	}
	if has {
		return tbcd.ITInvalid, nil, nil,
			database.DuplicateError("block headers insert duplicate")
	}

	// blocks missing
	bmTx, bmCommit, bmDiscard, err := l.startTransaction(level.BlocksMissingDB)
	if err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("blocks missing open transaction: %w", err)
	}
	defer bmDiscard()

	// height hash
	hhTx, hhCommit, hhDiscard, err := l.startTransaction(level.HeightHashDB)
	if err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("height hash open transaction: %w", err)
	}
	defer hhDiscard()

	// retrieve best/canonical block header
	var lastRecord []byte
	bbh, err := bhsTx.Get([]byte(bhsCanonicalTipKey), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return tbcd.ITInvalid, nil, nil,
				database.NotFoundError("best block header not found")
		}
		return tbcd.ITInvalid, nil, nil,
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
	for k, bh := range bhs {
		// The first element is skipped, as it is pre-decoded.
		if k != 0 {
			wbh, err = tbcd.B2H(bh[:])
			if err != nil {
				return tbcd.ITInvalid, nil, nil,
					fmt.Errorf("block headers insert b2h: %w", err)
			}
			bhash = wbh.BlockHash()
		}

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
		ebh := encodeBlockHeader(height, bh, cdiff)
		bhsBatch.Put(bhash[:], ebh[:])
		lastRecord = ebh[:]
	}

	var header [80]byte
	copy(header[:], bhs[len(bhs)-1][:])
	cbh := &tbcd.BlockHeader{
		Hash:       bhash[:],
		Height:     height,
		Header:     header[:],
		Difficulty: *cdiff,
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

	if upstreamStateId != nil {
		bhsBatch.Put([]byte(upstreamStateIdKey), upstreamStateId[:])
	} else {
		bhsBatch.Put([]byte(upstreamStateIdKey), tbcd.DefaultUpstreamStateId[:])
	}

	// Write height hash batch
	if err = hhTx.Write(hhBatch, nil); err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("height hash batch: %w", err)
	}

	// Write missing blocks batch
	if err = bmTx.Write(bmBatch, nil); err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("blocks missing batch: %w", err)
	}

	// Write block headers batch
	if err = bhsTx.Write(bhsBatch, nil); err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("block headers insert: %w", err)
	}

	// height hash commit
	if err = hhCommit(); err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("height hash commit: %w", err)
	}

	// blocks missing commit
	if err = bmCommit(); err != nil {
		return tbcd.ITInvalid, nil, nil,
			fmt.Errorf("blocks missing commit: %w", err)
	}

	// block headers commit
	if err = bhsCommit(); err != nil {
		return tbcd.ITInvalid, nil, nil, fmt.Errorf("block headers commit: %w", err)
	}

	return it, cbh, lbh, nil
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
		if err = bDB.Put(b.Hash, b.Block, nil); err != nil {
			return -1, fmt.Errorf("blocks insert put: %w", err)
		}
	}

	// It's possible to remove the transaction for bm without a transaction
	// as well since the only risk would be duplicate work. Reason about
	// this some more.

	// Remove block identifier from blocks missing
	key := heightHashToKey(bh.Height, bh.Hash)
	bmDB := l.pool[level.BlocksMissingDB]
	if err = bmDB.Delete(key, nil); err != nil {
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

func (l *ldb) BlocksByTxId(ctx context.Context, txId []byte) ([]tbcd.BlockHash, error) {
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
		ctxid, _ := chainhash.NewHash(txId)
		return nil, database.NotFoundError(fmt.Sprintf("tx not found: %v", ctxid))
	}

	return blocks, nil
}

func (l *ldb) SpentOutputsByTxId(ctx context.Context, txId []byte) ([]tbcd.SpentInfo, error) {
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
		var s tbcd.SpentInfo
		copy(s.TxId[:], it.Value()[0:32])
		copy(s.BlockHash[:], it.Key()[37:])
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
		switch direction {
		case -1:
			txsBatch.Delete(key)
		case 1:
			txsBatch.Put(key, value)
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
