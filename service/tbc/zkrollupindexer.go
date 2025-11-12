// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hemilabs/x/zktrie"
	"github.com/mitchellh/go-homedir"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

type zkRollupIndexer struct {
	indexerCommon

	cacheCapacity int

	tr *zktrie.ZKTrie
}

var (
	_ Indexer = (*zkRollupIndexer)(nil)
	_ indexer = (*zkRollupIndexer)(nil)

	zkRollupIndexHashKey = []byte("zkrollupindexhash")
)

type ZKRollupKey chainhash.Hash

func NewZKRollupIndexer(g geometryParams, cacheLen int, enabled bool, network, home string) (Indexer, error) {
	homedir, err := homedir.Expand(filepath.Join(home, network, "zkrollup"))
	if err != nil {
		return nil, err
	}
	tr, err := zktrie.NewZKTrie(homedir)
	if err != nil {
		return nil, err
	}
	zi := &zkRollupIndexer{
		cacheCapacity: cacheLen,
		tr:            tr,
	}
	zi.indexerCommon = indexerCommon{
		name:    "zkrollupindexer",
		enabled: enabled,
		g:       g,
		p:       zi,
	}
	return zi, nil
}

func (i *zkRollupIndexer) newCache() indexerCache {
	return NewCache[ZKRollupKey, []byte](i.cacheCapacity)
}

func (i *zkRollupIndexer) indexerAt(ctx context.Context) (*tbcd.BlockHeader, error) {
	bhHashR, err := i.tr.Get(zkRollupIndexHashKey)
	if err != nil {
		// XXX trie returns level error, we should think about
		// larryizing it.
		if !errors.Is(err, leveldb.ErrNotFound) {
			return nil, err
		}
		return &tbcd.BlockHeader{
			Hash:   *i.g.chain.GenesisHash,
			Height: 0,
			Header: h2b(&i.g.chain.GenesisBlock.Header),
		}, nil
	}
	bhHash, err := chainhash.NewHash(bhHashR)
	if err != nil {
		return nil, err
	}
	return i.g.db.BlockHeaderByHash(ctx, *bhHash)
}

func (i *zkRollupIndexer) processTx(ctx context.Context, zkb *zktrie.ZKBlock, blockHeight uint32, blockHash *chainhash.Hash, tx *btcutil.Tx, c indexerCache) error {
	for txInIdx, txIn := range tx.MsgTx().TxIn {
		// Skip coinbase inputs
		if blockchain.IsCoinBase(tx) {
			continue
		}
		_ = txIn
		_ = txInIdx
	}

	for txOutIdx, txOut := range tx.MsgTx().TxOut {
		// Skip unspendables.
		if txscript.IsUnspendable(txOut.PkScript) {
			continue
		}

		o := zktrie.NewOutpoint(*tx.Hash(), uint32(txOutIdx))
		so := zktrie.NewSpendableOutput(*blockHash, *tx.Hash(), uint32(txOutIdx), uint64(txOut.Value))
		zkb.NewOut(txOut.PkScript, o, so)
	}
	cache[blockhash] = nil // Just store the blockhash to fill up cache

	return nil
}

// XXX this gets replaced by blockhash -> stateRoot cache
var previousStateRoot = types.EmptyRootHash

func (i *zkRollupIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	blockHash := *block.Hash()
	prevBlockHash := block.MsgBlock().Header.PrevBlock
	blockHeight := block.Height()
	log.Tracef("processing: %v %v", blockHeight, blockHash)
	log.Infof("direction %v processing: %v %v", direction, blockHeight, blockHash)

	switch direction {
	case -1:
		// Revert trie here and exit
		panic("revertme")
	case 1:
	default:
		panic(fmt.Sprintf("diagnostic: %v", direction))
	}

	zkb := zktrie.NewZKBlock(blockHash, prevBlockHash, previousStateRoot, uint64(blockHeight))

	for _, tx := range block.Transactions() {
		err := i.processTx(ctx, zkb, uint32(blockHeight), &blockHash, tx, c)
		if err != nil {
			return err
		}
	}

	// XXX create stateroot for block here and cache that
	// NewMetadata(blockheader, previous stateroot)
	// StateRoot = zkb.InsertBlock()
	// rawdb[blockhash]=StateRoot
	// can we pull the previous state root from the 0xff account?

	return nil
}

func (i *zkRollupIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	panic("commit")
	// clear cache
	// cache := c.(*Cache[tbcd.ZKRollupKey, []byte])
	// return i.g.db.BlockZKUpdate(ctx, direction, cache.Map(), atHash)
}

func (i *zkRollupIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk rollup indexer.
	return nil
}
