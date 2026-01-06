// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/common"
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
	// err = tr.Put(g.chain.GenesisHash[:], types.EmptyRootHash[:])
	// if err != nil {
	// 	return nil, err
	// }
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

func (i *zkRollupIndexer) BalanceByScriptHash(ctx context.Context, sh tbcd.ScriptHash) (uint64, error) {
	addr := common.BytesToAddress(sh[:])
	bh, err := i.indexerAt(ctx)
	if err != nil {
		return 0, fmt.Errorf("get indexer at: %w", err)
	}
	var remaining uint64 = 1
	for remaining > 0 {
		remaining, err = i.tr.SyncProgress()
		if err != nil {
			return 0, fmt.Errorf("sync progress: %w", err)
		}
		if remaining > 0 {
			log.Infof("%d unindexed blocks remaining", remaining)
			time.Sleep(10 * time.Second)
		}
	}
	log.Infof("blockheader height: %d", bh.Height)
	h, err := i.getStateRoot(*bh.ParentHash(), i.newCache())
	if err != nil {
		return 0, fmt.Errorf("get state root from block hash: %w", err)
	}
	log.Infof("state root: %v", h.Hex())
	acc, err := i.tr.GetAccount(addr, &h)
	if err != nil {
		return 0, fmt.Errorf("get account from zktrie: %w", err)
	}
	spew.Dump(acc)
	return acc.Balance.Uint64(), nil
}

func (i *zkRollupIndexer) newCache() indexerCache {
	return NewCache[chainhash.Hash, []byte](i.cacheCapacity)
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

func (i *zkRollupIndexer) processTx(ctx context.Context, zkb *zktrie.ZKBlock, blockHash *chainhash.Hash, tx *btcutil.Tx) error {
	for txInIdx, txIn := range tx.MsgTx().TxIn {
		// Skip coinbase inputs
		if blockchain.IsCoinBase(tx) {
			continue
		}
		// Recreate Outpoint from TxIn.PreviousOutPoint
		pop := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
			txIn.PreviousOutPoint.Index)

		_, txOut, err := i.g.db.ZKValueAndScriptByOutpoint(ctx, pop)
		if err != nil {
			return err
		}

		o := zktrie.NewOutpoint(*tx.Hash(), uint32(txInIdx))
		so := zktrie.NewSpentOutput(*blockHash, *tx.Hash(), uint32(txInIdx))
		zkb.NewIn(txOut, o, so)
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
	return nil
}

func (i *zkRollupIndexer) getStateRoot(blockHash chainhash.Hash, c indexerCache) (common.Hash, error) {
	cache := c.(*Cache[chainhash.Hash, []byte]).Map()
	if sr, ok := cache[blockHash]; ok {
		return common.BytesToHash(sr), nil
	}

	// Not found in cache, fetch from db
	sr, err := i.tr.Get(blockHash[:])
	if err != nil {
		// XXX leveldb error
		if errors.Is(err, leveldb.ErrNotFound) {
			return types.EmptyRootHash, nil
		}
		return types.EmptyRootHash, err
	}
	if sr == nil {
		return types.EmptyRootHash, nil
	}
	return common.BytesToHash(sr), nil
}

func (i *zkRollupIndexer) process(ctx context.Context, direction int, block *btcutil.Block, c indexerCache) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}
	blockHash := *block.Hash()

	// skip genesis if we already inserted it once
	if blockHash.IsEqual(i.g.chain.GenesisHash) {
		state, err := i.getStateRoot(blockHash, c)
		if err != nil {
			return fmt.Errorf("get state from prev block: %w", err)
		}
		if state.Cmp(types.EmptyRootHash) != 0 {
			return nil
		}
	}

	cache := c.(*Cache[chainhash.Hash, []byte]).Map()
	prevBlockHash := block.MsgBlock().Header.PrevBlock
	blockHeight := block.Height()
	log.Tracef("processing: %v %v", blockHeight, blockHash)
	log.Infof("direction %v processing: %v %v", direction, blockHeight, blockHash)

	prevState, err := i.getStateRoot(prevBlockHash, c)
	if err != nil {
		return fmt.Errorf("get state from prev block: %w", err)
	}
	switch direction {
	case -1:
		// Revert trie here and exit
		if err := i.tr.Recover(prevState); err != nil {
			return err
		}
		log.Infof("reverted to %s", prevState)
		cache[blockHash] = nil
	case 1:
		zkb := zktrie.NewZKBlock(blockHash, prevBlockHash, prevState, uint64(blockHeight))
		for _, tx := range block.Transactions() {
			err := i.processTx(ctx, zkb, &blockHash, tx)
			if err != nil {
				return err
			}
		}
		stateRoot, err := i.tr.InsertBlock(zkb)
		if err != nil {
			return fmt.Errorf("insert trie block: %w", err)
		}
		if blockHash.IsEqual(i.g.chain.GenesisHash) {
			log.Infof("new genesis value %s", stateRoot)
		}
		cache[blockHash] = stateRoot[:]
	default:
		panic(fmt.Sprintf("diagnostic: %v", direction))
	}
	return nil
}

func (i *zkRollupIndexer) commit(ctx context.Context, direction int, atHash chainhash.Hash, c indexerCache) error {
	cache := c.(*Cache[chainhash.Hash, []byte]).Map()
	var updateTip bool
	defer func() {
		if !updateTip {
			return
		}
		if err := i.tr.Put(zkRollupIndexHashKey, atHash[:]); err != nil {
			log.Errorf("failed to update zkRollupIndexHashKey: %v", err)
		}
	}()
	switch direction {
	case -1:
		updateTip = true
		for bh := range cache {
			if err := i.tr.Del(bh[:]); err != nil {
				if !errors.Is(err, leveldb.ErrNotFound) {
					return fmt.Errorf("delete old blockhash state: %w", err)
				}
			}
		}
		return nil
	case 1:
		if err := i.tr.Commit(); err != nil {
			return fmt.Errorf("commit trie: %w", err)
		}
		updateTip = true
		for bh, sr := range cache {
			if err := i.tr.Put(bh[:], sr); err != nil {
				return fmt.Errorf("insert blockhash state: %w", err)
			}
		}
	default:
		panic(fmt.Sprintf("diagnostic: %v", direction))
	}
	c.Clear()
	return nil
}

func (i *zkRollupIndexer) fixupCacheHook(_ context.Context, _ *btcutil.Block, _ indexerCache) error {
	// Not needed for zk rollup indexer.
	return nil
}
