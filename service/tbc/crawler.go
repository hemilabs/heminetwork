// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/dustin/go-humanize"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/hemi/pop"
)

func s2h(s string) chainhash.Hash {
	h, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return *h
}

var (
	ErrAlreadyIndexing = errors.New("already indexing")

	testnet3Checkpoints = map[chainhash.Hash]uint64{
		s2h("0000000000c3410afe8a2bfef56757c8ba675eaa4bb786a2a02d4fc1124bedf2"): 3700000,
		s2h("0000000000002b9408d001dd42f830e16a9c28ed8daa828523e67e09ea9e0411"): 3600000,
		s2h("000000000000098faa89ab34c3ec0e6e037698e3e54c8d1bbb9dcfe0054a8e7a"): 3200000,
		s2h("0000000000001242d96bedebc9f45a2ecdd40d393ca0d725f500fb4977a50582"): 3100000,
		s2h("0000000000003c46fc60e56b9c2ae202b1efec83fcc7899d21de16757dea40a4"): 3000000,
		s2h("000000000000001669469c0354b3f341a36b10ab099d1962f7ec4fae528b1f1d"): 2900000,
		s2h("0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"): 2500000,
		s2h("000000000000010dd0863ec3d7a0bae17c1957ae1de9cbcdae8e77aad33e3b8c"): 2000000,
		s2h("000000000000000eda80f8c7e55459e348274292ecd77c662f95e29bedbb4865"): 1900000,
		s2h("0000000000049a6b07f91975568dc96bb1aec1a24c6bdadb21eb17c9f1b7256f"): 1500000,
		s2h("0000000000478e259a3eda2fafbeeb0106626f946347955e99278fe6cc848414"): 1000000,
		s2h("0000000000356f8d8924556e765b7a94aaebc6b5c8685dcfa2b1ee8b41acd89b"): 900000,
		s2h("000000000001a7c0aaa2630fbb2c0e476aafffc60f82177375b2aaa22209f606"): 500000,
	}

	mainnetCheckpoints = map[chainhash.Hash]uint64{
		s2h("00000000000000000002a0b5db2a7f8d9087464c2586b546be7bce8eb53b8187"): 850000,
		s2h("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"): 800000,
		s2h("0000000000000000000592a974b1b9f087cb77628bb4a097d5c2c11b3476a58e"): 750000,
		s2h("0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959"): 700000,
		s2h("0000000000000000000060e32d547b6ae2ded52aadbc6310808e4ae42b08cc6a"): 650000,
		s2h("00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91"): 600000,
		s2h("000000000000000000223b7a2298fb1c6c75fb0efc28a4c56853ff4112ec6bc9"): 550000,
		s2h("00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04"): 500000,
		s2h("0000000000000000014083723ed311a461c648068af8cef8a19dcd620c07a20b"): 450000,
		s2h("000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f"): 400000,
		s2h("0000000000000000053cf64f0400bb38e0c4b3872c38795ddde27acb40a112bb"): 350000,
		s2h("000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254"): 300000,
		s2h("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"): 250000,
		s2h("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"): 200000,
		s2h("0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"): 150000,
		s2h("000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"): 100000,
		s2h("000000001aeae195809d120b5d66a39c83eb48792e068f8ea1fea19d84a4278a"): 50000,
	}
)

type NotLinearError string

func (e NotLinearError) Error() string {
	return string(e)
}

func (e NotLinearError) Is(target error) bool {
	_, ok := target.(NotLinearError)
	return ok
}

var ErrNotLinear = NotLinearError("not linear")

func lastCheckpointHeight(height uint64, hhm map[chainhash.Hash]uint64) uint64 {
	c := make([]HashHeight, 0, len(hhm))
	for k, v := range hhm {
		c = append(c, HashHeight{Height: v, Hash: k})
	}
	sort.Slice(c, func(i, j int) bool {
		return c[i].Height > c[j].Height
	})
	for _, hh := range c {
		if hh.Height > height {
			continue
		}
		return hh.Height
	}
	return 0
}

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

type HashHeight struct {
	Hash      chainhash.Hash
	Height    uint64
	Timestamp int64 // optional
}

func (h HashHeight) String() string {
	return fmt.Sprintf("%v @ %v", h.Hash, h.Height)
}

func HashHeightFromBlockHeader(bh *tbcd.BlockHeader) *HashHeight {
	return &HashHeight{
		Hash:      bh.Hash,
		Height:    bh.Height,
		Timestamp: bh.Timestamp().Unix(),
	}
}

// UtxoIndexHash returns the last hash that has been UTxO indexed.
func (s *Server) UtxoIndexHash(ctx context.Context) (*HashHeight, error) {
	bh, err := s.db.BlockHeaderByUtxoIndex(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return nil, err
		}
		bh = &tbcd.BlockHeader{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
			Header: h2b(&s.chainParams.GenesisBlock.Header),
		}
	}
	return HashHeightFromBlockHeader(bh), nil
}

// TxIndexHash returns the last hash that has been Tx indexed.
func (s *Server) TxIndexHash(ctx context.Context) (*HashHeight, error) {
	bh, err := s.db.BlockHeaderByTxIndex(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return nil, err
		}
		bh = &tbcd.BlockHeader{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
			Header: h2b(&s.chainParams.GenesisBlock.Header),
		}
	}
	return HashHeightFromBlockHeader(bh), nil
}

// KeystoneIndexHash returns the last hash that has been Keystone indexed.
func (s *Server) KeystoneIndexHash(ctx context.Context) (*HashHeight, error) {
	bh, err := s.db.BlockHeaderByKeystoneIndex(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return nil, err
		}
		bh = &tbcd.BlockHeader{
			Hash:   *s.chainParams.GenesisHash,
			Height: 0,
			Header: h2b(&s.chainParams.GenesisBlock.Header),
		}
	}
	return HashHeightFromBlockHeader(bh), nil
}

func (s *Server) findCommonParent(ctx context.Context, bhX, bhY *tbcd.BlockHeader) (*tbcd.BlockHeader, error) {
	// This function has one odd corner case. If bhX and bhY are both on a
	// "long" chain without multiple blockheaders it will terminate on the
	// first height that has a single blockheader. This is to be expected!
	// This function "should" be called between forking blocks and then
	// it'll find the first common parent.

	// This function assumes that the highest block height connects to the
	// lowest block height.

	// 0. If bhX and bhY are the same return bhX.
	if bhX.Hash.IsEqual(&bhY.Hash) {
		return bhX, nil
	}

	// 1. Find lowest height between X and Y.
	h := min(bhX.Height, bhY.Height)

	// 2. Walk chain back until X and Y point to the same parent.
	for {
		bhs, err := s.db.BlockHeadersByHeight(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("block headers by height: %w", err)
		}
		if bhs[0].Hash.IsEqual(s.chainParams.GenesisHash) {
			if h != 0 {
				panic("height 0 not genesis")
			}
			return nil, fmt.Errorf("genesis")
		}

		// See if all blockheaders share a common parent.
		equals := 0
		var ph *chainhash.Hash
		for k := range bhs {
			if k == 0 {
				ph = bhs[k].ParentHash()
			}
			if !ph.IsEqual(bhs[k].ParentHash()) {
				break
			}
			equals++
		}
		if equals == len(bhs) {
			// All blockheaders point to the same parent.
			return s.db.BlockHeaderByHash(ctx, ph)
		}

		// Decrease height
		h--
	}
}

func (s *Server) isCanonical(ctx context.Context, bh *tbcd.BlockHeader) (bool, error) {
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return false, err
	}
	if bhb.Height < bh.Height {
		// We either hit a race or the caller did something wrong.
		// Either way, it cannot be canonical.
		log.Debugf("best height less than provided height: %v < %v",
			bhb.Height, bh.Height)
		return false, nil
	}
	if bhb.Hash.IsEqual(&bh.Hash) {
		// Self == best
		return true, nil
	}
	// Move best block header backwards until we find bh.
	for {
		// log.Infof("isCanonical %v @ %v bh %v", bhb.Height, bhb, bh.Height)
		if height, ok := s.checkpoints[bhb.Hash]; ok && height <= bh.Height {
			// Did not find bh in path
			return false, nil
		}
		bhb, err = s.db.BlockHeaderByHash(ctx, bhb.ParentHash())
		if err != nil {
			return false, err
		}
		if bhb.Hash.IsEqual(s.chainParams.GenesisHash) {
			return false, nil
		}
		if bhb.Hash.IsEqual(&bh.Hash) {
			return true, nil
		}
	}
}

func (s *Server) findCanonicalParent(ctx context.Context, bh *tbcd.BlockHeader) (*tbcd.BlockHeader, error) {
	log.Tracef("findCanonicalParent %v", bh)

	// Genesis is always canonical.
	if bh.Hash.IsEqual(s.chainParams.GenesisHash) {
		return bh, nil
	}

	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return nil, err
	}
	log.Debugf("findCanonicalParent %v @ %v best %v @ %v",
		bh, bh.Height, bhb, bhb.Height)
	for {
		canonical, err := s.isCanonical(ctx, bh)
		if err != nil {
			return nil, err
		}
		if canonical {
			log.Tracef("findCanonicalParent exit %v", bh)
			return bh, nil
		}
		bh, err = s.findCommonParent(ctx, bhb, bh)
		if err != nil {
			return nil, err
		}
	}
}

// findPathFromHash determines which hash is in the path by walking back the
// chain from the provided end point. It returns the index in bhs of the
// correct hash. On failure it returns -1 DELIBERATELY to crash the caller if
// error is not checked.
func (s *Server) findPathFromHash(ctx context.Context, endHash *chainhash.Hash, bhs []tbcd.BlockHeader) (int, error) {
	log.Tracef("findPathFromHash %v", len(bhs))
	switch len(bhs) {
	case 1:
		return 0, nil // most common fast path
	case 0:
		return -1, errors.New("no blockheaders provided")
	}

	// When this happens we have to walk back from endHash to find the
	// connecting block. There is no shortcut possible without hitting edge
	// conditions.
	h := endHash
	for {
		bh, err := s.db.BlockHeaderByHash(ctx, h)
		if err != nil {
			return -1, fmt.Errorf("block header by hash: %w", err)
		}
		for k, v := range bhs {
			if h.IsEqual(v.BlockHash()) {
				return k, nil
			}
		}
		if h.IsEqual(s.chainParams.GenesisHash) {
			break
		}
		h = bh.ParentHash()
	}
	return -1, errors.New("path not found")
}

func (s *Server) nextCanonicalBlockheader(ctx context.Context, endHash *chainhash.Hash, hh *HashHeight) (*HashHeight, error) {
	// Move to next block
	height := hh.Height + 1
	bhs, err := s.db.BlockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("block headers by height %v: %w",
			height, err)
	}
	index, err := s.findPathFromHash(ctx, endHash, bhs)
	if err != nil {
		return nil, fmt.Errorf("could not determine canonical path %v: %w",
			height, err)
	}
	// Verify it connects to parent
	if !hh.Hash.IsEqual(bhs[index].ParentHash()) {
		return nil, fmt.Errorf("%v does not connect to: %v", bhs[index], hh.Hash)
	}
	nbh := bhs[index]
	return &HashHeight{Hash: *nbh.BlockHash(), Height: nbh.Height}, nil
}

// headerAndBlock retrieves both the blockheader and the block. While the
// blockheader is part of the block we do this double database retrieval to
// ensure both exist.
func (s *Server) headerAndBlock(ctx context.Context, hash *chainhash.Hash) (*tbcd.BlockHeader, *btcutil.Block, error) {
	bh, err := s.db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("block header %v: %w", hash, err)
	}
	b, err := s.db.BlockByHash(ctx, &bh.Hash)
	if err != nil {
		return nil, nil, fmt.Errorf("block by hash %v: %w", bh, err)
	}

	return bh, b, nil
}

func logMemStats() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// Go memory statistics are hard to interpret but the following list is
	// an approximation:
	//	Alloc is currently allocated memory
	// 	TotalAlloc is all memory allocated over time
	// 	Sys is basically a peak memory use
	log.Infof("Alloc = %v, TotalAlloc = %v, Sys = %v, NumGC = %v\n",
		humanize.IBytes(mem.Alloc),
		humanize.IBytes(mem.TotalAlloc),
		humanize.IBytes(mem.Sys),
		mem.NumGC)
}

func processUtxos(txs []*btcutil.Tx, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	for _, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}
			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if utxo, ok := utxos[op]; ok && !utxo.IsDelete() {
				delete(utxos, op)
				continue
			}
		}
		for outIndex, txOut := range tx.MsgTx().TxOut {
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}
			utxos[tbcd.NewOutpoint(*tx.Hash(), uint32(outIndex))] = tbcd.NewCacheOutput(
				tbcd.NewScriptHashFromScript(txOut.PkScript),
				uint64(txOut.Value),
				uint32(outIndex))
		}
	}
	return nil
}

func (s *Server) scriptValue(ctx context.Context, op tbcd.Outpoint) ([]byte, int64, error) {
	txId := op.TxIdHash()
	txIndex := op.TxIndex()

	// Find block hashes
	blockHash, err := s.db.BlockHashByTxId(ctx, txId)
	if err != nil {
		return nil, 0, fmt.Errorf("block by txid: %w", err)
	}
	b, err := s.db.BlockByHash(ctx, blockHash)
	if err != nil {
		return nil, 0, fmt.Errorf("block by hash: %w", err)
	}
	for _, tx := range b.Transactions() {
		if !tx.Hash().IsEqual(txId) {
			continue
		}
		txOuts := tx.MsgTx().TxOut
		if len(txOuts) < int(txIndex) {
			return nil, 0, fmt.Errorf("tx index invalid: %v", op)
		}
		tx := txOuts[txIndex]
		return tx.PkScript, tx.Value, nil
	}

	return nil, 0, fmt.Errorf("tx id not found: %v", op)
}

func (s *Server) unprocessUtxos(ctx context.Context, txs []*btcutil.Tx, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	// Walk backwards through the txs
	for idx := len(txs) - 1; idx >= 0; idx-- {
		tx := txs[idx]
		// TxIn get data from disk and insert into the cache as insert
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			pkScript, value, err := s.scriptValue(ctx, op)
			if err != nil {
				return fmt.Errorf("script value: %w", err)
			}
			// XXX this should not happen. We are keeping it for
			// now to ensure it indeed does not happen. Remove in a
			// couple of years.
			if _, ok := utxos[op]; ok {
				return fmt.Errorf("impossible collision: %v", op)
			}
			utxos[op] = tbcd.NewCacheOutput(tbcd.NewScriptHashFromScript(pkScript),
				uint64(value), txIn.PreviousOutPoint.Index)
		}

		// TxOut if those are in the cache delete from cache; if they
		// are not in the cache insert "delete from disk command" into
		// cache.
		for outIndex, txOut := range tx.MsgTx().TxOut {
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}

			op := tbcd.NewOutpoint(*tx.Hash(), uint32(outIndex))
			if _, ok := utxos[op]; ok {
				delete(utxos, op)
			} else {
				utxos[op] = tbcd.NewDeleteCacheOutput(tbcd.NewScriptHashFromScript(txOut.PkScript),
					op.TxIndex())
			}
		}
	}

	return nil
}

func (s *Server) fetchOPParallel(ctx context.Context, w *sync.WaitGroup, op tbcd.Outpoint, utxos map[tbcd.Outpoint]tbcd.CacheOutput) {
	defer w.Done()

	sh, err := s.db.ScriptHashByOutpoint(ctx, op)
	if err != nil {
		// This happens when a transaction is created and spent in the
		// same block.
		// XXX this is probably too loud but log for investigation and
		// remove later.
		log.Debugf("db missing pkscript: %v", op)
		return
	}
	s.mtx.Lock()
	utxos[op] = tbcd.NewDeleteCacheOutput(*sh, op.TxIndex())
	s.mtx.Unlock()
}

func (s *Server) fixupCacheParallel(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	w := new(sync.WaitGroup)
	for _, tx := range b.Transactions() {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			s.mtx.Lock()
			if _, ok := utxos[op]; ok {
				s.mtx.Unlock()
				continue
			}
			s.mtx.Unlock()

			// utxo not found, retrieve pkscript from database.
			w.Add(1)
			go s.fetchOPParallel(ctx, w, op, utxos)
		}
	}

	w.Wait()

	return nil
}

func (s *Server) fixupCacheSerial(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	for _, tx := range b.Transactions() {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if _, ok := utxos[op]; ok {
				continue
			}

			sh, err := s.db.ScriptHashByOutpoint(ctx, op)
			if err != nil {
				// This happens when a transaction is created
				// and spent in the same block.
				continue
			}
			// utxo not found, retrieve pkscript from database.
			utxos[op] = tbcd.NewDeleteCacheOutput(*sh, op.TxIndex())
		}
	}

	return nil
}

func (s *Server) fixupCacheBatched(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	ops := make([]*tbcd.Outpoint, 0, 8192)
	defer clear(ops)
	for _, tx := range b.Transactions() {
		for _, txIn := range tx.MsgTx().TxIn {
			if blockchain.IsCoinBase(tx) {
				// Skip coinbase inputs
				break
			}

			op := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if _, ok := utxos[op]; ok {
				continue
			}

			ops = append(ops, &op)
		}
	}
	found := func(op tbcd.Outpoint, sh tbcd.ScriptHash) error {
		utxos[op] = tbcd.NewDeleteCacheOutput(sh, op.TxIndex())
		return nil
	}
	return s.db.ScriptHashesByOutpoint(ctx, ops, found)
}

// indexUtxosInBlocks indexes utxos from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it has processed.
func (s *Server) indexUtxosInBlocks(ctx context.Context, endHash *chainhash.Hash, utxos map[tbcd.Outpoint]tbcd.CacheOutput) (int, *HashHeight, error) {
	log.Tracef("indexUtxoBlocks")
	defer log.Tracef("indexUtxoBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("utxo index hash: %w", err)
	}

	// If we have a real block move forward to the next block since we
	// already indexed the last block.
	hh := utxoHH
	if !hh.Hash.IsEqual(s.chainParams.GenesisHash) {
		hh, err = s.nextCanonicalBlockheader(ctx, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("utxo next block %v: %w", hh, err)
		}
	}

	utxosPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	for {
		log.Debugf("indexing utxos: %v", hh)

		bh, b, err := s.headerAndBlock(ctx, &hh.Hash)
		if err != nil {
			return 0, last, err
		}

		err = s.fixupCache(ctx, b, utxos)
		if err != nil {
			return 0, last, fmt.Errorf("process utxos fixup %v: %w", hh, err)
		}
		err = processUtxos(b.Transactions(), utxos)
		if err != nil {
			return 0, last, fmt.Errorf("process utxos %v: %w", hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(utxos) * 100 / s.cfg.MaxCachedTxs
		if bh.Height%10000 == 0 || cp > utxosPercentage || blocksProcessed == 1 {
			log.Infof("Utxo indexer: %v utxo cache %v%%", hh, cp)
		}
		if cp > utxosPercentage {
			// Set utxosMax to the largest utxo capacity seen
			s.cfg.MaxCachedTxs = max(len(utxos), s.cfg.MaxCachedTxs)
			last = hh
			// Flush
			break
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hh.Hash) {
			last = hh
			break
		}

		// Move to next block
		hh, err = s.nextCanonicalBlockheader(ctx, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("utxo next block %v: %w", hh, err)
		}
	}

	return blocksProcessed, last, nil
}

// unindexUtxosInBlocks unindexes utxos from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it has processed.
func (s *Server) unindexUtxosInBlocks(ctx context.Context, endHash *chainhash.Hash, utxos map[tbcd.Outpoint]tbcd.CacheOutput) (int, *HashHeight, error) {
	log.Tracef("unindexUtxoBlocks")
	defer log.Tracef("unindexUtxoBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("utxo index hash: %w", err)
	}

	utxosPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	hh := utxoHH
	for {
		log.Debugf("unindexing utxos: %v", hh)

		hash := hh.Hash
		bh, err := s.db.BlockHeaderByHash(ctx, &hash)
		if err != nil {
			return 0, last, fmt.Errorf("block header %v: %w", hash, err)
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		// Index block
		b, err := s.db.BlockByHash(ctx, &bh.Hash)
		if err != nil {
			return 0, last, fmt.Errorf("block by hash %v: %w", bh, err)
		}

		err = s.unprocessUtxos(ctx, b.Transactions(), utxos)
		if err != nil {
			return 0, last, fmt.Errorf("process utxos %v: %w", hh, err)
		}

		// Add tx's back to the mempool.
		//if s.cfg.MempoolEnabled {
		//	// XXX this may not be the right spot.
		//	txHashes, _ := b.MsgBlock().TxHashes()
		//	_ = s.mempool.txsRemove(ctx, txHashes)
		//}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(utxos) * 100 / s.cfg.MaxCachedTxs
		if bh.Height%10000 == 0 || cp > utxosPercentage || blocksProcessed == 1 {
			log.Infof("UTxo unindexer: %v utxo cache %v%%", hh, cp)
		}

		// Move to previous block
		height := bh.Height - 1
		pbh, err := s.db.BlockHeaderByHash(ctx, bh.ParentHash())
		if err != nil {
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}
		hh.Hash = *pbh.BlockHash()
		hh.Height = pbh.Height

		// We check overflow AFTER obtaining the previous hash so that
		// we can update the database with the LAST processed block.
		if cp > utxosPercentage {
			// Set txsMax to the largest tx capacity seen
			s.cfg.MaxCachedTxs = max(len(utxos), s.cfg.MaxCachedTxs)
			last = hh
			// Flush
			break
		}
	}

	return blocksProcessed, last, nil
}

func (s *Server) UtxoIndexerUnwind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("UtxoIndexerUnwind")
	defer log.Tracef("UtxoIndexerUnwind exit")

	// XXX dedup with TxIndexedWind; it's basically the same code but with the direction, start and endhas flipped
	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("UtxoIndexerUnwind not true")
	}
	s.mtx.Unlock()

	// Allocate here so that we don't waste space when not indexing.
	utxos := make(map[tbcd.Outpoint]tbcd.CacheOutput, s.cfg.MaxCachedTxs)
	defer clear(utxos)

	log.Infof("Start unwinding UTxos at hash %v height %v", startBH, startBH.Height)
	log.Infof("End unwinding UTxos at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.unindexUtxosInBlocks(ctx, endHash, utxos)
		if err != nil {
			return fmt.Errorf("unindex utxos in blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		utxosCached := len(utxos)
		log.Infof("UTxo unwinder blocks processed %v in %v transactions cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Since(start), utxosCached,
			s.cfg.MaxCachedTxs-utxosCached, utxosCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockUtxoUpdate(ctx, -1, utxos, &last.Hash); err != nil {
			return fmt.Errorf("block utxo update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing unwind utxos complete %v took %v",
			utxosCached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}

	return nil
}

func (s *Server) UtxoIndexerWind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("UtxoIndexerWind")
	defer log.Tracef("UtxoIndexerWind exit")

	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("UtxoIndexerWind not true")
	}
	s.mtx.Unlock()

	// Allocate here so that we don't waste space when not indexing.
	utxos := make(map[tbcd.Outpoint]tbcd.CacheOutput, s.cfg.MaxCachedTxs)
	defer clear(utxos)

	log.Infof("Start indexing UTxos at hash %v height %v", startBH, startBH.Height)
	log.Infof("End indexing UTxos at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.indexUtxosInBlocks(ctx, endHash, utxos)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		utxosCached := len(utxos)
		log.Infof("Utxo indexer blocks processed %v in %v utxos cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Since(start), utxosCached,
			s.cfg.MaxCachedTxs-utxosCached, utxosCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockUtxoUpdate(ctx, 1, utxos, &last.Hash); err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}

		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing utxos complete %v took %v",
			utxosCached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}
	}

	return nil
}

func (s *Server) UtxoIndexer(ctx context.Context, endHash *chainhash.Hash) error {
	log.Tracef("UtxoIndexer")
	defer log.Tracef("UtxoIndexer exit")

	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("UtxoIndexer indexing not true")
	}
	s.mtx.Unlock()
	// XXX this is basically duplicate from UtxoIndexIsLinear

	// Verify exit condition hash
	if endHash == nil {
		return errors.New("must provide an end hash")
	}
	endBH, err := s.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return fmt.Errorf("blockheader hash: %w", err)
	}

	// Verify start point is not after the end point
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("utxo index hash: %w", err)
	}

	// XXX make sure there is no gap between start and end or vice versa.
	startBH, err := s.db.BlockHeaderByHash(ctx, &utxoHH.Hash)
	if err != nil {
		return fmt.Errorf("blockheader hash: %w", err)
	}
	direction, err := s.UtxoIndexIsLinear(ctx, endHash)
	if err != nil {
		return fmt.Errorf("utxo index is linear: %w", err)
	}
	log.Debugf("startbh %v", startBH.HH())
	log.Debugf("endHash %v", endHash)
	log.Debugf("direction %v", direction)
	switch direction {
	case 1:
		return s.UtxoIndexerWind(ctx, startBH, endBH)
	case -1:
		return s.UtxoIndexerUnwind(ctx, startBH, endBH)
	case 0:
		// Because we call UtxoIndexIsLinear we know it's the same block.
		return nil
	}
	return fmt.Errorf("invalid direction: %v", direction)
}

func processTxs(blockHash *chainhash.Hash, txs []*btcutil.Tx, txsCache map[tbcd.TxKey]*tbcd.TxValue) error {
	for _, tx := range txs {
		// cache txid <-> block
		txsCache[tbcd.NewTxMapping(tx.Hash(), blockHash)] = nil

		// Don't keep track of spent coinbase inputs
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

		for txInIdx, txIn := range tx.MsgTx().TxIn {
			txk, txv := tbcd.NewTxSpent(
				blockHash,
				tx.Hash(),
				&txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index,
				uint32(txInIdx))
			txsCache[txk] = &txv
		}
	}
	return nil
}

// indexTxsInBlocks indexes txs from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it has processed.
func (s *Server) indexTxsInBlocks(ctx context.Context, endHash *chainhash.Hash, txs map[tbcd.TxKey]*tbcd.TxValue) (int, *HashHeight, error) {
	log.Tracef("indexTxsInBlocks")
	defer log.Tracef("indexTxsInBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("tx index hash: %w", err)
	}

	// If we have a real block move forward to the next block since we
	// already indexed the last block.
	hh := txHH
	if !hh.Hash.IsEqual(s.chainParams.GenesisHash) {
		hh, err = s.nextCanonicalBlockheader(ctx, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("tx next block %v: %w", hh, err)
		}
	}

	txsPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	for {
		log.Debugf("indexing txs: %v", hh)

		bh, b, err := s.headerAndBlock(ctx, &hh.Hash)
		if err != nil {
			return 0, last, err
		}

		// Index block
		err = processTxs(b.Hash(), b.Transactions(), txs)
		if err != nil {
			return 0, last, fmt.Errorf("process txs %v: %w", hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(txs) * 100 / s.cfg.MaxCachedTxs
		if bh.Height%10000 == 0 || cp > txsPercentage || blocksProcessed == 1 {
			log.Infof("Tx indexer: %v tx cache %v%%", hh, cp)
		}
		if cp > txsPercentage {
			// Set txsMax to the largest tx capacity seen
			s.cfg.MaxCachedTxs = max(len(txs), s.cfg.MaxCachedTxs)
			last = hh
			// Flush
			break
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hh.Hash) {
			last = hh
			break
		}

		// Move to next block
		hh, err = s.nextCanonicalBlockheader(ctx, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("tx next block %v: %w", hh, err)
		}
	}

	return blocksProcessed, last, nil
}

// unindexTxsInBlocks indexes txs from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it has processed.
func (s *Server) unindexTxsInBlocks(ctx context.Context, endHash *chainhash.Hash, txs map[tbcd.TxKey]*tbcd.TxValue) (int, *HashHeight, error) {
	log.Tracef("unindexTxsInBlocks")
	defer log.Tracef("unindexTxsInBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("tx index hash: %w", err)
	}

	txsPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	hh := txHH
	for {
		log.Debugf("unindexing txs: %v", hh)

		hash := hh.Hash

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		bh, err := s.db.BlockHeaderByHash(ctx, &hash)
		if err != nil {
			return 0, last, fmt.Errorf("block header %v: %w", hash, err)
		}

		// Index block
		b, err := s.db.BlockByHash(ctx, &bh.Hash)
		if err != nil {
			return 0, last, fmt.Errorf("block by hash %v: %w", bh, err)
		}

		err = processTxs(b.Hash(), b.Transactions(), txs)
		if err != nil {
			return 0, last, fmt.Errorf("process txs %v: %w", hh, err)
		}

		// This is probably not needed here since we already dealt with
		// it via the utxo unindexer but since it will be mostly a
		// no-op just go ahead.
		//if s.cfg.MempoolEnabled {
		//	// XXX this may not be the right spot.
		//	txHashes, _ := b.MsgBlock().TxHashes()
		//	_ = s.mempool.txsRemove(ctx, txHashes)
		//}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(txs) * 100 / s.cfg.MaxCachedTxs
		if bh.Height%10000 == 0 || cp > txsPercentage || blocksProcessed == 1 {
			log.Infof("Tx unindexer: %v tx cache %v%%", hh, cp)
		}

		// Move to previous block
		height := bh.Height - 1
		pbh, err := s.db.BlockHeaderByHash(ctx, bh.ParentHash())
		if err != nil {
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}
		hh.Hash = *pbh.BlockHash()
		hh.Height = pbh.Height

		// We check overflow AFTER obtaining the previous hash so that
		// we can update the database with the LAST processed block.
		if cp > txsPercentage {
			// Set txsMax to the largest tx capacity seen
			s.cfg.MaxCachedTxs = max(len(txs), s.cfg.MaxCachedTxs)
			last = hh
			// Flush
			break
		}
	}

	return blocksProcessed, last, nil
}

func (s *Server) TxIndexerUnwind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("TxIndexerUnwind")
	defer log.Tracef("TxIndexerUnwind exit")

	// XXX dedup with TxIndexerWind; it's basically the same code but with the direction, start anf endhas flipped

	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("TxIndexerUnwind indexing not true")
	}
	s.mtx.Unlock()
	// Allocate here so that we don't waste space when not indexing.
	txs := make(map[tbcd.TxKey]*tbcd.TxValue, s.cfg.MaxCachedTxs)
	defer clear(txs)

	log.Infof("Start unwinding Txs at hash %v height %v", startBH, startBH.Height)
	log.Infof("End unwinding Txs at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.unindexTxsInBlocks(ctx, endHash, txs)
		if err != nil {
			return fmt.Errorf("unindex txs in blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		txsCached := len(txs)
		log.Infof("Tx unwinder blocks processed %v in %v transactions cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Since(start), txsCached,
			s.cfg.MaxCachedTxs-txsCached, txsCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockTxUpdate(ctx, -1, txs, &last.Hash); err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing unwind txs complete %v took %v",
			txsCached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}

	}
	return nil
}

func (s *Server) TxIndexerWind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("TxIndexerWind")
	defer log.Tracef("TxIndexerWind exit")

	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("TxIndexerWind not true")
	}
	s.mtx.Unlock()

	// Allocate here so that we don't waste space when not indexing.
	txs := make(map[tbcd.TxKey]*tbcd.TxValue, s.cfg.MaxCachedTxs)
	defer clear(txs)

	log.Infof("Start indexing Txs at hash %v height %v", startBH, startBH.Height)
	log.Infof("End indexing Txs at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.indexTxsInBlocks(ctx, endHash, txs)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		txsCached := len(txs)
		log.Infof("Tx indexer blocks processed %v in %v transactions cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Since(start), txsCached,
			s.cfg.MaxCachedTxs-txsCached, txsCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockTxUpdate(ctx, 1, txs, &last.Hash); err != nil {
			return fmt.Errorf("block tx update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing txs complete %v took %v",
			txsCached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}

	}

	return nil
}

func (s *Server) TxIndexer(ctx context.Context, endHash *chainhash.Hash) error {
	log.Tracef("TxIndexer")
	defer log.Tracef("TxIndexer exit")

	// XXX this is basically duplicate from TxIndexIsLinear

	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("TxIndexer not true")
	}
	s.mtx.Unlock()

	// Verify exit condition hash
	if endHash == nil {
		return errors.New("must provide an end hash")
	}
	endBH, err := s.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return fmt.Errorf("blockheader hash: %w", err)
	}

	// Verify start point is not after the end point
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("tx index hash: %w", err)
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := s.db.BlockHeaderByHash(ctx, &txHH.Hash)
	if err != nil {
		return fmt.Errorf("blockheader hash: %w", err)
	}
	direction, err := s.TxIndexIsLinear(ctx, endHash)
	if err != nil {
		return fmt.Errorf("tx index is linear: %w", err)
	}
	switch direction {
	case 1:
		return s.TxIndexerWind(ctx, startBH, endBH)
	case -1:
		return s.TxIndexerUnwind(ctx, startBH, endBH)
	case 0:
		// Because we call TxIndexIsLinear we know it's the same block.
		return nil
	}

	return fmt.Errorf("invalid direction: %v", direction)
}

func processKeystones(blockHash *chainhash.Hash, txs []*btcutil.Tx, direction int, kssCache map[chainhash.Hash]tbcd.Keystone) error {
	for _, tx := range txs {
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

		for _, txOut := range tx.MsgTx().TxOut {
			aPoPTx, err := pop.ParseTransactionL2FromOpReturn(txOut.PkScript)
			if err != nil {
				// log.Tracef("error parsing tx l2: %s", err)
				continue
			}
			if _, ok := kssCache[*aPoPTx.L2Keystone.Hash()]; ok {
				// Multiple keystones may exist in block, only
				// store first or last based on direction. When
				// we move forward we only care about the first
				// one, when we move backwards we only car
				// about the last one thus overwrite the value
				// in the map.
				if direction == 1 {
					continue
				}
			}

			abvKss := aPoPTx.L2Keystone.Serialize()
			kssCache[*aPoPTx.L2Keystone.Hash()] = tbcd.Keystone{
				BlockHash:           *blockHash,
				AbbreviatedKeystone: abvKss,
			}
		}
	}
	return nil
}

// indexKeystonesInBlocks indexes txs from the last processed block until the
// provided end hash, inclusive. It returns the number of blocks processed and
// the last hash it processed.
func (s *Server) indexKeystonesInBlocks(ctx context.Context, endHash *chainhash.Hash, kss map[chainhash.Hash]tbcd.Keystone) (int, *HashHeight, error) {
	log.Tracef("indexKeystonesInBlocks")
	defer log.Tracef("indexKeystonesInBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	keystoneHH, err := s.KeystoneIndexHash(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("keystone index hash: %w", err)
	}

	// If we have a real block move forward to the next block since we
	// already indexed the last block.
	hh := keystoneHH
	if !hh.Hash.IsEqual(s.chainParams.GenesisHash) {
		hh, err = s.nextCanonicalBlockheader(ctx, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("keystone next block %v: %w", hh, err)
		}
	} else {
		// Keystone indexer is special, override genesis.
		hh = s.hemiGenesis
	}

	keystonesPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	for {
		log.Debugf("indexing keystones: %v", hh)

		bh, b, err := s.headerAndBlock(ctx, &hh.Hash)
		if err != nil {
			return 0, last, err
		}

		// Index block
		err = processKeystones(b.Hash(), b.Transactions(), 1, kss)
		if err != nil {
			return 0, last, fmt.Errorf("process keystones %v: %w", hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(kss) * 100 / s.cfg.MaxCachedKeystones
		if bh.Height%10000 == 0 || cp > keystonesPercentage || blocksProcessed == 1 {
			log.Infof("Keystone indexer: %v keystone cache %v%%", hh, cp)
		}

		if cp > keystonesPercentage {
			// Set keystonesMax to the largest keystone capacity seen
			s.cfg.MaxCachedKeystones = max(len(kss), s.cfg.MaxCachedKeystones)
			last = hh
			// Flush
			break
		}

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hh.Hash) {
			last = hh
			break
		}

		// Move to next block
		hh, err = s.nextCanonicalBlockheader(ctx, endHash, hh)
		if err != nil {
			return 0, last, fmt.Errorf("keystone next block %v: %w", hh, err)
		}
	}

	return blocksProcessed, last, nil
}

// unindexKeystonesInBlocks unindexes keystones from the last processed block
// until the provided end hash, inclusive. It returns the number of blocks
// processed and the last hash it processed.
func (s *Server) unindexKeystonesInBlocks(ctx context.Context, endHash *chainhash.Hash, kss map[chainhash.Hash]tbcd.Keystone) (int, *HashHeight, error) {
	log.Tracef("unindexKeystonesInBlocks")
	defer log.Tracef("unindexKeystonesInBlocks exit")

	// indicates if we have processed endHash and thus have hit the exit
	// condition.
	var last *HashHeight

	// Find start hash
	ksHH, err := s.KeystoneIndexHash(ctx)
	if err != nil {
		return 0, last, fmt.Errorf("keystone index hash: %w", err)
	}

	kssPercentage := 95 // flush cache at >95% capacity
	blocksProcessed := 0
	hh := ksHH
	for {
		log.Debugf("unindexing keystones: %v", hh)

		hash := hh.Hash

		// Exit if we processed the provided end hash
		if endHash.IsEqual(&hash) {
			last = hh
			break
		}

		bh, err := s.db.BlockHeaderByHash(ctx, &hash)
		if err != nil {
			return 0, last, fmt.Errorf("block header %v: %w", hash, err)
		}

		// Index block
		b, err := s.db.BlockByHash(ctx, &bh.Hash)
		if err != nil {
			return 0, last, fmt.Errorf("block by hash %v: %w", bh, err)
		}

		err = processKeystones(b.Hash(), b.Transactions(), -1, kss)
		if err != nil {
			return 0, last, fmt.Errorf("process keystones %v: %w", hh, err)
		}

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(kss) * 100 / s.cfg.MaxCachedKeystones
		if bh.Height%10000 == 0 || cp > kssPercentage || blocksProcessed == 1 {
			log.Infof("Keystone unindexer: %v keystone cache %v%%", hh, cp)
		}

		// Move to previous block
		height := bh.Height - 1
		pbh, err := s.db.BlockHeaderByHash(ctx, bh.ParentHash())
		if err != nil {
			return 0, last, fmt.Errorf("block headers by height %v: %w",
				height, err)
		}
		hh.Hash = *pbh.BlockHash()
		hh.Height = pbh.Height

		// We check overflow AFTER obtaining the previous hash so that
		// we can update the database with the LAST processed block.
		if cp > kssPercentage {
			// Set kssMax to the largest keystone capacity seen
			s.cfg.MaxCachedKeystones = max(len(kss), s.cfg.MaxCachedKeystones)
			last = hh
			// Flush
			break
		}
	}

	return blocksProcessed, last, nil
}

func (s *Server) KeystoneIndexerUnwind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("KeystoneIndexerUnwind")
	defer log.Tracef("KeystoneIndexerUnwind exit")

	// XXX dedup with KeystoneIndexerWind; it's basically the same code but with the direction, start anf endhas flipped

	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("KeystoneIndexerUnwind indexing not true")
	}
	s.mtx.Unlock()
	// Allocate here so that we don't waste space when not indexing.
	kss := make(map[chainhash.Hash]tbcd.Keystone, s.cfg.MaxCachedKeystones)
	defer clear(kss)

	log.Infof("Start unwinding keystones at hash %v height %v", startBH, startBH.Height)
	log.Infof("End unwinding keystones at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.unindexKeystonesInBlocks(ctx, endHash, kss)
		if err != nil {
			return fmt.Errorf("unindex keystones in blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		kssCached := len(kss)
		log.Infof("Keystone unwinder blocks processed %v in %v keystones cached %v cache unused %v avg keystone/blk %v",
			blocksProcessed, time.Since(start), kssCached,
			s.cfg.MaxCachedKeystones-kssCached, kssCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockKeystoneUpdate(ctx, -1, kss, &last.Hash); err != nil {
			return fmt.Errorf("block keystone update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing unwind keystones complete %v took %v",
			kssCached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}

	}
	return nil
}

func (s *Server) KeystoneIndexerWind(ctx context.Context, startBH, endBH *tbcd.BlockHeader) error {
	log.Tracef("KeystoneIndexerWind")
	defer log.Tracef("KeystoneIndexerWind exit")

	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("KeystoneIndexerWind not true")
	}
	s.mtx.Unlock()

	// Allocate here so that we don't waste space when not indexing.
	kss := make(map[chainhash.Hash]tbcd.Keystone, s.cfg.MaxCachedKeystones)
	defer clear(kss)

	log.Infof("Start indexing keystones at hash %v height %v", startBH, startBH.Height)
	log.Infof("End indexing keystones at hash %v height %v", endBH, endBH.Height)
	endHash := endBH.BlockHash()
	for {
		start := time.Now()
		blocksProcessed, last, err := s.indexKeystonesInBlocks(ctx, endHash, kss)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		if blocksProcessed == 0 {
			return nil
		}
		kssCached := len(kss)
		log.Infof("Keystone indexer blocks processed %v in %v keystones cached %v cache unused %v avg keystones/blk %v",
			blocksProcessed, time.Since(start), kssCached,
			s.cfg.MaxCachedKeystones-kssCached, kssCached/blocksProcessed)

		// Flush to disk
		start = time.Now()
		if err = s.db.BlockKeystoneUpdate(ctx, 1, kss, &last.Hash); err != nil {
			return fmt.Errorf("block hemi update: %w", err)
		}
		// leveldb does all kinds of allocations, force GC to lower
		// memory pressure.
		logMemStats()
		runtime.GC()

		log.Infof("Flushing keystones complete %v took %v",
			kssCached, time.Since(start))

		if endHash.IsEqual(&last.Hash) {
			break
		}

	}

	return nil
}

func (s *Server) KeystoneIndexer(ctx context.Context, endHash *chainhash.Hash) error {
	log.Tracef("KeystoneIndexer")
	defer log.Tracef("KeystoneIndexer exit")

	// XXX this is basically duplicate from KeystoneIndexIsLinear

	if !s.cfg.HemiIndex {
		return errors.New("disabled")
	}
	s.mtx.Lock()
	if !s.indexing {
		// XXX this prob should be an error but pusnish bad callers for now
		s.mtx.Unlock()
		panic("KeystoneIndexer not true")
	}
	s.mtx.Unlock()

	// Verify exit condition hash
	if endHash == nil {
		return errors.New("must provide an end hash")
	}
	endBH, err := s.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return fmt.Errorf("blockheader end hash: %w", err)
	}

	// Verify start point is not after the end point
	keystoneHH, err := s.KeystoneIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("keystone index hash: %w", err)
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := s.db.BlockHeaderByHash(ctx, &keystoneHH.Hash)
	if err != nil {
		return fmt.Errorf("blockheader keystone hash: %w", err)
	}
	direction, err := s.KeystoneIndexIsLinear(ctx, endHash)
	if err != nil {
		return fmt.Errorf("keystone index is linear: %w", err)
	}
	switch direction {
	case 1:
		return s.KeystoneIndexerWind(ctx, startBH, endBH)
	case -1:
		return s.KeystoneIndexerUnwind(ctx, startBH, endBH)
	case 0:
		// Because we call KeystoneIndexIsLinear we know it's the same block.
		return nil
	}

	return fmt.Errorf("invalid direction: %v", direction)
}

func (s *Server) UtxoIndexIsLinear(ctx context.Context, endHash *chainhash.Hash) (int, error) {
	log.Tracef("UtxoIndexIsLinear")
	defer log.Tracef("UtxoIndexIsLinear exit")

	// Verify start point is not after the end point
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		return 0, fmt.Errorf("utxo index hash: %w", err)
	}

	return s.IndexIsLinear(ctx, &utxoHH.Hash, endHash)
}

func (s *Server) TxIndexIsLinear(ctx context.Context, endHash *chainhash.Hash) (int, error) {
	log.Tracef("TxIndexIsLinear")
	defer log.Tracef("TxIndexIsLinear exit")

	// Verify start point is not after the end point
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx index hash: %w", err)
	}

	return s.IndexIsLinear(ctx, &txHH.Hash, endHash)
}

func (s *Server) KeystoneIndexIsLinear(ctx context.Context, endHash *chainhash.Hash) (int, error) {
	log.Tracef("KeystoneIndexIsLinear")
	defer log.Tracef("KeystoneIndexIsLinear exit")

	// Verify start point is not after the end point
	keystoneHH, err := s.KeystoneIndexHash(ctx)
	if err != nil {
		return 0, fmt.Errorf("keystone index hash: %w", err)
	}

	return s.IndexIsLinear(ctx, &keystoneHH.Hash, endHash)
}

func (s *Server) IndexIsLinear(ctx context.Context, startHash, endHash *chainhash.Hash) (int, error) {
	log.Tracef("IndexIsLinear")
	defer log.Tracef("IndexIsLinear exit")

	// Verify exit condition hash
	if startHash == nil || endHash == nil {
		return 0, errors.New("must provide start and end hash")
	}
	endBH, err := s.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return 0, fmt.Errorf("blockheader hash: %w", err)
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := s.db.BlockHeaderByHash(ctx, startHash)
	if err != nil {
		return 0, fmt.Errorf("blockheader hash: %w", err)
	}
	// Short circuit if the block hash is the same.
	if startBH.BlockHash().IsEqual(endBH.BlockHash()) {
		return 0, nil
	}

	direction := endBH.Difficulty.Cmp(&startBH.Difficulty)
	log.Debugf("startBH %v %v", startBH.Height, startBH)
	log.Debugf("endBH %v %v", endBH.Height, endBH)
	log.Debugf("direction %v", direction)
	// Expensive linear test, this needs some performance love. We can
	// memoize it keep snapshot heights whereto we know the chain is
	// synced. For now just do the entire thing.

	// Always walk backwards because it's only a single lookup.
	var h, e *chainhash.Hash
	switch direction {
	case 1:
		h = endBH.BlockHash()
		e = startBH.BlockHash()
	case -1:
		h = startBH.BlockHash()
		e = endBH.BlockHash()
	default:
		// This is a fork and thus not linear.
		// XXX remove this once we determine if ErrNotLinear can happen here.
		log.Infof("startBH %v %v", startBH, startBH.Difficulty)
		log.Infof("endBH %v %v", endBH, endBH.Difficulty)
		log.Infof("direction %v", direction)
		return 0, NotLinearError(fmt.Sprintf("start %v end %v direction %v",
			startBH, endBH, direction))
	}
	for {
		bh, err := s.db.BlockHeaderByHash(ctx, h)
		if err != nil {
			return -1, fmt.Errorf("block header by hash: %w", err)
		}
		h = bh.ParentHash()
		if h.IsEqual(e) {
			return direction, nil
		}
		if h.IsEqual(s.chainParams.GenesisHash) {
			return 0, NotLinearError(fmt.Sprintf("start %v end %v "+
				"direction %v: genesis", startBH, endBH, direction))
		}
	}
}

// SyncIndexersToHash tries to move the various indexers to the supplied
// hash (inclusive).
// Note: on unwind it means that it WILL unwind the various indexers including
// the hash that was passed in. E.g. if this unwinds from 1001 to 1000 the
// indexes for block 1000 WILL be updated as well.
func (s *Server) SyncIndexersToHash(ctx context.Context, hash *chainhash.Hash) error {
	log.Tracef("SyncIndexersToHash")
	defer log.Tracef("SyncIndexersToHash exit")

	s.mtx.Lock()
	if s.indexing {
		s.mtx.Unlock()
		return ErrAlreadyIndexing
	}
	s.indexing = true
	s.mtx.Unlock()

	defer func() {
		// Mark indexing done.
		s.mtx.Lock()
		s.indexing = false
		s.mtx.Unlock()

		// Get block headers
		s.pm.All(ctx, s.headersPeer)
	}()

	log.Debugf("Syncing indexes to: %v", hash)

	// UTXOs
	if err := s.UtxoIndexer(ctx, hash); err != nil {
		return fmt.Errorf("utxo indexer: %w", err)
	}

	// Transactions index
	if err := s.TxIndexer(ctx, hash); err != nil {
		return fmt.Errorf("tx indexer: %w", err)
	}

	// Hemi indexes
	if s.cfg.HemiIndex {
		if err := s.KeystoneIndexer(ctx, hash); err != nil {
			return fmt.Errorf("keystone indexer: %w", err)
		}
	}

	log.Debugf("Done syncing to: %v", hash)

	bh, err := s.db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		log.Errorf("block header by hash: %v", err)
	} else {
		log.Infof("Syncing complete at: %v", bh.HH())
	}

	return nil
}

func (s *Server) utxoIndexersToBest(ctx context.Context, bhb *tbcd.BlockHeader) error {
	log.Tracef("utxoIndexersToBest")
	defer log.Tracef("utxoIndexersToBest exit")

	// Index Utxos to best
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("utxo index hash: %w", err)
	}
	utxoBH, err := s.db.BlockHeaderByHash(ctx, &utxoHH.Hash)
	if err != nil {
		return err
	}
	cp, err := s.findCanonicalParent(ctx, utxoBH)
	if err != nil {
		return err
	}
	if !cp.Hash.IsEqual(&utxoBH.Hash) {
		log.Infof("Syncing utxo index to: %v from: %v via: %v",
			bhb.HH(), utxoBH.HH(), cp.HH())
		// utxoBH is NOT on canonical chain, unwind first
		if err := s.UtxoIndexer(ctx, &cp.Hash); err != nil {
			return fmt.Errorf("utxo indexer unwind: %w", err)
		}
	}
	// Index utxo to best block
	if err := s.UtxoIndexer(ctx, &bhb.Hash); err != nil {
		return fmt.Errorf("utxo indexer: %w", err)
	}

	return nil
}

func (s *Server) txIndexersToBest(ctx context.Context, bhb *tbcd.BlockHeader) error {
	log.Tracef("txIndexersToBest")
	defer log.Tracef("txIndexersToBest exit")

	// Index Tx
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("tx index hash: %w", err)
	}
	txBH, err := s.db.BlockHeaderByHash(ctx, &txHH.Hash)
	if err != nil {
		return err
	}
	cp, err := s.findCanonicalParent(ctx, txBH)
	if err != nil {
		return err
	}
	if !cp.Hash.IsEqual(&txBH.Hash) {
		log.Infof("Syncing tx index to: %v from: %v via: %v",
			bhb.HH(), txBH.HH(), cp.HH())
		// txBH is NOT on canonical chain, unwind first
		if err := s.TxIndexer(ctx, &cp.Hash); err != nil {
			return fmt.Errorf("tx indexer unwind: %w", err)
		}
	}
	// Transactions index
	if err := s.TxIndexer(ctx, &bhb.Hash); err != nil {
		return fmt.Errorf("tx indexer: %w", err)
	}

	return nil
}

func (s *Server) keystoneIndexersToBest(ctx context.Context, bhb *tbcd.BlockHeader) error {
	log.Tracef("keystoneIndexersToBest")
	defer log.Tracef("keystoneIndexersToBest exit")

	// Index keystones to best
	keystoneHH, err := s.KeystoneIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("keystone index hash: %w", err)
	}
	keystoneBH, err := s.db.BlockHeaderByHash(ctx, &keystoneHH.Hash)
	if err != nil {
		return err
	}
	cp, err := s.findCanonicalParent(ctx, keystoneBH)
	if err != nil {
		return err
	}
	if !cp.Hash.IsEqual(&keystoneBH.Hash) {
		log.Infof("Syncing keystone index to: %v from: %v via: %v",
			bhb.HH(), keystoneBH.HH(), cp.HH())
		// keystoneBH is NOT on canonical chain, unwind first
		if err := s.KeystoneIndexer(ctx, &cp.Hash); err != nil {
			return fmt.Errorf("keystone indexer unwind: %w", err)
		}
	}
	// Index keystones to best block
	if err := s.KeystoneIndexer(ctx, &bhb.Hash); err != nil {
		return fmt.Errorf("keystone indexer: %w", err)
	}

	return nil
}

func (s *Server) syncIndexersToBest(ctx context.Context) error {
	log.Tracef("syncIndexersToBest")
	defer log.Tracef("syncIndexersToBest exit")

	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return err
	}

	log.Debugf("Sync indexers to best: %v @ %v", bhb, bhb.Height)

	if err := s.utxoIndexersToBest(ctx, bhb); err != nil {
		return err
	}

	if err := s.txIndexersToBest(ctx, bhb); err != nil {
		return err
	}

	if s.cfg.HemiIndex {
		if err := s.keystoneIndexersToBest(ctx, bhb); err != nil {
			return err
		}
	}

	// Print nice message to indicate completion.
	bh, err := s.db.BlockHeaderByHash(ctx, &bhb.Hash)
	if err != nil {
		log.Errorf("block header by hash: %v", err)
	} else {
		log.Debugf("Syncing complete at: %v", bh.HH())
	}

	return nil
}

func (s *Server) SyncIndexersToBest(ctx context.Context) error {
	t := time.Now()
	log.Tracef("SyncIndexersToBest")
	defer func() {
		log.Tracef("SyncIndexersToBest exit %v", time.Since(t))
	}()

	s.mtx.Lock()
	if s.indexing {
		s.mtx.Unlock()
		return ErrAlreadyIndexing
	}
	s.indexing = true
	s.mtx.Unlock()

	defer func() {
		s.mtx.Lock()
		s.indexing = false
		s.mtx.Unlock()
	}()

	// NOTE: the way this code works today is that it will ALWAYS reindex
	// the last block it already indexed. This is wasteful for resources
	// but so far does no harm. The reason this happens is because
	// the code to skip the last block is super awkward and potentially
	// brittle. It would require special handling for genesis or skip the
	// first block that's passed in. This needs to be revisited but reader
	// beware of this reality.
	return s.syncIndexersToBest(ctx)
}
