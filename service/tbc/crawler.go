// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
)

func s2h(s string) chainhash.Hash {
	h, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return *h
}

type checkpoint struct {
	height uint64
	hash   chainhash.Hash
}

var (
	ErrAlreadyIndexing = errors.New("already indexing")

	// checkpoints MUST be sorted high to low!
	testnet3Checkpoints = []checkpoint{
		{4000000, s2h("000000000000033947a6a47cecc029f944f3879da242dec26647360b2764adae")},
		{3900000, s2h("000000000b21ae775d87e6611b260e69c34f82b04dd95eb25fd946a512691358")},
		{3800000, s2h("00000000000000fa9c23f20506e6c57b6dda928fb2110629bf5d29df2f737ad2")},
		{3700000, s2h("0000000000c3410afe8a2bfef56757c8ba675eaa4bb786a2a02d4fc1124bedf2")},
		{3600000, s2h("0000000000002b9408d001dd42f830e16a9c28ed8daa828523e67e09ea9e0411")},
		{3500000, s2h("0000000000001b1bbe551b905c6826f428d88cb93e3349763e13c2441dba306f")},
		{3400000, s2h("000000000000ca2cd17231127ccd84e79510b64ca15e01ec4780923c13127ed1")},
		{3300000, s2h("000000000000c6086a41b512e03f15f0b54a49afdb4c3b69e8bbc4d0a257b84e")},
		{3200000, s2h("000000000000098faa89ab34c3ec0e6e037698e3e54c8d1bbb9dcfe0054a8e7a")},
		{3100000, s2h("0000000000001242d96bedebc9f45a2ecdd40d393ca0d725f500fb4977a50582")},
		{3000000, s2h("0000000000003c46fc60e56b9c2ae202b1efec83fcc7899d21de16757dea40a4")},
		{2900000, s2h("000000000000001669469c0354b3f341a36b10ab099d1962f7ec4fae528b1f1d")},
		{2800000, s2h("00000000000004ba1b39acdc644006ac1d6f6a3cd8d6b3d9e016c5bc87e1d4d4")},
		{2700000, s2h("0000000000002b57380c21d36237d0017325c872f4c77434293bb8112725e734")},
		{2600000, s2h("00000000000e8d171d334767249450f91ee48d5f8dd2d938062fda252503e183")},
		{2500000, s2h("0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f")},
		{2400000, s2h("000000000000075566fba6ca27a2e4c8b33c7763f8a5f917b231b0d88c743af8")},
		{2300000, s2h("000000000006dd1f9691995684ba15c0d4a4779360ff2fbe4224a1ce4b51c77f")},
		{2200000, s2h("0000000011bde1564966cf4557cad5e2e45197fc4bd868d3246db2191f57b1e1")},
		{2100000, s2h("000000000000002befeeec5aaa3b675ef421896c870e28669f00b0932e277eef")},
		{2000000, s2h("000000000000010dd0863ec3d7a0bae17c1957ae1de9cbcdae8e77aad33e3b8c")},
		{1900000, s2h("000000000000000eda80f8c7e55459e348274292ecd77c662f95e29bedbb4865")},
		{1800000, s2h("00000000000099aaf4c4ffe1ea8a51303c8a0a4be8a1226e12b151e503718462")},
		{1700000, s2h("000000000000fdd6e3e379abdfda6e82b47b51eb154f193ce3f066877f37b0af")},
		{1600000, s2h("00000000000172ff8a4e14441512072bacaf8d38b995a3fcd2f8435efc61717d")},
		{1500000, s2h("0000000000049a6b07f91975568dc96bb1aec1a24c6bdadb21eb17c9f1b7256f")},
		{1400000, s2h("000000000000fce208da3e3b8afcc369835926caa44044e9c2f0caa48c8eba0f")},
		{1300000, s2h("000000007ec390190c60b5010a8ea14f5ce53e35be684eacc36486fec3b34744")},
		{1200000, s2h("00000000000025c23a19cc91ad8d3e33c2630ce1df594e1ae0bf0eabe30a9176")},
		{1100000, s2h("00000000001c2fb9880485b1f3d7b0ffa9fabdfd0cf16e29b122bb6275c73db0")},
		{1000000, s2h("0000000000478e259a3eda2fafbeeb0106626f946347955e99278fe6cc848414")},
		{900000, s2h("0000000000356f8d8924556e765b7a94aaebc6b5c8685dcfa2b1ee8b41acd89b")},
		{800000, s2h("0000000000209b091d6519187be7c2ee205293f25f9f503f90027e25abf8b503")},
		{700000, s2h("000000000000406178b12a4dea3b27e13b3c4fe4510994fd667d7c1e6a3f4dc1")},
		{600000, s2h("000000000000624f06c69d3a9fe8d25e0a9030569128d63ad1b704bbb3059a16")},
		{500000, s2h("000000000001a7c0aaa2630fbb2c0e476aafffc60f82177375b2aaa22209f606")},
		{400000, s2h("000000000598cbbb1e79057b79eef828c495d4fc31050e6b179c57d07d00367c")},
		{300000, s2h("000000000000226f7618566e70a2b5e020e29579b46743f05348427239bf41a1")},
		{200000, s2h("0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2")},
		{100000, s2h("00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e")},
		{0, s2h("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")},
	}

	testnet4Checkpoints = []checkpoint{
		{80000, s2h("0000000006af13c1117f3e2eb14f10eb9736e255713118cf7eb6659b1448efc1")},
		{0, s2h("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")},
	}

	mainnetCheckpoints = []checkpoint{
		{850000, s2h("00000000000000000002a0b5db2a7f8d9087464c2586b546be7bce8eb53b8187")},
		{800000, s2h("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054")},
		{750000, s2h("0000000000000000000592a974b1b9f087cb77628bb4a097d5c2c11b3476a58e")},
		{700000, s2h("0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959")},
		{650000, s2h("0000000000000000000060e32d547b6ae2ded52aadbc6310808e4ae42b08cc6a")},
		{600000, s2h("00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91")},
		{550000, s2h("000000000000000000223b7a2298fb1c6c75fb0efc28a4c56853ff4112ec6bc9")},
		{500000, s2h("00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04")},
		{450000, s2h("0000000000000000014083723ed311a461c648068af8cef8a19dcd620c07a20b")},
		{400000, s2h("000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f")},
		{350000, s2h("0000000000000000053cf64f0400bb38e0c4b3872c38795ddde27acb40a112bb")},
		{300000, s2h("000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254")},
		{250000, s2h("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
		{200000, s2h("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf")},
		{150000, s2h("0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b")},
		{100000, s2h("000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506")},
		{50000, s2h("000000001aeae195809d120b5d66a39c83eb48792e068f8ea1fea19d84a4278a")},
		{0, s2h("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")},
	}

	localnetCheckpoints = []checkpoint{
		{0, s2h("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
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

func nextCheckpoint(bh *tbcd.BlockHeader, hha []checkpoint) *checkpoint {
	if len(hha) == 0 {
		return nil
	}
	for i := len(hha) - 1; i >= 0; i-- {
		if hha[i].height >= bh.Height {
			return &hha[i]
		}
	}
	return nil
}

func previousCheckpoint(bh *tbcd.BlockHeader, hha []checkpoint) *checkpoint {
	for k := range hha {
		if hha[k].height > bh.Height {
			continue
		}
		return &hha[k]
	}
	return nil
}

func previousCheckpointHeight(height uint64, hha []checkpoint) uint64 {
	hh := previousCheckpoint(&tbcd.BlockHeader{Height: height}, hha)
	if hh == nil {
		return 0
	}
	return hh.height
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
	Hash      chainhash.Hash `json:"hash"`
	Height    uint64         `json:"height"`
	Timestamp int64          `json:"timestamp"` // optional
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

// BlockKeystonesByHash returns all keystones within a block. If hash is not
// nil then it returns *only* the keystone transactions where the L2
// abbreviated hash is equal to the provided hash.
func BlockKeystonesByHash(block *btcutil.Block, hash *chainhash.Hash) []tbcapi.KeystoneTx {
	blockHash := block.Hash()
	height := uint(block.Height())
	ktxs := make([]tbcapi.KeystoneTx, 0, 16)
	for txIndex, tx := range block.Transactions() {
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

		for _, txOut := range tx.MsgTx().TxOut {
			tl2, err := pop.ParseTransactionL2FromOpReturn(txOut.PkScript)
			if err != nil {
				continue
			}

			// Filter non matching keystones.
			if hash != nil && !hash.IsEqual(tl2.L2Keystone.Hash()) {
				continue
			}

			// XXX it is a travesty that we have to reserialize
			// this tx. We should add a change to btcutil.Tx to
			// return the internal rawBytes.
			var rawTx bytes.Buffer
			if err := tx.MsgTx().Serialize(&rawTx); err != nil {
				// We should always be able to serialize.
				panic(fmt.Sprintf("serialize tx: %s", err))
			}
			ktxs = append(ktxs, tbcapi.KeystoneTx{
				BlockHash:   *blockHash,
				TxIndex:     uint(txIndex),
				BlockHeight: height,
				RawTx:       rawTx.Bytes(),
			})
		}
	}

	return ktxs
}

func BlockKeystones(block *btcutil.Block) []tbcapi.KeystoneTx {
	return BlockKeystonesByHash(block, nil)
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
			return s.db.BlockHeaderByHash(ctx, *ph)
		}

		// Decrease height
		h--
	}
}

// isCanonical uses checkpoints to determine if a block is on the canonical
// chain. This is a expensive call hence it tries to use checkpoints to short
// circuit the check.
func (s *Server) isCanonical(ctx context.Context, bh *tbcd.BlockHeader) (bool, error) {
	var (
		bhb *tbcd.BlockHeader
		err error
	)
	ncp := nextCheckpoint(bh, s.checkpoints)
	if ncp == nil {
		// Use best since we do not have a best checkpoint
		bhb, err = s.db.BlockHeaderBest(ctx)
	} else {
		bhb, err = s.db.BlockHeaderByHash(ctx, ncp.hash)
	}
	if err != nil {
		return false, err
	}

	// Basic shortcircuit
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

	genesisHash := previousCheckpoint(bh, s.checkpoints).hash // either genesis or a snapshot block

	// Move best block header backwards until we find bh.
	log.Debugf("isCanonical best %v bh %v genesis %v", bhb.HH(), bh.HH(), genesisHash)
	for {
		if bhb.Height <= bh.Height {
			return false, nil
		}
		bhb, err = s.db.BlockHeaderByHash(ctx, *bhb.ParentHash())
		if err != nil {
			return false, err
		}
		if bhb.Hash.IsEqual(&genesisHash) {
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
		bh, err := s.db.BlockHeaderByHash(ctx, *h)
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
func (s *Server) headerAndBlock(ctx context.Context, hash chainhash.Hash) (*tbcd.BlockHeader, *btcutil.Block, error) {
	bh, err := s.db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("block header %v: %w", hash, err)
	}
	b, err := s.db.BlockByHash(ctx, bh.Hash)
	if err != nil {
		return nil, nil, fmt.Errorf("block by hash %v: %w", bh, err)
	}
	b.SetHeight(int32(bh.Height))

	return bh, b, nil
}

func processUtxos(block *btcutil.Block, direction int, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	txs := block.Transactions()
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

func (s *Server) txOutFromOutPoint(ctx context.Context, op tbcd.Outpoint) (*wire.TxOut, error) {
	txId := op.TxIdHash()
	txIndex := op.TxIndex()

	// Find block hashes
	blockHash, err := s.db.BlockHashByTxId(ctx, *txId)
	if err != nil {
		return nil, fmt.Errorf("block by txid: %w", err)
	}
	b, err := s.db.BlockByHash(ctx, *blockHash)
	if err != nil {
		return nil, fmt.Errorf("block by hash: %w", err)
	}
	for _, tx := range b.Transactions() {
		if !tx.Hash().IsEqual(txId) {
			continue
		}
		txOuts := tx.MsgTx().TxOut
		if len(txOuts) < int(txIndex) {
			return nil, fmt.Errorf("tx index invalid: %v", op)
		}
		return txOuts[txIndex], nil
	}

	return nil, fmt.Errorf("tx id not found: %v", op)
}

func (s *Server) unprocessUtxos(ctx context.Context, block *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	txs := block.Transactions()
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
			prevTxOut, err := s.txOutFromOutPoint(ctx, op)
			if err != nil {
				return fmt.Errorf("script value: %w", err)
			}
			// XXX this should not happen. We are keeping it for
			// now to ensure it indeed does not happen. Remove in a
			// couple of years.
			if _, ok := utxos[op]; ok {
				return fmt.Errorf("impossible collision: %v", op)
			}
			utxos[op] = tbcd.NewCacheOutput(tbcd.NewScriptHashFromScript(prevTxOut.PkScript),
				uint64(prevTxOut.Value), txIn.PreviousOutPoint.Index)
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

func (s *Server) fetchOPParallel(ctx context.Context, c chan struct{}, w *sync.WaitGroup, op tbcd.Outpoint, utxos map[tbcd.Outpoint]tbcd.CacheOutput) {
	defer w.Done()
	if c != nil {
		defer func() {
			select {
			case <-ctx.Done():
			case c <- struct{}{}:
			}
		}()
	}

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
			go s.fetchOPParallel(ctx, nil, w, op, utxos)
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
	ops := make([]*tbcd.Outpoint, 0, 16384)
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

func (s *Server) fixupCacheChannel(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error {
	// prime slots
	slots := 128
	c := make(chan struct{}, slots)
	defer close(c)
	for i := 0; i < slots; i++ {
		select {
		case <-ctx.Done():
			return nil
		case c <- struct{}{}:
		default:
			return errors.New("shouldn't happen")
		}
	}

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

			// get slot or wait
			<-c

			// utxo not found, retrieve pkscript from database.
			w.Add(1)
			go s.fetchOPParallel(ctx, c, w, op, utxos)
		}
	}
	w.Wait()

	cl := len(c)
	if cl != slots {
		return fmt.Errorf("channel not empty: %v", cl)
	}

	return nil
}

func processTxs(block *btcutil.Block, direction int, txsCache map[tbcd.TxKey]*tbcd.TxValue) error {
	blockHash := block.Hash()
	txs := block.Transactions()
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

func processKeystones(block *btcutil.Block, direction int, kssCache map[chainhash.Hash]tbcd.Keystone) error {
	if block.Height() == btcutil.BlockHeightUnknown {
		panic("diagnostic: block height not set")
	}

	blockHash := *block.Hash()
	blockHeight := uint64(block.Height())
	txs := block.Transactions()
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
				BlockHash:           blockHash,
				BlockHeight:         uint32(blockHeight),
				AbbreviatedKeystone: abvKss,
			}
		}
	}
	return nil
}

// XXX TxIndexIsLinear do we really want this exported? remove
func (s *Server) TxIndexIsLinear(ctx context.Context, endHash chainhash.Hash) (int, error) {
	log.Tracef("TxIndexIsLinear")
	defer log.Tracef("TxIndexIsLinear exit")

	// Verify start point is not after the end point
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx index hash: %w", err)
	}

	return s.IndexIsLinear(ctx, txHH.Hash, endHash)
}

func (s *Server) IndexIsLinear(ctx context.Context, startHash, endHash chainhash.Hash) (int, error) {
	log.Tracef("IndexIsLinear")
	defer log.Tracef("IndexIsLinear exit")

	// Verify exit condition hash
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
		bh, err := s.db.BlockHeaderByHash(ctx, *h)
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
func (s *Server) SyncIndexersToHash(ctx context.Context, hash chainhash.Hash) error {
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

	// utxos
	if err := s.newUtxoIndexer().modeIndexer(ctx, hash); err != nil {
		return fmt.Errorf("utxo indexer: %w", err)
	}

	// Transactions index
	if err := s.newTxIndexer().modeIndexer(ctx, hash); err != nil {
		return fmt.Errorf("tx indexer: %w", err)
	}

	// Hemi indexes
	if s.cfg.HemiIndex {
		if err := s.newKeystoneIndexer().modeIndexer(ctx, hash); err != nil {
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

func (s *Server) syncIndexersToBest(ctx context.Context) error {
	log.Tracef("syncIndexersToBest")
	defer log.Tracef("syncIndexersToBest exit")

	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return err
	}

	log.Debugf("Sync indexers to best: %v @ %v", bhb, bhb.Height)

	if err := s.newUtxoIndexer().modeIndexersToBest(ctx, bhb); err != nil {
		return err
	}

	if err := s.newTxIndexer().modeIndexersToBest(ctx, bhb); err != nil {
		return err
	}

	if s.cfg.HemiIndex {
		if err := s.newKeystoneIndexer().modeIndexersToBest(ctx, bhb); err != nil {
			return err
		}
	}

	// Print nice message to indicate completion.
	bh, err := s.db.BlockHeaderByHash(ctx, bhb.Hash)
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
