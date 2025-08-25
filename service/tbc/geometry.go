// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

func s2h(s string) *chainhash.Hash {
	h, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return h
}

var (
	// checkpoints MUST be sorted high to low!
	testnet3Checkpoints = []chaincfg.Checkpoint{
		{Height: 4000000, Hash: s2h("000000000000033947a6a47cecc029f944f3879da242dec26647360b2764adae")},
		{Height: 3900000, Hash: s2h("000000000b21ae775d87e6611b260e69c34f82b04dd95eb25fd946a512691358")},
		{Height: 3800000, Hash: s2h("00000000000000fa9c23f20506e6c57b6dda928fb2110629bf5d29df2f737ad2")},
		{Height: 3700000, Hash: s2h("0000000000c3410afe8a2bfef56757c8ba675eaa4bb786a2a02d4fc1124bedf2")},
		{Height: 3600000, Hash: s2h("0000000000002b9408d001dd42f830e16a9c28ed8daa828523e67e09ea9e0411")},
		{Height: 3500000, Hash: s2h("0000000000001b1bbe551b905c6826f428d88cb93e3349763e13c2441dba306f")},
		{Height: 3400000, Hash: s2h("000000000000ca2cd17231127ccd84e79510b64ca15e01ec4780923c13127ed1")},
		{Height: 3300000, Hash: s2h("000000000000c6086a41b512e03f15f0b54a49afdb4c3b69e8bbc4d0a257b84e")},
		{Height: 3200000, Hash: s2h("000000000000098faa89ab34c3ec0e6e037698e3e54c8d1bbb9dcfe0054a8e7a")},
		{Height: 3100000, Hash: s2h("0000000000001242d96bedebc9f45a2ecdd40d393ca0d725f500fb4977a50582")},
		{Height: 3000000, Hash: s2h("0000000000003c46fc60e56b9c2ae202b1efec83fcc7899d21de16757dea40a4")},
		{Height: 2900000, Hash: s2h("000000000000001669469c0354b3f341a36b10ab099d1962f7ec4fae528b1f1d")},
		{Height: 2800000, Hash: s2h("00000000000004ba1b39acdc644006ac1d6f6a3cd8d6b3d9e016c5bc87e1d4d4")},
		{Height: 2700000, Hash: s2h("0000000000002b57380c21d36237d0017325c872f4c77434293bb8112725e734")},
		{Height: 2600000, Hash: s2h("00000000000e8d171d334767249450f91ee48d5f8dd2d938062fda252503e183")},
		{Height: 2500000, Hash: s2h("0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f")},
		{Height: 2400000, Hash: s2h("000000000000075566fba6ca27a2e4c8b33c7763f8a5f917b231b0d88c743af8")},
		{Height: 2300000, Hash: s2h("000000000006dd1f9691995684ba15c0d4a4779360ff2fbe4224a1ce4b51c77f")},
		{Height: 2200000, Hash: s2h("0000000011bde1564966cf4557cad5e2e45197fc4bd868d3246db2191f57b1e1")},
		{Height: 2100000, Hash: s2h("000000000000002befeeec5aaa3b675ef421896c870e28669f00b0932e277eef")},
		{Height: 2000000, Hash: s2h("000000000000010dd0863ec3d7a0bae17c1957ae1de9cbcdae8e77aad33e3b8c")},
		{Height: 1900000, Hash: s2h("000000000000000eda80f8c7e55459e348274292ecd77c662f95e29bedbb4865")},
		{Height: 1800000, Hash: s2h("00000000000099aaf4c4ffe1ea8a51303c8a0a4be8a1226e12b151e503718462")},
		{Height: 1700000, Hash: s2h("000000000000fdd6e3e379abdfda6e82b47b51eb154f193ce3f066877f37b0af")},
		{Height: 1600000, Hash: s2h("00000000000172ff8a4e14441512072bacaf8d38b995a3fcd2f8435efc61717d")},
		{Height: 1500000, Hash: s2h("0000000000049a6b07f91975568dc96bb1aec1a24c6bdadb21eb17c9f1b7256f")},
		{Height: 1400000, Hash: s2h("000000000000fce208da3e3b8afcc369835926caa44044e9c2f0caa48c8eba0f")},
		{Height: 1300000, Hash: s2h("000000007ec390190c60b5010a8ea14f5ce53e35be684eacc36486fec3b34744")},
		{Height: 1200000, Hash: s2h("00000000000025c23a19cc91ad8d3e33c2630ce1df594e1ae0bf0eabe30a9176")},
		{Height: 1100000, Hash: s2h("00000000001c2fb9880485b1f3d7b0ffa9fabdfd0cf16e29b122bb6275c73db0")},
		{Height: 1000000, Hash: s2h("0000000000478e259a3eda2fafbeeb0106626f946347955e99278fe6cc848414")},
		{Height: 900000, Hash: s2h("0000000000356f8d8924556e765b7a94aaebc6b5c8685dcfa2b1ee8b41acd89b")},
		{Height: 800000, Hash: s2h("0000000000209b091d6519187be7c2ee205293f25f9f503f90027e25abf8b503")},
		{Height: 700000, Hash: s2h("000000000000406178b12a4dea3b27e13b3c4fe4510994fd667d7c1e6a3f4dc1")},
		{Height: 600000, Hash: s2h("000000000000624f06c69d3a9fe8d25e0a9030569128d63ad1b704bbb3059a16")},
		{Height: 500000, Hash: s2h("000000000001a7c0aaa2630fbb2c0e476aafffc60f82177375b2aaa22209f606")},
		{Height: 400000, Hash: s2h("000000000598cbbb1e79057b79eef828c495d4fc31050e6b179c57d07d00367c")},
		{Height: 300000, Hash: s2h("000000000000226f7618566e70a2b5e020e29579b46743f05348427239bf41a1")},
		{Height: 200000, Hash: s2h("0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2")},
		{Height: 100000, Hash: s2h("00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e")},
		{Height: 0, Hash: s2h("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")},
	}

	testnet4Checkpoints = []chaincfg.Checkpoint{
		{Height: 80000, Hash: s2h("0000000006af13c1117f3e2eb14f10eb9736e255713118cf7eb6659b1448efc1")},
		{Height: 0, Hash: s2h("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")},
	}

	mainnetCheckpoints = []chaincfg.Checkpoint{
		{Height: 850000, Hash: s2h("00000000000000000002a0b5db2a7f8d9087464c2586b546be7bce8eb53b8187")},
		{Height: 800000, Hash: s2h("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054")},
		{Height: 750000, Hash: s2h("0000000000000000000592a974b1b9f087cb77628bb4a097d5c2c11b3476a58e")},
		{Height: 700000, Hash: s2h("0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959")},
		{Height: 650000, Hash: s2h("0000000000000000000060e32d547b6ae2ded52aadbc6310808e4ae42b08cc6a")},
		{Height: 600000, Hash: s2h("00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91")},
		{Height: 550000, Hash: s2h("000000000000000000223b7a2298fb1c6c75fb0efc28a4c56853ff4112ec6bc9")},
		{Height: 500000, Hash: s2h("00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04")},
		{Height: 450000, Hash: s2h("0000000000000000014083723ed311a461c648068af8cef8a19dcd620c07a20b")},
		{Height: 400000, Hash: s2h("000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f")},
		{Height: 350000, Hash: s2h("0000000000000000053cf64f0400bb38e0c4b3872c38795ddde27acb40a112bb")},
		{Height: 300000, Hash: s2h("000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254")},
		{Height: 250000, Hash: s2h("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
		{Height: 200000, Hash: s2h("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf")},
		{Height: 150000, Hash: s2h("0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b")},
		{Height: 100000, Hash: s2h("000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506")},
		{Height: 50000, Hash: s2h("000000001aeae195809d120b5d66a39c83eb48792e068f8ea1fea19d84a4278a")},
		{Height: 0, Hash: s2h("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")},
	}

	localnetCheckpoints = []chaincfg.Checkpoint{
		{Height: 0, Hash: s2h("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
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

func nextCheckpoint(bh *tbcd.BlockHeader, hha []chaincfg.Checkpoint) *chaincfg.Checkpoint {
	if len(hha) == 0 {
		return nil
	}
	for i := len(hha) - 1; i >= 0; i-- {
		if uint64(hha[i].Height) >= bh.Height {
			return &hha[i]
		}
	}
	return nil
}

func previousCheckpoint(bh *tbcd.BlockHeader, hha []chaincfg.Checkpoint) *chaincfg.Checkpoint {
	for k := range hha {
		if uint64(hha[k].Height) > bh.Height {
			continue
		}
		return &hha[k]
	}
	return nil
}

func previousCheckpointHeight(height uint64, hha []chaincfg.Checkpoint) uint64 {
	hh := previousCheckpoint(&tbcd.BlockHeader{Height: height}, hha)
	if hh == nil {
		return 0
	}
	return uint64(hh.Height)
}

// indexIsLinear determines if the blockchain is linear without gaps between
// the two provided blockheaders. It will move forward or backward depending on
// blockheader height.
func indexIsLinear(ctx context.Context, g geometryParams, startHash, endHash chainhash.Hash) (int, error) {
	log.Tracef("indexIsLinear")
	defer log.Tracef("indexIsLinear exit")

	// Verify exit condition hash
	endBH, err := g.db.BlockHeaderByHash(ctx, endHash)
	if err != nil {
		return 0, fmt.Errorf("blockheader hash: %w", err)
	}

	// Make sure there is no gap between start and end or vice versa.
	startBH, err := g.db.BlockHeaderByHash(ctx, startHash)
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
		return 0, NotLinearError(fmt.Sprintf("start %v end %v direction %v",
			startBH, endBH, direction))
	}
	for {
		bh, err := g.db.BlockHeaderByHash(ctx, *h)
		if err != nil {
			return -1, fmt.Errorf("block header by hash: %w", err)
		}
		h = bh.ParentHash()
		if h.IsEqual(e) {
			return direction, nil
		}
		if h.IsEqual(g.chain.GenesisHash) {
			return 0, NotLinearError(fmt.Sprintf("start %v end %v "+
				"direction %v: genesis", startBH, endBH, direction))
		}
	}
}

// findCanonicalParent walks the chain back and finds the canonical parent of
// the provided block header.
func findCanonicalParent(ctx context.Context, g geometryParams, bh *tbcd.BlockHeader) (*tbcd.BlockHeader, error) {
	log.Tracef("findCanonicalParent %v", bh)

	// Genesis is always canonical.
	if bh.Hash.IsEqual(g.chain.GenesisHash) {
		return bh, nil
	}

	bhb, err := g.db.BlockHeaderBest(ctx)
	if err != nil {
		return nil, err
	}
	log.Debugf("findCanonicalParent %v @ %v best %v @ %v",
		bh, bh.Height, bhb, bhb.Height)
	for {
		canonical, err := isCanonical(ctx, g, bh)
		if err != nil {
			return nil, err
		}
		if canonical {
			log.Tracef("findCanonicalParent exit %v", bh)
			return bh, nil
		}
		bh, err = findCommonParent(ctx, g, bhb, bh)
		if err != nil {
			return nil, err
		}
	}
}

// isCanonical uses checkpoints to determine if a block is on the canonical
// chain. This is a expensive call hence it tries to use checkpoints to short
// circuit the check.
func isCanonical(ctx context.Context, g geometryParams, bh *tbcd.BlockHeader) (bool, error) {
	var (
		bhb *tbcd.BlockHeader
		err error
	)
	ncp := nextCheckpoint(bh, g.chain.Checkpoints)
	if ncp == nil {
		// Use best since we do not have a best checkpoint
		bhb, err = g.db.BlockHeaderBest(ctx)
	} else {
		bhb, err = g.db.BlockHeaderByHash(ctx, *ncp.Hash)
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

	genesisHash := previousCheckpoint(bh, g.chain.Checkpoints).Hash // either genesis or a snapshot block

	// Move best block header backwards until we find bh.
	log.Debugf("isCanonical best %v bh %v genesis %v", bhb.HH(), bh.HH(), genesisHash)
	for {
		if bhb.Height <= bh.Height {
			return false, nil
		}
		bhb, err = g.db.BlockHeaderByHash(ctx, *bhb.ParentHash())
		if err != nil {
			return false, err
		}
		if bhb.Hash.IsEqual(genesisHash) {
			return false, nil
		}
		if bhb.Hash.IsEqual(&bh.Hash) {
			return true, nil
		}
	}
}

// findCommonParent find the common parrent between the two provided
// blockheaders. It will return an error if it walks all the way back to
// genesis.
func findCommonParent(ctx context.Context, g geometryParams, bhX, bhY *tbcd.BlockHeader) (*tbcd.BlockHeader, error) {
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
		bhs, err := g.db.BlockHeadersByHeight(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("block headers by height: %w", err)
		}
		if bhs[0].Hash.IsEqual(g.chain.GenesisHash) {
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
			return g.db.BlockHeaderByHash(ctx, *ph)
		}

		// Decrease height
		h--
	}
}

// nextCanonicalBlockheader walks the chain forward and looks for the next
// canonical blockheader or returns a failure if it cannot find one.
func nextCanonicalBlockheader(ctx context.Context, g geometryParams, endHash *chainhash.Hash, hh *HashHeight) (*HashHeight, error) {
	// Move to next block
	height := hh.Height + 1
	bhs, err := g.db.BlockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("block headers by height %v: %w",
			height, err)
	}
	index, err := findPathFromHash(ctx, g, endHash, bhs)
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

// findPathFromHash determines which hash is in the path by walking back the
// chain from the provided end point. It returns the index in bhs of the
// correct hash. On failure it returns -1 DELIBERATELY to crash the caller if
// error is not checked.
func findPathFromHash(ctx context.Context, g geometryParams, endHash *chainhash.Hash, bhs []tbcd.BlockHeader) (int, error) {
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
		bh, err := g.db.BlockHeaderByHash(ctx, *h)
		if err != nil {
			return -1, fmt.Errorf("block header by hash: %w", err)
		}
		for k, v := range bhs {
			if h.IsEqual(v.BlockHash()) {
				return k, nil
			}
		}
		if h.IsEqual(g.chain.GenesisHash) {
			break
		}
		h = bh.ParentHash()
	}
	return -1, errors.New("path not found")
}
