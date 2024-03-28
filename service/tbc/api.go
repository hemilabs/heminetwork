package tbc

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcutil"

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

type TbcApi struct {
	db tbcd.Database
}

func NewApi(db tbcd.Database) *TbcApi {
	return &TbcApi{
		db: db,
	}
}

func (t *TbcApi) BtcBlockMetadataByHeight(ctx context.Context, height uint64) (*tbcapi.BtcBlockMetadata, error) {
	bh, err := t.db.BlockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, err
	}

	if len(bh) == 0 {
		return nil, fmt.Errorf("no block headers found for height %d", height)
	}

	b, err := t.db.BlockByHash(ctx, bh[0].Hash)
	if err != nil {
		return nil, err
	}

	block, err := btcutil.NewBlockFromBytes(b.Block)
	if err != nil {
		return nil, err
	}

	prevHash := block.MsgBlock().Header.PrevBlock[:]
	slices.Reverse(prevHash)

	merkleRoot := block.MsgBlock().Header.MerkleRoot[:]
	slices.Reverse(merkleRoot)

	return &tbcapi.BtcBlockMetadata{
		Height: uint32(bh[0].Height),
		NumTx:  uint32(len(block.Transactions())),
		Header: tbcapi.BtcHeader{
			Version:    uint32(block.MsgBlock().Header.Version),
			PrevHash:   hex.EncodeToString(prevHash),
			MerkleRoot: hex.EncodeToString(merkleRoot),
			Timestamp:  uint64(block.MsgBlock().Header.Timestamp.Unix()),
			Bits:       fmt.Sprintf("%x", block.MsgBlock().Header.Bits),
			Nonce:      block.MsgBlock().Header.Nonce,
		},
	}, nil
}
