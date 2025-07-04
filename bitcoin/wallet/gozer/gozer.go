// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package gozer provides an interface for accessing Bitcoin data.
//
// Gozer was originally worshiped as a god by the Hittites, Mesopotamians, and
// the Sumerians around 6000 BC. Gozer was genderless and could assume any form
// it wanted.
package gozer

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
)

// Gozer is an interface providing access to Bitcoin data.
type Gozer interface {
	FeeEstimates(ctx context.Context) ([]*tbcapi.FeeEstimate, error)
	UtxosByAddress(ctx context.Context, filterMempool bool, addr btcutil.Address, start, count uint) ([]*tbcapi.UTXO, error)
	BlocksByL2AbrevHashes(ctx context.Context, hashes []chainhash.Hash) *BlocksByL2AbrevHashesResponse
	KeystonesByHeight(ctx context.Context, height uint32, depth int) (*KeystonesByHeightResponse, error)
	BroadcastTx(ctx context.Context, tx *wire.MsgTx) (*chainhash.Hash, error)
	BtcHeight(ctx context.Context) (uint64, error)
}

// FeeByConfirmations picks a suitable fee by matching the exact number of
// blocks provided by the caller.
func FeeByConfirmations(blocks uint, feeEstimates []*tbcapi.FeeEstimate) (*tbcapi.FeeEstimate, error) {
	if len(feeEstimates) == 0 {
		return nil, errors.New("no estimates")
	}

	// We should probably add a variance check but for now be exact.
	for _, v := range feeEstimates {
		if v.Blocks == blocks {
			return v, nil
		}
	}

	return nil, errors.New("no suitable fee estimate")
}

// BalanceFromUtxos returns the total amount of the provided utxos.
func BalanceFromUtxos(utxos []*tbcapi.UTXO) btcutil.Amount {
	var amount btcutil.Amount
	for k := range utxos {
		amount += utxos[k].Value
	}
	return amount
}

// L2KeystoneAbrev is the abbreviated format of an L2Keystone. It simply clips
// various hashes to a shorter version.
type L2KeystoneAbrev struct {
	Version            uint          `json:"version"`
	L1BlockNumber      uint          `json:"l1_block_number"`
	L2BlockNumber      uint          `json:"l2_block_number"`
	ParentEPHash       api.ByteSlice `json:"parent_ep_hash"`
	PrevKeystoneEPHash api.ByteSlice `json:"prev_keystone_ep_hash"`
	StateRoot          api.ByteSlice `json:"state_root"`
	EPHash             api.ByteSlice `json:"ep_hash"`
}

func (a *L2KeystoneAbrev) Serialize() [72]byte {
	var r [72]byte
	r[0] = uint8(a.Version)
	binary.BigEndian.PutUint32(r[1:5], uint32(a.L1BlockNumber))
	binary.BigEndian.PutUint32(r[5:9], uint32(a.L2BlockNumber))
	copy(r[9:], a.ParentEPHash[:])
	copy(r[20:], a.PrevKeystoneEPHash[:])
	copy(r[32:], a.StateRoot[:])
	copy(r[64:], a.EPHash[:])
	return r
}

func TBC2Gozer(req *tbcapi.BlocksByL2AbrevHashesResponse) *BlocksByL2AbrevHashesResponse {
	blkInfos := make([]L2KeystoneBlockInfo, 0, len(req.L2KeystoneBlocks))
	for _, info := range req.L2KeystoneBlocks {
		var gi L2KeystoneBlockInfo
		if info.Error != nil {
			gi.Error = info.Error
		} else {
			gi = L2KeystoneBlockInfo{
				L2KeystoneAbrev: L2KeystoneAbrev{
					Version:            uint(info.L2KeystoneAbrev.Version),
					L1BlockNumber:      uint(info.L2KeystoneAbrev.L1BlockNumber),
					L2BlockNumber:      uint(info.L2KeystoneAbrev.L2BlockNumber),
					ParentEPHash:       info.L2KeystoneAbrev.ParentEPHash[:],
					PrevKeystoneEPHash: info.L2KeystoneAbrev.PrevKeystoneEPHash[:],
					StateRoot:          info.L2KeystoneAbrev.StateRoot[:],
					EPHash:             info.L2KeystoneAbrev.EPHash[:],
				},
				L2KeystoneBlockHash:   *info.L2KeystoneBlockHash,
				L2KeystoneBlockHeight: info.L2KeystoneBlockHeight,
			}
		}
		blkInfos = append(blkInfos, gi)
	}
	r := &BlocksByL2AbrevHashesResponse{
		L2KeystoneBlocks:  blkInfos,
		BtcTipBlockHash:   *req.BtcTipBlockHash,
		BtcTipBlockHeight: req.BtcTipBlockHeight,
	}

	return r
}

type L2KeystoneBlockInfo struct {
	L2KeystoneAbrev       L2KeystoneAbrev `json:"l2_keystone_abrev"`
	L2KeystoneBlockHash   chainhash.Hash  `json:"l2_keystone_block_hash"`
	L2KeystoneBlockHeight uint            `json:"l2_keystone_block_height"`
	Error                 *protocol.Error `json:"error,omitempty"`
}

// BlocksByL2AbrevHashesResponse JSON response to keystone
// finality route. Note that if the keystone exists that, by definition, the
// keystone lives on the canonical chain. This is why we can return the best
// tip height and hash.
type BlocksByL2AbrevHashesResponse struct {
	L2KeystoneBlocks  []L2KeystoneBlockInfo `json:"l2_keystone_blocks"`
	BtcTipBlockHash   chainhash.Hash        `json:"btc_tip_block_hash"`
	BtcTipBlockHeight uint                  `json:"btc_tip_block_height"`
	Error             *protocol.Error       `json:"error,omitempty"`
}

type KeystonesByHeightResponse struct {
	L2KeystoneAbrevs []*hemi.L2KeystoneAbrev `json:"l2_keystone_abrevs"`
	BTCTipHeight     uint64                  `json:"btc_tip_height"`
	Error            *protocol.Error         `json:"error,omitempty"`
}
