// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gozer

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/tbcapi"
)

// Gozer was originally worshiped as a god by the Hittites, Mesopotamians, and
// the Sumerians around 6000 BC. Gozer was genderless and could assume any form
// it wanted.

type Gozer interface {
	FeeEstimates(ctx context.Context) ([]FeeEstimate, error)
	UtxosByAddress(ctx context.Context, addr btcutil.Address, start, count uint) ([]*tbcapi.UTXO, error)
	BlockKeystoneByL2KeystoneAbrevHash(ctx context.Context, hash *chainhash.Hash) (*BlockKeystoneByL2KeystoneAbrevHashResponse, error)
	BroadcastTx(ctx context.Context, tx *wire.MsgTx) (*chainhash.Hash, error)
}

type FeeEstimate struct {
	Blocks      uint
	SatsPerByte float64
}

// FeeByConfirmations picks a suitable fee by matching the exact number of
// blocks provided by the caller.
func FeeByConfirmations(blocks uint, feeEstimates []FeeEstimate) (*FeeEstimate, error) {
	if len(feeEstimates) == 0 {
		return nil, errors.New("no estimates")
	}

	// We should probably add a variance check but for now be exact.
	for _, v := range feeEstimates {
		if v.Blocks == blocks {
			return &v, nil
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

// BlockKeystoneByL2KeystoneAbrevHashResponse JSON response to keystone
// finality route. Note that if the keystone exists that, by definition, the
// keystone lives on the canonical chain. This is why we can return the best
// tip height and hash.
type BlockKeystoneByL2KeystoneAbrevHashResponse struct {
	L2KeystoneAbrev       L2KeystoneAbrev `json:"l2_keystone_abrev"`
	L2KeystoneBlockHash   chainhash.Hash  `json:"l2_keystone_block_hash"`
	L2KeystoneBlockHeight uint            `json:"l2_keystone_block_height"`
	BtcTipBlockHash       chainhash.Hash  `json:"btc_tip_block_hash"`
	BtcTipBlockHeight     uint            `json:"btc_tip_block_height"`
}
