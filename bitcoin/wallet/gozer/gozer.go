// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gozer

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
)

// Gozer was originally worshiped as a god by the Hittites, Mesopotamians, and
// the Sumerians around 6000 BC. Gozer was genderless and could assume any form
// it wanted.

type Gozer interface {
	FeeEstimates(ctx context.Context) ([]FeeEstimate, error)
	UtxosByAddress(ctx context.Context, addr btcutil.Address, start, count uint) ([]*tbcapi.UTXO, error)
	BlockKeystoneByL2KeystoneAbrevHash(ctx context.Context, hash *chainhash.Hash) (*chainhash.Hash, *hemi.L2KeystoneAbrev, error)
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
