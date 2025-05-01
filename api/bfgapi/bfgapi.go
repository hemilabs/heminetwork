// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfgapi

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/hemi"
)

const (
	APIVersion = 2

	BitcoinSuperFinality = 10
)

var (
	APIVersionRoute         = fmt.Sprintf("v%d", APIVersion)
	DefaultListenAddress    = "localhost:8080"
	DefaultPrometheusListen = "localhost:2112"

	RouteKeystoneFinality = "GET /" + APIVersionRoute + "/" + "keystonefinality/{hash...}"
)

// XXX this is opgeth, please move this antonio
type L2KeystoneValidityRequest struct {
	L2KeystoneHash chainhash.Hash `json:"hash"`
	KeystoneCount  int32          `json:"count"` // this should uint
}

type L2KeystoneValidityResponse struct {
	L2Keystones []hemi.L2Keystone `json:"keystones"`
	Error       *protocol.Error   `json:"error,omitempty"`
}

// L2KeystoneBitcoinFinalityResponse is a response to an HTTP get on
// RouteKeystoneFinality.
type L2KeystoneBitcoinFinalityResponse struct {
	L2Keystone             hemi.L2Keystone `json:"l2_keystone"`
	BlockHash              api.ByteSlice   `json:"block_hash"`
	BlockHeight            uint            `json:"block_height"`
	EffectiveConfirmations uint            `json:"effective_confirmations"`
	SuperFinality          *bool           `json:"super_finality,omitempty"`
}
