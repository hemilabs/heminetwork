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
	APIVersion = 1
)

var (
	APIVersionRoute         = fmt.Sprintf("v%d", APIVersion)
	DefaultListenAddress    = "localhost:8080"
	DefaultPrometheusListen = "localhost:2112"

	RouteKeystoneFinality = "GET /" + APIVersionRoute + "/" + "keystonefinality/{hash...}"
)

type L2KeystoneValidityResponse struct {
	L2KeystonesHashes []chainhash.Hash `json:"keystones"`
	Error             *protocol.Error  `json:"error,omitempty"`
}

type L2BTCFinality struct {
	L2Keystone       hemi.L2Keystone `json:"l2_keystone"`
	BTCPubHeight     int64           `json:"btc_pub_height"`
	BTCPubHeaderHash api.ByteSlice   `json:"btc_pub_header_hash"`
	BTCFinality      int32           `json:"btc_finality"`
}
