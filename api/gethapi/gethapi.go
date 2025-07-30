// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gethapi

import (
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/hemi"
)

const (
	DefaultCommandTimeout = 5 * time.Second
)

// TODO: Find better solution
// This package stores functions and structs to communicate
// with the op-geth hemi api. It is stored on both sides to
// prevent a circular dependency issue.

type L2KeystoneValidityRequest struct {
	L2KeystoneHash chainhash.Hash `json:"l2_keystone_hash"`
	KeystoneCount  uint           `json:"keystone_count"`
}

type L2KeystoneValidityResponse struct {
	L2Keystones []hemi.L2Keystone `json:"keystones"`
	Error       *protocol.Error   `json:"error,omitempty"`
}

type L2KeystoneLatestRequest struct {
	KeystoneCount uint `json:"keystone_count"`
}

// Same as ValidityResponse but keep separate in
// case one changes in future api versions.
type L2KeystoneLatestResponse struct {
	L2Keystones []hemi.L2Keystone `json:"keystones"`
	Error       *protocol.Error   `json:"error,omitempty"`
}
