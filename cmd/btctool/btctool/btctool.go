// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package btctool

import (
	"context"
	"fmt"

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/cmd/btctool/bdf"
	"github.com/hemilabs/heminetwork/cmd/btctool/blockstream"
)

var log = loggo.GetLogger("btctool")

func GetAndStoreBlockHeader(ctx context.Context, height int, dir string) (string, error) {
	hash, err := blockstream.BlockHeightHash(ctx, fmt.Sprintf("%v", height))
	if err != nil {
		return "", fmt.Errorf("BlockHeightHash %v: %v", height, err)
	}

	header, err := blockstream.BlockHeader(ctx, hash)
	if err != nil {
		return "", fmt.Errorf("BlockHeader %v: %v", hash, err)
	}

	// Write header
	err = bdf.WriteHeader(height, header, dir)
	if err != nil {
		return "", fmt.Errorf("WriteHeight: %v", err)
	}

	return hash, nil
}
