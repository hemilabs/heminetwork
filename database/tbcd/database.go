// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcd

import (
	"context"

	"github.com/hemilabs/heminetwork/database"
)

type Database interface {
	database.Database

	// Version table
	Version(ctx context.Context) (int, error)

	BlockHeaderByHash(ctx context.Context, hash []byte) (*BlockHeader, error)
	BlockHeadersBest(ctx context.Context) ([]BlockHeader, error)
	BlockHeadersInsert(ctx context.Context, bhs []BlockHeader) error
}

type BlockHeader struct {
	Hash      database.ByteArray
	Height    uint64
	Header    database.ByteArray
	CreatedAt database.Timestamp `deep:"-"`
}
