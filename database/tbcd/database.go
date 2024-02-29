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

	BtcHashHeightInsert(ctx context.Context, bhh []BtcHashHeight) error
}

type BtcHashHeight struct {
	Hash      database.ByteArray `json:"hash"`
	Height    uint64             `json:"height"`
	CreatedAt database.Timestamp `deep:"-"`
}
