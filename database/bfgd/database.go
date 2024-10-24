// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfgd

import (
	"context"

	"github.com/hemilabs/heminetwork/database"
)

type Database interface {
	database.Database

	// Version table
	Version(ctx context.Context) (int, error)

	// L2 keystone table
	L2KeystonesInsert(ctx context.Context, l2ks []L2Keystone) error
	L2KeystoneByAbrevHash(ctx context.Context, aHash [32]byte) (*L2Keystone, error)
	L2KeystonesMostRecentN(ctx context.Context, n uint32) ([]L2Keystone, error)

	// Btc block table
	BtcBlockInsert(ctx context.Context, bb *BtcBlock) error
	BtcBlockByHash(ctx context.Context, hash [32]byte) (*BtcBlock, error)
	BtcBlockHeightByHash(ctx context.Context, hash [32]byte) (uint64, error)
	BtcBlocksHeightsWithNoChildren(ctx context.Context) ([]uint64, error)

	// Pop data
	PopBasisByL2KeystoneAbrevHash(ctx context.Context, aHash [32]byte, excludeUnconfirmed bool, page uint32) ([]PopBasis, error)
	PopBasisInsertFull(ctx context.Context, pb *PopBasis) error
	PopBasisInsertPopMFields(ctx context.Context, pb *PopBasis) error
	PopBasisUpdateBTCFields(ctx context.Context, pb *PopBasis) (int64, error)

	L2BTCFinalityMostRecent(ctx context.Context, limit uint32) ([]L2BTCFinality, error)
	L2BTCFinalityByL2KeystoneAbrevHash(ctx context.Context, l2KeystoneAbrevHashes []database.ByteArray, page uint32, limit uint32) ([]L2BTCFinality, error)

	BtcBlockCanonicalHeight(ctx context.Context) (uint64, error)

	AccessPublicKeyInsert(ctx context.Context, publicKey *AccessPublicKey) error
	AccessPublicKeyExists(ctx context.Context, publicKey *AccessPublicKey) (bool, error)
	AccessPublicKeyDelete(ctx context.Context, publicKey *AccessPublicKey) error

	BtcTransactionBroadcastRequestInsert(ctx context.Context, serializedTx []byte, txId string) error
	BtcTransactionBroadcastRequestGetNext(ctx context.Context, onlyNew bool) ([]byte, error)
	BtcTransactionBroadcastRequestConfirmBroadcast(ctx context.Context, txId string) error
	BtcTransactionBroadcastRequestSetLastError(ctx context.Context, txId string, lastErr string) error
	BtcTransactionBroadcastRequestTrim(ctx context.Context) error
}

// NotificationName identifies a database notification type.
const (
	NotificationBtcBlocks             database.NotificationName = "btc_blocks"
	NotificationAccessPublicKeyDelete database.NotificationName = "access_public_keys"
	NotificationL2Keystones           database.NotificationName = "l2_keystones"
)

// NotificationPayload returns the data structure corresponding to the given
// notification type.
func NotificationPayload(ntfn database.NotificationName) (any, bool) {
	payload, ok := notifications[ntfn]
	return payload, ok
}

// notifications specifies the mapping between a notification type and its
// data structure.
var notifications = map[database.NotificationName]any{
	NotificationBtcBlocks:             BtcBlock{},
	NotificationAccessPublicKeyDelete: AccessPublicKey{},
	NotificationL2Keystones:           []L2Keystone{},
}

// we use the `deep:"-"` tag to ignore checking for these
// values in tests with deep.Equal.  since the database
// generates these values, there is no way to guarantee
// their value from Go.  in the future we can tests that these
// values are between Go values, but for now ignore

type L2Keystone struct {
	Hash               database.ByteArray // lookup key
	Version            uint32
	L1BlockNumber      uint32
	L2BlockNumber      uint32
	ParentEPHash       database.ByteArray
	PrevKeystoneEPHash database.ByteArray
	StateRoot          database.ByteArray
	EPHash             database.ByteArray
	CreatedAt          database.Timestamp `deep:"-"`
	UpdatedAt          database.Timestamp `deep:"-"`
}

type BtcBlock struct {
	Hash      database.ByteArray `json:"hash"`
	Header    database.ByteArray `json:"header"`
	Height    uint64             `json:"height"`
	CreatedAt database.Timestamp `deep:"-"`
	UpdatedAt database.Timestamp `deep:"-"`
}

type PopBasis struct {
	ID                  uint64 `deep:"-"`
	BtcTxId             database.ByteArray
	BtcRawTx            database.ByteArray
	BtcHeaderHash       database.ByteArray
	BtcTxIndex          *uint64
	BtcMerklePath       []string
	PopTxId             database.ByteArray
	PopMinerPublicKey   database.ByteArray
	L2KeystoneAbrevHash database.ByteArray
	CreatedAt           database.Timestamp `deep:"-"`
	UpdatedAt           database.Timestamp `deep:"-"`
}

type L2BTCFinality struct {
	L2Keystone       L2Keystone
	BTCPubHeight     int64
	BTCPubHeaderHash database.ByteArray
	EffectiveHeight  uint32
	BTCTipHeight     uint32
}

// XXX this needs to be generic
type Notification struct {
	ID string
}

type AccessPublicKey struct {
	PublicKey []byte
	CreatedAt database.Timestamp `deep:"-"`

	// this is a hack to pull the public key from db notifications,
	// since it comes back as an encoded string
	PublicKeyEncoded string `json:"public_key" deep:"-"`
}

const (
	IdentifierBTCNewBlock = "btc-new-block"
	IdentifierBTCFinality = "btc-finality"
)

var BTCNewBlockNotification = Notification{
	ID: IdentifierBTCNewBlock,
}

var BTCFinalityNotification = Notification{
	ID: IdentifierBTCFinality,
}
