// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/database"
)

type Database interface {
	database.Database

	// Metadata
	Version(ctx context.Context) (int, error)
	MetadataGet(ctx context.Context, key []byte) ([]byte, error)
	MetadataPut(ctx context.Context, key, value []byte) error

	// Block header
	BlockHeaderByHash(ctx context.Context, hash []byte) (*BlockHeader, error)
	BlockHeadersBest(ctx context.Context) ([]BlockHeader, error)
	BlockHeadersInsert(ctx context.Context, bhs []BlockHeader) error
	BlockHeadersByHeight(ctx context.Context, height uint64) ([]BlockHeader, error)

	// Block
	BlocksMissing(ctx context.Context, count int) ([]BlockIdentifier, error)
	BlockInsert(ctx context.Context, b *Block) (int64, error)
	// XXX replace BlockInsert with plural version
	// BlocksInsert(ctx context.Context, bs []*Block) (int64, error)
	BlockByHash(ctx context.Context, hash []byte) (*Block, error)

	// Transactions
	// UTxosInsert(ctx context.Context, butxos []BlockUtxo) error
	// BlockTxUpdate(ctx context.Context, blockhash []byte, btxs []Tx) error
	BlockTxUpdate(ctx context.Context, utxos map[Outpoint]Utxo) error

	// Peer manager
	PeersStats(ctx context.Context) (int, int)               // good, bad count
	PeersInsert(ctx context.Context, peers []Peer) error     // insert or update
	PeerDelete(ctx context.Context, host, port string) error // remove peer
	PeersRandom(ctx context.Context, count int) ([]Peer, error)
}

// BlockHeader contains the first 80 raw bytes of a bitcoin block and its
// location information (hash+height).
type BlockHeader struct {
	Hash   database.ByteArray
	Height uint64
	Header database.ByteArray
}

// Block contains a raw bitcoin block and its corresponding hash.
type Block struct {
	Hash  database.ByteArray
	Block database.ByteArray
}

// BlockIdentifier uniquely identifies a block using it's hash and height.
type BlockIdentifier struct {
	Height uint64
	Hash   database.ByteArray
}

// Peer
type Peer struct {
	Host      string
	Port      string
	LastAt    database.Timestamp `deep:"-"` // Last time connected
	CreatedAt database.Timestamp `deep:"-"`
}

// Outpoint is a bitcoin structure that points to a transaction in a block. It
// is expressed as an array of bytes in order to pack it as dense as possible
// for memory conservation reasons.
type Outpoint [36]byte // Outpoint Tx id

// String returns a reversed pretty printed outpoint.
func (o Outpoint) String() string {
	hash, _ := chainhash.NewHash(o[0:32])
	return fmt.Sprintf("%s:%d", hash, binary.BigEndian.Uint32(o[32:]))
}

func (o Outpoint) TxId() []byte {
	return o[0:32]
}

func (o Outpoint) TxIndex() uint32 {
	return binary.BigEndian.Uint32(o[32:])
}

func (o Outpoint) TxIndexBytes() []byte {
	return o[32:]
}

func NewOutpoint(txid [32]byte, index uint32) (op Outpoint) {
	copy(op[0:32], txid[:])
	binary.BigEndian.PutUint32(op[32:], index)
	return
}

// Utxo is a densely packed representation of a bitcoin UTXo. The fields are
// script_hash + value + out_index. It is packed for
// memory conservation reasons.
type Utxo [32 + 8 + 4]byte // script_hash + value + out_idx

// String reutrns pretty printable Utxo. Hash is not reversed since it is an
// opaque pointer. It prints satoshis@script_hash:output_index
func (u Utxo) String() string {
	return fmt.Sprintf("%d @ %x:%d", binary.BigEndian.Uint64(u[32:40]),
		u[0:32], binary.BigEndian.Uint32(u[40:]))
}

func (u Utxo) ScriptHash() []byte {
	return u[0:32]
}

func (u Utxo) Value() uint64 {
	return binary.BigEndian.Uint64(u[32:40])
}

func (u Utxo) ValueBytes() []byte {
	return u[32:40]
}

func (u Utxo) OutputIndex() uint32 {
	return binary.BigEndian.Uint32(u[40:])
}

func (u Utxo) OutputIndexBytes() []byte {
	return u[40:44]
}

func (u Utxo) Equal(x Utxo) bool {
	return bytes.Equal(u[:], x[:])
}

func NewUtxo(scriptHash [32]byte, value uint64, outIndex uint32) (utxo Utxo) {
	copy(utxo[0:32], scriptHash[:])
	binary.BigEndian.PutUint64(utxo[32:40], value)
	binary.BigEndian.PutUint32(utxo[40:], outIndex)
	return
}

var DeleteUtxo Utxo

func init() {
	// Initialize sentinel that marks utxo cache entries for deletion
	for i := 0; i < len(DeleteUtxo); i++ {
		DeleteUtxo[i] = 0xff
	}
}
