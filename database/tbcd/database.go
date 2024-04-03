// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
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
	BlockHeadersByHeight(ctx context.Context, height uint64) ([]BlockHeader, error)
	BlockHeadersInsert(ctx context.Context, bhs []BlockHeader) error

	// Block
	BlocksMissing(ctx context.Context, count int) ([]BlockIdentifier, error)
	BlockInsert(ctx context.Context, b *Block) (int64, error)
	// XXX replace BlockInsert with plural version
	// BlocksInsert(ctx context.Context, bs []*Block) (int64, error)
	BlockByHash(ctx context.Context, hash []byte) (*Block, error)

	// Transactions
	BlockUtxoUpdate(ctx context.Context, utxos map[Outpoint]Utxo) error
	BlockTxUpdate(ctx context.Context, txs map[TxKey]*TxValue) error
	BlocksByTxId(ctx context.Context, txId TxId) ([]BlockHash, error)
	SpendOutputsByTxId(ctx context.Context, txId TxId) ([]SpendInfo, error)

	// Peer manager
	PeersStats(ctx context.Context) (int, int)               // good, bad count
	PeersInsert(ctx context.Context, peers []Peer) error     // insert or update
	PeerDelete(ctx context.Context, host, port string) error // remove peer
	PeersRandom(ctx context.Context, count int) ([]Peer, error)

	// ScriptHash returns the sha256 of PkScript for the provided outpoint.
	BalanceByScriptHash(ctx context.Context, sh ScriptHash) (uint64, error)
	ScriptHashByOutpoint(ctx context.Context, op Outpoint) (*ScriptHash, error)
	UtxosByScriptHash(ctx context.Context, sh ScriptHash) ([]Utxo, error)
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

type SpendInfo struct {
	BlockHash  BlockHash
	TxId       TxId
	InputIndex uint32
}

// Peer
type Peer struct {
	Host      string
	Port      string
	LastAt    database.Timestamp `deep:"-"` // Last time connected
	CreatedAt database.Timestamp `deep:"-"`
}

// XXX we can probably save a bunch of bcopy if we construct the key directly
// for the db. Peek at the s + t cache which does this.

// Outpoint is a bitcoin structure that points to a transaction in a block. It
// is expressed as an array of bytes in order to pack it as dense as possible
// for memory conservation reasons.
type Outpoint [37]byte // Outpoint Tx id

// String returns a reversed pretty printed outpoint.
func (o Outpoint) String() string {
	hash, _ := chainhash.NewHash(o[1:33])
	return fmt.Sprintf("%s:%d", hash, binary.BigEndian.Uint32(o[33:]))
}

func (o Outpoint) TxId() []byte {
	return o[1:33]
}

func (o Outpoint) TxIndex() uint32 {
	return binary.BigEndian.Uint32(o[33:])
}

func (o Outpoint) TxIndexBytes() []byte {
	return o[33:]
}

func NewOutpoint(txid [32]byte, index uint32) (op Outpoint) {
	op[0] = 'u' // match leveldb cache so that we preven a bunch of bcopy
	copy(op[1:33], txid[:])
	binary.BigEndian.PutUint32(op[33:], index)
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

func (u Utxo) ScriptHash() (hash [32]byte) {
	copy(hash[:], u[0:32])
	return
}

func (u Utxo) ScriptHashSlice() []byte {
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

// DeleteUtxo is the max uint64 value which is used as a sentinel to indicate
// that a utxo should be reaped. The remaining fields must remain untouched
// since they are part of the lookup key of the utxo balance.
var DeleteUtxo = [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func (u Utxo) IsDelete() bool {
	return bytes.Equal(u[32:40], DeleteUtxo[:])
}

func NewUtxo(scriptHash [32]byte, value uint64, outIndex uint32) (utxo Utxo) {
	copy(utxo[0:32], scriptHash[:])
	binary.BigEndian.PutUint64(utxo[32:40], value)
	binary.BigEndian.PutUint32(utxo[40:], outIndex)
	return
}

func NewDeleteUtxo(scriptHash [32]byte, outIndex uint32) (utxo Utxo) {
	copy(utxo[0:32], scriptHash[:])
	copy(utxo[32:40], DeleteUtxo[:])
	binary.BigEndian.PutUint32(utxo[40:], outIndex)
	return
}

// TxId is a bitcoin transaction id. The underlying slice is reversed, only
// when using the stringer does it apear in human readable format.
type TxId [32]byte

func (t TxId) String() string {
	var rev [32]byte
	for k := range t {
		rev[32-k-1] = t[k]
	}
	return hex.EncodeToString(rev[:])
}

func NewTxId(x [32]byte) (txId TxId) {
	copy(txId[:], x[:])
	return
}

func NewTxIdFromBytes(x []byte) (txId TxId, err error) {
	if len(x) != 32 {
		err = fmt.Errorf("invalid transaction hash length")
		return
	}
	copy(txId[:], x[:])
	return
}

// BlockHash is a bitcoin transaction id. The underlying slice is reversed, only
// when using the stringer does it apear in human readable format.
type BlockHash [32]byte

func (bh BlockHash) String() string {
	var rev [32]byte
	for k := range bh {
		rev[32-k-1] = bh[k]
	}
	return hex.EncodeToString(rev[:])
}

func NewBlockHash(x [32]byte) (blockHash BlockHash) {
	copy(blockHash[:], x[:])
	return
}

func NewBlockHashFromBytes(x []byte) (blockHash BlockHash, err error) {
	if len(x) != 32 {
		err = fmt.Errorf("invalid block hash length")
		return
	}
	copy(blockHash[:], x[:])
	return
}

// ScriptHash is a bitcoin transaction id. The underlying slice is reversed, only
// when using the stringer does it apear in human readable format.
type ScriptHash [32]byte

func (bh ScriptHash) String() string {
	return hex.EncodeToString(bh[:])
}

func NewScriptHash(x [32]byte) (scriptHash ScriptHash) {
	copy(scriptHash[:], x[:])
	return
}

func NewScriptHashFromBytes(x []byte) (scriptHash ScriptHash, err error) {
	if len(x) != 32 {
		err = fmt.Errorf("invalid script hash length")
		return
	}
	copy(scriptHash[:], x[:])
	return
}

// Spent Transaction:
//
//	s + txin.PrevOutPoint.Hash + txin.PrevOutPoint.Index + blockhash = txid + txin_index + blockhash | [1 + 32 + 4 + 32] = [32 + 4]
//
// Transaction ID to Block mapping:
//
//	t + txid + blockhash = nil | [1 + 32 + 32] = nil
type (
	TxKey   [69]byte // Allocate max sized key, the prefix byte determines the lengths
	TxValue [36]byte // allocate max sized value
)

// NewTxSpent returns a TxKey and TxValue that maps a spent transaction to a
// location in a block.
func NewTxSpent(blockHash, txId, inPrevHash *chainhash.Hash, inPrevIndex, txInIndex uint32) (txKey TxKey, txValue TxValue) {
	// Construct key
	txKey[0] = 's'
	copy(txKey[1:33], inPrevHash[:])
	binary.BigEndian.PutUint32(txKey[33:37], inPrevIndex)
	copy(txKey[37:], blockHash[:])

	// Construct value
	copy(txValue[0:], txId[:])
	binary.BigEndian.PutUint32(txValue[32:36], txInIndex)

	return txKey, txValue
}

// NewTxMapping returns a TxKey and TxValue that maps a tx id to a block hash.
func NewTxMapping(txId, blockHash *chainhash.Hash) (txKey TxKey) {
	// Construct key
	txKey[0] = 't'
	copy(txKey[1:33], txId[:])
	copy(txKey[33:], blockHash[:])

	return txKey
}
