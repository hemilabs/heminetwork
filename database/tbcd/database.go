// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
)

type InsertType int

const (
	ITInvalid     InsertType = 0 // Invalid insert
	ITChainExtend InsertType = 1 // Normal insert, does not require further action.
	ITChainFork   InsertType = 2 // Chain forked, unwind and rewind indexes.
	ITForkExtend  InsertType = 3 // Extended a fork, does not require further action.
)

var itStrings = map[InsertType]string{
	ITInvalid:     "invalid",
	ITChainExtend: "chain extended",
	ITChainFork:   "chain forked",
	ITForkExtend:  "fork extended",
}

func (it InsertType) String() string {
	return itStrings[it]
}

type Database interface {
	database.Database

	// Metadata
	Version(ctx context.Context) (int, error)
	MetadataGet(ctx context.Context, key []byte) ([]byte, error)
	MetadataPut(ctx context.Context, key, value []byte) error

	// Block header
	BlockHeaderBest(ctx context.Context) (*BlockHeader, error) // return canonical
	BlockHeaderByHash(ctx context.Context, hash *chainhash.Hash) (*BlockHeader, error)
	BlockHeaderGenesisInsert(ctx context.Context, wbh *wire.BlockHeader) error

	// Block headers
	BlockHeadersByHeight(ctx context.Context, height uint64) ([]BlockHeader, error)
	BlockHeadersInsert(ctx context.Context, bhs *wire.MsgHeaders) (InsertType, *BlockHeader, *BlockHeader, int, error)

	// Block
	BlocksMissing(ctx context.Context, count int) ([]BlockIdentifier, error)
	BlockMissingDelete(ctx context.Context, height int64, hash *chainhash.Hash) error
	BlockInsert(ctx context.Context, b *btcutil.Block) (int64, error)
	// BlocksInsert(ctx context.Context, bs []*btcutil.Block) (int64, error)
	BlockByHash(ctx context.Context, hash *chainhash.Hash) (*btcutil.Block, error)

	// Transactions
	BlockUtxoUpdate(ctx context.Context, direction int, utxos map[Outpoint]CacheOutput) error
	BlockTxUpdate(ctx context.Context, direction int, txs map[TxKey]*TxValue) error
	BlockHashByTxId(ctx context.Context, txId *chainhash.Hash) (*chainhash.Hash, error)
	SpentOutputsByTxId(ctx context.Context, txId *chainhash.Hash) ([]SpentInfo, error)

	// ScriptHash returns the sha256 of PkScript for the provided outpoint.
	BalanceByScriptHash(ctx context.Context, sh ScriptHash) (uint64, error)
	BlockInTxIndex(ctx context.Context, hash *chainhash.Hash) (bool, error)
	ScriptHashByOutpoint(ctx context.Context, op Outpoint) (*ScriptHash, error)
	UtxosByScriptHash(ctx context.Context, sh ScriptHash, start uint64, count uint64) ([]Utxo, error)
}

// XXX there exist various types in this file that need to be reevaluated.
// Such as BlockHash, ScriptHash etc. They exist for convenience reasons but
// it may be worth to switch to chainhash and btcd.OutPoint etc. This does need
// thought because we have composites that are needed for the code to function
// properly.

// BlockHeader contains the first 80 raw bytes of a bitcoin block plus its
// location information (hash+height) and the cumulative difficulty.
type BlockHeader struct {
	Hash       chainhash.Hash
	Height     uint64
	Header     [80]byte
	Difficulty big.Int
}

func (bh BlockHeader) String() string {
	return bh.Hash.String()
}

func (bh BlockHeader) HH() string {
	return fmt.Sprintf("%v @ %v", bh.Height, bh.Hash.String())
}

func (bh BlockHeader) Timestamp() time.Time {
	var wbh wire.BlockHeader
	err := wbh.Deserialize(bytes.NewReader(bh.Header[:]))
	if err != nil {
		return time.Time{}
	}
	return wbh.Timestamp
}

func (bh BlockHeader) Wire() (*wire.BlockHeader, error) {
	var wbh wire.BlockHeader
	err := wbh.Deserialize(bytes.NewReader(bh.Header[:]))
	if err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}
	return &wbh, nil
}

func (bh BlockHeader) BlockHash() *chainhash.Hash {
	return &bh.Hash
}

func (bh BlockHeader) ParentHash() *chainhash.Hash {
	wh, err := bh.Wire()
	if err != nil {
		panic(err)
	}
	return &wh.PrevBlock
}

// BlockIdentifier uniquely identifies a block using it's hash and height.
type BlockIdentifier struct {
	Height uint64
	Hash   *chainhash.Hash
}

type SpentInfo struct {
	BlockHash  *chainhash.Hash
	TxId       *chainhash.Hash
	InputIndex uint32
}

// XXX we can probably save a bunch of bcopy if we construct the key directly
// for the db. Peek at the s + t cache which does this.

// Outpoint is a bitcoin structure that points to a transaction in a block. It
// is expressed as an array of bytes in order to pack it as dense as possible
// for memory conservation reasons.
//
// The bytes contained by Outpoint is 'u' + txid + index.
type Outpoint [1 + 32 + 4]byte

// String returns a reversed pretty printed outpoint.
func (o Outpoint) String() string {
	hash, _ := chainhash.NewHash(o[1:33])
	return fmt.Sprintf("%s:%d", hash, binary.BigEndian.Uint32(o[33:]))
}

func (o Outpoint) TxId() []byte {
	return o[1:33]
}

func (o Outpoint) TxIdHash() *chainhash.Hash {
	h, _ := chainhash.NewHash(o[1:33])
	return h
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

// CacheOutput is a densely packed representation of a bitcoin UTXo. The fields are
// script_hash + value + out_index. It is packed for
// memory conservation reasons.
type CacheOutput [32 + 8 + 4]byte // script_hash + value + out_idx

// String reutrns pretty printable CacheOutput. Hash is not reversed since it is an
// opaque pointer. It prints satoshis@script_hash:output_index
func (c CacheOutput) String() string {
	return fmt.Sprintf("%d @ %x:%d", binary.BigEndian.Uint64(c[32:40]),
		c[0:32], binary.BigEndian.Uint32(c[40:]))
}

func (c CacheOutput) ScriptHash() (hash ScriptHash) {
	copy(hash[:], c[0:32])
	return
}

func (c CacheOutput) ScriptHashSlice() []byte {
	return c[0:32]
}

func (c CacheOutput) Value() uint64 {
	return binary.BigEndian.Uint64(c[32:40])
}

func (c CacheOutput) ValueBytes() []byte {
	return c[32:40]
}

func (c CacheOutput) OutputIndex() uint32 {
	return binary.BigEndian.Uint32(c[40:])
}

func (c CacheOutput) OutputIndexBytes() []byte {
	return c[40:44]
}

func (c CacheOutput) Equal(x CacheOutput) bool {
	return bytes.Equal(c[:], x[:])
}

// DeleteUtxo is the max uint64 value which is used as a sentinel to indicate
// that a utxo should be reaped. The remaining fields must remain untouched
// since they are part of the lookup key of the utxo balance.
var DeleteUtxo = [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func (c CacheOutput) IsDelete() bool {
	return bytes.Equal(c[32:40], DeleteUtxo[:])
}

func NewCacheOutput(hash [32]byte, value uint64, outIndex uint32) (co CacheOutput) {
	copy(co[0:32], hash[:]) // scripthash
	binary.BigEndian.PutUint64(co[32:40], value)
	binary.BigEndian.PutUint32(co[40:], outIndex)
	return
}

func NewDeleteCacheOutput(hash [32]byte, outIndex uint32) (co CacheOutput) {
	copy(co[0:32], hash[:]) // scripthash or txid
	copy(co[32:40], DeleteUtxo[:])
	binary.BigEndian.PutUint32(co[40:], outIndex)
	return
}

// Utxo packs a transaction id, the value and the out index.
type Utxo [32 + 8 + 4]byte // tx_id + value + out_idx

// String reutrns pretty printable CacheOutput. Hash is not reversed since it is an
// opaque pointer. It prints satoshis@script_hash:output_index
func (u Utxo) String() string {
	ch, _ := chainhash.NewHash(u[0:32])
	return fmt.Sprintf("%d @ %v:%d", binary.BigEndian.Uint64(u[32:40]),
		ch, binary.BigEndian.Uint32(u[40:]))
}

func (u Utxo) ScriptHash() (hash ScriptHash) {
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

func (u Utxo) Equal(x CacheOutput) bool {
	return bytes.Equal(u[:], x[:])
}

func NewUtxo(hash [32]byte, value uint64, outIndex uint32) (u Utxo) {
	copy(u[0:32], hash[:]) // txid
	binary.BigEndian.PutUint64(u[32:40], value)
	binary.BigEndian.PutUint32(u[40:], outIndex)
	return
}

// ScriptHash is a SHA256 hash that implements fmt.Stringer.
type ScriptHash [sha256.Size]byte

func (sh ScriptHash) String() string {
	return hex.EncodeToString(sh[:])
}

func NewScriptHashFromScript(script []byte) (scriptHash ScriptHash) {
	return sha256.Sum256(script)
}

func NewScriptHashFromBytes(hash []byte) (scriptHash ScriptHash, err error) {
	if len(hash) != 32 {
		err = errors.New("invalid script hash length")
		return
	}
	copy(scriptHash[:], hash[:])
	return
}

func NewScriptHashFromString(hash string) (ScriptHash, error) {
	shs, err := hex.DecodeString(hash)
	if err != nil {
		return ScriptHash{}, err
	}
	return NewScriptHashFromBytes(shs)
}

// Spent Transaction:
//
//	s + txin.PrevOutPoint.Hash + txin.PrevOutPoint.Index + blockhash = txid + txin_index | [1 + 32 + 4 + 32] = [32 + 4]
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

func TxIdBlockHashFromTxKey(txKey TxKey) (*chainhash.Hash, *chainhash.Hash, error) {
	if txKey[0] != 't' {
		return nil, nil, fmt.Errorf("invalid magic 0x%02x", txKey[0])
	}
	txId, err := chainhash.NewHash(txKey[1:33])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid tx id: %w", err)
	}
	blockHash, err := chainhash.NewHash(txKey[33:65])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid block hash: %w", err)
	}
	return txId, blockHash, nil
}
