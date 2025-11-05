// Copyright (c) 2024-2025 Hemi Labs, Inc.
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
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/hemi"
)

type InsertType int

const (
	ITInvalid     InsertType = 0 // Invalid insert
	ITChainExtend InsertType = 1 // Normal insert, does not require further action.
	ITChainFork   InsertType = 2 // Chain forked, unwind and rewind indexes.
	ITForkExtend  InsertType = 3 // Extended a fork, does not require further action.
)

var (
	itStrings = map[InsertType]string{
		ITInvalid:     "invalid",
		ITChainExtend: "chain extended",
		ITChainFork:   "chain forked",
		ITForkExtend:  "fork extended",
	}

	Welcome = true
)

func (it InsertType) String() string {
	return itStrings[it]
}

// Row is used in metadata batches.
type Row struct {
	Key   []byte
	Value []byte
	Error error
}

// Canonical chain geometry changes resulting from header removal
type RemoveType int

const (
	RTInvalid      RemoveType = 0 // Invalid removal for generic reason (ex: no headers to remove)
	RTChainDescend RemoveType = 1 // Removal walked the canonical chain backwards, but existing chain is still canonical
	RTForkDescend  RemoveType = 2 // Removal walked a non-canonical chain backwards, no change to canonical chain remaining canonical
	RTChainFork    RemoveType = 3 // Removal walked canonical chain backwards far enough that another chain is now canonical
)

var rtStrings = map[RemoveType]string{
	RTInvalid:      "invalid",
	RTChainDescend: "canonical chain descend",
	RTForkDescend:  "fork chain descend",
	RTChainFork:    "canonical descend changed canonical",
}

func (rt RemoveType) String() string {
	return rtStrings[rt]
}

type Batch struct {
	Batch *leveldb.Batch
}

type BatchHook func(ctx context.Context, batches map[string]Batch) error

type Database interface {
	database.Database

	// Metadata
	Version(ctx context.Context) (int, error)
	MetadataDel(ctx context.Context, key []byte) error
	MetadataGet(ctx context.Context, key []byte) ([]byte, error)
	MetadataPut(ctx context.Context, key, value []byte) error
	MetadataBatchGet(ctx context.Context, allOrNone bool, keys [][]byte) ([]Row, error)
	MetadataBatchPut(ctx context.Context, rows []Row) error

	// Block header
	BlockHeaderBest(ctx context.Context) (*BlockHeader, error) // return canonical
	BlockHeaderByHash(ctx context.Context, hash chainhash.Hash) (*BlockHeader, error)
	BlockHeaderGenesisInsert(ctx context.Context, wbh wire.BlockHeader, height uint64, diff *big.Int) error
	BlockHeaderCacheStats() CacheStats

	// Block headers
	BlockHeadersByHeight(ctx context.Context, height uint64) ([]BlockHeader, error)
	BlockHeadersInsert(ctx context.Context, bhs *wire.MsgHeaders, batchHook BatchHook) (InsertType, *BlockHeader, *BlockHeader, int, error)
	BlockHeadersRemove(ctx context.Context, bhs *wire.MsgHeaders, tipAfterRemoval *wire.BlockHeader, batchHook BatchHook) (RemoveType, *BlockHeader, error)

	// Block
	BlocksMissing(ctx context.Context, count int) ([]BlockIdentifier, error)
	BlockMissingDelete(ctx context.Context, height int64, hash chainhash.Hash) error
	BlockInsert(ctx context.Context, b *btcutil.Block) (int64, error)
	// BlocksInsert(ctx context.Context, bs []*btcutil.Block) (int64, error)
	BlockByHash(ctx context.Context, hash chainhash.Hash) (*btcutil.Block, error)
	BlockExistsByHash(ctx context.Context, hash chainhash.Hash) (bool, error)
	BlockCacheStats() CacheStats

	// Transactions
	BlockHeaderByUtxoIndex(ctx context.Context) (*BlockHeader, error)
	BlockHeaderByTxIndex(ctx context.Context) (*BlockHeader, error)
	BlockUtxoUpdate(ctx context.Context, direction int, utxos map[Outpoint]CacheOutput, utxoIndexHash chainhash.Hash) error
	BlockTxUpdate(ctx context.Context, direction int, txs map[TxKey]*TxValue, txIndexHash chainhash.Hash) error
	BlockHashByTxId(ctx context.Context, txId chainhash.Hash) (*chainhash.Hash, error)
	SpentOutputsByTxId(ctx context.Context, txId chainhash.Hash) ([]SpentInfo, error)
	// ScriptHash returns the sha256 of PkScript for the provided outpoint.
	BalanceByScriptHash(ctx context.Context, sh ScriptHash) (uint64, error)
	BlockInTxIndex(ctx context.Context, hash chainhash.Hash) (bool, error)
	ScriptHashByOutpoint(ctx context.Context, op Outpoint) (*ScriptHash, error)
	ScriptHashesByOutpoint(ctx context.Context, ops []*Outpoint, result func(Outpoint, ScriptHash) error) error
	UtxosByScriptHash(ctx context.Context, sh ScriptHash, start uint64, count uint64) ([]Utxo, error)
	UtxosByScriptHashCount(ctx context.Context, sh ScriptHash) (uint64, error)

	// Hemi
	BlockKeystoneUpdate(ctx context.Context, direction int, keystones map[chainhash.Hash]Keystone, keystoneIndexHash chainhash.Hash) error
	BlockKeystoneByL2KeystoneAbrevHash(ctx context.Context, abrevhash chainhash.Hash) (*Keystone, error)
	BlockHeaderByKeystoneIndex(ctx context.Context) (*BlockHeader, error)
	KeystonesByHeight(ctx context.Context, height uint32, depth int) ([]Keystone, error)

	// ZKUtxo
	BlockHeaderByZKIndex(ctx context.Context) (*BlockHeader, error)
	BlockZKUpdate(ctx context.Context, direction int, blockheaders map[ZKIndexKey][]byte, zkIndexHash chainhash.Hash) error
	ZKValueAndScriptByOutpoint(ctx context.Context, op Outpoint) (uint64, []byte, error)
	ZKBalanceByScriptHash(ctx context.Context, sh ScriptHash) (uint64, error)
	ZKSpentOutputs(ctx context.Context, sh ScriptHash) ([]ZKSpentOutput, error)
	ZKSpendingOutpoints(ctx context.Context, txid chainhash.Hash) ([]ZKSpendingOutpoint, error)
	ZKSpendableOutputs(ctx context.Context, sh ScriptHash) ([]ZKSpendableOutput, error)
}

type Keystone struct {
	BlockHash           chainhash.Hash                 // Block that contains abbreviated keystone
	BlockHeight         uint32                         // Block height
	AbbreviatedKeystone [hemi.L2KeystoneAbrevSize]byte // Abbreviated keystone
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
// XXX can we make index 2 bytes?
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
	op[0] = 'u' // match leveldb cache so that we prevent a bunch of bcopy
	copy(op[1:33], txid[:])
	binary.BigEndian.PutUint32(op[33:], index)
	return op
}

func NewOutpointFromString(s string) (*Outpoint, error) {
	p := strings.SplitN(s, ":", 2)
	if len(p) != 2 {
		return nil, errors.New("invalid point")
	}
	h, err := chainhash.NewHashFromStr(p[0])
	if err != nil {
		return nil, err
	}
	i, err := strconv.ParseUint(p[1], 10, 32)
	if err != nil {
		return nil, err
	}
	point := NewOutpoint(*h, uint32(i))
	return &point, nil
}

func NewTxOut(txOut *wire.TxOut) []byte {
	x := make([]byte, 8+len(txOut.PkScript))
	binary.BigEndian.PutUint64(x[0:], uint64(txOut.Value))
	copy(x[8:], txOut.PkScript)
	return x
}

func TxOutFromBytes(x []byte) (txOut wire.TxOut) {
	txOut.Value = int64(binary.BigEndian.Uint64(x[0:]))
	txOut.PkScript = append([]byte{}, x[8:]...)
	return txOut
}

// CacheOutput is a densely packed representation of a bitcoin UTXo. The fields
// are script_hash + value + out_index. It is packed for memory conservation
// reasons.
type CacheOutput [32 + 8 + 4]byte // script_hash + value + out_idx

// String returns pretty printable CacheOutput. Hash is not reversed since it
// is an opaque pointer. It prints satoshis@script_hash:output_index
func (c CacheOutput) String() string {
	return fmt.Sprintf("%d @ %x:%d", binary.BigEndian.Uint64(c[32:40]),
		c[0:32], binary.BigEndian.Uint32(c[40:]))
}

func (c CacheOutput) ScriptHash() (hash ScriptHash) {
	copy(hash[:], c[0:32])
	return hash
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
	return co
}

func NewDeleteCacheOutput(hash [32]byte, outIndex uint32) (co CacheOutput) {
	copy(co[0:32], hash[:]) // scripthash or txid
	copy(co[32:40], DeleteUtxo[:])
	binary.BigEndian.PutUint32(co[40:], outIndex)
	return co
}

// Utxo packs a transaction id, the value and the out index.
// XXX why are we using ScriptHash here instead of chainhash?
type Utxo [32 + 8 + 4]byte // tx_id + value + out_idx

// String returns pretty printable CacheOutput. Hash is not reversed since it
// is an opaque pointer. It prints satoshis@script_hash:output_index
func (u Utxo) String() string {
	ch, _ := chainhash.NewHash(u[0:32])
	return fmt.Sprintf("%d @ %v:%d", binary.BigEndian.Uint64(u[32:40]),
		ch, binary.BigEndian.Uint32(u[40:]))
}

func (u Utxo) ChainHash() *chainhash.Hash {
	ch, _ := chainhash.NewHash(u[0:32])
	return ch
}

// XXX deprecate
func (u Utxo) ScriptHash() (hash ScriptHash) {
	copy(hash[:], u[0:32])
	return hash
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
	return u
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
	if len(hash) != sha256.Size {
		err = errors.New("invalid script hash length")
		return scriptHash, err
	}
	copy(scriptHash[:], hash)
	return scriptHash, err
}

func NewScriptHashFromBytesP(hash []byte) (scriptHash ScriptHash) {
	sh, err := NewScriptHashFromBytes(hash)
	if err != nil {
		panic(err)
	}
	return sh
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

// Cache
type CacheStats struct {
	Hits   int
	Misses int
	Purges int
	Size   int
	Items  int
}

// SpendingOutpointKey is a database encoded key for a SpendingOutpoint
type SpendingOutpointKey [32 + 4 + 32 + 4]byte // txid:blockheight:blockhash:VoutIdx

type ZKSpendingOutpoint struct {
	TxID             chainhash.Hash
	BlockHeight      uint32
	BlockHash        chainhash.Hash
	VOutIndex        uint32
	SpendingOutpoint *ZKSpendingOutpointValue
}

func NewSpendingOutpointKey(txId chainhash.Hash, height uint32, blockHash chainhash.Hash, voutIdx uint32) (sok SpendingOutpointKey) {
	copy(sok[:], txId[:])
	binary.BigEndian.PutUint32(sok[32:], height)
	copy(sok[32+4:], blockHash[:])
	binary.BigEndian.PutUint32(sok[32+4+32:], voutIdx)
	return sok
}

// SpendingOutpointValue
type SpendingOutpointValue [32 + 4]byte // hash:idx of spending tx

type ZKSpendingOutpointValue struct {
	TxID  chainhash.Hash
	Index uint32
}

func (p SpendingOutpointValue) String() string {
	h, _ := chainhash.NewHash(p[0:32])
	return fmt.Sprintf("%v:%v", h, binary.BigEndian.Uint32(p[32:]))
}

func NewSpendingOutpointValue(h chainhash.Hash, idx uint32) (p SpendingOutpointValue) {
	copy(p[0:], h[:])
	binary.BigEndian.PutUint32(p[32:], idx)
	return p
}

func NewSpendingOutpointValueSlice(h chainhash.Hash, idx uint32) []byte {
	p := NewSpendingOutpointValue(h, idx)
	return p[:]
}

// SpentOutput sha256(PreviousOutPoint->pkscript):blockheight:blockhash:txId:PreviousOutPoint.Hash:PreviousOutPoint.Index:txInIdx
type SpentOutput [32 + 4 + 32 + 32 + 32 + 4 + 4]byte

type ZKSpentOutput struct {
	ScriptHash        ScriptHash
	BlockHeight       uint32
	BlockHash         chainhash.Hash
	TxID              chainhash.Hash
	PrevOutpointHash  chainhash.Hash
	PrevOutpointIndex uint32
	TxInIndex         uint32
}

func NewSpentOutput(prevScripthash chainhash.Hash, height uint32, blockhash, txid, txidPrevHash chainhash.Hash, txidPrevIndex, txinIndex uint32) (o SpentOutput) {
	copy(o[0:], prevScripthash[:])
	binary.BigEndian.PutUint32(o[32:], height)
	copy(o[32+4:], blockhash[:])
	copy(o[32+4+32:], txid[:])
	copy(o[32+4+32+32:], txidPrevHash[:])
	binary.BigEndian.PutUint32(o[32+4+32+32+32:], txidPrevIndex)
	binary.BigEndian.PutUint32(o[32+4+32+32+32+4:], txinIndex)
	return o
}

// SpendableOutput = sha256(PkScript):blockheight:blockhash:txId:txOutIdx
type SpendableOutput [32 + 4 + 32 + 32 + 4]byte

type ZKSpendableOutput struct {
	ScriptHash  ScriptHash
	BlockHeight uint32
	BlockHash   chainhash.Hash
	TxID        chainhash.Hash
	TxOutIndex  uint32
}

func (o SpendableOutput) String() string {
	block, err := chainhash.NewHash(o[32+4 : 32+4+32])
	if err != nil {
		panic(err)
	}
	txid, err := chainhash.NewHash(o[33+4+32 : 33+4+32+32])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("sh %x height %v block %v tx %v:%v", o[0:32],
		binary.BigEndian.Uint32(o[32:32+4]), block, txid,
		binary.BigEndian.Uint32(o[32+4+32+32:]))
}

func NewSpendableOutput(scripthash chainhash.Hash, height uint32, blockhash, txid chainhash.Hash, txOutIndex uint32) (o SpendableOutput) {
	copy(o[0:], scripthash[:])
	binary.BigEndian.PutUint32(o[32:], height)
	copy(o[32+4:], blockhash[:])
	copy(o[32+4+32:], txid[:])
	binary.BigEndian.PutUint32(o[32+4+32+32:], txOutIndex)
	return o
}

// ZKIndexKey is a wrapper to the various types to make the comparable.  Valid
// keys are, SpendableOutput(104), SpentOutput(140), Outpoint(37),
// ScriptHash(32), TxSpendKey(72). ScriptHash(32) is the *ONLY* table that is
// updated, the others are essentially a journal of activity.
type ZKIndexKey string // ugh to make []byte comparable

func BEUint64(x uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], x)
	return b[:]
}

func BEAddUint64(x []byte, y uint64) []byte {
	if len(x) != 8 {
		panic("fix your code")
	}
	xx := binary.BigEndian.Uint64(x)
	var z [8]byte
	binary.BigEndian.PutUint64(z[:], xx+y)
	return z[:]
}

func BESubUint64(x []byte, y uint64) []byte {
	if len(x) != 8 {
		panic("fix your code")
	}
	xx := binary.BigEndian.Uint64(x)
	if y > xx {
		panic(fmt.Sprintf("xx %v y %v", xx, y))
	}
	var z [8]byte
	binary.BigEndian.PutUint64(z[:], xx-y)
	return z[:]
}
