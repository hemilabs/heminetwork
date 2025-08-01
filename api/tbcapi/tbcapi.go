// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcapi

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/api"
	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/hemi"
)

// XXX we should kill the wrapping types that are basically identical to wire.
// Wire is a full citizen so treat it as such.

const (
	APIVersion = 1

	CmdPingRequest  = "tbcapi-ping-request"
	CmdPingResponse = "tbcapi-ping-response"

	CmdBlockByHashRawRequest  = "tbcapi-block-by-hash-raw-request"
	CmdBlockByHashRawResponse = "tbcapi-block-by-hash-raw-response"

	CmdBlockByHashRequest  = "tbcapi-block-by-hash-request"
	CmdBlockByHashResponse = "tbcapi-block-by-hash-response"

	CmdBlockHeadersByHeightRawRequest  = "tbcapi-block-headers-by-height-raw-request"
	CmdBlockHeadersByHeightRawResponse = "tbcapi-block-headers-by-height-raw-response"

	CmdBlockHeadersByHeightRequest  = "tbcapi-block-headers-by-height-request"
	CmdBlockHeadersByHeightResponse = "tbcapi-block-headers-by-height-response"

	CmdBlockHeaderBestRawRequest  = "tbcapi-block-header-best-raw-request"
	CmdBlockHeaderBestRawResponse = "tbcapi-block-header-best-raw-response"

	CmdBlockHeaderBestRequest  = "tbcapi-block-header-best-request"
	CmdBlockHeaderBestResponse = "tbcapi-block-header-best-response"

	CmdBalanceByAddressRequest  = "tbcapi-balance-by-address-request"
	CmdBalanceByAddressResponse = "tbcapi-balance-by-address-response"

	CmdUTXOsByAddressRawRequest  = "tbcapi-utxos-by-address-raw-request"
	CmdUTXOsByAddressRawResponse = "tbcapi-utxos-by-address-raw-response"

	CmdUTXOsByAddressRequest  = "tbcapi-utxos-by-address-request"
	CmdUTXOsByAddressResponse = "tbcapi-utxos-by-address-response"

	CmdTxByIdRawRequest  = "tbcapi-tx-by-id-raw-request"
	CmdTxByIdRawResponse = "tbcapi-tx-by-id-raw-response"

	CmdTxByIdRequest  = "tbcapi-tx-by-id-request"
	CmdTxByIdResponse = "tbcapi-tx-by-id-response"

	CmdTxBroadcastRequest  = "tbcapi-tx-broadcast-request"
	CmdTxBroadcastResponse = "tbcapi-tx-broadcast-response"

	CmdTxBroadcastRawRequest  = "tbcapi-tx-broadcast-raw-request"
	CmdTxBroadcastRawResponse = "tbcapi-tx-broadcast-raw-response"

	CmdBlockInsertRequest  = "tbcapi-block-insert-request"
	CmdBlockInsertResponse = "tbcapi-block-insert-response"

	CmdBlockInsertRawRequest  = "tbcapi-block-insert-raw-request"
	CmdBlockInsertRawResponse = "tbcapi-block-insert-raw-response"

	CmdBlockDownloadAsyncRequest  = "tbcapi-block-download-async-request"
	CmdBlockDownloadAsyncResponse = "tbcapi-block-download-async-response"

	CmdBlockDownloadAsyncRawRequest  = "tbcapi-block-download-async-raw-request"
	CmdBlockDownloadAsyncRawResponse = "tbcapi-block-download-async-raw-response"

	CmdBlocksByL2AbrevHashesRequest  = "tbcapi-block-by-l2-abrev-hash-request"
	CmdBlocksByL2AbrevHashesResponse = "tbcapi-block-by-l2-abrev-hash-response"

	CmdKeystoneTxsByL2KeystoneAbrevHashRequest  = "tbcapi-l2-keystone-txs-by-abrev-hash-request"
	CmdKeystoneTxsByL2KeystoneAbrevHashResponse = "tbcapi-l2-keystone-txs-by-abrev-hash-response"

	CmdFeeEstimateRequest  = "tbcapi-fee-estimate-request"
	CmdFeeEstimateResponse = "tbcapi-fee-estimate-response"

	CmdMempoolInfoRequest  = "tbcapi-mempool-info-request"
	CmdMempoolInfoResponse = "tbcapi-mempool-info-response"

	CmdKeystonesByHeightRequest  = "tbcapi-keystones-by-height-request"
	CmdKeystonesByHeightResponse = "tbcapi-keystones-by-height-response"
)

var (
	APIVersionRoute = fmt.Sprintf("v%d", APIVersion)
	RouteWebsocket  = fmt.Sprintf("/%s/ws", APIVersionRoute)

	DefaultListen = "localhost:8082"
	DefaultURL    = fmt.Sprintf("ws://%s/%s", DefaultListen, RouteWebsocket)
)

type (
	PingRequest  protocol.PingRequest
	PingResponse protocol.PingResponse
)

// TxWitness represents a Bitcoin transaction witness.
type TxWitness []api.ByteSlice

// TxIn represents a Bitcoin transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint      `json:"outpoint"`
	SignatureScript  api.ByteSlice `json:"signature_script"`
	Witness          TxWitness     `json:"tx_witness"`
	Sequence         uint32        `json:"sequence"`
}

// OutPoint is a transaction out point.
type OutPoint struct {
	Hash  chainhash.Hash `json:"hash"`
	Index uint32         `json:"index"`
}

// TxOut represents a Bitcoin transaction output.
type TxOut struct {
	Value    int64         `json:"value"`
	PkScript api.ByteSlice `json:"pk_script"`
}

// Tx represents a Bitcoin transaction.
type Tx struct {
	Version  int32    `json:"version"`
	LockTime uint32   `json:"lock_time"`
	TxIn     []*TxIn  `json:"tx_in"`
	TxOut    []*TxOut `json:"tx_out"`
}

// UTXO represents a Bitcoin unspent transaction output.
type UTXO struct {
	TxId     chainhash.Hash `json:"tx_id"`
	Value    btcutil.Amount `json:"value"`
	OutIndex uint32         `json:"out_index"`
}

// BlockHeader represents a Bitcoin block header.
type BlockHeader struct {
	Version    int32          `json:"version"`
	PrevHash   chainhash.Hash `json:"prev_hash"`
	MerkleRoot chainhash.Hash `json:"merkle_root"`
	Timestamp  int64          `json:"timestamp"`
	Bits       string         `json:"bits"`
	Nonce      uint32         `json:"nonce"`
}

// Block represents a Bitcoin block.
type Block struct {
	Hash   chainhash.Hash `json:"hash"`
	Header BlockHeader    `json:"header"`
	Txs    []Tx           `json:"txs"`
}

type L2KeystoneBlockInfo struct {
	L2KeystoneAbrev       *hemi.L2KeystoneAbrev `json:"l2_keystone_abrev"`
	L2KeystoneBlockHash   *chainhash.Hash       `json:"l2_keystone_block_hash"`
	L2KeystoneBlockHeight uint                  `json:"l2_keystone_block_height"`
	Error                 *protocol.Error       `json:"error,omitempty"`
}

type FeeEstimate struct {
	Blocks      uint    `json:"blocks"`
	SatsPerByte float64 `json:"sats_per_byte"`
}

// BlockByHashRequest requests a [Block] by its hash.
type BlockByHashRequest struct {
	Hash chainhash.Hash `json:"hash"`
}

// BlockByHashResponse is the response for [BlockByHashRequest].
type BlockByHashResponse struct {
	Block *Block          `json:"block"`
	Error *protocol.Error `json:"error,omitempty"`
}

// BlockByHashRawRequest requests a raw block by its hash.
type BlockByHashRawRequest struct {
	Hash chainhash.Hash `json:"hash"`
}

// BlockByHashRawResponse is the response for [BlockByHashRawRequest].
type BlockByHashRawResponse struct {
	Block api.ByteSlice   `json:"block"`
	Error *protocol.Error `json:"error,omitempty"`
}

type BlockHeadersByHeightRawRequest struct {
	Height uint32 `json:"height"`
}

type BlockHeadersByHeightRawResponse struct {
	BlockHeaders []api.ByteSlice `json:"block_headers"`
	Error        *protocol.Error `json:"error,omitempty"`
}

type BlockHeadersByHeightRequest struct {
	Height uint32 `json:"height"`
}

type BlockHeadersByHeightResponse struct {
	BlockHeaders []*BlockHeader  `json:"block_headers"`
	Error        *protocol.Error `json:"error,omitempty"`
}

type BlockHeaderBestRawRequest struct{}

type BlockHeaderBestRawResponse struct {
	Height      uint64          `json:"height"`
	BlockHeader api.ByteSlice   `json:"block_header"`
	Error       *protocol.Error `json:"error,omitempty"`
}

type BlockHeaderBestRequest struct{}

type BlockHeaderBestResponse struct {
	Height      uint64          `json:"height"`
	BlockHeader *BlockHeader    `json:"block_header"`
	Error       *protocol.Error `json:"error,omitempty"`
}

type BalanceByAddressRequest struct {
	Address string `json:"address"`
}

type BalanceByAddressResponse struct {
	Balance uint64          `json:"balance"`
	Error   *protocol.Error `json:"error,omitempty"`
}

type UTXOsByAddressRawRequest struct {
	FilterMempool bool   `json:"filter_mempool"`
	Address       string `json:"address"`
	Start         uint   `json:"start"`
	Count         uint   `json:"count"`
}

type UTXOsByAddressRawResponse struct {
	UTXOs []api.ByteSlice `json:"utxos"`
	Error *protocol.Error `json:"error,omitempty"`
}

type UTXOsByAddressRequest struct {
	FilterMempool bool   `json:"filter_mempool"`
	Address       string `json:"address"`
	Start         uint   `json:"start"`
	Count         uint   `json:"count"`
}

type UTXOsByAddressResponse struct {
	UTXOs []*UTXO         `json:"utxos"`
	Error *protocol.Error `json:"error,omitempty"`
}

type TxByIdRawRequest struct {
	TxID chainhash.Hash `json:"tx_id"`
}

type TxByIdRawResponse struct {
	Tx    api.ByteSlice   `json:"tx"`
	Error *protocol.Error `json:"error,omitempty"`
}

type TxByIdRequest struct {
	TxID chainhash.Hash `json:"tx_id"`
}

type TxByIdResponse struct {
	Tx    *Tx             `json:"tx"`
	Error *protocol.Error `json:"error,omitempty"`
}

type TxBroadcastRequest struct {
	Tx    *wire.MsgTx `json:"tx"`
	Force bool        `json:"force"`
}

type TxBroadcastResponse struct {
	TxID  *chainhash.Hash `json:"tx_id"`
	Error *protocol.Error `json:"error,omitempty"`
}

type TxBroadcastRawRequest struct {
	Tx    api.ByteSlice `json:"tx"`
	Force bool          `json:"force"`
}

type TxBroadcastRawResponse struct {
	TxID  *chainhash.Hash `json:"tx_id"`
	Error *protocol.Error `json:"error,omitempty"`
}

type BlockInsertRequest struct {
	Block *wire.MsgBlock `json:"block"`
}

type BlockInsertResponse struct {
	BlockHash *chainhash.Hash `json:"block_hash"`
	Error     *protocol.Error `json:"error,omitempty"`
}

type BlockInsertRawRequest struct {
	Block api.ByteSlice `json:"block"`
}

type BlocksByL2AbrevHashesRequest struct {
	L2KeystoneAbrevHashes []chainhash.Hash `json:"l2_keystone_abrev_hashes"`
}

type BlocksByL2AbrevHashesResponse struct {
	L2KeystoneBlocks  []*L2KeystoneBlockInfo `json:"l2_keystone_blocks"`
	BtcTipBlockHash   *chainhash.Hash        `json:"btc_tip_block_hash"`
	BtcTipBlockHeight uint                   `json:"btc_tip_block_height"`
	Error             *protocol.Error        `json:"error,omitempty"`
}

// KeystoneTxsByL2KeystoneAbrevHashRequest retrieve raw keystone tx's starting
// from L2KeystoneAbrevHash for up to Depth blocks. Depth cannot be negative
// since the hash is guaranteed to be the first occurrence.
type KeystoneTxsByL2KeystoneAbrevHashRequest struct {
	L2KeystoneAbrevHash chainhash.Hash `json:"l2_keystone_abrev_hash"`
	Depth               uint           `json:"depth"`
}

type KeystoneTx struct {
	BlockHash   chainhash.Hash `json:"block_hash"`
	TxIndex     uint           `json:"tx_index"`
	BlockHeight uint           `json:"block_height"`
	RawTx       api.ByteSlice  `json:"raw_tx"` // Keystone Tx
}

type KeystoneTxsByL2KeystoneAbrevHashResponse struct {
	KeystoneTxs []KeystoneTx    `json:"keystone_txs"`
	Error       *protocol.Error `json:"error,omitempty"`
}

type KeystonesByHeightRequest struct {
	Height uint32 `json:"height"`
	Depth  int    `json:"depth"`
}

type KeystonesByHeightResponse struct {
	L2KeystoneAbrevs []*hemi.L2KeystoneAbrev `json:"l2_keystone_abrevs"`
	BTCTipHeight     uint64                  `json:"btc_tip_height"`
	Error            *protocol.Error         `json:"error,omitempty"`
}

type BlockInsertRawResponse struct {
	BlockHash *chainhash.Hash `json:"block_hash"`
	Error     *protocol.Error `json:"error,omitempty"`
}

// BlockDownloadAsyncResponse returns a block if it exists or attempts to
// download the block from p2p asynchronously.
type BlockDownloadAsyncRequest struct {
	Hash  chainhash.Hash `json:"hash"`
	Peers uint           `json:"peers"`
}

// BlockDownloadAsyncResponse replies with a block, an error or nothing. When
// bot Error and Block are nil it measn the block download request was issued
// to p2p.
type BlockDownloadAsyncResponse struct {
	Block *wire.MsgBlock  `json:"block,omitempty"`
	Error *protocol.Error `json:"error,omitempty"`
}

type BlockDownloadAsyncRawRequest struct {
	Hash  chainhash.Hash `json:"hash"`
	Peers uint           `json:"peers"`
}

type BlockDownloadAsyncRawResponse struct {
	Block api.ByteSlice   `json:"block,omitempty"`
	Error *protocol.Error `json:"error,omitempty"`
}

type FeeEstimateRequest struct{}

type FeeEstimateResponse struct {
	FeeEstimates []*FeeEstimate  `json:"fee_estimate"`
	Error        *protocol.Error `json:"error,omitempty"`
}

type MempoolInfoRequest struct{}

type MempoolInfoResponse struct {
	Size  int64           `json:"size"`
	TxNum uint            `json:"tx_num"`
	Error *protocol.Error `json:"error,omitempty"`
}

var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:                              reflect.TypeOf(PingRequest{}),
	CmdPingResponse:                             reflect.TypeOf(PingResponse{}),
	CmdBlockByHashRequest:                       reflect.TypeOf(BlockByHashRequest{}),
	CmdBlockByHashResponse:                      reflect.TypeOf(BlockByHashResponse{}),
	CmdBlockByHashRawRequest:                    reflect.TypeOf(BlockByHashRawRequest{}),
	CmdBlockByHashRawResponse:                   reflect.TypeOf(BlockByHashRawResponse{}),
	CmdBlockHeadersByHeightRawRequest:           reflect.TypeOf(BlockHeadersByHeightRawRequest{}),
	CmdBlockHeadersByHeightRawResponse:          reflect.TypeOf(BlockHeadersByHeightRawResponse{}),
	CmdBlockHeadersByHeightRequest:              reflect.TypeOf(BlockHeadersByHeightRequest{}),
	CmdBlockHeadersByHeightResponse:             reflect.TypeOf(BlockHeadersByHeightResponse{}),
	CmdBlockHeaderBestRawRequest:                reflect.TypeOf(BlockHeaderBestRawRequest{}),
	CmdBlockHeaderBestRawResponse:               reflect.TypeOf(BlockHeaderBestRawResponse{}),
	CmdBlockHeaderBestRequest:                   reflect.TypeOf(BlockHeaderBestRequest{}),
	CmdBlockHeaderBestResponse:                  reflect.TypeOf(BlockHeaderBestResponse{}),
	CmdBalanceByAddressRequest:                  reflect.TypeOf(BalanceByAddressRequest{}),
	CmdBalanceByAddressResponse:                 reflect.TypeOf(BalanceByAddressResponse{}),
	CmdUTXOsByAddressRawRequest:                 reflect.TypeOf(UTXOsByAddressRawRequest{}),
	CmdUTXOsByAddressRawResponse:                reflect.TypeOf(UTXOsByAddressRawResponse{}),
	CmdUTXOsByAddressRequest:                    reflect.TypeOf(UTXOsByAddressRequest{}),
	CmdUTXOsByAddressResponse:                   reflect.TypeOf(UTXOsByAddressResponse{}),
	CmdTxByIdRawRequest:                         reflect.TypeOf(TxByIdRawRequest{}),
	CmdTxByIdRawResponse:                        reflect.TypeOf(TxByIdRawResponse{}),
	CmdTxByIdRequest:                            reflect.TypeOf(TxByIdRequest{}),
	CmdTxByIdResponse:                           reflect.TypeOf(TxByIdResponse{}),
	CmdTxBroadcastRequest:                       reflect.TypeOf(TxBroadcastRequest{}),
	CmdTxBroadcastResponse:                      reflect.TypeOf(TxBroadcastResponse{}),
	CmdTxBroadcastRawRequest:                    reflect.TypeOf(TxBroadcastRawRequest{}),
	CmdTxBroadcastRawResponse:                   reflect.TypeOf(TxBroadcastRawResponse{}),
	CmdBlockInsertRequest:                       reflect.TypeOf(BlockInsertRequest{}),
	CmdBlockInsertResponse:                      reflect.TypeOf(BlockInsertResponse{}),
	CmdBlockInsertRawRequest:                    reflect.TypeOf(BlockInsertRawRequest{}),
	CmdBlockInsertRawResponse:                   reflect.TypeOf(BlockInsertRawResponse{}),
	CmdBlockDownloadAsyncRequest:                reflect.TypeOf(BlockDownloadAsyncRequest{}),
	CmdBlockDownloadAsyncResponse:               reflect.TypeOf(BlockDownloadAsyncResponse{}),
	CmdBlockDownloadAsyncRawRequest:             reflect.TypeOf(BlockDownloadAsyncRawRequest{}),
	CmdBlockDownloadAsyncRawResponse:            reflect.TypeOf(BlockDownloadAsyncRawResponse{}),
	CmdBlocksByL2AbrevHashesRequest:             reflect.TypeOf(BlocksByL2AbrevHashesRequest{}),
	CmdBlocksByL2AbrevHashesResponse:            reflect.TypeOf(BlocksByL2AbrevHashesResponse{}),
	CmdKeystoneTxsByL2KeystoneAbrevHashRequest:  reflect.TypeOf(KeystoneTxsByL2KeystoneAbrevHashRequest{}),
	CmdKeystoneTxsByL2KeystoneAbrevHashResponse: reflect.TypeOf(KeystoneTxsByL2KeystoneAbrevHashResponse{}),
	CmdFeeEstimateRequest:                       reflect.TypeOf(FeeEstimateRequest{}),
	CmdFeeEstimateResponse:                      reflect.TypeOf(FeeEstimateResponse{}),
	CmdMempoolInfoRequest:                       reflect.TypeOf(MempoolInfoRequest{}),
	CmdMempoolInfoResponse:                      reflect.TypeOf(MempoolInfoResponse{}),
	CmdKeystonesByHeightRequest:                 reflect.TypeOf(KeystonesByHeightRequest{}),
	CmdKeystonesByHeightResponse:                reflect.TypeOf(KeystonesByHeightResponse{}),
}

type tbcAPI struct{}

func (a *tbcAPI) Commands() map[protocol.Command]reflect.Type {
	return commands
}

func APICommands() map[protocol.Command]reflect.Type {
	return maps.Clone(commands)
}

// Write is the low level primitive of a protocol Write. One should generally
// not use this function and use WriteConn and Call instead.
func Write(ctx context.Context, c protocol.APIConn, id string, payload any) error {
	return protocol.Write(ctx, c, &tbcAPI{}, id, payload)
}

// Read is the low level primitive of a protocol Read. One should generally
// not use this function and use ReadConn instead.
func Read(ctx context.Context, c protocol.APIConn) (protocol.Command, string, any, error) {
	return protocol.Read(ctx, c, &tbcAPI{})
}

// Call is a blocking call. One should use ReadConn when using Call or else the
// completion will end up in the Read instead of being completed as expected.
func Call(ctx context.Context, c *protocol.Conn, payload any) (protocol.Command, string, any, error) {
	return c.Call(ctx, &tbcAPI{}, payload)
}

// WriteConn writes to Conn. It is equivalent to Write but exists for symmetry
// reasons.
func WriteConn(ctx context.Context, c *protocol.Conn, id string, payload any) error {
	return c.Write(ctx, &tbcAPI{}, id, payload)
}

// ReadConn reads from Conn and performs callbacks. One should use ReadConn over
// Read when mixing Write, WriteConn and Call.
func ReadConn(ctx context.Context, c *protocol.Conn) (protocol.Command, string, any, error) {
	return c.Read(ctx, &tbcAPI{})
}
