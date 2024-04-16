// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcapi

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/protocol"
)

const (
	APIVersion = 1

	CmdPingRequest  = "tbcapi-ping-request"
	CmdPingResponse = "tbcapi-ping-response"

	CmdBlockHeadersByHeightRawRequest  = "tbcapi-block-headers-by-height-raw-request"
	CmdBlockHeadersByHeightRawResponse = "tbcapi-block-headers-by-height-raw-response"

	CmdBlockHeadersByHeightRequest  = "tbcapi-block-headers-by-height-request"
	CmdBlockHeadersByHeightResponse = "tbcapi-block-headers-by-height-response"

	CmdBlockHeadersBestRawRequest  = "tbcapi-block-headers-best-raw-request"
	CmdBlockHeadersBestRawResponse = "tbcapi-block-headers-best-raw-response"

	CmdBlockHeadersBestRequest  = "tbcapi-block-headers-best-request"
	CmdBlockHeadersBestResponse = "tbcapi-block-headers-best-response"

	CmdBalanceByAddressRequest  = "tbcapi-balance-by-address-request"
	CmdBalanceByAddressResponse = "tbcapi-balance-by-address-response"

	CmdUtxosByAddressRawRequest  = "tbcapi-utxos-by-address-raw-request"
	CmdUtxosByAddressRawResponse = "tbcapi-utxos-by-address-raw-response"

	CmdUtxosByAddressRequest  = "tbcapi-utxos-by-address-request"
	CmdUtxosByAddressResponse = "tbcapi-utxos-by-address-response"

	CmdTxByIdRawRequest  = "tbcapi-tx-by-id-raw-request"
	CmdTxByIdRawResponse = "tbcapi-tx-by-id-raw-response"

	CmdTxByIdRequest  = "tbcapi-tx-by-id-request"
	CmdTxByIdResponse = "tbcapi-tx-by-id-response"
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

type BlockHeader struct {
	Version    int32  `json:"version"`
	PrevHash   string `json:"prev_hash"`
	MerkleRoot string `json:"merkle_root"`
	Timestamp  int64  `json:"timestamp"`
	Bits       string `json:"bits"`
	Nonce      uint32 `json:"nonce"`
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

type BlockHeadersBestRawRequest struct{}

type BlockHeadersBestRawResponse struct {
	Height       uint64          `json:"height"`
	BlockHeaders []api.ByteSlice `json:"block_headers"`
	Error        *protocol.Error `json:"error,omitempty"`
}

type BlockHeadersBestRequest struct{}

type BlockHeadersBestResponse struct {
	Height       uint64          `json:"height"`
	BlockHeaders []*BlockHeader  `json:"block_headers"`
	Error        *protocol.Error `json:"error,omitempty"`
}

type BalanceByAddressRequest struct {
	Address string `json:"address"`
}

type BalanceByAddressResponse struct {
	Balance uint64          `json:"balance"`
	Error   *protocol.Error `json:"error,omitempty"`
}

type UtxosByAddressRawRequest struct {
	Address string `json:"address"`
	Start   uint   `json:"start"`
	Count   uint   `json:"count"`
}

type UtxosByAddressRawResponse struct {
	Utxos []api.ByteSlice `json:"utxos"`
	Error *protocol.Error `json:"error,omitempty"`
}

type UtxosByAddressRequest struct {
	Address string `json:"address"`
	Start   uint   `json:"start"`
	Count   uint   `json:"count"`
}

type Utxo struct {
	TxId     api.ByteSlice `json:"tx_id"`
	Value    uint64        `json:"value"`
	OutIndex uint32        `json:"out_index"`
}

type UtxosByAddressResponse struct {
	Utxos []Utxo          `json:"utxos"`
	Error *protocol.Error `json:"error,omitempty"`
}

type TxByIdRawRequest struct {
	TxId api.ByteSlice `json:"tx_id"`
}

type TxByIdRawResponse struct {
	Tx    api.ByteSlice   `json:"tx"`
	Error *protocol.Error `json:"error,omitempty"`
}

type TxByIdRequest struct {
	TxId api.ByteSlice `json:"tx_id"`
}

type TxByIdResponse struct {
	Tx    Tx              `json:"tx"`
	Error *protocol.Error `json:"error,omitempty"`
}

type OutPoint struct {
	Hash  api.ByteSlice `json:"hash"`
	Index uint32        `json:"index"`
}

type TxWitness []api.ByteSlice

type TxIn struct {
	PreviousOutPoint OutPoint      `json:"outpoint"`
	SignatureScript  api.ByteSlice `json:"signature_script"`
	Witness          TxWitness     `json:"tx_witness"`
	Sequence         uint32        `json:"sequence"`
}

type TxOut struct {
	Value    int64         `json:"value"`
	PkScript api.ByteSlice `json:"pk_script"`
}

type Tx struct {
	Version  int32    `json:"version"`
	LockTime uint32   `json:"lock_time"`
	TxIn     []*TxIn  `json:"tx_in"`
	TxOut    []*TxOut `json:"tx_out"`
}

var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:                     reflect.TypeOf(PingRequest{}),
	CmdPingResponse:                    reflect.TypeOf(PingResponse{}),
	CmdBlockHeadersByHeightRawRequest:  reflect.TypeOf(BlockHeadersByHeightRawRequest{}),
	CmdBlockHeadersByHeightRawResponse: reflect.TypeOf(BlockHeadersByHeightRawResponse{}),
	CmdBlockHeadersByHeightRequest:     reflect.TypeOf(BlockHeadersByHeightRequest{}),
	CmdBlockHeadersByHeightResponse:    reflect.TypeOf(BlockHeadersByHeightResponse{}),
	CmdBlockHeadersBestRawRequest:      reflect.TypeOf(BlockHeadersBestRawRequest{}),
	CmdBlockHeadersBestRawResponse:     reflect.TypeOf(BlockHeadersBestRawResponse{}),
	CmdBlockHeadersBestRequest:         reflect.TypeOf(BlockHeadersBestRequest{}),
	CmdBlockHeadersBestResponse:        reflect.TypeOf(BlockHeadersBestResponse{}),
	CmdBalanceByAddressRequest:         reflect.TypeOf(BalanceByAddressRequest{}),
	CmdBalanceByAddressResponse:        reflect.TypeOf(BalanceByAddressResponse{}),
	CmdUtxosByAddressRawRequest:        reflect.TypeOf(UtxosByAddressRawRequest{}),
	CmdUtxosByAddressRawResponse:       reflect.TypeOf(UtxosByAddressRawResponse{}),
	CmdUtxosByAddressRequest:           reflect.TypeOf(UtxosByAddressRequest{}),
	CmdUtxosByAddressResponse:          reflect.TypeOf(UtxosByAddressResponse{}),
	CmdTxByIdRawRequest:                reflect.TypeOf(TxByIdRawRequest{}),
	CmdTxByIdRawResponse:               reflect.TypeOf(TxByIdRawResponse{}),
	CmdTxByIdRequest:                   reflect.TypeOf(TxByIdRequest{}),
	CmdTxByIdResponse:                  reflect.TypeOf(TxByIdResponse{}),
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
