// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcapi

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	"github.com/hemilabs/heminetwork/api/protocol"
)

const (
	APIVersion = 1

	CmdPingRequest  = "tbcapi-ping-request"
	CmdPingResponse = "tbcapi-ping-response"

	CmdBtcBlockHeaderByHeightRequest  = "tbcapi-btc-block-header-by-height-request"
	CmdBtcBlockHeaderByHeightResponse = "tbcapi-btc-block-header-by-height-response"

	CmdBlockHeadersBestRequest  = "tbcapi-block-headers-best-request"
	CmdBlockHeadersBestResponse = "tbcapi-block-headers-best-response"

	CmdBtcBalanceByAddressRequest  = "tbcapi-btc-balance-by-address-request"
	CmdBtcBalanceByAddressResponse = "tbcapi-btc-balance-by-address-response"

	CmdUtxosByAddressRequest  = "tbcapi-utxos-by-address-request"
	CmdUtxosByAddressResponse = "tbcapi-utxos-by-address-response"

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

type BtcHeader struct {
	Version uint32 `json:"version"`

	// hex encoded byte array
	PrevHash string `json:"prev_hash"`

	// hex encoded byte array
	MerkleRoot string `json:"merkle_root"`

	Timestamp uint64 `json:"timestamp"`

	// hex encoded int
	Bits string `json:"bits"`

	Nonce uint32 `json:"nonce"`
}

type BtcBlockHeader struct {
	Height uint32    `json:"height"`
	NumTx  uint32    `json:"num_tx"`
	Header BtcHeader `json:"header"`
}

type BtcBlockHeaderByHeightRequest struct {
	Height uint32 `json:"height"`
}

type BtcBlockHeaderByHeightResponse struct {
	BlockHeaders [][]byte        `json:"block_headers"`
	Error        *protocol.Error `json:"error,omitempty"`
}

type BlockHeadersBestRequest struct{}

type BlockHeadersBestResponse struct {
	Height       uint64          `json:"height"`
	BlockHeaders [][]byte        `json:"block_headers"`
	Error        *protocol.Error `json:"error,omitempty"`
}

type BtcAddrBalanceRequest struct {
	Address string `json:"address"`
}

type BtcAddrBalanceResponse struct {
	Balance uint64          `json:"balance"`
	Error   *protocol.Error `json:"error,omitempty"`
}

type UtxosByAddressRequest struct {
	Address string `json:"address"`
	Start   uint   `json:"start"`
	Count   uint   `json:"count"`
}

type UtxosByAddressResponse struct {
	Utxos [][]byte        `json:"utxos"`
	Error *protocol.Error `json:"error"`
}

type TxByIdRequest struct {
	TxId [32]byte `json:"tx_id"`
}

type TxByIdResponse struct {
	Tx    []byte          `json:"tx"`
	Error *protocol.Error `json:"error"`
}

var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:                    reflect.TypeOf(PingRequest{}),
	CmdPingResponse:                   reflect.TypeOf(PingResponse{}),
	CmdBtcBlockHeaderByHeightRequest:  reflect.TypeOf(BtcBlockHeaderByHeightRequest{}),
	CmdBtcBlockHeaderByHeightResponse: reflect.TypeOf(BtcBlockHeaderByHeightResponse{}),
	CmdBlockHeadersBestRequest:        reflect.TypeOf(BlockHeadersBestRequest{}),
	CmdBlockHeadersBestResponse:       reflect.TypeOf(BlockHeadersBestResponse{}),
	CmdBtcBalanceByAddressRequest:     reflect.TypeOf(BtcAddrBalanceRequest{}),
	CmdBtcBalanceByAddressResponse:    reflect.TypeOf(BtcAddrBalanceResponse{}),
	CmdUtxosByAddressRequest:          reflect.TypeOf(UtxosByAddressRequest{}),
	CmdUtxosByAddressResponse:         reflect.TypeOf(UtxosByAddressResponse{}),
	CmdTxByIdRequest:                  reflect.TypeOf(TxByIdRequest{}),
	CmdTxByIdResponse:                 reflect.TypeOf(TxByIdResponse{}),
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
