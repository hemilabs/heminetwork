// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package twcapi

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

	CmdPingRequest  = "twcapi-ping-request"
	CmdPingResponse = "twcapi-ping-response"

	// CmdBTCNewBlockNotification              = "twcapi-btc-new-block-notification"
	CmdBitcoinBalanceRequest    = "twcapi-bitcoin-balance-request"
	CmdBitcoinBalanceResponse   = "twcapi-bitcoin-balance-response"
	CmdBitcoinBroadcastRequest  = "twcapi-bitcoin-broadcast-request"
	CmdBitcoinBroadcastResponse = "twcapi-bitcoin-broadcast-response"
	CmdBitcoinInfoRequest       = "twcapi-bitcoin-info-request"
	CmdBitcoinInfoResponse      = "twcapi-bitcoin-info-response"
	CmdBitcoinUTXOsRequest      = "twcapi-bitcoin-utxos-request"
	CmdBitcoinUTXOsResponse     = "twcapi-bitcoin-utxos-response"
)

var (
	APIVersionRoute = fmt.Sprintf("v%d", APIVersion)
	RouteWebsocket  = fmt.Sprintf("/%s/ws", APIVersionRoute)

	DefaultListen = "localhost:8083" // XXX confirm port is ok
	DefaultURL    = fmt.Sprintf("ws://%s/%s", DefaultListen, RouteWebsocket)
)

type (
	PingRequest  protocol.PingRequest
	PingResponse protocol.PingResponse
)

// type BTCNewBlockNotification struct{}
type BitcoinBalanceRequest struct {
	ScriptHash api.ByteSlice `json:"script_hash"`
}

type BitcoinBalanceResponse struct {
	Confirmed   uint64          `json:"confirmed"`
	Unconfirmed int64           `json:"unconfirmed"`
	Error       *protocol.Error `json:"error,omitempty"`
}

type BitcoinBroadcastRequest struct {
	Transaction api.ByteSlice `json:"transaction"` // XXX this needs to be plural
}

type BitcoinBroadcastResponse struct {
	TXID  api.ByteSlice   `json:"txid"`
	Error *protocol.Error `json:"error,omitempty"`
}

type BitcoinInfoRequest struct{}

type BitcoinInfoResponse struct {
	Height uint64          `json:"height"`
	Error  *protocol.Error `json:"error,omitempty"`
}
type BitcoinUTXO struct {
	Hash  api.ByteSlice `json:"hash"`
	Index uint32        `json:"index"`
	Value int64         `json:"value"`
}

type BitcoinUTXOsRequest struct {
	ScriptHash api.ByteSlice `json:"script_hash"`
}

type BitcoinUTXOsResponse struct {
	UTXOs []*BitcoinUTXO  `json:"utxos"`
	Error *protocol.Error `json:"error,omitempty"`
}

var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:  reflect.TypeOf(PingRequest{}),
	CmdPingResponse: reflect.TypeOf(PingResponse{}),

	// CmdBTCNewBlockNotification:              reflect.TypeOf(BTCNewBlockNotification{}),
	CmdBitcoinBalanceRequest:    reflect.TypeOf(BitcoinBalanceRequest{}),
	CmdBitcoinBalanceResponse:   reflect.TypeOf(BitcoinBalanceResponse{}),
	CmdBitcoinBroadcastRequest:  reflect.TypeOf(BitcoinBroadcastRequest{}),
	CmdBitcoinBroadcastResponse: reflect.TypeOf(BitcoinBroadcastResponse{}),
	CmdBitcoinInfoRequest:       reflect.TypeOf(BitcoinInfoRequest{}),
	CmdBitcoinInfoResponse:      reflect.TypeOf(BitcoinInfoResponse{}),
	CmdBitcoinUTXOsRequest:      reflect.TypeOf(BitcoinUTXOsRequest{}),
	CmdBitcoinUTXOsResponse:     reflect.TypeOf(BitcoinUTXOsResponse{}),
}

type twcAPI struct{}

func (a *twcAPI) Commands() map[protocol.Command]reflect.Type {
	return commands
}

func APICommands() map[protocol.Command]reflect.Type {
	return maps.Clone(commands)
}

// Write is the low level primitive of a protocol Write. One should generally
// not use this function and use WriteConn and Call instead.
func Write(ctx context.Context, c protocol.APIConn, id string, payload any) error {
	return protocol.Write(ctx, c, &twcAPI{}, id, payload)
}

// Read is the low level primitive of a protocol Read. One should generally
// not use this function and use ReadConn instead.
func Read(ctx context.Context, c protocol.APIConn) (protocol.Command, string, any, error) {
	return protocol.Read(ctx, c, &twcAPI{})
}

// Call is a blocking call. One should use ReadConn when using Call or else the
// completion will end up in the Read instead of being completed as expected.
func Call(ctx context.Context, c *protocol.Conn, payload any) (protocol.Command, string, any, error) {
	return c.Call(ctx, &twcAPI{}, payload)
}

// WriteConn writes to Conn. It is equivalent to Write but exists for symmetry
// reasons.
func WriteConn(ctx context.Context, c *protocol.Conn, id string, payload any) error {
	return c.Write(ctx, &twcAPI{}, id, payload)
}

// ReadConn reads from Conn and performs callbacks. One should use ReadConn over
// Read when mixing Write, WriteConn and Call.
func ReadConn(ctx context.Context, c *protocol.Conn) (protocol.Command, string, any, error) {
	return c.Read(ctx, &twcAPI{})
}
