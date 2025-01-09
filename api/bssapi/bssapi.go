// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bssapi

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/hemi"
)

const (
	APIVersion = 1
)

var (
	APIVersionRoute         = fmt.Sprintf("v%d", APIVersion)
	RouteWebsocket          = fmt.Sprintf("/%s/ws", APIVersionRoute)
	DefaultListen           = "localhost:8081"
	DefaultPrometheusListen = "localhost:2112"
	DefaultURL              = "ws://" + DefaultListen + RouteWebsocket
)

type OptimismKeystone hemi.L2Keystone // dop only

// Websocket stuff follows.

type (
	PingRequest  protocol.PingRequest
	PingResponse protocol.PingResponse
)

type BTCFinalityByRecentKeystonesRequest struct {
	NumRecentKeystones uint32 `json:"num_recent_keystones"`
}

type BTCFinalityByRecentKeystonesResponse struct {
	L2BTCFinalities []hemi.L2BTCFinality `json:"l2_btc_finalities"`
	Error           *protocol.Error      `json:"error,omitempty"`
}

type BTCFinalityByKeystonesRequest struct {
	L2Keystones []hemi.L2Keystone `json:"l2_keystones"`
	Page        uint32            `json:"page,omitempty"`
	Limit       uint32            `json:"limit,omitempty"`
}

type BTCFinalityByKeystonesResponse struct {
	L2BTCFinalities []hemi.L2BTCFinality `json:"l2_btc_finalities"`
	Error           *protocol.Error      `json:"error,omitempty"`
}

type BTCFinalityNotification struct{}

type BTCNewBlockNotification struct{}

const (
	// Generic RPC commands
	CmdPingRequest  = "bssapi-ping-request"
	CmdPingResponse = "bssapi-ping-response"

	// Custom RPC commands
	CmdBTCFinalityByRecentKeystonesRequest  protocol.Command = "bssapi-btc-finality-by-recent-keystones-request"
	CmdBTCFinalityByRecentKeystonesResponse protocol.Command = "bssapi-btc-finality-by-recent-keystones-response"
	CmdBTCFinalityByKeystonesRequest        protocol.Command = "bssapi-btc-finality-by-keystones-request"
	CmdBTCFinalityByKeystonesResponse       protocol.Command = "bssapi-btc-finality-by-keystones-response"
	CmdBTCFinalityNotification              protocol.Command = "bssapi-btc-finality-notification"
)

// commands contains the command key and type. This is used during RPC calls.
var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:                          reflect.TypeOf(PingRequest{}),
	CmdPingResponse:                         reflect.TypeOf(PingResponse{}),
	CmdBTCFinalityByRecentKeystonesRequest:  reflect.TypeOf(BTCFinalityByRecentKeystonesRequest{}),
	CmdBTCFinalityByRecentKeystonesResponse: reflect.TypeOf(BTCFinalityByRecentKeystonesResponse{}),
	CmdBTCFinalityByKeystonesRequest:        reflect.TypeOf(BTCFinalityByKeystonesRequest{}),
	CmdBTCFinalityByKeystonesResponse:       reflect.TypeOf(BTCFinalityByKeystonesResponse{}),
	CmdBTCFinalityNotification:              reflect.TypeOf(BTCFinalityNotification{}),
}

// apiCmd is an empty structure used to satisfy the protocol.API interface.
type apiCmd struct{}

// Commands satisfies the protocol.API interface.
func (a *apiCmd) Commands() map[protocol.Command]reflect.Type {
	return commands
}

func APICommands() map[protocol.Command]reflect.Type {
	return maps.Clone(commands)
}

// Read reads a command from an APIConn. This is used server side.
func Read(ctx context.Context, c protocol.APIConn) (protocol.Command, string, any, error) {
	return protocol.Read(ctx, c, &apiCmd{})
}

// Write writes a command to an APIConn. This is used server side.
func Write(ctx context.Context, c protocol.APIConn, id string, payload any) error {
	return protocol.Write(ctx, c, &apiCmd{}, id, payload)
}

// Call executes a blocking RPC call. Note that this requires the client to
// provide a ReadConn in a for loop in order to receive commands. This may be
// fixed in the future but seems simple enough to just leave alone for now. The
// need for the ReadConn loop is because apiCmd is not exported.
func Call(ctx context.Context, c *protocol.Conn, payload any) (protocol.Command, string, any, error) {
	return c.Call(ctx, &apiCmd{}, payload)
}

// ReadConn reads a command from a protocol.Conn. This is used client side.
func ReadConn(ctx context.Context, c *protocol.Conn) (protocol.Command, string, any, error) {
	return c.Read(ctx, &apiCmd{})
}

// WriteConn writes a command to a protocol.Conn. This is used client side.
func WriteConn(ctx context.Context, c *protocol.Conn, id string, payload any) error {
	return c.Write(ctx, &apiCmd{}, id, payload)
}
