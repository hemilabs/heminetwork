// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bssapi

import (
	"context"
	"fmt"
	"maps"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/common"

	"github.com/hemilabs/heminetwork/api"
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

type PopPayout struct {
	MinerAddress common.Address `json:"miner_address"`
	Amount       *big.Int       `json:"amount"`
}

type PopPayoutsRequest struct {
	L2BlockForPayout api.ByteSlice `json:"l2_block_for_payout"`
	Page             uint32        `json:"page,omitempty"`

	// these are unused at this point, they will be used in the future to determine the
	// total payout to miners
	PopDifficultyNumerator   uint64 `json:"popDifficultyNumerator,omitempty"`
	PopDifficultyDenominator uint64 `json:"popDifficultyDenominator,omitempty"`
}

type PopPayoutsResponse struct {
	PopPayouts []PopPayout `json:"pop_payouts"`

	// unused for now
	PopScore uint64 `json:"pop_score,omitempty"`

	Error *protocol.Error `json:"error,omitempty"`
}

type L2KeystoneRequest struct {
	L2Keystone hemi.L2Keystone
}

type L2KeystoneResponse struct {
	Error *protocol.Error `json:"error,omitempty"`
}

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
	CmdPopPayoutRequest                     protocol.Command = "bssapi-pop-payout-request"
	CmdPopPayoutResponse                    protocol.Command = "bssapi-pop-payout-response"
	CmdL2KeystoneRequest                    protocol.Command = "bssapi-l2-keystone-request"
	CmdL2KeystoneResponse                   protocol.Command = "bssapi-l2-keystone-response"
	CmdBTCFinalityByRecentKeystonesRequest  protocol.Command = "bssapi-btc-finality-by-recent-keystones-request"
	CmdBTCFinalityByRecentKeystonesResponse protocol.Command = "bssapi-btc-finality-by-recent-keystones-response"
	CmdBTCFinalityByKeystonesRequest        protocol.Command = "bssapi-btc-finality-by-keystones-request"
	CmdBTCFinalityByKeystonesResponse       protocol.Command = "bssapi-btc-finality-by-keystones-response"
	CmdBTCFinalityNotification              protocol.Command = "bssapi-btc-finality-notification"
	CmdBTCNewBlockNotification              protocol.Command = "bssapi-btc-new-block-notification"
)

// commands contains the command key and type. This is used during RPC calls.
var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:                          reflect.TypeOf(PingRequest{}),
	CmdPingResponse:                         reflect.TypeOf(PingResponse{}),
	CmdPopPayoutRequest:                     reflect.TypeOf(PopPayoutsRequest{}),
	CmdPopPayoutResponse:                    reflect.TypeOf(PopPayoutsResponse{}),
	CmdL2KeystoneRequest:                    reflect.TypeOf(L2KeystoneRequest{}),
	CmdL2KeystoneResponse:                   reflect.TypeOf(L2KeystoneResponse{}),
	CmdBTCFinalityByRecentKeystonesRequest:  reflect.TypeOf(BTCFinalityByRecentKeystonesRequest{}),
	CmdBTCFinalityByRecentKeystonesResponse: reflect.TypeOf(BTCFinalityByRecentKeystonesResponse{}),
	CmdBTCFinalityByKeystonesRequest:        reflect.TypeOf(BTCFinalityByKeystonesRequest{}),
	CmdBTCFinalityByKeystonesResponse:       reflect.TypeOf(BTCFinalityByKeystonesResponse{}),
	CmdBTCFinalityNotification:              reflect.TypeOf(BTCFinalityNotification{}),
	CmdBTCNewBlockNotification:              reflect.TypeOf(BTCNewBlockNotification{}),
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
