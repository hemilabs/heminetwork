// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfgapi

import (
	"context"
	"fmt"
	"reflect"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/hemi"
)

const (
	APIVersion = 1

	CmdPingRequest                          = "bfgapi-ping-request"
	CmdPingResponse                         = "bfgapi-ping-response"
	CmdPopTxForL2BlockRequest               = "bfgapi-pop-txs-for-l2-block-request"
	CmdPopTxForL2BlockResponse              = "bfgapi-pop-txs-for-l2-block-response"
	CmdNewL2KeystonesRequest                = "bfgapi-new-l2-keystones-request"
	CmdNewL2KeystonesResponse               = "bfgapi-new-l2-keystones-response"
	CmdBTCFinalityByRecentKeystonesRequest  = "bfgapi-btc-finality-by-recent-keystones-request"
	CmdBTCFinalityByRecentKeystonesResponse = "bfgapi-btc-finality-by-recent-keystones-response"
	CmdBTCFinalityByKeystonesRequest        = "bfgapi-btc-finality-by-keystones-request"
	CmdBTCFinalityByKeystonesResponse       = "bfgapi-btc-finality-by-keystones-response"
	CmdBTCFinalityNotification              = "bfgapi-btc-finality-notification"
	CmdBTCNewBlockNotification              = "bfgapi-btc-new-block-notification"
	CmdL2KeystonesNotification              = "bfgapi-l2-keystones-notification"
	CmdL2KeystonesRequest                   = "bfgapi-l2-keystones-request"
	CmdL2KeystonesResponse                  = "bfgapi-l2-keystones-response"
	CmdBitcoinBalanceRequest                = "bfgapi-bitcoin-balance-request"
	CmdBitcoinBalanceResponse               = "bfgapi-bitcoin-balance-response"
	CmdBitcoinBroadcastRequest              = "bfgapi-bitcoin-broadcast-request"
	CmdBitcoinBroadcastResponse             = "bfgapi-bitcoin-broadcast-response"
	CmdBitcoinInfoRequest                   = "bfgapi-bitcoin-info-request"
	CmdBitcoinInfoResponse                  = "bfgapi-bitcoin-info-response"
	CmdBitcoinUTXOsRequest                  = "bfgapi-bitcoin-utxos-request"
	CmdBitcoinUTXOsResponse                 = "bfgapi-bitcoin-utxos-response"
	CmdAccessPublicKeyCreateRequest         = "bfgapi-access-public-key-create-request"
	CmdAccessPublicKeyCreateResponse        = "bfgapi-access-public-key-create-response"
	CmdAccessPublicKeyDeleteRequest         = "bfgapi-access-public-key-delete-request"
	CmdAccessPublicKeyDeleteResponse        = "bfgapi-access-public-key-delete-response"
)

var (
	APIVersionRoute         = fmt.Sprintf("v%d", APIVersion)
	RouteWebsocketPrivate   = fmt.Sprintf("/%s/ws/private", APIVersionRoute)
	RouteWebsocketPublic    = fmt.Sprintf("/%s/ws/public", APIVersionRoute)
	DefaultPrivateListen    = "localhost:8080"
	DefaultPublicListen     = "localhost:8383"
	DefaultPrometheusListen = "localhost:2112"
	DefaultPrivateURL       = "ws://" + DefaultPrivateListen + RouteWebsocketPrivate
	DefaultPublicURL        = "ws://" + DefaultPublicListen + RouteWebsocketPublic
	DefaultRequestLimit     = 10000 // XXX this is a bandaid
	DefaultRequestTimeout   = 10    // XXX PNOOMA
)

type AccessPublicKey struct {
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at" deep:"-"`
}

// PingRequest and PingResponse are bfg-specific ping request/replies
type (
	PingRequest  protocol.PingRequest
	PingResponse protocol.PingResponse
)

type NewL2KeystonesRequest struct {
	L2Keystones []hemi.L2Keystone `json:"l2_keystones"`
}

type NewL2KeystonesResponse struct {
	Error *protocol.Error `json:"error,omitempty"`
}

type L2KeystonesRequest struct {
	NumL2Keystones uint64 `json:"num_l2_keystones"`
}

type L2KeystonesResponse struct {
	L2Keystones []hemi.L2Keystone `json:"l2_keystones"`
	Error       *protocol.Error   `json:"error,omitempty"`
}

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

type PopTxsForL2BlockRequest struct {
	L2Block api.ByteSlice `json:"l2_block"`
	Page    uint32        `json:"page,omitempty"`
}

type PopTxsForL2BlockResponse struct {
	PopTxs []PopTx         `json:"pop_txs"`
	Error  *protocol.Error `json:"error,omitempty"`
}

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

type L2KeystonesNotification struct{}

type AccessPublicKeyCreateRequest struct {
	PublicKey string `json:"public_key"` // encoded compressed public key
}

type AccessPublicKeyCreateResponse struct {
	Error *protocol.Error `json:"error,omitempty"`
}

type AccessPublicKeyDeleteRequest struct {
	PublicKey string `json:"public_key"`
}

type AccessPublicKeyDeleteResponse struct {
	Error *protocol.Error `json:"error,omitempty"`
}

type PopTx struct {
	BtcTxId             api.ByteSlice `json:"btc_tx_id"`
	BtcRawTx            api.ByteSlice `json:"btc_raw_tx"`
	BtcHeaderHash       api.ByteSlice `json:"btc_header_hash"`
	BtcTxIndex          *uint64       `json:"btc_tx_index"`
	BtcMerklePath       []string      `json:"btc_merkle_path"`
	PopTxId             api.ByteSlice `json:"pop_tx_id"`
	PopMinerPublicKey   api.ByteSlice `json:"pop_miner_public_key"`
	L2KeystoneAbrevHash api.ByteSlice `json:"l2_keystone_abrev_hash"`
}

var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:                          reflect.TypeOf(PingRequest{}),
	CmdPingResponse:                         reflect.TypeOf(PingResponse{}),
	CmdPopTxForL2BlockRequest:               reflect.TypeOf(PopTxsForL2BlockRequest{}),
	CmdPopTxForL2BlockResponse:              reflect.TypeOf(PopTxsForL2BlockResponse{}),
	CmdNewL2KeystonesRequest:                reflect.TypeOf(NewL2KeystonesRequest{}),
	CmdNewL2KeystonesResponse:               reflect.TypeOf(NewL2KeystonesResponse{}),
	CmdBTCFinalityByRecentKeystonesRequest:  reflect.TypeOf(BTCFinalityByRecentKeystonesRequest{}),
	CmdBTCFinalityByRecentKeystonesResponse: reflect.TypeOf(BTCFinalityByRecentKeystonesResponse{}),
	CmdBTCFinalityByKeystonesRequest:        reflect.TypeOf(BTCFinalityByKeystonesRequest{}),
	CmdBTCFinalityByKeystonesResponse:       reflect.TypeOf(BTCFinalityByKeystonesResponse{}),
	CmdBTCFinalityNotification:              reflect.TypeOf(BTCFinalityNotification{}),
	CmdBTCNewBlockNotification:              reflect.TypeOf(BTCNewBlockNotification{}),
	CmdL2KeystonesNotification:              reflect.TypeOf(L2KeystonesNotification{}),
	CmdL2KeystonesRequest:                   reflect.TypeOf(L2KeystonesRequest{}),
	CmdL2KeystonesResponse:                  reflect.TypeOf(L2KeystonesResponse{}),
	CmdBitcoinBalanceRequest:                reflect.TypeOf(BitcoinBalanceRequest{}),
	CmdBitcoinBalanceResponse:               reflect.TypeOf(BitcoinBalanceResponse{}),
	CmdBitcoinBroadcastRequest:              reflect.TypeOf(BitcoinBroadcastRequest{}),
	CmdBitcoinBroadcastResponse:             reflect.TypeOf(BitcoinBroadcastResponse{}),
	CmdBitcoinInfoRequest:                   reflect.TypeOf(BitcoinInfoRequest{}),
	CmdBitcoinInfoResponse:                  reflect.TypeOf(BitcoinInfoResponse{}),
	CmdBitcoinUTXOsRequest:                  reflect.TypeOf(BitcoinUTXOsRequest{}),
	CmdBitcoinUTXOsResponse:                 reflect.TypeOf(BitcoinUTXOsResponse{}),
	CmdAccessPublicKeyCreateRequest:         reflect.TypeOf(AccessPublicKeyCreateRequest{}),
	CmdAccessPublicKeyCreateResponse:        reflect.TypeOf(AccessPublicKeyCreateResponse{}),
	CmdAccessPublicKeyDeleteRequest:         reflect.TypeOf(AccessPublicKeyDeleteRequest{}),
	CmdAccessPublicKeyDeleteResponse:        reflect.TypeOf(AccessPublicKeyDeleteResponse{}),
}

type bfgAPI struct{}

var protocolAPI = new(bfgAPI)

func (a *bfgAPI) Commands() map[protocol.Command]reflect.Type {
	return commands
}

func APICommands() map[protocol.Command]reflect.Type {
	return commands
}

// Write is the low level primitive of a protocol Write. One should generally
// not use this function and use WriteConn and Call instead.
func Write(ctx context.Context, c protocol.APIConn, id string, payload any) error {
	return protocol.Write(ctx, c, protocolAPI, id, payload)
}

// Read is the low level primitive of a protocol Read. One should generally
// not use this function and use ReadConn instead.
func Read(ctx context.Context, c protocol.APIConn) (protocol.Command, string, any, error) {
	return protocol.Read(ctx, c, protocolAPI)
}

// Call is a blocking call. One should use ReadConn when using Call or else the
// completion will end up in the Read instead of being completed as expected.
func Call(ctx context.Context, c *protocol.Conn, payload any) (protocol.Command, string, any, error) {
	return c.Call(ctx, protocolAPI, payload)
}

// WriteConn writes to Conn. It is equivalent to Write but exists for symmetry
// reasons.
func WriteConn(ctx context.Context, c *protocol.Conn, id string, payload any) error {
	return c.Write(ctx, protocolAPI, id, payload)
}

// ReadConn reads from Conn and performs callbacks. One should use ReadConn over
// Read when mixing Write, WriteConn and Call.
func ReadConn(ctx context.Context, c *protocol.Conn) (protocol.Command, string, any, error) {
	return c.Read(ctx, protocolAPI)
}
