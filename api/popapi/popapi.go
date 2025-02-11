// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popapi

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

	CmdPingRequest  = "popapi-ping-request"
	CmdPingResponse = "popapi-ping-response"

	CmdL2KeystoneNotification = "popapi-notification"

	CmdL2KeystoneRequest  = "popapi-l2keystone-request"
	CmdL2KeystoneResponse = "popapi-l2keystone-response"
)

var (
	APIVersionRoute = fmt.Sprintf("v%d", APIVersion)
	RouteWebsocket  = fmt.Sprintf("/%s/ws", APIVersionRoute)

	DefaultListen = "localhost:31337"
	DefaultURL    = fmt.Sprintf("ws://%s/%s", DefaultListen, RouteWebsocket)
)

type (
	PingRequest  protocol.PingRequest
	PingResponse protocol.PingResponse
)

type L2KeystoneNotfication struct{}

type L2KeystoneRequest struct {
	Count uint32 `json:"count"`
}

type L2KeystoneResponse struct {
	L2Keystones []*hemi.L2Keystone `json:"keystones"`
	Error       *protocol.Error    `json:"error,omitempty"`
}

var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:  reflect.TypeOf(PingRequest{}),
	CmdPingResponse: reflect.TypeOf(PingResponse{}),

	CmdL2KeystoneNotification: reflect.TypeOf(L2KeystoneNotfication{}),
	CmdL2KeystoneRequest:      reflect.TypeOf(L2KeystoneRequest{}),
	CmdL2KeystoneResponse:     reflect.TypeOf(L2KeystoneResponse{}),
}

type popAPI struct{}

func (a *popAPI) Commands() map[protocol.Command]reflect.Type {
	return commands
}

func APICommands() map[protocol.Command]reflect.Type {
	return maps.Clone(commands)
}

// Write is the low level primitive of a protocol Write. One should generally
// not use this function and use WriteConn and Call instead.
func Write(ctx context.Context, c protocol.APIConn, id string, payload any) error {
	return protocol.Write(ctx, c, &popAPI{}, id, payload)
}

// Read is the low level primitive of a protocol Read. One should generally
// not use this function and use ReadConn instead.
func Read(ctx context.Context, c protocol.APIConn) (protocol.Command, string, any, error) {
	return protocol.Read(ctx, c, &popAPI{})
}

// Call is a blocking call. One should use ReadConn when using Call or else the
// completion will end up in the Read instead of being completed as expected.
func Call(ctx context.Context, c *protocol.Conn, payload any) (protocol.Command, string, any, error) {
	return c.Call(ctx, &popAPI{}, payload)
}

// WriteConn writes to Conn. It is equivalent to Write but exists for symmetry
// reasons.
func WriteConn(ctx context.Context, c *protocol.Conn, id string, payload any) error {
	return c.Write(ctx, &popAPI{}, id, payload)
}

// ReadConn reads from Conn and performs callbacks. One should use ReadConn over
// Read when mixing Write, WriteConn and Call.
func ReadConn(ctx context.Context, c *protocol.Conn) (protocol.Command, string, any, error) {
	return c.Read(ctx, &popAPI{})
}
