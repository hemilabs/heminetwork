// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package dashapi

import (
	"context"
	"fmt"
	"reflect"

	"github.com/hemilabs/heminetwork/api/protocol"
)

const (
	APIVersion = 1
)

var (
	APIVersionRoute         = fmt.Sprintf("v%d", APIVersion)
	RouteWebsocket          = fmt.Sprintf("/%s/ws", APIVersionRoute)
	DefaultListen           = "localhost:49153"
	DefaultPrometheusListen = "localhost:2112"
	DefaultURL              = "ws://" + DefaultListen + RouteWebsocket
)

const (
	// Generic RPC commands
	CmdPingRequest  = "dashapi-ping-request"
	CmdPingResponse = "dashapi-ping-response"

	// Custom RPC commands
	CmdHeartbeatRequest  protocol.Command = "dashapi-heartbeat-request"
	CmdHeartbeatResponse protocol.Command = "dashapi-heartbeat-response"
)

type (
	PingRequest  protocol.PingRequest
	PingResponse protocol.PingResponse
)

type HeartbeatRequest struct {
	Timestamp int64 `json:"timestamp"`
}

type HeartbeatResponse struct {
	Error *protocol.Error `json:"error,omitempty"`
}

// commands contains the command key and type. This is used during RPC calls.
var commands = map[protocol.Command]reflect.Type{
	CmdPingRequest:       reflect.TypeOf(PingRequest{}),
	CmdPingResponse:      reflect.TypeOf(PingResponse{}),
	CmdHeartbeatRequest:  reflect.TypeOf(HeartbeatRequest{}),
	CmdHeartbeatResponse: reflect.TypeOf(HeartbeatResponse{}),
}

// apiCmd is an empty structure used to satisfy the protocol.API interface.
type apiCmd struct{}

// Commands satisfies the protocol.API interface.
func (a *apiCmd) Commands() map[protocol.Command]reflect.Type {
	return commands
}

func APICommands() map[protocol.Command]reflect.Type {
	return commands // XXX make copy
}

// Error is the dash protocol error type
type Error protocol.Error

func (e Error) String() string {
	return (protocol.Error)(e).String()
}

func Errorf(msg string, args ...interface{}) *Error {
	return (*Error)(protocol.Errorf(msg, args...))
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
