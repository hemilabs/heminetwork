// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package protocol

import "github.com/coder/websocket"

func newDialOptions(_ ConnOptions) *websocket.DialOptions {
	// HTTPHeader is not supported in WASM, due to the JavaScript WebSocket API
	// not supporting setting HTTP headers for the handshake/initial HTTP
	// request.
	return nil
}
