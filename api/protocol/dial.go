// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build !js && !wasm

package protocol

import "github.com/coder/websocket"

func newDialOptions(opts ConnOptions) *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPHeader: opts.Headers,
	}
}
