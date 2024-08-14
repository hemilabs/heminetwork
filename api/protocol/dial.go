//go:build !js && !wasm

package protocol

import "github.com/coder/websocket"

func newDialOptions(opts ConnOptions) *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPHeader: opts.Headers,
	}
}
