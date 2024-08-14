//go:build js && wasm

package protocol

import "github.com/coder/websocket"

func newDialOptions(_ ConnOptions) *websocket.DialOptions {
	// HTTPHeader is not supported in WASM, due to the JavaScript WebSocket API
	// not supporting setting HTTP headers for the handshake/initial HTTP
	// request.
	return nil
}
