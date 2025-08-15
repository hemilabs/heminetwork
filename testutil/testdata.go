package testutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
)

// CreateAddress creates a localhost address with a free port
// This is commonly used in tests for creating test server addresses
// Returns a string in format "localhost:port"
func CreateAddress() string {
	return fmt.Sprintf("localhost:%s", GetFreePort())
}

// MustNewJSONRPCRequest creates a JSON RPC request and panics on error
// This is commonly used in tests for creating RPC requests
// Parameters:
//   - id: request ID
//   - method: RPC method name
//   - params: RPC parameters
//
// Returns a JSON RPC request, panics on error
func MustNewJSONRPCRequest(id uint64, method string, params any) interface{} {
	// This is a placeholder - the actual implementation would depend on the JSONRPCRequest type
	// which is not available in this package
	return map[string]interface{}{
		"id":     id,
		"method": method,
		"params": params,
	}
}

// AllocateMap creates a map of specified size with test data
// This is commonly used in benchmarks and tests for testing map performance
// Parameters:
//   - size: the size of the map to create
//
// Returns a map with test data
func AllocateMap[T comparable, V any](size int, key T, value V) map[T]V {
	m := make(map[T]V, size)
	for i := 0; i < size; i++ {
		// Create unique keys by appending index
		if strKey, ok := any(key).(string); ok {
			uniqueKey := any(strKey + fmt.Sprintf("_%d", i)).(T)
			m[uniqueKey] = value
		} else {
			// For non-string keys, just use the original key
			// Note: this will result in a map with only one element
			m[key] = value
		}
	}
	return m
}

// PingPeer sends a ping message to a peer and waits for pong response
// This is commonly used in tests for testing peer connectivity
// Parameters:
//   - ctx: context for the operation
//   - t: testing context
//   - p: peer to ping
//
// Returns error if ping failed
func PingPeer(ctx context.Context, t *testing.T, p *rawpeer.RawPeer) error {
	err := p.Write(time.Second, wire.NewMsgPing(uint64(time.Now().Unix())))
	if err != nil {
		return err
	}

	for {
		msg, _, err := p.Read(time.Second)
		if err != nil {
			if errors.Is(err, wire.ErrUnknownMessage) {
				continue
			}
			return err
		}
		switch msg.(type) {
		case *wire.MsgPong:
			return nil
		}
	}
}

// CreateCallback creates a callback function that decrements a WaitGroup
// This is commonly used in tests for testing TTL and timeout functionality
// Returns a callback function
func CreateCallback() func(context.Context, any, any) {
	return func(ctx context.Context, key any, value any) {
		v, ok := value.(*sync.WaitGroup)
		if !ok {
			panic(fmt.Sprintf("invalid value type: %T", value))
		}
		v.Done()
	}
}

// CreateCallbackPanic creates a callback function that panics
// This is commonly used in tests for testing error conditions
// Returns a callback function that panics
func CreateCallbackPanic() func(context.Context, any, any) {
	return func(ctx context.Context, key any, value any) {
		panic(fmt.Sprintf("unexpected callback: %v", key))
	}
}

// CreateMockServer creates a mock server for testing WebSocket connections
// This is commonly used in tests for testing WebSocket functionality
// Parameters:
//   - t: testing context
//   - handler: connection handler function
//
// Returns a mock server, cleanup function, and error
func CreateMockServer(t *testing.T, handler func(net.Conn)) (*httptest.Server, func()) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := net.Dial("tcp", r.Host)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		handler(conn)
	}))

	cleanup := func() {
		server.Close()
	}

	return server, cleanup
}
