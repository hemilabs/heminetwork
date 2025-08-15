// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.
package testutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/phayes/freeport"
)

// EnsureCanConnectWS attempts to connect to a WebSocket URL with exponential backoff
// until successful or timeout is reached.
// Parameters:
//   - t: testing context
//   - url: WebSocket URL to connect to
//   - timeout: maximum time to attempt connections
//
// Returns error if connection could not be established within timeout.
func EnsureCanConnectWS(t *testing.T, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if testing.Verbose() {
		t.Logf("connecting to %s", url)
	}

	doneCh := make(chan struct{})
	go func() {
		retryCount := 0
		for {
			c, _, err := websocket.Dial(ctx, url, nil)
			if err != nil {
				// retry with exponential backoff
				// Limit maximum delay to 32 seconds (2^5)
				if retryCount > 5 {
					retryCount = 5
				}
				backoffTime := time.Duration(1<<uint(retryCount)) * time.Second
				time.Sleep(backoffTime)
				retryCount++
				continue
			}
			c.CloseNow()
			close(doneCh)
			return
		}
	}()

	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// EnsureCanConnectTCP checks TCP connectivity to address within timeout.
// Parameters:
//   - t: testing context
//   - addr: TCP address to connect to (host:port)
//   - timeout: maximum time to attempt connection
//
// Returns error if connection could not be established.
func EnsureCanConnectTCP(t *testing.T, addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// GetFreePort returns a free TCP port as string.
// Uses the freeport package to find an available port on the system.
// Returns the port number as a string.
// Panics if unable to get a free port.
func GetFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}
	return strconv.Itoa(port)
}

// AssertPing verifies that a WebSocket connection receives the expected ping command.
// Parameters:
//   - ctx: context for the operation
//   - t: testing context
//   - c: WebSocket connection
//   - cmd: expected protocol command
//
// Fails the test if the received command doesn't match the expected one.
func AssertPing(ctx context.Context, t *testing.T, c *websocket.Conn, cmd protocol.Command) {
	var v protocol.Message
	err := wsjson.Read(ctx, c, &v)
	if err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != cmd {
		t.Fatalf("unexpected command: %s", v.Header.Command)
	}
}

// GetVerifiedFreePort returns a free TCP port that has been verified to be available.
// Unlike GetFreePort, this function actually attempts to connect to the port
// to ensure it's truly available.
// Parameters:
//   - ctx: context for the operation
//   - t: testing context
//
// Returns a verified free port number.
func GetVerifiedFreePort(ctx context.Context, t *testing.T) int {
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}

		port, err := freeport.GetFreePort()
		if err != nil {
			t.Fatal(err)
		}

		if _, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", fmt.Sprintf("%d", port)), 1*time.Second); err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				// connection error, port is open
				return port
			}

			t.Fatal(err)
		}
	}
}
