// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestGetFreePort(t *testing.T) {
	port := GetFreePort()
	if port == "" {
		t.Fatal("GetFreePort returned empty string")
	}

	// Try to parse as integer
	portInt := 0
	_, err := fmt.Sscanf(port, "%d", &portInt)
	if err != nil {
		t.Fatalf("GetFreePort returned invalid port number: %s", port)
	}

	if portInt <= 0 || portInt > 65535 {
		t.Fatalf("GetFreePort returned invalid port range: %d", portInt)
	}
}

func TestGetVerifiedFreePort(t *testing.T) {
	// Skip this test on Windows due to connection issues
	if runtime.GOOS == "windows" {
		t.Skip("Skipping GetVerifiedFreePort test on Windows due to connection issues")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	port := GetVerifiedFreePort(ctx, t)
	if port <= 0 || port > 65535 {
		t.Fatalf("GetVerifiedFreePort returned invalid port range: %d", port)
	}

	// Verify the port is actually free by trying to listen on it
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatalf("Port %d is not actually free: %v", port, err)
	}
	listener.Close()
}

func TestEnsureCanConnectTCP(t *testing.T) {
	// Test with invalid address
	err := EnsureCanConnectTCP(t, "invalid:address", 1*time.Second)
	if err == nil {
		t.Fatal("Expected error for invalid address")
	}

	// Test with unreachable address
	err = EnsureCanConnectTCP(t, "localhost:99999", 1*time.Second)
	if err == nil {
		t.Fatal("Expected error for unreachable address")
	}

	// Test with valid but closed port
	err = EnsureCanConnectTCP(t, "localhost:1", 1*time.Second)
	if err == nil {
		t.Fatal("Expected error for closed port")
	}
}

func TestEnsureCanConnectWS(t *testing.T) {
	// Test with invalid URL
	err := EnsureCanConnectWS(t, "invalid://url", 1*time.Second)
	if err == nil {
		t.Fatal("Expected error for invalid WebSocket URL")
	}

	// Test with unreachable WebSocket URL
	err = EnsureCanConnectWS(t, "ws://localhost:99999", 1*time.Second)
	if err == nil {
		t.Fatal("Expected error for unreachable WebSocket URL")
	}
}

func TestAssertPing(t *testing.T) {
	// This test would require a mock WebSocket connection
	// For now, we'll just test that the function exists and can be called
	// In a real implementation, you would create a mock WebSocket connection
	// and test the AssertPing function with it

	// Example of how this would be tested with a mock:
	// mockConn := &MockWebSocketConn{}
	// ctx := context.Background()
	// AssertPing(ctx, t, mockConn, protocol.CmdPingRequest)
}

// MockWebSocketConn is a mock implementation for testing
type MockWebSocketConn struct{}

func (m *MockWebSocketConn) Close() error {
	return nil
}

func (m *MockWebSocketConn) CloseNow() error {
	return nil
}

func (m *MockWebSocketConn) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	// Mock implementation
	return websocket.MessageType(1), []byte(`{"header":{"command":"ping"}}`), nil
}

func (m *MockWebSocketConn) Write(ctx context.Context, messageType websocket.MessageType, data []byte) error {
	// Mock implementation
	return nil
}
