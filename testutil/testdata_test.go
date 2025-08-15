package testutil

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestCreateAddress(t *testing.T) {
	addr := CreateAddress()
	if addr == "" {
		t.Error("CreateAddress() returned empty string")
	}
	if len(addr) < 10 || addr[:10] != "localhost:" {
		t.Errorf("CreateAddress() = %s, want prefix 'localhost:'", addr)
	}
	// The address should be in format "localhost:port" where port is a number
	if len(addr) <= 10 {
		t.Errorf("CreateAddress() = %s, should have port number", addr)
	}
	t.Logf("Created address: %s", addr)
}

func TestAllocateMap(t *testing.T) {
	size := 10
	key := "test"
	value := 123
	m := AllocateMap(size, key, value)

	if len(m) != size {
		t.Errorf("AllocateMap() returned map of length %d, want %d", len(m), size)
	}

	count := 0
	for _, v := range m {
		if v != value {
			t.Errorf("AllocateMap() value = %d, want %d", v, value)
		}
		count++
	}

	if count != size {
		t.Errorf("AllocateMap() iterated over %d items, want %d", count, size)
	}
}

func TestCreateCallback(t *testing.T) {
	callback := CreateCallback()
	var wg sync.WaitGroup
	wg.Add(1)

	// Test that callback decrements WaitGroup
	callback(context.Background(), "key", &wg)

	// WaitGroup should be done
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Error("WaitGroup was not decremented by callback")
	}
}

func TestCreateCallbackPanic(t *testing.T) {
	callback := CreateCallbackPanic()

	// Test that callback panics
	defer func() {
		if r := recover(); r == nil {
			t.Error("CreateCallbackPanic() did not panic")
		}
	}()

	callback(context.Background(), "test", "value")
}

func TestCreateMockServer(t *testing.T) {
	handler := func(conn net.Conn) {
		// Simple handler that just closes the connection
		conn.Close()
	}

	server, cleanup := CreateMockServer(t, handler)
	defer cleanup()

	if server == nil {
		t.Error("CreateMockServer() returned nil server")
	}

	if server.URL == "" {
		t.Error("CreateMockServer() returned server with empty URL")
	}
}
