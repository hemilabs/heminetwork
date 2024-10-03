// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package electrs

import (
	"context"
	"testing"
	"time"
)

const (
	clientInitialConnections = 2
	clientMaximumConnections = 5
)

var testClientOpts = &ClientOptions{
	InitialConnections: clientInitialConnections,
	MaxConnections:     clientMaximumConnections,
}

func TestConnPool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server := createMockServer(t)
	defer server.Close()

	pool, err := newConnPool("tcp", server.address, testClientOpts, nil)
	if err != nil {
		t.Fatalf("failed to create connPool: %v", err)
	}

	// Ensure initial connections were added to the pool
	if s := pool.size(); s != clientInitialConnections {
		t.Errorf("pool size = %d, want %d", s, clientInitialConnections)
	}

	// Ensure initial connections were established
	for i := range clientInitialConnections {
		select {
		case s := <-server.stateCh:
			if !s {
				t.Errorf("unexpected disconnect")
			}
		case <-ctx.Done():
			t.Fatalf("waiting for initial connection %d: %v", i, ctx.Err())
		}
	}

	// Add more connections to the pool to hit the maximum limit
	for range clientMaximumConnections {
		conn, err := pool.newConn()
		if err != nil {
			t.Errorf("new connection: %v", err)
		}
		pool.freeConn(conn)
	}

	// Ensure pool does not contain more than the maximum number of connections
	if s := pool.size(); s != clientMaximumConnections {
		t.Errorf("pool size = %d, want %d", s, clientMaximumConnections)
	}

	// Ensure extra connections were closed when returned to the pool
	var newConnCount int
	for i := range clientMaximumConnections + clientInitialConnections {
		select {
		case s := <-server.stateCh:
			if !s {
				newConnCount--
				continue
			}
			newConnCount++
		case <-ctx.Done():
			t.Fatalf("waiting for extra connections (%d): %v", i, ctx.Err())
		}
	}
	wantNewConnCount := clientMaximumConnections - clientInitialConnections
	if newConnCount != wantNewConnCount {
		t.Errorf("%d new connections, want %d", newConnCount, wantNewConnCount)
	}

	// Acquire connections from the pool
	poolSize := pool.size()
	removeConns := 2
	for range removeConns {
		conn, err := pool.acquireConn()
		if err != nil {
			t.Errorf("acquire connection: %v", err)
		}

		_ = conn.Close()
		select {
		case <-server.stateCh: // remove close notification
		case <-ctx.Done():
			t.Fatalf("remove close notification: %v", ctx.Err())
		}
	}

	// Ensure connections were removed from the pool
	if s := pool.size(); s != poolSize-removeConns {
		t.Errorf("pool size = %d, want %d", s, poolSize-removeConns)
	}

	poolSize = pool.size()
	if err = pool.Close(); err != nil {
		t.Errorf("failed to close pool: %v", err)
	}

	// Ensure all connections were closed
	for i := range poolSize {
		select {
		case s := <-server.stateCh:
			if s {
				t.Errorf("unexpected connection")
			}
		case <-ctx.Done():
			t.Fatalf("waiting for all connections to close (%d): %v", i, ctx.Err())
		}
	}
}
