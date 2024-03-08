package electrumx

import (
	"context"
	"testing"
	"time"
)

func TestConnPool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, cleanup := createMockServer(ctx, t)
	defer cleanup()

	pool, err := newConnPool("tcp", server.address,
		clientInitialConnections, clientMaximumConnections)
	if err != nil {
		t.Fatalf("failed to create connPool: %v", err)
	}

	// Ensure initial connections were added to the pool
	if s := pool.size(); s != clientInitialConnections {
		t.Errorf("pool size = %d, want %d", s, clientInitialConnections)
	}

	// Ensure initial connections were established
	for i := 0; i < clientInitialConnections; i++ {
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
	for i := 0; i < clientMaximumConnections; i++ {
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
	// TODO: There has to be a better way of doing this
	var newConnCount int
	for i := 0; i < clientMaximumConnections; i++ {
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
	for i := 0; i < removeConns; i++ {
		conn, err := pool.acquireConn()
		if err != nil {
			t.Errorf("acquire connection: %v", err)
		}
		_ = conn.Close()
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
	// TODO(joshuasing)
}
