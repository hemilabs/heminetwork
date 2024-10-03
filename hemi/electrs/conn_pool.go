// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package electrs

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
)

// connPool represents an electrs connection pool.
type connPool struct {
	network string
	address string
	dialer  net.Dialer

	// max is the maximum number of connections this pool may hold.
	max int

	// poolMx is a mutex used for pool.
	poolMx sync.Mutex

	// pool is a queue used to store pooled connections.
	// TODO(joshuasing): This is used as a basic queue, however there are much
	//  more performant queue implementations that could be used.
	pool []*clientConn

	// metrics contains prometheus collectors used for collecting metrics.
	metrics *metrics
}

// newConnPool creates a new connection pool.
func newConnPool(network, address string, opts *ClientOptions, metrics *metrics) (*connPool, error) {
	if opts.InitialConnections > opts.MaxConnections {
		return nil, errors.New(
			"initial connections must be less than or equal to max connections",
		)
	}

	p := &connPool{
		network: network,
		address: address,
		max:     opts.MaxConnections,
		metrics: metrics,
	}

	// Add initial connections to the pool.
	for range opts.InitialConnections {
		conn, err := p.newConn()
		if err != nil {
			return nil, fmt.Errorf("new initial connection: %w", err)
		}
		p.freeConn(conn)
	}

	return p, nil
}

// newConn creates a connection.
func (p *connPool) newConn() (*clientConn, error) {
	log.Tracef("newConn")
	defer log.Tracef("newConn exit")

	c, err := p.dialer.Dial(p.network, p.address)
	if err != nil {
		return nil, err
	}
	return newClientConn(c, p.metrics, p.onClose), nil
}

// onClose removes a connection from the pool if found.
// This function is called by a connection when it is closed.
func (p *connPool) onClose(conn *clientConn) {
	log.Tracef("onClose")
	defer log.Tracef("onClose exit")

	p.poolMx.Lock()
	// Remove the connection from the pool.
	l := len(p.pool)
	p.pool = slices.DeleteFunc(p.pool, func(c *clientConn) bool {
		return c == conn
	})
	removed := len(p.pool) != l
	p.poolMx.Unlock()

	if p.metrics != nil && removed {
		p.metrics.connsIdle.Dec()
	}
}

// acquireConn returns a connection from the pool.
// If there are no available connections, a new connection will be returned.
func (p *connPool) acquireConn() (*clientConn, error) {
	log.Tracef("acquireConn")
	defer log.Tracef("acquireConn exit")

	var c *clientConn
	p.poolMx.Lock()
	if len(p.pool) > 0 {
		c, p.pool = p.pool[0], p.pool[1:]
	}
	p.poolMx.Unlock()

	if c != nil {
		// Successfully acquired a connection from the pool.
		if c.metrics != nil {
			c.metrics.connsIdle.Dec()
		}
		return c, nil
	}

	// The connection pool is empty, create a new connection.
	var err error
	if c, err = p.newConn(); err != nil {
		return nil, fmt.Errorf("new connection: %w", err)
	}
	return c, nil
}

// freeConn returns a connection to the pool.
// Closed connections must not be returned.
func (p *connPool) freeConn(conn *clientConn) {
	log.Tracef("freeConn")
	defer log.Tracef("freeConn exit")

	if conn == nil {
		return
	}

	p.poolMx.Lock()
	if len(p.pool) >= p.max {
		p.poolMx.Unlock()
		// The connection pool is full, close the connection.
		_ = conn.Close()
		return
	}

	p.pool = append(p.pool, conn)
	p.poolMx.Unlock()
	if p.metrics != nil {
		p.metrics.connsIdle.Inc()
	}
}

// size returns the number of connections in the pool.
func (p *connPool) size() int {
	p.poolMx.Lock()
	defer p.poolMx.Unlock()
	return len(p.pool)
}

// Close closes the connection pool and all stored connections.
func (p *connPool) Close() error {
	p.poolMx.Lock()
	pool := make([]*clientConn, len(p.pool))
	copy(pool, p.pool)
	p.pool = nil
	p.max = 0
	p.poolMx.Unlock()

	for _, c := range pool {
		_ = c.Close()
	}
	return nil
}
