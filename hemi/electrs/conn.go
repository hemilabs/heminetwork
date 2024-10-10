// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package electrs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	connPingInterval = 5 * time.Minute
	connPingTimeout  = 5 * time.Second
)

// clientConn is a connection with an Electrs server.
type clientConn struct {
	mx        sync.Mutex
	conn      net.Conn
	requestID uint64

	ctx     context.Context
	cancel  context.CancelFunc
	onClose func(c *clientConn)

	metrics *metrics
}

// newClientConn returns a new clientConn.
func newClientConn(conn net.Conn, metrics *metrics, onClose func(c *clientConn)) *clientConn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &clientConn{
		conn:    conn,
		ctx:     ctx,
		cancel:  cancel,
		onClose: onClose,
		metrics: metrics,
	}

	if metrics != nil {
		metrics.connsOpened.Inc()
		metrics.connsOpen.Inc()
	}

	go c.pinger()
	return c
}

// call writes a request to the server and reads the response.
func (c *clientConn) call(ctx context.Context, method string, params, result any) error {
	log.Tracef("call")
	defer log.Tracef("call exit")

	c.mx.Lock()
	defer c.mx.Unlock()

	if c.conn == nil {
		return net.ErrClosed
	}

	if c.metrics != nil {
		start := time.Now()
		defer func() {
			c.metrics.rpcCallsDuration.With(prometheus.Labels{
				"method": method,
			}).Observe(time.Since(start).Seconds())
		}()
		c.metrics.rpcCallsTotal.With(prometheus.Labels{
			"method": method,
		}).Inc()
	}

	c.requestID++
	req, err := NewJSONRPCRequest(c.requestID, method, params)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if err = writeRequest(ctx, c.conn, req); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	res, err := readResponse(ctx, c.conn, req.ID)
	if err != nil {
		var rpcErr RPCError
		if errors.As(err, &rpcErr) {
			return rpcErr
		}
		return fmt.Errorf("read response: %w", err)
	}

	if result != nil {
		if err = json.Unmarshal(res.Result, &result); err != nil {
			return fmt.Errorf("unmarshal result: %w", err)
		}
	}

	return nil
}

// writeRequest writes a request to the connection.
func writeRequest(_ context.Context, w io.Writer, req *JSONRPCRequest) error {
	log.Tracef("writeRequest")
	defer log.Tracef("writeRequest exit")

	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	b = append(b, byte('\n'))

	if _, err = io.Copy(w, bytes.NewReader(b)); err != nil {
		return err
	}

	return nil
}

// readResponse reads a response from the connection.
func readResponse(ctx context.Context, r io.Reader, reqID uint64) (*JSONRPCResponse, error) {
	log.Tracef("readResponse")
	defer log.Tracef("readResponse exit")

	reader := bufio.NewReader(r)
	b, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	var res JSONRPCResponse
	if err = json.Unmarshal(b, &res); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	if res.Error != "" {
		return nil, RPCError(res.Error)
	}

	if res.ID != reqID {
		if res.ID == 0 {
			// Electrs may have sent a request, ignore it and try again.
			// TODO(joshuasing): We should probably handle incoming requests by
			//  having a separate goroutine that handles reading.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			log.Debugf("Received a response from Electrs with ID 0, retrying read response...")
			return readResponse(ctx, r, reqID)
		}
		return nil, fmt.Errorf("response ID differs from request ID (%d != %d)", res.ID, reqID)
	}

	return &res, nil
}

// ping writes a ping request to the connection.
func (c *clientConn) ping(ctx context.Context) error {
	log.Tracef("ping")
	defer log.Tracef("ping exit")

	ctx, cancel := context.WithTimeout(ctx, connPingTimeout)
	defer cancel()

	if err := c.call(ctx, "server.ping", nil, nil); err != nil {
		return err
	}

	return nil
}

// pinger pings each connection on a ticker.
func (c *clientConn) pinger() {
	ticker := time.NewTicker(connPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			// Connection closed.
			return
		case <-ticker.C:
			log.Debugf("Pinging")
			if err := c.ping(c.ctx); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Errorf("An error occurred while pinging connection: %v", err)
				}
				_ = c.Close()
				return
			}
		}
	}
}

// Close closes the connection.
func (c *clientConn) Close() error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	c.mx.Lock()
	defer c.mx.Unlock()

	if c.conn == nil {
		// Already closed.
		return net.ErrClosed
	}

	if c.onClose != nil {
		c.onClose(c)
	}

	defer c.cancel()
	if err := c.conn.Close(); err != nil {
		return err
	}
	c.conn = nil

	if c.metrics != nil {
		c.metrics.connsClosed.Inc()
		c.metrics.connsOpen.Dec()
	}

	return nil
}
