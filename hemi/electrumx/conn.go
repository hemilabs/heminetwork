// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package electrumx

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
)

const (
	connPingInterval = 5 * time.Minute
	connPingTimeout  = 5 * time.Second
)

// clientConn is a connection with an ElectrumX server.
type clientConn struct {
	mx sync.Mutex

	conn      net.Conn
	requestID uint64

	closeCh chan struct{}
	onClose func(c *clientConn)
}

// newClientConn returns a new clientConn.
func newClientConn(conn net.Conn, onClose func(c *clientConn)) *clientConn {
	c := &clientConn{
		conn:    conn,
		closeCh: make(chan struct{}),
		onClose: onClose,
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
	if res.Error != nil {
		return nil, RPCError(res.Error.Message)
	}

	if res.ID != reqID {
		if res.ID == 0 {
			// ElectrumX may have sent a request, ignore it and try again.
			// TODO(joshuasing): We should probably handle incoming requests by
			//  having a separate goroutine that handles reading.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			log.Debugf("Received a response from ElectrumX with ID 0, retrying read response...")
			return readResponse(ctx, r, reqID)
		}
		return nil, fmt.Errorf("response ID differs from request ID (%d != %d)", res.ID, reqID)
	}

	return &res, nil
}

// ping writes a ping request to the connection.
func (c *clientConn) ping() error {
	log.Tracef("ping")
	defer log.Tracef("ping exit")

	ctx, cancel := context.WithTimeout(context.Background(), connPingTimeout)
	defer cancel()

	if err := c.call(ctx, "server.ping", nil, nil); err != nil {
		return err
	}

	return nil
}

// pinger pings each connection on a ticker.
func (c *clientConn) pinger() {
	ticker := time.NewTicker(connPingInterval)
	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			log.Debugf("Pinging")
			if err := c.ping(); err != nil {
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

	if c.onClose != nil {
		c.onClose(c)
	}
	if c.closeCh != nil {
		close(c.closeCh)
		c.closeCh = nil
	}
	return c.conn.Close()
}
