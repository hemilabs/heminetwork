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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phayes/freeport"
)

func TestClientConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := createMockServer(t)
	defer server.Close()

	conn, err := net.Dial("tcp", server.address)
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	c := newClientConn(conn, nil)

	tests := []struct {
		name   string
		method string

		wantErr         bool
		wantErrContains string
	}{
		{
			name:   "ping",
			method: "server.ping",
		},
		{
			name:            "response id mismatch",
			method:          "test.mismatch.res-id",
			wantErr:         true,
			wantErrContains: "response ID differs from request ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.call(ctx, tt.method, nil, nil)
			switch {
			case (err != nil) != tt.wantErr:
				t.Errorf("call err = %v, want err %v",
					err, tt.wantErr)
			case err != nil && tt.wantErr:
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("call err = %q, want contains %q",
						err.Error(), tt.wantErrContains)
				}
			}
		})
	}
}

func TestWriteRequest(t *testing.T) {
	tests := []struct {
		name string
		req  *JSONRPCRequest
		want string
	}{
		{
			name: "simple",
			req:  NewJSONRPCRequest(1, "test", nil),
			want: "{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"id\":1}\n",
		},
		{
			name: "with params",
			req: NewJSONRPCRequest(2, "test", map[string]any{
				"test": true,
			}),
			want: "{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"params\":{\"test\":true},\"id\":2}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeRequest(context.Background(), &buf, tt.req); err != nil {
				t.Errorf("writeRequest() err = %v", err)
			}

			if got := buf.String(); got != tt.want {
				t.Errorf("writeRequest() wrote %s, want %s", got, tt.want)
			}
		})
	}
}

func TestReadResponse(t *testing.T) {
	tests := []struct {
		name       string
		reqID      uint64
		writeRes   *JSONRPCResponse
		want       *JSONRPCResponse
		wantErr    bool
		wantErrStr string
	}{
		{
			name:  "simple",
			reqID: 1,
			writeRes: &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      1,
			},
			want: &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      1,
			},
		},
		{
			name:  "response id mismatch",
			reqID: 3,
			writeRes: &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      1,
			},
			wantErr:    true,
			wantErrStr: "response ID differs from request ID (1 != 3)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.writeRes)
			buf := bytes.NewBuffer(b)
			_ = buf.WriteByte('\n')

			res, err := readResponse(context.Background(), buf, tt.reqID)
			switch {
			case (err != nil) != tt.wantErr:
				t.Errorf("readResponse() err = %v, want err %v",
					err, tt.wantErr)
			case err != nil && tt.wantErr:
				if tt.wantErrStr != "" && err.Error() != tt.wantErrStr {
					t.Errorf("readResponse() err = %q, want %q",
						err.Error(), tt.wantErrStr)
				}
			}

			p, _ := json.Marshal(res)
			want, _ := json.Marshal(tt.want)
			if string(p) != string(want) {
				t.Errorf("readResponse() res = %s, want %s",
					string(p), string(want))
			}
		})
	}
}

type mockServer struct {
	address string
	ln      net.Listener
	stateCh chan bool

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func createMockServer(t *testing.T) *mockServer {
	addr := createAddress()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	s := &mockServer{
		address: addr,
		ln:      ln,
		stateCh: make(chan bool, 25),
		stopCh:  make(chan struct{}, 1),
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.stopCh:
				return
			default:
			}

			conn, err := ln.Accept()
			if err != nil {
				continue
			}

			s.wg.Add(1)
			go s.handleConnection(t, conn)
		}
	}()

	return s
}

func (s *mockServer) Close() {
	close(s.stopCh)
	_ = s.ln.Close()
	s.wg.Wait()
	close(s.stateCh)
}

func (s *mockServer) handleConnection(t *testing.T, conn net.Conn) {
	select {
	case s.stateCh <- true:
	default:
	}

	defer func() {
		select {
		case s.stateCh <- false:
		default:
		}

		_ = conn.Close()
		s.wg.Done()
	}()

	t.Logf("Handling connection: %s", conn.RemoteAddr())
	reader := bufio.NewReader(conn)

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		err := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			t.Errorf("failed to set read deadline: %v", err)
			return
		}

		b, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			t.Errorf("failed to read from connection: %v", err)
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(b, &req); err != nil {
			t.Errorf("failed to unmarshal request: %v", err)
			continue
		}

		res := &JSONRPCResponse{}

		if req.Method == "server.ping" {
			res.ID = req.ID
		}

		if req.Method == "test.mismatch.res-id" {
			res.ID = 0x4a6f73687561
		}

		if res.ID != 0 {
			b, err = json.Marshal(res)
			if err != nil {
				t.Errorf("failed to marshal response: %v", err)
				continue
			}
			b = append(b, '\n')

			_, err = io.Copy(conn, bytes.NewReader(b))
			if err != nil {
				t.Errorf("failed to write response: %v", err)
			}
		}
	}
}

func createAddress() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(fmt.Errorf("find free port: %v", err))
	}
	return fmt.Sprintf("localhost:%d", port)
}
