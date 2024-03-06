// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package electrumx

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

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
			name: "with-params",
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
