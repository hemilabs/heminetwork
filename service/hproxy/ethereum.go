// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type Proxy interface {
	Poke(ctx context.Context) error
}

type EthereumProxy struct {
	f func(ctx context.Context) error
}

var _ Proxy = EthereumProxy{}

const EthereumVersion = "2.0"

// EthereumRequest is a JSON-RPC request object.
// https://www.jsonrpc.org/specification
type EthereumRequest struct {
	Version string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params,omitempty"`
	ID      any    `json:"id"`
}

// EthereumResponse is a JSON-RPC response object.
// https://www.jsonrpc.org/specification
type EthereumResponse struct {
	Version string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error,omitempty"`
	ID      any             `json:"id"`
}

func ethID() string {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func CallEthereum(ctx context.Context, c *http.Client, url, method string, params ...any) (*EthereumResponse, error) {
	ec := EthereumRequest{
		Method:  method,
		Params:  params,
		ID:      ethID(),
		Version: EthereumVersion,
	}
	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(ec); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, b)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	default:
		return nil, errors.New(http.StatusText(resp.StatusCode))
	}

	var res EthereumResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	if res.Version != EthereumVersion {
		return nil, fmt.Errorf("unexpected version: %s", res.Version)
	}
	if res.ID != ec.ID {
		return nil, fmt.Errorf("invalid response id: %s instead of %s",
			res.ID, ec.ID)
	}
	return &res, nil
}

func (e EthereumProxy) Poke(ctx context.Context) error {
	return e.f(ctx)
}

func NewEthereumProxy(f func(ctx context.Context) error) Proxy {
	return &EthereumProxy{f: f}
}
