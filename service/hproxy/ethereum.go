// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
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

type EthereumCall struct {
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      uint64 `json:"id"`
	Version string `json:"jsonrpc"`
}

func ethID() uint64 {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(buf)
}

func CallEthereum(ctx context.Context, c *http.Client, url, method string, params []any) ([]byte, error) {
	ec := EthereumCall{
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

	return io.ReadAll(resp.Body)
}

func (e EthereumProxy) Poke(ctx context.Context) error {
	return e.f(ctx)
}

func NewEthereumProxy(f func(ctx context.Context) error) Proxy {
	return &EthereumProxy{f: f}
}
