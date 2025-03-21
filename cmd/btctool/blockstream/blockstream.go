// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package blockstream

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/hemilabs/heminetwork/cmd/btctool/httpclient"
)

var (
	bsTestnet3URL = "https://blockstream.info/testnet/api"
	bsMainnetURL  = "https://blockstream.info/api"
	bsURL         = bsTestnet3URL
)

func SetNetwork(network string) error {
	switch network {
	case "mainnet":
		bsURL = bsMainnetURL
	case "testnet3":
		bsURL = bsTestnet3URL
	default:
		return fmt.Errorf("invalid network: %v", network)
	}
	return nil
}

type TBlock struct {
	ID                string `json:"id"`
	Height            uint   `json:"height"`
	Version           uint   `json:"version"`
	Timestamp         int64  `json:"timestamp"`
	TxCount           uint   `json:"tx_count"`
	Size              uint   `json:"size"`
	Weight            uint   `json:"weight"`
	MerkleRoot        string `json:"merkle_root"`
	PreviousBlockHash string `json:"previousblockhash"`
	MedianTime        int64  `json:"mediantime"`
	Nonce             uint   `json:"nonce"`
	Bits              uint   `json:"bits"`
	Difficulty        uint   `json:"difficulty"`
}

func Tip(ctx context.Context) (int, error) {
	b, err := httpclient.Request(ctx, "GET", bsURL+"/blocks/tip/height", nil)
	if err != nil {
		return 0, fmt.Errorf("request: %w", err)
	}
	height, err := strconv.ParseInt(string(b), 10, 0)
	if err != nil {
		return 0, fmt.Errorf("parse uint: %w", err)
	}
	if height < 0 {
		return 0, fmt.Errorf("parse uint: unexpected negative value")
	}

	return int(height), nil
}

func BlockHeader(ctx context.Context, hash string) (string, error) {
	bh, err := httpclient.Request(ctx, "GET", bsURL+"/block/"+hash+"/header", nil)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	_, err = hex.DecodeString(string(bh))
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	return string(bh), nil
}

func BlockHeightHash(ctx context.Context, height string) (string, error) {
	bh, err := httpclient.Request(ctx, "GET", bsURL+"/block-height/"+height, nil)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	_, err = hex.DecodeString(string(bh))
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	return string(bh), nil
}

func Block(ctx context.Context, hash string, raw bool) (string, error) {
	suffix := ""
	if raw {
		suffix = "/raw"
	}
	b, err := httpclient.Request(ctx, "GET", bsURL+"/block/"+hash+suffix, nil)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	if raw {
		return hex.EncodeToString(b), nil
	}
	return string(b), nil
}

func BlockBytes(ctx context.Context, hash string) ([]byte, error) {
	suffix := "/raw"
	b, err := httpclient.Request(ctx, "GET", bsURL+"/block/"+hash+suffix, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	return b, nil
}

func Tx(ctx context.Context, hash string, raw bool) (string, error) {
	suffix := ""
	if raw {
		suffix = "/raw"
	}
	b, err := httpclient.Request(ctx, "GET", bsURL+"/tx/"+hash+suffix, nil)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	if raw {
		return hex.EncodeToString(b), nil
	}
	return string(b), nil
}
