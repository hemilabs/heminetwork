package blockstream

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/hemilabs/heminetwork/cmd/btctool/httpclient"
)

var bsURL = "https://blockstream.info/testnet/api" // XXX wrap in structure

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
		return 0, fmt.Errorf("request: %v", err)
	}
	height, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ParseUint: %v", err)
	}

	return int(height), nil
}

func BlockHeader(ctx context.Context, hash string) (string, error) {
	bh, err := httpclient.Request(ctx, "GET", bsURL+"/block/"+hash+"/header", nil)
	if err != nil {
		return "", fmt.Errorf("request: %v", err)
	}
	_, err = hex.DecodeString(string(bh))
	if err != nil {
		return "", fmt.Errorf("DecodeString: %v", err)
	}
	return string(bh), nil
}

func BlockHeightHash(ctx context.Context, height string) (string, error) {
	bh, err := httpclient.Request(ctx, "GET", bsURL+"/block-height/"+height, nil)
	if err != nil {
		return "", fmt.Errorf("request: %v", err)
	}
	_, err = hex.DecodeString(string(bh))
	if err != nil {
		return "", fmt.Errorf("DecodeString: %v", err)
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
		return "", fmt.Errorf("request: %v", err)
	}
	if raw {
		return hex.EncodeToString(b), nil
	}
	return string(b), nil
}
