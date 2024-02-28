package btctool

import (
	"context"
	"fmt"

	"github.com/hemilabs/heminetwork/cmd/btctool/bdf"
	"github.com/hemilabs/heminetwork/cmd/btctool/blockstream"
	"github.com/juju/loggo"
)

var log = loggo.GetLogger("btctool")

func GetAndStoreBlockHeader(ctx context.Context, height int, dir string) (string, error) {
	hash, err := blockstream.BlockHeightHash(ctx, fmt.Sprintf("%v", height))
	if err != nil {
		return "", fmt.Errorf("BlockHeightHash %v: %v", height, err)
	}

	header, err := blockstream.BlockHeader(ctx, hash)
	if err != nil {
		return "", fmt.Errorf("BlockHeader %v: %v", hash, err)
	}

	// Write header
	err = bdf.WriteHeader(height, header, dir)
	if err != nil {
		return "", fmt.Errorf("WriteHeight: %v", err)
	}

	return hash, nil
}
