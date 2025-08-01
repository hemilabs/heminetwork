// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package blockstream implements [gozer.Gozer] and retrieves Bitcoin data from
// Blockstream (https://blockstream.info/).
package blockstream

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/v2/cmd/btctool/httpclient"
)

var (
	bsMainnetURL  = "https://blockstream.info/api"
	bsTestne3tURL = "https://blockstream.info/testnet/api"
)

// blockstreamGozer implements [gozer.Gozer] and retrieves Bitcoin data from
// Blockstream.
type blockstreamGozer struct {
	url string
}

var _ gozer.Gozer = (*blockstreamGozer)(nil)

func (bs *blockstreamGozer) Connected() bool {
	return true // XXX should we try to connect first?
}

func (bs *blockstreamGozer) BestHeightHashTime(ctx context.Context) (uint64, *chainhash.Hash, time.Time, error) {
	var timestamp time.Time
	u := fmt.Sprintf("%v/blocks/tip/hash", bs.url)
	rawHash, err := httpclient.Request(ctx, "GET", u, nil)
	if err != nil {
		return 0, nil, timestamp, fmt.Errorf("request: %w", err)
	}
	hash, err := chainhash.NewHashFromStr(string(rawHash))
	if err != nil {
		return 0, nil, timestamp, err
	}

	u = fmt.Sprintf("%v/block/%v", bs.url, hash)
	blockInfo, err := httpclient.Request(ctx, "GET", u, nil)
	if err != nil {
		return 0, nil, timestamp, fmt.Errorf("request: %w", err)
	}

	var bi map[string]any
	err = json.Unmarshal(blockInfo, &bi)
	if err != nil {
		return 0, nil, timestamp, err
	}
	if t, ok := bi["timestamp"]; ok {
		if ts, ok := t.(float64); ok && ts > 0 {
			timestamp = time.Unix(int64(ts), 0)
		} else {
			return 0, nil, timestamp, fmt.Errorf("invalid timestamp")
		}
	} else {
		return 0, nil, timestamp, fmt.Errorf("invalid timestamp")
	}
	if h, ok := bi["height"]; ok {
		if height, ok := h.(float64); ok && height >= 0 {
			return uint64(height), hash, timestamp, nil
		}
	}

	return 0, nil, time.Time{}, fmt.Errorf("invalid height")
}

func (bs *blockstreamGozer) FeeEstimates(ctx context.Context) ([]*tbcapi.FeeEstimate, error) {
	u := fmt.Sprintf("%v/fee-estimates", bs.url)
	feeEstimates, err := httpclient.Request(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	fm := make(map[uint]float64, len(u))
	err = json.Unmarshal(feeEstimates, &fm)
	if err != nil {
		return nil, err
	}

	frv := make([]*tbcapi.FeeEstimate, 0, len(fm))
	for k, v := range fm {
		frv = append(frv, &tbcapi.FeeEstimate{Blocks: k, SatsPerByte: v})
	}

	return frv, nil
}

func (bs *blockstreamGozer) BroadcastTx(ctx context.Context, tx *wire.MsgTx) (*chainhash.Hash, error) {
	u := fmt.Sprintf("%v/tx", bs.url)

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}
	hexTx := hex.EncodeToString(buf.Bytes())

	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
		strings.NewReader(hexTx))
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request: %v %v",
			resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	respb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	txidBytes, err := hex.DecodeString(string(respb))
	if err != nil {
		return nil, err
	}
	slices.Reverse(txidBytes)

	txidHash, err := chainhash.NewHash(txidBytes)
	if err != nil {
		return nil, err
	}

	return txidHash, nil
}

func (bs *blockstreamGozer) UtxosByAddress(ctx context.Context, filterMempool bool, addr btcutil.Address, start, count uint) ([]*tbcapi.UTXO, error) {
	u := fmt.Sprintf("%v/address/%v/utxo", bs.url, addr)
	utxos, err := httpclient.Request(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	// XXX figure out if we need to set ot do something with filterMempool here
	type statusJSON struct {
		Confirmed   bool           `json:"confirmed"`
		BlockHeight uint64         `json:"block_height"`
		BlockHash   chainhash.Hash `json:"block_hash"`
		BlockTime   int64          `json:"block_time"`
	}
	type utxosJSON struct {
		TxId   chainhash.Hash `json:"txid"`
		Vout   uint32         `json:"vout"`
		Value  btcutil.Amount `json:"value"`
		Status statusJSON     `json:"status"`
	}
	var uj []utxosJSON
	err = json.Unmarshal(utxos, &uj)
	if err != nil {
		return nil, err
	}

	urv := make([]*tbcapi.UTXO, 0, len(uj))
	for _, v := range uj {
		if !v.Status.Confirmed {
			continue
		}
		urv = append(urv, &tbcapi.UTXO{
			TxId:     v.TxId,
			OutIndex: v.Vout,
			Value:    v.Value,
		})
	}
	return urv, nil
}

func (bs *blockstreamGozer) BlocksByL2AbrevHashes(ctx context.Context, hashes []chainhash.Hash) *gozer.BlocksByL2AbrevHashesResponse {
	return &gozer.BlocksByL2AbrevHashesResponse{
		Error: protocol.Errorf("not supported yet"),
	}
}

func (bs *blockstreamGozer) KeystonesByHeight(ctx context.Context, height uint32, depth int) (*gozer.KeystonesByHeightResponse, error) {
	err := errors.New("not supported yet")
	return &gozer.KeystonesByHeightResponse{
		Error: protocol.Errorf("%v", err),
	}, err
}

func (bs *blockstreamGozer) Run(_ context.Context, _ func()) error {
	return nil
}

// New returns a new Blockstream Gozer.
func New(params *chaincfg.Params) (gozer.Gozer, error) {
	bs := &blockstreamGozer{}
	switch params {
	case &chaincfg.MainNetParams:
		bs.url = bsMainnetURL
	case &chaincfg.TestNet3Params:
		bs.url = bsTestne3tURL
	default:
		// XXX blockstream does not currently support testnet4
		return nil, errors.New("invalid net")
	}
	return bs, nil
}
