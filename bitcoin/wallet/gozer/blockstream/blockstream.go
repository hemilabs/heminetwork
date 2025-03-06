// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

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

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/cmd/btctool/httpclient"
)

var (
	bsMainnetURL  = "https://blockstream.info/api"
	bsTestne3tURL = "https://blockstream.info/testnet/api"
)

type blockstream struct {
	url string
}

var _ gozer.Gozer = (*blockstream)(nil)

func (bs *blockstream) FeeEstimates(ctx context.Context) ([]gozer.FeeEstimate, error) {
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

	frv := make([]gozer.FeeEstimate, 0, len(fm))
	for k, v := range fm {
		frv = append(frv, gozer.FeeEstimate{Blocks: k, SatsPerByte: v})
	}

	return frv, nil
}

func (bs *blockstream) BroadcastTx(ctx context.Context, tx *wire.MsgTx) (*chainhash.Hash, error) {
	u := fmt.Sprintf("%v/tx", bs.url)

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}
	hexTx := hex.EncodeToString(buf.Bytes())

	resp, err := http.Post(u, "text/plain",
		strings.NewReader(hexTx))
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

func (bs *blockstream) UtxosByAddress(ctx context.Context, addr btcutil.Address, start, count uint) ([]*tbcapi.UTXO, error) {
	u := fmt.Sprintf("%v/address/%v/utxo", bs.url, addr)
	utxos, err := httpclient.Request(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

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

func (bs *blockstream) BlockKeystoneByL2KeystoneAbrevHash(ctx context.Context, hash *chainhash.Hash) (*gozer.BlockKeystoneByL2KeystoneAbrevHashResponse, error) {
	return nil, fmt.Errorf("not supported yet")
}

func BlockstreamNew(params *chaincfg.Params) (gozer.Gozer, error) {
	bs := &blockstream{}
	switch params {
	case &chaincfg.MainNetParams:
		bs.url = bsMainnetURL
	case &chaincfg.TestNet3Params:
		bs.url = bsTestne3tURL
	default:
		return nil, errors.New("invalid net")
	}
	return bs, nil
}
