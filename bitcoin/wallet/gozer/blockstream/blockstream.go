package blockstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

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

func (bs *blockstream) UtxosByAddress(ctx context.Context, addr btcutil.Address) ([]*tbcapi.UTXO, error) {
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
