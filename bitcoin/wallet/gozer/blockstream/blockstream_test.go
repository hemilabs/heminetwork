// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package blockstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
)

func mockHttpServer() *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fakeHash := "00000000c5cbf1fcdc75539ac75fe8a98417976e548197355b3e5f6c4e884a17"
		switch {
		case strings.HasPrefix(r.URL.Path, "/address/") && strings.HasSuffix(r.URL.Path, "/utxo"):
			utxos := []map[string]interface{}{
				{
					"txid":  chainhash.Hash{},
					"vout":  1,
					"value": 100000000,
					"status": map[string]interface{}{
						"confirmed":    true,
						"block_height": 1,
						"block_hash":   chainhash.Hash{},
						"block_time":   1,
					},
				},
			}
			resp, err := json.Marshal(utxos)
			if err != nil {
				http.NotFound(w, r)
				break
			}
			w.WriteHeader(http.StatusOK)
			if _, err = w.Write(resp); err != nil {
				panic(err)
			}
		case r.URL.Path == "/fee-estimates":
			response := []byte(`{"1":1.0,"2":1.0,"3":1.0,"4":1.0,"5":1.0,"6":1.0}`)
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(response); err != nil {
				panic(err)
			}
		case r.URL.Path == "/blocks/tip/height":
			response := []byte(`1000`)
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(response); err != nil {
				panic(err)
			}
		case r.URL.Path == "/blocks/tip/hash":
			response := fakeHash
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(response)); err != nil {
				panic(err)
			}
		case r.URL.Path == fmt.Sprintf("/block/%s", fakeHash):
			response := map[string]uint64{"height": uint64(10)}
			b, err := json.Marshal(response)
			if err != nil {
				panic(err)
			}
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(b); err != nil {
				panic(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	return ts
}

func TestBlockstreamGozer(t *testing.T) {
	testAddrString := "n2BosBT7DvxWk1tZprk1tR1kyQmXwcv8M8"

	testAddr, err := btcutil.DecodeAddress(testAddrString, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("Failed to decode address: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// use mock http server rather than blockstream api
	ts := mockHttpServer()
	defer ts.Close()

	// can't use Run() for custom urls
	b := &blockstreamGozer{}
	b.url = ts.URL

	feeEstimates, err := b.FeeEstimates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	feeEstimate, err := gozer.FeeByConfirmations(6, feeEstimates)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(feeEstimate))

	// XXX antonio, is true correct here
	utxos, err := b.UtxosByAddress(ctx, true, testAddr, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("balance %v: %v", testAddr, gozer.BalanceFromUtxos(utxos))

	height, _, err := b.BestHeightHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BTC tip height: %v", height)
}
