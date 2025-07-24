// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcgozer

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/hemilabs/heminetwork/testutil"
)

func TestTBCGozer(t *testing.T) {
	testAddrString := "n2BosBT7DvxWk1tZprk1tR1kyQmXwcv8M8"

	testAddr, err := btcutil.DecodeAddress(testAddrString, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("Failed to decode address: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	port := testutil.FreePort()

	// Connect tbc service
	tbcCfg := &tbc.Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		LevelDBHome:             t.TempDir(),
		LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 "localnet",
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:18444"},
		ListenAddress:           "localhost:" + port,
	}
	_ = loggo.ConfigureLoggers(tbcCfg.LogLevel)
	s, err := tbc.NewServer(tbcCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	time.Sleep(1 * time.Second)

	b, err := Run(ctx, fmt.Sprintf("http://%s/v1/ws", tbcCfg.ListenAddress), nil)
	if err != nil {
		t.Fatal(err)
	}

	tg, ok := b.(*tbcGozer)
	if !ok {
		t.Fatal("expected gozer to be of type tbcGozer")
	}

	for !tg.Connected() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.Tick(50 * time.Millisecond):
		}
	}
	t.Logf("gozer connected")

	feeEstimates, err := b.FeeEstimates(ctx)
	if err != nil {
		t.Fatal(err)
	}

	feeEstimate, err := gozer.FeeByConfirmations(6, feeEstimates)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(feeEstimate))

	utxos, err := b.UtxosByAddress(ctx, true, testAddr, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("balance %v: %v", testAddr, gozer.BalanceFromUtxos(utxos))

	height, err := b.BtcHeight(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BTC tip height: %v", height)
}
