// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcgozer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/v2/service/tbc"
	"github.com/hemilabs/heminetwork/v2/testutil"
	"github.com/hemilabs/heminetwork/v2/testutil/mock"
)

func TestTBCGozerConnection(t *testing.T) {
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

	b := New(fmt.Sprintf("http://%s/v1/ws", tbcCfg.ListenAddress))
	err = b.Run(ctx, nil)
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

	height, _, _, err := b.BestHeightHashTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BTC tip height: %v", height)
}

func TestTBCGozerCalls(t *testing.T) {
	testAddrString := "n2BosBT7DvxWk1tZprk1tR1kyQmXwcv8M8"

	testAddr, err := btcutil.DecodeAddress(testAddrString, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("Failed to decode address: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	kssMap, kssList := testutil.MakeSharedKeystones(10)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	// Create tbc test server with the request handler.
	mtbc := mock.NewMockTBC(ctx, nil, nil, kssMap, btcTip, 100)
	defer mtbc.Shutdown()

	b := New("ws" + strings.TrimPrefix(mtbc.URL(), "http"))
	if err = b.Run(ctx, nil); err != nil {
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

	height, _, _, err := b.BestHeightHashTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BTC tip height: %v", height)

	_, err = b.KeystonesByHeight(ctx, 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
}
