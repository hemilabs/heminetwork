// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcgozer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/api"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
	"github.com/hemilabs/heminetwork/v2/internal/testutil/mock"
	"github.com/hemilabs/heminetwork/v2/service/tbc"
)

func TestTBCGozerConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	// Connect tbc service
	tbcCfg := &tbc.Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		LevelDBHome:             t.TempDir(),
		LogLevel:                "tbcd=INFO:level=INFO:tbcgozer=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 "localnet",
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:18444"},
		ListenAddress:           "127.0.0.1:0",
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

	// Wait for HTTP server to start
	var tbcAddr string
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
		if addr := s.HTTPAddress(); addr != nil {
			tbcAddr = addr.String()
			break
		}
	}

	DefaultRequestTimeout = 10 * time.Second // CI is slow as balls
	b := New(fmt.Sprintf("http://%s/v1/ws", tbcAddr))
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
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Logf("gozer connected")

	height, _, _, err := b.BestHeightHashTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BTC tip height: %v", height)

	// Repeat a bunch of times to test queue depth
	var (
		wg    sync.WaitGroup
		ccMtx sync.Mutex
		cc    int
	)
	qd := DefaultCommandQueueDepth * 100
	for range qd {
		wg.Go(func() {
			h, _, _, err := b.BestHeightHashTime(ctx)
			if err != nil {
				panic(err)
			}
			if height != h {
				panic(fmt.Sprintf("h %v != height %v", h, height))
			}
			ccMtx.Lock()
			cc++
			ccMtx.Unlock()
		})
	}

	wg.Wait()
	if cc != qd {
		t.Fatalf("cc %v != qd %v", cc, qd)
	}
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

	DefaultRequestTimeout = 10 * time.Second // CI is slow as balls
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
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Logf("gozer connected")

	feeEstimates, err := b.FeeEstimates(ctx)
	if err != nil {
		panic(err)
	}

	blocks := uint(6)
	expectedSats := float64(1) // XXX antonio, make this more interesting to test
	feeEstimate, err := gozer.FeeByConfirmations(blocks, feeEstimates)
	if err != nil {
		panic(err)
	}
	if feeEstimate.Blocks != blocks {
		t.Fatalf("got %v, wanted %v", feeEstimate.Blocks, blocks)
	}
	if feeEstimate.SatsPerByte != expectedSats {
		t.Fatalf("got %v, wanted %v", feeEstimate.SatsPerByte, expectedSats)
	}

	expectedAmount, _ := btcutil.NewAmount(0.01)
	utxos, err := b.UtxosByAddress(ctx, true, testAddr, 0, 0)
	if err != nil {
		panic(err)
	}
	if gozer.BalanceFromUtxos(utxos) != expectedAmount {
		t.Fatalf("got %v, wanted %v",
			gozer.BalanceFromUtxos(utxos), expectedAmount)
	}

	expectedHeight := uint64(8) // XXX antonio, make this more interesting
	height, _, _, err := b.BestHeightHashTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if height != expectedHeight {
		t.Fatalf("got %v, wanted %v", height, expectedHeight)
	}

	expectedAbrevs := 0 // XXX WTF is this shit?
	keystones, err := b.KeystonesByHeight(ctx, 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(keystones.L2KeystoneAbrevs) != expectedAbrevs {
		t.Fatalf("got %v, wanted %v",
			len(keystones.L2KeystoneAbrevs), expectedAbrevs)
	}

	// Repeat a bunch of times to test queue depth
	var (
		wg    sync.WaitGroup
		ccMtx sync.Mutex
		cc    int
	)
	qd := DefaultCommandQueueDepth * 100
	for range qd {
		wg.Go(func() {
			fes, err := b.FeeEstimates(ctx)
			if err != nil {
				panic(err)
			}

			fe, err := gozer.FeeByConfirmations(6, fes)
			if err != nil {
				panic(err)
			}
			if fe.Blocks != feeEstimate.Blocks {
				panic(fmt.Sprintf("got %v != wanted %v",
					fe.Blocks, feeEstimate.Blocks))
			}
			if fe.SatsPerByte != feeEstimate.SatsPerByte {
				panic(fmt.Sprintf("got %v != wanted %v",
					fe.SatsPerByte, feeEstimate.SatsPerByte))
			}

			us, err := b.UtxosByAddress(ctx, true, testAddr, 0, 0)
			if err != nil {
				panic(err)
			}
			if len(us) != len(utxos) {
				panic(fmt.Sprintf("got %v != wanted %v",
					len(us), len(utxos)))
			}

			h, _, _, err := b.BestHeightHashTime(ctx)
			if err != nil {
				panic(err)
			}
			if h != height {
				panic(fmt.Sprintf("got %v != wanted %v", h, height))
			}

			ks, err := b.KeystonesByHeight(ctx, 1000, 10)
			if err != nil {
				panic(err)
			}
			if len(ks.L2KeystoneAbrevs) != len(keystones.L2KeystoneAbrevs) {
				panic(fmt.Sprintf("got %v != wanted %v",
					len(ks.L2KeystoneAbrevs),
					len(keystones.L2KeystoneAbrevs)))
			}
			if ks.BTCTipHeight != keystones.BTCTipHeight {
				panic(fmt.Sprintf("got %v != wanted %v",
					ks.BTCTipHeight, keystones.BTCTipHeight))
			}
			ccMtx.Lock()
			cc++
			ccMtx.Unlock()
		})
	}

	wg.Wait()
	if cc != qd {
		t.Fatalf("cc %v != qd %v", cc, qd)
	}
}

func TestTBCGozerMempoolUtxos(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	kssMap, kssList := testutil.MakeSharedKeystones(5)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	mtbc := mock.NewMockTBC(ctx, nil, nil, kssMap, btcTip, 10)
	defer mtbc.Shutdown()

	DefaultRequestTimeout = 10 * time.Second
	b := New("ws" + strings.TrimPrefix(mtbc.URL(), "http"))
	if err := b.Run(ctx, nil); err != nil {
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
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Script used in the test transaction below.
	testScript := []byte{
		0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	}
	opTrueScript := []byte{0x51}
	sh1 := tbcd.NewScriptHashFromScript(testScript)
	sh2 := tbcd.NewScriptHashFromScript(opTrueScript)
	allHashes := []api.ByteSlice{sh1[:], sh2[:]}

	t.Run("empty mempool", func(t *testing.T) {
		resp, err := b.MempoolUtxos(ctx, allHashes)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.UTXOs) != 0 {
			t.Errorf("got %d utxos, want 0", len(resp.UTXOs))
		}
		if len(resp.SpentOutpoints) != 0 {
			t.Errorf("got %d spent, want 0", len(resp.SpentOutpoints))
		}
	})

	// Broadcast a tx to populate the mempool.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.HashH([]byte("funding")),
			Index: 0,
		},
	})
	tx.AddTxOut(wire.NewTxOut(50000, []byte{
		0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	}))
	tx.AddTxOut(wire.NewTxOut(10000, []byte{0x51}))

	if _, err := b.BroadcastTx(ctx, tx); err != nil {
		t.Fatal(err)
	}

	t.Run("after broadcast", func(t *testing.T) {
		resp, err := b.MempoolUtxos(ctx, allHashes)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.UTXOs) != 2 {
			t.Fatalf("got %d utxos, want 2", len(resp.UTXOs))
		}
		if len(resp.SpentOutpoints) != 1 {
			t.Fatalf("got %d spent, want 1", len(resp.SpentOutpoints))
		}

		// Verify values.
		var total btcutil.Amount
		for _, u := range resp.UTXOs {
			total += u.Value
		}
		if total != 60000 {
			t.Errorf("total = %d, want 60000", total)
		}

		// Verify script hashes are non-zero.
		for _, u := range resp.UTXOs {
			var zero chainhash.Hash
			if u.ScriptHash == zero {
				t.Error("script hash is zero")
			}
		}
	})

	t.Run("FilterSpent integration", func(t *testing.T) {
		resp, err := b.MempoolUtxos(ctx, allHashes)
		if err != nil {
			t.Fatal(err)
		}

		// No outputs are spent by another mempool tx, so
		// FilterSpent should return all of them.
		filtered := gozer.FilterSpent(resp.UTXOs, resp.SpentOutpoints)
		if len(filtered) != len(resp.UTXOs) {
			t.Fatalf("FilterSpent: got %d, want %d",
				len(filtered), len(resp.UTXOs))
		}
	})
}
