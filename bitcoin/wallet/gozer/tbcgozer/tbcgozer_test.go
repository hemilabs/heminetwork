// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcgozer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/api"
	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
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
		AutoIndex:       false,
		BlockCacheSize:  "10mb",
		HeaderCacheSize: "1mb",

		LevelDBHome:             t.TempDir(),
		LogLevel:                "tbcd=INFO:level=INFO:tbcgozer=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 "localnet",
		RequestTimeout:          10 * time.Second,
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

func TestTBCGozerAlreadyBroadcast(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	tbcCfg := &tbc.Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		HeaderCacheSize:         "1mb",
		LevelDBHome:             t.TempDir(),
		MaxCachedTxs:            1000,
		Network:                 "localnet",
		RequestTimeout:          10 * time.Second,
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:18444"},
		ListenAddress:           "127.0.0.1:0",
		NotificationBlocking:    true,
	}
	s, err := tbc.NewServer(tbcCfg)
	if err != nil {
		t.Fatal(err)
	}

	// subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// Wait for http service to start up
	var tbcURL string
	for {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(msg)
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		// TBC sends a notification when the http service has started.
		if !msg.Is(tbc.NotificationService("", "")) {
			continue
		}

		if msg.ID != "tbc_http_server" || msg.Msg != "ready" {
			continue
		}

		if addr := s.HTTPAddress(); addr != nil {
			tbcURL = addr.String()
			break
		}
	}
	l.Unsubscribe()

	connChan := make(chan struct{})
	connFunc := func() {
		connChan <- struct{}{}
	}

	DefaultRequestTimeout = 10 * time.Second
	b := New(fmt.Sprintf("http://%s/v1/ws", tbcURL))
	if err = b.Run(ctx, connFunc); err != nil {
		t.Fatal(err)
	}

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-connChan:
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.HashH([]byte("test")),
			Index: 0,
		},
	})
	tx.AddTxOut(wire.NewTxOut(50000, []byte{0x51}))

	// first attempt fails with no peers, but is marked as broadcast by TBC
	if _, err := b.BroadcastTx(ctx, tx); err == nil ||
		!strings.Contains(err.Error(), tbc.ErrTxBroadcastNoPeers.Error()) {
		t.Fatalf("expected error %v, got %v", tbc.ErrTxBroadcastNoPeers, err)
	}

	// second attempt fails with already broadcast
	_, err = b.BroadcastTx(ctx, tx)
	if gErr, ok := errors.AsType[gozer.TxBroadcastError](err); !ok {
		t.Fatalf("expected error %v, got %v", gozer.TxBroadcastError{}, err)
	} else if !gErr.AlreadyBroadcast {
		t.Fatal("expected error to include 'already broadcast' flag")
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
	if feeEstimate.SatsPerVByte != expectedSats {
		t.Fatalf("got %v, wanted %v", feeEstimate.SatsPerVByte, expectedSats)
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
			if fe.SatsPerVByte != feeEstimate.SatsPerVByte {
				panic(fmt.Sprintf("got %v != wanted %v",
					fe.SatsPerVByte, feeEstimate.SatsPerVByte))
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

func TestTBCGozerTxByIDNilTxid(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	kssMap, kssList := testutil.MakeSharedKeystones(10)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	mtbc := mock.NewMockTBC(ctx, nil, nil, kssMap, btcTip, 100)
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
		case <-time.Tick(50 * time.Millisecond):
		}
	}

	_, err := b.TxByID(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil txid")
	}
	if err.Error() != "txid cannot be nil" {
		t.Fatalf("expected 'txid cannot be nil', got: %v", err)
	}
}

func TestTBCGozerTxByIDNotConnected(t *testing.T) {
	b := New("ws://127.0.0.1:0/v1/ws")
	tg := b.(*tbcGozer)

	if tg.Connected() {
		t.Fatal("expected gozer to not be connected")
	}

	txid := chainhash.Hash{0x01}
	_, err := b.TxByID(t.Context(), &txid)
	if err == nil {
		t.Fatal("expected error for not connected")
	}
	if err.Error() != "not connected to tbc" {
		t.Fatalf("expected 'not connected to tbc', got: %v", err)
	}
}

func TestTBCGozerTxByID(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	kssMap, kssList := testutil.MakeSharedKeystones(10)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	mtbc := mock.NewMockTBC(ctx, nil, nil, kssMap, btcTip, 100)
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
		case <-time.Tick(50 * time.Millisecond):
		}
	}

	txid := chainhash.Hash{0xaa, 0xbb, 0xcc}
	tx, err := b.TxByID(ctx, &txid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tx == nil {
		t.Fatal("expected non-nil tx")
	}
	if tx.Version != 2 {
		t.Fatalf("expected version 2, got %v", tx.Version)
	}
	if len(tx.TxIn) != 1 {
		t.Fatalf("expected 1 txin, got %v", len(tx.TxIn))
	}
	if tx.TxIn[0].PreviousOutPoint.Hash != txid {
		t.Fatalf("expected txin outpoint hash to match txid")
	}
	if len(tx.TxOut) != 1 {
		t.Fatalf("expected 1 txout, got %v", len(tx.TxOut))
	}
	if tx.TxOut[0].Value != 50000 {
		t.Fatalf("expected txout value 50000, got %v", tx.TxOut[0].Value)
	}

	// Repeat concurrently to exercise queue depth.
	var (
		wg    sync.WaitGroup
		ccMtx sync.Mutex
		cc    int
	)
	qd := DefaultCommandQueueDepth * 10
	for range qd {
		wg.Go(func() {
			rtx, err := b.TxByID(ctx, &txid)
			if err != nil {
				panic(fmt.Sprintf("TxByID: %v", err))
			}
			if rtx.Version != tx.Version {
				panic(fmt.Sprintf("version %v != %v",
					rtx.Version, tx.Version))
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

func TestTBCGozerTxByIDErrorResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	kssMap, kssList := testutil.MakeSharedKeystones(10)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	mtbc := mock.NewMockTBC(ctx, nil, nil, kssMap, btcTip, 100)
	defer mtbc.Shutdown()

	DefaultRequestTimeout = 10 * time.Second
	b := New("ws" + strings.TrimPrefix(mtbc.URL(), "http"))
	if err := b.Run(ctx, nil); err != nil {
		t.Fatal(err)
	}

	tg := b.(*tbcGozer)
	for !tg.Connected() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.Tick(50 * time.Millisecond):
		}
	}

	// Zero hash triggers error response from mock.
	zeroHash := chainhash.Hash{}
	_, err := b.TxByID(ctx, &zeroHash)
	if err == nil {
		t.Fatal("expected error for zero hash (not-found)")
	}
	if !strings.Contains(err.Error(), "tx not found") {
		t.Fatalf("expected 'tx not found' in error, got: %v", err)
	}
}

func TestTBCGozerTxByIDContextCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	kssMap, kssList := testutil.MakeSharedKeystones(10)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	mtbc := mock.NewMockTBC(ctx, nil, nil, kssMap, btcTip, 100)
	defer mtbc.Shutdown()

	DefaultRequestTimeout = 10 * time.Second
	b := New("ws" + strings.TrimPrefix(mtbc.URL(), "http"))
	if err := b.Run(ctx, nil); err != nil {
		t.Fatal(err)
	}

	tg := b.(*tbcGozer)
	for !tg.Connected() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.Tick(50 * time.Millisecond):
		}
	}

	// Cancel context before calling TxByID.
	cancelledCtx, cancelNow := context.WithCancel(ctx)
	cancelNow()

	txid := chainhash.Hash{0xde, 0xad}
	_, err := b.TxByID(cancelledCtx, &txid)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

// testTBC is a tbcGozer connected to a test TBC server.
type testTBC struct {
	*tbcGozer

	cancel context.CancelFunc // ends the connection context
	conns  atomic.Int32       // connections the server accepted
}

// newTestTBC connects a tbcGozer to a test TBC server.  The server uses
// listener l when it is not nil, sends the ping and then calls serve on each
// connection.
func newTestTBC(t *testing.T, l net.Listener, serve func(context.Context, *websocket.Conn)) *testTBC {
	t.Helper()

	tt := &testTBC{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tt.conns.Add(1)
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(-1)
		ping := &tbcapi.PingRequest{Timestamp: time.Now().Unix()}
		if err := tbcapi.Write(r.Context(), protocol.NewWSConn(c), "0", ping); err != nil {
			return
		}
		serve(r.Context(), c)
	}))
	if l != nil {
		srv.Listener.Close()
		srv.Listener = l
	}
	srv.Start()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(t.Context())
	tt.cancel = cancel
	conn, err := protocol.NewConn("ws"+strings.TrimPrefix(srv.URL, "http"),
		&protocol.ConnOptions{ReadLimit: tbcapi.MaxResponseSize})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Connect(ctx); err != nil {
		t.Fatal(err)
	}

	tt.tbcGozer = &tbcGozer{
		cmdCh:     make(chan tbcCmd, DefaultCommandQueueDepth),
		connected: true,
	}
	tt.wg.Add(2)
	go tt.handleTBCWebsocketRead(ctx, conn)
	go tt.handleTBCWebsocketCall(ctx, conn)
	t.Cleanup(func() {
		cancel()
		tt.wg.Wait()
	})
	return tt
}

// requireOneConn fails when the server accepted more than one connection.
// A new connection means that the old one closed, which failed every
// request in flight on it.
func (tt *testTBC) requireOneConn(t *testing.T) {
	t.Helper()

	if n := tt.conns.Load(); n != 1 {
		t.Fatalf("server accepted %v connections, want 1", n)
	}
}

// newSilentTBC returns a testTBC whose server reads every request and never
// replies, and a channel that carries the command of each request the
// server reads.
func newSilentTBC(t *testing.T) (*testTBC, <-chan protocol.Command) {
	t.Helper()

	reqCh := make(chan protocol.Command, 4*DefaultCommandQueueDepth)
	tt := newTestTBC(t, nil, func(ctx context.Context, c *websocket.Conn) {
		wc := protocol.NewWSConn(c)
		for {
			cmd, _, _, err := tbcapi.Read(ctx, wc)
			if err != nil {
				return
			}
			select {
			case reqCh <- cmd:
			default: // never block the server
			}
		}
	})
	return tt, reqCh
}

// txByIDs starts n TxByID requests with ctx and returns a channel that
// carries the error of each request.  The test joins every caller before
// it ends.
func txByIDs(t *testing.T, tg *tbcGozer, ctx context.Context, n int) <-chan error {
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)

	errCh := make(chan error, n)
	req := &tbcapi.TxByIdRequest{TxID: chainhash.Hash{0xde, 0xad}}
	for range n {
		wg.Go(func() {
			_, err := tg.callTBC(ctx, time.Hour, req)
			errCh <- err
		})
	}
	return errCh
}

// waitRequests waits until the server reads n requests with command cmd,
// and fails when it reads a request with another command.
func waitRequests(t *testing.T, reqCh <-chan protocol.Command, cmd protocol.Command, n int) {
	t.Helper()

	timeout := time.After(10 * time.Second)
	for i := range n {
		select {
		case <-timeout:
			t.Fatalf("server read %v of %v %v requests", i, n, cmd)
		case got := <-reqCh:
			if got != cmd {
				t.Fatalf("server read %v, want %v", got, cmd)
			}
		}
	}
}

// waitErr waits for an error on errCh.
func waitErr(t *testing.T, errCh <-chan error) error {
	t.Helper()

	select {
	case <-time.After(10 * time.Second):
		t.Fatal("caller did not return")
		return nil
	case err := <-errCh:
		return err
	}
}

// TestCallTBCCancelledCallFreesSlot checks that cancelling the callers of
// in-flight requests returns context.Canceled and at once frees their
// worker slots, instead of after the request timeout.
func TestCallTBCCancelledCallFreesSlot(t *testing.T) {
	tt, reqCh := newSilentTBC(t)
	n := DefaultCommandQueueDepth

	// Fill every slot with a request that the server never answers.
	ctx, cancel := context.WithCancel(t.Context())
	errCh := txByIDs(t, tt.tbcGozer, ctx, n)
	waitRequests(t, reqCh, tbcapi.CmdTxByIdRequest, n)

	cancel()
	for range n {
		if err := waitErr(t, errCh); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	}

	// All slots must be free again.
	txByIDs(t, tt.tbcGozer, t.Context(), n)
	waitRequests(t, reqCh, tbcapi.CmdTxByIdRequest, n)
	tt.requireOneConn(t)
}

// TestCallTBCQueuedCancelledNotSent checks that a request whose caller is
// done while it waits for a worker slot is never sent and takes no slot.
func TestCallTBCQueuedCancelledNotSent(t *testing.T) {
	tt, reqCh := newSilentTBC(t)
	n := DefaultCommandQueueDepth

	// Fill every slot with a request that the server never answers.
	ctx, cancel := context.WithCancel(t.Context())
	txByIDs(t, tt.tbcGozer, ctx, n)
	waitRequests(t, reqCh, tbcapi.CmdTxByIdRequest, n)

	// Queue a request for a caller that is done.
	qctx, qcancel := context.WithTimeout(t.Context(), time.Hour)
	qcancel()
	tt.cmdCh <- tbcCmd{
		ctx: qctx,
		msg: &tbcapi.BlockHeaderBestRequest{},
		ch:  make(chan any),
	}

	// Free the slots.  The server must read n new TxByID requests and
	// never the queued request.
	cancel()
	txByIDs(t, tt.tbcGozer, t.Context(), n)
	waitRequests(t, reqCh, tbcapi.CmdTxByIdRequest, n)
	tt.requireOneConn(t)
}

// TestCallTBCConnectionEndFailsCalls checks that every caller with a
// request in flight gets an error at once when the connection ends,
// instead of waiting for its timeout.
func TestCallTBCConnectionEndFailsCalls(t *testing.T) {
	tt, reqCh := newSilentTBC(t)
	n := DefaultCommandQueueDepth

	errCh := txByIDs(t, tt.tbcGozer, t.Context(), n)
	waitRequests(t, reqCh, tbcapi.CmdTxByIdRequest, n)

	tt.cancel()
	for range n {
		if err := waitErr(t, errCh); err == nil {
			t.Fatal("expected an error")
		}
	}
}

// smallBufListener sets a small receive buffer on each connection, so that
// a large message does not fit in the socket buffers.  It keeps the last
// connection, so that the buffer can grow again.
type smallBufListener struct {
	net.Listener

	last atomic.Pointer[net.TCPConn]
}

func (l *smallBufListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		if err := tc.SetReadBuffer(4096); err != nil {
			c.Close()
			return nil, err
		}
		l.last.Store(tc)
	}
	return c, nil
}

// TestCallTBCCancelledWriteKeepsConnection checks that a caller that
// cancels while its request is being written does not close the
// connection, so that the other requests in flight still get replies.
func TestCallTBCCancelledWriteKeepsConnection(t *testing.T) {
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// The server reads the small request, then only the start of the
	// large one, and waits for release.  It then reads the rest of the
	// large request and replies to the small one.
	var (
		smallRead  = make(chan struct{})
		largeStart = make(chan struct{})
		release    = make(chan struct{})
	)
	sl := &smallBufListener{Listener: l}
	tt := newTestTBC(t, sl, func(ctx context.Context, c *websocket.Conn) {
		_, r, err := c.Reader(ctx)
		if err != nil {
			return
		}
		var msg protocol.Message
		if err := json.NewDecoder(r).Decode(&msg); err != nil {
			return
		}
		close(smallRead)

		_, r, err = c.Reader(ctx)
		if err != nil {
			return
		}
		if _, err := io.ReadFull(r, make([]byte, 1024)); err != nil {
			return
		}
		close(largeStart)
		select {
		case <-ctx.Done():
			return
		case <-release:
		}
		// A small buffer makes the rest of the read slow.
		if err := sl.last.Load().SetReadBuffer(4 << 20); err != nil {
			return
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			return
		}

		reply := &tbcapi.TxByIdResponse{Tx: &tbcapi.Tx{Version: 2}}
		if err := tbcapi.Write(ctx, protocol.NewWSConn(c), msg.Header.ID, reply); err != nil {
			return
		}
		<-ctx.Done()
	})
	waitClosed := func(ch <-chan struct{}) {
		t.Helper()
		select {
		case <-time.After(10 * time.Second):
			t.Fatal("server did not read the request")
		case <-ch:
		}
	}

	smallErr := txByIDs(t, tt.tbcGozer, t.Context(), 1)
	waitClosed(smallRead)

	// The large request is far larger than the socket buffers, so its
	// write blocks until the server reads it.
	lctx, lcancel := context.WithCancel(t.Context())
	defer lcancel()
	largeErr := make(chan error, 1)
	go func() {
		large := &tbcapi.MempoolUtxosRequest{
			ScriptHashes: []api.ByteSlice{make([]byte, 8<<20)},
		}
		_, err := tt.callTBC(lctx, time.Hour, large)
		largeErr <- err
	}()
	waitClosed(largeStart)

	lcancel()
	if err := waitErr(t, largeErr); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	close(release)
	if err := waitErr(t, smallErr); err != nil {
		t.Fatalf("small request: %v", err)
	}
	tt.requireOneConn(t)
}

func FuzzTBCGozerTxByID(f *testing.F) {
	f.Add(make([]byte, 32))         // zero hash
	f.Add([]byte{0xaa, 0xbb, 0xcc}) // short
	f.Add(make([]byte, 33))         // oversize
	f.Add([]byte{})                 // empty
	f.Add([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}) // all-ones

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		kssMap, kssList := testutil.MakeSharedKeystones(2)
		btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

		mtbc := mock.NewMockTBC(ctx, nil, nil, kssMap, btcTip, 1)
		defer mtbc.Shutdown()

		DefaultRequestTimeout = 5 * time.Second
		b := New("ws" + strings.TrimPrefix(mtbc.URL(), "http"))
		if err := b.Run(ctx, nil); err != nil {
			t.Skip("failed to start gozer:", err)
		}

		tg := b.(*tbcGozer)
		for !tg.Connected() {
			select {
			case <-ctx.Done():
				t.Skip("timeout waiting for connection")
			case <-time.Tick(50 * time.Millisecond):
			}
		}

		// Pad or truncate to exactly 32 bytes.
		var hashBytes [32]byte
		copy(hashBytes[:], data)
		txid := chainhash.Hash(hashBytes)

		// Must not panic for any input.  Errors are acceptable.
		_, _ = b.TxByID(ctx, &txid)
	})
}
