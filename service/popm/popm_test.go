// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/testutil"
	"github.com/hemilabs/heminetwork/testutil/mock"
)

// XXX antonio, please add a test case where opgeth/gozer aren't connected to
// make sure we don't deadlock or something else silly when network blips
// occur.

const wantedKeystones = 40

func TestPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	kssMap, kssList := testutil.MakeSharedKeystones(wantedKeystones)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	// Create opgeth test server with the request handler.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList)
	defer opgeth.Shutdown()

	// Create tbc test server with the request handler.
	mtbc := mock.NewMockTBC(ctx, errCh, msgCh, kssMap, btcTip, 100)
	defer mtbc.Shutdown()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	// cfg.LogLevel = "popm=TRACE"

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	// Create pop miner
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Start pop miner
	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_subscribe":          1,
		"kss_getLatestKeystones": 1,
	}

	// receive messages and errors from opgeth and tbc
	err = messageListener(ctx, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTickingPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	l2KeystoneMaxAge = mock.DefaultNtfnDuration * (wantedKeystones + 1 - defaultL2KeystonesCount)

	_, kssList := testutil.MakeSharedKeystones(wantedKeystones)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	// Create opgeth test server with the request handler.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList)
	defer opgeth.Shutdown()

	emptyMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	// Create tbc test server with the request handler.
	mtbc := mock.NewMockTBC(ctx, errCh, msgCh, emptyMap, btcTip, 100)
	defer mtbc.Shutdown()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	// cfg.LogLevel = "popm=TRACE"

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	// Create pop miner
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Start pop miner
	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_subscribe":              1,
		"kss_getLatestKeystones":     1,
		tbcapi.CmdTxBroadcastRequest: wantedKeystones,
	}

	// receive messages and errors from opgeth and tbc
	err = messageListener(ctx, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	if len(s.keystones) != wantedKeystones {
		t.Fatalf("cached keystones %v wanted %v", len(s.keystones), wantedKeystones)
	}
	for _, k := range s.keystones {
		if _, ok := mtbc.GetKeystones()[*k.hash]; !ok {
			t.Fatalf("missing keystone: %v", k.hash)
		}
	}

	time.Sleep(500 * time.Millisecond)
	if err = s.mine(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(s.keystones) == wantedKeystones {
		t.Fatalf("cached keystones %v wanted %v", len(s.keystones), wantedKeystones)
	}
	t.Log("Received all expected messages")
}

func TestPopmFilterUtxos(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	l2KeystoneMaxAge = mock.DefaultNtfnDuration * (wantedKeystones + 1 - defaultL2KeystonesCount)

	_, kssList := testutil.MakeSharedKeystones(wantedKeystones)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	// Create opgeth test server with the request handler.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList)
	defer opgeth.Shutdown()

	emptyMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	// Create tbc test server with the request handler.
	mtbc := mock.NewMockTBC(ctx, errCh, msgCh, emptyMap, btcTip, defaultL2KeystonesCount-1)
	defer mtbc.Shutdown()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	cfg.LogLevel = "popm=TRACE"

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	// Create pop miner
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Start pop miner
	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_getLatestKeystones": 1,
		"kss_subscribe":          1,
	}

	// receive messages and errors from opgeth and tbc
	err = messageListener(ctx, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	// try to mine keystones
	err = s.mine(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// expect at least one to not have utxo, hence fail
	for _, kss := range s.keystones {
		if kss.state == keystoneStateError {
			return
		}
	}
	t.Fatal("expected not enough utxos after filter")
}

func TestDisconnectedOpgeth(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	l2KeystoneMaxAge = mock.DefaultNtfnDuration * (wantedKeystones + 1 - defaultL2KeystonesCount)
	opgethReconnectTimeout = 500 * time.Millisecond

	_, kssList := testutil.MakeSharedKeystones(wantedKeystones)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	// Create opgeth test server with the request handler.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList)
	defer opgeth.Shutdown()

	emptyMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	// Create tbc test server with the request handler.
	mtbc := mock.NewMockTBC(ctx, errCh, msgCh, emptyMap, btcTip, 100)
	defer mtbc.Shutdown()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	cfg.LogLevel = "popm=TRACE; mock=TRACE;"

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	// Create pop miner
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Start pop miner
	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_subscribe":          1,
		"kss_getLatestKeystones": 1,
	}

	// receive messages and errors from opgeth and tbc
	err = messageListener(ctx, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	// close current popm connection to opgeth
	if err = opgeth.CloseConnections(); err != nil {
		t.Fatal(err)
	}

	// messages we expect to receive
	expectedMsg = map[string]int{
		"kss_getLatestKeystones":     1,
		"kss_subscribe":              1,
		tbcapi.CmdTxBroadcastRequest: 1,
	}

	// receive messages and errors from opgeth and tbc
	err = messageListener(ctx, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}
}

func messageListener(ctx context.Context, expected map[string]int, errCh chan error, msgCh chan string) error {
	for {
		select {
		case err := <-errCh:
			return err
		case n := <-msgCh:
			expected[n]--
		case <-ctx.Done():
			return ctx.Err()
		}
		finished := true
		for _, k := range expected {
			if k > 0 {
				finished = false
			}
		}
		if finished {
			return nil
		}
	}
}
