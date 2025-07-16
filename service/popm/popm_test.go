// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"context"
	"errors"
	"net"
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

const wantedKeystones = 20

func TestPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
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
	err = messageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTickingPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

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

	// keystone expiration is forced below
	s.cfg.l2KeystoneMaxAge = mock.InfiniteDuration

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
	err = messageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	// s.keystones is protected by this mutex
	s.mtx.Lock()

	if len(s.keystones) != wantedKeystones {
		t.Fatalf("cached keystones %v wanted %v", len(s.keystones), wantedKeystones)
	}

	for _, k := range s.keystones {
		if _, ok := mtbc.GetKeystones()[*k.hash]; !ok {
			t.Fatalf("missing keystone: %v", k.hash)
		}
	}

	// force expiration of keystones
	for i := range s.keystones {
		now := time.Now()
		s.keystones[i].expires = &now
	}
	s.mtx.Unlock()

	time.Sleep(500 * time.Millisecond)

	// ensure keystones transition to 'mined' state
	if _, err := s.updateKeystoneStates(ctx); err != nil {
		t.Fatal(err)
	}

	// ensure 'mined' keystones get removed
	if err = s.mine(ctx); err != nil {
		t.Fatal(err)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	if len(s.keystones) >= wantedKeystones {
		t.Fatalf("cached keystones %v wanted less than %v", len(s.keystones), wantedKeystones)
	}
	t.Log("Received all expected messages")
}

func TestPopmFilterUtxos(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

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

	s.cfg.l2KeystoneMaxAge = mock.InfiniteDuration

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
	err = messageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	// try to mine keystones
	err = s.mine(ctx)
	if err != nil {
		t.Fatal(err)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	// expect at least one to not have utxo, hence fail
	for _, kss := range s.keystones {
		if kss.state == keystoneStateError {
			return
		}
	}
	t.Fatal("expected not enough utxos after filter")
}

func TestDisconnectedOpgeth(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

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
	cfg.l2KeystoneMaxAge = mock.DefaultNtfnDuration * (wantedKeystones + 1 - defaultL2KeystonesCount)
	cfg.opgethReconnectTimeout = 500 * time.Millisecond

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
	err = messageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	// close current popm connection to opgeth
	if err = opgeth.CloseConnections(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}

	// messages we expect to receive
	expectedMsg = map[string]int{
		"kss_getLatestKeystones":     1,
		"kss_subscribe":              1,
		tbcapi.CmdTxBroadcastRequest: 1,
	}

	// receive messages and errors from opgeth and tbc
	err = messageListener(t, expectedMsg, errCh, msgCh)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func messageListener(t *testing.T, expected map[string]int, errCh chan error, msgCh chan string) error {
	for {
		select {
		case err := <-errCh:
			return err
		case n := <-msgCh:
			t.Logf("received message %s", n)
			expected[n]--
		case <-t.Context().Done():
			return t.Context().Err()
		}
		finished := true
		for v, k := range expected {
			if k > 0 {
				t.Logf("missing %d messages of type %s", k, v)
				finished = false
			}
		}
		if finished {
			return nil
		}
	}
}
