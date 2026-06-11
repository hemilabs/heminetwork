// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
	"github.com/hemilabs/heminetwork/v2/internal/testutil/mock"
	"github.com/hemilabs/heminetwork/v2/service/tbc"
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
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList, defaultL2KeystonesCount)
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
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPromPollBeforeOpgeth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()

		// Setup pop miner
		cfg := NewDefaultConfig()
		cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"

		// Create pop miner
		s, err := NewServer(cfg)
		if err != nil {
			t.Fatal(err)
		}

		// if we try to do opgeth calls before we have connected at least
		// once, this will panic.
		if err := s.promPoll(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

func TestTickingPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	_, kssList := testutil.MakeSharedKeystones(wantedKeystones)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	// Create opgeth test server with the request handler.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList, defaultL2KeystonesCount)
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
	cfg.LogLevel = "popm=TRACE; mock=TRACE"

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
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
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

	go func() {
		defer func() {
			msgCh <- "miningDone"
		}()
		// ensure 'mined' keystones get removed
		err = s.mine(ctx)
		if err != nil {
			panic(err)
		}
	}()

	// wait until all keystones are mined and broadcast
	expectedMsg = map[string]int{
		"miningDone": 1,
	}

	// receive messages and errors from opgeth and tbc
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
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
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList, defaultL2KeystonesCount)
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
	// cfg.LogLevel = "popm=TRACE"

	// XXX is this not handled in pop miner?
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
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		defer func() {
			msgCh <- "miningDone"
		}()
		// try to mine keystones
		err = s.mine(ctx)
		if err != nil {
			panic(err)
		}
	}()

	// wait until all keystones are mined and broadcast
	expectedMsg = map[string]int{
		"miningDone": 1,
	}

	// receive messages and errors from opgeth and tbc
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
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

	_, kssList := testutil.MakeSharedKeystones(1)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	errCh := make(chan error)
	msgCh := make(chan string)

	// Create opgeth test server with the request handler.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList, defaultL2KeystonesCount)
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
	cfg.l2KeystoneMaxAge = mock.InfiniteDuration
	cfg.opgethMaxReconnectDelay = 100 * time.Millisecond
	cfg.opgethMinReconnectDelay = 50 * time.Millisecond

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
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	// close current popm connection to opgeth
	opgeth.Stop()
	err = opgeth.CloseConnections(false)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}

	// wait for popminer to try and reconnect
	var rcvErr error
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-msgCh:
		case rcvErr = <-errCh:
		}

		// miner has tried to reconnect
		if errors.Is(rcvErr, mock.ErrConnectionClosed) {
			t.Log("popminer attempted to reconnect")
			opgeth.Start()
			break
		}
	}

	// flush all other error messages
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-errCh:
			continue
		default:
		}

		t.Log("error messages flushed")
		break
	}

	// messages we expect to receive
	expectedMsg = map[string]int{
		"kss_getLatestKeystones": 1,
		"kss_subscribe":          1,
	}

	// receive messages and errors from opgeth and tbc
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStaticFee(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	cfg.LogLevel = "popm=TRACE; mock=TRACE;"
	cfg.StaticFee = 0.5

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	_, err := NewServer(cfg)
	if err == nil {
		t.Fatal("expected error")
	}

	cfg.StaticFee = 1.5
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	fee, err := s.estimateFee(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if fee.SatsPerVByte != 1.5 {
		t.Fatalf("expected fee of 1.5 sats/vbyte, got %v sats/vbyte", fee.SatsPerVByte)
	}
}

func TestMaxFeeRemine(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	_, kssList := testutil.MakeSharedKeystones(wantedKeystones)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	// Create opgeth test server with the request handler.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList, defaultL2KeystonesCount)
	defer opgeth.Shutdown()

	emptyMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	// Create tbc test server with the request handler.
	mtbc := mock.NewMockTBC(ctx, errCh, msgCh, emptyMap, btcTip, 100)
	defer mtbc.Shutdown()

	mtbc.SetFeeEstimate(100.0)

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	cfg.LogLevel = "popm=TRACE; mock=TRACE"
	cfg.MaxFee = 50.0

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

	now := time.Now()

	expectedMsg := map[string]int{
		"kss_subscribe":              1,
		"kss_getLatestKeystones":     1,
		tbcapi.CmdFeeEstimateRequest: wantedKeystones,
	}

	// receive messages and errors from opgeth and tbc
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	// Check that all keystones are waiting to be retried

	s.mtx.Lock()

	if len(s.keystones) != wantedKeystones {
		t.Fatalf("cached keystones %v wanted %v", len(s.keystones), wantedKeystones)
	}

	for i := range s.keystones {
		if s.keystones[i].state != keystoneStateError {
			t.Fatalf("expected kss state %d, got %d",
				keystoneStateError, s.keystones[i].state)
		}
		if !s.keystones[i].retry.After(now) {
			t.Fatalf("keystone not delayed, retry set to %v",
				time.Until(s.keystones[i].retry.UTC()))
		}
	}
	// add an extra keystone that should expire and be removed
	fakeHash := testutil.RandomHash()
	s.keystones[*fakeHash] = &keystone{
		hash:    fakeHash,
		state:   keystoneStateError,
		retry:   timestamp(defaultL2KeystoneFeeRetry),
		expires: timestamp(0),
	}
	s.mtx.Unlock()

	// Manually try to mine and make sure we fail since fees are still high
	if err := s.mine(ctx); err != nil {
		t.Fatal(err)
	}

	s.mtx.Lock()
	if len(s.keystones) != wantedKeystones {
		t.Fatalf("cached keystones %v wanted %v", len(s.keystones), wantedKeystones)
	}

	for i := range s.keystones {
		if s.keystones[i].state != keystoneStateError {
			t.Fatalf("expected kss state %d, got %d",
				keystoneStateError, s.keystones[i].state)
		}
		if !s.keystones[i].retry.After(now) {
			t.Fatalf("keystone not delayed, retry set to %v",
				time.Until(s.keystones[i].retry.UTC()))
		}
		// reset retry
		s.keystones[i].retry = timestamp(0)
	}
	s.mtx.Unlock()

	// lower fees
	mtbc.SetFeeEstimate(5.0)

	s.workC <- struct{}{}

	// messages we expect to receive
	expectedMsg = map[string]int{
		tbcapi.CmdTxBroadcastRequest: wantedKeystones,
	}

	// receive messages and errors from opgeth and tbc
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMaxFee(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	_, kssList := testutil.MakeSharedKeystones(1)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	emptyMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	mtbc := mock.NewMockTBC(ctx, errCh, msgCh, emptyMap, btcTip, 100)
	mtbc.SetFeeEstimate(50.0)
	defer mtbc.Shutdown()

	// Setup pop miner with max fee of 10 sats/vbyte
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	cfg.MaxFee = 0.5

	if _, err := NewServer(cfg); err == nil {
		t.Fatal("expected error")
	}

	cfg.MaxFee = 10.0

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	gozerReady := make(chan struct{})
	go func() {
		err := s.gozer.Run(ctx, func() {
			gozerReady <- struct{}{}
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// Wait for gozer to be ready
	select {
	case <-gozerReady:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// Test that high fee estimate returns FeeMaxExceededError
	_, err = s.estimateFee(ctx)
	if !errors.Is(err, ErrFeeMaxExceeded) {
		t.Fatalf("expected error %v, got %v", ErrFeeMaxExceeded, err)
	}

	// Test that fee below MaxFee is returned without error
	mtbc.SetFeeEstimate(5.0)

	fee, err := s.estimateFee(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if fee.SatsPerVByte != 5.0 {
		t.Fatalf("expected fee of 5, got %v", fee.SatsPerVByte)
	}

	// Test that MaxFee of 0 disables the cap
	s.cfg.MaxFee = 0

	mtbc.SetFeeEstimate(100.0)

	fee, err = s.estimateFee(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if fee.SatsPerVByte != 100.0 {
		t.Fatalf("expected fee of 100, got %v", fee.SatsPerVByte)
	}
}

func TestOpgethReconnect(t *testing.T) {
	const (
		minDelay = 250 * time.Millisecond
		maxDelay = 1 * time.Second
	)

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	_, kssList := testutil.MakeSharedKeystones(1)

	// Create opgeth test server with the request handler.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList, 0)
	defer opgeth.Shutdown()

	opgeth.Stop()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	cfg.LogLevel = "popm=TRACE; mock=TRACE;"
	cfg.l2KeystoneMaxAge = mock.InfiniteDuration
	cfg.opgethMinReconnectDelay = minDelay
	cfg.opgethMaxReconnectDelay = maxDelay

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	// Create pop miner
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// slightly buffered to process messages
	maxCtx, cancelMax := context.WithTimeout(ctx, maxDelay*2)
	defer cancelMax()

	start := time.Now()

	go s.opgeth(maxCtx)

	var reconAttempts int
	for {
		select {
		case <-maxCtx.Done():
			t.Fatal("reconnect too long")
		case err := <-errCh:
			if errors.Is(err, mock.ErrConnectionClosed) {
				reconAttempts += 1
			}
		}

		if reconAttempts >= 2 {
			if time.Since(start) < minDelay {
				t.Fatal("reconnected too fast")
			}
			return
		}
	}
}

func TestPopMinerE2E(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	const (
		secret      = "72a2c41c84147325ce3c0f37697ef1e670c7169063dda89be9995c3c5219740f"
		otherSecret = "72a2c41c84147325ce3c0f37697ef1e670c7169063dda89be9995c3c5219ffff"
		kssCount    = 4
	)

	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	// Create bitcoind container
	bitcoindContainer := testutil.CreateBitcoind(ctx)

	// Generate miner address to fund with BTC from mining
	_, _, btcAddress, err := bitcoin.KeysAndAddressFromHexString(
		secret,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Generate secondary address
	_, _, otherAddress, err := bitcoin.KeysAndAddressFromHexString(
		otherSecret,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Generate blockCount blocks that fund the miner's wallet
	_, err = testutil.RunBitcoindCommand(ctx, bitcoindContainer, []string{
		"bitcoin-cli",
		"-regtest=1",
		"generatetoaddress",
		strconv.FormatUint(kssCount, 10),
		btcAddress.EncodeAddress(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Generate 100 more blocks to reach coinbase maturity. We send to
	// another address to prevent the wallet from selection UTXOs that
	// maybe not yet be ready for spending.
	_, err = testutil.RunBitcoindCommand(ctx, bitcoindContainer, []string{
		"bitcoin-cli",
		"-regtest=1",
		"generatetoaddress",
		"100",
		otherAddress.EncodeAddress(),
	})
	if err != nil {
		t.Fatal(err)
	}

	mappedPeerPort, err := bitcoindContainer.MappedPort(ctx, "18444")
	if err != nil {
		t.Errorf("error getting mapped port %v", err)
	}

	tbcCfg := &tbc.Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		HeaderCacheSize:         "1mb",
		HemiIndex:               true,
		LevelDBHome:             t.TempDir(),
		MaxCachedTxs:            1000,
		MaxCachedKeystones:      1000,
		Network:                 "localnet",
		ListenAddress:           "127.0.0.1:0",
		PeersWanted:             1,
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		NotificationBlocking:    true,
		// LogLevel:                "tbc=TRACE",
		Seeds: []string{
			"127.0.0.1:" + mappedPeerPort.Port(),
		},
	}

	if err := loggo.ConfigureLoggers(tbcCfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	tbcServer, err := tbc.NewServer(tbcCfg)
	if err != nil {
		t.Fatal(err)
	}

	l, err := tbcServer.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	// Start TBC
	go func() {
		err := tbcServer.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// Wait until TBC inserts all blocks
	var insertCount int
	for {
		notif, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if notif.Is(tbc.NotificationBlock(chainhash.Hash{})) {
			insertCount++
		}
		if insertCount == kssCount+100 {
			break
		}
	}
	l.Unsubscribe()

	// Sync TBC to latest block
	if err := tbcServer.SyncIndexersToBest(ctx); err != nil {
		t.Fatal(err)
	}

	_, kssList := testutil.MakeSharedKeystones(kssCount)
	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	// Create opgeth test server to generate and send keystones.
	opgeth := mock.NewMockOpGeth(ctx, errCh, msgCh, kssList, kssCount)
	defer opgeth.Shutdown()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws://" + tbcServer.HTTPAddress().String() + tbcapi.RouteWebsocket
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	cfg.BitcoinSecret = secret
	cfg.Network = "localnet"
	// cfg.LogLevel = "popm=TRACE;tbc=TRACE"
	cfg.l2KeystonePollTimeout = 500 * time.Millisecond
	cfg.StaticFee = 100

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	// Confirm our address has the expected balance
	bal, err := tbcServer.BalanceByAddress(ctx, btcAddress.EncodeAddress())
	if err != nil {
		t.Fatal(err)
	}
	expectedBal := uint64(kssCount * btcutil.SatoshiPerBitcoin * 50)
	if bal != expectedBal {
		t.Fatalf("expected balance of %d, got %d", expectedBal, bal)
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

	// Wait for pop miner to retrieve keystones and then
	// send a request to start mining
	expectedMsg := map[string]int{
		"kss_subscribe":          1,
		"kss_getLatestKeystones": 1,
	}
	err = testutil.MessageListener(t, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}
	s.workC <- struct{}{}

	var (
		listen    *tbc.Listener
		txIDs     string
		inMempool bool
	)
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case err := <-errCh:
			t.Fatal(err)
		case <-time.Tick(250 * time.Millisecond):
			// Check if bitcoind has received the PoP Txs
			txIDs, err = testutil.RunBitcoindCommand(ctx, bitcoindContainer, []string{
				"bitcoin-cli",
				"-regtest",
				"getrawmempool",
				"false",
			})
			if err != nil {
				panic(err)
			}

			var out []string
			if err := json.Unmarshal([]byte(txIDs), &out); err != nil {
				panic(err)
			}

			if len(out) == kssCount {
				inMempool = true
			}
		}
		if inMempool {
			break
		}
	}

	listen, err = tbcServer.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Unsubscribe()

	// Generate block with the new PoP TXs
	_, err = testutil.RunBitcoindCommand(ctx, bitcoindContainer, []string{
		"bitcoin-cli",
		"-regtest",
		"generateblock",
		otherAddress.EncodeAddress(),
		txIDs,
	})
	if err != nil {
		panic(err)
	}

	// Wait for TBC to insert the new block
	for {
		notif, err := listen.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if notif.Is(tbc.NotificationBlock(chainhash.Hash{})) {
			break
		}
	}
	listen.Unsubscribe()

	// Sync TBC to the new block
	if err = tbcServer.SyncIndexersToBest(ctx); err != nil {
		t.Fatal(err)
	}

	// Confirm our address has a lower balance now
	bal, err = tbcServer.BalanceByAddress(ctx, btcAddress.EncodeAddress())
	if err != nil {
		t.Fatal(err)
	}

	// Original balance - (STATIC_FEE * POP_TX_SIZE * KssCount)
	newBal := expectedBal - (uint64(cfg.StaticFee) * 285 * kssCount)
	if bal != newBal {
		t.Fatalf("expected balance of %d, got %d", newBal, bal)
	}

	// Speed up pop miner and update keystone states
	if _, err = s.updateKeystoneStates(ctx); err != nil {
		t.Fatal(err)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Ensure every keystone is marked as 'mined'
	for kh, kss := range s.keystones {
		if kss.state != keystoneStateMined {
			t.Fatalf("expected keystone %s to be mined", kh)
		}
	}
}

func TestDefaultMaxFee(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg.MaxFee != defaultMaxFee {
		t.Fatalf("expected default MaxFee of %v, got %v",
			defaultMaxFee, cfg.MaxFee)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	_, kssList := testutil.MakeSharedKeystones(1)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	emptyMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	mtbc := mock.NewMockTBC(ctx, errCh, msgCh, emptyMap, btcTip, 100)
	defer mtbc.Shutdown()

	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	gozerReady := make(chan struct{})
	go func() {
		err := s.gozer.Run(ctx, func() {
			gozerReady <- struct{}{}
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	select {
	case <-gozerReady:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// Fee above default cap should be rejected.
	mtbc.SetFeeEstimate(defaultMaxFee + 50)
	_, err = s.estimateFee(ctx)
	if !errors.Is(err, ErrFeeMaxExceeded) {
		t.Fatalf("expected FeeMaxExceededError for fee above default cap, got: %v", err)
	}

	// Fee below default cap should pass.
	mtbc.SetFeeEstimate(defaultMaxFee - 10)
	fee, err := s.estimateFee(ctx)
	if err != nil {
		t.Fatalf("expected no error for fee below default cap, got: %v", err)
	}
	if fee.SatsPerVByte != defaultMaxFee-10 {
		t.Fatalf("expected fee of %v, got %v", defaultMaxFee-10, fee.SatsPerVByte)
	}
}
