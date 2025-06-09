// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/phayes/freeport"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/service/popm"
	"github.com/hemilabs/heminetwork/service/testutil"
)

const wantedKeystones = 10

func TestBFG(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	kssMap, kssList := testutil.MakeSharedKeystones(30)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	// Create opgeth test server with the request handler.
	opgeth := testutil.NewMockOpGeth(ctx, errCh, msgCh, kssList)
	defer opgeth.Shutdown()

	// Create tbc test server with the request handler.
	mtbc := testutil.NewMockTBC(ctx, errCh, msgCh, kssMap, btcTip, 10)
	defer mtbc.Shutdown()

	bfgCfg := NewDefaultConfig()
	bfgCfg.Network = "testnet3"
	bfgCfg.BitcoinSource = "tbc"
	bfgCfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	bfgCfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	bfgCfg.ListenAddress = createAddress()
	// bfgCfg.LogLevel = "bfg=Info; mock:Trace"

	if err := loggo.ConfigureLoggers(bfgCfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	s, err := NewServer(bfgCfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_getKeystone":                      wantedKeystones,
		tbcapi.CmdBlocksByL2AbrevHashesRequest: wantedKeystones,
	}

	for !s.Connected() {
		time.Sleep(10 * time.Millisecond)
	}

	var wg sync.WaitGroup
	// send finality requests to bfg, which should return super finality
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendFinalityRequests(ctx, kssList, bfgCfg.ListenAddress, 9, 10000)
	}()

	// receive messages and errors from opgeth and tbc
	if err = messageListener(ctx, expectedMsg, errCh, msgCh); err != nil {
		t.Fatal(err)
	}

	wg.Wait()
}

func TestKeystoneFinalityInheritance(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	kssMap, kssList := testutil.MakeSharedKeystones(30)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	// ensure no keystone has super finality, except the
	// last one, ensuring they inherit it
	for i, ks := range kssList {
		// lower l1 block than first keystone
		ks.L1BlockNumber = 10029
		kssList[i] = ks
		kssMap[*hemi.L2KeystoneAbbreviate(ks).Hash()] = hemi.L2KeystoneAbbreviate(ks)
	}
	lastKss := kssList[len(kssList)-1]
	lastKss.L1BlockNumber = 500
	kssList[len(kssList)-1] = lastKss
	kssMap[*hemi.L2KeystoneAbbreviate(lastKss).Hash()] = hemi.L2KeystoneAbbreviate(lastKss)

	// Create opgeth test server with the request handler.
	opgeth := testutil.NewMockOpGeth(ctx, errCh, msgCh, kssList)
	defer opgeth.Shutdown()

	// Create tbc test server with the request handler.
	mtbc := testutil.NewMockTBC(ctx, errCh, msgCh, kssMap, btcTip, 10)
	defer mtbc.Shutdown()

	bfgCfg := NewDefaultConfig()
	bfgCfg.Network = "testnet3"
	bfgCfg.BitcoinSource = "tbc"
	bfgCfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	bfgCfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	bfgCfg.ListenAddress = createAddress()
	// bfgCfg.LogLevel = "bfg=Info; mock=Trace"

	if err := loggo.ConfigureLoggers(bfgCfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	s, err := NewServer(bfgCfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_getKeystone":                      wantedKeystones,
		tbcapi.CmdBlocksByL2AbrevHashesRequest: wantedKeystones,
	}

	for !s.Connected() {
		time.Sleep(10 * time.Millisecond)
	}

	var wg sync.WaitGroup
	// send finality requests to bfg, which should return super finality
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendFinalityRequests(ctx, kssList, bfgCfg.ListenAddress, 9, 10000)
	}()

	// receive messages and errors from opgeth and tbc
	if err = messageListener(ctx, expectedMsg, errCh, msgCh); err != nil {
		t.Fatal(err)
	}

	wg.Wait()
}

func TestFullMockIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	_, kssList := testutil.MakeSharedKeystones(wantedKeystones * 2)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	// Create opgeth test server with the request handler.
	opgeth := testutil.NewMockOpGeth(ctx, errCh, msgCh, kssList)
	defer opgeth.Shutdown()

	kssMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev)

	// Create tbc test server with the request handler.
	mtbc := testutil.NewMockTBC(ctx, errCh, msgCh, kssMap, btcTip, 20)
	defer mtbc.Shutdown()

	bfgCfg := NewDefaultConfig()
	bfgCfg.Network = "testnet3"
	bfgCfg.BitcoinSource = "tbc"
	bfgCfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	bfgCfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	bfgCfg.ListenAddress = createAddress()
	// bfgCfg.LogLevel = "bfg=Info; mock=Trace; popm=TRACE"

	if err := loggo.ConfigureLoggers(bfgCfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	s, err := NewServer(bfgCfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_getKeystone":                      wantedKeystones,
		tbcapi.CmdBlocksByL2AbrevHashesRequest: wantedKeystones,
	}

	for !s.Connected() {
		time.Sleep(10 * time.Millisecond)
	}

	// send finality requests to bfg, which should not return super finality
	go sendFinalityRequests(ctx, kssList, bfgCfg.ListenAddress, 0, 0)

	// receive messages and errors from opgeth and tbc
	if err = messageListener(ctx, expectedMsg, errCh, msgCh); err != nil {
		t.Fatal(err)
	}

	// Setup pop miner
	popCfg := popm.NewDefaultConfig()
	popCfg.BitcoinSource = "tbc"
	popCfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL(), "http")
	popCfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL(), "http")
	popCfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	// popCfg.LogLevel = "popm=TRACE"

	// Create pop miner
	popm, err := popm.NewServer(popCfg)
	if err != nil {
		t.Fatal(err)
	}

	// Start pop miner
	go func() {
		if err := popm.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// wait until all keystones are mined and broadcast
	expectedMsg = map[string]int{
		"kss_subscribe":              1,
		"kss_getLatestKeystones":     1,
		tbcapi.CmdTxBroadcastRequest: wantedKeystones * 2,
	}

	// receive messages and errors from opgeth and tbc
	err = messageListener(ctx, expectedMsg, errCh, msgCh)
	if err != nil {
		t.Fatal(err)
	}

	// wait until we ask for the finality value of all keystones
	expectedMsg = map[string]int{
		"kss_getKeystone":                      wantedKeystones,
		tbcapi.CmdBlocksByL2AbrevHashesRequest: wantedKeystones,
	}

	var wg sync.WaitGroup
	// send finality requests to bfg, which should return super finality
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendFinalityRequests(ctx, kssList, bfgCfg.ListenAddress, 9, 10000)
	}()

	// receive messages and errors from opgeth and tbc
	if err = messageListener(ctx, expectedMsg, errCh, msgCh); err != nil {
		t.Fatal(err)
	}

	wg.Wait()
}

func sendFinalityRequests(ctx context.Context, kssList []hemi.L2Keystone, url string, minConfirms, maxConfirms uint) {
	client := &http.Client{}
	for i := range wantedKeystones {
		kssHash := hemi.L2KeystoneAbbreviate(kssList[i]).Hash()
		u := fmt.Sprintf("http://%v/v%v/keystonefinality/%v",
			url, bfgapi.APIVersion, kssHash)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			panic(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			panic(fmt.Sprintf("unexpected status code: %v", resp.StatusCode))
		}

		fin := bfgapi.L2KeystoneBitcoinFinalityResponse{}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		if err = resp.Body.Close(); err != nil {
			panic(err)
		}

		if err = json.Unmarshal(body, &fin); err != nil {
			panic(err)
		}

		if fin.EffectiveConfirmations < minConfirms {
			panic(fmt.Errorf("unexpected finality result: %v",
				spew.Sdump(fin)))
		}

		if fin.EffectiveConfirmations > maxConfirms {
			panic(fmt.Errorf("unexpected finality result: %v",
				spew.Sdump(fin)))
		}
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

func createAddress() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(fmt.Errorf("find free port: %w", err))
	}
	return fmt.Sprintf("localhost:%d", port)
}
