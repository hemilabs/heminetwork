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
	"github.com/hemilabs/heminetwork/service/testutil"
)

// XXX antonio, please add a test case where opgeth/gozer aren't connected to
// make sure we don't deadlock or something else silly when network blips
// occur.

const wantedKeystones = 40

func TestPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	kssMap, kssList := testutil.MakeSharedKeystones(wantedKeystones)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	// Create opgeth test server with the request handler.
	opMsg, opErr, opgeth := testutil.NewMockOpGeth(ctx, kssList)
	defer opgeth.Close()

	// Create tbc test server with the request handler.
	tbcMsg, tbcErr, mtbc := testutil.NewMockTBC(ctx, kssMap, btcTip)
	defer mtbc.Close()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL, "http")
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL, "http")
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
		"kss_subscribe":          1,
		"kss_getLatestKeystones": 1,
		// tbcapi.CmdBlockKeystoneByL2KeystoneAbrevHashRequest: 2,
		// tbcapi.CmdUTXOsByAddressRequest:  keystoneRequestCount,
		// tbcapi.CmdFeeEstimateRequest:     keystoneRequestCount,
		// tbcapi.CmdTxBroadcastRequest:     keystoneRequestCount,
		// tbcapi.CmdBlockHeaderBestRequest: keystoneRequestCount,
	}

	// receive messages and errors from opgeth and tbc
	for {
		select {
		case err = <-opErr:
			t.Fatal(err)
		case err = <-tbcErr:
			t.Fatal(err)
		case n := <-opMsg:
			expectedMsg[n]--
		case n := <-tbcMsg:
			expectedMsg[n]--
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		finished := true
		for msg, k := range expectedMsg {
			if k > 0 {
				t.Logf("Still missing %v messages of type %s", k, msg)
				finished = false
			}
		}
		if finished {
			t.Log("Received all expected messages")
			return
		}
	}
}

func TestTickingPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	l2KeystoneMaxAge = 7 * time.Second

	_, kssList := testutil.MakeSharedKeystones(wantedKeystones)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	// Create opgeth test server with the request handler.
	opMsg, opErr, opgeth := testutil.NewMockOpGeth(ctx, kssList)
	defer opgeth.Close()

	emptyMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	// Create tbc test server with the request handler.
	tbcMsg, tbcErr, mtbc := testutil.NewMockTBC(ctx, emptyMap, btcTip)
	defer mtbc.Close()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL, "http")
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL, "http")
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
		"kss_subscribe":              1,
		"kss_getLatestKeystones":     1,
		tbcapi.CmdTxBroadcastRequest: wantedKeystones,
	}

	// receive messages and errors from opgeth and tbc
	for {
		select {
		case err = <-opErr:
			t.Fatal(err)
		case err = <-tbcErr:
			t.Fatal(err)
		case n := <-opMsg:
			expectedMsg[n]--
		case n := <-tbcMsg:
			expectedMsg[n]--
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		finished := true
		for msg, k := range expectedMsg {
			if k > 0 {
				t.Logf("Still missing %v messages of type %s", k, msg)
				finished = false
			}
		}
		if finished {
			if len(s.keystones) != wantedKeystones {
				t.Fatalf("cached keystones %v wanted %v", len(s.keystones), wantedKeystones)
			}
			for _, k := range s.keystones {
				if _, ok := emptyMap[*k.hash]; !ok {
					t.Fatalf("missing keystone: %v", k.hash)
				}
			}
			if err = s.mine(ctx); err != nil {
				t.Fatal(err)
			}
			if len(s.keystones) == wantedKeystones {
				t.Fatalf("cached keystones %v wanted %v", len(s.keystones), wantedKeystones)
			}
			t.Log("Received all expected messages")
			return
		}
	}
}
