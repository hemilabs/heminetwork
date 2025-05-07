// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/service/testutil"
)

func TestPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	kssMap, kssList := makeSharedKeystones(40)
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

func makeSharedKeystones(n int) (map[chainhash.Hash]*hemi.L2KeystoneAbrev, []hemi.L2Keystone) {
	kssList := make([]hemi.L2Keystone, n)
	kssMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	prevKeystone := &hemi.L2Keystone{
		Version:       1,
		L1BlockNumber: 0xbadc0ffe,
	}
	for ci := range n {
		x := uint8(ci)
		l2Keystone := hemi.L2Keystone{
			Version:            1,
			L1BlockNumber:      prevKeystone.L1BlockNumber + 1,
			L2BlockNumber:      uint32(ci+1) * 25,
			ParentEPHash:       digest256([]byte{x}),
			PrevKeystoneEPHash: digest256([]byte{x, x}),
			StateRoot:          digest256([]byte{x, x, x}),
			EPHash:             digest256([]byte{x, x, x, x}),
		}

		abrevKss := hemi.L2KeystoneAbbreviate(l2Keystone)
		kssMap[*abrevKss.Hash()] = abrevKss
		kssList[ci] = l2Keystone
		prevKeystone = &l2Keystone
	}

	return kssMap, kssList
}

func digest256(x []byte) []byte {
	xx := sha256.Sum256(x)
	return xx[:]
}
