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
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/phayes/freeport"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/service/testutil"
)

func createAddress() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(fmt.Errorf("find free port: %w", err))
	}
	return fmt.Sprintf("localhost:%d", port)
}

func TestBFG(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	const keystoneCount = 10

	kssMap, kssList := testutil.MakeSharedKeystones(30)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	// Create opgeth test server with the request handler.
	opMsg, opErr, opgeth := testutil.NewMockOpGeth(ctx, kssList)
	defer opgeth.Close()

	// Create tbc test server with the request handler.
	tbcMsg, tbcErr, mtbc := testutil.NewMockTBC(ctx, kssMap, btcTip)
	defer mtbc.Close()

	bfgCfg := NewDefaultConfig()
	bfgCfg.Network = "testnet3"
	bfgCfg.BitcoinSource = "tbc"
	bfgCfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL, "http")
	bfgCfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL, "http")
	bfgCfg.ListenAddress = createAddress()
	// bfgCfg.LogLevel = "bfg=Trace;"

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
		"kss_getKeystone": keystoneCount,
		tbcapi.CmdBlockKeystoneByL2KeystoneAbrevHashRequest: defaultKeystoneCount * keystoneCount,
	}

	for !s.Connected() {
		time.Sleep(10 * time.Millisecond)
	}

	// send finality requests to bfg
	go func() {
		for i := range keystoneCount {
			kssHash := hemi.L2KeystoneAbbreviate(kssList[i]).Hash()
			u := fmt.Sprintf("http://%v/v%v/keystonefinality/%v",
				bfgCfg.ListenAddress, bfgapi.APIVersion, kssHash)
			resp, err := http.Get(u)
			if err != nil {
				panic(err)
			}

			if resp.StatusCode != 200 {
				panic(fmt.Sprintf("unexpected status code: %v", resp.StatusCode))
			}

			fin := bfgapi.L2KeystoneBitcoinFinalityResponse{}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				panic(err)
			}

			if err = json.Unmarshal(body, &fin); err != nil {
				panic(err)
			}

			if !*fin.SuperFinality {
				panic(fmt.Errorf("unexpected finality result: %v",
					spew.Sdump(fin)))
			}
		}
	}()

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
