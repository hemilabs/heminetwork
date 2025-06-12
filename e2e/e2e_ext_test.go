// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package e2e_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/go-test/deep"
	gwebsocket "github.com/gorilla/websocket"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/service/bfg"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/hemilabs/heminetwork/testutil"
)

func EnsureCanConnect(t *testing.T, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	t.Logf("connecting to %s", url)

	var err error

	doneCh := make(chan bool)
	go func() {
		for {
			c, _, err := websocket.Dial(ctx, url, nil)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
			c.CloseNow()
			doneCh <- true
		}
	}()

	select {
	case <-doneCh:
	case <-ctx.Done():
		return fmt.Errorf("timed out trying to reach WS server in tests, last error: %w", err)
	}

	return nil
}

func EnsureCanConnectTCP(t *testing.T, addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}

	conn.Close()
	return nil
}

// since we don't use httptest when running bfg, we have to start in this port
// range.  use the mutex to make it safe
var (
	somePort    = 3000
	somePortMtx = sync.Mutex{}
)

func nextPort(ctx context.Context, t *testing.T) int {
	somePortMtx.Lock()
	defer somePortMtx.Unlock()
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}

		port := somePort
		somePort++

		if _, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", fmt.Sprintf("%d", port)), 1*time.Second); err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				// connection error, port is open
				return port
			}

			t.Fatal(err)
		}
	}
}

func createBfgServer(ctx context.Context, t *testing.T, levelDbHome string, opgethWsUrl string) (*bfg.Server, string) {
	_, tbcPublicUrl := createTbcServer(ctx, t, levelDbHome)

	bfgPublicListenAddress := fmt.Sprintf(":%d", nextPort(ctx, t))

	cfg := &bfg.Config{
		ListenAddress: bfgPublicListenAddress,
		BitcoinURL:    tbcPublicUrl,
		BitcoinSource: "tbc",
		Network:       "localnet",
		OpgethURL:     opgethWsUrl,
	}

	bfgServer, err := bfg.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := bfgServer.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	bfgPublicUrl := fmt.Sprintf("localhost%s", bfgPublicListenAddress)

	if err := EnsureCanConnectTCP(t, bfgPublicUrl, 5*time.Second); err != nil {
		t.Fatalf("could not connect to %s: %s", bfgPublicUrl, err.Error())
	}

	return bfgServer, bfgPublicUrl
}

func createTbcServer(ctx context.Context, t *testing.T, levelDbHome string) (*tbc.Server, string) {
	tbcPublicListenAddress := fmt.Sprintf(":%d", nextPort(ctx, t))

	cfg := tbc.NewDefaultConfig()

	cfg.ListenAddress = tbcPublicListenAddress
	cfg.Network = "localnet"
	cfg.LevelDBHome = levelDbHome

	tbcServer, err := tbc.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := tbcServer.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	tbcPublicUrl := fmt.Sprintf("http://localhost%s/v1/ws", tbcPublicListenAddress)

	if err := EnsureCanConnect(t, tbcPublicUrl, 5*time.Second); err != nil {
		t.Fatalf("could not connect to %s: %s", tbcPublicUrl, err.Error())
	}

	return tbcServer, tbcPublicUrl
}

func defaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func randomL2Keystone(l2BlockNumber *int) *hemi.L2Keystone {
	k := &hemi.L2Keystone{
		Version:            uint8(1),
		L1BlockNumber:      rand.Uint32(),
		L2BlockNumber:      rand.Uint32(),
		ParentEPHash:       testutil.FillBytes("", 32),
		PrevKeystoneEPHash: testutil.FillBytes("", 32),
		StateRoot:          testutil.FillBytes("", 32),
		EPHash:             testutil.FillBytes("", 32),
	}

	if l2BlockNumber != nil {
		k.L2BlockNumber = L2BlockNumber
	}

	return k
}

func createChainWithKeystones(ctx context.Context, t *testing.T, db tbcd.Database, height uint64, keystones map[uint64]tbcd.Keystone) {
	var prevHeader *wire.BlockHeader

	for h := range height {
		t.Logf("prevHeader = %v, height = %d", prevHeader, h)
		wireHeader := wire.BlockHeader{
			Version: 1,
			Nonce:   uint32(h), // something unique so there are no collisions
		}

		if prevHeader != nil {
			wireHeader.PrevBlock = prevHeader.BlockHash()
		}

		msgHeaders := wire.NewMsgHeaders()

		if err := msgHeaders.AddBlockHeader(&wireHeader); err != nil {
			t.Fatal(err)
		}

		wireBlock := wire.MsgBlock{
			Header: wireHeader,
		}

		block := btcutil.NewBlock(&wireBlock)

		if h == 0 {
			err := db.BlockHeaderGenesisInsert(ctx, wireHeader, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			_, _, _, _, err := db.BlockHeadersInsert(ctx, msgHeaders, nil)
			if err != nil {
				t.Fatal(err)
			}
		}

		_, err := db.BlockInsert(ctx, block)
		if err != nil {
			t.Fatal(err)
		}

		if l2Keystone, ok := keystones[h]; ok {
			l2Keystone.BlockHash = *block.Hash()
			if err := db.BlockKeystoneUpdate(ctx, 1, map[chainhash.Hash]tbcd.Keystone{
				*hemi.L2KeystoneAbrevDeserialize(l2Keystone.AbbreviatedKeystone).Hash(): l2Keystone,
			}, *block.Hash()); err != nil {
				t.Fatal(err)
			}
			t.Logf("inserted keystone %s at btc height %d", hemi.L2KeystoneAbrevDeserialize(l2Keystone.AbbreviatedKeystone).Hash(), block.Height())
		}

		t.Logf("inserted block")
		prevHeader = &wireHeader
	}
}

func TestGetFinalitiesByL2KeystoneBFGInheritingfinality(t *testing.T) {
	t.Skip("FIXME: THIS FUNCTIONALITY NEEDS TO BE WORKING")

	ctx, cancel := defaultTestContext()
	defer cancel()

	levelDbHome, err := os.MkdirTemp("", "tbc-random-*") //nolint:all // I want to use this one
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := os.RemoveAll(levelDbHome); err != nil {
			t.Fatal(err)
		}
	}()

	cfg, err := level.NewConfig("localnet", levelDbHome, "0", "0")
	if err != nil {
		t.Fatal(err)
	}

	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	l2BlockNumber := 1
	keystoneOne := randomL2Keystone(&l2BlockNumber)
	l2BlockNumber++
	keystoneTwo := randomL2Keystone(&l2BlockNumber)

	createChainWithKeystones(ctx, t, db, 13, map[uint64]tbcd.Keystone{
		8: {
			AbbreviatedKeystone: hemi.L2KeystoneAbbreviate(*keystoneOne).Serialize(),
		},
		1: {
			AbbreviatedKeystone: hemi.L2KeystoneAbbreviate(*keystoneTwo).Serialize(),
		},
	})

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(http.HandlerFunc(newMockOpgeth(ctx, t, []hemi.L2Keystone{
		*keystoneOne,
		*keystoneTwo,
	})))
	defer s.Close()

	opgethWsurl := "ws" + strings.TrimPrefix(s.URL, "http")

	_, bfgUrl := createBfgServer(ctx, t, levelDbHome, opgethWsurl)
	time.Sleep(2 * time.Second)

	expectedConfirmations := []int{
		11,
		11,
	}

	for i, k := range []hemi.L2Keystone{
		*keystoneOne,
		*keystoneTwo,
	} {
		bfgUrlTmp := fmt.Sprintf("http://%s/v2/keystonefinality/%s", bfgUrl, hemi.L2KeystoneAbbreviate(k).Hash())

		resp, err := http.Get(bfgUrlTmp) //nolint:all // this is fine
		if err != nil {
			t.Fatal(err)
		}

		defer resp.Body.Close()

		var finalityResponse bfgapi.L2KeystoneBitcoinFinalityResponse
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("received body in response: %s", body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code %d", resp.StatusCode)
		}

		if err := json.Unmarshal(body, &finalityResponse); err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(finalityResponse.L2Keystone, k); len(diff) > 0 {
			t.Fatalf("unexpected diff: %s", diff)
		}

		if finalityResponse.EffectiveConfirmations != uint(expectedConfirmations[i]) {
			t.Fatalf("unexpected effective confirmations. btc height %d, effective confirmations %d", finalityResponse.BlockHeight, finalityResponse.EffectiveConfirmations)
		}

		if finalityResponse.EffectiveConfirmations >= 10 && !*finalityResponse.SuperFinality {
			t.Fatalf("super finality should have been reached with effective confirmations of %d", finalityResponse.EffectiveConfirmations)
		}
	}
}

func TestGetFinalitiesByL2KeystoneBFGInOrder(t *testing.T) {
	ctx, cancel := defaultTestContext()
	defer cancel()

	levelDbHome, err := os.MkdirTemp("", "tbc-random-*") //nolint:all // I want to use this one
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := os.RemoveAll(levelDbHome); err != nil {
			t.Fatal(err)
		}
	}()

	cfg, err := level.NewConfig("localnet", levelDbHome, "0", "0")
	if err != nil {
		t.Fatal(err)
	}

	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	l2BlockNumber := 1
	keystoneOne := randomL2Keystone(&l2BlockNumber)
	l2BlockNumber++
	keystoneTwo := randomL2Keystone(&l2BlockNumber)
	l2BlockNumber++
	keystoneThree := randomL2Keystone(&l2BlockNumber)

	createChainWithKeystones(ctx, t, db, 13, map[uint64]tbcd.Keystone{
		1: {
			AbbreviatedKeystone: hemi.L2KeystoneAbbreviate(*keystoneOne).Serialize(),
		},
		2: {
			AbbreviatedKeystone: hemi.L2KeystoneAbbreviate(*keystoneTwo).Serialize(),
		},
		3: {
			AbbreviatedKeystone: hemi.L2KeystoneAbbreviate(*keystoneThree).Serialize(),
		},
	})

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(http.HandlerFunc(newMockOpgeth(ctx, t, []hemi.L2Keystone{
		*keystoneOne,
		*keystoneTwo,
		*keystoneThree,
	})))
	defer s.Close()

	opgethWsurl := "ws" + strings.TrimPrefix(s.URL, "http")

	_, bfgUrl := createBfgServer(ctx, t, levelDbHome, opgethWsurl)
	time.Sleep(2 * time.Second)

	expectedConfirmations := []int{
		11,
		10,
		9,
	}

	for i, k := range []hemi.L2Keystone{
		*keystoneOne,
		*keystoneTwo,
		*keystoneThree,
	} {
		bfgUrlTmp := fmt.Sprintf("http://%s/v2/keystonefinality/%s", bfgUrl, hemi.L2KeystoneAbbreviate(k).Hash())

		resp, err := http.Get(bfgUrlTmp) //nolint:all // this is fine
		if err != nil {
			t.Fatal(err)
		}

		defer resp.Body.Close()

		var finalityResponse bfgapi.L2KeystoneBitcoinFinalityResponse
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("received body in response: %s", body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code %d", resp.StatusCode)
		}

		if err := json.Unmarshal(body, &finalityResponse); err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(finalityResponse.L2Keystone, k); len(diff) > 0 {
			t.Fatalf("unexpected diff: %s", diff)
		}

		if finalityResponse.EffectiveConfirmations != uint(expectedConfirmations[i]) {
			t.Fatalf("unexpected effective confirmations. btc height %d, effective confirmations %d, expected %d", finalityResponse.BlockHeight, finalityResponse.EffectiveConfirmations, expectedConfirmations[i])
		}

		if finalityResponse.EffectiveConfirmations >= 10 && !*finalityResponse.SuperFinality {
			t.Fatalf("super finality should have been reached with effective confirmations of %d", finalityResponse.EffectiveConfirmations)
		}
	}
}

func TestGetFinalitiesByL2KeystoneBFGNotFoundOnChain(t *testing.T) {
	ctx, cancel := defaultTestContext()
	defer cancel()

	levelDbHome, err := os.MkdirTemp("", "tbc-random-*") //nolint:all // I want to use this one
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := os.RemoveAll(levelDbHome); err != nil {
			t.Fatal(err)
		}
	}()

	cfg, err := level.NewConfig("localnet", levelDbHome, "0", "0")
	if err != nil {
		t.Fatal(err)
	}

	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	keystoneOne := randomL2Keystone(nil)

	createChainWithKeystones(ctx, t, db, 13, map[uint64]tbcd.Keystone{})

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(http.HandlerFunc(newMockOpgeth(ctx, t, []hemi.L2Keystone{
		*keystoneOne,
	})))
	defer s.Close()

	opgethWsurl := "ws" + strings.TrimPrefix(s.URL, "http")

	_, bfgUrl := createBfgServer(ctx, t, levelDbHome, opgethWsurl)
	time.Sleep(2 * time.Second)

	bfgUrlTmp := fmt.Sprintf("http://%s/v2/keystonefinality/%s", bfgUrl, hemi.L2KeystoneAbbreviate(*keystoneOne).Hash())

	resp, err := http.Get(bfgUrlTmp) //nolint:all // this is fine
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, received %d", http.StatusNotFound, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("received body in response: %s", body)

	expectedConfirmations := []int{
		0,
	}

	for i, k := range []hemi.L2Keystone{
		*keystoneOne,
	} {
		bfgUrlTmp := fmt.Sprintf("http://%s/v2/keystonefinality/%s", bfgUrl, hemi.L2KeystoneAbbreviate(k).Hash())

		resp, err := http.Get(bfgUrlTmp) //nolint:all // this is fine
		if err != nil {
			t.Fatal(err)
		}

		defer resp.Body.Close()

		var finalityResponse bfgapi.L2KeystoneBitcoinFinalityResponse
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("received body in response: %s", body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code %d", resp.StatusCode)
		}

		if err := json.Unmarshal(body, &finalityResponse); err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(finalityResponse.L2Keystone, k); len(diff) > 0 {
			t.Fatalf("unexpected diff: %s", diff)
		}

		if finalityResponse.EffectiveConfirmations != uint(expectedConfirmations[i]) {
			t.Fatalf("unexpected effective confirmations. btc height %d, effective confirmations %d", finalityResponse.BlockHeight, finalityResponse.EffectiveConfirmations)
		}

		if finalityResponse.EffectiveConfirmations >= 10 && !*finalityResponse.SuperFinality {
			t.Fatalf("super finality should have been reached with effective confirmations of %d", finalityResponse.EffectiveConfirmations)
		}
	}
}

func TestGetFinalitiesByL2KeystoneBFGNotFoundOpGeth(t *testing.T) {
	ctx, cancel := defaultTestContext()
	defer cancel()

	levelDbHome, err := os.MkdirTemp("", "tbc-random-*") //nolint:all // I want to use this one
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := os.RemoveAll(levelDbHome); err != nil {
			t.Fatal(err)
		}
	}()

	cfg, err := level.NewConfig("localnet", levelDbHome, "0", "0")
	if err != nil {
		t.Fatal(err)
	}

	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	keystoneOne := randomL2Keystone(nil)

	createChainWithKeystones(ctx, t, db, 13, map[uint64]tbcd.Keystone{
		8: {
			AbbreviatedKeystone: hemi.L2KeystoneAbbreviate(*keystoneOne).Serialize(),
		},
	})

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(http.HandlerFunc(newMockOpgeth(ctx, t, []hemi.L2Keystone{})))
	defer s.Close()

	opgethWsurl := "ws" + strings.TrimPrefix(s.URL, "http")

	_, bfgUrl := createBfgServer(ctx, t, levelDbHome, opgethWsurl)
	time.Sleep(2 * time.Second)

	bfgUrlTmp := fmt.Sprintf("http://%s/v2/keystonefinality/%s", bfgUrl, hemi.L2KeystoneAbbreviate(*keystoneOne).Hash())

	resp, err := http.Get(bfgUrlTmp) //nolint:all // this is fine
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected %d, received %d", http.StatusNotFound, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("received body in response: %s", body)
}

func newMockOpgeth(ctx context.Context, t *testing.T, keystones []hemi.L2Keystone) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		upgrader := gwebsocket.Upgrader{}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			var err error
			mt, message, err := c.ReadMessage()
			if err != nil {
				break
			}

			type keystoneValidityRequest struct {
				Jsonrpc string        `json:"jsonrpc"`
				ID      int           `json:"id"`
				Method  string        `json:"method"`
				Params  []interface{} `json:"params"`
			}

			type keystoneVadlidityResponse struct {
				Jsonrpc string                         `json:"jsonrpc"`
				ID      int                            `json:"id"`
				Result  eth.L2KeystoneValidityResponse `json:"result"`
			}

			t.Logf("the ws request is %s", string(message))

			var l2KeystoneValidityRequest keystoneValidityRequest
			if err := json.Unmarshal(message, &l2KeystoneValidityRequest); err != nil {
				t.Fatal(err)
			}

			if l2KeystoneValidityRequest.Method != "kss_getKeystone" {
				continue
			}

			var responseMessage []byte

			hash, err := hex.DecodeString(l2KeystoneValidityRequest.Params[0].(string))
			if err != nil {
				t.Fatal(err)
			}

			slices.Reverse(hash)

			var l2KeystoneValidityResponse *eth.L2KeystoneValidityResponse

			for _, k := range keystones {
				if bytes.Equal(
					hash,
					hemi.L2KeystoneAbbreviate(k).Hash().CloneBytes(),
				) {
					l2KeystoneValidityResponse = &eth.L2KeystoneValidityResponse{
						L2Keystones: []hemi.L2Keystone{
							k,
						},
					}
				}
			}

			var fullResponseMessage keystoneVadlidityResponse

			if l2KeystoneValidityResponse == nil {
				fullResponseMessage = keystoneVadlidityResponse{
					Jsonrpc: l2KeystoneValidityRequest.Jsonrpc,
					ID:      l2KeystoneValidityRequest.ID,
					Result: eth.L2KeystoneValidityResponse{
						Error: protocol.Errorf("not found"),
					},
				}
			} else {
				fullResponseMessage = keystoneVadlidityResponse{
					Jsonrpc: l2KeystoneValidityRequest.Jsonrpc,
					ID:      l2KeystoneValidityRequest.ID,
					Result:  *l2KeystoneValidityResponse,
				}
			}

			responseMessage, err = json.Marshal(&fullResponseMessage)
			if err != nil {
				t.Fatalf("could not marshal response: %s", err)
			}

			t.Logf("writing ws response: %s", string(responseMessage))

			err = c.WriteMessage(mt, responseMessage)
			if err != nil {
				break
			}
		}
	}
}
