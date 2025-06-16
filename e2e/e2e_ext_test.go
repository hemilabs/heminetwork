// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/go-test/deep"
	"github.com/phayes/freeport"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/service/bfg"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/hemilabs/heminetwork/testutil"
	"github.com/hemilabs/heminetwork/testutil/mock"
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

func ConnectTCP(t *testing.T, addr string, timeout time.Duration) (net.Conn, error) {
	start := time.Now()
	t.Logf("ConnectTCP enters at: %v", start)
	defer func() { t.Logf("ConnectTCP duration: %v", time.Since(start)) }()

	d := net.Dialer{
		Deadline: time.Now().Add(5 * time.Second),
	}

	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func nextPort(ctx context.Context, t *testing.T) int {
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}

		port, err := freeport.GetFreePort()
		if err != nil {
			t.Fatal(err)
		}

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

	port := nextPort(ctx, t)

	bfgPublicListenAddress := net.JoinHostPort("", fmt.Sprintf("%d", port))

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

	bfgPublicUrl := net.JoinHostPort("localhost", fmt.Sprintf("%d", port))

	if conn, err := ConnectTCP(t, bfgPublicUrl, 5*time.Second); err != nil {
		t.Fatalf("could not connect to %s: %s", bfgPublicUrl, err.Error())
	} else {
		conn.Close()
	}

	// wait here for bfg to start up, setup routes, and populate db with
	// keystones from the btc chain
	time.Sleep(200 * time.Millisecond)

	return bfgServer, bfgPublicUrl
}

func createTbcServer(ctx context.Context, t *testing.T, levelDbHome string) (*tbc.Server, string) {
	port := nextPort(ctx, t)
	tbcPublicListenAddress := net.JoinHostPort("", fmt.Sprintf("%d", port))

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

	tbcPublicUrl := fmt.Sprintf("http://%s/v1/ws", net.JoinHostPort("localhost", fmt.Sprintf("%d", port)))

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
		k.L2BlockNumber = uint32(*l2BlockNumber)
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
			t.Logf("inserted keystone %s:%d at btc height %d", hemi.L2KeystoneAbrevDeserialize(l2Keystone.AbbreviatedKeystone).Hash(), hemi.L2KeystoneAbrevDeserialize(l2Keystone.AbbreviatedKeystone).L2BlockNumber, block.Height())
		}

		t.Logf("inserted block")
		prevHeader = &wireHeader
	}
}

func TestGetFinalitiesByL2KeystoneBFGInheritingfinality(t *testing.T) {
	t.Skip("FIXME: THIS FUNCTIONALITY NEEDS TO BE WORKING")

	ctx, cancel := defaultTestContext()
	defer cancel()

	levelDbHome, err := os.MkdirTemp("", "tbc-random-*") //nolint:all // I was having permission issues with TempDir() on mac
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

	opgeth := mock.NewMockOpGeth(ctx, nil, nil, []hemi.L2Keystone{
		*keystoneOne,
		*keystoneTwo,
	})
	defer opgeth.Shutdown()

	opgethWsurl := "ws" + strings.TrimPrefix(opgeth.URL(), "http")

	_, bfgUrl := createBfgServer(ctx, t, levelDbHome, opgethWsurl)

	expectedConfirmations := []int{
		11,
		11,
	}

	for i, k := range []hemi.L2Keystone{
		*keystoneOne,
		*keystoneTwo,
	} {
		bfgUrlTmp := fmt.Sprintf("http://%s/v2/keystonefinality/%s", bfgUrl, hemi.L2KeystoneAbbreviate(k).Hash())

		client := http.Client{}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, bfgUrlTmp, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(request)
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

	levelDbHome, err := os.MkdirTemp("", "tbc-random-*") //nolint:all // I was having permission issues with TempDir() on mac
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

	opgeth := mock.NewMockOpGeth(ctx, nil, nil, []hemi.L2Keystone{
		*keystoneOne,
		*keystoneTwo,
		*keystoneThree,
	})
	defer opgeth.Shutdown()

	opgethWsurl := "ws" + strings.TrimPrefix(opgeth.URL(), "http")

	_, bfgUrl := createBfgServer(ctx, t, levelDbHome, opgethWsurl)

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

		t.Logf("will query for %s", bfgUrlTmp)

		client := http.Client{}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, bfgUrlTmp, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(request)
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

	levelDbHome, err := os.MkdirTemp("", "tbc-random-*") //nolint:all // I was having permission issues with TempDir() on mac
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

	opgeth := mock.NewMockOpGeth(ctx, nil, nil, []hemi.L2Keystone{
		*keystoneOne,
	})
	defer opgeth.Shutdown()

	opgethWsurl := "ws" + strings.TrimPrefix(opgeth.URL(), "http")

	_, bfgUrl := createBfgServer(ctx, t, levelDbHome, opgethWsurl)

	bfgUrlTmp := fmt.Sprintf("http://%s/v2/keystonefinality/%s", bfgUrl, hemi.L2KeystoneAbbreviate(*keystoneOne).Hash())

	client := http.Client{}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, bfgUrlTmp, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(request)
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

		client := http.Client{}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, bfgUrlTmp, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(request)
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

	levelDbHome, err := os.MkdirTemp("", "tbc-random-*") //nolint:all // I was having permission issues with TempDir() on mac
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

	opgeth := mock.NewMockOpGeth(ctx, nil, nil, []hemi.L2Keystone{})
	defer opgeth.Shutdown()

	opgethWsurl := "ws" + strings.TrimPrefix(opgeth.URL(), "http")

	_, bfgUrl := createBfgServer(ctx, t, levelDbHome, opgethWsurl)

	bfgUrlTmp := fmt.Sprintf("http://%s/v2/keystonefinality/%s", bfgUrl, hemi.L2KeystoneAbbreviate(*keystoneOne).Hash())

	client := http.Client{}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, bfgUrlTmp, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(request)
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
