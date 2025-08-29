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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/v2/api/bfgapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer/tbcgozer"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/service/bfg"
	"github.com/hemilabs/heminetwork/v2/service/tbc"
	"github.com/hemilabs/heminetwork/v2/testutil"
	"github.com/hemilabs/heminetwork/v2/testutil/mock"
)

func nextPort(ctx context.Context, t *testing.T) int {
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}

		if _, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", testutil.FreePort()), 1*time.Second); err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				// connection error, port is open
				port, _ := strconv.Atoi(testutil.FreePort())
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
	time.Sleep(time.Second) // Let bfg settle

	bfgPublicUrl := net.JoinHostPort("localhost", fmt.Sprintf("%d", port))

	if err := EnsureCanConnectHTTP(t, fmt.Sprintf("http://%s/somethinginvalid", bfgPublicUrl)); err != nil {
		t.Fatalf("could not make http request to bfg in timeout: %s", err)
	}

	return bfgServer, bfgPublicUrl
}

func EnsureCanConnectHTTP(t *testing.T, url string) error {
	client := &http.Client{}
	for {
		t.Logf("try to connect: %v", url)
		defer t.Logf("connected:  %v", url)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx,
			http.MethodGet, url, http.NoBody)
		if err != nil {
			return err
		}
		resp, err := client.Do(request)
		if err != nil {
			if t.Context().Err() != nil {
				return t.Context().Err()
			}
			t.Logf("could not make http request: %s", err)
			continue
		}
		defer resp.Body.Close()

		// we're making an http request to an invalid URL, ensure
		// that we get the expected code of 404: Not Found
		if resp.StatusCode == http.StatusNotFound {
			return nil
		}
	}
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
	time.Sleep(time.Second) // Let tbc settle

	tbcPublicUrl := fmt.Sprintf("http://%s/v1/ws",
		net.JoinHostPort("localhost", fmt.Sprintf("%d", port)))

	// Connect with gozer to ensure connectedness
	g := tbcgozer.New(tbcPublicUrl)
	err = g.Run(ctx, nil)
	if err != nil {
		panic(err)
	}
	for {
		select {
		case <-ctx.Done():
			panic(ctx.Err())
		case <-time.Tick(50 * time.Millisecond):
		}
		if _, _, _, err := g.BestHeightHashTime(ctx); err == nil {
			break
		}
	}
	t.Logf("gozer connected")

	return tbcServer, tbcPublicUrl
}

func defaultTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithTimeout(t.Context(), 15*time.Second)
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
	ctx, cancel := defaultTestContext(t)
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
	}, 12)
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
		t.Logf("%v", bfgUrlTmp)

		client := &http.Client{}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, bfgUrlTmp, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(request)
		if err != nil {
			panic(err)
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
	ctx, cancel := defaultTestContext(t)
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
	}, 12)
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
	ctx, cancel := defaultTestContext(t)
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
	}, 12)
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
	ctx, cancel := defaultTestContext(t)
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

	opgeth := mock.NewMockOpGeth(ctx, nil, nil, []hemi.L2Keystone{}, 12)
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
