// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/go-test/deep"
	"github.com/phayes/freeport"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

const (
	privateKey  = "72a2c41c84147325ce3c0f37697ef1e670c7169063dda89be9995c3c5219740f"
	levelDbHome = ".testleveldb"
)

type StdoutLogConsumer struct {
	Name string // name of service
}

func (t *StdoutLogConsumer) Accept(l testcontainers.Log) {
	fmt.Printf("%s: %s", t.Name, string(l.Content))
}

func skipIfNoDocker(t *testing.T) {
	envValue := os.Getenv("HEMI_DOCKER_TESTS")
	val, err := strconv.ParseBool(envValue)
	if envValue != "" && err != nil {
		t.Fatal(err)
	}

	if !val {
		t.Skip("skipping docker tests")
	}
}

func TestBlockHeadersByHeightRaw(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 100, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()
	_, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.BlockHeadersByHeightRawResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		lastErr = nil
		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRawRequest{
			Height: 55,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdBlockHeadersByHeightRawResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}
			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}
	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}

	bh, err := bytes2Header(response.BlockHeaders[0])
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(spew.Sdump(bh))

	if response.Error != nil {
		t.Errorf("got unwanted error: %v", response.Error)
	}

	cliBlockHeader := bitcoindBlockAtHeight(ctx, t, bitcoindContainer, 55)
	expected := cliBlockHeaderToRaw(t, cliBlockHeader)
	if diff := deep.Equal(expected, response.BlockHeaders); len(diff) > 0 {
		t.Errorf("unexpected diff: %s", diff)
	}
}

func TestBlockHeadersByHeight(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 100, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.BlockHeadersByHeightResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		lastErr = nil
		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRequest{
			Height: 55,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdBlockHeadersByHeightResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}
			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}

	if response.Error != nil {
		t.Errorf("got unwanted error: %v", response.Error)
	}

	cliBlockHeader := bitcoindBlockAtHeight(ctx, t, bitcoindContainer, 55)
	expected := cliBlockHeaderToTBC(t, cliBlockHeader)
	if diff := deep.Equal(expected, response.BlockHeaders); len(diff) > 0 {
		t.Errorf("unexpected diff: %s", diff)
	}
}

func TestBlockHeadersByHeightDoesNotExist(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 100, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.BlockHeadersByHeightResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		lastErr = nil
		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRequest{
			Height: 550,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdBlockHeadersByHeightResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}
			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}

	if response.Error.Message != "block headers not found at height 550" {
		t.Fatalf("unexpected error message: %s", response.Error.Message)
	}
}

func TestBlockHeadersBestRaw(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 50, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.BlockHeadersBestRawResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		lastErr = nil
		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersBestRawRequest{})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdBlockHeadersBestRawResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}
			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}
	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}

	bh, err := bytes2Header(response.BlockHeaders[0])
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(spew.Sdump(bh))

	if response.Error != nil {
		t.Errorf("got unwanted error: %v", response.Error)
	}

	cliBlockHeader := bitcoindBestBlock(ctx, t, bitcoindContainer)
	expected := cliBlockHeaderToRaw(t, cliBlockHeader)
	if diff := deep.Equal(expected, response.BlockHeaders); len(diff) > 0 {
		t.Errorf("unexpected diff: %s", diff)
	}
}

func TestBtcBlockHeadersBest(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 100, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.BlockHeadersBestResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		lastErr = nil
		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersBestRequest{})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdBlockHeadersBestResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}
			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}

	if response.Error != nil {
		t.Errorf("got unwanted error: %v", response.Error)
	}

	cliBlockHeader := bitcoindBestBlock(ctx, t, bitcoindContainer)
	expected := cliBlockHeaderToTBC(t, cliBlockHeader)
	if diff := deep.Equal(expected, response.BlockHeaders); len(diff) > 0 {
		t.Errorf("unexpected diff: %s", diff)
	}
}

func TestServerBlockHeadersBest(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	blocks := uint64(100)
	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, blocks, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	tbcServer, _ := createTbcServer(ctx, t, mappedPeerPort)

	select {
	case <-time.After(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	height, bhs, err := tbcServer.BlockHeadersBest(ctx)
	if err != nil {
		t.Errorf("BlockHeadersBest() err = %v, want nil", err)
	}

	if l := len(bhs); l != 1 {
		t.Errorf("BlockHeadersBest() block len = %d, want 1", l)
	}

	if height != blocks {
		t.Errorf("BlockHeadersBest() height = %d, want %d", height, blocks)
	}
}

func TestBalanceByAddress(t *testing.T) {
	skipIfNoDocker(t)

	type testTableItem struct {
		name          string
		address       func() string
		doNotGenerate bool
	}

	testTable := []testTableItem{
		{
			name: "Pay to public key hash",
			address: func() string {
				_, _, address, err := bitcoin.KeysAndAddressFromHexString(
					privateKey,
					&chaincfg.RegressionNetParams,
				)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
		},
		{
			name: "Pay to script hash",
			address: func() string {
				address, err := btcutil.NewAddressScriptHash([]byte("blahblahscripthash"), &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
		},
		{
			name: "Pay to witness public key hash",
			address: func() string {
				address, err := btcutil.NewAddressWitnessPubKeyHash([]byte("blahblahwitnesspublickeyhash")[:20], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
		},
		{
			name: "Pay to witness script hash",
			address: func() string {
				address, err := btcutil.NewAddressWitnessScriptHash([]byte("blahblahwitnessscripthashblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
		},
		{
			name: "Pay to taproot",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
		},
		{
			name: "no balance",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			doNotGenerate: true,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			initialBlocks := 0
			if !tti.doNotGenerate {
				initialBlocks = 4
			}

			bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, uint64(initialBlocks), tti.address())
			defer func() {
				if err := bitcoindContainer.Terminate(ctx); err != nil {
					panic(err)
				}
			}()

			// generate to another address to ensure it's not included in our query
			someOtherAddress, err := btcutil.NewAddressScriptHash([]byte("blahblahotherscripthash"), &chaincfg.RegressionNetParams)
			if err != nil {
				t.Fatal(err)
			}
			_, err = runBitcoinCommand(
				ctx,
				t,
				bitcoindContainer,
				[]string{
					"bitcoin-cli",
					"-regtest=1",
					"generatetoaddress",
					"3",
					someOtherAddress.EncodeAddress(),
				})
			if err != nil {
				t.Fatal(err)
			}

			tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

			c, _, err := websocket.Dial(ctx, tbcUrl, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{
				conn: protocol.NewWSConn(c),
			}

			var lastErr error
			var response tbcapi.BalanceByAddressResponse
			for {
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				err = tbcServer.UtxoIndexer(ctx, 0, 1000)
				if err != nil {
					t.Fatal(err)
				}
				lastErr = nil
				err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BalanceByAddressRequest{
					Address: tti.address(),
				})
				if err != nil {
					lastErr = err
					continue
				}

				var v protocol.Message
				err = wsjson.Read(ctx, c, &v)
				if err != nil {
					lastErr = err
					continue
				}

				if v.Header.Command == tbcapi.CmdBalanceByAddressResponse {
					if err := json.Unmarshal(v.Payload, &response); err != nil {
						t.Fatal(err)
					}

					var pricePerBlock uint64 = 50 * 100000000
					var blocks uint64 = 4
					var expectedBalance uint64 = 0
					if !tti.doNotGenerate {
						expectedBalance = pricePerBlock * blocks
					}

					expected := tbcapi.BalanceByAddressResponse{
						Balance: expectedBalance,
						Error:   nil,
					}
					if diff := deep.Equal(expected, response); len(diff) > 0 {
						if response.Error != nil {
							t.Error(response.Error.Message)
						}
						t.Logf("unexpected diff: %s", diff)

						// there is a chance we just haven't finished indexing
						// the blocks and txs, retry until timeout
						continue
					}
					break
				} else {
					lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
				}

			}

			if lastErr != nil {
				t.Fatal(lastErr)
			}
		})
	}
}

func TestUtxosByAddressRaw(t *testing.T) {
	skipIfNoDocker(t)

	type testTableItem struct {
		name          string
		address       func() string
		doNotGenerate bool
		limit         uint64
		start         uint64
	}

	testTable := []testTableItem{
		{
			name: "Pay to public key hash",
			address: func() string {
				_, _, address, err := bitcoin.KeysAndAddressFromHexString(
					privateKey,
					&chaincfg.RegressionNetParams,
				)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "Pay to script hash",
			address: func() string {
				address, err := btcutil.NewAddressScriptHash([]byte("blahblahscripthash"), &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "Pay to witness public key hash",
			address: func() string {
				address, err := btcutil.NewAddressWitnessPubKeyHash([]byte("blahblahwitnesspublickeyhash")[:20], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "Pay to witness script hash",
			address: func() string {
				address, err := btcutil.NewAddressWitnessScriptHash([]byte("blahblahwitnessscripthashblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "Pay to taproot",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "no balance",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			doNotGenerate: true,
			limit:         10,
		},
		{
			name: "small limit",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblahsmalllimit")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 2,
		},
		{
			name: "offset",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblahsmalllimit")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			start: 3,
			limit: 10,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			var bitcoindContainer testcontainers.Container
			var mappedPeerPort nat.Port
			initialBlocks := 0
			if !tti.doNotGenerate {
				initialBlocks = 4
			}
			bitcoindContainer, mappedPeerPort = createBitcoindWithInitialBlocks(ctx, t, uint64(initialBlocks), tti.address())
			defer func() {
				if err := bitcoindContainer.Terminate(ctx); err != nil {
					panic(err)
				}
			}()

			// generate to another address to ensure it's not included in our query
			someOtherAddress, err := btcutil.NewAddressScriptHash([]byte("blahblahotherscripthash"), &chaincfg.RegressionNetParams)
			if err != nil {
				t.Fatal(err)
			}
			_, err = runBitcoinCommand(
				ctx,
				t,
				bitcoindContainer,
				[]string{
					"bitcoin-cli",
					"-regtest=1",
					"generatetoaddress",
					"3",
					someOtherAddress.EncodeAddress(),
				})
			if err != nil {
				t.Fatal(err)
			}

			tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

			c, _, err := websocket.Dial(ctx, tbcUrl, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{
				conn: protocol.NewWSConn(c),
			}

			var lastErr error
			var response tbcapi.UtxosByAddressRawResponse
			for {
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				err = tbcServer.UtxoIndexer(ctx, 0, 1000)
				if err != nil {
					t.Fatal(err)
				}
				lastErr = nil
				err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.UtxosByAddressRawRequest{
					Address: tti.address(),
					Start:   uint(tti.start),
					Count:   uint(tti.limit),
				})
				if err != nil {
					lastErr = err
					continue
				}

				var v protocol.Message
				err = wsjson.Read(ctx, c, &v)
				if err != nil {
					lastErr = err
					continue
				}

				if v.Header.Command == tbcapi.CmdUtxosByAddressRawResponse {
					if err := json.Unmarshal(v.Payload, &response); err != nil {
						t.Fatal(err)
					}

					// we generated 4 blocks to this address previously, therefore
					// there should be 4 utxos
					expectedCount := 4 - tti.start
					if tti.limit < uint64(expectedCount) {
						expectedCount = tti.limit
					}

					if !tti.doNotGenerate && len(response.Utxos) != int(expectedCount) {
						t.Fatalf("should have %d utxos, received: %d", expectedCount, len(response.Utxos))
					} else if tti.doNotGenerate && len(response.Utxos) != 0 {
						t.Fatalf("did not generate any blocks for address, should not have utxos")
					}
					break
				} else {
					lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
				}

			}

			if lastErr != nil {
				t.Fatal(lastErr)
			}
		})
	}
}

func TestUtxosByAddress(t *testing.T) {
	skipIfNoDocker(t)

	type testTableItem struct {
		name          string
		address       func() string
		doNotGenerate bool
		limit         uint64
		start         uint64
	}

	testTable := []testTableItem{
		{
			name: "Pay to public key hash",
			address: func() string {
				_, _, address, err := bitcoin.KeysAndAddressFromHexString(
					privateKey,
					&chaincfg.RegressionNetParams,
				)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "Pay to script hash",
			address: func() string {
				address, err := btcutil.NewAddressScriptHash([]byte("blahblahscripthash"), &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "Pay to witness public key hash",
			address: func() string {
				address, err := btcutil.NewAddressWitnessPubKeyHash([]byte("blahblahwitnesspublickeyhash")[:20], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "Pay to witness script hash",
			address: func() string {
				address, err := btcutil.NewAddressWitnessScriptHash([]byte("blahblahwitnessscripthashblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "Pay to taproot",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 10,
		},
		{
			name: "no balance",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblah")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			doNotGenerate: true,
			limit:         10,
		},
		{
			name: "small limit",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblahsmalllimit")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			limit: 2,
		},
		{
			name: "offset",
			address: func() string {
				address, err := btcutil.NewAddressTaproot([]byte("blahblahwtaprootblahblahblahblahsmalllimit")[:32], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}

				return address.EncodeAddress()
			},
			start: 3,
			limit: 10,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			var bitcoindContainer testcontainers.Container
			var mappedPeerPort nat.Port
			initialBlocks := 0
			if !tti.doNotGenerate {
				initialBlocks = 4
			}
			bitcoindContainer, mappedPeerPort = createBitcoindWithInitialBlocks(ctx, t, uint64(initialBlocks), tti.address())
			defer func() {
				if err := bitcoindContainer.Terminate(ctx); err != nil {
					panic(err)
				}
			}()

			// generate to another address to ensure it's not included in our query
			someOtherAddress, err := btcutil.NewAddressScriptHash([]byte("blahblahotherscripthash"), &chaincfg.RegressionNetParams)
			if err != nil {
				t.Fatal(err)
			}
			_, err = runBitcoinCommand(
				ctx,
				t,
				bitcoindContainer,
				[]string{
					"bitcoin-cli",
					"-regtest=1",
					"generatetoaddress",
					"3",
					someOtherAddress.EncodeAddress(),
				})
			if err != nil {
				t.Fatal(err)
			}

			tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

			c, _, err := websocket.Dial(ctx, tbcUrl, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{
				conn: protocol.NewWSConn(c),
			}

			var lastErr error
			var response tbcapi.UtxosByAddressResponse
			for {
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				err = tbcServer.UtxoIndexer(ctx, 0, 1000)
				if err != nil {
					t.Fatal(err)
				}
				lastErr = nil
				err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.UtxosByAddressRequest{
					Address: tti.address(),
					Start:   uint(tti.start),
					Count:   uint(tti.limit),
				})
				if err != nil {
					lastErr = err
					continue
				}

				var v protocol.Message
				err = wsjson.Read(ctx, c, &v)
				if err != nil {
					lastErr = err
					continue
				}

				if v.Header.Command == tbcapi.CmdUtxosByAddressResponse {
					if err := json.Unmarshal(v.Payload, &response); err != nil {
						t.Fatal(err)
					}

					// we generated 4 blocks to this address previously, therefore
					// there should be 4 utxos
					expectedCount := 4 - tti.start
					if tti.limit < uint64(expectedCount) {
						expectedCount = tti.limit
					}

					if !tti.doNotGenerate && len(response.Utxos) != int(expectedCount) {
						t.Fatalf("should have %d utxos, received: %d", expectedCount, len(response.Utxos))
					} else if tti.doNotGenerate && len(response.Utxos) != 0 {
						t.Fatalf("did not generate any blocks for address, should not have utxos")
					}
					break
				} else {
					lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
				}

			}

			if lastErr != nil {
				t.Fatal(lastErr)
			}
		})
	}
}

func TestTxByIdRaw(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	_, _, address, err := bitcoin.KeysAndAddressFromHexString(
		privateKey,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 4, address.String())
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.TxByIdRawResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		err = tbcServer.TxIndexer(ctx, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		lastErr = nil
		txId := getRandomTxId(ctx, t, bitcoindContainer)
		txIdBytes, err := hex.DecodeString(txId)
		if err != nil {
			t.Fatal(err)
		}

		slices.Reverse(txIdBytes) // convert to natural order

		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRawRequest{
			TxId: txIdBytes,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdTxByIdRawResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			if response.Error != nil {
				t.Fatal(response.Error.Message)
			}

			// XXX - write a better test than this, we should be able to compare
			// against bitcoin-cli response fields

			// did we get the tx and can we parse it?
			tx, err := bytes2Tx(response.Tx)
			if err != nil {
				t.Fatal(err)
			}

			// is the hash equal to what we queried for?
			if tx.TxHash().String() != txId {
				t.Fatalf("id mismatch: %s != %s", tx.TxHash().String(), txId)
			}

			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}
}

func TestTxByIdRawInvalid(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	_, _, address, err := bitcoin.KeysAndAddressFromHexString(
		privateKey,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 4, address.String())
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.TxByIdRawResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		err = tbcServer.TxIndexer(ctx, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		lastErr = nil
		txId := getRandomTxId(ctx, t, bitcoindContainer)
		txIdBytes, err := hex.DecodeString(txId)
		if err != nil {
			t.Fatal(err)
		}

		txIdBytes[0]++

		slices.Reverse(txIdBytes) // convert to natural order

		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRawRequest{
			TxId: txIdBytes,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdTxByIdRawResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			if response.Error == nil {
				t.Fatal("expecting error")
			}

			if response.Error != nil {
				if !strings.Contains(response.Error.Message, "not found:") {
					t.Fatalf("incorrect error found %s", response.Error.Message)
				}
			}

			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}
}

func TestTxByIdRawNotFound(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 0, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, _, address, err := bitcoin.KeysAndAddressFromHexString(
		privateKey,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"generatetoaddress",
			"4",
			address.EncodeAddress(),
		})
	if err != nil {
		t.Fatal(err)
	}

	tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.TxByIdRawResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		err = tbcServer.TxIndexer(ctx, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		lastErr = nil
		txId := getRandomTxId(ctx, t, bitcoindContainer)
		txIdBytes, err := hex.DecodeString(txId)
		if err != nil {
			t.Fatal(err)
		}

		txIdBytes = append(txIdBytes, 8)

		slices.Reverse(txIdBytes) // convert to natural order

		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRawRequest{
			TxId: txIdBytes,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdTxByIdRawResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			if response.Error == nil {
				t.Fatal("expecting error")
			}

			if response.Error != nil {
				if !strings.Contains(response.Error.Message, "invalid tx id") {
					t.Fatalf("incorrect error found: %s", response.Error.Message)
				}
			}

			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}
}

func TestTxById(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	_, _, address, err := bitcoin.KeysAndAddressFromHexString(
		privateKey,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 4, address.String())
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.TxByIdResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		err = tbcServer.TxIndexer(ctx, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		lastErr = nil
		txId := getRandomTxId(ctx, t, bitcoindContainer)
		txIdBytes, err := hex.DecodeString(txId)
		if err != nil {
			t.Fatal(err)
		}

		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRequest{
			TxId: txIdBytes,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdTxByIdResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			if response.Error != nil {
				t.Fatal(response.Error.Message)
			}

			tx, err := tbcServer.TxById(ctx, tbcd.TxId(reverseBytes(txIdBytes)))
			if err != nil {
				t.Fatal(err)
			}

			w := wireTxToTBC(tx)

			if diff := deep.Equal(w, response.Tx); len(diff) > 0 {
				t.Fatal(diff)
			}

			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}
}

func TestTxByIdInvalid(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	_, _, address, err := bitcoin.KeysAndAddressFromHexString(
		privateKey,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 4, address.String())
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.TxByIdResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		err = tbcServer.TxIndexer(ctx, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		lastErr = nil
		txId := getRandomTxId(ctx, t, bitcoindContainer)
		txIdBytes, err := hex.DecodeString(txId)
		if err != nil {
			t.Fatal(err)
		}

		txIdBytes[0]++

		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRequest{
			TxId: txIdBytes,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdTxByIdResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			if response.Error == nil {
				t.Fatal("expecting error")
			}

			if response.Error != nil {
				if !strings.Contains(response.Error.Message, "not found:") {
					t.Fatalf("incorrect error found %s", response.Error.Message)
				}
			}

			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}
}

func TestTxByIdNotFound(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 0, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, _, address, err := bitcoin.KeysAndAddressFromHexString(
		privateKey,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"generatetoaddress",
			"4",
			address.EncodeAddress(),
		})
	if err != nil {
		t.Fatal(err)
	}

	tbcServer, tbcUrl := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var lastErr error
	var response tbcapi.TxByIdResponse
	for {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		err = tbcServer.TxIndexer(ctx, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		lastErr = nil
		txId := getRandomTxId(ctx, t, bitcoindContainer)
		txIdBytes, err := hex.DecodeString(txId)
		if err != nil {
			t.Fatal(err)
		}

		txIdBytes = append(txIdBytes, 8)

		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRequest{
			TxId: txIdBytes,
		})
		if err != nil {
			lastErr = err
			continue
		}

		var v protocol.Message
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			lastErr = err
			continue
		}

		if v.Header.Command == tbcapi.CmdTxByIdResponse {
			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			if response.Error == nil {
				t.Fatal("expecting error")
			}

			if response.Error != nil {
				if !strings.Contains(response.Error.Message, "invalid tx id") {
					t.Fatalf("incorrect error found: %s", response.Error.Message)
				}
			}

			break
		} else {
			lastErr = fmt.Errorf("received unexpected command: %s", v.Header.Command)
		}

	}

	if lastErr != nil {
		t.Fatal(lastErr)
	}
}

func createBitcoind(ctx context.Context, t *testing.T) testcontainers.Container {
	id, err := randHexId(6)
	if err != nil {
		t.Fatal("failed to generate random id:", err)
	}

	name := fmt.Sprintf("bitcoind-%s", id)
	req := testcontainers.ContainerRequest{
		Image:        "kylemanna/bitcoind",
		Cmd:          []string{"bitcoind", "-regtest=1", "-debug=1", "-rpcallowip=0.0.0.0/0", "-rpcbind=0.0.0.0:18443", "-txindex=1", "-noonion", "-listenonion=0"},
		ExposedPorts: []string{"18443", "18444"},
		WaitingFor:   wait.ForLog("dnsseed thread exit").WithPollInterval(1 * time.Second),
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&StdoutLogConsumer{
				Name: name,
			}},
		},
		Name: name,
		HostConfigModifier: func(hostConfig *container.HostConfig) {
			hostConfig.PortBindings = nat.PortMap{
				"18443/tcp": []nat.PortBinding{
					{
						HostPort: "18443",
					},
				},
				"18444/tcp": []nat.PortBinding{
					{
						HostPort: "18444",
					},
				},
			}
		},
	}
	bitcoindContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	return bitcoindContainer
}

func runBitcoinCommand(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container, cmd []string) (string, error) {
	exitCode, result, err := bitcoindContainer.Exec(ctx, cmd)
	if err != nil {
		return "", err
	}

	buf := new(strings.Builder)
	_, err = io.Copy(buf, result)
	if err != nil {
		return "", err
	}
	t.Logf(buf.String())

	if exitCode != 0 {
		return "", fmt.Errorf("error code received: %d", exitCode)
	}

	// first 8 bytes are header, there is also a newline character at the end of the response
	return buf.String()[8 : len(buf.String())-1], nil
}

func getRandomTxId(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container) string {
	blockHash, err := runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"getblockhash",
			fmt.Sprintf("%d", 1),
		})
	if err != nil {
		t.Fatal(err)
	}

	blockJson, err := runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"getblock",
			blockHash,
		})
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		Tx []string `json:"tx"`
	}
	if err := json.Unmarshal([]byte(blockJson), &parsed); err != nil {
		t.Fatal(err)
	}

	if len(parsed.Tx) == 0 {
		t.Fatal("was expecting at least 1 transaction")
	}

	return parsed.Tx[0]
}

func getEndpointWithRetries(ctx context.Context, container testcontainers.Container, retries int) (string, error) {
	backoff := 500 * time.Millisecond
	var lastError error
	for range retries {
		endpoint, err := container.Endpoint(ctx, "")
		if err != nil {
			lastError = err
			time.Sleep(backoff)
			backoff = backoff * 2
			continue
		}
		return endpoint, nil
	}

	return "", lastError
}

func nextPort() int {
	ports, err := freeport.GetFreePorts(1000)
	if err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}

	return ports[time.Now().Unix()%int64(len(ports))]
}

func createTbcServer(ctx context.Context, t *testing.T, mappedPeerPort nat.Port) (*Server, string) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	home := fmt.Sprintf("%s/%s", wd, levelDbHome)

	if err := os.RemoveAll(home); err != nil {
		t.Fatal(err)
	}
	tcbListenAddress := fmt.Sprintf(":%d", nextPort())

	cfg := NewDefaultConfig()
	cfg.LevelDBHome = home
	cfg.Network = networkLocalnet
	cfg.ListenAddress = tcbListenAddress
	tbcServer, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tbcServer.ignoreUlimit = true

	go func() {
		err := tbcServer.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// let tbc index
	select {
	case <-time.After(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	tbcUrl := fmt.Sprintf("http://localhost%s%s", tcbListenAddress, tbcapi.RouteWebsocket)
	err = EnsureCanConnect(t, tbcUrl, 5*time.Second)
	if err != nil {
		t.Fatalf("could not connect to %s: %s", tbcUrl, err.Error())
	}

	return tbcServer, tbcUrl
}

func EnsureCanConnect(t *testing.T, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
		return fmt.Errorf("timed out trying to reach WS server in tests, last error: %s", err)
	}

	return nil
}

func assertPing(ctx context.Context, t *testing.T, c *websocket.Conn, cmd protocol.Command) {
	var v protocol.Message
	err := wsjson.Read(ctx, c, &v)
	if err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != cmd {
		t.Fatalf("unexpected command: %s", v.Header.Command)
	}
}

// BtcCliBlockHeader represents the block header structure used by bitcoin-cli.
type BtcCliBlockHeader struct {
	Hash              string  `json:"hash"`
	Confirmations     int     `json:"confirmations"`
	Height            uint32  `json:"height"`
	Version           uint64  `json:"version"`
	VersionHex        string  `json:"versionHex"`
	MerkleRoot        string  `json:"merkleroot"`
	Time              uint64  `json:"time"`
	MedianTime        uint64  `json:"mediantime"`
	Nonce             uint64  `json:"nonce"`
	Bits              string  `json:"bits"`
	Difficulty        float64 `json:"difficulty"`
	Chainwork         string  `json:"chainwork"`
	NTx               uint64  `json:"nTx"`
	PreviousBlockHash string  `json:"previousblockhash"`
	NextBlockHash     string  `json:"nextblockhash"`
}

// cliBlockHeaderToWire converts a bitcoin-cli block header to the
// [wire.BlockHeader] representation of the block header.
func cliBlockHeaderToWire(t *testing.T, header *BtcCliBlockHeader) *wire.BlockHeader {
	prevBlockHash, err := chainhash.NewHashFromStr(header.PreviousBlockHash)
	if err != nil {
		t.Fatal(fmt.Errorf("convert prevBlockHash to chainhash: %w", err))
	}
	merkleRoot, err := chainhash.NewHashFromStr(header.MerkleRoot)
	if err != nil {
		t.Fatal(fmt.Errorf("convert merkleRoot to chainhash: %w", err))
	}
	bits, err := strconv.ParseUint(header.Bits, 16, 64)
	if err != nil {
		t.Fatal(fmt.Errorf("parse bits as uint: %w", err))
	}

	blockHeader := wire.NewBlockHeader(
		int32(header.Version),
		prevBlockHash,
		merkleRoot,
		uint32(bits),
		uint32(header.Nonce),
	)
	blockHeader.Timestamp = time.Unix(int64(header.Time), 0)
	return blockHeader
}

// cliBlockHeaderToRaw converts a bitcoin-cli block header to a slice containing
// the raw byte representation of the block header.
func cliBlockHeaderToRaw(t *testing.T, cliBlockHeader *BtcCliBlockHeader) []api.ByteSlice {
	blockHeader := cliBlockHeaderToWire(t, cliBlockHeader)
	t.Logf(spew.Sdump(blockHeader))

	bytes, err := header2Bytes(blockHeader)
	if err != nil {
		t.Fatal(fmt.Errorf("header to bytes: %w", err))
	}

	return []api.ByteSlice{bytes}
}

// cliBlockHeaderToTBC converts a bitcoin-cli block header to a slice containing
// the [tbcapi.BlockHeader] representation of the block header.
func cliBlockHeaderToTBC(t *testing.T, btcCliBlockHeader *BtcCliBlockHeader) []*tbcapi.BlockHeader {
	blockHeader := cliBlockHeaderToWire(t, btcCliBlockHeader)
	t.Logf(spew.Sdump(blockHeader))
	return wireBlockHeadersToTBC([]*wire.BlockHeader{blockHeader})
}

func bitcoindBlockAtHeight(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container, height uint64) *BtcCliBlockHeader {
	blockHash, err := runBitcoinCommand(ctx, t, bitcoindContainer, []string{
		"bitcoin-cli",
		"-regtest=1",
		"getblockhash",
		fmt.Sprintf("%d", height),
	})
	if err != nil {
		t.Fatal(fmt.Errorf("bitcoin-cli getblockhash %d: %w", height, err))
	}

	return bitcoindBlockByHash(ctx, t, bitcoindContainer, blockHash)
}

func bitcoindBestBlock(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container) *BtcCliBlockHeader {
	blockHash, err := runBitcoinCommand(ctx, t, bitcoindContainer, []string{
		"bitcoin-cli",
		"-regtest=1",
		"getbestblockhash",
	})
	if err != nil {
		t.Fatal(fmt.Errorf("bitcoin-cli getbestblockhash: %w", err))
	}

	return bitcoindBlockByHash(ctx, t, bitcoindContainer, blockHash)
}

func bitcoindBlockByHash(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container, blockHash string) *BtcCliBlockHeader {
	blockHeaderJson, err := runBitcoinCommand(
		ctx, t, bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"getblockheader",
			blockHash,
		})
	if err != nil {
		t.Fatal(fmt.Errorf("bitcoin-cli getblockheader: %w", err))
	}

	var btcCliBlockHeader BtcCliBlockHeader
	if err = json.Unmarshal([]byte(blockHeaderJson), &btcCliBlockHeader); err != nil {
		t.Fatal(fmt.Errorf("unmarshal json output: %w", err))
	}

	return &btcCliBlockHeader
}

func createBitcoindWithInitialBlocks(ctx context.Context, t *testing.T, blocks uint64, overrideAddress string) (testcontainers.Container, nat.Port) {
	t.Helper()

	bitcoindContainer := createBitcoind(ctx, t)

	_, _, btcAddress, err := bitcoin.KeysAndAddressFromHexString(
		privateKey,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	var address string
	if overrideAddress != "" {
		address = overrideAddress
	} else {
		address = btcAddress.EncodeAddress()
	}

	_, err = runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"generatetoaddress",
			strconv.FormatUint(blocks, 10),
			address,
		})
	if err != nil {
		t.Fatal(err)
	}

	return bitcoindContainer, nat.Port(localnetPort)
}
