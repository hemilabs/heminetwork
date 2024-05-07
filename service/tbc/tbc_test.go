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
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
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

func TestForksWithGen(t *testing.T) {
	skipIfNoDocker(t)

	otherPrivateKey := "72a2c41c84147325ce3c0f37697ef1e670c7169063dda89be9995c3c5219ffff"
	_, _, otherAddress, err := bitcoin.KeysAndAddressFromHexString(
		otherPrivateKey,
		&chaincfg.RegressionNetParams,
	)
	if err != nil {
		t.Fatal(err)
	}

	type tbcForkTestTableItem struct {
		name             string
		testForkScenario func(t *testing.T, ctx context.Context, bitcoindContainer testcontainers.Container, walletAddress string, tbcServer *Server)
	}

	testTable := []tbcForkTestTableItem{
		{
			name: "Split Tip, Single Block",
			testForkScenario: func(t *testing.T, ctx context.Context, bitcoindContainer testcontainers.Container, walletAddress string, tbcServer *Server) {
				_, err := runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"sendtoaddress",
						otherAddress.EncodeAddress(),
						"10",
					})
				if err != nil {
					t.Fatal(err)
				}

				blockHashesResponse, err := runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"generatetoaddress",
						"1",
						walletAddress,
					})
				if err != nil {
					t.Fatal(err)
				}

				go tbcServer.syncBlocks(ctx)
				time.Sleep(5 * time.Second)

				err = tbcServer.SyncIndexersToHeight(ctx, 201)
				if err != nil {
					t.Fatal(err)
				}

				balance, err := tbcServer.BalanceByAddress(ctx, otherAddress.EncodeAddress())
				if err != nil {
					t.Fatal(err)
				}

				if balance != 1000000000 {
					t.Fatalf("unexpected balance: %d", balance)
				}

				var blockHashes []string
				if err := json.Unmarshal([]byte(blockHashesResponse), &blockHashes); err != nil {
					t.Fatal(err)
				}

				// create fork
				_, err = runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"invalidateblock",
						blockHashes[0],
					})
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
						"sendtoaddress",
						otherAddress.EncodeAddress(),
						"120",
					})
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
						"1",
						walletAddress,
					})
				if err != nil {
					t.Fatal(err)
				}

				// the new tip has the "otherAddress" given 120 btc
				balance, err = tbcServer.BalanceByAddress(ctx, otherAddress.EncodeAddress())
				if err != nil {
					t.Fatal(err)
				}

				if balance != 12000000000 {
					t.Fatalf("unexpected balance: %d", balance)
				}
			},
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			// generate 200 to btcAddress
			bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 0, "")
			defer func() {
				if err := bitcoindContainer.Terminate(ctx); err != nil {
					panic(err)
				}
			}()

			_, err = runBitcoinCommand(
				ctx,
				t,
				bitcoindContainer,
				[]string{
					"bitcoin-cli",
					"-regtest=1",
					"createwallet",
					"mywallet",
				})
			if err != nil {
				t.Fatal(err)
			}

			walletAddress, err := runBitcoinCommand(
				ctx,
				t,
				bitcoindContainer,
				[]string{
					"bitcoin-cli",
					"-regtest=1",
					"getnewaddress",
				})
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
					"200",
					walletAddress,
				})
			if err != nil {
				t.Fatal(err)
			}

			tbcServer, _ := createTbcServer(ctx, t, mappedPeerPort)

			tt.testForkScenario(t, ctx, bitcoindContainer, walletAddress, tbcServer)
		})
	}
}

func TestForks(t *testing.T) {
	// I am likely not going to use this test setup
	t.Skip()
	skipIfNoDocker(t)

	type tbcForkTestTableItem struct {
		name                    string
		rawBlocks               []string
		expectedBalancesAtBlock func(t *testing.T, b string) map[string]int
	}

	tbcForkTestTable := []tbcForkTestTableItem{
		{
			name:      "TbcForkTest1",
			rawBlocks: tbcForkTestData1,
			expectedBalancesAtBlock: func(t *testing.T, b string) map[string]int {
				if b == "00000030908841eba84836569857842b79f67d7274ca0192aee3402045fc8a1e8c756a50da4ec0d4d1996b8aacd7e18f926c175d275291c66dc14147b40cd067db1cdf14e5bf3266ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402cc0000ffffffff0200f9029500000000160014bfccec420c4ea43a36f354793609e0806b3e087e0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000" {
					return map[string]int{
						"bcrt1q9jl9v3gwyhqts730l90u3nvjtkuxsu9mc7srje": 10000000000,
						"bcrt1q3v7mwuxch2yl9rxpzqy7tkhezdlexda54uccsm": 10000000000,
						"bcrt1qk3na83yp2aspc9q25ta05nxa02x9wwuueqt60t": 20000000000,
						"bcrt1q8wl0dfl70cr0sy7pyy32th8v29e9kjl5dx9sp8": 50000000000,
					}
				}

				if b == "0000003077075b7f64fb1eda2f1083121e007eec7c988991d1683809b622ee4cc8827c40329dd112aebc19dd7346be673a7a50013b70181d19b9a6fdaf140b1887513f1b20c43266ffff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402cd0000ffffffff02005b4096000000001600140961bff2951cc01349c8852e175dfdb0cd71b3fb0000000000000000266a24aa21a9ed53256c542013393ba2d188a3fc6f57e98c6c2bcca6e79a766ac5eb3f0908f2320120000000000000000000000000000000000000000000000000000000000000000000000000020000000001023a8ada23e38cd867c67a787425b82edf65e782f9bc679dc4f135b5a0e42a680d0000000000fdffffffd6a1696bc256f83061dbe1a5ae4b277a9ecdf1549c2da44de8c24fb49be81b890000000000fdffffff020097c59300000000160014d5b9011891dc81339f74d282b1fd3712c8341a4d00eb08bf010000001600141937673dc4079425339dc90eb8e095be45e6e5ca0247304402203f1a3a3a215a4765295457972ad384c8f1a852ac822cf08afdfe032e9ec4345802206ab7849d5ed9ee692aadd956ed01ae28e97c4b5e49b200acbba586cabc47ab8c0121022783f7c72ea4e5f919475a3f0d788df979b8be4a408b9ebcf679717d983a0ba9024730440220149f408554da5b0c149fe209830e5c3f371f538511a620ff43cb3962317f9fa9022003d5bbd51bc8bfdfa52a5c4bc309a4a7766d4c934758ce18949baa3c813f05ac0121022783f7c72ea4e5f919475a3f0d788df979b8be4a408b9ebcf679717d983a0ba9cc000000" {
					return map[string]int{
						"bcrt1qk3na83yp2aspc9q25ta05nxa02x9wwuueqt60t": 0,
						"bcrt1q8wl0dfl70cr0sy7pyy32th8v29e9kjl5dx9sp8": 0,
						"bcrt1qwf8a3z3h4wefgyhw050upcmkvva2ftjdrjvrch": 20000000000,
						"bcrt1qfcxjagapu5mnys3480xt8ckp0d3wjym7wfuydy": 1000000000,
						"bcrt1qdh9m3mskza9ez2v6z3nrcu7ntqw2pek50ak70p": 2500000000,
						"bcrt1qrymkw0wyq72z2vuaey8t3cy4hez7dew2nxyrar": 7500000000,
					}
				}

				return map[string]int{}
			},
		},
		{
			name:      "TbcForkTest2",
			rawBlocks: tbcForkTestData2,
			expectedBalancesAtBlock: func(t *testing.T, b string) map[string]int {
				if b == "0000002080ff3fe68e24ccf97ec7075df124ca246fba79df9402f5b8b3252836a80c705414b1dc9ff92b6831c020822f14962c95bc6c1966cd452aa3d2b3dd96a7e89956f6623a66ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016400ffffffff0200f2052a010000001976a914aa6ec3bfb728624a078dc82798dcc807ab894ea488ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000" {
					return map[string]int{
						"mw47rj9rG25J67G6W8bbjRayRQjWN5ZSEG": 500000000000,
						"mrVWrkuzrGJRaYvAUB8d9fwJtegWevFQok": 0,
					}
				}

				if b == "0000002034eba736fac2e9d0f4f03ee458414f9ec08d3557df9ca8f3432ef1abeb1a5c43d26809e044b3fa338ab5ba39bce43b8739d09de4d2d688ec5f2636e02953a350f6623a66ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016600ffffffff0200f2052a010000001976a9147863bc115f71f0289db3b994eed4bfed8bd9898788ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000" {
					return map[string]int{
						"mw47rj9rG25J67G6W8bbjRayRQjWN5ZSEG": 495000000000,
						"mrVWrkuzrGJRaYvAUB8d9fwJtegWevFQok": 10000000000,
					}
				}

				return map[string]int{}
			},
		},
	}

	for _, tt := range tbcForkTestTable {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 0, "")
			defer func() {
				if err := bitcoindContainer.Terminate(ctx); err != nil {
					panic(err)
				}
			}()

			tbcServer, _ := createTbcServer(ctx, t, mappedPeerPort)

			for i, b := range tt.rawBlocks {
				t.Logf("submitting block at index %d", i)
				submitBlock(ctx, t, b, bitcoindContainer)

				expectedBalances := tt.expectedBalancesAtBlock(t, b)
				if len(expectedBalances) == 0 {
					continue
				}

				// XXX we may need to revisit this; this allows tbc to sync
				// and index blocks and other resources
				time.Sleep(5 * time.Second)
				go tbcServer.syncBlocks(ctx)
				time.Sleep(5 * time.Second)

				err := tbcServer.SyncIndexersToHeight(ctx, uint64(i))
				if err != nil {
					t.Fatal(err)
				}

				for k, v := range expectedBalances {
					balance, err := tbcServer.BalanceByAddress(ctx, k)
					if err != nil {
						t.Fatal(err)
					}

					if uint64(v) != balance {
						t.Errorf("unexpected balance: %d != %d", v, balance)
					}
				}
			}
		})
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
		Cmd:          []string{"bitcoind", "-regtest=1", "-debug=1", "-rpcallowip=0.0.0.0/0", "-rpcbind=0.0.0.0:18443", "-txindex=1", "-noonion", "-listenonion=0", "-fallbackfee=0.01"},
		ExposedPorts: []string{"18443", "18444"},
		WaitingFor:   wait.ForLog("dnsseed thread exit").WithPollInterval(1 * time.Second),
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{
				&StdoutLogConsumer{
					Name: name,
				},
			},
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

	if len(buf.String()) == 0 {
		return "", nil
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
		ctx, t, bitcoindContainer,
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

func createTbcServer(ctx context.Context, t *testing.T, mappedPeerPort nat.Port) (*Server, string) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	home := fmt.Sprintf("%s/%s", wd, levelDbHome)

	if err := os.RemoveAll(home); err != nil {
		t.Fatal(err)
	}
	tcbListenAddress := fmt.Sprintf(":%d", nextPort(ctx, t))

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

func submitBlock(ctx context.Context, t *testing.T, rawBtcBlockHexEncoded string, bitcoindContainer testcontainers.Container) {
	t.Helper()

	if _, err := runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"submitblock",
			rawBtcBlockHexEncoded,
		}); err != nil {
		t.Fatal(err)
	}
}
