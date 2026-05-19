// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/davecgh/go-spew/spew"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/docker/go-connections/nat"
	"github.com/go-test/deep"
	"github.com/juju/loggo/v2"
	"github.com/testcontainers/testcontainers-go"

	"github.com/hemilabs/heminetwork/v2/api"
	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcadminapi"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin"
	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
)

func bytes2Tx(b []byte) (*wire.MsgTx, error) {
	var w wire.MsgTx
	if err := w.Deserialize(bytes.NewReader(b)); err != nil {
		return nil, err
	}

	return &w, nil
}

func header2Slice(wbh *wire.BlockHeader) ([]byte, error) {
	var b bytes.Buffer
	err := wbh.Serialize(&b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func header2Array(wbh *wire.BlockHeader) ([80]byte, error) {
	sb, err := header2Slice(wbh)
	if err != nil {
		return [80]byte{}, err
	}
	return [80]byte(sb), nil
}

func slice2Header(header []byte) (*wire.BlockHeader, error) {
	var bh wire.BlockHeader
	err := bh.Deserialize(bytes.NewReader(header[:]))
	if err != nil {
		return nil, fmt.Errorf("deserialize block header: %w", err)
	}
	return &bh, nil
}

func TestBlockHeadersByHeightRaw(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 100, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()
	_, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.BlockHeadersByHeightRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRawRequest{
		Height: 55,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdBlockHeadersByHeightRawResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
	}

	bh, err := slice2Header(response.BlockHeaders[0])
	if err != nil {
		t.Fatal(err)
	}

	t.Log(spew.Sdump(bh))

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

	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 100, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.BlockHeadersByHeightResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRequest{
		Height: 55,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdBlockHeadersByHeightResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
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

	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 100, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.BlockHeadersByHeightResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRequest{
		Height: 550,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdBlockHeadersByHeightResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
	}

	if response.Error.Message != protocol.NotFoundError("block headers", 550).Message {
		t.Fatalf("unexpected error message: %s", response.Error.Message)
	}
}

func TestBlockHeaderBestRaw(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 50, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.BlockHeaderBestRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeaderBestRawRequest{}); err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdBlockHeaderBestRawResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
	}

	bh, err := slice2Header(response.BlockHeader)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(spew.Sdump(bh))

	if response.Error != nil {
		t.Errorf("got unwanted error: %v", response.Error)
	}

	cliBlockHeader := bitcoindBestBlock(ctx, t, bitcoindContainer)
	expected := cliBlockHeaderToRaw(t, cliBlockHeader)
	if diff := deep.Equal(expected, []api.ByteSlice{response.BlockHeader}); len(diff) > 0 {
		t.Errorf("unexpected diff: %s", diff)
	}
}

func TestBtcBlockHeaderBest(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	bitcoindContainer, mappedPeerPort := createBitcoindWithInitialBlocks(ctx, t, 100, "")
	defer func() {
		if err := bitcoindContainer.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	_, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.BlockHeaderBestResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeaderBestRequest{}); err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdBlockHeaderBestResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
	}

	if response.Error != nil {
		t.Errorf("got unwanted error: %v", response.Error)
	}

	cliBlockHeader := bitcoindBestBlock(ctx, t, bitcoindContainer)
	expected := cliBlockHeaderToTBC(t, cliBlockHeader)
	if diff := deep.Equal(expected, []*tbcapi.BlockHeader{response.BlockHeader}); len(diff) > 0 {
		t.Errorf("unexpected diff: %s", diff)
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
			ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

			tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

			c, _, err := websocket.Dial(ctx, tbcURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{
				conn: protocol.NewWSConn(c),
			}

			var response tbcapi.BalanceByAddressResponse
			for {
				select {
				case <-time.Tick(1 * time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				indexAll(ctx, t, tbcServer)

				err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BalanceByAddressRequest{
					Address: tti.address(),
				})
				if err != nil {
					t.Fatal(err)
				}

				var v protocol.Message
				if err := wsjson.Read(ctx, c, &v); err != nil {
					t.Fatal(err)
				}

				if v.Header.Command != tbcapi.CmdBalanceByAddressResponse {
					t.Fatalf("received unexpected command: %s", v.Header.Command)
				}

				if err := json.Unmarshal(v.Payload, &response); err != nil {
					t.Fatal(err)
				}

				var pricePerBlock uint64 = 50 * 100000000
				var blocks uint64 = 4
				var expectedBalance uint64
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
			ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

			tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

			c, _, err := websocket.Dial(ctx, tbcURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{
				conn: protocol.NewWSConn(c),
			}

			var response tbcapi.UTXOsByAddressRawResponse
			select {
			case <-time.Tick(1 * time.Second):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			indexAll(ctx, t, tbcServer)

			err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.UTXOsByAddressRawRequest{
				Address: tti.address(),
				Start:   uint(tti.start),
				Count:   uint(tti.limit),
			})
			if err != nil {
				t.Fatal(err)
			}

			var v protocol.Message
			if err := wsjson.Read(ctx, c, &v); err != nil {
				t.Fatal(err)
			}

			if v.Header.Command != tbcapi.CmdUTXOsByAddressRawResponse {
				t.Fatalf("received unexpected command: %s", v.Header.Command)
			}

			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			// we generated 4 blocks to this address previously, therefore
			// there should be 4 utxos
			expectedCount := min(tti.limit, 4-tti.start)

			if !tti.doNotGenerate && len(response.UTXOs) != int(expectedCount) {
				t.Fatalf("should have %d utxos, received: %d", expectedCount, len(response.UTXOs))
			} else if tti.doNotGenerate && len(response.UTXOs) != 0 {
				t.Fatalf("did not generate any blocks for address, should not have utxos")
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
			ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

			tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

			c, _, err := websocket.Dial(ctx, tbcURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{
				conn: protocol.NewWSConn(c),
			}

			var response tbcapi.UTXOsByAddressResponse
			select {
			case <-time.Tick(1 * time.Second):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			indexAll(ctx, t, tbcServer)

			err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.UTXOsByAddressRequest{
				Address: tti.address(),
				Start:   uint(tti.start),
				Count:   uint(tti.limit),
			})
			if err != nil {
				t.Fatal(err)
			}

			var v protocol.Message
			if err := wsjson.Read(ctx, c, &v); err != nil {
				t.Fatal(err)
			}

			if v.Header.Command != tbcapi.CmdUTXOsByAddressResponse {
				t.Fatalf("received unexpected command: %s", v.Header.Command)
			}

			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			// we generated 4 blocks to this address previously, therefore
			// there should be 4 utxos
			expectedCount := min(tti.limit, 4-tti.start)

			if !tti.doNotGenerate && len(response.UTXOs) != int(expectedCount) {
				t.Fatalf("should have %d utxos, received: %d", expectedCount, len(response.UTXOs))
			} else if tti.doNotGenerate && len(response.UTXOs) != 0 {
				t.Fatalf("did not generate any blocks for address, should not have utxos")
			}
		})
	}
}

func TestTxByIdRaw(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

	tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.TxByIDRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	indexAll(ctx, t, tbcServer)

	txID := getRandomTxID(ctx, t, bitcoindContainer)

	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIDRawRequest{
		TxID: *txID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIDRawResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

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
	txHash := tx.TxHash()
	if !txID.IsEqual(&txHash) {
		t.Fatalf("id mismatch: %s != %s", txHash, txID)
	}
}

func TestTxByIdRawInvalid(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

	tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.TxByIDRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	indexAll(ctx, t, tbcServer)

	txID := getRandomTxID(ctx, t, bitcoindContainer)
	txID[0]++

	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIDRawRequest{
		TxID: *txID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIDRawResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

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
}

func TestTxByIdRawNotFound(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

	tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.TxByIDRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	indexAll(ctx, t, tbcServer)

	txID := getRandomTxID(ctx, t, bitcoindContainer)
	txID[len(txID)-1] = 8

	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIDRawRequest{
		TxID: *txID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIDRawResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
	}

	if response.Error == nil {
		t.Fatal("expecting error")
	}

	if response.Error != nil {
		if !strings.Contains(response.Error.Message, "not found: tx") {
			t.Fatalf("incorrect error found: %s", response.Error.Message)
		}
	}
}

func TestTxById(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

	tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	var response tbcapi.TxByIDResponse

	indexAll(ctx, t, tbcServer)

	txID := getRandomTxID(ctx, t, bitcoindContainer)
	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIDRequest{
		TxID: *txID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIDResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
	}

	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}

	tx, err := tbcServer.TxByID(ctx, *txID)
	if err != nil {
		t.Fatal(err)
	}

	w := wireTxToTBC(tx)

	if diff := deep.Equal(w, response.Tx); len(diff) > 0 {
		t.Fatal(diff)
	}
}

func TestTxByIdInvalid(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

	tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.TxByIDResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	indexAll(ctx, t, tbcServer)

	txID := getRandomTxID(ctx, t, bitcoindContainer)
	txID[0]++

	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIDRequest{
		TxID: *txID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIDResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

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
}

func TestRpcZK(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	home := t.TempDir()

	// Fill up a db with zk index keys
	const balance uint64 = 10
	cache := createFullZKDB(ctx, t, home, balance)

	// Parse out values from inserted keys
	var (
		out       tbcd.Outpoint
		sh        tbcd.ScriptHash
		spent     tbcd.SpentOutput
		spending  tbcd.SpendingOutpointKey
		spendable tbcd.SpendableOutput
	)
	// No need to check if variables were copied, if not
	// it will fail in the subtests
	for k := range cache {
		op := []byte(k)
		switch len(k) {
		case len(out):
			copy(out[:], op[:])
		case len(sh):
			copy(sh[:], op[:])
		case len(spent):
			copy(spent[:], op[:])
		case len(spending):
			copy(spending[:], op[:])
		case len(spendable):
			copy(spendable[:], op[:])
		default:
			t.Fatalf("unexpected key len = %d", len(k))
		}
	}

	// Translate to API structs
	apiSpent := tbcapi.ZKSpentOutput{
		ScriptHash:        sh[:],
		BlockHeight:       binary.BigEndian.Uint32(spent[32:]),
		BlockHash:         *testutil.Bytes2Hash(spent[32+4 : 32+4+32]),
		TxID:              *testutil.Bytes2Hash(spent[32+4+32 : 32+4+32+32]),
		PrevOutpointHash:  *testutil.Bytes2Hash(spent[32+4+32+32 : 32+4+32+32+32]),
		PrevOutpointIndex: binary.BigEndian.Uint32(spent[32+4+32+32+32:]),
		TxInIndex:         binary.BigEndian.Uint32(spent[32+4+32+32+32+4:]),
	}
	apiSpending := tbcapi.ZKSpendingOutpoint{
		TxID:        *testutil.Bytes2Hash(spending[0:32]),
		BlockHeight: binary.BigEndian.Uint32(spending[32:]),
		BlockHash:   *testutil.Bytes2Hash(spending[32+4 : 32+4+32]),
		VOutIndex:   binary.BigEndian.Uint32(spending[32+4+32:]),
		SpendingOutpoint: &tbcapi.ZKSpendingOutpointValue{
			TxID:  apiSpent.TxID,
			Index: apiSpent.BlockHeight,
		},
	}
	apiSpendable := tbcapi.ZKSpendableOutput{
		ScriptHash:  sh[:],
		BlockHeight: binary.BigEndian.Uint32(spendable[32:]),
		BlockHash:   *testutil.Bytes2Hash(spendable[32+4 : 32+4+32]),
		TxID:        *testutil.Bytes2Hash(spendable[32+4+32 : 32+4+32+32]),
		TxOutIndex:  binary.BigEndian.Uint32(spendable[32+4+32+32:]),
	}

	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		ZKIndex:              true,
		LevelDBHome:          home,
		ListenAddress:        "127.0.0.1:0",
		MaxCachedTxs:         1000,
		MaxCachedZK:          1000,
		Network:              networkLocalnet,
		Seeds:                []string{"192.0.2.1:8333"},
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// Wait for HTTP server to start
	var tbcAddr string
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
		if addr := s.HTTPAddress(); addr != nil {
			tbcAddr = addr.String()
			break
		}
	}

	tbcURL := fmt.Sprintf("http://%s%s", tbcAddr, tbcapi.RouteWebsocket)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	type testTableItem struct {
		name          string
		req           any
		respHeader    protocol.Command
		handler       func(ctx context.Context, v protocol.Message) *protocol.Error
		expectedError *protocol.Error
	}

	tests := []testTableItem{
		{
			name: "ValueAndScriptByOutpoint",
			req: tbcapi.ZKValueAndScriptByOutpointRequest{
				Outpoint: tbcapi.OutPoint{
					Hash:  *out.TxIDHash(),
					Index: out.TxIndex(),
				},
			},
			respHeader: tbcapi.CmdZKValueAndScriptByOutpointResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKValueAndScriptByOutpointResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Satoshis != balance {
					return protocol.Errorf("balance: got %v, wanted %v",
						r.Satoshis, balance)
				}
				if !bytes.Equal(out[1:33], r.PkScript) {
					return protocol.Errorf("pkscript: got %s, wanted %x",
						r.PkScript, out[1:33])
				}
				return r.Error
			},
		},
		{
			name:       "ValueAndScriptByOutpoint Not Found",
			req:        tbcapi.ZKValueAndScriptByOutpointRequest{},
			respHeader: tbcapi.CmdZKValueAndScriptByOutpointResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKValueAndScriptByOutpointResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: protocol.NotFoundError("outpoint", tbcapi.OutPoint{}),
		},
		{
			name: "BalanceByScriptHash",
			req: tbcapi.ZKBalanceByScriptHashRequest{
				ScriptHash: sh[:],
			},
			respHeader: tbcapi.CmdZKBalanceByScriptHashResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKBalanceByScriptHashResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Satoshis != balance {
					return protocol.Errorf("balance: got %v, wanted %v",
						r.Satoshis, balance)
				}
				return r.Error
			},
		},
		{
			name: "BalanceByScriptHash Not Found",
			req: tbcapi.ZKBalanceByScriptHashRequest{
				ScriptHash: testutil.SHA256(nil),
			},
			respHeader: tbcapi.CmdZKBalanceByScriptHashResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKBalanceByScriptHashResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: protocol.NotFoundError("scripthash",
				api.ByteSlice(testutil.SHA256(nil)),
			),
		},
		{
			name:       "BalanceByScriptHash Invalid",
			req:        tbcapi.ZKBalanceByScriptHashRequest{},
			respHeader: tbcapi.CmdZKBalanceByScriptHashResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKBalanceByScriptHashResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: protocol.RequestErrorf("invalid scripthash: invalid script hash length"),
		},
		{
			name: "SpentOutputs",
			req: tbcapi.ZKSpentOutputsRequest{
				ScriptHash: sh[:],
			},
			respHeader: tbcapi.CmdZKSpentOutputsResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKSpentOutputsResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if len(r.SpentOutputs) != 1 {
					return protocol.Errorf("expected 1 output, got %d",
						len(r.SpentOutputs))
				}
				if diff := deep.Equal(apiSpent, r.SpentOutputs[0]); len(diff) > 0 {
					return protocol.Errorf("unexpected output diff: %s", diff)
				}
				return r.Error
			},
		},
		{
			name: "SpentOutputs Empty",
			req: tbcapi.ZKSpentOutputsRequest{
				ScriptHash: testutil.SHA256(nil),
			},
			respHeader: tbcapi.CmdZKSpentOutputsResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKSpentOutputsResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if len(r.SpentOutputs) > 0 {
					return protocol.Errorf("expected 0 outputs, got %d",
						len(r.SpentOutputs))
				}
				return r.Error
			},
		},
		{
			name:       "SpentOutputs Invalid",
			req:        tbcapi.ZKSpentOutputsRequest{},
			respHeader: tbcapi.CmdZKSpentOutputsResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKSpentOutputsResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: protocol.RequestErrorf("invalid scripthash: invalid script hash length"),
		},
		{
			name: "SpendingOutpoints",
			req: tbcapi.ZKSpendingOutpointsRequest{
				TxID: chainhash.Hash(spending[:32]),
			},
			respHeader: tbcapi.CmdZKSpendingOutpointsResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKSpendingOutpointsResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if len(r.SpendingOutpoints) != 1 {
					return protocol.Errorf("expected 1 outpoint, got %d",
						len(r.SpendingOutpoints))
				}
				if diff := deep.Equal(apiSpending, r.SpendingOutpoints[0]); len(diff) > 0 {
					return protocol.Errorf("unexpected outpoint diff: %s", diff)
				}
				return r.Error
			},
		},
		{
			name: "SpendingOutpoints Not Found",
			req: tbcapi.ZKSpendingOutpointsRequest{
				TxID: chainhash.Hash{},
			},
			respHeader: tbcapi.CmdZKSpendingOutpointsResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKSpendingOutpointsResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if len(r.SpendingOutpoints) > 0 {
					return protocol.Errorf("expected 0 outpoints, got %d",
						len(r.SpendingOutpoints))
				}
				return r.Error
			},
		},
		{
			name: "SpendableOutputs",
			req: tbcapi.ZKSpendableOutputsRequest{
				ScriptHash: sh[:],
			},
			respHeader: tbcapi.CmdZKSpendableOutputsResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKSpendableOutputsResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if len(r.SpendableOutputs) != 1 {
					return protocol.Errorf("expected 1 output, got %d",
						len(r.SpendableOutputs))
				}
				if diff := deep.Equal(apiSpendable, r.SpendableOutputs[0]); len(diff) > 0 {
					return protocol.Errorf("unexpected outpoint diff: %s", diff)
				}
				return r.Error
			},
		},
		{
			name: "SpendableOutputs Empty",
			req: tbcapi.ZKSpendableOutputsRequest{
				ScriptHash: testutil.SHA256(nil),
			},
			respHeader: tbcapi.CmdZKSpendableOutputsResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKSpendableOutputsResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if len(r.SpendableOutputs) != 0 {
					return protocol.Errorf("expected 0 output, got %d",
						len(r.SpendableOutputs))
				}
				return r.Error
			},
		},
		{
			name:       "SpendableOutputs Invalid",
			req:        tbcapi.ZKSpendableOutputsRequest{},
			respHeader: tbcapi.CmdZKSpendableOutputsResponse,
			handler: func(_ context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.ZKSpendableOutputsResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: protocol.RequestErrorf("invalid scripthash: invalid script hash length"),
		},
	}

	for _, tti := range tests {
		t.Run(tti.name, func(t *testing.T) {
			err = tbcapi.Write(ctx, tws.conn, "someid", tti.req)
			if err != nil {
				t.Fatal(err)
			}

			var v protocol.Message
			if err := wsjson.Read(ctx, c, &v); err != nil {
				t.Fatal(err)
			}

			if v.Header.Command != tti.respHeader {
				t.Fatalf("received unexpected command: %s", v.Header.Command)
			}

			resp := tti.handler(ctx, v)
			if tti.expectedError != nil {
				if resp == nil || resp.Message != tti.expectedError.Message {
					t.Fatalf("unexpected error: got %v, wanted %v",
						resp, tti.expectedError)
				}
			} else if resp != nil {
				t.Fatalf("unexpected error: %v", resp.Message)
			}
		})
	}
}

func TestTxByIdNotFound(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
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

	tbcServer, tbcURL := createTbcServer(ctx, t, mappedPeerPort)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	var response tbcapi.TxByIDResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	indexAll(ctx, t, tbcServer)

	txID := getRandomTxID(ctx, t, bitcoindContainer)
	txID[len(txID)-1] = 8

	err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIDRequest{
		TxID: *txID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIDResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
	}

	if response.Error == nil {
		t.Fatal("expecting error")
	}

	if response.Error != nil {
		if !strings.Contains(response.Error.Message, "not found: tx") {
			t.Fatalf("incorrect error found: %s", response.Error.Message)
		}
	}
}

// XXX This form of testing L2 keystone by abrev hash no longer works
func TestL2BlockByAbrevHash(t *testing.T) {
	t.Skip()
	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	popTx := pop.TransactionL2{
		L2Keystone: hemi.L2KeystoneAbbreviate(l2Keystone),
	}

	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(spew.Sdump(popTxOpReturn))

	btcBlockHash := chainhash.Hash(testutil.FillBytes("blockhash", 32))

	invalidL2KeystoneAbrevHash := chainhash.Hash(testutil.FillBytes("123", 32))

	type testTableItem struct {
		name                    string
		l2KeystoneAbrevHash     *chainhash.Hash
		expectedError           *protocol.Error
		expectedL2KeystoneAbrev *hemi.L2KeystoneAbrev
		expectedBTCBlockHash    *chainhash.Hash
	}

	testTable := []testTableItem{
		{
			name:                "invalidL2KeystoneAbrevHash",
			l2KeystoneAbrevHash: &invalidL2KeystoneAbrevHash,
			expectedError:       protocol.RequestErrorf("could not find l2 keystone"),
		},
		{
			name:                    "validL2KeystoneAbrevHash",
			l2KeystoneAbrevHash:     hemi.L2KeystoneAbbreviate(l2Keystone).Hash(),
			expectedL2KeystoneAbrev: hemi.L2KeystoneAbbreviate(l2Keystone),
			expectedBTCBlockHash:    &btcBlockHash,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			port, err := nat.NewPort("tcp", "9999")
			if err != nil {
				t.Fatal(err)
			}
			s, tbcURL := createTbcServer(ctx, t, port)

			c, _, err := websocket.Dial(ctx, tbcURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{
				conn: protocol.NewWSConn(c),
			}

			var response tbcapi.BlocksByL2AbrevHashesResponse
			select {
			case <-time.Tick(1 * time.Second):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}

			// 1
			btx := createBtcTx(t, 199, &l2Keystone, []byte{1, 2, 3})

			aPoPTx, err := pop.ParseTransactionL2FromOpReturn(btx)
			if err != nil {
				t.Fatal(err)
			}

			abrvKss := aPoPTx.L2Keystone.Serialize()

			kssCache := make(map[chainhash.Hash]tbcd.Keystone)

			kssCache[*hemi.L2KeystoneAbbreviate(l2Keystone).Hash()] = tbcd.Keystone{
				BlockHash:           btcBlockHash,
				AbbreviatedKeystone: abrvKss,
			}

			if err := s.g.db.BlockKeystoneUpdate(ctx, 1, kssCache, btcBlockHash); err != nil {
				t.Fatal(err)
			}

			err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlocksByL2AbrevHashesRequest{
				L2KeystoneAbrevHashes: []chainhash.Hash{*tti.l2KeystoneAbrevHash},
			})
			if err != nil {
				t.Fatal(err)
			}

			var v protocol.Message
			if err := wsjson.Read(ctx, c, &v); err != nil {
				t.Fatal(err)
			}

			if v.Header.Command != tbcapi.CmdBlocksByL2AbrevHashesResponse {
				t.Fatalf("received unexpected command: %s", v.Header.Command)
			}

			if err := json.Unmarshal(v.Payload, &response); err != nil {
				t.Fatal(err)
			}

			if diff := deep.Equal(response.Error, tti.expectedError); len(diff) > 0 {
				t.Fatalf("unexpected error diff: %s", diff)
			}

			if response.L2KeystoneBlocks[0].L2KeystoneAbrev != nil {
				t.Logf("%s\n\n%s", spew.Sdump(response.L2KeystoneBlocks[0].L2KeystoneAbrev.Serialize()), spew.Sdump(tti.expectedL2KeystoneAbrev.Serialize()))
			}

			if diff := deep.Equal(response.L2KeystoneBlocks[0].L2KeystoneBlockHash, tti.expectedBTCBlockHash); len(diff) > 0 {
				t.Fatalf("unexpected retrieved block hash diff: %s", diff)
			}

			if diff := deep.Equal(response.L2KeystoneBlocks[0].L2KeystoneAbrev, tti.expectedL2KeystoneAbrev); len(diff) > 0 {
				t.Fatalf("unexpected retrieved keystone diff: %s", diff)
			}
		})
	}
}

func assertPing(ctx context.Context, t *testing.T, c *websocket.Conn, cmd protocol.Command) {
	v := callTbc(ctx, t, c, nil)

	if v.Header.Command != cmd {
		t.Fatalf("unexpected command: %s", v.Header.Command)
	}
}

func indexAll(ctx context.Context, t *testing.T, tbcServer *Server) {
	_, bh, err := tbcServer.BlockHeaderBest(ctx)
	if err != nil {
		t.Fatal(err)
	}

	hash := bh.BlockHash()

	if err := tbcServer.SyncIndexersToHash(ctx, hash); err != nil {
		t.Fatal(err)
	}
}

func createBtcTx(t *testing.T, btcHeight uint64, l2Keystone *hemi.L2Keystone, minerPrivateKeyBytes []byte) []byte {
	btx := &wire.MsgTx{
		Version:  2,
		LockTime: uint32(btcHeight),
	}

	popTx := pop.TransactionL2{
		L2Keystone: hemi.L2KeystoneAbbreviate(*l2Keystone),
	}

	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		t.Fatal(err)
	}

	privateKey := dcrsecp256k1.PrivKeyFromBytes(minerPrivateKeyBytes)
	publicKey := privateKey.PubKey()
	pubKeyBytes := publicKey.SerializeCompressed()
	btcAddress, err := btcutil.NewAddressPubKey(pubKeyBytes, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	payToScript, err := txscript.PayToAddrScript(btcAddress.AddressPubKeyHash())
	if err != nil {
		t.Fatal(err)
	}

	if len(payToScript) != 25 {
		t.Fatalf("incorrect length for pay to public key script (%d != 25)", len(payToScript))
	}

	outPoint := wire.OutPoint{Hash: chainhash.Hash(testutil.FillBytes("hash", 32)), Index: 0}
	btx.TxIn = []*wire.TxIn{wire.NewTxIn(&outPoint, payToScript, nil)}

	changeAmount := int64(100)
	btx.TxOut = []*wire.TxOut{wire.NewTxOut(changeAmount, payToScript)}

	btx.TxOut = append(btx.TxOut, wire.NewTxOut(0, popTxOpReturn))

	sig := dcrecdsa.Sign(privateKey, []byte{})
	sigBytes := append(sig.Serialize(), byte(txscript.SigHashAll))
	sigScript, err := txscript.NewScriptBuilder().AddData(sigBytes).AddData(pubKeyBytes).Script()
	if err != nil {
		t.Fatal(err)
	}
	btx.TxIn[0].SignatureScript = sigScript

	return btx.TxOut[1].PkScript
}

func TestNotFoundError(t *testing.T) {
	type testTableItem struct {
		name          string
		handler       func(ctx context.Context) (*protocol.Error, error)
		expectedError protocol.Error
	}

	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()

	var dupErr database.DuplicateError

	// Connect tbc service
	cfg := &Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		HemiIndex:               true,
		LevelDBHome:             t.TempDir(),
		ListenAddress:           "127.0.0.1:0",
		MaxCachedTxs:            1000,
		Network:                 networkLocalnet,
		PrometheusListenAddress: "",
		Seeds:                   []string{"192.0.2.1:8333"},
		NotificationBlocking:    true,
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, dupErr) {
			panic(err)
		}
	}()

	// Wait for tbc to start up
	for {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(msg)
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		// TBC sends a notification when the http service has started.
		if msg.Is(NotificationService("", "")) {
			if msg.ID == "tbc_http_server" && msg.Msg == "ready" {
				break
			}
		}
	}

	l.Unsubscribe()

	var emptyHash chainhash.Hash
	testTable := []testTableItem{
		{
			name: "BlockByHash",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.BlockByHashRequest{
					Hash: emptyHash,
				}
				res, err := s.handleBlockByHashRequest(ctx, &req)
				val, ok := res.(*tbcapi.BlockByHashResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("block", emptyHash),
		},
		{
			name: "BlockByHashRaw",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.BlockByHashRawRequest{
					Hash: emptyHash,
				}
				res, err := s.handleBlockByHashRawRequest(ctx, &req)
				val, ok := res.(*tbcapi.BlockByHashRawResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("block", emptyHash),
		},
		{
			name: "BlockHeadersByHeight",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.BlockHeadersByHeightRequest{
					Height: 1,
				}
				res, err := s.handleBlockHeadersByHeightRequest(ctx, &req)
				val, ok := res.(*tbcapi.BlockHeadersByHeightResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("block headers", 1),
		},
		{
			name: "BlockHeadersByHeightRaw",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.BlockHeadersByHeightRawRequest{
					Height: 1,
				}
				res, err := s.handleBlockHeadersByHeightRawRequest(ctx, &req)
				val, ok := res.(*tbcapi.BlockHeadersByHeightRawResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("block headers", 1),
		},
		{
			name: "TxByID",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.TxByIDRequest{
					TxID: emptyHash,
				}
				res, err := s.handleTxByIDRequest(ctx, &req)
				val, ok := res.(*tbcapi.TxByIDResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("tx", emptyHash),
		},
		{
			name: "TxByIdRaw",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.TxByIDRawRequest{
					TxID: emptyHash,
				}
				res, err := s.handleTxByIDRawRequest(ctx, &req)
				val, ok := res.(*tbcapi.TxByIDRawResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("tx", emptyHash),
		},
		{
			name: "BlockKeystoneByL2KeystoneAbrevHash",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.BlocksByL2AbrevHashesRequest{
					L2KeystoneAbrevHashes: []chainhash.Hash{emptyHash},
				}
				res, err := s.handleBlockKeystoneByL2KeystoneAbrevHashRequest(ctx, &req)
				val, ok := res.(*tbcapi.BlocksByL2AbrevHashesResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				// allow panic if index 0 not found
				return val.L2KeystoneBlocks[0].Error, err
			},
			expectedError: *protocol.NotFoundError("keystone", emptyHash),
		},
		{
			name: "KeystoneTxsByL2KeystoneAbrevHash",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.KeystoneTxsByL2KeystoneAbrevHashRequest{
					L2KeystoneAbrevHash: emptyHash,
				}
				res, err := s.handleKeystoneTxsByL2KeystoneAbrevHashRequest(ctx, &req)
				val, ok := res.(*tbcapi.KeystoneTxsByL2KeystoneAbrevHashResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("keystone", emptyHash),
		},
		{
			name: "BlockHashByTxId",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.BlockHashByTxIDRequest{
					TxID: emptyHash,
				}
				res, err := s.handleBlockHashByTxIdRequest(ctx, &req)
				val, ok := res.(*tbcapi.BlockHashByTxIDResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("tx", emptyHash),
		},
		{
			name: "BlockHeaderByHash",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.BlockHeaderByHashRequest{
					Hash: emptyHash,
				}
				res, err := s.handleBlockHeaderByHashRequest(ctx, &req)
				val, ok := res.(*tbcapi.BlockHeaderByHashResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("block header", emptyHash),
		},
		{
			name: "BlockHeaderByHashRaw",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.BlockHeaderByHashRawRequest{
					Hash: emptyHash,
				}
				res, err := s.handleBlockHeaderByHashRawRequest(ctx, &req)
				val, ok := res.(*tbcapi.BlockHeaderByHashRawResponse)
				if !ok {
					return nil, fmt.Errorf("unexpected type: %T", res)
				}
				return val.Error, err
			},
			expectedError: *protocol.NotFoundError("block header", emptyHash),
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			resp, err := tti.handler(ctx)
			if err != nil {
				t.Fatal(err)
			}

			if resp.Message != tti.expectedError.Message {
				t.Fatalf("unexpected error %v != %v",
					resp.Message, tti.expectedError.Message)
			}
		})
	}
}

func createLocalTBCServer(ctx context.Context, t *testing.T, jwtSecret string) (string, *Server, *btcNode) {
	t.Helper()

	n, err := newFakeNode(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := n.Stop()
		if err != nil {
			t.Logf("node stop: %v", err)
		}
	}()
	go func() {
		err := n.Run(ctx)
		if !testutil.ErrorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	cfg := &Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		LevelDBHome:             t.TempDir(),
		MaxCachedTxs:            1000,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		ListenAddress:           "127.0.0.1:0",
		Network:                 networkLocalnet,
		NotificationBlocking:    true,
		JWTSecret:               jwtSecret,
		Seeds:                   []string{n.Address()},
		// LogLevel:             "tbcd=TRACE:tbc=TRACE:level=DEBUG",
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// Wait for http service to start up
	var tbcURL string
	for {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(msg)
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		// TBC sends a notification when the http service has started.
		if !msg.Is(NotificationService("", "")) {
			continue
		}

		if msg.ID != "tbc_http_server" || msg.Msg != "ready" {
			continue
		}

		if addr := s.HTTPAddress(); addr != nil {
			tbcURL = addr.String()
			break
		}
	}

	route := tbcapi.RouteWebsocket
	if jwtSecret != "" {
		route = tbcadminapi.RouteAdminWs
	}
	tbcAddr := fmt.Sprintf("http://%s%s", tbcURL, route)

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	// g ->  b1 ->  b2 -> b3

	parent := chaincfg.RegressionNetParams.GenesisHash
	address := n.address
	b1, err := n.MineAndSend(ctx, "b1", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := n.MineAndSend(ctx, "b2", b1.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := n.MineAndSend(ctx, "b3", b2.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// Verify linear indexing. Current TxIndex is sitting at genesis

	// genesis -> b3 should work with negative direction (cdiff is less than target)
	direction, err := indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b3.Hash())
	if err != nil {
		t.Fatalf("expected success g -> b3, got %v", err)
	}
	if direction <= 0 {
		t.Fatalf("expected 1 going from genesis to b3, got %v", direction)
	}

	return tbcAddr, s, n
}

func callTbc(ctx context.Context, t *testing.T, c *websocket.Conn, msg any) protocol.Message {
	t.Helper()

	if msg != nil {
		tws := &tbcWs{
			conn: protocol.NewWSConn(c),
		}

		err := tbcapi.Write(ctx, tws.conn, "someid", msg)
		if err != nil {
			t.Fatal(err)
		}
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	return v
}

func compareResponse(t *testing.T, cmd protocol.Command, v protocol.Message, expected any) {
	t.Helper()

	respType, ok := tbcapi.APICommands()[cmd]
	if !ok {
		t.Fatalf("unknown command %s", cmd)
	}

	if v.Header.Command != cmd {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	target := reflect.New(respType).Interface()
	if err := json.Unmarshal(v.Payload, &target); err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(target, expected); len(diff) != 0 {
		t.Fatalf("got %v, wanted %v: diff %s", target, expected, diff)
	}
}

func getRandomUtxoLocal(ctx context.Context, s *Server, n *btcNode) (*tbcd.Utxo, error) {
	for addr := range n.keys {
		utxos, err := s.UtxosByAddress(ctx, false, addr, 0, 1)
		if err != nil {
			return nil, err
		}
		if len(utxos) != 0 {
			return &utxos[0], nil
		}
	}
	return nil, errors.New("no suitable utxo found")
}

func getRandomTxIDLocal(n *btcNode) (*chainhash.Hash, *chainhash.Hash, error) {
	for i := n.height; i > 0; i-- {
		blk := n.blocksAtHeight[i][0]
		for t := range blk.txs {
			txID, expectedHash, err := tbcd.TxIdBlockHashFromTxKey(t)
			if err != nil {
				continue
			}
			return txID, expectedHash, nil
		}
	}
	return nil, nil, errors.New("no suitable tx found")
}

func TestRPCRequestsLocal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	type testTableItem struct {
		name        string
		requestFunc func(*testing.T) (any, any)
		expectedCmd protocol.Command
	}

	tbcUrl, tbcServer, n := createLocalTBCServer(ctx, t, "")

	indexAll(ctx, t, tbcServer)

	// Get a random TX and associated block
	txID, expectedHash, err := getRandomTxIDLocal(n)
	if err != nil {
		t.Fatal(err)
	}

	// Get a random UTXO
	utxo, err := getRandomUtxoLocal(ctx, tbcServer, n)
	if err != nil {
		t.Fatal(err)
	}

	tests := []testTableItem{
		{
			name:        "BlockHashByTxID",
			expectedCmd: tbcapi.CmdBlockHashByTxIDResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.BlockHashByTxIDRequest{TxID: *txID}
				expectedResp := &tbcapi.BlockHashByTxIDResponse{BlockHash: expectedHash}
				return request, expectedResp
			},
		},
		{
			name:        "BlockHashByTxID Not Found",
			expectedCmd: tbcapi.CmdBlockHashByTxIDResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.BlockHashByTxIDRequest{TxID: chainhash.Hash{}}
				expectedResp := &tbcapi.BlockHashByTxIDResponse{
					Error: protocol.NotFoundError("tx", chainhash.Hash{}),
				}
				return request, expectedResp
			},
		},
		{
			name:        "BlockInTxIndex",
			expectedCmd: tbcapi.CmdBlockInTxIndexResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.BlockInTxIndexRequest{BlockHash: *expectedHash}
				expectedResp := &tbcapi.BlockInTxIndexResponse{Indexed: true}
				return request, expectedResp
			},
		},
		{
			name:        "BlockInTxIndex Negative",
			expectedCmd: tbcapi.CmdBlockInTxIndexResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.BlockInTxIndexRequest{BlockHash: chainhash.Hash{}}
				expectedResp := &tbcapi.BlockInTxIndexResponse{Indexed: false}
				return request, expectedResp
			},
		},
		{
			name:        "FullBlockAvailable",
			expectedCmd: tbcapi.CmdFullBlockAvailableResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.FullBlockAvailableRequest{Hash: *expectedHash}
				expectedResp := &tbcapi.FullBlockAvailableResponse{Available: true}
				return request, expectedResp
			},
		},
		{
			name:        "FullBlockAvailable Negative",
			expectedCmd: tbcapi.CmdFullBlockAvailableResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.FullBlockAvailableRequest{Hash: chainhash.Hash{}}
				expectedResp := &tbcapi.FullBlockAvailableResponse{Available: false}
				return request, expectedResp
			},
		},
		{
			name:        "BlockHeaderByHash",
			expectedCmd: tbcapi.CmdBlockHeaderByHashResponse,
			requestFunc: func(t *testing.T) (any, any) {
				bh, height, err := tbcServer.BlockHeaderByHash(ctx, *expectedHash)
				if err != nil {
					t.Fatal(err)
				}
				request := &tbcapi.BlockHeaderByHashRequest{Hash: *expectedHash}
				expectedResp := &tbcapi.BlockHeaderByHashResponse{
					Height:      height,
					BlockHeader: wireBlockHeaderToTBC(bh),
				}
				return request, expectedResp
			},
		},
		{
			name:        "BlockHeaderByHash Not Found",
			expectedCmd: tbcapi.CmdBlockHeaderByHashResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.BlockHeaderByHashRequest{Hash: chainhash.Hash{}}
				expectedResp := &tbcapi.BlockHeaderByHashResponse{
					Error: protocol.NotFoundError("block header", chainhash.Hash{}),
				}
				return request, expectedResp
			},
		},
		{
			name:        "BlockHeaderByHashRaw",
			expectedCmd: tbcapi.CmdBlockHeaderByHashRawResponse,
			requestFunc: func(t *testing.T) (any, any) {
				bh, height, err := tbcServer.BlockHeaderByHash(ctx, *expectedHash)
				if err != nil {
					t.Fatal(err)
				}
				request := &tbcapi.BlockHeaderByHashRawRequest{Hash: *expectedHash}
				expectedResp := &tbcapi.BlockHeaderByHashRawResponse{
					Height:      height,
					BlockHeader: new(h2b(bh))[:],
				}
				return request, expectedResp
			},
		},
		{
			name:        "BlockHeaderByHashRaw Not Found",
			expectedCmd: tbcapi.CmdBlockHeaderByHashRawResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.BlockHeaderByHashRawRequest{Hash: chainhash.Hash{}}
				expectedResp := &tbcapi.BlockHeaderByHashRawResponse{
					Error: protocol.NotFoundError("block header", chainhash.Hash{}),
				}
				return request, expectedResp
			},
		},
		{
			name:        "ScriptHashAvailableToSpend",
			expectedCmd: tbcapi.CmdScriptHashAvailableToSpendResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.ScriptHashAvailableToSpendRequest{
					TxID:  *utxo.ChainHash(),
					Index: utxo.OutputIndex(),
				}
				expectedResp := &tbcapi.ScriptHashAvailableToSpendResponse{Available: true}
				return request, expectedResp
			},
		},
		{
			name:        "ScriptHashAvailableToSpend Negative",
			expectedCmd: tbcapi.CmdScriptHashAvailableToSpendResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.ScriptHashAvailableToSpendRequest{
					TxID:  chainhash.Hash{},
					Index: 0,
				}
				expectedResp := &tbcapi.ScriptHashAvailableToSpendResponse{Available: false}
				return request, expectedResp
			},
		},
		{
			name:        "SyncStatus",
			expectedCmd: tbcapi.CmdSyncStatusResponse,
			requestFunc: func(t *testing.T) (any, any) {
				request := &tbcapi.SyncStatusRequest{}
				height, bh, err := tbcServer.BlockHeaderBest(ctx)
				if err != nil {
					t.Fatal(err)
				}
				bestHH := tbcapi.HashHeight{
					Height: height,
					Hash:   bh.BlockHash(),
				}
				expectedResp := &tbcapi.SyncStatusResponse{
					Synced:         true,
					AtLeastMissing: 0,
					BlockHeader:    bestHH,
					Tx:             bestHH,
					Utxo:           bestHH,
				}
				return request, expectedResp
			},
		},
	}

	for _, tti := range tests {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			c, _, err := websocket.Dial(ctx, tbcUrl, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			req, expected := tti.requestFunc(t)

			v := callTbc(ctx, t, c, req)
			compareResponse(t, tti.expectedCmd, v, expected)
		})
	}
}

func TestTxWatchNotification(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	var dupErr database.DuplicateError

	cfg := &Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		HemiIndex:               true,
		LevelDBHome:             t.TempDir(),
		MaxCachedTxs:            1000,
		MempoolEnabled:          true,
		Network:                 networkLocalnet,
		ListenAddress:           "127.0.0.1:0",
		PrometheusListenAddress: "",
		Seeds:                   []string{"192.0.2.1:8333"},
		NotificationBlocking:    true,
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to internal notifications to know when the server
	// is ready (genesis block inserted).
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, dupErr) {
			panic(err)
		}
	}()

	// Wait for genesis block notification.
	for {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Is(NotificationBlock(chainhash.Hash{})) {
			break
		}
	}
	l.Unsubscribe()

	// Wait for HTTP to be listening.
	var tbcAddr string
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
		if addr := s.HTTPAddress(); addr != nil {
			tbcAddr = addr.String()
			break
		}
	}

	tbcURL := fmt.Sprintf("http://%s%s", tbcAddr, tbcapi.RouteWebsocket)

	// Connect websocket client.
	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	// Create a script hash to watch.
	watchedScript := []byte{
		0x00, 0x14, // witness v0 keyhash
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14,
	}
	watchedSH := tbcd.NewScriptHashFromScript(watchedScript)

	// Send TxWatch request.
	err = tbcapi.Write(ctx, tws.conn, "watch-1", tbcapi.TxWatchRequest{
		ScriptHashes: []api.ByteSlice{watchedSH[:]},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read TxWatch response.
	var watchResp protocol.Message
	if err := wsjson.Read(ctx, c, &watchResp); err != nil {
		t.Fatal(err)
	}
	if watchResp.Header.Command != tbcapi.CmdTxWatchResponse {
		t.Fatalf("expected %s, got %s", tbcapi.CmdTxWatchResponse, watchResp.Header.Command)
	}

	// Inject a notification through the server's notifier to simulate
	// a mempool tx matching the watched script hash.
	fakeTxid := chainhash.Hash{0xaa, 0xbb, 0xcc}
	if err := s.notifier.Notify(ctx, NotificationTxMempool(fakeTxid, watchedSH)); err != nil {
		t.Fatal(err)
	}

	// Read the push notification from the websocket.
	var ntfy protocol.Message
	if err := wsjson.Read(ctx, c, &ntfy); err != nil {
		t.Fatal(err)
	}
	if ntfy.Header.Command != tbcapi.CmdTxNotification {
		t.Fatalf("expected %s, got %s", tbcapi.CmdTxNotification, ntfy.Header.Command)
	}

	var txn tbcapi.TxNotification
	if err := json.Unmarshal(ntfy.Payload, &txn); err != nil {
		t.Fatal(err)
	}
	if txn.Type != NtfnTypeTxMempool {
		t.Fatalf("expected type tx_mempool, got %s", txn.Type)
	}
	if txn.TxID != fakeTxid.String() {
		t.Fatalf("expected txid %s, got %s", fakeTxid, txn.TxID)
	}
}

func TestTxWatchFilterDrop(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	var dupErr database.DuplicateError

	cfg := &Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		HemiIndex:               true,
		LevelDBHome:             t.TempDir(),
		MaxCachedTxs:            1000,
		MempoolEnabled:          true,
		Network:                 networkLocalnet,
		ListenAddress:           "127.0.0.1:0",
		PrometheusListenAddress: "",
		Seeds:                   []string{"192.0.2.1:8333"},
		NotificationBlocking:    true,
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, dupErr) {
			panic(err)
		}
	}()

	for {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Is(NotificationBlock(chainhash.Hash{})) {
			break
		}
	}
	l.Unsubscribe()

	var tbcAddr string
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
		if addr := s.HTTPAddress(); addr != nil {
			tbcAddr = addr.String()
			break
		}
	}

	tbcURL := fmt.Sprintf("http://%s%s", tbcAddr, tbcapi.RouteWebsocket)

	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	// Watch for script hash A.
	shA := tbcd.NewScriptHashFromScript([]byte("address-A"))
	shB := tbcd.NewScriptHashFromScript([]byte("address-B"))

	err = tbcapi.Write(ctx, tws.conn, "watch-1", tbcapi.TxWatchRequest{
		ScriptHashes: []api.ByteSlice{shA[:]},
	})
	if err != nil {
		t.Fatal(err)
	}

	var watchResp protocol.Message
	if err := wsjson.Read(ctx, c, &watchResp); err != nil {
		t.Fatal(err)
	}

	// Send a notification for unwatched shB — should be filtered out.
	if err := s.notifier.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x01}, shB)); err != nil {
		t.Fatal(err)
	}

	// Send a notification for watched shA — should arrive.
	if err := s.notifier.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x02}, shA)); err != nil {
		t.Fatal(err)
	}

	// Read — we should get shA's notification, not shB's.
	var ntfy protocol.Message
	if err := wsjson.Read(ctx, c, &ntfy); err != nil {
		t.Fatal(err)
	}
	if ntfy.Header.Command != tbcapi.CmdTxNotification {
		t.Fatalf("expected %s, got %s", tbcapi.CmdTxNotification, ntfy.Header.Command)
	}

	var txn tbcapi.TxNotification
	if err := json.Unmarshal(ntfy.Payload, &txn); err != nil {
		t.Fatal(err)
	}
	if txn.TxID != (chainhash.Hash{0x02}).String() {
		t.Fatalf("expected txid for shA (0x02), got %s — filter did not drop shB", txn.TxID)
	}
}

// txWatchTestServer creates a tbcd server for tx watch tests and returns
// the server, a connected websocket, and a cleanup function.
func txWatchTestServer(t *testing.T) (*Server, *websocket.Conn, *tbcWs) {
	t.Helper()

	ctx := t.Context()
	var dupErr database.DuplicateError

	cfg := &Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		HemiIndex:               true,
		LevelDBHome:             t.TempDir(),
		MaxCachedTxs:            1000,
		MempoolEnabled:          true,
		Network:                 networkLocalnet,
		ListenAddress:           "127.0.0.1:0",
		PrometheusListenAddress: "",
		Seeds:                   []string{"192.0.2.1:8333"},
		NotificationBlocking:    true,
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, dupErr) {
			panic(err)
		}
	}()

	for {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Is(NotificationBlock(chainhash.Hash{})) {
			break
		}
	}
	l.Unsubscribe()

	var tbcAddr string
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
		if addr := s.HTTPAddress(); addr != nil {
			tbcAddr = addr.String()
			break
		}
	}

	tbcURL := fmt.Sprintf("http://%s%s", tbcAddr, tbcapi.RouteWebsocket)
	c, _, err := websocket.Dial(ctx, tbcURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{conn: protocol.NewWSConn(c)}
	return s, c, tws
}

func TestTxUnwatchThroughWebsocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	s, c, tws := txWatchTestServer(t)

	sh := tbcd.NewScriptHashFromScript([]byte("merchant-addr"))

	// Watch first.
	err := tbcapi.Write(ctx, tws.conn, "w1", tbcapi.TxWatchRequest{
		ScriptHashes: []api.ByteSlice{sh[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	var resp protocol.Message
	if err := wsjson.Read(ctx, c, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Command != tbcapi.CmdTxWatchResponse {
		t.Fatalf("expected %s, got %s", tbcapi.CmdTxWatchResponse, resp.Header.Command)
	}

	// Unwatch.
	err = tbcapi.Write(ctx, tws.conn, "u1", tbcapi.TxUnwatchRequest{
		ScriptHashes: []api.ByteSlice{sh[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Read(ctx, c, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Command != tbcapi.CmdTxUnwatchResponse {
		t.Fatalf("expected %s, got %s", tbcapi.CmdTxUnwatchResponse, resp.Header.Command)
	}
	var unwatchResult tbcapi.TxUnwatchResponse
	if err := json.Unmarshal(resp.Payload, &unwatchResult); err != nil {
		t.Fatal(err)
	}
	if unwatchResult.Error != nil {
		t.Fatalf("unwatch returned error: %v", unwatchResult.Error)
	}

	// Verify the unwatch took effect: notification for sh should be dropped.
	if err := s.notifier.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x01}, sh)); err != nil {
		t.Fatal(err)
	}
	// Send a block as sentinel — if we get the block next, the tx was dropped.
	if err := s.notifier.Notify(ctx, NotificationBlock(chainhash.Hash{0xff})); err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Read(ctx, c, &resp); err != nil {
		t.Fatal(err)
	}
	// The push goroutine serializes all notifications as TxNotification.
	// Check the payload Type field to verify we got the block sentinel,
	// not the tx notification that should have been filtered out.
	var ntfy tbcapi.TxNotification
	if err := json.Unmarshal(resp.Payload, &ntfy); err != nil {
		t.Fatal(err)
	}
	if ntfy.Type == NtfnTypeTxMempool {
		t.Fatal("received tx_mempool after unwatch — filter did not remove script hash")
	}
	if ntfy.Type != NtfnTypeBlockInsert {
		t.Fatalf("expected block_insert sentinel, got %s", ntfy.Type)
	}
}

func TestTxUnwatchBeforeWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	_, c, tws := txWatchTestServer(t)

	// Unwatch without ever calling Watch — should succeed with no error.
	sh := tbcd.NewScriptHashFromScript([]byte("never-watched"))
	err := tbcapi.Write(ctx, tws.conn, "u1", tbcapi.TxUnwatchRequest{
		ScriptHashes: []api.ByteSlice{sh[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	var resp protocol.Message
	if err := wsjson.Read(ctx, c, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Command != tbcapi.CmdTxUnwatchResponse {
		t.Fatalf("expected %s, got %s", tbcapi.CmdTxUnwatchResponse, resp.Header.Command)
	}
	var result tbcapi.TxUnwatchResponse
	if err := json.Unmarshal(resp.Payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Error != nil {
		t.Fatalf("unwatch before watch returned error: %v", result.Error)
	}
}

func TestTxWatchBadScriptHashLength(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	_, c, tws := txWatchTestServer(t)

	// Send a script hash that's too short (16 bytes instead of 32).
	err := tbcapi.Write(ctx, tws.conn, "w1", tbcapi.TxWatchRequest{
		ScriptHashes: []api.ByteSlice{make([]byte, 16)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var resp protocol.Message
	if err := wsjson.Read(ctx, c, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Command != tbcapi.CmdTxWatchResponse {
		t.Fatalf("expected %s, got %s", tbcapi.CmdTxWatchResponse, resp.Header.Command)
	}
	var result tbcapi.TxWatchResponse
	if err := json.Unmarshal(resp.Payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Error == nil {
		t.Fatal("expected error for bad script hash length, got nil")
	}
}

func TestTxUnwatchBadScriptHashLength(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	_, c, tws := txWatchTestServer(t)

	// Watch first so the listener exists.
	sh := tbcd.NewScriptHashFromScript([]byte("addr"))
	err := tbcapi.Write(ctx, tws.conn, "w1", tbcapi.TxWatchRequest{
		ScriptHashes: []api.ByteSlice{sh[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	var resp protocol.Message
	if err := wsjson.Read(ctx, c, &resp); err != nil {
		t.Fatal(err)
	}

	// Unwatch with bad length.
	err = tbcapi.Write(ctx, tws.conn, "u1", tbcapi.TxUnwatchRequest{
		ScriptHashes: []api.ByteSlice{make([]byte, 5)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Read(ctx, c, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Command != tbcapi.CmdTxUnwatchResponse {
		t.Fatalf("expected %s, got %s", tbcapi.CmdTxUnwatchResponse, resp.Header.Command)
	}
	var result tbcapi.TxUnwatchResponse
	if err := json.Unmarshal(resp.Payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Error == nil {
		t.Fatal("expected error for bad unwatch script hash length, got nil")
	}
}

func TestTxWatchExceedsLimitThroughWebsocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	_, c, tws := txWatchTestServer(t)

	// Fill the watch set to the limit in batches (websocket has a
	// 32KB frame limit, so we can't send all 1024 hashes at once).
	const batch = 100
	sent := 0
	for sent < maxWatchScripts {
		n := batch
		if sent+n > maxWatchScripts {
			n = maxWatchScripts - sent
		}
		hashes := make([]api.ByteSlice, n)
		for i := range hashes {
			sh := tbcd.NewScriptHashFromScript([]byte(fmt.Sprintf("addr-%d", sent+i)))
			hashes[i] = sh[:]
		}
		id := fmt.Sprintf("w%d", sent)
		err := tbcapi.Write(ctx, tws.conn, id, tbcapi.TxWatchRequest{
			ScriptHashes: hashes,
		})
		if err != nil {
			t.Fatal(err)
		}
		var resp protocol.Message
		if err := wsjson.Read(ctx, c, &resp); err != nil {
			t.Fatal(err)
		}
		var result tbcapi.TxWatchResponse
		if err := json.Unmarshal(resp.Payload, &result); err != nil {
			t.Fatal(err)
		}
		if result.Error != nil {
			t.Fatalf("batch at offset %d should succeed: %v", sent, result.Error)
		}
		sent += n
	}

	// One more should exceed the limit.
	extra := tbcd.NewScriptHashFromScript([]byte("one-too-many"))
	err := tbcapi.Write(ctx, tws.conn, "overflow", tbcapi.TxWatchRequest{
		ScriptHashes: []api.ByteSlice{extra[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	var resp protocol.Message
	if err := wsjson.Read(ctx, c, &resp); err != nil {
		t.Fatal(err)
	}
	var result tbcapi.TxWatchResponse
	if err := json.Unmarshal(resp.Payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Error == nil {
		t.Fatal("expected error for exceeding watch limit, got nil")
	}
}

func TestNotifyTxOutputsNoListeners(t *testing.T) {
	ctx := t.Context()
	s := &Server{
		notifier: NewNotifier(false),
	}
	// No listeners — should return immediately without panic.
	tx := &wire.MsgTx{
		TxOut: []*wire.TxOut{
			{PkScript: []byte{0x00, 0x14, 0x01}},
		},
	}
	s.notifyTxOutputs(ctx, tx, tx.TxHash(), NotificationTxMempool)
}

func TestNotifyTxOutputsContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	s := &Server{
		notifier: NewNotifier(true),
	}

	l, err := s.notifier.Subscribe(ctx, 1) // capacity 1 — will block on second
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	tx := &wire.MsgTx{
		TxOut: []*wire.TxOut{
			{PkScript: []byte{0x00, 0x14, 0x01}},
			{PkScript: []byte{0x00, 0x14, 0x02}},
		},
	}

	// Cancel context before notification — Notify should fail.
	cancel()
	s.notifyTxOutputs(ctx, tx, tx.TxHash(), NotificationTxMempool)
	// Should not panic; the error path logs and returns.
}
