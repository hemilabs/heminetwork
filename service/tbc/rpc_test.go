// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/juju/loggo"
	"github.com/testcontainers/testcontainers-go"

	"github.com/hemilabs/heminetwork/v2/api"
	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin"
	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
	"github.com/hemilabs/heminetwork/v2/testutil"
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

	var response tbcapi.BlockHeadersByHeightRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRawRequest{
		Height: 55,
	}); err != nil {
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

	var response tbcapi.BlockHeadersByHeightResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRequest{
		Height: 55,
	}); err != nil {
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

	var response tbcapi.BlockHeadersByHeightResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlockHeadersByHeightRequest{
		Height: 550,
	}); err != nil {
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

			var response tbcapi.BalanceByAddressResponse
			for {
				select {
				case <-time.Tick(1 * time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				indexAll(ctx, t, tbcServer)

				if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BalanceByAddressRequest{
					Address: tti.address(),
				}); err != nil {
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
				} else {
					break
				}
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

			var response tbcapi.UTXOsByAddressRawResponse
			select {
			case <-time.Tick(1 * time.Second):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			indexAll(ctx, t, tbcServer)

			if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.UTXOsByAddressRawRequest{
				Address: tti.address(),
				Start:   uint(tti.start),
				Count:   uint(tti.limit),
			}); err != nil {
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
			expectedCount := 4 - tti.start
			if tti.limit < expectedCount {
				expectedCount = tti.limit
			}

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

			var response tbcapi.UTXOsByAddressResponse
			select {
			case <-time.Tick(1 * time.Second):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			indexAll(ctx, t, tbcServer)

			if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.UTXOsByAddressRequest{
				Address: tti.address(),
				Start:   uint(tti.start),
				Count:   uint(tti.limit),
			}); err != nil {
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
			expectedCount := 4 - tti.start
			if tti.limit < expectedCount {
				expectedCount = tti.limit
			}

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

	var response tbcapi.TxByIdRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	indexAll(ctx, t, tbcServer)

	txId := getRandomTxId(ctx, t, bitcoindContainer)

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRawRequest{
		TxID: *txId,
	}); err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIdRawResponse {
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
	if !txId.IsEqual(&txHash) {
		t.Fatalf("id mismatch: %s != %s", txHash, txId)
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

	var response tbcapi.TxByIdRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	indexAll(ctx, t, tbcServer)

	txId := getRandomTxId(ctx, t, bitcoindContainer)
	txId[0]++

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRawRequest{
		TxID: *txId,
	}); err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIdRawResponse {
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

	var response tbcapi.TxByIdRawResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	indexAll(ctx, t, tbcServer)

	txId := getRandomTxId(ctx, t, bitcoindContainer)
	txId[len(txId)-1] = 8

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRawRequest{
		TxID: *txId,
	}); err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIdRawResponse {
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

	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	var response tbcapi.TxByIdResponse

	indexAll(ctx, t, tbcServer)

	txId := getRandomTxId(ctx, t, bitcoindContainer)
	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRequest{
		TxID: *txId,
	}); err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIdResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &response); err != nil {
		t.Fatal(err)
	}

	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}

	tx, err := tbcServer.TxById(ctx, *txId)
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

	var response tbcapi.TxByIdResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	indexAll(ctx, t, tbcServer)

	txId := getRandomTxId(ctx, t, bitcoindContainer)
	txId[0]++

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRequest{
		TxID: *txId,
	}); err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIdResponse {
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

	var response tbcapi.TxByIdResponse
	select {
	case <-time.Tick(1 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	indexAll(ctx, t, tbcServer)

	txId := getRandomTxId(ctx, t, bitcoindContainer)
	txId[len(txId)-1] = 8

	if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.TxByIdRequest{
		TxID: *txId,
	}); err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != tbcapi.CmdTxByIdResponse {
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
			s, tbcUrl := createTbcServer(ctx, t, port)

			c, _, err := websocket.Dial(ctx, tbcUrl, nil)
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

			if err := tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BlocksByL2AbrevHashesRequest{
				L2KeystoneAbrevHashes: []chainhash.Hash{*tti.l2KeystoneAbrevHash},
			}); err != nil {
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
	var v protocol.Message
	err := wsjson.Read(ctx, c, &v)
	if err != nil {
		t.Fatal(err)
	}

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
	defer func() {
		cancel()
	}()

	var dupErr database.DuplicateError

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		HemiIndex:            true,
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PrometheusListenAddress: "",
		Seeds:                   []string{"127.0.0.1:" + testutil.FreePort()},
		NotificationBlocking:    true,
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
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		// If we insert genesis, then TBC has finished starting up
		if msg.Is(NotificationBlock(chainhash.Hash{})) {
			break
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
			name: "TxById",
			handler: func(ctx context.Context) (*protocol.Error, error) {
				req := tbcapi.TxByIdRequest{
					TxID: emptyHash,
				}
				res, err := s.handleTxByIdRequest(ctx, &req)
				val, ok := res.(*tbcapi.TxByIdResponse)
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
				req := tbcapi.TxByIdRawRequest{
					TxID: emptyHash,
				}
				res, err := s.handleTxByIdRawRequest(ctx, &req)
				val, ok := res.(*tbcapi.TxByIdRawResponse)
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
