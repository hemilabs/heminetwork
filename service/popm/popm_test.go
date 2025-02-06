// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
)

const (
	privateKey      = "72a2c41c84147325ce3c0f37697ef1e670c7169063dda89be9995c3c5219740f"
	levelDbHome     = ".testleveldb"
	EventConnected  = "event_connected"
	networkLocalnet = "localnet"
)

var defaultTestTimeout = 30 * time.Second

func TestBTCPrivateKeyFromHex(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
	}{
		{
			input: "0000000000000000000000000000000000000000000000000000000000000001",
			want: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
		},
		{
			input: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
			want: []byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
				0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
				0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
			},
		},
		{
			input: "0000000000000000000000000000000000000000000000000000000000000000",
			want:  nil,
		},
		{
			input: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
			want:  nil,
		},
		{
			input: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want:  nil,
		},
	}
	for i, test := range tests {
		got, err := bitcoin.PrivKeyFromHexString(test.input)
		switch {
		case test.want == nil && err == nil:
			t.Errorf("Test %d - succeeded, want error", i)
		case test.want != nil && err != nil:
			t.Errorf("Test %d - failed with error: %v", i, err)
		case test.want != nil && err == nil:
			if !bytes.Equal(got.Serialize(), test.want) {
				t.Errorf("Test %d - got private key %x, want %x", i, got.Serialize(), test.want)
			}
		}
	}
}

func TestNewMiner(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.BTCChainName = "testnet3"
	cfg.BTCPrivateKey = "ebaaedce6af48a03bbfd25e8cd0364140ebaaedce6af48a03bbfd25e8cd03641"

	m, err := NewMiner(cfg)
	if err != nil {
		t.Fatalf("Failed to create new miner: %v", err)
	}

	got, want := m.btcAddress.EncodeAddress(), "mnwAf6TWJK1MjbKkK9rq8MGvWBRUuo3PJk"
	if got != want {
		t.Errorf("Got BTC pubkey hash address %q, want %q", got, want)
	}
	got, want = m.btcAddress.String(), "mnwAf6TWJK1MjbKkK9rq8MGvWBRUuo3PJk"
	if got != want {
		t.Errorf("Got BTC pubkey hash address %q, want %q", got, want)
	}
}

func TestConnectToTBC(t *testing.T) {

	privateKey, err := dcrsecp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	/* publicKey := hex.EncodeToString(privateKey.PubKey().SerializeCompressed()) */

	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()

	// Connect tbc service
	cfg := &tbc.Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PrometheusListenAddress: "",
		Seeds:                   []string{"127.0.0.1:18444"},
		ListenAddress:           "localhost:8881",
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := tbc.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	time.Sleep(1 * time.Second)

	ctx2, cancel2 := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel2()

	miner, err := NewMiner(&Config{
		TBCWSURL:      fmt.Sprintf("ws://%s/%s", cfg.ListenAddress, tbcapi.RouteWebsocket),
		BTCChainName:  "testnet3",
		BTCPrivateKey: hex.EncodeToString(privateKey.Serialize()),
	})
	if err != nil {
		panic(err)
	}
	go func() {
		err = miner.Run(ctx2)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	res, err := miner.callTBC(ctx2, miner.requestTimeout, &tbcapi.PingRequest{
		Timestamp: 1000000,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, ok := res.(*tbcapi.PingResponse)
	if !ok {
		t.Fatalf("not a PingResponse: %T", res)
	}
	t.Logf("Received PingResponse")
}
