// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/phayes/freeport"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"nhooyr.io/websocket"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin"
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
