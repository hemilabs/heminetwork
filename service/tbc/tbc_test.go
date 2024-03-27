package tbc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/docker/go-connections/nat"
	"github.com/go-test/deep"
	"github.com/phayes/freeport"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/hemilabs/heminetwork/api/protocol"
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

func TestBtcBlockMetadataByNum(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	bitcoindContainer := createBitcoind(ctx, t)
	bitcoindHost, err := bitcoindContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	peerPort, err := nat.NewPort("tcp", "18444")
	if err != nil {
		t.Fatal(err)
	}

	rpcPort, err := nat.NewPort("tcp", "18443")
	if err != nil {
		t.Fatal(err)
	}

	mappedPeerPort, err := bitcoindContainer.MappedPort(ctx, peerPort)
	if err != nil {
		t.Fatal(err)
	}

	mappedRpcPort, err := bitcoindContainer.MappedPort(ctx, rpcPort)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("bitcoind host is: %s", bitcoindHost)
	t.Logf("bitcoind peer port is: %s", mappedPeerPort.Port())
	t.Logf("bitcoind rpc port is: %s", mappedRpcPort.Port())

	_, _, btcAddress, err := bitcoin.KeysAndAddressFromHexString(
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
			"100",
			btcAddress.EncodeAddress(),
		})
	if err != nil {
		t.Fatal(err)
	}

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
	var response tbcapi.BtcBlockMetadataByNumResponse
	for {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		lastErr = nil
		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BtcBlockMetadataByNumRequest{
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

		if v.Header.Command == tbcapi.CmdBtcBlockMetadataByNumResponse {
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

	cliBtcBlock := blockAtHeight(ctx, t, bitcoindContainer, 55)
	expected := cliBlockToResponse(cliBtcBlock)
	if diff := deep.Equal(expected, response); len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}
}

func TestBtcBlockMetadataByNumDoesNotExist(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	bitcoindContainer := createBitcoind(ctx, t)
	bitcoindHost, err := bitcoindContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	peerPort, err := nat.NewPort("tcp", "18444")
	if err != nil {
		t.Fatal(err)
	}

	rpcPort, err := nat.NewPort("tcp", "18443")
	if err != nil {
		t.Fatal(err)
	}

	mappedPeerPort, err := bitcoindContainer.MappedPort(ctx, peerPort)
	if err != nil {
		t.Fatal(err)
	}

	mappedRpcPort, err := bitcoindContainer.MappedPort(ctx, rpcPort)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("bitcoind host is: %s", bitcoindHost)
	t.Logf("bitcoind peer port is: %s", mappedPeerPort.Port())
	t.Logf("bitcoind rpc port is: %s", mappedRpcPort.Port())

	_, _, btcAddress, err := bitcoin.KeysAndAddressFromHexString(
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
			"100",
			btcAddress.EncodeAddress(),
		})
	if err != nil {
		t.Fatal(err)
	}

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
	var response tbcapi.BtcBlockMetadataByNumResponse
	for {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		lastErr = nil
		err = tbcapi.Write(ctx, tws.conn, "someid", tbcapi.BtcBlockMetadataByNumRequest{
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

		if v.Header.Command == tbcapi.CmdBtcBlockMetadataByNumResponse {
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

	if response.Error.Message != "could not get block header at height 550" {
		t.Fatalf("unexpected error message: %s", response.Error.Message)
	}
}

func createBitcoind(ctx context.Context, t *testing.T) testcontainers.Container {
	name := fmt.Sprintf("bitcoind-%d", time.Now().Unix())
	req := testcontainers.ContainerRequest{
		Image:        "kylemanna/bitcoind",
		Cmd:          []string{"bitcoind", "-regtest=1", "-debug=1", "-rpcallowip=0.0.0.0/0", "-rpcbind=0.0.0.0:18443", "-txindex=1"},
		ExposedPorts: []string{"18443/tcp", "18444/tcp"},
		WaitingFor:   wait.ForLog("dnsseed thread exit").WithPollInterval(1 * time.Second),
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&StdoutLogConsumer{
				Name: name,
			}},
		},
		Name: name,
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

func getEndpointWithRetries(ctx context.Context, container testcontainers.Container, retries int) (string, error) {
	backoff := 500 * time.Millisecond
	var lastError error
	for i := 0; i < retries; i++ {
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
	port, err := freeport.GetFreePort()
	if err != nil && err != context.Canceled {
		panic(err)
	}

	return port
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
	cfg.ForceSeedPort = mappedPeerPort.Port()
	cfg.ListenAddress = tcbListenAddress
	tbcServer, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := tbcServer.Run(ctx)
		if err != nil && err != context.Canceled {
			panic(err)
		}
	}()

	// let tbc index
	select {
	case <-time.After(10 * time.Second):
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

func cliBlockToResponse(btcCliBlockHeader BtcCliBlockHeader) tbcapi.BtcBlockMetadataByNumResponse {
	return tbcapi.BtcBlockMetadataByNumResponse{
		Block: tbcapi.BtcBlockMetadata{
			Height: uint32(btcCliBlockHeader.Height),
			NumTx:  uint32(btcCliBlockHeader.NTx),
			Header: tbcapi.BtcHeader{
				Version:    uint32(btcCliBlockHeader.Version),
				PrevHash:   btcCliBlockHeader.PreviousBlockHash,
				MerkleRoot: btcCliBlockHeader.MerkleRoot,
				Timestamp:  btcCliBlockHeader.Time,
				Bits:       btcCliBlockHeader.Bits,
				Nonce:      uint32(btcCliBlockHeader.Nonce),
			},
		},
	}
}

func blockAtHeight(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container, height uint64) BtcCliBlockHeader {
	blockHash, err := runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"getblockhash",
			fmt.Sprintf("%d", height),
		})
	if err != nil {
		t.Fatal(err)
	}

	blockHeaderJson, err := runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"getblockheader",
			blockHash,
		})
	if err != nil {
		t.Fatal(err)
	}

	var btcCliBlockHeader BtcCliBlockHeader
	if err := json.Unmarshal([]byte(blockHeaderJson), &btcCliBlockHeader); err != nil {
		t.Fatal(err)
	}

	return btcCliBlockHeader
}
