package e2e

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	btcchaincfg "github.com/btcsuite/btcd/chaincfg"
	"github.com/davecgh/go-spew/spew"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"nhooyr.io/websocket"

	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/bitcoin"
	"github.com/hemilabs/heminetwork/ethereum"
	"github.com/hemilabs/heminetwork/hemi"
)

const (
	privateKey  = "72a2c41c84147325ce3c0f37697ef1e670c7169063dda89be9995c3c5219740f"
	hostGateway = "mylocalhost"
)

type StdoutLogConsumer struct {
	Name string // name of service
}

func (t *StdoutLogConsumer) Accept(l testcontainers.Log) {
	fmt.Printf("%s: %s", t.Name, string(l.Content))
}

type bssWs struct {
	wg   sync.WaitGroup
	addr string
	conn *protocol.WSConn
}

func TestFullNetwork(t *testing.T) {
	// only run this when this env is set, this is a very heavy test
	envValue := os.Getenv("HEMI_RUN_NETWORK_TEST")
	val, err := strconv.ParseBool(envValue)
	if envValue != "" && err != nil {
		t.Fatal(err)
	}

	if !val {
		t.Skip("skipping network test")
	}

	// this test runs for a long time, give it a large timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// create the key pair for the pop miner
	_, publicKey, btcAddress, err := bitcoin.KeysAndAddressFromHexString(
		privateKey,
		&btcchaincfg.TestNet3Params,
	)
	if err != nil {
		t.Fatal(err)
	}

	// create the bictoind container running in regtest mode
	bitcoindContainer := createBitcoind(ctx, t)

	_, err = bitcoindContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"-rpcuser=user",
			"-rpcpassword=password",
			"generatetoaddress",
			"5000", // need to generate a lot for greater chance to not spend coinbase
			btcAddress.EncodeAddress(),
		})
	if err != nil {
		t.Fatal(err)
	}

	bitcoindEndpoint, err := getEndpointWithRetries(ctx, bitcoindContainer, 5)
	if err != nil {
		t.Fatal(err)
	}

	bitcoindEndpoint = "http://user:password@" + bitcoindEndpoint

	// create the electrumx container and connect it to bitcoind
	electrumxContainer := createElectrumx(ctx, t, bitcoindEndpoint)
	electrumxEndpoint, err := getEndpointWithRetries(ctx, electrumxContainer, 5)
	if err != nil {
		t.Fatal(err)
	}

	// create the postgres container
	postgresContainer := createPostgres(ctx, t)

	postgresEndpoint, err := getEndpointWithRetries(ctx, postgresContainer, 5)
	if err != nil {
		t.Fatal(err)
	}

	postgresEndpoint = "postgres://postgres@" + postgresEndpoint + "/bfg?sslmode=disable"

	// create the bfg container, connect it to postgres and electrmux
	bfgContainer := createBfg(ctx, t, postgresEndpoint, electrumxEndpoint)

	privatePort, err := nat.NewPort("tcp", "8080")
	if err != nil {
		t.Fatal(err)
	}

	bfgPrivateEndpoint, err := getEndpointWithPortAndRetries(ctx, bfgContainer, 5, privatePort)
	if err != nil {
		t.Fatal(err)
	}

	publicPort, err := nat.NewPort("tcp", "8383")
	if err != nil {
		t.Fatal(err)
	}
	bfgPublicEndpoint, err := getEndpointWithPortAndRetries(ctx, bfgContainer, 5, publicPort)
	if err != nil {
		t.Fatal(err)
	}

	bfgPrivateEndpoint = fmt.Sprintf("ws://%s/v1/ws/private", bfgPrivateEndpoint)
	bfgPublicEndpoint = fmt.Sprintf("http://%s/v1/ws/public", bfgPublicEndpoint)

	// create the bss container and connect it to bfg
	bssContainer := createBss(ctx, t, bfgPrivateEndpoint)

	bssEndpoint, err := getEndpointWithRetries(ctx, bssContainer, 5)
	if err != nil {
		t.Fatal(err)
	}

	bssEndpoint = fmt.Sprintf("http://%s/v1/ws", bssEndpoint)

	// connect to bss, this is what we will perform tests against
	c, _, err := websocket.Dial(ctx, bssEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.Close(websocket.StatusNormalClosure, ""); err != nil {
			t.Logf("error closing websocket: %s", err)
		}
	}()
	bws := &bssWs{
		conn: protocol.NewWSConn(c),
	}

	createPopm(ctx, t, bfgPublicEndpoint)

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       fillOutBytes("parentephash", 32),
		PrevKeystoneEPHash: fillOutBytes("prevkeystoneephash", 32),
		StateRoot:          fillOutBytes("stateroot", 32),
		EPHash:             fillOutBytes("ephash", 32),
	}

	popPayoutReceived := make(chan struct{})

	go func() {
		for {
			// add Max's test cases here
			// read responses from bss as we perform actions
			cmd, _, response, err := bssapi.Read(ctx, bws.conn)
			if err != nil {
				return
			}

			t.Logf("received command %s", cmd)
			t.Logf("%v", spew.Sdump(response))

			if cmd == bssapi.CmdPopPayoutResponse {
				popPayoutResponse := response.(*bssapi.PopPayoutsResponse)
				if len(popPayoutResponse.PopPayouts) == 0 {
					continue
				}
				publicKeyB := publicKey.SerializeUncompressed()
				minerAddress := ethereum.PublicKeyToAddress(publicKeyB)
				t.Logf("equal addresses? %s ?= %s", minerAddress.String(), popPayoutResponse.PopPayouts[0].MinerAddress.String())
				if slices.Equal(minerAddress.Bytes(), popPayoutResponse.PopPayouts[0].MinerAddress.Bytes()) {
					select {
					case popPayoutReceived <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	go func() {
		for {
			l2Keystone.L2BlockNumber++
			l2Keystone.L1BlockNumber++

			l2KeystoneRequest := bssapi.L2KeystoneRequest{
				L2Keystone: l2Keystone,
			}

			err = bssapi.Write(ctx, bws.conn, "someid", l2KeystoneRequest)
			if err != nil {
				t.Logf("error: %s", err)
				return
			}

			// give time for the L2 Keystone to propogate to bitcoin tx mempool
			select {
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
				panic(ctx.Err())
			}

			// generate a new btc block, this should include the l2 keystone
			err = runBitcoinCommand(ctx,
				t,
				bitcoindContainer,
				[]string{
					"bitcoin-cli",
					"-regtest=1",
					"-rpcuser=user",
					"-rpcpassword=password",
					"generatetoaddress",
					"1",
					btcAddress.EncodeAddress(),
				},
			)
			if err != nil {
				t.Log(err)
				return
			}

			// give time for bfg to see the new block
			select {
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
				panic(ctx.Err())
			}

			// ensure the l2 keystone is in the chain
			ks := hemi.L2KeystoneAbbreviate(l2Keystone).Serialize()
			err = bssapi.Write(ctx, bws.conn, "someotherid", bssapi.PopPayoutsRequest{
				L2BlockForPayout: ks[:],
			})
			if err != nil {
				t.Logf("error: %s", err)
				return
			}
		}
	}()

	select {
	case <-popPayoutReceived:
		t.Logf("got the pop payout!")
	case <-ctx.Done():
		t.Fatal(ctx.Err().Error())
	}
}

func createBitcoind(ctx context.Context, t *testing.T) testcontainers.Container {
	req := testcontainers.ContainerRequest{
		Image:        "kylemanna/bitcoind",
		Cmd:          []string{"bitcoind", "-regtest=1", "-rpcuser=user", "-rpcpassword=password", "-rpcallowip=0.0.0.0/0", "-rpcbind=0.0.0.0:18443", "-txindex=1"},
		ExposedPorts: []string{"18443/tcp"},
		WaitingFor:   wait.ForLog("dnsseed thread exit").WithPollInterval(1 * time.Second),
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&StdoutLogConsumer{
				Name: "bitcoind",
			}},
		},
		Name: "bitcoind",
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

func createElectrumx(ctx context.Context, t *testing.T, bitcoindEndpoint string) testcontainers.Container {
	bitcoindEndpoint = replaceHost(bitcoindEndpoint)
	req := testcontainers.ContainerRequest{
		Image: "lukechilds/electrumx",
		Env: map[string]string{
			"DAEMON_URL": bitcoindEndpoint,
			"COIN":       "BitcoinSegwit",
			"NET":        "regtest",
		},
		ExposedPorts: []string{"50001/tcp"},
		WaitingFor:   wait.ForLog("INFO:Daemon:daemon #1").WithPollInterval(1 * time.Second),
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&StdoutLogConsumer{
				Name: "electrumx",
			}},
		},
		Name: "electrumx",
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.ExtraHosts = []string{
				fmt.Sprintf("%s:host-gateway", hostGateway),
			}
		},
	}

	electrumxContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	return electrumxContainer
}

func createPostgres(ctx context.Context, t *testing.T) testcontainers.Container {
	req := testcontainers.ContainerRequest{
		Env: map[string]string{
			"POSTGRES_DB":               "bfg",
			"POSTGRES_HOST_AUTH_METHOD": "trust",
		},
		ExposedPorts: []string{"5432/tcp"},
		WaitingFor:   wait.ForLog("database system is ready to accept connections").WithPollInterval(1 * time.Second),
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       "./..",
			Dockerfile:    "./e2e/postgres.Dockerfile",
			PrintBuildLog: true,
		},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&StdoutLogConsumer{
				Name: "postgres",
			}},
		},
		Name: "postgres",
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.ExtraHosts = []string{
				fmt.Sprintf("%s:host-gateway", hostGateway),
			}
		},
	}

	postgresContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	return postgresContainer
}

func createBfg(ctx context.Context, t *testing.T, pgUri string, electrumxAddr string) testcontainers.Container {
	pgUri = replaceHost(pgUri)
	electrumxAddr = replaceHost(electrumxAddr)
	req := testcontainers.ContainerRequest{
		Env: map[string]string{
			"BFG_POSTGRES_URI":     pgUri,
			"BFG_BTC_START_HEIGHT": "100",
			"BFG_EXBTC_ADDRESS":    electrumxAddr,
			"BFG_LOG_LEVEL":        "TRACE",
			"BFG_PUBLIC_ADDRESS":   ":8383",
			"BFG_PRIVATE_ADDRESS":  ":8080",
		},
		ExposedPorts: []string{"8080/tcp", "8383/tcp"},
		WaitingFor:   wait.ForExposedPort().WithPollInterval(1 * time.Second),
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       "./..",
			Dockerfile:    "./docker/bfgd/Dockerfile",
			PrintBuildLog: true,
		},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&StdoutLogConsumer{
				Name: "bfg",
			}},
		},
		Name: "bfg",
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.ExtraHosts = []string{
				fmt.Sprintf("%s:host-gateway", hostGateway),
			}
		},
	}

	bfgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	return bfgContainer
}

func createBss(ctx context.Context, t *testing.T, bfgUrl string) testcontainers.Container {
	bfgUrl = replaceHost(bfgUrl)
	req := testcontainers.ContainerRequest{
		Env: map[string]string{
			"BSS_BFG_URL":   bfgUrl,
			"BSS_LOG_LEVEL": "TRACE",
			"BSS_ADDRESS":   ":8081",
		},
		ExposedPorts: []string{"8081/tcp"},
		WaitingFor:   wait.ForExposedPort().WithPollInterval(1 * time.Second),
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       "./..",
			Dockerfile:    "./docker/bssd/Dockerfile",
			PrintBuildLog: true,
		},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&StdoutLogConsumer{
				Name: "bss",
			}},
		},
		Name: "bss",
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.ExtraHosts = []string{
				fmt.Sprintf("%s:host-gateway", hostGateway),
			}
		},
	}

	bssContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	return bssContainer
}

func createPopm(ctx context.Context, t *testing.T, bfgUrl string) testcontainers.Container {
	bfgUrl = replaceHost(bfgUrl)
	req := testcontainers.ContainerRequest{
		Env: map[string]string{
			"POPM_BTC_PRIVKEY": privateKey,
			"POPM_BFG_URL":     bfgUrl,
			"POPM_LOG_LEVEL":   "TRACE",
		},
		WaitingFor: wait.ForLog("Starting PoP miner with BTC address").WithPollInterval(1 * time.Second),
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       "./..",
			Dockerfile:    "./docker/popmd/Dockerfile",
			PrintBuildLog: true,
		},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&StdoutLogConsumer{
				Name: "popm",
			}},
		},
		Name: "popm",
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.ExtraHosts = []string{
				fmt.Sprintf("%s:host-gateway", hostGateway),
			}
		},
	}

	popmContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	return popmContainer
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

func getEndpointWithPortAndRetries(ctx context.Context, container testcontainers.Container, retries int, port nat.Port) (string, error) {
	backoff := 500 * time.Millisecond
	var lastError error
	for i := 0; i < retries; i++ {
		endpoint, err := container.PortEndpoint(ctx, port, "")
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

// fillOutBytes will take a string and return a slice of bytes
// with values from the string suffixed until a size with bytes '_'
func fillOutBytes(prefix string, size int) []byte {
	result := []byte(prefix)
	for len(result) < size {
		result = append(result, '_')
	}

	return result
}

func runBitcoinCommand(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container, cmd []string) error {
	exitCode, result, err := bitcoindContainer.Exec(ctx, cmd)
	if err != nil {
		return err
	}

	buf := new(strings.Builder)
	_, err = io.Copy(buf, result)
	if err != nil {
		return err
	}

	t.Logf(buf.String())
	if exitCode != 0 {
		return fmt.Errorf("error code received: %d", exitCode)
	}

	return nil
}

// replaceHost will replace the host that is returned from .Endpoint() with
// the hostname that resolves to the docker host (hostGateway)
func replaceHost(h string) string {
	return strings.Replace(h, "localhost", hostGateway, 1)
}
