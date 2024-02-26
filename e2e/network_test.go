package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
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
	"github.com/hemilabs/heminetwork/hemi/pop"
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

	_, err = runBitcoinCommand(
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

	bws := bssWs{
		conn: protocol.NewWSConn(c),
	}

	// flush ping
	_, _, _, err = bssapi.Read(ctx, bws.conn)
	if err != nil {
		t.Fatal(err)
	}

	var popPayoutsResponse bssapi.PopPayoutsResponse
	for {
		if err := bssapi.Write(ctx, bws.conn, "someid", &bssapi.L2KeystoneRequest{
			L2Keystone: l2Keystone,
		}); err != nil {
			t.Fatal(err)
		}

		// flush the l2 keystone response
		_, _, _, err = bssapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		// give time for the L2 Keystone to propogate to bitcoin tx mempool
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}

		// before being published to btc, finality should be -9
		if err := bssapi.Write(ctx, bws.conn, "someid", &bssapi.BTCFinalityByKeystonesRequest{
			L2Keystones: []hemi.L2Keystone{l2Keystone},
		}); err != nil {
			t.Fatal(err)
		}

		// flush the l2 keystone response
		_, _, response, err := bssapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		btcFinalityByKeystonesResponse, ok := response.(*bssapi.BTCFinalityByKeystonesResponse)
		if !ok {
			t.Fatal("not a finality response")
		}

		if len(btcFinalityByKeystonesResponse.L2BTCFinalities) != 1 {
			t.Fatalf("expected only one finality, received %d", len(btcFinalityByKeystonesResponse.L2BTCFinalities))
		}

		if btcFinalityByKeystonesResponse.L2BTCFinalities[0].BTCFinality != -9 {
			t.Fatalf("expected finality to be -9, received %d", btcFinalityByKeystonesResponse.L2BTCFinalities[0].BTCFinality)
		}

		// generate a new btc block, this should include the l2 keystone
		_, err = runBitcoinCommand(ctx,
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
			t.Fatal(err)
		}

		// give time for bfg to see the new block
		select {
		case <-time.After(20 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}

		// flush finality notification and block notification
		for i := 0; i < 2; i++ {
			_, _, _, err := bssapi.Read(ctx, bws.conn)
			if err != nil {
				t.Fatal(err)
			}
		}

		ks := hemi.L2KeystoneAbbreviate(l2Keystone).Serialize()
		id := "poppayouts1"
		if err := bssapi.Write(ctx, bws.conn, id, &bssapi.PopPayoutsRequest{
			L2BlockForPayout: ks[:],
		}); err != nil {
			t.Fatal(err)
		}

		_, _, response, err = bssapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		popPayoutsResponseTmp, ok := response.(*bssapi.PopPayoutsResponse)
		if !ok {
			t.Fatal("not pop payout response")
		}

		if len(popPayoutsResponseTmp.PopPayouts) == 0 {
			t.Log("pop payout not found, retrying")
			continue
		}

		popPayoutsResponse = *popPayoutsResponseTmp
		break
	}

	publicKeyB := publicKey.SerializeUncompressed()
	minerAddress := ethereum.PublicKeyToAddress(publicKeyB)
	t.Logf("equal addresses? %s ?= %s", minerAddress.String(), popPayoutsResponse.PopPayouts[0].MinerAddress.String())
	// acceptance test case: PoP payouts are calculated for each keystone starting at 25, and payout address matches PoP miner ETH address
	if !slices.Equal(minerAddress.Bytes(), popPayoutsResponse.PopPayouts[0].MinerAddress.Bytes()) {
		t.Fatalf("unexpected address")
	}

	// ok, now that there is a pop payout, find it and perform tests
	t.Logf("getting bitcoin transactions")
	cliResponse, err := runBitcoinCommand(ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"-rpcuser=user",
			"-rpcpassword=password",
			"getchaintips",
		},
	)
	if err != nil {
		t.Log(err)
	}

	t.Logf("chain tips: %s", cliResponse)
	chainTips := []struct {
		Hash string `json:"hash"`
	}{}

	if err := json.Unmarshal([]byte(cliResponse), &chainTips); err != nil {
		t.Fatal(err)
	}

	// popTxCounts is used to check for duplicate publications after going down
	// the chain
	popTxCounts := map[string]int{}

	hash := chainTips[0].Hash
	for {
		t.Logf("getting block at : %s", hash)
		var block struct {
			Tx                []string `json:"tx"`
			PreviousBlockHash string   `json:"previousBlockHash"`
			Height            int      `json:"height"`
		}
		response, err := runBitcoinCommand(ctx,
			t,
			bitcoindContainer,
			[]string{
				"bitcoin-cli",
				"-regtest=1",
				"-rpcuser=user",
				"-rpcpassword=password",
				"getblock",
				hash,
			},
		)
		if err != nil {
			t.Log(err)
		}

		if err := json.Unmarshal([]byte(response), &block); err != nil {
			panic(err)
		}

		foundFee := false
		for _, tx := range block.Tx {
			t.Log(tx)
			response, err = runBitcoinCommand(ctx,
				t,
				bitcoindContainer,
				[]string{
					"bitcoin-cli",
					"-regtest=1",
					"-rpcuser=user",
					"-rpcpassword=password",
					"getrawtransaction",
					tx,
					"true",
				},
			)
			if err != nil {
				t.Log(err)
			}

			verboseResponse := struct {
				Vout []struct {
					Value float64 `json:"value"`
				} `json:"vout"`
			}{}

			if err := json.Unmarshal([]byte(response), &verboseResponse); err != nil {
				t.Fatal(err)
			}

			// we would have been rewarded 25 btc for coinbase, our fee
			// is that minute the values of the outputs
			vout := float64(0)
			for _, v := range verboseResponse.Vout {
				vout += v.Value
			}

			response, err = runBitcoinCommand(ctx,
				t,
				bitcoindContainer,
				[]string{
					"bitcoin-cli",
					"-regtest=1",
					"-rpcuser=user",
					"-rpcpassword=password",
					"getrawtransaction",
					tx,
				},
			)
			if err != nil {
				t.Log(err)
			}

			abbrev := hemi.L2KeystoneAbbreviate(l2Keystone)
			popTx := pop.TransactionL2{L2Keystone: abbrev}
			popTxOpReturn, err := popTx.EncodeToOpReturn()
			if err != nil {
				panic(err)
			}

			t.Logf("contains HEMI in OPRETURN? %s > %s", response, hex.EncodeToString(popTxOpReturn))

			// acceptance test case: PoP transactions get published to Bitcoin, and each contains an OP_RETURN starting with 'HEMI"
			if strings.Contains(response, hex.EncodeToString(popTxOpReturn)) {
				popTxCounts[hex.EncodeToString(popTxOpReturn)]++
				// acceptance test case: PoP transactions are using the correct fee (approx 1 sat/vB)

				// blocks half every 150 blocks in regtest mode, and we can't guarantee
				// what UTXO was picked (it's selected randomly at the time of writing this)
				// so we need to check any of the following
				possibleCoinbases := []float64{50, 25, 12.5, 6.25, 3.125, 1.5625}
				found := false
				expectedFee := float64(0.00000285)
				for _, possibleCoinbase := range possibleCoinbases {
					t.Logf("checking fee: %f - %f == %f?", possibleCoinbase, expectedFee, vout)
					if possibleCoinbase-expectedFee == vout {
						found = true
						break
					}
				}
				if found == false {
					t.Fatal("was not able to find expected fee")
				} else {
					t.Logf("found correct fee")
					foundFee = true
					break
				}
			}
			if foundFee {
				break
			}
		}

		if foundFee {
			break
		}
		hash = block.PreviousBlockHash
		// change this to a constant, this is the pre-keystone block height
		if block.Height <= 5000 {
			break
		}
	}

	// acceptance test case: PoP miner only creates one BTC transaction for each keystone
	for k, v := range popTxCounts {
		if v != 1 {
			t.Fatalf("unexpected number of publications %d for %s", v, k)
		}
	}

	// acceptance test case: Bitcoin Finality for blocks starts at -9 and progresses in step with new Bitcoin blocks
	// note we check for "unconfirmed" btc finality earlier at -9, so this starts at -8
	// check that, as we add btc blocks, finality goes up
	otherL2Keystone := l2Keystone
	for i := 0; i < 10; i++ {
		otherL2Keystone.L1BlockNumber++
		otherL2Keystone.L2BlockNumber++

		if err := bssapi.Write(ctx, bws.conn, "someid", &bssapi.BTCFinalityByKeystonesRequest{
			L2Keystones: []hemi.L2Keystone{l2Keystone},
		}); err != nil {
			t.Fatal(err)
		}

		_, _, response, err := bssapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		btcFinalityByKeystonesResponse, ok := response.(*bssapi.BTCFinalityByKeystonesResponse)
		if !ok {
			t.Fatal("not a finality response")
		}

		if len(btcFinalityByKeystonesResponse.L2BTCFinalities) != 1 {
			t.Fatalf("expected only one finality, received %d", len(btcFinalityByKeystonesResponse.L2BTCFinalities))
		}

		expectedFinality := -9 + i + 1
		if btcFinalityByKeystonesResponse.L2BTCFinalities[0].BTCFinality != int32(expectedFinality) {
			t.Fatalf("expected finality to be %d, received %d", expectedFinality, btcFinalityByKeystonesResponse.L2BTCFinalities[0].BTCFinality)
		}

		if err := bssapi.Write(ctx, bws.conn, "someid", &bssapi.BTCFinalityByRecentKeystonesRequest{
			NumRecentKeystones: 100,
		}); err != nil {
			t.Fatal(err)
		}

		_, _, response, err = bssapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		btcFinalityByRecentKeystonesResponse, ok := response.(*bssapi.BTCFinalityByRecentKeystonesResponse)
		if !ok {
			t.Fatal("not a recent keystone response")
		}

		if len(btcFinalityByRecentKeystonesResponse.L2BTCFinalities) != 1+i {
			t.Fatalf("missing keystones, expecting %d received %d", 1+i, len(btcFinalityByRecentKeystonesResponse.L2BTCFinalities))
		}

		// acceptance test case: Bitcoin Finality returns same result for last 10 blocks and querying for specific block in that list
		// check down the list of recent finalities, the should be in descending order
		// for example: -8, -7...
		// NOTE: these are only confirmed finalities
		for k, v := range btcFinalityByRecentKeystonesResponse.L2BTCFinalities {
			if v.BTCFinality != int32(-9+1+k) {
				t.Fatalf("expected finality at index %d to be %d, got %d", k, -9+k, v.BTCFinality)
			}
		}

		if err := bssapi.Write(ctx, bws.conn, "someid", &bssapi.L2KeystoneRequest{
			L2Keystone: otherL2Keystone,
		}); err != nil {
			t.Fatal(err)
		}

		// flush the l2 keystone response
		_, _, _, err = bssapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		// let the keystone make it into the tx mempool
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}

		_, err = runBitcoinCommand(ctx,
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
			t.Fatal(err)
		}
		select {
		case <-time.After(20 * time.Second):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}

		// flush finality notification and block notification
		for i := 0; i < 2; i++ {
			_, _, _, err := bssapi.Read(ctx, bws.conn)
			if err != nil {
				t.Fatal(err)
			}
		}

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
			"BFG_BTC_START_HEIGHT": "5000",
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
			"POPM_LOG_LEVEL":   "INFO",
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

	// first 8 bytes are header
	return buf.String()[8:], nil
}

// replaceHost will replace the host that is returned from .Endpoint() with
// the hostname that resolves to the docker host (hostGateway)
func replaceHost(h string) string {
	return strings.Replace(h, "localhost", hostGateway, 1)
}
