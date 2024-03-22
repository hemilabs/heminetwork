package tbc

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type StdoutLogConsumer struct {
	Name string // name of service
}

func (t *StdoutLogConsumer) Accept(l testcontainers.Log) {
	fmt.Printf("%s: %s", t.Name, string(l.Content))
}

func skipIfNoDocker(t *testing.T) {
	if os.Getenv("HEMI_DOCKER_TESTS") != "1" {
		t.Skip("not running docker test")
	}
}

func TestBitcoindConnection(t *testing.T) {
	skipIfNoDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bitcoindContainer := createBitcoind(ctx, t)
	bitcoindHost, err := bitcoindContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	endpoint, err := getEndpointWithRetries(ctx, bitcoindContainer, 5)
	if err != nil {
		t.Fatal(err)
	}

	// there is a better way to do this, like MappedPort, but I am in a rush
	port := strings.Split(endpoint, ":")[1]

	t.Logf("bitcoind host is: %s", bitcoindHost)
	t.Logf("bitcoind port is: %s", port)

	cfg := NewDefaultConfig()
	cfg.ForceSeedPort = port
	cfg.Network = networkLocalnet
	cfg.PeersWanted = 1
	tbc, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := tbc.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func createBitcoind(ctx context.Context, t *testing.T) testcontainers.Container {
	req := testcontainers.ContainerRequest{
		Image:        "kylemanna/bitcoind",
		Cmd:          []string{"bitcoind", "-rest", "-regtest=1", "-debug=1", "-rpcallowip=0.0.0.0/0", "-rpcbind=0.0.0.0:18443", "-txindex=1"},
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
