// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum_e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dockercontainer "github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/hemilabs/heminetwork/v2/service/continuum"
)

const (
	trfListenPort = 18843
	trfDomain     = "tss.local"
	trfHomeDir    = "/tmp/trf"
)

type logConsumer struct{ name string }

func (l *logConsumer) Accept(log testcontainers.Log) {
	fmt.Printf("%s: %s", l.name, string(log.Content))
}

type nodeInfo struct {
	name      string
	hostname  string
	privKey   string
	secret    *continuum.Secret
	preparams json.RawMessage
}

type tssSetup struct {
	LocalSec   *continuum.Secret
	Identities []continuum.Identity // one per container node, in order
	ProxyAddrs []string             // "localhost:PORT" for each container node
}

func dial(ctx context.Context, sec *continuum.Secret, addr string) (*continuum.Transport, error) {
	conn, err := new(net.Dialer).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tr := new(continuum.Transport)
	if err := tr.KeyExchange(ctx, conn); err != nil {
		tr.Close()
		return nil, err
	}
	if _, _, err := tr.Handshake(ctx, sec); err != nil {
		tr.Close()
		return nil, err
	}
	return tr, nil
}

// readResponse reads from tr, transparently handling protocol overhead (pings,
// peer list requests, ceremony list requests) until a non-overhead message arrives.
func readResponse(ctx context.Context, sec *continuum.Secret, tr *continuum.Transport) (any, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		_, cmd, err := tr.Read()
		if err != nil {
			return nil, err
		}
		switch v := cmd.(type) {
		case *continuum.PingRequest:
			if err := tr.Write(sec.Identity, continuum.PingResponse{
				OriginTimestamp: v.OriginTimestamp,
				PeerTimestamp:   time.Now().Unix(),
			}); err != nil {
				return nil, err
			}
		case *continuum.CeremonyListRequest:
			if err := tr.Write(sec.Identity, continuum.CeremonyListResponse{}); err != nil {
				return nil, err
			}
		case *continuum.PeerListRequest:
			if err := tr.Write(sec.Identity, continuum.PeerListResponse{}); err != nil {
				return nil, err
			}
		case *continuum.PeerNotify, *continuum.PingResponse:
		default:
			return cmd, nil
		}
	}
}

func loadPreparams(t *testing.T) []json.RawMessage {
	t.Helper()
	data, err := os.ReadFile("../testdata/preparams.json")
	if err != nil {
		t.Fatalf("read preparams: %v", err)
	}
	var params []json.RawMessage
	if err := json.Unmarshal(data, &params); err != nil {
		t.Fatalf("parse preparams: %v", err)
	}
	return params
}

// preparamsDir writes a node's preparams into a temp directory
func preparamsDir(t *testing.T, n nodeInfo) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "trf")
	dir := filepath.Join(root, n.secret.String())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "preparams.json"), n.preparams, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func generateNodes(t *testing.T, n int) []nodeInfo {
	t.Helper()
	nodes := make([]nodeInfo, n)
	for i := range n {
		key, err := dcrsecpk256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		privKey := hex.EncodeToString(key.Serialize())
		secret, err := continuum.NewSecretFromString(privKey)
		if err != nil {
			t.Fatal(err)
		}
		nodeName := fmt.Sprintf("node-%d", i)
		nodes[i] = nodeInfo{
			name:     nodeName,
			hostname: fmt.Sprintf("%s.%s", nodeName, trfDomain),
			privKey:  privKey,
			secret:   secret,
		}
		t.Logf("%s: %s", nodeName, secret.Identity)
	}
	return nodes
}

func newDNSHandler(nodes []nodeInfo) *DNSHandler {
	handler := NewDNSHandler(trfDomain)
	// register local node under arbitrary loopback address. Since dockerized
	// nodes will only query for PTR records, we just need to associated the
	// secret to node-0's name.
	handler.addNode(nodes[0].name, net.IPv4(127, 0, 0, 1), trfListenPort, nodes[0].secret)
	for _, n := range nodes[1:] {
		handler.addDynamicNode(n.name, trfListenPort, n.secret)
	}
	return handler
}

func startDNSServer(ctx context.Context, t *testing.T, handler *DNSHandler) (port string) {
	t.Helper()
	srv := NewDNSServer(ctx, handler)
	t.Cleanup(func() { srv.Shutdown(ctx) })
	_, port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return port
}

func startDockerNetwork(ctx context.Context, t *testing.T) (*dockerclient.Client, *testcontainers.DockerNetwork) {
	t.Helper()
	cli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err = cli.Close(); err != nil {
			t.Logf("error closing docker cli: %v", err)
		}
	})
	network, err := tcnetwork.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err = network.Remove(ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Logf("error removing network: %v", err)
			}
		}
	})
	return cli, network
}

// startNodes spins up N containarized transfunctionerd nodes. These nodes
// can't be pre-registered to DNS, since we need to start them to know their
// address.
func startNodes(ctx context.Context, t *testing.T, cli *dockerclient.Client, networkName, dnsPort string, nodes []nodeInfo) []string {
	t.Helper()
	debug := "1"
	var prevPeer string
	var nodeIPs []string
	for _, n := range nodes[1:] {
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				FromDockerfile: testcontainers.FromDockerfile{
					Tag:        "latest",
					Repo:       "hemilabs/transfunctionerd",
					Dockerfile: "./docker/transfunctionerd/Dockerfile",
					Context:    "./../../..",
					BuildArgs: map[string]*string{
						"GO_LDFLAGS":      new(string),
						"CONTINUUM_DEBUG": &debug,
					},
				},
				Name:         n.name,
				Networks:     []string{networkName},
				ExposedPorts: []string{strconv.Itoa(trfListenPort)},
				Env: map[string]string{
					"TRF_LISTEN_ADDRESS": fmt.Sprintf("0.0.0.0:%d", trfListenPort),
					"TRF_DNS":            "all",
					"TRF_DNS_SERVER":     "host.docker.internal:" + dnsPort,
					"TRF_PRIVATE_KEY":    n.privKey,
					"TRF_HOME":           trfHomeDir,
					"TRF_HOSTNAME":       n.hostname,
					"TRF_LOG_LEVEL":      "INFO",
					"TRF_CONNECT":        prevPeer,
					"TRF_PEERS_WANTED":   strconv.Itoa(len(nodes)),
				},
				Files: []testcontainers.ContainerFile{{
					HostFilePath:      preparamsDir(t, n),
					ContainerFilePath: trfHomeDir,
					FileMode:          0o777,
				}},
				HostConfigModifier: func(hc *dockercontainer.HostConfig) {
					hc.ExtraHosts = []string{"host.docker.internal:host-gateway"}
				},
				WaitingFor: wait.ForLog("Identity: ").WithPollInterval(time.Second),
				LogConsumerCfg: &testcontainers.LogConsumerConfig{
					Consumers: []testcontainers.LogConsumer{&logConsumer{name: n.name}},
				},
			},
			Started: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err = c.Terminate(ctx); err != nil {
				if !errors.Is(err, context.Canceled) {
					t.Logf("error terminating container %s: %v", n.name, err)
				}
			}
		})

		prevPeer = fmt.Sprintf("%s:%d", n.hostname, trfListenPort)
		info, err := cli.ContainerInspect(ctx, c.GetContainerID())
		if err != nil {
			t.Fatal(err)
		}
		ep, ok := info.NetworkSettings.Networks[networkName]
		if !ok {
			t.Fatalf("%s not on network %s", n.name, networkName)
		}
		nodeIPs = append(nodeIPs, ep.IPAddress)
	}
	return nodeIPs
}

// startProxy starts a single socat container with one forwarder per node on
// consecutive ports. The local transfunctionerd instance routes its traffic
// through it in order to maintain a consistent address that can be registered
// in the DNS server.
func startProxy(ctx context.Context, t *testing.T, cli *dockerclient.Client, networkName string, handler *DNSHandler, nodeIPs []string) []string {
	t.Helper()
	var socatCmds, exposedPorts []string
	for i, ip := range nodeIPs {
		port := trfListenPort + i
		cmd := fmt.Sprintf("socat TCP-LISTEN:%d,reuseaddr,fork TCP:%s:%d",
			port, ip, trfListenPort)
		socatCmds = append(socatCmds, cmd)
		exposedPorts = append(exposedPorts, strconv.Itoa(port))
	}
	proxy, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "alpine/socat",
			Entrypoint:   []string{"sh", "-c"},
			Cmd:          []string{strings.Join(socatCmds, " & ") + " & wait"},
			Networks:     []string{networkName},
			ExposedPorts: exposedPorts,
			WaitingFor:   wait.ForListeningPort(nat.Port(strconv.Itoa(trfListenPort) + "/tcp")).WithStartupTimeout(15 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err = proxy.Terminate(ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Logf("error terminating proxy: %v", err)
			}
		}
	})

	info, err := cli.ContainerInspect(ctx, proxy.GetContainerID())
	if err != nil {
		t.Fatal(err)
	}
	ep, ok := info.NetworkSettings.Networks[networkName]
	if !ok {
		t.Fatalf("proxy not on network %s", networkName)
	}
	handler.addPTR(net.ParseIP(ep.IPAddress), "node-0")

	addrs := make([]string, len(nodeIPs))
	for i := range nodeIPs {
		port, err := proxy.MappedPort(ctx, nat.Port(strconv.Itoa(trfListenPort+i)+"/tcp"))
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = "localhost:" + port.Port()
	}
	return addrs
}

// setupTSSNodes generates a docker network of nodeCount transfunctionerd nodes.
// The first node is local, and communicates with the network through a proxy
// (which allows it to maintain a stable known address that can be registered in
// the DNS server).
func setupTSSNodes(ctx context.Context, t *testing.T, nodeCount int) *tssSetup {
	t.Helper()

	preParams := loadPreparams(t)
	if nodeCount-1 > len(preParams) {
		t.Fatalf("need %d preparams entries, have %d", nodeCount-1, len(preParams))
	}

	nodes := generateNodes(t, nodeCount)
	for i := 1; i < len(nodes); i++ {
		nodes[i].preparams = preParams[i-1]
	}

	handler := newDNSHandler(nodes)
	dnsPort := startDNSServer(ctx, t, handler)

	cli, network := startDockerNetwork(ctx, t)
	handler.DockerCli = cli
	handler.DockerNetwork = network.Name

	nodeIPs := startNodes(ctx, t, cli, network.Name, dnsPort, nodes)
	proxyAddrs := startProxy(ctx, t, cli, network.Name, handler, nodeIPs)

	identities := make([]continuum.Identity, nodeCount-1)
	for i := range identities {
		identities[i] = nodes[i+1].secret.Identity
	}
	return &tssSetup{
		LocalSec:   nodes[0].secret,
		Identities: identities,
		ProxyAddrs: proxyAddrs,
	}
}

func TestE2EPeers(t *testing.T) {
	const nodeCount = 10

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	setup := setupTSSNodes(ctx, t, nodeCount)

	for i, addr := range setup.ProxyAddrs {
		tr, err := dial(ctx, setup.LocalSec, addr)
		if err != nil {
			t.Fatalf("node-%d: %v", i+1, err)
		}
		want := len(setup.ProxyAddrs)
		for {
			if err := tr.Write(setup.LocalSec.Identity, continuum.PeerListRequest{}); err != nil {
				t.Fatal(err)
			}
			resp, err := readResponse(ctx, setup.LocalSec, tr)
			if err != nil {
				t.Fatal(err)
			}
			peers := resp.(*continuum.PeerListResponse).Peers
			if len(peers) >= want {
				break
			}
			t.Logf("node-%d: %d/%d peers", i+1, len(peers), want)
		}
	}
}

func TestE2EKeygen(t *testing.T) {
	const nodeCount = 4

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	setup := setupTSSNodes(ctx, t, nodeCount)

	tr, err := dial(ctx, setup.LocalSec, setup.ProxyAddrs[0])
	if err != nil {
		t.Fatal(err)
	}

	req := continuum.KeygenRequest{
		CeremonyID:  continuum.NewCeremonyID(),
		Curve:       "secp256k1",
		Committee:   continuum.IdentitiesToPartyIDs(setup.Identities),
		Threshold:   1,
		Coordinator: setup.Identities[0],
	}
	for _, id := range setup.Identities {
		if err := tr.WriteTo(setup.LocalSec.Identity, id, 8, req); err != nil {
			t.Fatal(err)
		}
	}

	for {
		cmd, err := readResponse(ctx, setup.LocalSec, tr)
		if err != nil {
			t.Fatal(err)
		}
		if result, ok := cmd.(*continuum.CeremonyResult); ok {
			if !result.Success {
				t.Fatal("ceremony failed")
			}
			return
		}
	}
}
