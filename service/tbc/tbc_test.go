// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"encoding/hex"
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

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/hemi/pop"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/davecgh/go-spew/spew"
	"github.com/docker/go-connections/nat"
	"github.com/go-test/deep"
	"github.com/phayes/freeport"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin"
)

const (
	privateKey  = "72a2c41c84147325ce3c0f37697ef1e670c7169063dda89be9995c3c5219740f"
	levelDbHome = ".testleveldb"
)

var defaultUpstreamStateId = [32]byte{
	0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
	0x44, 0x45, 0x46, 0x41, 0x55, 0x4C, 0x54, 0x55, 0x50, 0x53, // DEFAULTUPS
	0x54, 0x52, 0x45, 0x41, 0x4D, 0x53, 0x54, 0x41, 0x54, 0x45, // TREAMSTATE
	0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
}

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

func TestBlockHeaderEncodeDecode(t *testing.T) {
	chainParams := &chaincfg.TestNet3Params
	gwbh := chainParams.GenesisBlock.Header
	sh, err := header2Slice(&gwbh)
	if err != nil {
		t.Error(err)
	}
	wbh, err := slice2Header(sh)
	if err != nil {
		t.Error(err)
	}
	if diff := deep.Equal(&gwbh, wbh); len(diff) > 0 {
		t.Errorf("unexpected diff: %s", diff)
	}

	ash, err := header2Array(&gwbh)
	if err != nil {
		t.Error(err)
	}
	awbh, err := slice2Header(ash[:])
	if err != nil {
		t.Errorf("bytes2Header failed: %v", err)
	}
	if diff := deep.Equal(&gwbh, awbh); len(diff) > 0 {
		t.Errorf("unexpected diff: %s", diff)
	}
}

func countKeystones(b *btcutil.Block) int {
	// Count ALL keystones
	keystonesFound := 0
	for _, tx := range b.Transactions() {
		if blockchain.IsCoinBase(tx) {
			// Skip coinbase inputs
			continue
		}

		for _, txOut := range tx.MsgTx().TxOut {
			_, err := pop.ParseTransactionL2FromOpReturn(txOut.PkScript)
			if err != nil {
				continue
			}
			keystonesFound++
		}
	}
	return keystonesFound
}

func TestDbUpgrade(t *testing.T) {
	home := t.TempDir()
	t.Logf("temp: %v", home)

	err := extract("testdata/testdatabase.tar.gz", home)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          true,
		HemiIndex:            true,
		LevelDBHome:          home,
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		MaxCachedKeystones:      1000, // XXX
		Network:                 "testnet3",
		PrometheusListenAddress: "",
		ListenAddress:           "",
		PeersWanted:             0,
		MempoolEnabled:          false,
		Seeds:                   []string{"127.0.0.1:18444"},
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

	// check if db upgrade finished before checking for bh
	for !s.Running() {
	}

	_, err = s.BlockHeadersByHeight(ctx, 9)
	if err != nil {
		t.Fatal(err)
	}

	// Pull version from DB
	version, err := s.db.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Fatalf("expected version 3, got %v", version)
	}

	// version 2 checks

	// Copied from level package because this test can't be run there.
	utxoIndexHashKey := []byte("utxoindexhash")
	txIndexHashKey := []byte("txindexhash")
	keystoneIndexHashKey := []byte("keystoneindexhash")
	// Make sure db no longer has index keys
	_, err = s.db.MetadataGet(ctx, utxoIndexHashKey)
	if err == nil {
		t.Fatal("expected failure retrieving utxo index hash")
	}
	_, err = s.db.MetadataGet(ctx, txIndexHashKey)
	if err == nil {
		t.Fatal("expected failure retrieving tx index hash")
	}
	_, err = s.db.MetadataGet(ctx, keystoneIndexHashKey)
	if err == nil {
		t.Fatal("expected failure retrieving keystone index hash")
	}

	// Make sure we get the expected indexkeys from db
	hash := s2h("0000000050ff3053ada24e6ad581fa0295297f20a2747d034997ffc899aa931e")
	utxobh, err := s.db.BlockHeaderByUtxoIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !utxobh.Hash.IsEqual(&hash) {
		t.Fatal("unexpected utxo hash")
	}

	txbh, err := s.db.BlockHeaderByTxIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !txbh.Hash.IsEqual(&hash) {
		t.Fatal("unexpected tx hash")
	}

	keystonebh, err := s.db.BlockHeaderByKeystoneIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !keystonebh.Hash.IsEqual(&hash) {
		t.Fatal("unexpected keystone hash")
	}

	// version 3 checks
}

func TestKeystonesInBlock(t *testing.T) {
	hb1, err := os.ReadFile("testdata/0000000000000006200009cf36af2bbcb1362b887b4e2625113b6b44327435b8.hex") // Testnet3 block 3802508
	if err != nil {
		t.Fatal(err)
	}
	hb2, err := os.ReadFile("testdata/00000000055a5c34a021ab3b1f3f6f0304b403775feb9e5a235dc7f724c5833f.hex") // Testnet3 block 3802509
	if err != nil {
		t.Fatal(err)
	}
	rb1, err := hex.DecodeString(string(hb1))
	if err != nil {
		t.Fatal(err)
	}
	rb2, err := hex.DecodeString(string(hb2))
	if err != nil {
		t.Fatal(err)
	}
	b1, err := btcutil.NewBlockFromBytes(rb1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := btcutil.NewBlockFromBytes(rb2)
	if err != nil {
		t.Fatal(err)
	}

	// Run through processKeystones
	kssCache1 := make(map[chainhash.Hash]tbcd.Keystone, 10000)
	err = processKeystones(b1.Hash(), b1.Transactions(), 1, kssCache1)
	if err != nil {
		t.Fatal(err)
	}
	err = processKeystones(b2.Hash(), b2.Transactions(), 1, kssCache1)
	if err != nil {
		t.Fatal(err)
	}
	keystonesFound1 := countKeystones(b1)
	keystonesFound2 := countKeystones(b2)

	t.Logf("keystones in block 3802508: %v", keystonesFound1)
	t.Logf("keystones in block 3802509: %v", keystonesFound2)
	t.Logf("keystones dup in blocks   : %v", keystonesFound1+keystonesFound2-len(kssCache1))
	t.Logf("keystones to db 1         : %v", len(kssCache1))

	// go run btctool.go block hash=0000000000000006200009cf36af2bbcb1362b887b4e2625113b6b44327435b8 wire=true | grep HEMI | wc -l
	// 3448
	// go run btctool.go block hash=00000000055a5c34a021ab3b1f3f6f0304b403775feb9e5a235dc7f724c5833f wire=true | grep HEMI | wc -l
	// 3521

	if keystonesFound1 != 3448 {
		t.Fatalf("found keystones %v, wanted %v", keystonesFound1, 3448)
	}
	if keystonesFound2 != 3521 {
		t.Fatalf("found keystones %v, wanted %v", keystonesFound1, 3521)
	}

	// Pretend unwind
	kssCache2 := make(map[chainhash.Hash]tbcd.Keystone, 10000)
	err = processKeystones(b2.Hash(), b2.Transactions(), -1, kssCache2)
	if err != nil {
		t.Fatal(err)
	}
	err = processKeystones(b1.Hash(), b1.Transactions(), -1, kssCache2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("keystones to db 2         : %v", len(kssCache2))
	if len(kssCache1)-len(kssCache2) != 0 {
		t.Fatalf("expected 0 cache, got %v", len(kssCache1)-len(kssCache2))
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

	height, bhb, err := tbcServer.BlockHeaderBest(ctx)
	if err != nil {
		t.Errorf("BlockHeaderBest() err = %v, want nil", err)
	}
	_ = bhb // XXX probably should decode and test
	if height != blocks {
		t.Errorf("BlockHeaderBest() height = %d, want %d", height, blocks)
	}
}

func TestForksWithGen(t *testing.T) {
	skipIfNoDocker(t)

	t.Skip("need unwind functionality to run these tests, they need to be audited after that as well")

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
				// block 1A, send 7 btc to otherAddress
				_, err := runBitcoinCommand(
					ctx, t, bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"-named",
						"sendtoaddress",
						fmt.Sprintf("address=%s", otherAddress.EncodeAddress()),
						"conf_target=1",
						"amount=7",
						"avoid_reuse=false",
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
						"-generate",
						"1",
					})
				if err != nil {
					t.Fatal(err)
				}

				// XXX: Rewrite test to use tbcServer.SyncIndexersToHash
				if true {
					panic("replace tbcServer.SyncIndexersToHeight with tbcServer.SyncIndexersToHash")
				}
				// err = tbcServer.SyncIndexersToHeight(ctx, 201)
				// if err != nil {
				//	t.Fatal(err)
				// }

				balance, err := tbcServer.BalanceByAddress(ctx, otherAddress.String())
				if err != nil {
					t.Fatal(err)
				}

				if balance != 700000000 {
					t.Fatalf("unexpected balance: %d", balance)
				}

				var blockHashes struct {
					Blocks []string `json:"blocks"`
				}
				if err := json.Unmarshal([]byte(blockHashesResponse), &blockHashes); err != nil {
					t.Fatal(err)
				}

				// create fork, invalidate block 1A, this returns the tx back
				// to the mempool
				invalidateBlock(ctx, t, bitcoindContainer, blockHashes.Blocks[0])

				_, err = runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"sendtoaddress",
						otherAddress.EncodeAddress(),
						"15",
						"avoid_reuse=false",
					})
				if err != nil {
					t.Fatal(err)
				}

				// create block 1B and 2B, the txs should be included
				// in 1B.  use 2B to move tbc forward
				_, err = runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"-generate",
						"2",
					})
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "Split Tip, Multiple Blocks",
			testForkScenario: func(t *testing.T, ctx context.Context, bitcoindContainer testcontainers.Container, walletAddress string, tbcServer *Server) {
				lastA := ""
				lastB := ""
				earliestA := ""
				earliestB := ""

				for i := 0; i < 3; i++ {

					// invalidate B and reconsider A to grow chain A
					if earliestB != "" {
						invalidateBlock(ctx, t, bitcoindContainer, earliestB)
					}

					if lastA != "" {
						reconsiderBlock(ctx, t, bitcoindContainer, lastA)
					}

					// block i*1A, send 7 btc to otherAddress
					_, err := runBitcoinCommand(
						ctx,
						t,
						bitcoindContainer,
						[]string{
							"bitcoin-cli",
							"-regtest=1",
							"-named",
							"sendtoaddress",
							fmt.Sprintf("address=%s", otherAddress.EncodeAddress()),
							"conf_target=1",
							"amount=3",
							"subtractfeefromamount=true",
							"avoid_reuse=false",
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
							"-generate",
							fmt.Sprintf("%d", i*2+1),
						})
					if err != nil {
						t.Fatal(err)
					}

					var blockHashes struct {
						Blocks []string `json:"blocks"`
					}
					if err := json.Unmarshal([]byte(blockHashesResponse), &blockHashes); err != nil {
						t.Fatal(err)
					}

					lastA = blockHashes.Blocks[0]
					if earliestA == "" {
						earliestA = lastA
					}

					// invalidate A and reconsider B to grow chain B
					if earliestA != "" {
						invalidateBlock(ctx, t, bitcoindContainer, earliestA)
					}

					if lastB != "" {
						reconsiderBlock(ctx, t, bitcoindContainer, lastB)
					}

					_, err = runBitcoinCommand(
						ctx,
						t,
						bitcoindContainer,
						[]string{
							"bitcoin-cli",
							"-regtest=1",
							"-named",
							"sendtoaddress",
							fmt.Sprintf("address=%s", otherAddress.EncodeAddress()),
							"conf_target=1",
							"amount=2",
							"subtractfeefromamount=true",
							"avoid_reuse=false",
						})
					if err != nil {
						t.Fatal(err)
					}

					blockHashesResponse, err = runBitcoinCommand(
						ctx,
						t,
						bitcoindContainer,
						[]string{
							"bitcoin-cli",
							"-regtest=1",
							"-generate",
							fmt.Sprintf("%d", i*2+2),
						})
					if err != nil {
						t.Fatal(err)
					}

					if err := json.Unmarshal([]byte(blockHashesResponse), &blockHashes); err != nil {
						t.Fatal(err)
					}

					lastB := blockHashes.Blocks[0]
					if earliestB == "" {
						earliestB = lastB
					}
				}
			},
		},

		{
			name: "Long reorg",
			testForkScenario: func(t *testing.T, ctx context.Context, bitcoindContainer testcontainers.Container, walletAddress string, tbcServer *Server) {
				_, err := runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"-named",
						"sendtoaddress",
						fmt.Sprintf("address=%s", otherAddress.EncodeAddress()),
						"conf_target=1",
						"amount=7",
						"avoid_reuse=false",
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
						"-generate",
						"1",
					})
				if err != nil {
					t.Fatal(err)
				}

				// XXX: Rewrite test to use tbcServer.SyncIndexersToHash
				if true {
					panic("replace tbcServer.SyncIndexersToHeight with tbcServer.SyncIndexersToHash")
				}
				// err = tbcServer.SyncIndexersToHeight(ctx, 201)
				// if err != nil {
				//	t.Fatal(err)
				// }

				balance, err := tbcServer.BalanceByAddress(ctx, otherAddress.String())
				if err != nil {
					t.Fatal(err)
				}

				if balance != 700000000 {
					t.Fatalf("unexpected balance: %d", balance)
				}

				blockHash, err := runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"getblockhash",
						"102",
					})
				if err != nil {
					t.Fatal(err)
				}

				// create fork, invalidate block at height 10, this means we
				// generate blocks starting at 10
				invalidateBlock(ctx, t, bitcoindContainer, blockHash)

				_, err = runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"sendtoaddress",
						otherAddress.EncodeAddress(),
						"15",
						"avoid_reuse=false",
					})
				if err != nil {
					t.Fatal(err)
				}

				// create long new chain
				_, err = runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"-generate",
						"300",
					})
				if err != nil {
					t.Fatal(err)
				}

				// XXX: Rewrite test to use tbcServer.SyncIndexersToHash
				panic("replace tbcServer.SyncIndexersToHeight with tbcServer.SyncIndexersToHash")
				// err = tbcServer.SyncIndexersToHeight(ctx, 310)
				// if err != nil {
				//	t.Fatal(err)
				// }
			},
		},
		{
			name: "Ancient orphan",
			testForkScenario: func(t *testing.T, ctx context.Context, bitcoindContainer testcontainers.Container, walletAddress string, tbcServer *Server) {
				_, err := runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"-named",
						"sendtoaddress",
						fmt.Sprintf("address=%s", otherAddress.EncodeAddress()),
						"conf_target=1",
						"amount=7",
						"avoid_reuse=false",
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
						"-generate",
						"1",
					})
				if err != nil {
					t.Fatal(err)
				}

				// XXX: Rewrite test to use tbcServer.SyncIndexersToHash
				if true {
					panic("replace tbcServer.SyncIndexersToHeight with tbcServer.SyncIndexersToHash")
				}
				// err = tbcServer.SyncIndexersToHeight(ctx, 201)
				// if err != nil {
				//	t.Fatal(err)
				// }

				balance, err := tbcServer.BalanceByAddress(ctx, otherAddress.String())
				if err != nil {
					t.Fatal(err)
				}

				if balance != 700000000 {
					t.Fatalf("unexpected balance: %d", balance)
				}

				blockHash, err := runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"getblockhash",
						"102",
					})
				if err != nil {
					t.Fatal(err)
				}

				// create fork, invalidate block at height 10, this means we
				// generate blocks starting at 10
				invalidateBlock(ctx, t, bitcoindContainer, blockHash)

				_, err = runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"sendtoaddress",
						otherAddress.EncodeAddress(),
						"15",
						"avoid_reuse=false",
					})
				if err != nil {
					t.Fatal(err)
				}

				// create long new chain
				_, err = runBitcoinCommand(
					ctx,
					t,
					bitcoindContainer,
					[]string{
						"bitcoin-cli",
						"-regtest=1",
						"-generate",
						"10",
					})
				if err != nil {
					t.Fatal(err)
				}

				// XXX: Rewrite test to use tbcServer.SyncIndexersToHash
				panic("replace tbcServer.SyncIndexersToHeight with tbcServer.SyncIndexersToHash")
				// err = tbcServer.SyncIndexersToHeight(ctx, 310)
				// if err != nil {
				//	t.Fatal(err)
				// }
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

func invalidateBlock(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container, blockHash string) {
	_, err := runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"invalidateblock",
			blockHash,
		})
	if err != nil {
		t.Fatal(err)
	}
}

func reconsiderBlock(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container, blockHash string) {
	_, err := runBitcoinCommand(
		ctx,
		t,
		bitcoindContainer,
		[]string{
			"bitcoin-cli",
			"-regtest=1",
			"reconsiderblock",
			blockHash,
		})
	if err != nil {
		t.Fatal(err)
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
		Cmd:          []string{"bitcoind", "-regtest=1", "-debug=1", "-rpcallowip=0.0.0.0/0", "-rpcbind=0.0.0.0:18443", "-txindex=1", "-noonion", "-listenonion=0", "-fallbackfee=0.01", "-peerbloomfilters=1", "-debug"},
		ExposedPorts: []string{"18443", "18444"},
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
	t.Log(buf.String())

	if exitCode != 0 {
		return "", fmt.Errorf("error code received: %d", exitCode)
	}

	if len(buf.String()) == 0 {
		return "", nil
	}

	// first 8 bytes are header, there is also a newline character at the end of the response
	return buf.String()[8 : len(buf.String())-1], nil
}

func getRandomTxId(ctx context.Context, t *testing.T, bitcoindContainer testcontainers.Container) *chainhash.Hash {
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
		ctx,
		t,
		bitcoindContainer,
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

	hash, err := chainhash.NewHashFromStr(parsed.Tx[0])
	if err != nil {
		t.Fatalf("failed to parse tx hash: %v", err)
	}
	return hash
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
	cfg.Seeds = []string{
		fmt.Sprintf("127.0.0.1:%s", mappedPeerPort.Port()),
	}

	tbcServer, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

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
	t.Log(spew.Sdump(blockHeader))

	bytes, err := header2Slice(blockHeader)
	if err != nil {
		t.Fatal(fmt.Errorf("header to bytes: %w", err))
	}

	return []api.ByteSlice{bytes}
}

// cliBlockHeaderToTBC converts a bitcoin-cli block header to a slice containing
// the [tbcapi.BlockHeader] representation of the block header.
func cliBlockHeaderToTBC(t *testing.T, btcCliBlockHeader *BtcCliBlockHeader) []*tbcapi.BlockHeader {
	blockHeader := cliBlockHeaderToWire(t, btcCliBlockHeader)
	t.Log(spew.Sdump(blockHeader))
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

	mappedPeerPort, err := bitcoindContainer.MappedPort(ctx, "18444")
	if err != nil {
		t.Errorf("error getting mapped port %v", err)
	}

	return bitcoindContainer, mappedPeerPort
}

func createTbcServerExternalHeaderMode(ctx context.Context, t *testing.T) *Server {
	home := t.TempDir()

	cfg := NewDefaultConfig()
	cfg.LevelDBHome = home
	cfg.ExternalHeaderMode = true
	cfg.Network = networkLocalnet
	cfg.BlockCacheSize = ""
	cfg.BlockheaderCacheSize = ""
	cfg.MempoolEnabled = false

	tbcServer, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tbcServer.ExternalHeaderSetup(ctx, defaultUpstreamStateId[:])
	return tbcServer
}

func hexToRawHeader(hexStr string) (*[80]byte, error) {
	if len(hexStr) != 80*2 {
		return nil, fmt.Errorf("attempted to convert %s to a header but length (%d) is incorrect", hexStr, len(hexStr))
	}

	parsed, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	header := [80]byte{}
	for i := 0; i < 80; i++ {
		header[i] = parsed[i]
	}

	return &header, nil
}

func hexToHash(hexStr string) (*[32]byte, error) {
	if len(hexStr) != 32*2 {
		return nil, fmt.Errorf("attempted to convert %s to a hash but length (%d) is incorrect", hexStr, len(hexStr))
	}

	parsed, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	hash := [32]byte{}
	for i := 0; i < 32; i++ {
		hash[i] = parsed[i]
	}

	return &hash, nil
}

var (
	regtestGenesisHeader = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000"
	regtestGenesisHash   = "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"
)

var simpleChainHeaders = [...]string{
	"0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f7f8d3254fe4edbe9490e7435863b654877e238842528042a89f26b877deadd0268dd9566ffff7f2000000000", // 1
	"00000020954556f526b4b9691cb511ba38d6e710d89d5fce5c6d5d3020a9da22eaa0bc2499d5e1d516ccc57fa5794cf076d3a38ac9f81225286fd06b4ef8c9889fd04b21d3e39566ffff7f2000000000", // 2
	"00000020e7d63d7e1e612d42d5d3dfb02fb80441eaf9e485289236b9de612ad6f5667d4fe0b53fbfb60b9cef5ad5ff58e3619d53f29a662b3246767828b0cef5dac5c10013e49566ffff7f2003000000", // 3
	"000000203e8590212e33dd13cb8468df1d5783a414fcde86b19d1fe92c8e93063b07b26aba38cfcbdcdcf3deb865585bd17c33f15e95528e60b9779c638e7c67b39a7b4d37e49566ffff7f2002000000", // 4
	"00000020fbd310b22ff1fae2baf96189eb37a7ad93ab625390be1ec8ad6a7c037b59e374ceaf8aa1ed66319e1bd858d012a37807ed894074e49678c5b6d0582dd4b7f3fc4fe49566ffff7f2000000000", // 5
	"00000020da8f4d2b9cb85d920f4c1f322b59eded48a5c2009d046843f8fc40501f94c91fb5cd6d0b21e590871f46027c5739227156f72d156a383818508a6a946ec1d01366e49566ffff7f2000000000", // 6
	"0000002042b4da2ec1f9d880d9a43c42e78426dff2ecb6c33b2f5b3b2552d40cdcea6a6f5fb1f6ac25c4f5bff5ea097d17ab7d4567702141a5585bfced189ed9f917fb417de49566ffff7f2000000000", // 7
	"00000020e56ca4b20fb7f89d563be23bdd5d656b551686989062562deafa1786d332d019ff2578b22c2577a5679790f9515958990143de8a36aae784f2b15a85d8837b7a20e59566ffff7f2002000000", // 8
	"00000020b899f492824f01d57357da84fa13a93aeef1e0a3d7b31580f3cdc6ca12e09e5821de432f7e2c78c266248c252dd21a8592e1a121778fe125de7aaaf1bfa17ce79cea9566ffff7f2003000000", // 9
}

var simpleChainHashes = [...]string{
	"954556f526b4b9691cb511ba38d6e710d89d5fce5c6d5d3020a9da22eaa0bc24", // 1
	"e7d63d7e1e612d42d5d3dfb02fb80441eaf9e485289236b9de612ad6f5667d4f", // 2
	"3e8590212e33dd13cb8468df1d5783a414fcde86b19d1fe92c8e93063b07b26a", // 3
	"fbd310b22ff1fae2baf96189eb37a7ad93ab625390be1ec8ad6a7c037b59e374", // 4
	"da8f4d2b9cb85d920f4c1f322b59eded48a5c2009d046843f8fc40501f94c91f", // 5
	"42b4da2ec1f9d880d9a43c42e78426dff2ecb6c33b2f5b3b2552d40cdcea6a6f", // 6
	"e56ca4b20fb7f89d563be23bdd5d656b551686989062562deafa1786d332d019", // 7
	"b899f492824f01d57357da84fa13a93aeef1e0a3d7b31580f3cdc6ca12e09e58", // 8
	"2ecb4489c443da37ac78d4e02064fa2e3643ef7a8424ebc441956f202f52b702", // 9
}

func bytes2Header(header [80]byte) (*wire.BlockHeader, error) {
	var bh wire.BlockHeader

	err := bh.Deserialize(bytes.NewReader(header[:]))
	if err != nil {
		return nil, fmt.Errorf("deserialize block header: %w", err)
	}

	return &bh, nil
}

func getRegtestGenesisHeaderAndHash() (*[80]byte, *wire.BlockHeader, *chainhash.Hash, error) {
	blockraw, err := hexToRawHeader(regtestGenesisHeader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse hex header %s", regtestGenesisHeader)
	}

	blockheader, err := bytes2Header(*blockraw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse raw header %s", regtestGenesisHeader)
	}

	blockhashcalc := blockheader.BlockHash()
	blockhashexp, err := hexToHash(regtestGenesisHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse expected block header %s", regtestGenesisHeader)
	}

	if !bytes.Equal(blockhashcalc[:], blockhashexp[:]) {
		return nil, nil, nil, fmt.Errorf("hash of header was %x but expected %x", blockhashcalc[:], blockhashexp[:])
	}

	return blockraw, blockheader, &blockhashcalc, nil
}

// Helper function to get a single parsed header and hash from headers defined by provided str arrays
// Returns:
// *[80]byte -> Raw header
// *wire.BlockHeader -> Parsed header
// *chainhash.Hash -> Hash of block, which is calculated and verified against expected values
func getHeaderHashIndex(index int, headerStrs []string, hashStrs []string) (*[80]byte, *wire.BlockHeader, *chainhash.Hash, error) {
	blockraw, err := hexToRawHeader(headerStrs[index])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse hex header %s", headerStrs[index])
	}

	blockheader, err := bytes2Header(*blockraw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse raw header %s", headerStrs[index])
	}

	blockhashcalc := blockheader.BlockHash()
	blockhashexp, err := hexToHash(hashStrs[index])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse expected block header %s", hashStrs[index])
	}

	if !bytes.Equal(blockhashcalc[:], blockhashexp[:]) {
		return nil, nil, nil, fmt.Errorf("hash of header was %x but expected %x", blockhashcalc[:], blockhashexp[:])
	}

	return blockraw, blockheader, &blockhashcalc, nil
}

// Helper function to get the parsed headers and hashes from headers defined by provided str arrays
// start index to end index (inclusive).
// list. Returns:
// *[][80]byte -> Raw headers
// *wire.MsgHeaders -> Parsed headers
// *[]chainhash.Hash -> Hashes of blocks, which are calculated and verified against expected values
func getHeaderHashesRange(start int, end int, headerStrs []string, hashStrs []string) ([][80]byte, *wire.MsgHeaders, []chainhash.Hash, error) {
	if start > end {
		return nil, nil, nil, fmt.Errorf("start %d must be less than end %d", start, end)
	}

	rawHeaders := make([][80]byte, end-start+1)
	parsedHeaders := make([]*wire.BlockHeader, end-start+1)
	calculatedHashes := make([]chainhash.Hash, end-start+1)

	for i := start; i <= end; i++ {
		raw, parsed, hash, err := getHeaderHashIndex(i, headerStrs, hashStrs)
		if err != nil {
			return nil, nil, nil, err
		}

		rawHeaders[i-start] = *raw
		parsedHeaders[i-start] = parsed
		calculatedHashes[i-start] = *hash
	}

	msgHeaders := &wire.MsgHeaders{
		Headers: parsedHeaders,
	}

	return rawHeaders, msgHeaders, calculatedHashes, nil
}

// Starts at regtest genesis block, walks up the simpleChain defined above
// one block at a time checking each new block added is correctly considered canonical
// and then walks back down one block at a time until only genesis remains.
// This test also tests to make sure upstreamStateIds are stored correctly.
// XXX TODO: Refactor this to use convenience methods
func TestExternalHeaderModeSimpleSingleBlockChunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	tbc := createTbcServerExternalHeaderMode(ctx, t)

	genHeight, genesis, err := tbc.BlockHeaderBest(ctx)
	if err != nil {
		t.Error(err)
	}

	if genHeight != 0 {
		t.Error("Height after inserting genesis block is not 0")
	}

	bh := genesis.BlockHash()
	egh, _ := hexToHash(regtestGenesisHash)
	if !bytes.Equal(bh[:], egh[:]) {
		t.Errorf("Header hash was %x but expected %x", bh[:], egh[:])
	}

	// STEP 1: Walk chain forward 9 blocks after genesis
	for i := 0; i < len(simpleChainHeaders); i++ {
		blockraw, err := hexToRawHeader(simpleChainHeaders[i])
		if err != nil {
			t.Errorf("unable to parse hex header %s", simpleChainHeaders[i])
		}

		blockheader, err := bytes2Header(*blockraw)
		if err != nil {
			t.Errorf("unable to parse raw header %s", simpleChainHeaders[i])
		}

		blockhashcalc := blockheader.BlockHash()
		t.Logf("Parsed block to add at index %d, hash: %x", i+1, blockhashcalc[:])
		blockhashexp, err := hexToHash(simpleChainHashes[i])
		if err != nil {
			t.Errorf("unable to parse expected block header %s", simpleChainHashes[i])
		}

		if !bytes.Equal(blockhashcalc[:], blockhashexp[:]) {
			t.Errorf("hash of header was %x but expected %x", blockhashcalc[:], blockhashexp[:])
		}

		headers := make([][80]byte, 1)
		headers[0] = *blockraw
		parsedHeaders := make([]*wire.BlockHeader, 1)
		parsedHeaders[0] = blockheader

		msgHeaders := &wire.MsgHeaders{
			Headers: parsedHeaders,
		}

		stateId := [32]byte{byte(i)}
		it, canon, last, _, err := tbc.AddExternalHeaders(ctx, msgHeaders, stateId[:])
		if err != nil {
			t.Error(err)
		}

		stateIdRet, err := tbc.UpstreamStateId(ctx)
		if err != nil {
			t.Errorf("unable to get upstream state id, err: %v", err)
		}

		if !bytes.Equal(stateIdRet[:], stateId[:]) {
			t.Errorf("after adding external headers, state id should have been %x but got %x instead",
				stateId[:], stateIdRet[:])
		}

		if it != tbcd.ITChainExtend {
			t.Errorf("Adding header should have extended canonical chain")
		}

		canonHash := canon.BlockHash()
		lastHash := last.BlockHash()
		if !bytes.Equal(canonHash[:], blockhashcalc[:]) {
			t.Errorf("Canonical hash %x does not match expected hash %x", canonHash[:], blockhashcalc[:])
		}

		if !bytes.Equal(canonHash[:], lastHash[:]) {
			t.Errorf("Canonical hash %x does not match last hash %x which is expected in this scenario", canonHash[:], lastHash[:])
		}

		t.Logf("Added block %x, canonical tip is now %x\n", blockhashcalc[:], canonHash[:])
		bestHeight, best, err := tbc.BlockHeaderBest(ctx)
		if err != nil {
			t.Error(err)
		}

		if bestHeight != uint64(i+1) {
			t.Errorf("Height from TBC is %d but %d was expected", bestHeight, uint64(i+1))
		}

		bestHash := best.BlockHash()
		if !bytes.Equal(bestHash[:], blockhashcalc[:]) {
			t.Errorf("best hash %x does not match expected hash %x", bestHash[:], blockhashcalc[:])
		}

		t.Logf("TBC canonical tip %x is at height %d\n", bestHash[:], bestHeight)
	}

	// STEP 2: Walk chain backwards 9 blocks to genesis
	for i := len(simpleChainHeaders) - 1; i >= 0; i-- {
		blockraw, err := hexToRawHeader(simpleChainHeaders[i])
		if err != nil {
			t.Errorf("unable to parse hex header %s", simpleChainHeaders[i])
		}

		blockheader, err := bytes2Header(*blockraw)
		if err != nil {
			t.Errorf("unable to parse raw header %s", simpleChainHeaders[i])
		}

		blockhashcalc := blockheader.BlockHash()
		t.Logf("Parsed block to remove at index %d, hash: %x\n", i+1, blockhashcalc[:])
		blockhashexp, err := hexToHash(simpleChainHashes[i])
		if err != nil {
			t.Errorf("unable to parse expected block header %s", simpleChainHashes[i])
		}

		if !bytes.Equal(blockhashcalc[:], blockhashexp[:]) {
			t.Errorf("hash of header was %x but expected %x", blockhashcalc[:], blockhashexp[:])
		}

		headers := make([][80]byte, 1)
		headers[0] = *blockraw
		parsedHeaders := make([]*wire.BlockHeader, 1)
		parsedHeaders[0], err = bytes2Header(headers[0])
		if err != nil {
			t.Errorf("Unable to parse header %s", simpleChainHeaders[i])
		}

		msgHeaders := &wire.MsgHeaders{
			Headers: parsedHeaders,
		}

		prevHeaderStr := regtestGenesisHeader
		if i > 0 {
			prevHeaderStr = simpleChainHeaders[i-1]
		}

		prevHeader, err := hexToRawHeader(prevHeaderStr)
		if err != nil {
			t.Errorf("unable to parse hex header %s", simpleChainHeaders[i-1])
		}

		prevHeaderParsed, err := bytes2Header(*prevHeader)
		if err != nil {
			t.Errorf("unable to parse raw header %s", simpleChainHeaders[i])
		}

		prevHeaderHash := prevHeaderParsed.BlockHash()
		// Different from the state IDs used earlier to ensure we differentiate
		stateId := [32]byte{byte(i), 0xFF}
		rt, postRemovalTip, err := tbc.RemoveExternalHeaders(ctx, msgHeaders, prevHeaderParsed, stateId[:])
		if err != nil {
			t.Error(err)
		}

		stateIdRet, err := tbc.UpstreamStateId(ctx)
		if err != nil {
			t.Errorf("unable to get upstream state id, err: %v", err)
		}

		if !bytes.Equal(stateIdRet[:], stateId[:]) {
			t.Errorf("after removing external headers, state id should have been %x but got %x instead",
				stateId[:], stateIdRet[:])
		}

		prtHash := postRemovalTip.BlockHash()
		if !bytes.Equal(prtHash[:], prevHeaderHash[:]) {
			t.Errorf("after removing header %x expected tip to be %x but was %x", headers[0][:], prevHeaderHash[:], prtHash[:])
		}

		if rt != tbcd.RTChainDescend {
			t.Errorf("removing header should have descended canonical chain")
		}

		bestHeight, best, err := tbc.BlockHeaderBest(ctx)
		if err != nil {
			t.Error(err)
		}

		if bestHeight != uint64(i) {
			t.Errorf("Height from TBC is %d but %d was expected", bestHeight, uint64(i))
		}

		bestHash := best.BlockHash()
		if !bytes.Equal(bestHash[:], prevHeaderHash[:]) {
			t.Errorf("best hash %x does not match expected hash %x", bestHash[:], prevHeaderHash[:])
		}

		t.Logf("TBC canonical tip %x is at height %d\n", bestHash[:], bestHeight)
	}
}

// Starts at regtest genesis block, walks up the simpleChain defined above
// three blocks at a time checking all blocks are added correctly and the
// last block is considered canonical, and then walks back down three blocks
// at a time until only genesis remains.
// XXX TODO: Refactor this to use convenience methods
func TestExternalHeaderModeSimpleThreeBlockChunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	tbc := createTbcServerExternalHeaderMode(ctx, t)

	// No need to check genesis insertion works correctly as another test already covers that
	// STEP 1: Walk chain forward 3 blocks at a time
	for i := 0; i < len(simpleChainHeaders); i += 3 {
		headers := make([][80]byte, 3)
		parsedHeaders := make([]*wire.BlockHeader, 3)
		var lastHashToAdd *chainhash.Hash

		for j := 0; j < 3; j++ {
			blockraw, err := hexToRawHeader(simpleChainHeaders[i+j])
			if err != nil {
				t.Errorf("unable to parse hex header %s", simpleChainHeaders[i+j])
			}

			blockheader, err := bytes2Header(*blockraw)
			if err != nil {
				t.Errorf("unable to parse raw header %s", simpleChainHeaders[i+j])
			}

			blockhashcalc := blockheader.BlockHash()
			lastHashToAdd = &blockhashcalc
			blockhashexp, err := hexToHash(simpleChainHashes[i+j])
			if err != nil {
				t.Errorf("unable to parse expected block header %s", simpleChainHashes[i+j])
			}

			if !bytes.Equal(blockhashcalc[:], blockhashexp[:]) {
				t.Errorf("hash of header was %x but expected %x", blockhashcalc[:], blockhashexp[:])
			}

			headers[j] = *blockraw
			parsedHeader, err := bytes2Header(headers[j])
			if err != nil {
				t.Errorf("Unable to parse header %s", simpleChainHeaders[i+j])
			}

			parsedHeaders[j] = parsedHeader
		}

		msgHeaders := &wire.MsgHeaders{
			Headers: parsedHeaders,
		}

		it, canon, last, _, err := tbc.AddExternalHeaders(ctx, msgHeaders, defaultUpstreamStateId[:])
		if err != nil {
			t.Error(err)
		}

		if it != tbcd.ITChainExtend {
			t.Errorf("Adding headers should have extended canonical chain")
		}

		canonHash := canon.BlockHash()
		lastHash := last.BlockHash()

		if !bytes.Equal(canonHash[:], lastHash[:]) {
			t.Errorf("Canonical hash %x does not match expected hash %x", canonHash[:], lastHash[:])
		}

		if !bytes.Equal(canonHash[:], lastHashToAdd[:]) {
			t.Errorf("Canonical hash %x does not match last hash %x which is expected in this scenario", canonHash[:], lastHashToAdd[:])
		}

		t.Logf("Added block %x, canonical tip is now %x\n", lastHashToAdd[:], canonHash[:])
		bestHeight, best, err := tbc.BlockHeaderBest(ctx)
		if err != nil {
			t.Error(err)
		}

		if bestHeight != uint64(i+3) {
			t.Errorf("Height from TBC is %d but %d was expected", bestHeight, uint64(i+3))
		}

		bestHash := best.BlockHash()
		if !bytes.Equal(bestHash[:], lastHashToAdd[:]) {
			t.Errorf("best hash %x does not match expected hash %x", bestHash[:], lastHashToAdd[:])
		}

		t.Logf("TBC canonical tip %x is at height %d\n", bestHash[:], bestHeight)
	}

	// STEP 2: Walk chain backward 3 blocks at a time
	for i := len(simpleChainHeaders) - 1; i > 0; i -= 3 {
		headers := make([][80]byte, 3)
		parsedHeaders := make([]*wire.BlockHeader, 3)

		// Headers still need to be lowest-to-highest ordered
		for j := -2; j <= 0; j++ {
			blockraw, err := hexToRawHeader(simpleChainHeaders[i+j])
			if err != nil {
				t.Errorf("unable to parse hex header %s", simpleChainHeaders[i+j])
			}

			blockheader, err := bytes2Header(*blockraw)
			if err != nil {
				t.Errorf("unable to parse raw header %s", simpleChainHeaders[i+j])
			}

			blockhashcalc := blockheader.BlockHash()
			blockhashexp, err := hexToHash(simpleChainHashes[i+j])
			if err != nil {
				t.Errorf("unable to parse expected block header %s", simpleChainHashes[i+j])
			}

			if !bytes.Equal(blockhashcalc[:], blockhashexp[:]) {
				t.Errorf("hash of header was %x but expected %x", blockhashcalc[:], blockhashexp[:])
			}

			headers[j+2] = *blockraw
			parsedHeader, err := bytes2Header(headers[j+2])
			if err != nil {
				t.Errorf("Unable to parse header %s", simpleChainHeaders[i+j])
			}

			parsedHeaders[j+2] = parsedHeader
		}

		msgHeaders := &wire.MsgHeaders{
			Headers: parsedHeaders,
		}

		prevHeaderIdx := i - 3
		prevHeaderStr := regtestGenesisHeader
		if prevHeaderIdx > 0 {
			prevHeaderStr = simpleChainHeaders[prevHeaderIdx]
		}

		prevHeader, err := hexToRawHeader(prevHeaderStr)
		if err != nil {
			t.Errorf("unable to parse hex header %s", simpleChainHeaders[i-1])
		}

		prevHeaderParsed, err := bytes2Header(*prevHeader)
		if err != nil {
			t.Errorf("unable to parse raw header %s", simpleChainHeaders[i])
		}

		prevHeaderHash := prevHeaderParsed.BlockHash()
		t.Logf("Headers to remove:")
		for k := len(headers) - 1; k >= 0; k-- {
			nh, _ := bytes2Header(headers[k])
			blockhashcalc := nh.BlockHash()
			bh := blockhashcalc[:]
			// slices.Reverse(bh)
			t.Logf("%d: %x", k, bh)
		}

		rt, postRemovalTip, err := tbc.RemoveExternalHeaders(ctx, msgHeaders, prevHeaderParsed, defaultUpstreamStateId[:])
		if err != nil {
			t.Error(err)
		}

		prtHash := postRemovalTip.BlockHash()
		if !bytes.Equal(prtHash[:], prevHeaderHash[:]) {
			t.Errorf("after removing lowest header %x expected tip to be %x but was %x", headers[0][:], prevHeaderHash[:], prtHash[:])
		}

		if rt != tbcd.RTChainDescend {
			t.Errorf("removing headers should have descended canonical chain")
		}

		bestHeight, best, err := tbc.BlockHeaderBest(ctx)
		if err != nil {
			t.Error(err)
		}

		if bestHeight != uint64(i-2) {
			t.Errorf("Height from TBC is %d but %d was expected", bestHeight, uint64(i-2))
		}

		bestHash := best.BlockHash()
		if !bytes.Equal(bestHash[:], prevHeaderHash[:]) {
			t.Errorf("best hash %x does not match expected hash %x", bestHash[:], prevHeaderHash[:])
		}

		t.Logf("TBC canonical tip %x is at height %d\n", bestHash[:], bestHeight)
	}
}

// Starts at regtest genesis block, walks up the simpleChain defined above
// in one move to height 9, checking all blocks are added correctly and
// the last block 9 is considered canonical, and then attempts to remove
// various segments of blocks below the tip and ensures that TBC correctly
// fails to perform the removal and does not make state changes.
// Then, this test removes blocks [3-9] correctly and ensures block 2
// is correctly set as the canonical tip.
// Finally, this test adds blocks [3-8] again and ensures block 8
// is correctly set as the canonical tip.
func TestExternalHeaderModeSimpleIncorrectRemoval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// XXX all t.Error in here should be t.Fatal. There is no point in
	// continuing the test.

	tbc := createTbcServerExternalHeaderMode(ctx, t)

	// STEP 1: Add headers from 1 to 9 in one go
	processToHeight := 9
	_, msgHeaders, hashes, err := getHeaderHashesRange(0, processToHeight-1, simpleChainHeaders[:], simpleChainHashes[:])
	if err != nil {
		t.Error(err)
	}

	// arbitrary values
	origInsertStateId := [32]byte{0xFF, 0x33, 0x99, 0xE3}
	it, canon, last, _, err := tbc.AddExternalHeaders(ctx, msgHeaders, origInsertStateId[:])
	if err != nil {
		t.Error(err)
	}

	stateIdRet, err := tbc.UpstreamStateId(ctx)
	if err != nil {
		t.Errorf("unable to get upstream state id, err: %v", err)
	}

	if !bytes.Equal(stateIdRet[:], origInsertStateId[:]) {
		t.Errorf("after adding external headers, state id should have been %x but got %x instead",
			origInsertStateId[:], stateIdRet[:])
	} else {
		t.Logf("after adding external headers, state id of %x is correct", stateIdRet[:])
	}

	if it != tbcd.ITChainExtend {
		t.Errorf("Adding headers should have extended canonical chain")
	}

	canonHash := canon.BlockHash()
	lastHash := last.BlockHash()
	lastHashToAdd := hashes[len(hashes)-1]

	if !bytes.Equal(canonHash[:], lastHash[:]) {
		t.Errorf("Canonical hash %x does not match expected hash %x", canonHash[:], lastHash[:])
	}

	if !bytes.Equal(canonHash[:], hashes[len(hashes)-1][:]) {
		t.Errorf("Canonical hash %x does not match last hash %x which is expected in this scenario", canonHash[:], hashes[len(hashes)-1][:])
	}

	bestHeight, best, err := tbc.BlockHeaderBest(ctx)
	if err != nil {
		t.Error(err)
	}

	if bestHeight != uint64(processToHeight) {
		t.Errorf("Height from TBC is %d but %d was expected", bestHeight, processToHeight)
	}

	bestHash := best.BlockHash()
	if !bytes.Equal(bestHash[:], lastHashToAdd[:]) {
		t.Errorf("best hash %x does not match expected hash %x", bestHash[:], lastHashToAdd[:])
	}

	// STEP 2: Attempt to remove several different chunks of the chain below the
	// current tip (block 9) and ensure TBC returns an error and doesn't make any
	// state changes underneath.
	badRanges := [][]int{
		{8, 8}, // Attempt to just remove block 8
		{6, 8}, // Attempt to remove blocks 6 through 8 inclusive
		{5, 8},
		{1, 8},
		{7, 7},
		{4, 7},
		{2, 7},
		{4, 5},
		{1, 5},
		{1, 1},
	}

	canonicalHeightBefore, canonicalBefore, err := tbc.BlockHeaderBest(ctx)
	if err != nil {
		t.Error(err)
	}

	canonicalBeforeHash := canonicalBefore.BlockHash()
	for _, badRange := range badRanges {
		start := badRange[0]
		end := badRange[1]

		// Subtract 1 from start and end because the ranges refer to block heights,
		// but the defined simple chain headers/hashes start at block #1
		_, msgHeaders, _, err := getHeaderHashesRange(start-1, end-1, simpleChainHeaders[:], simpleChainHashes[:])
		rawWouldBeCanonical, _, _, err := getRegtestGenesisHeaderAndHash()
		if err != nil {
			t.Error(err)
		}

		if start > 1 { // would-be-canonical tip is not genesis
			rawWouldBeCanonical, _, _, err = getHeaderHashIndex(start-2, simpleChainHeaders[:], simpleChainHashes[:])
			if err != nil {
				t.Error(err)
			}
		}

		wouldBeCanonical, err := bytes2Header(*rawWouldBeCanonical)
		if err != nil {
			t.Errorf("unable to parse heacer %x", rawWouldBeCanonical[:])
		}

		removeStateId := [32]byte{0xAA, 0xBB, 0xCC, 0xDD}
		rt, postRemovalTip, err := tbc.RemoveExternalHeaders(ctx, msgHeaders, wouldBeCanonical, removeStateId[:])
		if err == nil {
			t.Errorf("removing headers from %d to %d when tip is %d should have failed but did not", start, end, canonicalHeightBefore)
		}

		if rt != tbcd.RTInvalid {
			// Chain dangling
			t.Errorf("removing headers from %d to %d when tip is %d should have failed with tbcd.RTInvalid", start, end, canonicalHeightBefore)
		}

		if postRemovalTip != nil {
			t.Errorf("removing headers from %d to %d when tip is %d should not have returned a non-nil post removal tip", start, end, canonicalHeightBefore)
		}

		stateIdRet, err := tbc.UpstreamStateId(ctx)
		if err != nil {
			t.Errorf("unable to get upstream state id, err: %v", err)
		}

		if !bytes.Equal(stateIdRet[:], origInsertStateId[:]) {
			t.Errorf("after failing to remove external headers, state id should have been the original insert id %x but got %x instead",
				origInsertStateId[:], stateIdRet[:])
		} else {
			t.Logf("after failing to remove external headers, state id of %x is correct", stateIdRet[:])
		}

		canonicalHeightAfter, canonicalAfter, err := tbc.BlockHeaderBest(ctx)
		if err != nil {
			t.Error(err)
		}

		canonicalAfterHash := canonicalAfter.BlockHash()
		if canonicalHeightAfter != canonicalHeightBefore {
			t.Errorf("an invalid removal changed the canonical height from %d to %d which should not happen", canonicalHeightBefore, canonicalHeightAfter)
		}

		if !bytes.Equal(canonicalAfterHash[:], canonicalBeforeHash[:]) {
			t.Errorf("an invalid removal changed the canonical hash from %x to %x which should not happen", canonicalBeforeHash[:], canonicalAfterHash[:])
		}
	}

	// STEP 3: Remove blocks 3 through 9 which should work correctly and verify 2 is canonical afterward
	// Subtract 1 from start and end because the ranges refer to block heights,
	// but the defined simple chain headers/hashes start at block #1
	start := 3
	end := 9
	_, msgHeaders, _, err = getHeaderHashesRange(start-1, end-1, simpleChainHeaders[:], simpleChainHashes[:])
	rawShouldBeCanonical, _, shouldBeCanonicalHash, err := getHeaderHashIndex(start-2, simpleChainHeaders[:], simpleChainHashes[:])
	if err != nil {
		t.Error(err)
	}

	shouldBeCanonical, err := bytes2Header(*rawShouldBeCanonical)
	if err != nil {
		t.Errorf("unable to parse heacer %x", rawShouldBeCanonical[:])
	}

	rt, postRemovalTip, err := tbc.RemoveExternalHeaders(ctx, msgHeaders, shouldBeCanonical, defaultUpstreamStateId[:])
	if err != nil {
		t.Errorf("removing headers from %d to %d when tip is %d should have succeeded but did not", start, end, canonicalHeightBefore)
	}

	if rt != tbcd.RTChainDescend {
		t.Errorf("removing headers from %d to %d when tip is %d should have succeeded with tbcd.RTChainDescend", start, end, canonicalHeightBefore)
	}

	if postRemovalTip == nil {
		t.Errorf("removing headers from %d to %d when tip is %d should have returned a non-nil post removal tip", start, end, canonicalHeightBefore)
	}

	stateIdRet, err = tbc.UpstreamStateId(ctx)
	if err != nil {
		t.Errorf("unable to get upstream state id, err: %v", err)
	}

	if !bytes.Equal(stateIdRet[:], defaultUpstreamStateId[:]) {
		t.Errorf("after successfully removing external headers with no state id specified, state id should "+
			"have been the default upstream state id %x but got %x instead",
			defaultUpstreamStateId[:], stateIdRet[:])
	} else {
		t.Logf("after successfully removing external headers with no state id specified, state id of "+
			"%x is correct (set to default)", stateIdRet[:])
	}

	updateStateWithoutModificationsId := [32]byte{0x4C, 0xA1, 0x62, 0xB6}
	err = tbc.SetUpstreamStateId(ctx, updateStateWithoutModificationsId)
	if err != nil {
		t.Errorf("unable to set upstream state id, err: %v", err)
	}

	stateIdRet, err = tbc.UpstreamStateId(ctx)
	if err != nil {
		t.Errorf("unable to get upstream state id, err: %v", err)
	}

	if !bytes.Equal(stateIdRet[:], updateStateWithoutModificationsId[:]) {
		t.Errorf("after performing an explicit state id update without modifying header data state id should "+
			"have been %x but got %x instead",
			updateStateWithoutModificationsId[:], stateIdRet[:])
	} else {
		t.Logf("after performing an explicit state id update without modifying header data state, state id of "+
			"%x is correct (set to default)", stateIdRet[:])
	}

	canonicalHeightAfter, canonicalAfter, err := tbc.BlockHeaderBest(ctx)
	if err != nil {
		t.Error(err)
	}

	canonicalAfterHash := canonicalAfter.BlockHash()
	if canonicalHeightAfter != uint64(start-1) {
		t.Errorf("a valid removal of headers %d to %d should have set the canonical height to %d, but it is %d", start, end, uint64(start-1), canonicalHeightAfter)
	}

	if !bytes.Equal(canonicalAfterHash[:], shouldBeCanonicalHash[:]) {
		t.Errorf("a valid removal should have changed the canonical hash from %x to %x, but instead got %x", canonicalBeforeHash[:], shouldBeCanonicalHash[:], canonicalAfterHash[:])
	}

	// Check to make sure none of the removed headers can be fetched from TBC
	for i := start; i <= end; i++ {
		headers, err := tbc.BlockHeadersByHeight(ctx, uint64(i))
		if err == nil {
			t.Errorf("getting headers at height %d when tip is %d should have returned an error but did not", i, canonicalHeightAfter)
		}

		if headers != nil {
			t.Errorf("getting headers at height %d when tip is %d should have returned a nil headers array but did not", i, canonicalHeightAfter)
		}

		_, _, hash, err := getHeaderHashIndex(i-1, simpleChainHeaders[:], simpleChainHashes[:])
		header, height, err := tbc.BlockHeaderByHash(ctx, *hash)
		if err == nil {
			t.Errorf("getting header by hash %x should have returned an error but did not", hash[:])
		}

		if height != 0 {
			t.Errorf("getting header by hash %x should have returned a height of 0 but did not", hash[:])
		}

		if header != nil {
			t.Errorf("getting header by hash %x should have returned a nil header but did not", hash[:])
		}
	}

	// STEP 4: Add blocks 3 through 8 again and make sure canonical is now 8
	processToHeight = 8
	_, msgHeaders, hashes, err = getHeaderHashesRange(3-1, processToHeight-1, simpleChainHeaders[:], simpleChainHashes[:])
	if err != nil {
		t.Error(err)
	}

	it, canon, last, _, err = tbc.AddExternalHeaders(ctx, msgHeaders, defaultUpstreamStateId[:])
	if err != nil {
		t.Error(err)
	}

	if it != tbcd.ITChainExtend {
		t.Errorf("Adding headers should have extended canonical chain")
	}

	canonHash = canon.BlockHash()
	lastHash = last.BlockHash()
	lastHashToAdd = hashes[len(hashes)-1]
	if !bytes.Equal(canonHash[:], lastHash[:]) {
		t.Errorf("Canonical hash %x does not match expected hash %x", canonHash[:], lastHash[:])
	}

	if !bytes.Equal(canonHash[:], hashes[len(hashes)-1][:]) {
		t.Errorf("Canonical hash %x does not match last hash %x which is expected in this scenario", canonHash[:], hashes[len(hashes)-1][:])
	}

	bestHeight, best, err = tbc.BlockHeaderBest(ctx)
	if err != nil {
		t.Error(err)
	}

	if bestHeight != uint64(processToHeight) {
		t.Errorf("Height from TBC is %d but %d was expected", bestHeight, processToHeight)
	}

	bestHash = best.BlockHash()
	if !bytes.Equal(bestHash[:], lastHashToAdd[:]) {
		t.Errorf("best hash %x does not match expected hash %x", bestHash[:], lastHashToAdd[:])
	}
}
