// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	client "github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/gosuri/uilive"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/hemilabs/heminetwork/hemi/electrumx"
	"github.com/hemilabs/heminetwork/hemi/pop"

	"github.com/slack-go/slack"
)

const (
	dataRefreshSeconds   = 1
	tableRefreshSeconds  = 1
	batcherInboxAddress  = "0xff00000000000000000000000000000000000901"
	batcherSenderAddress = "0x78697c88847dfbbb40523e42c1f2e28a13a170be"
)

type state struct {
	bitcoinBlockCount           uint64
	containersRunning           []string
	popTxCount                  uint64
	firstBatcherPublicationHash string
	lastBatcherPublicationHash  string
	batcherPublicationCount     int
	popMinerBalance             string // very large number
}

type jsonOutput struct {
	BitcoinBlockCount           uint64 `json:"bitcoin_block_count"`
	PopTxCount                  uint64 `json:"pop_tx_count"`
	FirstBatcherPublicationHash string `json:"first_batcher_publication_hash"`
	LastBatcherPublicationHash  string `json:"last_batcher_publication_hash"`
	BatcherPublicationCount     uint64 `json:"batcher_publication_count"`
	PopMinerHemiBalance         string `json:"pop_miner_hemi_balance"`
}

func main() {
	output := monitor(dumpJsonAfterMsFromEnv())
	fmt.Println(output)
}

func weiToEth(wei *big.Int) *big.Float {
	return new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(params.Ether))
}

// monitor will wait the specified ms, then dump localnet's state as a json
// string.  the reason we "wait" is so that localnet can progress.  the caller
// chooses how long they want to wait in ms (i.e. how long they want to let
// localnet progress).  if dumpJsonAfterMs is 0, we assume the user wants to
// view the live-refresh table
func monitor(dumpJsonAfterMs uint) string {
	s := state{
		bitcoinBlockCount: 0,
	}
	mtx := sync.Mutex{}
	ctx := context.Background()
	t := table.NewWriter()
	writer := uilive.New()
	writer.Start()
	t.SetOutputMirror(writer)

	_, err := l2Version(l2())
	if err != nil {
		panic(err)
	}

	electrumxClient, err := electrumx.NewClient("electrumx.heminetwork:50001")
	if err != nil {
		panic(err)
	}

	for {

		addr, err := btcutil.DecodeAddress("msMgk6qaS5sso4CTao22VaUY8rbFPp3ThT", &chaincfg.TestNet3Params)
		if err != nil {
			panic(err)
		}

		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			panic(err)
		}

		scriptHash := sha256.Sum256(script)

		bitcoinBalance, err := electrumxClient.Balance(ctx, scriptHash[:])
		if err != nil {
			panic(err)
		}

		blockTime, err := latestL2BlockTime(ctx, l2())
		if err != nil {
			panic(err)
		}

		batcherBalance, err := l1batcherBalance(ctx, l1())
		if err != nil {
			panic(err)
		}

		proposerBalance, err := l1ProposerBalance(ctx, l1())
		if err != nil {
			panic(err)
		}

		notify := false
		d := time.Now().Sub(*blockTime)
		m := math.Round(d.Minutes())
		friendlyTime := fmt.Sprintf("last l2 block created %d minutes ago", int(m))
		friendlyBatcherBalance := fmt.Sprintf("batcher balance %f sep eth", weiToEth(batcherBalance))
		if weiToEth(batcherBalance).Cmp(big.NewFloat(5)) == -1 {
			fmt.Println("batcherBalancer is less than 5, notifying")
			notify = true
		}
		friendlyProposerBalance := fmt.Sprintf("proposer balance %f sep eth", weiToEth(proposerBalance))
		if weiToEth(proposerBalance).Cmp(big.NewFloat(1)) == -1 {
			fmt.Println("batcherBalancer is less than 1, notifying")
			notify = true
		}
		bitcoinBalanceFriendly := fmt.Sprintf("pop miner balance %f tbtc", float64(bitcoinBalance.Confirmed)/100000000.0)
		if float64(bitcoinBalance.Confirmed)/100000000.0 < 1.0 {
			fmt.Println("pop miner is less than 1, notifying")
			notify = true
		}

		// if 1 minute ago is after blockTime
		if time.Now().Add(-1*time.Minute).Compare(*blockTime) == 1 {
			notify = true
		}

		fmt.Println(friendlyBatcherBalance)
		fmt.Println(friendlyProposerBalance)
		fmt.Println(bitcoinBalanceFriendly)
		fmt.Println(friendlyTime)

		status := fmt.Sprintf("%s\n%s\n%s\n%s", friendlyTime, friendlyBatcherBalance, friendlyProposerBalance, bitcoinBalanceFriendly)

		if notify {
			api := slack.New(os.Getenv("HEMI_E2E_SLACK_TOKEN"))
			_, _, err = api.PostMessage("incentivized-testnet-monitoring", slack.MsgOptionText(status, false))
			if err != nil {
				panic(err)
			}
		}

		select {
		case <-ctx.Done():
			return ""
		case <-time.After(30 * time.Second):
		}
	}

	go monitorBitcoinBlocksCreated(ctx, &s, &mtx)
	go monitorPopTxs(ctx, &s, &mtx)
	go monitorRolledUpTxs(ctx, &s, &mtx)

	if dumpJsonAfterMs == 0 {
		go render(ctx, &s, t, &mtx)
	}

	if dumpJsonAfterMs > 0 {
		select {
		case <-time.After(time.Duration(dumpJsonAfterMs) * time.Millisecond):
			output := dumpJson(&mtx, &s)
			return output
		case <-ctx.Done():
			return ""
		}
	}

	<-ctx.Done()
	return ""
}

func render(ctx context.Context, s *state, w table.Writer, mtx *sync.Mutex) {
	for {
		mtx.Lock()
		w.ResetRows()

		w.AppendRow(table.Row{fmt.Sprintf("refreshing every %d seconds", dataRefreshSeconds)})

		bitcoindText := fmt.Sprintf("%d", s.bitcoinBlockCount)

		w.AppendRow(table.Row{"bitcoin block count", bitcoindText})

		w.AppendRow(table.Row{"poptxs mined", fmt.Sprintf("%d", s.popTxCount)})

		w.AppendRow(table.Row{"first batcher publication hash", fmt.Sprintf("%s", s.firstBatcherPublicationHash)})

		w.AppendRow(table.Row{"last batcher publication hash", fmt.Sprintf("%s", s.lastBatcherPublicationHash)})

		w.AppendRow(table.Row{"batcher publication count", fmt.Sprintf("%d", s.batcherPublicationCount)})

		w.AppendRow(table.Row{"pop miner $HEMI balance", fmt.Sprintf("%s", s.popMinerBalance)})

		for _, c := range s.containersRunning {
			w.AppendRow(table.Row{fmt.Sprintf("container %s", c), "running"})
		}
		w.Render()
		mtx.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(tableRefreshSeconds * time.Second):
		}
	}
}

func monitorBitcoinBlocksCreated(ctx context.Context, s *state, mtx *sync.Mutex) {
	for {
		config := client.ConnConfig{
			User:         "user",
			Pass:         "password",
			Host:         "localhost:18443",
			DisableTLS:   true,
			HTTPPostMode: true,
		}
		c, err := client.New(&config, nil)
		if err != nil {
			panic(fmt.Sprintf("could not create new client from config %v: %v", config, err))
		}

		count, err := c.GetBlockCount()
		if err != nil {
			panic(fmt.Sprintf("could not get block count: %v", err))
		}

		mtx.Lock()
		s.bitcoinBlockCount = uint64(count)
		mtx.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(dataRefreshSeconds * time.Second):

		}
	}
}

func monitorPopTxs(ctx context.Context, s *state, mtx *sync.Mutex) {
	cache := map[string]bool{}
	popTxs := 0
	for {
		config := client.ConnConfig{
			User:         "user",
			Pass:         "password",
			Host:         "localhost:18443",
			DisableTLS:   true,
			HTTPPostMode: true,
		}
		c, err := client.New(&config, nil)
		if err != nil {
			panic(fmt.Sprintf("could not create new client with config %v: %v", config, err))
		}

		tips, err := c.GetChainTips()
		if err != nil {
			panic(fmt.Sprintf("could not get chain tips: %v", err))
		}

		if len(tips) != 1 {
			// should not happen in localnet
			continue
		}

		hash, err := chainhash.NewHashFromStr(tips[0].Hash)
		if err != nil {
			panic(fmt.Sprintf("could not get hash from string %s: %v", tips[0].Hash, err))
		}

		block, err := c.GetBlock(hash)
		if err != nil {
			panic(fmt.Sprintf("could not get block from hash %v: %v", tips[0].Hash, err))
		}

		for block != nil {
			if !cache[block.BlockHash().String()] {
				cache[block.BlockHash().String()] = true
				for _, tx := range block.Transactions {
					for _, txo := range tx.TxOut {
						_, err := pop.ParseTransactionL2FromOpReturn(txo.PkScript)
						if err == nil {
							popTxs++
						}
					}
				}
			}

			hash = &block.Header.PrevBlock
			block, err = c.GetBlock(hash)
			if err != nil {
				break
			}
		}

		mtx.Lock()
		s.popTxCount = uint64(popTxs)
		mtx.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(dataRefreshSeconds * time.Second):

		}
	}
}

func monitorRolledUpTxs(ctx context.Context, s *state, mtx *sync.Mutex) {
	firstBatcherTxBlockJs := fmt.Sprintf(`
		let found = false;
		for (let i = 0; i <= eth.blockNumber; i++) {
			const block = eth.getBlock(i);
			for (const transactionHash of block.transactions) {
				const transaction = eth.getTransaction(transactionHash);
				if (transaction.from === '%s' && transaction.to === '%s') {
					console.log(`+"`${transaction.hash}, ${i}`"+`);
					found = true;
				}

				if (found) {
					break;
				}
			}

			if (found) {
				break;
			}
		}
	`, batcherSenderAddress, batcherInboxAddress)

	lastBatcherTxBlockJs := fmt.Sprintf(`
		let found = false;
		for (let i = eth.blockNumber;i >= 0; i--) {
			const block = eth.getBlock(i);
			for (const transactionHash of block.transactions) {
				const transaction = eth.getTransaction(transactionHash);
				if (transaction.from === '%s' && transaction.to === '%s') {
					console.log(`+"`${transaction.hash}, ${i}`"+`);
					found = true;
				}

				if (found) {
					break;
				}
			}

			if (found) {
				break;
			}
		}
	`, batcherSenderAddress, batcherInboxAddress)

	batcherPublicationCountJs := fmt.Sprintf(`
		let count = 0;
		for (let i = eth.blockNumber; i >= 0; i--) {
			const block = eth.getBlock(i);
			for (const transactionHash of block.transactions) {
				const transaction = eth.getTransaction(transactionHash);
				if (transaction.from === '%s' && transaction.to === '%s') {
					count++;
				}
			}
		}
		console.log(count);
	`, batcherSenderAddress, batcherInboxAddress)

	popMinerBalanceJs := `
		const hexValue = eth.call({
		  to: '0x4200000000000000000000000000000000000042',
		  from: eth.accounts[0],
		  data: '0x70a08231000000000000000000000000B275Ec0935e404BEe2d40622de13495F42F84d90',
		});
		console.log(Number.parseInt(hexValue, 16));
	`

	runJs := func(jsi string, layer string, ipcPath string) string {
		cmd := exec.Command(
			"docker",
			"exec",
			fmt.Sprintf("e2e-op-geth-%s-1", layer),
			"geth",
			"attach",
			"--exec",
			jsi,
			ipcPath,
		)
		output, err := cmd.Output()
		if err != nil {
			panic(fmt.Sprintf("error executing command %s: %v", cmd.String(), err))
		}

		return strings.Split(string(output), "\n")[0]
	}

	for {
		first := runJs(firstBatcherTxBlockJs, "l1", "geth.ipc")
		last := runJs(lastBatcherTxBlockJs, "l1", "geth.ipc")
		count := runJs(batcherPublicationCountJs, "l1", "geth.ipc")
		popMinerBalance := runJs(popMinerBalanceJs, "l2", "datadir/geth.ipc")

		mtx.Lock()
		s.firstBatcherPublicationHash = first
		s.lastBatcherPublicationHash = last

		s.popMinerBalance = popMinerBalance
		var err error
		s.batcherPublicationCount, err = strconv.Atoi(count)
		if err != nil {
			panic(fmt.Sprintf("could not get batcher publication count %s: %v", count, err))
		}
		mtx.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(dataRefreshSeconds * time.Second):
		}
	}
}

func dumpJsonAfterMsFromEnv() uint {
	val := os.Getenv("HEMI_E2E_DUMP_JSON_AFTER_MS")
	if val == "" {
		return 0
	}

	num, err := strconv.Atoi(val)
	if err != nil {
		panic(fmt.Sprintf("could not convert value to int %s: %v", val, err))
	}

	if num < 1000*10 {
		panic("need to wait at least 10 seconds")
	}

	return uint(num)
}

func l2() string {
	val := os.Getenv("HEMI_E2E_L2")
	if val == "" {
		val = "http://op-geth-l2:8546"
	}

	return val
}

func l1() string {
	val := os.Getenv("HEMI_E2E_L1")
	if val == "" {
		val = "http://op-geth-l1:8545"
	}

	return val
}

func dumpJson(mtx *sync.Mutex, s *state) string {
	mtx.Lock()
	output := jsonOutput{
		BitcoinBlockCount:           s.bitcoinBlockCount,
		PopTxCount:                  s.popTxCount,
		FirstBatcherPublicationHash: s.firstBatcherPublicationHash,
		LastBatcherPublicationHash:  s.lastBatcherPublicationHash,
		BatcherPublicationCount:     uint64(s.batcherPublicationCount),
		PopMinerHemiBalance:         s.popMinerBalance,
	}
	mtx.Unlock()

	b, err := json.Marshal(output)
	if err != nil {
		panic(fmt.Sprintf("could not marsh output to json: %v", err))
	}

	return string(b)
}

type EthereumRPCRequest struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	Id      int    `json:"id"`
}

type EthereumRPCResponse struct {
	Result string `json:"result"`
}

func l2Version(l2 string) (string, error) {
	body := EthereumRPCRequest{
		Jsonrpc: "2.0",
		Method:  "web3_clientVersion",
		Params:  []any{},
		Id:      rand.Int(),
	}

	return makeEthereumRPCRequest(l2, &body)
}

func latestL2BlockTime(ctx context.Context, l2 string) (*time.Time, error) {
	client, err := ethclient.DialContext(ctx, l2)
	if err != nil {
		return nil, err
	}

	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}

	t := time.Unix(int64(header.Time), 0)

	return &t, nil
}

const batcherAddress string = "0x2A9DC73B4Ac558f424087146672241F7Fc8199E9"
const sequencerAddress string = "0x485F17600E8b651b79997B304197844758e02AEf"
const proposerAddress string = "0x63643f30e892A3826B1F70932C11f2B8a740A104"

func l1BalanceForAddress(ctx context.Context, l1 string, address common.Address) (*big.Int, error) {
	client, err := ethclient.DialContext(ctx, l1)
	if err != nil {
		return nil, err
	}

	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}

	balance, err := client.BalanceAt(ctx, address, header.Number)
	if err != nil {
		return nil, err
	}

	return balance, nil
}

func l1batcherBalance(ctx context.Context, l1 string) (*big.Int, error) {
	return l1BalanceForAddress(ctx, l1, common.HexToAddress(batcherAddress))
}

func l1SequencerBalance(ctx context.Context, l1 string) (*big.Int, error) {
	return l1BalanceForAddress(ctx, l1, common.HexToAddress(sequencerAddress))
}

func l1ProposerBalance(ctx context.Context, l1 string) (*big.Int, error) {
	return l1BalanceForAddress(ctx, l1, common.HexToAddress(proposerAddress))
}

func makeEthereumRPCRequest(l2 string, body *EthereumRPCRequest) (string, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	client := http.Client{}
	req, err := http.NewRequest(http.MethodPost, l2, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if err := resp.Body.Close(); err != nil {
		return "", err
	}

	var response EthereumRPCResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return "", err
	}

	fmt.Println(string(respBody))

	return response.Result, nil
}
