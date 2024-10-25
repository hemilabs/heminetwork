// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	client "github.com/btcsuite/btcd/rpcclient"
	"github.com/gosuri/uilive"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/hemilabs/heminetwork/hemi/pop"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t := table.NewWriter()
	writer := uilive.New()
	writer.Start()
	t.SetOutputMirror(writer)

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

	runJs := func(jsi string, layer string, ipcPath string, replica string) string {
		prefix := "op-"
		if layer == "l1" {
			prefix = ""
		}

		container := fmt.Sprintf("e2e-%sgeth-%s-%s", prefix, layer, replica)
		cmd := exec.Command(
			"docker",
			"exec",
			container,
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
		first := runJs(firstBatcherTxBlockJs, "l1", "geth.ipc", "1")
		last := runJs(lastBatcherTxBlockJs, "l1", "geth.ipc", "1")
		count := runJs(batcherPublicationCountJs, "l1", "geth.ipc", "1")
		popMinerBalance := runJs(popMinerBalanceJs, "l2", "datadir/geth.ipc", "2-1")

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
