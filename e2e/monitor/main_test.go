// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/hemilabs/heminetwork/hemi"
)

// Test_Monitor is a small, bare-bones test to dump the state of localnet
// after 5 minutes and check that it has progressed at least to a certain
// point
func TestMonitor(t *testing.T) {
	time.Sleep(2 * time.Minute)

	var jo jsonOutput

	blockWaitTimeoutTimer := time.NewTimer(10 * time.Minute)
	for jo.BitcoinBlockCount < 1012 {

		select {
		case <-blockWaitTimeoutTimer.C:
			t.Fatalf("timed out waiting for btc blocks")
		case <-time.After(10 * time.Second):
		}

		output := monitor(uint(10 * 1000))
		t.Log(output)

		if err := json.Unmarshal([]byte(output), &jo); err != nil {
			t.Fatal(err)
		}
	}

	output := monitor(uint(60 * 1000))
	t.Log(output)
	if err := json.Unmarshal([]byte(output), &jo); err != nil {
		t.Fatal(err)
	}

	expectedPopTxs := 12

	t.Logf("expecting at least %d pop txs mined", expectedPopTxs)

	if jo.PopTxCount < uint64(expectedPopTxs) {
		t.Fatalf("popTxCount %d < %d", jo.PopTxCount, expectedPopTxs)
	}

	// the expected balance should be at least 1 BaseHEMI per poptx - 8.  We say
	// "- 8" because we lag 8 keystones behind a pop payout (200 L2 blocks at
	// 1 block per second)
	popMinerBalance := big.NewInt(0)
	balance, ok := popMinerBalance.SetString(jo.PopMinerHemiBalance, 10)
	if !ok {
		t.Fatalf("could not parse balance from %s", jo.PopMinerHemiBalance)
	}

	expectedPayouts := expectedPopTxs - 8
	expectedPayoutBalance := big.NewInt(hemi.HEMIBase)
	expectedPayoutBalance = expectedPayoutBalance.Mul(big.NewInt(int64(expectedPayouts)), expectedPayoutBalance)

	t.Logf("expecting actual balance %d to be greater than %d", balance, expectedPayoutBalance)

	if expectedPayoutBalance.Cmp(balance) > 0 {
		t.Fatalf("pop miner payout balance received %d, want at least %d", balance, expectedPayoutBalance)
	}
}
