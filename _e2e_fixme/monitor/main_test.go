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
	// let localnet start, there are smarter ways to do this but this will work
	// for now
	time.Sleep(2 * time.Minute)

	// somewhat arbitrary; we should be able to get to 12 pop txs mined in a
	// reasonable amount of time
	const expectedPopTxs = 12
	t.Logf("expecting at least %d pop txs mined", expectedPopTxs)

	// the expected balance should be at least 1 BaseHEMI per poptx - 8.  We say
	// "- 8" because we lag 8 keystones behind a pop payout
	expectedPayouts := expectedPopTxs - 8
	expectedPayoutBalance := big.NewInt(hemi.HEMIBase)
	expectedPayoutBalance = expectedPayoutBalance.Mul(big.NewInt(int64(expectedPayouts)), expectedPayoutBalance)
	t.Logf("expecting a HEMI balance of at least %d", expectedPayoutBalance)

	// if we get to 10 minutes without the expected number of pop txs
	// and HEMI balance, something is wrong, fail the test
	blockWaitTimeoutTimer := time.NewTimer(10 * time.Minute)

	for {
		// poll every 10 seconds until timeout
		select {
		case <-blockWaitTimeoutTimer.C:
			t.Fatalf("timed out")
		case <-time.After(10 * time.Second):
		}

		// let the goroutines gather stats for 10 seconds, then dump
		// it and check the results, if they're not what we expected try again
		output := monitor(uint(10 * 1000))
		t.Log(output)

		var jo jsonOutput
		if err := json.Unmarshal([]byte(output), &jo); err != nil {
			t.Fatal(err)
		}

		if jo.PopTxCount < uint64(expectedPopTxs) {
			t.Logf("popTxCount %d < %d", jo.PopTxCount, expectedPopTxs)
			continue
		}

		popMinerBalance := big.NewInt(0)
		balance, ok := popMinerBalance.SetString(jo.PopMinerHemiBalance, 10)
		if !ok {
			t.Fatalf("could not parse balance from %s", jo.PopMinerHemiBalance)
		}

		t.Logf("expecting actual balance %d to be greater than %d", balance, expectedPayoutBalance)

		if expectedPayoutBalance.Cmp(balance) > 0 {
			t.Logf("pop miner payout balance received %d, want at least %d", balance, expectedPayoutBalance)
			continue
		}

		// success; we passed the test
		break
	}
}
