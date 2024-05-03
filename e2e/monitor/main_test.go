// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/hemilabs/heminetwork/hemi"
)

// Test_Monitor is a small, bare-bones test to dump the state of localnet
// after 5 minutes and check that it has progressed at least to a certain
// point
func TestMonitor(t *testing.T) {
	ms := 1000 * 60 * 5 // dump after 5 minutes
	output := monitor(uint(ms))

	t.Log(output)

	var jo jsonOutput

	if err := json.Unmarshal([]byte(output), &jo); err != nil {
		t.Fatal(err)
	}

	// each keystone is 25 seconds, so there are 4 keystones per 100 seconds,
	// we expect the number of pop txs to be at least once every 25 seconds
	// for the time we waited
	seconds := ms / 1000
	popTxsPer100Seconds := 4
	expectedPopTxs := popTxsPer100Seconds * (seconds / 100)

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
