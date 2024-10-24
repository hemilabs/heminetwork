// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/hemilabs/heminetwork/hemi"
)

// Test_Monitor is a small, bare-bones test to dump the state of localnet
// after 5 minutes and check that it has progressed at least to a certain
// point
func TestMonitor(t *testing.T) {
	ms := (1000 * 60 * 5) + 25*1000 // dump after 5 minutes + 25 seconds for cushion (1 keystone)
	output := monitor(uint(ms))

	t.Log(output)

	var jo jsonOutput
	if err := json.Unmarshal([]byte(output), &jo); err != nil {
		t.Fatal(err)
	}

	// each keystone is 25 seconds, so there are 4 keystones per 100 seconds,
	// we expect the number of pop txs to be at least once every 25 seconds
	// for the time we waited
	// add 25 seconds for cushion
	seconds := ms / 1000
	popTxsPer100Seconds := 4
	expectedPopTxs := popTxsPer100Seconds * (seconds / 100)

	t.Logf("expecting at least %d pop txs mined", expectedPopTxs)

	const maxRetries = 5
	const retryAfterSeconds = 30
	var lastErr error

	for i := range maxRetries {
		lastErr = nil

		t.Logf("retry %d/%d, lastErr = %v", i, maxRetries, lastErr)

		if i != 0 {
			output := monitor(uint(retryAfterSeconds * 1000))

			t.Log(output)

			if err := json.Unmarshal([]byte(output), &jo); err != nil {
				t.Fatal(err)
			}
		}

		if jo.PopTxCount < uint64(expectedPopTxs) {
			lastErr = fmt.Errorf("popTxCount %d < %d", jo.PopTxCount, expectedPopTxs)
			continue
		}

		// the expected balance should be at least 1 BaseHEMI per poptx - 8.  We say
		// "- 8" because we lag 8 keystones behind a pop payout (200 L2 blocks at
		// 1 block per second)
		popMinerBalance := big.NewInt(0)
		balance, ok := popMinerBalance.SetString(jo.PopMinerHemiBalance, 10)
		if !ok {
			lastErr = fmt.Errorf("could not parse balance from %s", jo.PopMinerHemiBalance)
			continue
		}

		expectedPayouts := expectedPopTxs - 8
		expectedPayoutBalance := big.NewInt(hemi.HEMIBase)
		expectedPayoutBalance = expectedPayoutBalance.Mul(big.NewInt(int64(expectedPayouts)), expectedPayoutBalance)

		t.Logf("expecting actual balance %d to be greater than %d", balance, expectedPayoutBalance)

		if expectedPayoutBalance.Cmp(balance) > 0 {
			lastErr = fmt.Errorf("pop miner payout balance received %d, want at least %d", balance, expectedPayoutBalance)
			continue
		}

		break
	}

}
