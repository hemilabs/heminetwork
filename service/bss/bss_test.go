// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bss

import (
	"math/big"
	"slices"
	"testing"

	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/ethereum"
	"github.com/hemilabs/heminetwork/hemi"
)

func TestConvertPopTxsToPopPayouts(t *testing.T) {
	type testCaseDef struct {
		name               string
		popTxs             []bfgapi.PopTx
		expectedPopPayouts []bssapi.PopPayout
		extraSetup         func(*testCaseDef)
	}

	popMinerPublicKeyOne := []byte("popMinerPublicKeyOne")
	popMinerPublicKeyTwo := []byte("popMinerPublicKeyTwo")
	popMinerAddressOne := ethereum.PublicKeyToAddress(popMinerPublicKeyOne)
	popMinerAddressTwo := ethereum.PublicKeyToAddress(popMinerPublicKeyTwo)

	testTable := []testCaseDef{
		{
			name:               "convert empty poptxs",
			popTxs:             []bfgapi.PopTx{},
			expectedPopPayouts: []bssapi.PopPayout{},
		},
		{
			name: "convert no duplicate miner addresses",
			popTxs: []bfgapi.PopTx{
				{
					PopMinerPublicKey: popMinerPublicKeyOne,
				},
				{
					PopMinerPublicKey: popMinerPublicKeyTwo,
				},
			},
			expectedPopPayouts: []bssapi.PopPayout{
				{
					MinerAddress: popMinerAddressOne,
					Amount:       big.NewInt(hemi.HEMIBase),
				},
				{
					MinerAddress: popMinerAddressTwo,
					Amount:       big.NewInt(hemi.HEMIBase),
				},
			},
		},
		{
			name: "convert reduce duplicate miner addresses",
			popTxs: []bfgapi.PopTx{
				{
					PopMinerPublicKey: popMinerPublicKeyOne,
				},
				{
					PopMinerPublicKey: popMinerPublicKeyTwo,
				},
				{
					PopMinerPublicKey: popMinerPublicKeyOne,
				},
			},
			expectedPopPayouts: []bssapi.PopPayout{
				{
					MinerAddress: popMinerAddressOne,
					Amount:       big.NewInt(2 * hemi.HEMIBase),
				},
				{
					MinerAddress: popMinerAddressTwo,
					Amount:       big.NewInt(hemi.HEMIBase),
				},
			},
		},
		{
			name:   "convert reduce duplicate miner addresses large number",
			popTxs: []bfgapi.PopTx{},
			expectedPopPayouts: []bssapi.PopPayout{
				{
					MinerAddress: popMinerAddressOne,
					Amount:       big.NewInt(0).Mul(big.NewInt(1*hemi.HEMIBase), big.NewInt(360)),
				},
			},
			extraSetup: func(tcd *testCaseDef) {
				for range 360 {
					tcd.popTxs = append(tcd.popTxs, bfgapi.PopTx{
						PopMinerPublicKey: popMinerPublicKeyOne,
					})
				}
			},
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.extraSetup != nil {
				testCase.extraSetup(&testCase)
			}

			popPayouts := ConvertPopTxsToPopPayouts(testCase.popTxs)

			sortFn := func(a, b bssapi.PopPayout) int {
				// find first differing byte in miner addresses and sort by that,
				// this should lead to predictable ordering as
				// miner addresses are unique here

				var ab byte = 0
				var bb byte = 0

				for i := range len(a.MinerAddress) {
					ab = a.MinerAddress[i]
					bb = b.MinerAddress[i]
					if ab != bb {
						break
					}
				}

				if ab > bb {
					return -1
				}

				return 1
			}

			// sort to ensure expected order
			slices.SortFunc(popPayouts, sortFn)
			slices.SortFunc(testCase.expectedPopPayouts, sortFn)

			diff := deep.Equal(popPayouts, testCase.expectedPopPayouts)
			if len(diff) != 0 {
				t.Fatalf("unexpected diff %s", diff)
			}

			for i := range popPayouts {
				if popPayouts[i].Amount.Cmp(testCase.expectedPopPayouts[i].Amount) != 0 {
					t.Fatalf("amounts not equal: %v != %v", popPayouts[i].Amount, testCase.expectedPopPayouts[i].Amount)
				}
			}
		})
	}
}
