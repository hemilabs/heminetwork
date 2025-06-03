// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"crypto/sha256"
	"strconv"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/phayes/freeport"

	"github.com/hemilabs/heminetwork/hemi"
)

// MakeSharedKeystones a matching map and slice of N keystones
func MakeSharedKeystones(n int) (map[chainhash.Hash]*hemi.L2KeystoneAbrev, []hemi.L2Keystone) {
	kssList := make([]hemi.L2Keystone, 0, n)
	kssMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	prevKeystone := &hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      10000,
		L2BlockNumber:      25,
		PrevKeystoneEPHash: Digest256([]byte{0, 0}),
		EPHash:             Digest256([]byte{0}),
	}
	for ci := range n {
		x := uint8(ci + 1)
		l2Keystone := hemi.L2Keystone{
			Version:            1,
			L1BlockNumber:      prevKeystone.L1BlockNumber + 1,
			L2BlockNumber:      uint32(ci+1) * 25,
			ParentEPHash:       Digest256([]byte{x, x}),
			PrevKeystoneEPHash: prevKeystone.EPHash,
			StateRoot:          Digest256([]byte{x, x, x}),
			EPHash:             Digest256([]byte{x}),
		}

		abrevKss := hemi.L2KeystoneAbbreviate(l2Keystone)
		kssMap[*abrevKss.Hash()] = abrevKss
		kssList = append(kssList, l2Keystone)
		prevKeystone = &l2Keystone
	}

	return kssMap, kssList
}

func Digest256(x []byte) []byte {
	xx := sha256.Sum256(x)
	return xx[:]
}

// FillOutBytes will take a string and return a slice of bytes
// with values from the string suffixed until a size with bytes '_'
func FillOutBytes(prefix string, size int) []byte {
	result := []byte(prefix)
	for len(result) < size {
		result = append(result, '_')
	}

	return result
}

// FillOutBytesWith0s will take a string and return a slice of bytes
// with values from the string suffixed until a size with bytes '0'
func FillOutBytesWith0s(prefix string, size int) []byte {
	result := []byte(prefix)
	for len(result) < size {
		result = append(result, 0)
	}

	return result
}

// GetFreePort finds a port that is currently free.
func GetFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}
	return strconv.Itoa(port)
}
