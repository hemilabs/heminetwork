// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"crypto/rand"
	"crypto/sha256"
	"strconv"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"
	"github.com/phayes/freeport"

	"github.com/hemilabs/heminetwork/v2/hemi"
)

// MakeSharedKeystones creates a matching map and slice of N keystones.
func MakeSharedKeystones(n int) (map[chainhash.Hash]*hemi.L2KeystoneAbrev, []hemi.L2Keystone) {
	kssList := make([]hemi.L2Keystone, 0, n)
	kssMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	prevKeystone := &hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      10000,
		L2BlockNumber:      25,
		PrevKeystoneEPHash: SHA256([]byte{0, 0}),
		EPHash:             SHA256([]byte{0}),
	}
	for ci := range n {
		x := uint8(ci + 1)
		l2Keystone := hemi.L2Keystone{
			Version:            1,
			L1BlockNumber:      prevKeystone.L1BlockNumber + 1,
			L2BlockNumber:      uint32(ci+1) * 25,
			ParentEPHash:       SHA256([]byte{x, x}),
			PrevKeystoneEPHash: prevKeystone.EPHash,
			StateRoot:          SHA256([]byte{x, x, x}),
			EPHash:             SHA256([]byte{x}),
		}

		abrevKss := hemi.L2KeystoneAbbreviate(l2Keystone)
		kssMap[*abrevKss.Hash()] = abrevKss
		kssList = append(kssList, l2Keystone)
		prevKeystone = &l2Keystone
	}

	return kssMap, kssList
}

func SHA256(x []byte) []byte {
	xx := sha256.Sum256(x)
	return xx[:]
}

// FillBytes returns a byte slice with a length of n, containing the prefix and
// remaining bytes filled with underscores.
func FillBytes(prefix string, n int) []byte {
	if n < 0 {
		n = 0
	}
	if len(prefix) > n {
		prefix = prefix[:n]
	}

	result := make([]byte, n)
	copy(result, prefix)
	for i := len(prefix); i < len(result); i++ {
		result[i] = '_'
	}
	return result
}

// FillBytesZero returns a byte slice of length n containing only the prefix.
func FillBytesZero(prefix string, n int) []byte {
	if n < 0 {
		n = 0
	}
	if len(prefix) > n {
		prefix = prefix[:n]
	}

	result := make([]byte, n)
	copy(result, prefix)
	return result
}

// FreePort finds a port that is currently free.
// TODO: remove use of freeport library.
func FreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}
	return strconv.Itoa(port)
}

// RandomBytes returns a slice with cryptographically secure random bytes.
func RandomBytes(count int) []byte {
	b := make([]byte, count)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// ExecuteTX executes a bitcoin transaction script against a VM and optionally dumps steps.
// This consolidates the frequently used executeTX helper into testutil.
func ExecuteTX(t testing.TB, dump bool, scriptPubKey []byte, tx *btcutil.Tx) error {
	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures |
		txscript.ScriptStrictMultiSig | txscript.ScriptDiscourageUpgradableNops
	vm, err := txscript.NewEngine(scriptPubKey, tx.MsgTx(), 0, flags, nil, nil, -1, nil)
	if err != nil {
		return err
	}
	if dump {
		t.Logf("=== executing tx %v", tx.Hash())
	}
	for i := 0; ; i++ {
		d, err := vm.DisasmPC()
		if err != nil {
			return err
		}
		if dump {
			t.Logf("%v: %v", i, d)
		}
		done, err := vm.Step()
		if err != nil {
			return err
		}
		stack := vm.GetStack()
		if dump {
			t.Logf("%v: stack %v", i, spew.Sdump(stack))
		}
		if done {
			break
		}
	}
	err = vm.CheckErrorCondition(true)
	if err != nil {
		return err
	}

	if dump {
		t.Logf("=== SUCCESS tx %v", tx.Hash())
	}
	return nil
}
