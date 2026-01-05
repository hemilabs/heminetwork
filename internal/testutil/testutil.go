// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

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

// MessageListener waits until a set number of messages of specific types
// have been received on the message channel. It exits early if an error is
// received on the error channel, or the test context is cancelled.
func MessageListener(t *testing.T, expected map[string]int, errCh chan error, msgCh chan string) error {
	for {
		select {
		case err := <-errCh:
			return err
		case n := <-msgCh:
			expected[n]--
		case <-t.Context().Done():
			return t.Context().Err()
		}
		finished := true
		for v, k := range expected {
			if k > 0 {
				t.Logf("missing %d messages of type %s", k, v)
				finished = false
			}
		}
		if finished {
			return nil
		}
	}
}

// SHA256 returns the SHA256 checksum of the provided byte slice.
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
func FreePort(ctx context.Context) string {
	lc := net.ListenConfig{}
	l, err := lc.Listen(ctx, "tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// RandomBytes returns a random byte slice of size n.
func RandomBytes(count int) []byte {
	b := make([]byte, count)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// RandomHash returns a random hash.
func RandomHash() *chainhash.Hash {
	b := RandomBytes(len(chainhash.Hash{}))
	h, err := chainhash.NewHash(b)
	if err != nil {
		panic(err)
	}
	return h
}

// String2Hash converts a string into a hash.
func String2Hash(s string) *chainhash.Hash {
	h, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return h
}

// Bytes2Hash converts a byte slice into a hash.
func Bytes2Hash(b []byte) *chainhash.Hash {
	h, err := chainhash.NewHash(b)
	if err != nil {
		panic(err)
	}
	return h
}

// DecodeHex returns the bytes represented by a hexadecimal string.
func DecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ErrorIsOneOf verifies if err is one of the provided error types.
func ErrorIsOneOf(err error, errs []error) bool {
	for _, v := range errs {
		if errors.Is(err, v) {
			return true
		}
	}
	return false
}
