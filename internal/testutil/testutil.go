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
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

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

// String2Hash converts a string into a hash. If the provided string is
// smaller than the expected size for a hash, the hash will be padded
// with zeros.
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

// SkipIfNoDocker skips tests when the proper flag is not set.
func SkipIfNoDocker(t *testing.T) {
	envValue := os.Getenv("HEMI_DOCKER_TESTS")
	val, err := strconv.ParseBool(envValue)
	if envValue != "" && err != nil {
		t.Fatal(err)
	}

	if !val {
		t.Skip("skipping docker tests")
	}
}

type StdoutLogConsumer struct {
	Name string // name of service
}

func (t *StdoutLogConsumer) Accept(l testcontainers.Log) {
	fmt.Printf("%s: %s", t.Name, string(l.Content))
}

// CreateBitcoind starts a new bitcoind container using testcontainers.
func CreateBitcoind(ctx context.Context) testcontainers.Container {
	id := hex.EncodeToString(RandomBytes(6))

	name := "bitcoind-" + id
	req := testcontainers.ContainerRequest{
		Image:        "kylemanna/bitcoind",
		Cmd:          []string{"bitcoind", "-regtest=1", "-debug=1", "-rpcallowip=0.0.0.0/0", "-rpcbind=0.0.0.0:18443", "-txindex=1", "-noonion", "-listenonion=0", "-fallbackfee=0.01", "-peerbloomfilters=1", "-debug"},
		ExposedPorts: []string{"18443", "18444"},
		WaitingFor:   wait.ForLog("dnsseed thread exit").WithPollInterval(1 * time.Second),
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{
				&StdoutLogConsumer{
					Name: name,
				},
			},
		},
		Name: name,
	}

	bitcoindContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	return bitcoindContainer
}

// RunBitcoindCommand executes a bitcoind command.
func RunBitcoindCommand(ctx context.Context, bitcoindContainer testcontainers.Container, cmd []string) (string, error) {
	exitCode, result, err := bitcoindContainer.Exec(ctx, cmd)
	if err != nil {
		return "", err
	}

	buf := new(strings.Builder)
	_, err = io.Copy(buf, result)
	if err != nil {
		return "", err
	}

	if exitCode != 0 {
		return "", fmt.Errorf("error code received: %d", exitCode)
	}

	if len(buf.String()) == 0 {
		return "", nil
	}

	// first 8 bytes are header, there is also a newline character at the end of the response
	return buf.String()[8 : len(buf.String())-1], nil
}
