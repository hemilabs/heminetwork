// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/holiman/uint256"
)

var testChainID = big.NewInt(1337)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testBlob returns a blob that is filled with b.
func testBlob(b byte) *kzg4844.Blob {
	var blob kzg4844.Blob
	for i := range blob {
		blob[i] = b
	}
	return &blob
}

// testBlobTx returns the raw encoding of a signed blob transaction as it is
// submitted to a node, with a sidecar of the given version, and the versioned
// hashes of its blobs.
//
// The commitments and proofs are placeholders.  They are not looked at by
// fakebeacon, the L1 is what verifies them, and computing real ones is slow.
func testBlobTx(t *testing.T, version byte, blobs ...*kzg4844.Blob) ([]byte, []common.Hash) {
	t.Helper()

	var (
		sidecarBlobs []kzg4844.Blob
		commitments  []kzg4844.Commitment
		proofs       []kzg4844.Proof
	)
	for i, blob := range blobs {
		sidecarBlobs = append(sidecarBlobs, *blob)
		commitments = append(commitments, kzg4844.Commitment{byte(i), blob[0]})

		switch version {
		case types.BlobSidecarVersion0:
			proofs = append(proofs, kzg4844.Proof{byte(i)})
		case types.BlobSidecarVersion1:
			proofs = append(proofs, make([]kzg4844.Proof, kzg4844.CellProofsPerBlob)...)
		default:
			t.Fatalf("unknown sidecar version %d", version)
		}
	}
	sidecar := types.NewBlobTxSidecar(version, sidecarBlobs, commitments, proofs)

	tx, err := types.SignNewTx(testKey(t), types.LatestSignerForChainID(testChainID), &types.BlobTx{
		ChainID:    uint256.MustFromBig(testChainID),
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		Gas:        21000,
		To:         common.HexToAddress("0x00289c189bee4e70334629f04cd5ed602b6600eb"),
		BlobFeeCap: uint256.NewInt(1),
		BlobHashes: sidecar.BlobHashes(),
		Sidecar:    sidecar,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw, sidecar.BlobHashes()
}

func TestSidecarBlobs(t *testing.T) {
	blobs := []*kzg4844.Blob{testBlob(1), testBlob(2)}

	for _, version := range []byte{types.BlobSidecarVersion0, types.BlobSidecarVersion1} {
		t.Run(fmt.Sprintf("sidecar version %d", version), func(t *testing.T) {
			raw, hashes := testBlobTx(t, version, blobs...)

			got, err := sidecarBlobs(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(blobs) {
				t.Fatalf("got %d blobs, want %d", len(got), len(blobs))
			}
			for i, hash := range hashes {
				if !bytes.Equal(got[hash].blob, blobs[i][:]) {
					t.Fatalf("blob %d (%v) differs", i, hash)
				}
				if len(got[hash].commitment) != 48 {
					t.Fatalf("blob %d (%v) has a %d byte commitment", i, hash, len(got[hash].commitment))
				}
			}
		})
	}

	t.Run("blob transaction without sidecar", func(t *testing.T) {
		raw, _ := testBlobTx(t, types.BlobSidecarVersion0, blobs[0])
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		raw, err := tx.WithoutBlobTxSidecar().MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, err := sidecarBlobs(raw)
		if err != nil || got != nil {
			t.Fatalf("got %d blobs and error %v, want none", len(got), err)
		}
	})

	t.Run("not a blob transaction", func(t *testing.T) {
		tx, err := types.SignNewTx(testKey(t), types.LatestSignerForChainID(testChainID), &types.DynamicFeeTx{
			ChainID: testChainID,
			Gas:     21000,
			To:      &common.Address{1},
			Data:    []byte{1, 2, 3},
		})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range [][]byte{raw, nil} {
			got, err := sidecarBlobs(raw)
			if err != nil || got != nil {
				t.Fatalf("got %d blobs and error %v, want none", len(got), err)
			}
		}
	})

	t.Run("malformed blob transaction", func(t *testing.T) {
		if _, err := sidecarBlobs([]byte{types.BlobTxType, 0xc0}); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestRawTransactions(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "single",
			body: `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x0102"]}`,
			want: []string{"0x0102"},
		},
		{
			name: "batch",
			body: ` [{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x01"]},` +
				`{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]},` +
				`{"jsonrpc":"2.0","id":3,"method":"eth_sendRawTransaction","params":["0x02"]}]`,
			want: []string{"0x01", "0x02"},
		},
		{
			name: "other method",
			body: `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`,
		},
		{
			name: "no params",
			body: `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[]}`,
		},
		{
			name: "params are not hex",
			body: `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[12]}`,
		},
		{
			name: "not json",
			body: `hello`,
		},
		{
			name: "broken batch",
			body: `[{"jsonrpc":`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rawTransactions([]byte(tt.body))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d transactions, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if hexutil.Encode(got[i]) != tt.want[i] {
					t.Fatalf("transaction %d is %x, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestRPCProxy(t *testing.T) {
	var (
		mtx      sync.Mutex
		received []string
	)
	l1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		mtx.Lock()
		received = append(received, string(body))
		mtx.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xabcd"}`))
	}))
	defer l1.Close()

	l1URL, err := url.Parse(l1.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := newBlobStore()
	proxy := httptest.NewServer(newRPCProxy(l1URL, store))
	defer proxy.Close()

	raw, hashes := testBlobTx(t, types.BlobSidecarVersion1, testBlob(3))
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`,
		fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[%q]}`, hexutil.Encode(raw)),
		// a resubmission keeps one entry
		fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[%q]}`, hexutil.Encode(raw)),
		// the L1 decides what to do with a blob transaction that cannot be decoded
		`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x03c0"]}`,
	}
	for _, request := range requests {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxy.URL, strings.NewReader(request))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "0xabcd") {
			t.Fatalf("unexpected response %d: %s", resp.StatusCode, body)
		}
	}

	mtx.Lock()
	defer mtx.Unlock()
	if len(received) != len(requests) {
		t.Fatalf("l1 received %d requests, want %d", len(received), len(requests))
	}
	for i := range requests {
		if received[i] != requests[i] {
			t.Fatalf("l1 received a different request %d", i)
		}
	}

	if store.len() != 1 {
		t.Fatalf("%d blobs kept, want 1", store.len())
	}
	if blob, ok := store.get(hashes[0]); !ok || !bytes.Equal(blob.blob, testBlob(3)[:]) {
		t.Fatalf("blob %v was not kept", hashes[0])
	}
}

// testL1 is an L1 JSON-RPC server that only serves blocks.
type testL1 struct {
	blocks []l1Block
	fail   bool
}

func (l *testL1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string `json:"method"`
		Params []any  `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if l.fail {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"down"}}`))
		return
	}

	var result *l1Block
	switch number := req.Params[0].(string); number {
	case "latest":
		result = &l.blocks[len(l.blocks)-1]
	default:
		n, err := hexutil.DecodeUint64(number)
		if err == nil && n < uint64(len(l.blocks)) {
			result = &l.blocks[n]
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
}

func TestBeaconAPI(t *testing.T) {
	const genesisTime = 1000

	var (
		hashA = common.HexToHash("0x01aa")
		hashB = common.HexToHash("0x01bb")
		hashC = common.HexToHash("0x01cc") // not kept
		blobA = hexutil.Bytes{0xa}
		blobB = hexutil.Bytes{0xb}
	)

	// a block every 3 seconds, block 2 has blobs
	chain := &testL1{}
	for i := range 6 {
		chain.blocks = append(chain.blocks, l1Block{
			Number: hexutil.Uint64(i),
			Time:   hexutil.Uint64(genesisTime + 3*i),
		})
	}
	chain.blocks[2].Transactions = []struct {
		BlobVersionedHashes []common.Hash `json:"blobVersionedHashes"`
	}{
		{},
		{BlobVersionedHashes: []common.Hash{hashA}},
		{BlobVersionedHashes: []common.Hash{hashB}},
	}
	chain.blocks[4].Transactions = []struct {
		BlobVersionedHashes []common.Hash `json:"blobVersionedHashes"`
	}{
		{BlobVersionedHashes: []common.Hash{hashC}},
	}

	l1 := httptest.NewServer(chain)
	defer l1.Close()

	store := newBlobStore()
	store.put(hashA, keptBlob{blob: blobA, commitment: make(hexutil.Bytes, 48)})
	store.put(hashB, keptBlob{blob: blobB, commitment: append(hexutil.Bytes{0xcc}, make(hexutil.Bytes, 47)...)})

	l1c := &l1Client{url: l1.URL, client: l1.Client()}
	b := &beacon{l1: l1c, store: store}
	api := httptest.NewServer(b.handler())
	defer api.Close()
	legacy := &beacon{l1: l1c, store: store, legacy: true}
	legacyAPI := httptest.NewServer(legacy.handler())
	defer legacyAPI.Close()

	getFrom := func(base string, path string) (int, string) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, strings.TrimSpace(string(body))
	}
	get := func(path string) (int, string) { return getFrom(api.URL, path) }

	// the L1 is not reachable yet
	chain.fail = true
	for _, path := range []string{"/eth/v1/beacon/genesis", "/eth/v1/beacon/blobs/6"} {
		if status, body := get(path); status != http.StatusServiceUnavailable {
			t.Fatalf("GET %s: got %d %s, want %d", path, status, body, http.StatusServiceUnavailable)
		}
	}
	chain.fail = false

	tests := []struct {
		path   string
		status int
		body   string
	}{
		{"/eth/v1/node/version", http.StatusOK, `{"data":{"version":"` + version + `"}}`},
		{"/eth/v1/config/spec", http.StatusOK, `{"data":{"SECONDS_PER_SLOT":"1","SLOT_DURATION_MS":"1000"}}`},
		{"/eth/v1/beacon/genesis", http.StatusOK, `{"data":{"genesis_time":"1000"}}`},

		// block 2 is in slot 6
		{"/eth/v1/beacon/blobs/6", http.StatusOK, `{"data":["0x0a","0x0b"]}`},
		{"/eth/v1/beacon/blobs/6?versioned_hashes=" + hashB.Hex(), http.StatusOK, `{"data":["0x0b"]}`},
		{
			"/eth/v1/beacon/blobs/6?versioned_hashes=" + hashB.Hex() + "&versioned_hashes=" + hashA.Hex(),
			http.StatusOK, `{"data":["0x0a","0x0b"]}`,
		},
		{"/eth/v1/beacon/blobs/6?versioned_hashes=" + hashA.Hex() + "," + hashB.Hex(), http.StatusOK, `{"data":["0x0a","0x0b"]}`},
		// a blob that is not in the block
		{"/eth/v1/beacon/blobs/6?versioned_hashes=" + hashC.Hex(), http.StatusNotFound, ""},
		// blocks without blobs: the genesis block, the head block
		{"/eth/v1/beacon/blobs/0", http.StatusOK, `{"data":[]}`},
		{"/eth/v1/beacon/blobs/15", http.StatusOK, `{"data":[]}`},

		// slots without a block: between blocks, after the head
		{"/eth/v1/beacon/blobs/7", http.StatusNotFound, ""},
		{"/eth/v1/beacon/blobs/16", http.StatusNotFound, ""},
		// block 4 has a blob that was not submitted through the proxy
		{"/eth/v1/beacon/blobs/12", http.StatusNotFound, ""},

		{"/eth/v1/beacon/blobs/head", http.StatusBadRequest, ""},
		{"/eth/v1/beacon/blobs/6?versioned_hashes=0x01", http.StatusBadRequest, ""},
		{"/eth/v1/beacon/blob_sidecars/6", http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		status, body := get(tt.path)
		if status != tt.status {
			t.Fatalf("GET %s: got %d %s, want %d", tt.path, status, body, tt.status)
		}
		if tt.body != "" && body != tt.body {
			t.Fatalf("GET %s: got %s, want %s", tt.path, body, tt.body)
		}
		if tt.status != http.StatusOK {
			var beaconErr beaconError
			if err := json.Unmarshal([]byte(body), &beaconErr); err != nil || beaconErr.Code != tt.status {
				t.Fatalf("GET %s: unexpected error response %s (%v)", tt.path, body, err)
			}
		}
	}

	// the legacy beacon serves the same blobs as sidecars and only the new
	// spec key
	sidecarA := `{"index":"0","blob":"0x0a","kzg_commitment":"0x` + strings.Repeat("00", 48) + `","kzg_proof":"0x` + strings.Repeat("00", 48) + `"}`
	sidecarB := `{"index":"1","blob":"0x0b","kzg_commitment":"0xcc` + strings.Repeat("00", 47) + `","kzg_proof":"0x` + strings.Repeat("00", 48) + `"}`
	legacyTests := []struct {
		path   string
		status int
		body   string
	}{
		{"/eth/v1/config/spec", http.StatusOK, `{"data":{"SLOT_DURATION_MS":"1000"}}`},
		{"/eth/v1/beacon/blobs/6", http.StatusNotFound, ""},
		{"/eth/v1/beacon/blob_sidecars/6", http.StatusOK, `{"data":[` + sidecarA + `,` + sidecarB + `]}`},
		{"/eth/v1/beacon/blob_sidecars/6?indices=1", http.StatusOK, `{"data":[` + sidecarB + `]}`},
		{"/eth/v1/beacon/blob_sidecars/6?indices=1&indices=0", http.StatusOK, `{"data":[` + sidecarA + `,` + sidecarB + `]}`},
		{"/eth/v1/beacon/blob_sidecars/6?indices=0,1", http.StatusOK, `{"data":[` + sidecarA + `,` + sidecarB + `]}`},
		{"/eth/v1/beacon/blob_sidecars/6?indices=5", http.StatusOK, `{"data":[]}`},
		{"/eth/v1/beacon/blob_sidecars/6?indices=x", http.StatusBadRequest, ""},
		{"/eth/v1/beacon/blob_sidecars/0", http.StatusOK, `{"data":[]}`},
		{"/eth/v1/beacon/blob_sidecars/7", http.StatusNotFound, ""},
		{"/eth/v1/beacon/blob_sidecars/12", http.StatusNotFound, ""},
	}
	for _, tt := range legacyTests {
		status, body := getFrom(legacyAPI.URL, tt.path)
		if status != tt.status {
			t.Fatalf("legacy GET %s: got %d %s, want %d", tt.path, status, body, tt.status)
		}
		if tt.body != "" && body != tt.body {
			t.Fatalf("legacy GET %s: got %s, want %s", tt.path, body, tt.body)
		}
	}
}

func TestRun(t *testing.T) {
	// find free ports
	addresses := make([]string, 3)
	for i := range addresses {
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addresses[i] = listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("FAKEBEACON_BEACON_ADDRESS", addresses[0])
	t.Setenv("FAKEBEACON_RPC_ADDRESS", addresses[1])
	t.Setenv("FAKEBEACON_BEACON_LEGACY_ADDRESS", addresses[2])
	t.Setenv("FAKEBEACON_L1_RPC_URL", "http://127.0.0.1:1")

	ctx, cancel := context.WithCancel(t.Context())
	errC := make(chan error, 1)
	go func() {
		errC <- run(ctx)
	}()

	// the beacon api answers
	deadline := time.Now().Add(10 * time.Second)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addresses[0]+"/eth/v1/node/version", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("unexpected status %d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("beacon api did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// the addresses are taken now
	if err := run(ctx); err == nil {
		t.Fatal("expected an error listening on an address in use")
	}

	cancel()
	select {
	case err := <-errC:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}

	t.Setenv("FAKEBEACON_L1_RPC_URL", "http://bad url")
	if err := run(t.Context()); err == nil {
		t.Fatal("expected an error for a bad l1 rpc url")
	}
}
