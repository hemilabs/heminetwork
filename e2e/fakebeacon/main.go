// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Command fakebeacon stands in for an L1 consensus layer (beacon) node in the
// e2e localnet.
//
// The localnet L1 is a single geth node running in --dev mode.  There is no
// consensus layer node, so nothing keeps the blobs of blob transactions once
// they are included in a block and op-node has nowhere to fetch them from.
// This prevents op-batcher from being run the way it is run in production,
// with blob data availability.
//
// fakebeacon fills that gap with two HTTP servers:
//
//   - An L1 JSON-RPC reverse proxy.  Every request is forwarded to the L1
//     unchanged, but the blobs of blob transactions submitted through it with
//     eth_sendRawTransaction are kept.  op-batcher is pointed at this proxy.
//   - The few Beacon API endpoints used by op-node, which serve the kept
//     blobs of an L1 block.  The op-nodes use this as their L1 beacon
//     endpoint.
//
// The beacon chain it pretends to be has one second slots and the genesis
// time of the L1 execution chain, so the slot of an L1 block is its timestamp
// minus the L1 genesis timestamp.
//
// This is test infrastructure, it must never be used outside of the localnet.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	// maxRequestSize bounds the size of a proxied JSON-RPC request.  A blob
	// transaction carrying the maximum number of blobs is a few megabytes
	// when hex encoded.
	maxRequestSize = 64 << 20

	// secondsPerSlot is the slot duration of the pretended beacon chain.
	// With one second slots every L1 block has a slot of its own, whatever
	// the L1 block time is.
	secondsPerSlot = 1

	version = "hemi-localnet-fakebeacon/1.0.0"

	requestTimeout = 10 * time.Second
)

// blobStore keeps blobs by their versioned hash.
type blobStore struct {
	mtx   sync.RWMutex
	blobs map[common.Hash]hexutil.Bytes
}

func newBlobStore() *blobStore {
	return &blobStore{blobs: make(map[common.Hash]hexutil.Bytes)}
}

func (s *blobStore) put(hash common.Hash, blob []byte) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.blobs[hash] = blob
}

func (s *blobStore) get(hash common.Hash) (hexutil.Bytes, bool) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	blob, ok := s.blobs[hash]
	return blob, ok
}

func (s *blobStore) len() int {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return len(s.blobs)
}

// sidecarBlobs returns the blobs carried by a raw transaction as submitted
// with eth_sendRawTransaction, by versioned hash.  It returns nothing if the
// transaction is not a blob transaction with a sidecar.
func sidecarBlobs(raw []byte) (map[common.Hash][]byte, error) {
	if len(raw) == 0 || raw[0] != types.BlobTxType {
		return nil, nil
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("decode blob transaction: %w", err)
	}
	sidecar := tx.BlobTxSidecar()
	if sidecar == nil {
		return nil, nil
	}
	hashes := sidecar.BlobHashes()
	if len(hashes) != len(sidecar.Blobs) {
		return nil, fmt.Errorf("blob transaction %v has %d blobs but %d commitments",
			tx.Hash(), len(sidecar.Blobs), len(hashes))
	}
	blobs := make(map[common.Hash][]byte, len(hashes))
	for i, hash := range hashes {
		blobs[hash] = bytes.Clone(sidecar.Blobs[i][:])
	}
	return blobs, nil
}

// rpcRequest is the part of a JSON-RPC request that is looked at.
type rpcRequest struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// rawTransactions returns the raw transactions submitted by a JSON-RPC
// request body, which is either a single request or a batch of requests.
func rawTransactions(body []byte) [][]byte {
	var reqs []rpcRequest
	if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(body, &reqs); err != nil {
			return nil
		}
	} else {
		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return nil
		}
		reqs = []rpcRequest{req}
	}

	var txs [][]byte
	for _, req := range reqs {
		if req.Method != "eth_sendRawTransaction" || len(req.Params) == 0 {
			continue
		}
		var raw hexutil.Bytes
		if err := json.Unmarshal(req.Params[0], &raw); err != nil {
			continue
		}
		txs = append(txs, raw)
	}
	return txs
}

// newRPCProxy returns a handler that forwards JSON-RPC requests to the L1 and
// keeps the blobs of the blob transactions submitted through it.
func newRPCProxy(l1 *url.URL, store *blobStore) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(l1)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestSize))
		if err != nil {
			http.Error(w, "read request: "+err.Error(), http.StatusBadRequest)
			return
		}
		for _, raw := range rawTransactions(body) {
			blobs, err := sidecarBlobs(raw)
			if err != nil {
				// Forward it anyway, the L1 decides what is valid.
				log.Printf("not keeping blobs: %v", err)
				continue
			}
			for hash, blob := range blobs {
				store.put(hash, blob)
				log.Printf("keeping blob %v (%d kept)", hash, store.len())
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
	})
}

// l1Block is the part of an L1 block that is looked at.
type l1Block struct {
	Number       hexutil.Uint64 `json:"number"`
	Time         hexutil.Uint64 `json:"timestamp"`
	Transactions []struct {
		BlobVersionedHashes []common.Hash `json:"blobVersionedHashes"`
	} `json:"transactions"`
}

// l1Client is a minimal L1 JSON-RPC client.
type l1Client struct {
	url    string
	client *http.Client
}

// blockByNumber returns the L1 block with the given number, which may be a
// block tag.  It returns nil if there is no such block.
func (c *l1Client) blockByNumber(ctx context.Context, number string) (*l1Block, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_getBlockByNumber",
		"params":  []any{number, true},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rpcResp struct {
		Result *l1Block `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("l1 rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

// blockByTime returns the L1 block with exactly the given timestamp.  It
// returns nil if there is no such block, like for a slot without a block.
func (c *l1Client) blockByTime(ctx context.Context, timestamp uint64) (*l1Block, error) {
	head, err := c.blockByNumber(ctx, "latest")
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, errors.New("l1 has no head block")
	}
	if timestamp > uint64(head.Time) {
		return nil, nil
	}
	if timestamp == uint64(head.Time) {
		return head, nil
	}

	// Block timestamps strictly increase, binary search for the first block
	// with a timestamp that is not before the requested one.
	lo, hi := uint64(0), uint64(head.Number)
	for lo < hi {
		mid := lo + (hi-lo)/2
		block, err := c.blockByNumber(ctx, hexutil.EncodeUint64(mid))
		if err != nil {
			return nil, err
		}
		if block == nil {
			return nil, fmt.Errorf("l1 block %d not found", mid)
		}
		if uint64(block.Time) < timestamp {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	block, err := c.blockByNumber(ctx, hexutil.EncodeUint64(lo))
	if err != nil {
		return nil, err
	}
	if block == nil || uint64(block.Time) != timestamp {
		return nil, nil
	}
	return block, nil
}

// beacon serves the Beacon API endpoints used by op-node.
type beacon struct {
	l1    *l1Client
	store *blobStore

	mtx         sync.Mutex
	genesisTime *uint64 // L1 genesis timestamp, once known
}

// beaconError is the Beacon API error response.
type beaconError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, beaconError{Code: status, Message: fmt.Sprintf(format, args...)})
}

// genesis returns the genesis time of the pretended beacon chain, which is
// the timestamp of the L1 genesis block.
func (b *beacon) genesis(ctx context.Context) (uint64, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	if b.genesisTime != nil {
		return *b.genesisTime, nil
	}
	block, err := b.l1.blockByNumber(ctx, "0x0")
	if err != nil {
		return 0, fmt.Errorf("fetch l1 genesis block: %w", err)
	}
	if block == nil {
		return 0, errors.New("l1 genesis block not found")
	}
	t := uint64(block.Time)
	b.genesisTime = &t
	return t, nil
}

func (b *beacon) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]string{"version": version},
	})
}

func (b *beacon) handleSpec(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]string{"SECONDS_PER_SLOT": strconv.Itoa(secondsPerSlot)},
	})
}

func (b *beacon) handleGenesis(w http.ResponseWriter, r *http.Request) {
	genesisTime, err := b.genesis(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]string{"genesis_time": strconv.FormatUint(genesisTime, 10)},
	})
}

// handleBlobs serves GET /eth/v1/beacon/blobs/{block_id}: the blobs of the L1
// block in a slot, in the order they appear in the block.  Only numeric block
// ids (slots) are supported.  If versioned_hashes is given, only those blobs
// are returned.
func (b *beacon) handleBlobs(w http.ResponseWriter, r *http.Request) {
	slot, err := strconv.ParseUint(r.PathValue("block_id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unsupported block id %q, must be a slot",
			r.PathValue("block_id"))
		return
	}

	wanted := make(map[common.Hash]struct{})
	for _, values := range r.URL.Query()["versioned_hashes"] {
		for _, value := range strings.Split(values, ",") {
			raw, err := hexutil.Decode(value)
			if err != nil || len(raw) != common.HashLength {
				writeError(w, http.StatusBadRequest, "invalid versioned hash %q", value)
				return
			}
			wanted[common.BytesToHash(raw)] = struct{}{}
		}
	}

	genesisTime, err := b.genesis(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "%v", err)
		return
	}
	block, err := b.l1.blockByTime(r.Context(), genesisTime+slot*secondsPerSlot)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "find l1 block of slot %d: %v", slot, err)
		return
	}
	if block == nil {
		writeError(w, http.StatusNotFound, "no block in slot %d", slot)
		return
	}

	blobs := make([]hexutil.Bytes, 0)
	for _, tx := range block.Transactions {
		for _, hash := range tx.BlobVersionedHashes {
			if _, ok := wanted[hash]; len(wanted) > 0 && !ok {
				continue
			}
			blob, ok := b.store.get(hash)
			if !ok {
				// The transaction was not submitted through the proxy.
				writeError(w, http.StatusNotFound,
					"blob %v of l1 block %d (slot %d) is not known", hash, block.Number, slot)
				return
			}
			blobs = append(blobs, blob)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": blobs})
}

// handleBlobSidecars answers the endpoint that was deprecated in favour of
// handleBlobs.  op-node only falls back to it when fetching blobs failed.
func (b *beacon) handleBlobSidecars(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "blob sidecars are not served, use /eth/v1/beacon/blobs")
}

func (b *beacon) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /eth/v1/node/version", b.handleVersion)
	mux.HandleFunc("GET /eth/v1/config/spec", b.handleSpec)
	mux.HandleFunc("GET /eth/v1/beacon/genesis", b.handleGenesis)
	mux.HandleFunc("GET /eth/v1/beacon/blobs/{block_id}", b.handleBlobs)
	mux.HandleFunc("GET /eth/v1/beacon/blob_sidecars/{block_id}", b.handleBlobSidecars)
	return mux
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func run(ctx context.Context) error {
	var (
		l1RPCURL      = envOr("FAKEBEACON_L1_RPC_URL", "http://localhost:8545")
		beaconAddress = envOr("FAKEBEACON_BEACON_ADDRESS", ":5052")
		rpcAddress    = envOr("FAKEBEACON_RPC_ADDRESS", ":8545")
	)

	l1URL, err := url.Parse(l1RPCURL)
	if err != nil {
		return fmt.Errorf("parse l1 rpc url: %w", err)
	}

	store := newBlobStore()
	b := &beacon{
		l1:    &l1Client{url: l1RPCURL, client: &http.Client{Timeout: requestTimeout}},
		store: store,
	}

	servers := map[string]*http.Server{
		"beacon api":   {Addr: beaconAddress, Handler: b.handler(), ReadHeaderTimeout: requestTimeout},
		"l1 rpc proxy": {Addr: rpcAddress, Handler: newRPCProxy(l1URL, store), ReadHeaderTimeout: requestTimeout},
	}

	errC := make(chan error, len(servers))
	for name, server := range servers {
		listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", server.Addr)
		if err != nil {
			return fmt.Errorf("listen for %s: %w", name, err)
		}
		log.Printf("%s listening on %v (l1 rpc: %s)", name, listener.Addr(), l1RPCURL)
		go func() {
			if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				errC <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	select {
	case err := <-errC:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
	defer cancel()
	for name, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown %s: %v", name, err)
		}
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatalf("fakebeacon: %v", err)
	}
}
