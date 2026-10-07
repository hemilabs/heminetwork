// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

// Tests that the Hemi stack keeps working while the L1 it settles on migrates
// to Glamsterdam.
//
// The localnet L1 starts on Osaka and activates Glamsterdam (the Amsterdam
// execution layer fork) a few minutes after its genesis, see
// L1_AMSTERDAM_OFFSET_SECONDS in e2e/genesisl2.sh.  The L2 does not activate
// Glamsterdam, it only has to keep following the L1: the op-nodes have to
// keep recognising L1 blocks (their hash covers two new header fields from
// the first Glamsterdam block on), op-batcher and op-proposer have to keep
// getting their transactions included under the new L1 gas rules, and all of
// this without the L2 itself changing.
//
// The EIPNNNN_ functions in the eipNNNN_test.go files only show that the L1
// has Glamsterdam active.  The tests in this file check the Hemi side.
//
// The L1 is always read as raw JSON here.  The go-ethereum types vendored by
// this module predate Glamsterdam, and what the L1 node itself reports is
// what the Hemi stack is compared against.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	// glamsterdamL1RPC is the localnet L1, geth-l1.
	glamsterdamL1RPC = "http://localhost:8545"

	// l1BlockPredeploy is the L2 contract that holds the attributes of the
	// L1 origin of an L2 block.
	l1BlockPredeploy = "0x4200000000000000000000000000000000000015"
)

// opStackNode is one of the op-node and L2 execution client pairs of the
// localnet.
type opStackNode struct {
	// name is the docker compose service of the op-node.
	name string

	rollupRPC string
	l2RPC     string

	// runsFromL1Genesis is true for the op-nodes that are started together
	// with the L1.  They are running when the L1 activates Glamsterdam and
	// have to follow it across the fork.  The others are started later and
	// sync across the fork from the L2 genesis.
	runsFromL1Genesis bool

	// derivesFromL1Genesis is true for the op-nodes that derive the whole
	// L2 from the L1.  The other one starts with the L2 that its execution
	// client synced from its peers.
	derivesFromL1Genesis bool
}

func (n opStackNode) container() string {
	return "e2e-" + n.name + "-1"
}

var opStackNodes = []opStackNode{
	{
		name: "op-node", rollupRPC: "http://localhost:8548", l2RPC: "http://localhost:8546",
		runsFromL1Genesis: true, derivesFromL1Genesis: true,
	},
	{
		name: "op-node-non-sequencing", rollupRPC: "http://localhost:18548", l2RPC: "http://localhost:18546",
		runsFromL1Genesis: true, derivesFromL1Genesis: true,
	},
	{
		name: "op-node-non-sequencing-snap-sync", rollupRPC: "http://localhost:28548", l2RPC: "http://localhost:28546",
	},
	{
		name: "op-node-non-sequencing-full-sync", rollupRPC: "http://localhost:38548", l2RPC: "http://localhost:38546",
		derivesFromL1Genesis: true,
	},
}

func dialRPC(t *testing.T, ctx context.Context, url string) *rpc.Client {
	t.Helper()

	c, err := rpc.DialContext(ctx, url)
	if err != nil {
		t.Fatalf("could not dial %s: %v", url, err)
	}
	t.Cleanup(c.Close)
	return c
}

// ---- L1 as raw JSON --------------------------------------------------------

type l1Header struct {
	Number     hexutil.Uint64 `json:"number"`
	Hash       common.Hash    `json:"hash"`
	ParentHash common.Hash    `json:"parentHash"`
	Time       hexutil.Uint64 `json:"timestamp"`
	BaseFee    *hexutil.Big   `json:"baseFeePerGas"`

	// added to the header by Glamsterdam (EIP-7928 and EIP-7843)
	BlockAccessListHash *common.Hash    `json:"blockAccessListHash"`
	SlotNumber          *hexutil.Uint64 `json:"slotNumber"`
}

// glamsterdam returns true if the header has the fields added by Glamsterdam.
func (h *l1Header) glamsterdam() (bool, error) {
	switch {
	case h.BlockAccessListHash != nil && h.SlotNumber != nil:
		return true, nil
	case h.BlockAccessListHash == nil && h.SlotNumber == nil:
		return false, nil
	default:
		return false, fmt.Errorf("l1 block %d has only one of blockAccessListHash (%v) and slotNumber (%v)",
			h.Number, h.BlockAccessListHash, h.SlotNumber)
	}
}

// l1HeaderByTag returns the header of an L1 block by number or block tag.
func l1HeaderByTag(ctx context.Context, l1 *rpc.Client, block string) (*l1Header, error) {
	var h *l1Header
	if err := l1.CallContext(ctx, &h, "eth_getBlockByNumber", block, false); err != nil {
		return nil, fmt.Errorf("fetch l1 block %s: %w", block, err)
	}
	if h == nil {
		return nil, fmt.Errorf("l1 block %s not found", block)
	}
	return h, nil
}

func l1HeaderByNumber(ctx context.Context, l1 *rpc.Client, number uint64) (*l1Header, error) {
	return l1HeaderByTag(ctx, l1, hexutil.EncodeUint64(number))
}

func mustL1Header(t *testing.T, ctx context.Context, l1 *rpc.Client, number uint64) *l1Header {
	t.Helper()

	h, err := l1HeaderByNumber(ctx, l1, number)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// ---- the L1 fork -----------------------------------------------------------

// glamsterdamFork describes where the L1 activated Glamsterdam.
type glamsterdamFork struct {
	// amsterdamTime is the activation timestamp from the L1 genesis.
	amsterdamTime uint64

	// lastBefore is the last L1 block before Glamsterdam, first is the first
	// L1 block on Glamsterdam.
	lastBefore l1Header
	first      l1Header
}

var (
	glamsterdamForkMtx   sync.Mutex
	glamsterdamForkFound *glamsterdamFork
)

// l1AmsterdamTime returns the Glamsterdam activation timestamp from the L1
// genesis that e2e/genesisl2.sh wrote.
func l1AmsterdamTime(ctx context.Context) (uint64, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", "e2e-op-geth-l2-1",
		"jq", "-r", ".config.amsterdamTime", "/shared-dir/l1genesis.json")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("read amsterdamTime from the l1 genesis: %w", err)
	}
	s := strings.TrimSpace(string(out))
	if s == "" || s == "null" {
		return 0, errors.New("the l1 genesis does not schedule Glamsterdam (no amsterdamTime)")
	}
	amsterdamTime, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse amsterdamTime %q: %w", s, err)
	}
	return amsterdamTime, nil
}

// findL1GlamsterdamFork waits for the L1 to activate Glamsterdam and returns
// where it did.  It is an error if the L1 runs Glamsterdam from its genesis,
// the migration is what is tested here.
func findL1GlamsterdamFork(ctx context.Context, logf func(format string, args ...any)) (*glamsterdamFork, error) {
	l1, err := rpc.DialContext(ctx, glamsterdamL1RPC)
	if err != nil {
		return nil, fmt.Errorf("dial l1: %w", err)
	}
	defer l1.Close()

	amsterdamTime, err := l1AmsterdamTime(ctx)
	if err != nil {
		return nil, err
	}

	genesis, err := l1HeaderByNumber(ctx, l1, 0)
	if err != nil {
		return nil, err
	}
	if amsterdamTime <= uint64(genesis.Time) {
		return nil, fmt.Errorf("the l1 runs Glamsterdam from its genesis (amsterdamTime %d, genesis time %d), "+
			"the migration is not exercised; start the localnet with L1_AMSTERDAM_OFFSET_SECONDS > 0",
			amsterdamTime, genesis.Time)
	}

	// wait for the first block on Glamsterdam
	var head *l1Header
	for {
		head, err = l1HeaderByTag(ctx, l1, "latest")
		if err != nil {
			return nil, err
		}
		if uint64(head.Time) >= amsterdamTime {
			break
		}
		logf("waiting for the l1 to activate Glamsterdam in %d seconds (l1 head %d)",
			amsterdamTime-uint64(head.Time), head.Number)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("the l1 did not activate Glamsterdam: %w", ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}

	// block timestamps strictly increase, binary search for the first block
	// at or after the activation timestamp
	lo, hi := uint64(1), uint64(head.Number)
	for lo < hi {
		mid := lo + (hi-lo)/2
		h, err := l1HeaderByNumber(ctx, l1, mid)
		if err != nil {
			return nil, err
		}
		if uint64(h.Time) < amsterdamTime {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	first, err := l1HeaderByNumber(ctx, l1, lo)
	if err != nil {
		return nil, err
	}
	lastBefore, err := l1HeaderByNumber(ctx, l1, lo-1)
	if err != nil {
		return nil, err
	}

	return &glamsterdamFork{
		amsterdamTime: amsterdamTime,
		lastBefore:    *lastBefore,
		first:         *first,
	}, nil
}

// l1GlamsterdamFork waits for the L1 to activate Glamsterdam and returns
// where it did.
func l1GlamsterdamFork(t *testing.T, ctx context.Context) glamsterdamFork {
	t.Helper()

	glamsterdamForkMtx.Lock()
	defer glamsterdamForkMtx.Unlock()

	if glamsterdamForkFound == nil {
		fork, err := findL1GlamsterdamFork(ctx, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		glamsterdamForkFound = fork
	}
	return *glamsterdamForkFound
}

// ---- op-node ---------------------------------------------------------------

type opNodeL1Ref struct {
	Hash       common.Hash `json:"hash"`
	Number     uint64      `json:"number"`
	ParentHash common.Hash `json:"parentHash"`
	Time       uint64      `json:"timestamp"`
}

func (r opNodeL1Ref) String() string {
	return fmt.Sprintf("%s:%d", r.Hash, r.Number)
}

type opNodeL2Ref struct {
	Hash     common.Hash `json:"hash"`
	Number   uint64      `json:"number"`
	L1Origin struct {
		Hash   common.Hash `json:"hash"`
		Number uint64      `json:"number"`
	} `json:"l1origin"`
}

// opNodeSyncStatus is the part of the optimism_syncStatus response that is
// looked at.
type opNodeSyncStatus struct {
	CurrentL1   opNodeL1Ref `json:"current_l1"`
	HeadL1      opNodeL1Ref `json:"head_l1"`
	SafeL1      opNodeL1Ref `json:"safe_l1"`
	FinalizedL1 opNodeL1Ref `json:"finalized_l1"`
	UnsafeL2    opNodeL2Ref `json:"unsafe_l2"`
	SafeL2      opNodeL2Ref `json:"safe_l2"`
	FinalizedL2 opNodeL2Ref `json:"finalized_l2"`
}

func (s *opNodeSyncStatus) String() string {
	return fmt.Sprintf("l1 head %d, l1 current %d, l2 unsafe %d (l1 origin %d), l2 safe %d (l1 origin %d), l2 finalized %d (l1 origin %d)",
		s.HeadL1.Number, s.CurrentL1.Number,
		s.UnsafeL2.Number, s.UnsafeL2.L1Origin.Number,
		s.SafeL2.Number, s.SafeL2.L1Origin.Number,
		s.FinalizedL2.Number, s.FinalizedL2.L1Origin.Number)
}

// waitForSyncStatus polls the sync status of an op-node until done returns
// true.  The op-node may be unreachable for a while, it is retried until ctx
// is done.
func waitForSyncStatus(t *testing.T, ctx context.Context, rollup *rpc.Client, name string, what string, done func(s *opNodeSyncStatus) bool) *opNodeSyncStatus {
	t.Helper()

	var (
		last    *opNodeSyncStatus
		lastErr error
		logged  time.Time
	)
	for {
		var s *opNodeSyncStatus
		if err := rollup.CallContext(ctx, &s, "optimism_syncStatus"); err != nil {
			lastErr = err
		} else if s != nil {
			last, lastErr = s, nil
			if done(s) {
				t.Logf("%s: %s: %s", name, what, s)
				return s
			}
		}

		if time.Since(logged) > 20*time.Second {
			logged = time.Now()
			t.Logf("%s: waiting %s (%v, last error: %v)", name, what, last, lastErr)
		}

		select {
		case <-ctx.Done():
			t.Fatalf("%s: timed out waiting %s (%v, last error: %v)", name, what, last, lastErr)
		case <-time.After(2 * time.Second):
		}
	}
}

// checkOpNodeL1View ensures that every L1 block an op-node refers to is the
// block that the L1 itself has at that height.  A hash that differs from the
// L1's means that the op-node does not compute the hash of L1 blocks the way
// the L1 does.
//
// allLabels requires the safe and finalized L1 labels to be known too; they
// are not right after a start.
func checkOpNodeL1View(t *testing.T, ctx context.Context, l1 *rpc.Client, name string, s *opNodeSyncStatus, allLabels bool) {
	t.Helper()

	l1Refs := []struct {
		label    string
		ref      opNodeL1Ref
		required bool
	}{
		// head_l1 is fed by the L1 head subscription, the others by the
		// derivation pipeline and the L1 safe and finalized polling
		{"head_l1", s.HeadL1, true},
		{"current_l1", s.CurrentL1, true},
		{"safe_l1", s.SafeL1, allLabels},
		{"finalized_l1", s.FinalizedL1, allLabels},
	}
	for _, r := range l1Refs {
		if r.ref == (opNodeL1Ref{}) {
			if r.required {
				t.Errorf("%s: %s is not set", name, r.label)
			}
			continue
		}
		canonical := mustL1Header(t, ctx, l1, r.ref.Number)
		if canonical.Hash != r.ref.Hash {
			t.Errorf("%s: %s is %s but the l1 has %s at that height",
				name, r.label, r.ref, canonical.Hash)
		}
		if canonical.ParentHash != r.ref.ParentHash {
			t.Errorf("%s: %s %s has parent %s but on the l1 its parent is %s",
				name, r.label, r.ref, r.ref.ParentHash, canonical.ParentHash)
		}
		if uint64(canonical.Time) != r.ref.Time {
			t.Errorf("%s: %s %s has timestamp %d but on the l1 it has %d",
				name, r.label, r.ref, r.ref.Time, canonical.Time)
		}
	}

	l2Refs := []struct {
		label string
		ref   opNodeL2Ref
	}{
		{"unsafe_l2", s.UnsafeL2},
		{"safe_l2", s.SafeL2},
		{"finalized_l2", s.FinalizedL2},
	}
	for _, r := range l2Refs {
		if r.ref.Hash == (common.Hash{}) {
			// not known yet, like the finalized head right after a start
			continue
		}
		canonical := mustL1Header(t, ctx, l1, r.ref.L1Origin.Number)
		if canonical.Hash != r.ref.L1Origin.Hash {
			t.Errorf("%s: %s %d has l1 origin %s:%d but the l1 has %s at that height",
				name, r.label, r.ref.Number, r.ref.L1Origin.Hash, r.ref.L1Origin.Number, canonical.Hash)
		}
	}

	if t.Failed() {
		t.FailNow()
	}
}

// l2BlockHash returns the hash of an L2 block as the L2 execution client has
// it and ensures the header does not have the fields that Glamsterdam adds,
// the L2 does not activate Glamsterdam.
func l2BlockHash(t *testing.T, ctx context.Context, l2 *rpc.Client, name string, number uint64) common.Hash {
	t.Helper()

	var header map[string]json.RawMessage
	if err := l2.CallContext(ctx, &header, "eth_getBlockByNumber", hexutil.EncodeUint64(number), false); err != nil {
		t.Fatalf("%s: fetch l2 block %d: %v", name, number, err)
	}
	if header == nil {
		t.Fatalf("%s: l2 block %d not found", name, number)
	}
	for _, field := range []string{"blockAccessListHash", "slotNumber"} {
		if v, ok := header[field]; ok {
			t.Fatalf("%s: l2 block %d has the Glamsterdam header field %s (%s), the l2 must not activate Glamsterdam",
				name, number, field, v)
		}
	}
	var hash common.Hash
	if err := json.Unmarshal(header["hash"], &hash); err != nil {
		t.Fatalf("%s: l2 block %d: decode hash: %v", name, number, err)
	}
	return hash
}

// l1Attributes are the attributes of its L1 origin that an L2 block carries
// in its first transaction, the L1 attributes deposit.
type l1Attributes struct {
	number      uint64
	time        uint64
	baseFee     *big.Int
	blobBaseFee *big.Int
	hash        common.Hash
	batcherHash common.Hash
}

// l2L1Attributes returns the hash of an L2 block and the attributes of its
// L1 origin, taken from the block as the L2 execution client has it.
func l2L1Attributes(t *testing.T, ctx context.Context, l2 *rpc.Client, name string, number uint64) (common.Hash, l1Attributes) {
	t.Helper()

	var block *struct {
		Hash         common.Hash `json:"hash"`
		Transactions []struct {
			Type  hexutil.Uint64 `json:"type"`
			Input hexutil.Bytes  `json:"input"`
		} `json:"transactions"`
	}
	if err := l2.CallContext(ctx, &block, "eth_getBlockByNumber", hexutil.EncodeUint64(number), true); err != nil {
		t.Fatalf("%s: fetch l2 block %d: %v", name, number, err)
	}
	if block == nil {
		t.Fatalf("%s: l2 block %d not found", name, number)
	}
	if len(block.Transactions) == 0 || block.Transactions[0].Type != types.DepositTxType {
		t.Fatalf("%s: l2 block %d does not start with a deposit transaction", name, number)
	}

	// The calldata of setL1BlockValuesEcotone() and setL1BlockValuesIsthmus()
	// is packed: selector, base fee scalar (4 bytes), blob base fee scalar
	// (4), sequence number (8), timestamp (8), number (8), base fee (32),
	// blob base fee (32), hash (32), batcher hash (32).  Isthmus appends
	// the operator fee parameters.
	input := block.Transactions[0].Input
	const ecotoneLen = 4 + 4 + 4 + 8 + 8 + 8 + 32 + 32 + 32 + 32
	if len(input) < ecotoneLen {
		t.Fatalf("%s: l1 attributes of l2 block %d have %d bytes, expected at least %d",
			name, number, len(input), ecotoneLen)
	}
	switch selector := hexutil.Encode(input[:4]); selector {
	case "0x440a5e20", "0x098999be": // Ecotone, Isthmus
	default:
		t.Fatalf("%s: l1 attributes of l2 block %d have an unknown format (selector %s)", name, number, selector)
	}
	return block.Hash, l1Attributes{
		time:        new(big.Int).SetBytes(input[20:28]).Uint64(),
		number:      new(big.Int).SetBytes(input[28:36]).Uint64(),
		baseFee:     new(big.Int).SetBytes(input[36:68]),
		blobBaseFee: new(big.Int).SetBytes(input[68:100]),
		hash:        common.BytesToHash(input[100:132]),
		batcherHash: common.BytesToHash(input[132:164]),
	}
}

// checkL1AttributesOnL2 ensures that the attributes of its L1 origin that an
// L2 block carries are those of the L1 block, and returns them.
func checkL1AttributesOnL2(t *testing.T, ctx context.Context, l1 *rpc.Client, l2 *rpc.Client, name string, l2Number uint64) l1Attributes {
	t.Helper()

	_, attrs := l2L1Attributes(t, ctx, l2, name, l2Number)

	canonical := mustL1Header(t, ctx, l1, attrs.number)
	if attrs.hash != canonical.Hash {
		t.Fatalf("%s: l2 block %d has l1 origin %s:%d but the l1 has %s at that height",
			name, l2Number, attrs.hash, attrs.number, canonical.Hash)
	}
	if attrs.time != uint64(canonical.Time) {
		t.Fatalf("%s: l2 block %d has l1 origin timestamp %d but l1 block %d has %d",
			name, l2Number, attrs.time, canonical.Number, canonical.Time)
	}
	if canonical.BaseFee == nil || attrs.baseFee.Cmp(canonical.BaseFee.ToInt()) != 0 {
		t.Fatalf("%s: l2 block %d has l1 base fee %s but l1 block %d has %v",
			name, l2Number, attrs.baseFee, canonical.Number, canonical.BaseFee)
	}
	if want := common.BytesToHash(common.HexToAddress(batcherSenderAddress).Bytes()); attrs.batcherHash != want {
		t.Fatalf("%s: l2 block %d has batcher hash %s, expected %s", name, l2Number, attrs.batcherHash, want)
	}

	var feeHistory struct {
		BaseFeePerBlobGas []*hexutil.Big `json:"baseFeePerBlobGas"`
	}
	err := l1.CallContext(ctx, &feeHistory, "eth_feeHistory", "0x1", hexutil.EncodeUint64(attrs.number), []float64{})
	if err != nil {
		t.Fatalf("fetch l1 fee history of block %d: %v", attrs.number, err)
	}
	if len(feeHistory.BaseFeePerBlobGas) == 0 || feeHistory.BaseFeePerBlobGas[0] == nil {
		t.Fatalf("l1 fee history of block %d has no blob base fee", attrs.number)
	}
	if want := feeHistory.BaseFeePerBlobGas[0].ToInt(); attrs.blobBaseFee.Cmp(want) != 0 {
		t.Fatalf("%s: l2 block %d has l1 blob base fee %s but l1 block %d has %s",
			name, l2Number, attrs.blobBaseFee, canonical.Number, want)
	}
	return attrs
}

// checkL2AcrossForkBoundary finds the L2 blocks around the first one that has
// the first Glamsterdam L1 block as its L1 origin and ensures that they carry
// the attributes of the L1 blocks on both sides of the fork.  The L1 block
// hash in them is the first one the sequencer had to compute over the new
// header fields.
func checkL2AcrossForkBoundary(t *testing.T, ctx context.Context, l1 *rpc.Client, l2 *rpc.Client, name string, fork glamsterdamFork, l2Head uint64) {
	t.Helper()

	// L1 origins never decrease, binary search for the first L2 block with
	// an L1 origin on Glamsterdam
	forkNumber := uint64(fork.first.Number)
	lo, hi := uint64(1), l2Head
	for lo < hi {
		mid := lo + (hi-lo)/2
		if _, attrs := l2L1Attributes(t, ctx, l2, name, mid); attrs.number < forkNumber {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < 2 {
		t.Fatalf("%s: no l2 block has an l1 origin before Glamsterdam", name)
	}

	// The L1 origin advances by at most one L1 block per L2 block.  Look at
	// some L2 blocks on both sides, they cover the L1 blocks around the
	// fork.
	origins := make(map[uint64]struct{})
	for n := lo - min(lo-1, 12); n <= min(lo+12, l2Head); n++ {
		attrs := checkL1AttributesOnL2(t, ctx, l1, l2, name, n)
		origins[attrs.number] = struct{}{}
		switch {
		case n < lo && attrs.number >= forkNumber, n >= lo && attrs.number < forkNumber:
			t.Fatalf("%s: l2 block %d has l1 origin %d, the first l2 block on Glamsterdam l1 origins is %d",
				name, n, attrs.number, lo)
		case attrs.number == forkNumber && attrs.hash != fork.first.Hash:
			t.Fatalf("%s: l2 block %d has l1 origin %s for the first Glamsterdam l1 block %d %s",
				name, n, attrs.hash, forkNumber, fork.first.Hash)
		case attrs.number == forkNumber-1 && attrs.hash != fork.lastBefore.Hash:
			t.Fatalf("%s: l2 block %d has l1 origin %s for the last l1 block before Glamsterdam %d %s",
				name, n, attrs.hash, forkNumber-1, fork.lastBefore.Hash)
		}
	}
	for _, n := range []uint64{forkNumber - 1, forkNumber} {
		if _, ok := origins[n]; !ok {
			t.Fatalf("%s: no l2 block around l2 block %d has l1 block %d as its l1 origin", name, lo, n)
		}
	}
	t.Logf("%s: l2 block %d is the first with an l1 origin on Glamsterdam (l1 block %d), "+
		"the l2 blocks around it carry the attributes of the l1 blocks on both sides of the fork",
		name, lo, forkNumber)
}

// opNodeSafeHead is the response of optimism_safeHeadAtL1Block: the safe L2
// head that an op-node derived from the L1 up to an L1 block, and the L1
// block it derived that head from.
type opNodeSafeHead struct {
	L1Block struct {
		Hash   common.Hash `json:"hash"`
		Number uint64      `json:"number"`
	} `json:"l1Block"`
	SafeHead struct {
		Hash   common.Hash `json:"hash"`
		Number uint64      `json:"number"`
	} `json:"safeHead"`
}

// checkSafeHeadsAcrossFork ensures that an op-node derived safe L2 blocks
// from batches in L1 blocks before Glamsterdam and from batches in L1 blocks
// on Glamsterdam.
func checkSafeHeadsAcrossFork(t *testing.T, ctx context.Context, l1 *rpc.Client, l2 *rpc.Client, rollup *rpc.Client, name string, fork glamsterdamFork, status *opNodeSyncStatus) {
	t.Helper()

	check := func(what string, l1Number uint64) opNodeSafeHead {
		var safeHead *opNodeSafeHead
		err := rollup.CallContext(ctx, &safeHead, "optimism_safeHeadAtL1Block", hexutil.Uint64(l1Number))
		if err != nil || safeHead == nil {
			t.Fatalf("%s: no safe l2 head was derived from the l1 %s (up to l1 block %d): %v", name, what, l1Number, err)
		}
		if canonical := mustL1Header(t, ctx, l1, safeHead.L1Block.Number); canonical.Hash != safeHead.L1Block.Hash {
			t.Fatalf("%s: safe l2 head %d was derived from l1 block %s:%d but the l1 has %s at that height",
				name, safeHead.SafeHead.Number, safeHead.L1Block.Hash, safeHead.L1Block.Number, canonical.Hash)
		}
		if hash := l2BlockHash(t, ctx, l2, name, safeHead.SafeHead.Number); hash != safeHead.SafeHead.Hash {
			t.Fatalf("%s: safe l2 head %d derived from l1 block %d is %s but the execution client has %s",
				name, safeHead.SafeHead.Number, safeHead.L1Block.Number, safeHead.SafeHead.Hash, hash)
		}
		return *safeHead
	}

	forkNumber := uint64(fork.first.Number)

	before := check("before Glamsterdam", forkNumber-1)
	if before.SafeHead.Number == 0 {
		t.Fatalf("%s: no l2 block was derived from the l1 before Glamsterdam", name)
	}

	after := check("on Glamsterdam", status.CurrentL1.Number)
	if after.L1Block.Number < forkNumber {
		t.Fatalf("%s: the latest safe l2 head %d was derived from l1 block %d, before Glamsterdam (l1 block %d)",
			name, after.SafeHead.Number, after.L1Block.Number, forkNumber)
	}
	if after.SafeHead.Number <= before.SafeHead.Number {
		t.Fatalf("%s: the safe l2 head did not advance on Glamsterdam: %d derived from l1 block %d, %d from l1 block %d",
			name, before.SafeHead.Number, before.L1Block.Number, after.SafeHead.Number, after.L1Block.Number)
	}

	t.Logf("%s: derived safe l2 head %d from l1 block %d before Glamsterdam and safe l2 head %d from l1 block %d on Glamsterdam",
		name, before.SafeHead.Number, before.L1Block.Number, after.SafeHead.Number, after.L1Block.Number)
}

// evmHasGlamsterdam returns true if the EVM of a chain executes SLOTNUM
// (EIP-7843), an opcode that Glamsterdam adds.
func evmHasGlamsterdam(ctx context.Context, c *rpc.Client) (bool, error) {
	// SLOTNUM STOP, run as contract creation code
	var out hexutil.Bytes
	err := c.CallContext(ctx, &out, "eth_call", map[string]string{"data": "0x4b00"}, "latest")
	switch {
	case err == nil:
		return true, nil
	case strings.Contains(err.Error(), "invalid opcode"):
		return false, nil
	default:
		return false, err
	}
}

// ---- docker ----------------------------------------------------------------

func dockerOutput(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// checkContainerConfig ensures that an op-node container runs with the
// settings that make the tests meaningful: it must verify what the L1 RPC
// returns and keep its receipt validation.  These are the production
// settings, and the ones a previous version of the localnet did not use.
func checkContainerConfig(t *testing.T, ctx context.Context, container string) {
	t.Helper()

	out, err := dockerOutput(ctx, "inspect", "-f", "{{json .Config.Cmd}}", container)
	if err != nil {
		t.Fatal(err)
	}
	var cmd []string
	if err := json.Unmarshal([]byte(out), &cmd); err != nil {
		t.Fatalf("decode the command of %s: %v", container, err)
	}
	for _, arg := range cmd {
		for _, forbidden := range []string{"--l1.trustrpc", "--hemitrap.enabled"} {
			if arg == forbidden || strings.HasPrefix(arg, forbidden+"=") {
				t.Fatalf("%s runs with %s, the tests need op-node to verify the l1 the way it does in production", container, arg)
			}
		}
	}
}

// checkContainerNotRestarted ensures that docker did not restart a container
// because its service exited: a service that crashes and recovers after a
// restart would otherwise go unnoticed.  Restarts asked for by the tests do
// not count.
func checkContainerNotRestarted(t *testing.T, ctx context.Context, container string) {
	t.Helper()

	out, err := dockerOutput(ctx, "inspect", "-f", "{{.RestartCount}}", container)
	if err != nil {
		t.Fatal(err)
	}
	if out != "0" {
		t.Fatalf("%s exited and was restarted by docker %s times", container, out)
	}
}

func containerStartedAt(ctx context.Context, container string) (time.Time, error) {
	out, err := dockerOutput(ctx, "inspect", "-f", "{{.State.StartedAt}}", container)
	if err != nil {
		return time.Time{}, err
	}
	startedAt, err := time.Parse(time.RFC3339Nano, out)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse start time of %s: %w", container, err)
	}
	return startedAt, nil
}

// opStackLogProblems are log messages of the OP stack services that must not
// appear at all.
var opStackLogProblems = []string{
	// op-node computed the hash of an L1 block, or of the transactions or
	// withdrawals in it, and it is not what the L1 says
	"failed to verify block hash",
	"Computed block hash does not match",
	"failed to verify transactions list",
	"failed to verify withdrawals list",
	"failed to verify block from RPC",
	// same for the receipts of an L1 block
	"expected receipt root",
	"has invalid gas used metadata",
	"receipts but expected",
	// and for L1 contract storage read by op-node
	"failed to verify retrieved proof against state root",
	// op-node and the L2 execution client disagree about an L2 block
	"invalid block extraData",
	// a service crashed
	"panic:",
	"CRIT ",
	"Application failed",
}

// maxOpNodeReorgLogs is the most "possible L1 re-org" warnings an op-node may
// log in a run.  The localnet L1 does not reorg.  An op-node that computes a
// different hash than the L1 for every block logs it for every block.
const maxOpNodeReorgLogs = 8

// opNodeReorgLog matches the warning that op-node logs when a new L1 head is
// not the child of the previous L1 head it knows.
var opNodeReorgLog = regexp.MustCompile(`L1 head signal indicates a possible L1 re-org\s+old_l1_head=(\S+):(\d+)\s+new_l1_head_parent=(\S+)\s+new_l1_head=(\S+):(\d+)`)

// scanOpStackLogs looks for signs of the service in a container not
// understanding the L1 in its logs.  It returns the offending log lines.
func scanOpStackLogs(ctx context.Context, container string) ([]string, error) {
	pr, pw := io.Pipe()
	cmd := exec.CommandContext(ctx, "docker", "logs", container)
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("docker logs %s: %w", container, err)
	}
	go func() {
		pw.CloseWithError(cmd.Wait())
	}()

	const maxProblems = 20
	var (
		problems  []string
		lines     int
		reorgLogs int
	)
	add := func(reason string, line string) {
		if len(problems) < maxProblems {
			problems = append(problems, fmt.Sprintf("%s: %s", reason, strings.TrimSpace(line)))
		}
	}

	r := bufio.NewReaderSize(pr, 1<<20)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			lines++
			for _, problem := range opStackLogProblems {
				if strings.Contains(line, problem) {
					add("unexpected "+strconv.Quote(problem), line)
				}
			}
			if m := opNodeReorgLog.FindStringSubmatch(line); m != nil {
				// A new head that directly follows the previous head but
				// does not have its hash as parent hash means that op-node
				// computed a different hash for the previous head than the
				// one the L1 uses.  The localnet L1 does not reorg.
				oldNumber, _ := strconv.ParseUint(m[2], 10, 64)
				newNumber, _ := strconv.ParseUint(m[5], 10, 64)
				if newNumber == oldNumber+1 {
					add("l1 head hash mismatch", line)
				}
				if reorgLogs++; reorgLogs == maxOpNodeReorgLogs+1 {
					add(fmt.Sprintf("more than %d l1 re-org warnings", maxOpNodeReorgLogs), line)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("docker logs %s: %w", container, err)
		}
	}
	if lines == 0 {
		return nil, fmt.Errorf("docker logs %s: no log lines", container)
	}
	return problems, nil
}

// checkOpStackLogs fails the test if the logs of a container show that the
// service in it does not understand the L1.
func checkOpStackLogs(t *testing.T, ctx context.Context, container string) {
	t.Helper()

	problems, err := scanOpStackLogs(ctx, container)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("%s logged %d or more problems with the l1:\n%s",
			container, len(problems), strings.Join(problems, "\n"))
	}
	t.Logf("the logs of %s show no problems with the l1", container)
}

// ---- tests -----------------------------------------------------------------

// TestL1MigratesToGlamsterdam ensures that the L1 was started before
// Glamsterdam and activated it while running.  It is not run in parallel so
// that it completes before the other tests, which all need the L1 to be on
// Glamsterdam.
func TestL1MigratesToGlamsterdam(t *testing.T) {
	if testingFork() {
		t.Skip("only run against a fresh localnet")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()

	fork := l1GlamsterdamFork(t, ctx)
	l1 := dialRPC(t, ctx, glamsterdamL1RPC)

	t.Logf("l1 activated Glamsterdam at timestamp %d: last block before is %d (timestamp %d), first block on it is %d (timestamp %d)",
		fork.amsterdamTime, fork.lastBefore.Number, fork.lastBefore.Time, fork.first.Number, fork.first.Time)

	if fork.first.ParentHash != fork.lastBefore.Hash {
		t.Fatalf("l1 block %d is not the parent of l1 block %d", fork.lastBefore.Number, fork.first.Number)
	}

	// the header fields that Glamsterdam adds must appear exactly from the
	// first block at or after the activation timestamp
	head, err := l1HeaderByTag(ctx, l1, "latest")
	if err != nil {
		t.Fatal(err)
	}
	numbers := map[uint64]struct{}{0: {}, uint64(head.Number): {}}
	for i := uint64(0); i <= 16; i++ {
		if n := uint64(fork.first.Number) + i; n <= uint64(head.Number) {
			numbers[n] = struct{}{}
		}
		if n := uint64(fork.lastBefore.Number); n >= i {
			numbers[n-i] = struct{}{}
		}
	}
	for n := range numbers {
		h := mustL1Header(t, ctx, l1, n)
		got, err := h.glamsterdam()
		if err != nil {
			t.Fatal(err)
		}
		if want := n >= uint64(fork.first.Number); got != want {
			t.Fatalf("l1 block %d (timestamp %d): has Glamsterdam header fields: %v, expected %v",
				n, h.Time, got, want)
		}
	}
}

// TestOpNodesFollowL1AcrossGlamsterdam ensures that every op-node derives the
// L2 from L1 blocks before and after the L1 activated Glamsterdam, and that
// the L1 blocks it refers to are the blocks that the L1 has.
func TestOpNodesFollowL1AcrossGlamsterdam(t *testing.T) {
	if testingFork() {
		t.Skip("only run against a fresh localnet")
	}

	t.Parallel()

	for _, node := range opStackNodes {
		t.Run(node.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Minute)
			defer cancel()

			fork := l1GlamsterdamFork(t, ctx)
			forkNumber := uint64(fork.first.Number)

			l1 := dialRPC(t, ctx, glamsterdamL1RPC)
			rollup := dialRPC(t, ctx, node.rollupRPC)
			l2 := dialRPC(t, ctx, node.l2RPC)

			checkContainerConfig(t, ctx, node.container())

			startedAt, err := containerStartedAt(ctx, node.container())
			if err != nil {
				t.Fatal(err)
			}
			if node.runsFromL1Genesis {
				// it must have been running when the L1 migrated, or it
				// did not have to follow the L1 across the fork
				if uint64(startedAt.Unix()) >= fork.amsterdamTime {
					t.Fatalf("%s was (re)started at %s, after the l1 activated Glamsterdam at %s; "+
						"it was not running across the migration.  Use a fresh localnet, and a larger "+
						"L1_AMSTERDAM_OFFSET_SECONDS if it starts up slowly",
						node.container(), startedAt.UTC(), time.Unix(int64(fork.amsterdamTime), 0).UTC())
				}
				t.Logf("%s runs since %s, %d seconds before the l1 activated Glamsterdam",
					node.container(), startedAt.UTC(), int64(fork.amsterdamTime)-startedAt.Unix())
			} else {
				// started by the localnet once the first nodes had
				// finalized L2 blocks, usually after the fork
				t.Logf("%s runs since %s, %d seconds after the l1 activated Glamsterdam",
					node.container(), startedAt.UTC(), startedAt.Unix()-int64(fork.amsterdamTime))
			}

			// if it already logged that it does not understand the L1 there
			// is no point in waiting for it
			checkOpStackLogs(t, ctx, node.container())

			// The L1 origin of the finalized L2 head is on Glamsterdam once
			// the node derived L2 blocks from batches posted to Glamsterdam
			// L1 blocks, with L1 origins on Glamsterdam, and saw them
			// finalize on the L1.
			waitCtx, cancelWait := context.WithTimeout(ctx, 15*time.Minute)
			defer cancelWait()
			status := waitForSyncStatus(t, waitCtx, rollup, node.name,
				fmt.Sprintf("for it to finalize l2 blocks that have an l1 origin on Glamsterdam (l1 block %d and later)", forkNumber),
				func(s *opNodeSyncStatus) bool {
					return s.HeadL1.Number > forkNumber &&
						s.CurrentL1.Number > forkNumber &&
						s.UnsafeL2.L1Origin.Number >= forkNumber &&
						s.SafeL2.L1Origin.Number >= forkNumber &&
						s.FinalizedL2.L1Origin.Number >= forkNumber
				})

			// look at it a few times, the L1 head moves every few seconds
			sequencerL2 := dialRPC(t, ctx, opStackNodes[0].l2RPC)
			for i := range 8 {
				if i > 0 {
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(4 * time.Second):
					}
					if err := rollup.CallContext(ctx, &status, "optimism_syncStatus"); err != nil {
						t.Fatalf("%s: fetch sync status: %v", node.name, err)
					}
				}

				checkOpNodeL1View(t, ctx, l1, node.name, status, true)

				// every node derives the same L2 from the L1, without
				// Glamsterdam header fields
				for _, ref := range []opNodeL2Ref{status.SafeL2, status.FinalizedL2} {
					hash := l2BlockHash(t, ctx, l2, node.name, ref.Number)
					if hash != ref.Hash {
						t.Fatalf("%s: op-node has l2 block %d as %s but its execution client has %s",
							node.name, ref.Number, ref.Hash, hash)
					}
					if sequencerHash := l2BlockHash(t, ctx, sequencerL2, opStackNodes[0].name, ref.Number); hash != sequencerHash {
						t.Fatalf("%s has l2 block %d as %s but the sequencer has %s",
							node.name, ref.Number, hash, sequencerHash)
					}
				}
				_ = l2BlockHash(t, ctx, l2, node.name, status.UnsafeL2.Number)
			}

			if node.derivesFromL1Genesis {
				checkSafeHeadsAcrossFork(t, ctx, l1, l2, rollup, node.name, fork, status)
			}

			// the L2 blocks carry the attributes of their L1 origins, at the
			// fork boundary and now
			checkL2AcrossForkBoundary(t, ctx, l1, l2, node.name, fork, status.SafeL2.Number)
			for _, ref := range []opNodeL2Ref{status.FinalizedL2, status.SafeL2, status.UnsafeL2} {
				if attrs := checkL1AttributesOnL2(t, ctx, l1, l2, node.name, ref.Number); attrs.number != ref.L1Origin.Number {
					t.Fatalf("%s: l2 block %d has l1 origin %d but op-node says %d",
						node.name, ref.Number, attrs.number, ref.L1Origin.Number)
				}
			}

			// the L2 does not execute what Glamsterdam adds to the EVM, the
			// L1 does
			for _, c := range []struct {
				name   string
				client *rpc.Client
				want   bool
			}{
				{"l1", l1, true},
				{node.name + " l2", l2, false},
			} {
				got, err := evmHasGlamsterdam(ctx, c.client)
				if err != nil {
					t.Fatalf("%s: check for the SLOTNUM opcode: %v", c.name, err)
				}
				if got != c.want {
					t.Fatalf("%s: the EVM executes the Glamsterdam opcode SLOTNUM: %v, expected %v", c.name, got, c.want)
				}
			}

			checkContainerNotRestarted(t, ctx, node.container())
			checkOpStackLogs(t, ctx, node.container())
		})
	}
}
