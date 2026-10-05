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
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum-optimism/optimism/op-node/bindings"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	// glamsterdamL1RPC is the localnet L1, geth-l1.
	glamsterdamL1RPC = "http://localhost:8545"

	// l1BlockPredeploy is the L2 contract that holds the attributes of the
	// L1 origin of an L2 block.
	l1BlockPredeploy = "0x4200000000000000000000000000000000000015"

	// glamsterdamZeroValueCallBaseGas is the EIP-2780 intrinsic base cost of
	// a transaction that calls another account without sending value: 12000
	// for the transaction itself plus 3000 for touching the recipient.  It
	// replaces the 21000 gas charged before Glamsterdam.
	glamsterdamZeroValueCallBaseGas uint64 = 12000 + 3000

	// preGlamsterdamFloorPerToken is the EIP-7623 calldata floor cost per
	// token, which EIP-7976 raises to totalCostFloorPerToken.
	preGlamsterdamFloorPerToken uint64 = 10

	// glamsterdamHeavyTxs transactions of glamsterdamHeavyTxSize random
	// bytes are sent on the L2 so that the batcher has to post batches of
	// production size.
	glamsterdamHeavyTxs    = 6
	glamsterdamHeavyTxSize = 30_000
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
}

func (n opStackNode) container() string {
	return "e2e-" + n.name + "-1"
}

var opStackNodes = []opStackNode{
	{name: "op-node", rollupRPC: "http://localhost:8548", l2RPC: "http://localhost:8546", runsFromL1Genesis: true},
	{name: "op-node-non-sequencing", rollupRPC: "http://localhost:18548", l2RPC: "http://localhost:18546", runsFromL1Genesis: true},
	{name: "op-node-non-sequencing-snap-sync", rollupRPC: "http://localhost:28548", l2RPC: "http://localhost:28546"},
	{name: "op-node-non-sequencing-full-sync", rollupRPC: "http://localhost:38548", l2RPC: "http://localhost:38546"},
}

// testingPostRun returns true when the tests that disturb the localnet are to
// be run.  They are run on their own, after all other tests have passed.
func testingPostRun() bool {
	return os.Getenv("HEMI_E2E_POST_RUN") == "true"
}

// batcherDAType returns how the localnet op-batcher was told to publish
// batches, "calldata" or "blobs".  See BATCHER_DA_TYPE in docker-compose.yml.
func batcherDAType(t *testing.T) string {
	t.Helper()

	switch da := os.Getenv("BATCHER_DA_TYPE"); da {
	case "":
		return "calldata"
	case "calldata", "blobs":
		return da
	default:
		t.Fatalf("unknown BATCHER_DA_TYPE %q, expected calldata or blobs", da)
		return ""
	}
}

// glamsterdamLoadKey returns the key of the account used to put load on the
// batcher.  It is derived from a public label and funded on the L1 by
// e2e/genesisl2.sh, it is only meant for the localnet.
func glamsterdamLoadKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := crypto.ToECDSA(crypto.Keccak256([]byte("hemi localnet glamsterdam batcher load")))
	if err != nil {
		t.Fatal(err)
	}
	return key
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

type l1Tx struct {
	Hash                common.Hash     `json:"hash"`
	From                common.Address  `json:"from"`
	To                  *common.Address `json:"to"`
	Input               hexutil.Bytes   `json:"input"`
	Gas                 hexutil.Uint64  `json:"gas"`
	Type                hexutil.Uint64  `json:"type"`
	Value               *hexutil.Big    `json:"value"`
	BlobVersionedHashes []common.Hash   `json:"blobVersionedHashes"`
}

type l1Block struct {
	l1Header
	Transactions []l1Tx `json:"transactions"`
}

type l1Receipt struct {
	Status      hexutil.Uint64 `json:"status"`
	GasUsed     hexutil.Uint64 `json:"gasUsed"`
	BlockNumber hexutil.Uint64 `json:"blockNumber"`
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

// l1BlockByNumber returns an L1 block with its transactions.
func l1BlockByNumber(ctx context.Context, l1 *rpc.Client, number uint64) (*l1Block, error) {
	var b *l1Block
	if err := l1.CallContext(ctx, &b, "eth_getBlockByNumber", hexutil.EncodeUint64(number), true); err != nil {
		return nil, fmt.Errorf("fetch l1 block %d: %w", number, err)
	}
	if b == nil {
		return nil, fmt.Errorf("l1 block %d not found", number)
	}
	return b, nil
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
func checkOpNodeL1View(t *testing.T, ctx context.Context, l1 *rpc.Client, name string, s *opNodeSyncStatus) {
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
		{"safe_l1", s.SafeL1, false},
		{"finalized_l1", s.FinalizedL1, false},
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

// checkL1AttributesOnL2 ensures that the attributes of the L1 origin that an
// L2 block carries in the L1Block contract are those of the L1 block.
func checkL1AttributesOnL2(t *testing.T, ctx context.Context, l1 *rpc.Client, l2 *rpc.Client, name string, ref opNodeL2Ref) {
	t.Helper()

	call := func(what string, selector string) *big.Int {
		var out hexutil.Bytes
		err := l2.CallContext(ctx, &out, "eth_call",
			map[string]string{"to": l1BlockPredeploy, "data": selector},
			hexutil.EncodeUint64(ref.Number))
		if err != nil {
			t.Fatalf("%s: read L1Block.%s at l2 block %d: %v", name, what, ref.Number, err)
		}
		if len(out) != 32 {
			t.Fatalf("%s: L1Block.%s at l2 block %d returned %d bytes", name, what, ref.Number, len(out))
		}
		return new(big.Int).SetBytes(out)
	}

	var (
		number      = call("number()", "0x8381f58a")
		hash        = common.BigToHash(call("hash()", "0x09bd5a60"))
		baseFee     = call("basefee()", "0x5cf24969")
		blobBaseFee = call("blobBaseFee()", "0xf8206140")
	)

	if !number.IsUint64() || number.Uint64() != ref.L1Origin.Number {
		t.Fatalf("%s: L1Block.number at l2 block %d is %s, op-node says its l1 origin is %d",
			name, ref.Number, number, ref.L1Origin.Number)
	}

	canonical := mustL1Header(t, ctx, l1, number.Uint64())
	if hash != canonical.Hash {
		t.Fatalf("%s: L1Block.hash at l2 block %d is %s but l1 block %d is %s",
			name, ref.Number, hash, canonical.Number, canonical.Hash)
	}
	if canonical.BaseFee == nil || baseFee.Cmp(canonical.BaseFee.ToInt()) != 0 {
		t.Fatalf("%s: L1Block.basefee at l2 block %d is %s but l1 block %d has base fee %v",
			name, ref.Number, baseFee, canonical.Number, canonical.BaseFee)
	}

	var feeHistory struct {
		BaseFeePerBlobGas []*hexutil.Big `json:"baseFeePerBlobGas"`
	}
	err := l1.CallContext(ctx, &feeHistory, "eth_feeHistory", "0x1", hexutil.EncodeUint64(number.Uint64()), []float64{})
	if err != nil {
		t.Fatalf("fetch l1 fee history of block %d: %v", number, err)
	}
	if len(feeHistory.BaseFeePerBlobGas) == 0 || feeHistory.BaseFeePerBlobGas[0] == nil {
		t.Fatalf("l1 fee history of block %d has no blob base fee", number)
	}
	if want := feeHistory.BaseFeePerBlobGas[0].ToInt(); blobBaseFee.Cmp(want) != 0 {
		t.Fatalf("%s: L1Block.blobBaseFee at l2 block %d is %s but l1 block %d has blob base fee %s",
			name, ref.Number, blobBaseFee, canonical.Number, want)
	}

	t.Logf("%s: l2 block %d carries the attributes of l1 block %d %s (base fee %s, blob base fee %s)",
		name, ref.Number, canonical.Number, canonical.Hash, baseFee, blobBaseFee)
}

// ---- docker ----------------------------------------------------------------

func dockerOutput(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
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
	// the L1 rejected a transaction of op-batcher or op-proposer because of
	// its gas limit
	"insufficient gas for floor data gas cost",
	"intrinsic gas too low",
	// op-node and the L2 execution client disagree about an L2 block
	"invalid block extraData",
}

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
		problems []string
		lines    int
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
				// The localnet L1 is a single node that never reorgs.  A
				// new head that is not the child of the previous head is
				// fine if heads were skipped in between.  If it directly
				// follows the previous head, or is not after it, then
				// op-node computed a different hash for the previous head
				// than the one the L1 uses as the parent hash.
				oldNumber, _ := strconv.ParseUint(m[2], 10, 64)
				newNumber, _ := strconv.ParseUint(m[5], 10, 64)
				if newNumber <= oldNumber+1 {
					add("l1 head hash mismatch", line)
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
	if testingFork() || testingPostRun() {
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
	if testingFork() || testingPostRun() {
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

			if node.runsFromL1Genesis {
				// it must have been running when the L1 migrated, or it
				// did not have to follow the L1 across the fork
				startedAt, err := containerStartedAt(ctx, node.container())
				if err != nil {
					t.Fatal(err)
				}
				if uint64(startedAt.Unix()) >= fork.amsterdamTime {
					t.Fatalf("%s was (re)started at %s, after the l1 activated Glamsterdam at %s; "+
						"it was not running across the migration.  Use a fresh localnet, and a larger "+
						"L1_AMSTERDAM_OFFSET_SECONDS if it starts up slowly",
						node.container(), startedAt.UTC(), time.Unix(int64(fork.amsterdamTime), 0).UTC())
				}
				t.Logf("%s runs since %s, %d seconds before the l1 activated Glamsterdam",
					node.container(), startedAt.UTC(), int64(fork.amsterdamTime)-startedAt.Unix())
			}

			// The L1 origin of the finalized L2 head is on Glamsterdam once
			// the node derived L2 blocks from batches posted to Glamsterdam
			// L1 blocks, with L1 origins on Glamsterdam, and saw them
			// finalize on the L1.
			status := waitForSyncStatus(t, ctx, rollup, node.name,
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

				checkOpNodeL1View(t, ctx, l1, node.name, status)

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

			checkL1AttributesOnL2(t, ctx, l1, l2, node.name, status.SafeL2)

			checkOpStackLogs(t, ctx, node.container())
		})
	}
}

// batcherTx is a transaction that op-batcher sent to the batch inbox.
type batcherTx struct {
	l1Tx
	block       uint64
	glamsterdam bool
}

// batcherTransactions returns the transactions that the batcher sent to the
// batch inbox in the L1 blocks from 1 to the L1 head.
func batcherTransactions(t *testing.T, ctx context.Context, l1 *rpc.Client, fork glamsterdamFork) []batcherTx {
	t.Helper()

	var (
		batcher = common.HexToAddress(batcherSenderAddress)
		inbox   = common.HexToAddress(batcherInboxAddress)
	)

	head, err := l1HeaderByTag(ctx, l1, "latest")
	if err != nil {
		t.Fatal(err)
	}

	var txs []batcherTx
	for n := uint64(1); n <= uint64(head.Number); n++ {
		block, err := l1BlockByNumber(ctx, l1, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, tx := range block.Transactions {
			if tx.From != batcher || tx.To == nil || *tx.To != inbox {
				continue
			}
			txs = append(txs, batcherTx{
				l1Tx:        tx,
				block:       n,
				glamsterdam: n >= uint64(fork.first.Number),
			})
		}
	}
	return txs
}

// sendHeavyL2Transactions sends transactions with a lot of incompressible
// data to the L2 and returns the number of the last L2 block that includes
// one of them.  The batcher has to post that data to the L1.
//
// The transactions are sent with exactly the gas that such a transaction
// needs before Glamsterdam, which is far less than what it needs on
// Glamsterdam.  The L2 accepting them shows that the L2 did not pick up the
// Glamsterdam gas rules.
func sendHeavyL2Transactions(t *testing.T, ctx context.Context) uint64 {
	t.Helper()

	key := glamsterdamLoadKey(t)
	from := crypto.PubkeyToAddress(key.PublicKey)

	l1Client, err := ethclient.DialContext(ctx, l1Endpoint())
	if err != nil {
		t.Fatalf("could not dial eth l1 %s", err)
	}
	defer l1Client.Close()

	l2Client, err := ethclient.DialContext(ctx, opStackNodes[0].l2RPC)
	if err != nil {
		t.Fatalf("could not dial eth l2 %s", err)
	}
	defer l2Client.Close()

	// the account is only funded on the L1
	minBalance := big.NewInt(50_000_000_000_000_000)
	balance, err := l2Client.BalanceAt(ctx, from, nil)
	if err != nil {
		t.Fatal(err)
	}
	if balance.Cmp(minBalance) < 0 {
		bridgeEthL1ToL2(t, ctx, l1Client, l2Client, key)
		for balance.Cmp(minBalance) < 0 {
			select {
			case <-ctx.Done():
				t.Fatalf("timed out waiting for the l1 -> l2 eth bridge to %s", from)
			case <-time.After(3 * time.Second):
			}
			if balance, err = l2Client.BalanceAt(ctx, from, nil); err != nil {
				t.Fatal(err)
			}
		}
	}

	gasPrice, err := l2Client.SuggestGasPrice(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gasPrice = new(big.Int).Add(new(big.Int).Mul(gasPrice, big.NewInt(2)), big.NewInt(1_000_000_000))

	nonce, err := l2Client.PendingNonceAt(ctx, from)
	if err != nil {
		t.Fatal(err)
	}

	signer := types.LatestSignerForChainID(l2ChainId())
	txs := make([]*types.Transaction, 0, glamsterdamHeavyTxs)
	for i := range glamsterdamHeavyTxs {
		data := make([]byte, glamsterdamHeavyTxSize)
		if _, err := crand.Read(data); err != nil {
			t.Fatal(err)
		}

		tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
			Nonce:    nonce + uint64(i),
			To:       &dummyRecipient,
			Gas:      txBaseCost + preGlamsterdamFloorPerToken*tokensInCalldata(data),
			GasPrice: gasPrice,
			Data:     data,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := l2Client.SendTransaction(ctx, tx); err != nil {
			t.Fatalf("send l2 transaction with %d bytes of data and gas limit %d: %v", len(data), tx.Gas(), err)
		}
		txs = append(txs, tx)
	}

	var lastBlock uint64
	for _, tx := range txs {
		var receipt *types.Receipt
		for deadline := time.Now().Add(3 * time.Minute); receipt == nil; {
			if receipt, err = l2Client.TransactionReceipt(ctx, tx.Hash()); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("l2 transaction %s was not included: %v", tx.Hash(), err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Second):
			}
		}
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("l2 transaction %s failed", tx.Hash())
		}
		if receipt.GasUsed != tx.Gas() {
			t.Fatalf("l2 transaction %s with %d bytes of data used %d gas, expected the pre-Glamsterdam calldata floor of %d",
				tx.Hash(), len(tx.Data()), receipt.GasUsed, tx.Gas())
		}
		lastBlock = max(lastBlock, receipt.BlockNumber.Uint64())
	}

	t.Logf("sent %d l2 transactions with %d bytes of random data each, the last one is in l2 block %d",
		len(txs), glamsterdamHeavyTxSize, lastBlock)

	return lastBlock
}

// TestBatcherPostsAcrossGlamsterdam ensures that op-batcher got batches
// included in the L1 before and after the L1 activated Glamsterdam, paying
// what the L1 charged for them at the time, and that all op-nodes derive the
// L2 from them.
func TestBatcherPostsAcrossGlamsterdam(t *testing.T) {
	if testingFork() || testingPostRun() {
		t.Skip("only run against a fresh localnet")
	}

	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Minute)
	defer cancel()

	da := batcherDAType(t)
	fork := l1GlamsterdamFork(t, ctx)
	l1 := dialRPC(t, ctx, glamsterdamL1RPC)

	// Make the batcher post a lot of data after the fork.  Compressed random
	// data has enough zero bytes to tell a calldata floor that counts every
	// byte, like the one of Glamsterdam, from one that counts zero bytes
	// for less.
	heavyBlock := sendHeavyL2Transactions(t, ctx)

	// the batches with that data have to make it to the L1 and be derived
	// from it by every op-node, in blob mode this includes fetching the
	// blobs from the beacon API
	for _, node := range opStackNodes {
		rollup := dialRPC(t, ctx, node.rollupRPC)
		waitForSyncStatus(t, ctx, rollup, node.name,
			fmt.Sprintf("for l2 block %d to be derived from the l1", heavyBlock),
			func(s *opNodeSyncStatus) bool {
				return s.SafeL2.Number >= heavyBlock
			})
	}

	var (
		txs               = batcherTransactions(t, ctx, l1, fork)
		before, after     int
		maxZeroBytesAfter int
		maxSizeAfter      int
	)
	for _, tx := range txs {
		var receipt *l1Receipt
		if err := l1.CallContext(ctx, &receipt, "eth_getTransactionReceipt", tx.Hash); err != nil || receipt == nil {
			t.Fatalf("fetch receipt of batcher transaction %s: %v", tx.Hash, err)
		}
		if receipt.Status != 1 {
			t.Fatalf("batcher transaction %s in l1 block %d failed", tx.Hash, tx.block)
		}

		// A batcher transaction does not execute anything, it uses the
		// intrinsic gas of its data or the calldata floor.  Before
		// Glamsterdam that is 21000 gas plus 10 gas per calldata token
		// (EIP-7623), on Glamsterdam 15000 gas (EIP-2780) plus 64 gas per
		// byte (EIP-7976).
		var wantGasUsed uint64
		if tx.glamsterdam {
			after++
			wantGasUsed = glamsterdamZeroValueCallBaseGas + floorCost(tx.Input)
		} else {
			before++
			wantGasUsed = txBaseCost + preGlamsterdamFloorPerToken*tokensInCalldata(tx.Input)
		}
		if uint64(receipt.GasUsed) != wantGasUsed {
			t.Fatalf("batcher transaction %s in l1 block %d (on Glamsterdam: %v) with %d bytes of calldata used %d gas, expected %d",
				tx.Hash, tx.block, tx.glamsterdam, len(tx.Input), receipt.GasUsed, wantGasUsed)
		}
		if uint64(tx.Gas) < wantGasUsed {
			t.Fatalf("batcher transaction %s in l1 block %d has gas limit %d, below the %d gas it used",
				tx.Hash, tx.block, tx.Gas, wantGasUsed)
		}

		switch da {
		case "calldata":
			if tx.Type == types.BlobTxType || len(tx.BlobVersionedHashes) != 0 || len(tx.Input) == 0 {
				t.Fatalf("batcher transaction %s in l1 block %d is not a calldata transaction (type %d, %d blobs, %d bytes of calldata)",
					tx.Hash, tx.block, tx.Type, len(tx.BlobVersionedHashes), len(tx.Input))
			}
		case "blobs":
			if tx.Type != types.BlobTxType || len(tx.BlobVersionedHashes) == 0 {
				t.Fatalf("batcher transaction %s in l1 block %d is not a blob transaction (type %d, %d blobs)",
					tx.Hash, tx.block, tx.Type, len(tx.BlobVersionedHashes))
			}
		}

		if tx.glamsterdam {
			maxSizeAfter = max(maxSizeAfter, len(tx.Input))
			zeroBytes := 0
			for _, b := range tx.Input {
				if b == 0 {
					zeroBytes++
				}
			}
			maxZeroBytesAfter = max(maxZeroBytesAfter, zeroBytes)
		}
	}

	t.Logf("the batcher posted %d %s transactions before and %d after the l1 activated Glamsterdam at l1 block %d",
		before, da, after, fork.first.Number)

	if before == 0 {
		t.Fatalf("the batcher did not post a batch before the l1 activated Glamsterdam at l1 block %d; "+
			"it was not batching across the migration.  Use a larger L1_AMSTERDAM_OFFSET_SECONDS "+
			"if the localnet starts up slowly", fork.first.Number)
	}
	if after == 0 {
		t.Fatal("the batcher did not post a batch after the l1 activated Glamsterdam")
	}

	if da == "calldata" {
		// The pre-Glamsterdam floor charges a zero byte a quarter of a
		// non-zero byte, the Glamsterdam floor charges every byte the
		// same.  A gas limit that still discounts zero bytes is too low on
		// Glamsterdam once a batch has more than 125 of them.
		t.Logf("the largest batch posted on Glamsterdam has %d bytes, the most zero bytes in a batch are %d",
			maxSizeAfter, maxZeroBytesAfter)
		if maxZeroBytesAfter <= 125 {
			t.Fatalf("no batch posted on Glamsterdam has more than 125 zero bytes (most: %d), "+
				"the calldata floor was not exercised with a large batch", maxZeroBytesAfter)
		}
	}
}

// TestProposerProposesAfterGlamsterdam ensures that op-proposer got an
// output root proposal included in the L1 after the L1 activated Glamsterdam.
func TestProposerProposesAfterGlamsterdam(t *testing.T) {
	if testingFork() || testingPostRun() {
		t.Skip("only run against a fresh localnet")
	}

	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Minute)
	defer cancel()

	fork := l1GlamsterdamFork(t, ctx)

	l1Client, err := ethclient.DialContext(ctx, l1Endpoint())
	if err != nil {
		t.Fatalf("could not dial eth l1 %s", err)
	}
	defer l1Client.Close()

	// latest returns the L1 timestamp of the latest proposal, 0 if there is
	// none yet
	var latest func() (uint64, error)
	if testingL2OO() {
		oracle, err := bindings.NewL2OutputOracleCaller(l2OutputOracle(t), l1Client)
		if err != nil {
			t.Fatal(err)
		}
		latest = func() (uint64, error) {
			next, err := oracle.NextOutputIndex(&bind.CallOpts{Context: ctx})
			if err != nil || next.Sign() == 0 {
				return 0, err
			}
			output, err := oracle.GetL2Output(&bind.CallOpts{Context: ctx}, new(big.Int).Sub(next, big.NewInt(1)))
			if err != nil {
				return 0, err
			}
			if output.Timestamp.Uint64() >= fork.amsterdamTime {
				// and it is the output root that op-node has
				checkL2OOOutputRoot(t, ctx, output)
			}
			return output.Timestamp.Uint64(), nil
		}
	} else {
		factory, err := bindings.NewDisputeGameFactoryCaller(disputeGameFactory(t), l1Client)
		if err != nil {
			t.Fatal(err)
		}
		latest = func() (uint64, error) {
			count, err := factory.GameCount(&bind.CallOpts{Context: ctx})
			if err != nil || count.Sign() == 0 {
				return 0, err
			}
			game, err := factory.GameAtIndex(&bind.CallOpts{Context: ctx}, new(big.Int).Sub(count, big.NewInt(1)))
			if err != nil {
				return 0, err
			}
			return game.Timestamp, nil
		}
	}

	for {
		proposedAt, err := latest()
		if err != nil {
			t.Fatal(err)
		}
		if proposedAt >= fork.amsterdamTime {
			t.Logf("the latest proposal was included in the l1 at timestamp %d, %d seconds after the l1 activated Glamsterdam",
				proposedAt, proposedAt-fork.amsterdamTime)
			return
		}

		t.Logf("waiting for a proposal after the l1 activated Glamsterdam (latest at timestamp %d)", proposedAt)
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for a proposal after the l1 activated Glamsterdam: %s", ctx.Err())
		case <-time.After(10 * time.Second):
		}
	}
}

// ---- post-run tests --------------------------------------------------------
//
// These disturb the localnet or look at everything that happened, they are
// run on their own after all other tests have passed:
//
//	HEMI_E2E_POST_RUN=true go test -v -run '^TestPostRun' .

// TestPostRunOpStackRestartsOnGlamsterdam ensures that op-batcher and the
// op-nodes can be restarted when the L1 is on Glamsterdam.  When they start
// they have to find their place on the L1 again, starting from L1 blocks
// that are on Glamsterdam.
func TestPostRunOpStackRestartsOnGlamsterdam(t *testing.T) {
	if testingFork() || !testingPostRun() {
		t.Skip("only run with HEMI_E2E_POST_RUN=true, after the other tests have passed")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()

	fork := l1GlamsterdamFork(t, ctx)
	l1 := dialRPC(t, ctx, glamsterdamL1RPC)

	var (
		sequencer = opStackNodes[0]
		verifier  = opStackNodes[1]
	)
	sequencerRollup := dialRPC(t, ctx, sequencer.rollupRPC)
	verifierRollup := dialRPC(t, ctx, verifier.rollupRPC)

	before := waitForSyncStatus(t, ctx, sequencerRollup, sequencer.name, "for it to be on Glamsterdam l1 blocks",
		func(s *opNodeSyncStatus) bool {
			return s.SafeL2.L1Origin.Number >= uint64(fork.first.Number)
		})

	for _, container := range []string{"e2e-op-batcher-1", verifier.container(), sequencer.container()} {
		t.Logf("restarting %s", container)
		if _, err := dockerOutput(ctx, "restart", container); err != nil {
			t.Fatal(err)
		}
	}

	// The sequencer has to produce new L2 blocks, the batcher has to post
	// them to the L1, and both op-nodes have to derive them from the L1:
	// the safe L2 head has to get past the L2 block that was the unsafe head
	// before the restarts.
	target := before.UnsafeL2.Number + 10
	progressed := func(s *opNodeSyncStatus) bool {
		return s.UnsafeL2.Number > target &&
			s.SafeL2.Number > target &&
			s.HeadL1.Number > before.HeadL1.Number &&
			s.CurrentL1.Number > before.HeadL1.Number
	}
	what := fmt.Sprintf("for it to derive l2 block %d from the l1 after the restart", target)
	sequencerStatus := waitForSyncStatus(t, ctx, sequencerRollup, sequencer.name, what, progressed)
	verifierStatus := waitForSyncStatus(t, ctx, verifierRollup, verifier.name, what, progressed)

	checkOpNodeL1View(t, ctx, l1, sequencer.name, sequencerStatus)
	checkOpNodeL1View(t, ctx, l1, verifier.name, verifierStatus)

	sequencerL2 := dialRPC(t, ctx, sequencer.l2RPC)
	verifierL2 := dialRPC(t, ctx, verifier.l2RPC)
	number := min(sequencerStatus.SafeL2.Number, verifierStatus.SafeL2.Number)
	sequencerHash := l2BlockHash(t, ctx, sequencerL2, sequencer.name, number)
	if verifierHash := l2BlockHash(t, ctx, verifierL2, verifier.name, number); verifierHash != sequencerHash {
		t.Fatalf("%s has l2 block %d as %s but the sequencer has %s", verifier.name, number, verifierHash, sequencerHash)
	}
}

// TestPostRunOpStackLogs ensures that none of the OP stack services logged
// that it does not understand the L1, at any time since the localnet was
// started.
func TestPostRunOpStackLogs(t *testing.T) {
	if testingFork() || !testingPostRun() {
		t.Skip("only run with HEMI_E2E_POST_RUN=true, after the other tests have passed")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	containers := []string{"e2e-op-batcher-1", "e2e-op-proposer-1"}
	for _, node := range opStackNodes {
		containers = append(containers, node.container())
	}
	for _, container := range containers {
		checkOpStackLogs(t, ctx, container)
	}
}
