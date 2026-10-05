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
	"github.com/holiman/uint256"
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

	// l1MaxTxGas is the gas limit of a single L1 transaction (EIP-7825).
	l1MaxTxGas uint64 = 1 << 24

	// l1GasBurners transactions that each burn l1MaxTxGas are sent to the
	// L1 in one block so that its gas used exceeds the target and the base
	// fee of the following block rises.
	l1GasBurners = 8

	// opStackContainers are the containers of the OP stack services.
	batcherContainer  = "e2e-op-batcher-1"
	proposerContainer = "e2e-op-proposer-1"
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
// returns, use a beacon endpoint, and keep its receipt validation.  These
// are the production settings, and the ones a previous version of the
// localnet did not use.
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
		for _, forbidden := range []string{"--l1.trustrpc", "--l1.beacon.ignore", "--hemitrap.enabled"} {
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
	// the L1 rejected a transaction of op-batcher or op-proposer because of
	// its gas limit
	"insufficient gas for floor data gas cost",
	"intrinsic gas too low",
	// op-node and the L2 execution client disagree about an L2 block
	"invalid block extraData",
	// op-batcher or op-proposer could not get a transaction accepted by the
	// L1 or re-estimate its gas; the transaction manager retries with a
	// re-estimated gas limit after a while, which hides a wrong gas limit
	// from everything but the logs
	"unable to publish transaction",
	"failed to re-estimate gas",
	// op-batcher fell back to the L1's gas estimate
	"Failed to calculate batch transaction gas limit",
	// op-node could not read the beacon spec
	"beacon spec has neither",
	"got bad value for seconds per slot",
	// a service crashed
	"panic:",
	"CRIT ",
	"Application failed",
}

// maxOpNodeReorgLogs is the most "possible L1 re-org" warnings an op-node may
// log in a run.  The localnet L1 only reorgs when a test makes it, and then
// each op-node logs the warning once.  An op-node that computes a different
// hash than the L1 for every block logs it for every block.
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
				// one the L1 uses.  The localnet L1 only reorgs when a test
				// makes it, which op-node sees as a new head at or below the
				// previous one.
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
		aroundFork        []uint64
	)
	for _, tx := range txs {
		if tx.block+4 >= uint64(fork.first.Number) && tx.block <= uint64(fork.first.Number)+4 {
			aroundFork = append(aroundFork, tx.block)
		}
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

		// The batcher does not know when the L1 activates Glamsterdam, it
		// sets the gas limit that satisfies both the pre-Glamsterdam and
		// the Glamsterdam calldata floor.  A transaction that the L1
		// rejected for its gas limit is resent later with the L1's gas
		// estimate, which is the floor as well; such rejections are found
		// in the batcher logs below.
		wantGasLimit := max(txBaseCost+preGlamsterdamFloorPerToken*tokensInCalldata(tx.Input),
			glamsterdamZeroValueCallBaseGas+floorCost(tx.Input))
		if uint64(tx.Gas) != wantGasLimit {
			t.Fatalf("batcher transaction %s in l1 block %d with %d bytes of calldata has gas limit %d, expected %d",
				tx.Hash, tx.block, len(tx.Input), tx.Gas, wantGasLimit)
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

	t.Logf("the batcher posted %d %s transactions before and %d after the l1 activated Glamsterdam at l1 block %d; "+
		"the l1 blocks around the fork with batcher transactions are %v",
		before, da, after, fork.first.Number, aroundFork)

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

	// a gas limit the L1 rejected is only visible in the logs
	checkContainerNotRestarted(t, ctx, batcherContainer)
	checkOpStackLogs(t, ctx, batcherContainer)
}

// sendL1Transaction signs and sends a transaction to the L1 and returns its
// receipt once it is included.
func sendL1Transaction(t *testing.T, ctx context.Context, l1Client *ethclient.Client, key *ecdsa.PrivateKey, txdata types.TxData) *types.Receipt {
	t.Helper()

	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(l1ChainId()), txdata)
	if err != nil {
		t.Fatal(err)
	}
	if err := l1Client.SendTransaction(ctx, tx); err != nil {
		t.Fatalf("send l1 transaction of type %d: %v", tx.Type(), err)
	}
	for deadline := time.Now().Add(2 * time.Minute); ; {
		receipt, err := l1Client.TransactionReceipt(ctx, tx.Hash())
		if err == nil {
			return receipt
		}
		if time.Now().After(deadline) {
			t.Fatalf("l1 transaction %s of type %d was not included: %v", tx.Hash(), tx.Type(), err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// TestOpNodesVerifyL1BlocksWithEverything puts into L1 blocks what the
// localnet does not otherwise put there and what the op-nodes have to verify
// on a Glamsterdam L1: set code (type 4) transactions, withdrawals, and a
// base fee that changes.  It then ensures that every op-node got past those
// blocks and that the L2 carries the changed base fee.
func TestOpNodesVerifyL1BlocksWithEverything(t *testing.T) {
	if testingFork() || testingPostRun() {
		t.Skip("only run against a fresh localnet")
	}

	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Minute)
	defer cancel()

	fork := l1GlamsterdamFork(t, ctx)
	l1 := dialRPC(t, ctx, glamsterdamL1RPC)
	l1Client := ethclient.NewClient(l1)

	// an account of its own, the load account is busy on the L2
	key, err := crypto.ToECDSA(crypto.Keccak256([]byte("hemi localnet glamsterdam l1 transactions")))
	if err != nil {
		t.Fatal(err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	loadKey := glamsterdamLoadKey(t)

	chainID := uint256.MustFromBig(l1ChainId())
	gasFeeCap := uint256.NewInt(1_000_000_000)

	// fund it from the load account
	nonce, err := l1Client.PendingNonceAt(ctx, crypto.PubkeyToAddress(loadKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	receipt := sendL1Transaction(t, ctx, l1Client, loadKey, &types.DynamicFeeTx{
		ChainID:   l1ChainId(),
		Nonce:     nonce,
		GasTipCap: big.NewInt(1),
		GasFeeCap: gasFeeCap.ToBig(),
		Gas:       100_000,
		To:        &from,
		Value:     new(big.Int).Mul(big.NewInt(400), big.NewInt(1_000_000_000_000_000_000)),
	})
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("funding %s failed", from)
	}
	firstBlock := receipt.BlockNumber.Uint64()

	// A withdrawal in the next L1 block.  The L1 is in dev mode and has no
	// consensus layer to issue withdrawals, dev_addWithdrawal queues one.
	if err := l1.CallContext(ctx, nil, "dev_addWithdrawal", &types.Withdrawal{
		Index: 1, Validator: 1, Address: from, Amount: 1_000_000_000,
	}); err != nil {
		t.Fatalf("add a withdrawal to the l1: %v", err)
	}

	// A set code transaction (EIP-7702) that delegates the account to an
	// address without code and one that removes the delegation again.
	for i, delegate := range []common.Address{dummyRecipient, {}} {
		nonce, err := l1Client.PendingNonceAt(ctx, from)
		if err != nil {
			t.Fatal(err)
		}
		auth, err := types.SignSetCode(key, types.SetCodeAuthorization{
			ChainID: *chainID,
			Address: delegate,
			Nonce:   nonce + 1, // the authorization is checked after the transaction's own nonce
		})
		if err != nil {
			t.Fatal(err)
		}
		receipt := sendL1Transaction(t, ctx, l1Client, key, &types.SetCodeTx{
			ChainID:   chainID,
			Nonce:     nonce,
			GasTipCap: uint256.NewInt(1),
			GasFeeCap: gasFeeCap,
			Gas:       200_000,
			To:        from,
			AuthList:  []types.SetCodeAuthorization{auth},
		})
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("set code transaction %d failed", i)
		}
		if receipt.Type != types.SetCodeTxType {
			t.Fatalf("set code transaction %d has type %d", i, receipt.Type)
		}
		code, err := l1Client.CodeAt(ctx, from, receipt.BlockNumber)
		if err != nil {
			t.Fatal(err)
		}
		if want := (delegate != common.Address{}); (len(code) > 0) != want {
			t.Fatalf("after set code transaction %d, account %s has code %x, delegated: %v", i, from, code, want)
		}
		t.Logf("set code transaction %d is in l1 block %d (delegated to %s)", i, receipt.BlockNumber, delegate)
	}

	// Transactions that each burn the most gas a transaction may use, all
	// in one block, so that the block uses more than the gas target and the
	// base fee of the next block rises.  The code of a burner loops
	// forever: JUMPDEST PUSH0 JUMP.
	nonce, err = l1Client.PendingNonceAt(ctx, from)
	if err != nil {
		t.Fatal(err)
	}
	burners := make([]*types.Transaction, 0, l1GasBurners)
	for i := range uint64(l1GasBurners) {
		tx, err := types.SignNewTx(key, types.LatestSignerForChainID(l1ChainId()), &types.DynamicFeeTx{
			ChainID:   l1ChainId(),
			Nonce:     nonce + i,
			GasTipCap: big.NewInt(1),
			GasFeeCap: gasFeeCap.ToBig(),
			Gas:       l1MaxTxGas,
			Data:      []byte{0x5b, 0x5f, 0x56},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := l1Client.SendTransaction(ctx, tx); err != nil {
			t.Fatalf("send gas burner %d: %v", i, err)
		}
		burners = append(burners, tx)
	}
	var burnerBlocks []uint64
	for i, tx := range burners {
		for deadline := time.Now().Add(2 * time.Minute); ; {
			receipt, err := l1Client.TransactionReceipt(ctx, tx.Hash())
			if err == nil {
				if receipt.GasUsed != l1MaxTxGas {
					t.Fatalf("gas burner %d used %d gas, expected %d", i, receipt.GasUsed, l1MaxTxGas)
				}
				burnerBlocks = append(burnerBlocks, receipt.BlockNumber.Uint64())
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("gas burner %d was not included: %v", i, err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Second):
			}
		}
	}
	lastBlock := burnerBlocks[len(burnerBlocks)-1]
	t.Logf("the %d gas burners are in l1 blocks %v", len(burners), burnerBlocks)

	// the blocks after the burners have a higher base fee
	baseFees := make(map[string]int)
	var raised uint64
	for n := firstBlock; n <= lastBlock+1; n++ {
		h := mustL1Header(t, ctx, l1, n)
		if h.BaseFee == nil {
			t.Fatalf("l1 block %d has no base fee", n)
		}
		baseFees[h.BaseFee.String()]++
		if n > burnerBlocks[0] && h.BaseFee.ToInt().Cmp(mustL1Header(t, ctx, l1, burnerBlocks[0]).BaseFee.ToInt()) > 0 && raised == 0 {
			raised = n
		}
	}
	if raised == 0 {
		t.Fatalf("the l1 base fee did not rise after the gas burners (base fees seen: %v)", baseFees)
	}
	t.Logf("l1 blocks %d to %d carry base fees %v, the base fee rose in block %d", firstBlock, lastBlock+1, baseFees, raised)

	if firstBlock < uint64(fork.first.Number) {
		t.Fatalf("l1 block %d is before Glamsterdam (l1 block %d)", firstBlock, fork.first.Number)
	}

	// every op-node has to get past those blocks, and the L2 blocks with
	// those L1 origins carry their base fees
	for _, node := range opStackNodes {
		rollup := dialRPC(t, ctx, node.rollupRPC)
		l2 := dialRPC(t, ctx, node.l2RPC)
		status := waitForSyncStatus(t, ctx, rollup, node.name,
			fmt.Sprintf("for it to derive l2 blocks with l1 origins past l1 block %d", lastBlock+1),
			func(s *opNodeSyncStatus) bool {
				return s.SafeL2.L1Origin.Number > lastBlock+1
			})
		checkOpNodeL1View(t, ctx, l1, node.name, status, true)

		// L1 origins never decrease, binary search for the first L2 block
		// with the L1 block with the raised base fee as its origin
		lo, hi := uint64(1), status.SafeL2.Number
		for lo < hi {
			mid := lo + (hi-lo)/2
			if _, attrs := l2L1Attributes(t, ctx, l2, node.name, mid); attrs.number < raised {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		attrs := checkL1AttributesOnL2(t, ctx, l1, l2, node.name, lo)
		if attrs.number != raised {
			t.Fatalf("%s: no l2 block has l1 block %d as its origin (l2 block %d has %d)", node.name, raised, lo, attrs.number)
		}
		t.Logf("%s: l2 block %d carries the raised base fee %s of l1 block %d", node.name, lo, attrs.baseFee, raised)
		checkOpStackLogs(t, ctx, node.container())
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

	l1 := dialRPC(t, ctx, glamsterdamL1RPC)
	forkNumber := uint64(fork.first.Number)

	// latest looks at the latest proposal and returns true once it is one
	// made on Glamsterdam about Glamsterdam L1 blocks, or an error
	var latest func() (bool, error)
	if testingL2OO() {
		ooproxy := l2OutputOracle(t)
		oracle, err := bindings.NewL2OutputOracle(ooproxy, l1Client)
		if err != nil {
			t.Fatal(err)
		}
		latest = func() (bool, error) {
			next, err := oracle.NextOutputIndex(&bind.CallOpts{Context: ctx})
			if err != nil || next.Sign() == 0 {
				return false, err
			}
			index := new(big.Int).Sub(next, big.NewInt(1))
			output, err := oracle.GetL2Output(&bind.CallOpts{Context: ctx}, index)
			if err != nil {
				return false, err
			}
			if output.Timestamp.Uint64() < fork.amsterdamTime {
				t.Logf("the latest proposal (output %d) was included at timestamp %d, before Glamsterdam", index, output.Timestamp)
				return false, nil
			}

			// The proposal names the L1 block op-node was at, by number and
			// hash: proposeL2Output(outputRoot, l2BlockNumber, l1BlockHash,
			// l1BlockNumber).  The L2OutputOracle rejects a proposal whose
			// hash is not blockhash(l1BlockNumber), so an included proposal
			// about a Glamsterdam L1 block is the L1 itself agreeing with the
			// hash that op-node computed for it.
			events, err := oracle.FilterOutputProposed(&bind.FilterOpts{Context: ctx}, nil, []*big.Int{index}, nil)
			if err != nil {
				return false, err
			}
			defer events.Close()
			if !events.Next() {
				return false, fmt.Errorf("no OutputProposed event for output %d: %v", index, events.Error())
			}
			tx, _, err := l1Client.TransactionByHash(ctx, events.Event.Raw.TxHash)
			if err != nil {
				return false, err
			}
			input := tx.Data()
			if len(input) != 4+4*32 || hexutil.Encode(input[:4]) != "0x9aaab648" {
				return false, fmt.Errorf("proposal transaction %s is not a proposeL2Output call (%d bytes, selector %s)",
					tx.Hash(), len(input), hexutil.Encode(input[:min(4, len(input))]))
			}
			var (
				l1BlockHash   = common.BytesToHash(input[68:100])
				l1BlockNumber = new(big.Int).SetBytes(input[100:132])
			)
			if !l1BlockNumber.IsUint64() {
				return false, fmt.Errorf("proposal %s names l1 block %s", tx.Hash(), l1BlockNumber)
			}
			if l1BlockNumber.Uint64() < forkNumber {
				t.Logf("the latest proposal (output %d, included at timestamp %d) is about l1 block %d, before Glamsterdam",
					index, output.Timestamp, l1BlockNumber)
				return false, nil
			}
			canonical := mustL1Header(t, ctx, l1, l1BlockNumber.Uint64())
			if canonical.Hash != l1BlockHash {
				return false, fmt.Errorf("proposal %s names l1 block %d as %s but the l1 has %s",
					tx.Hash(), l1BlockNumber, l1BlockHash, canonical.Hash)
			}

			// and it is the output root that op-node has
			checkL2OOOutputRoot(t, ctx, bindings.TypesOutputProposal(output))
			t.Logf("output %d for l2 block %d was proposed at timestamp %d (%d seconds after the l1 activated Glamsterdam) "+
				"about l1 block %d %s, which the l1 agrees with",
				index, output.L2BlockNumber, output.Timestamp, output.Timestamp.Uint64()-fork.amsterdamTime, l1BlockNumber, l1BlockHash)
			return true, nil
		}
	} else {
		factory, err := bindings.NewDisputeGameFactoryCaller(disputeGameFactory(t), l1Client)
		if err != nil {
			t.Fatal(err)
		}
		rollup := dialRPC(t, ctx, opStackNodes[0].rollupRPC)
		latest = func() (bool, error) {
			count, err := factory.GameCount(&bind.CallOpts{Context: ctx})
			if err != nil || count.Sign() == 0 {
				return false, err
			}
			game, err := factory.GameAtIndex(&bind.CallOpts{Context: ctx}, new(big.Int).Sub(count, big.NewInt(1)))
			if err != nil {
				return false, err
			}
			if game.Timestamp < fork.amsterdamTime {
				t.Logf("the latest game was created at timestamp %d, before Glamsterdam", game.Timestamp)
				return false, nil
			}

			// the root claim of the game is op-node's output root for the
			// L2 block it is about
			call := func(selector string) ([]byte, error) {
				var out hexutil.Bytes
				err := l1.CallContext(ctx, &out, "eth_call",
					map[string]string{"to": game.Proxy.Hex(), "data": selector}, "latest")
				return out, err
			}
			rootClaim, err := call("0xbcef3b55") // rootClaim()
			if err != nil {
				return false, err
			}
			l2BlockNumber, err := call("0x8b85902b") // l2BlockNumber()
			if err != nil {
				return false, err
			}
			if len(rootClaim) != 32 || len(l2BlockNumber) != 32 {
				return false, fmt.Errorf("game %s returned %d and %d bytes for rootClaim and l2BlockNumber", game.Proxy, len(rootClaim), len(l2BlockNumber))
			}
			var outputAtBlock struct {
				OutputRoot common.Hash `json:"outputRoot"`
			}
			if err := rollup.CallContext(ctx, &outputAtBlock, "optimism_outputAtBlock", hexutil.EncodeBig(new(big.Int).SetBytes(l2BlockNumber))); err != nil {
				return false, err
			}
			if outputAtBlock.OutputRoot != common.BytesToHash(rootClaim) {
				return false, fmt.Errorf("game %s claims %x for l2 block %d but op-node has %s",
					game.Proxy, rootClaim, new(big.Int).SetBytes(l2BlockNumber), outputAtBlock.OutputRoot)
			}
			t.Logf("game %s for l2 block %d was created at timestamp %d (%d seconds after the l1 activated Glamsterdam) with op-node's output root",
				game.Proxy, new(big.Int).SetBytes(l2BlockNumber), game.Timestamp, game.Timestamp-fork.amsterdamTime)
			return true, nil
		}
	}

	var lastErr error
	for errors := 0; ; {
		done, err := latest()
		if err != nil {
			// the L1 or op-node RPC may fail now and then
			if errors++; errors > 5 {
				t.Fatalf("checking the latest proposal failed %d times, last: %v", errors, err)
			}
			lastErr = err
			t.Logf("checking the latest proposal failed, will retry: %v", err)
		} else if done {
			break
		}

		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for a proposal about the Glamsterdam l1: %s (last error: %v)", ctx.Err(), lastErr)
		case <-time.After(10 * time.Second):
		}
	}

	checkContainerNotRestarted(t, ctx, proposerContainer)
	checkOpStackLogs(t, ctx, proposerContainer)
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

	before := waitForSyncStatus(t, ctx, sequencerRollup, sequencer.name, "for it to be on Glamsterdam l1 blocks",
		func(s *opNodeSyncStatus) bool {
			return s.SafeL2.L1Origin.Number >= uint64(fork.first.Number)
		})

	fullSync := opStackNodes[3]
	for _, container := range []string{batcherContainer, proposerContainer, fullSync.container(), verifier.container(), sequencer.container()} {
		t.Logf("restarting %s", container)
		if _, err := dockerOutput(ctx, "restart", container); err != nil {
			t.Fatal(err)
		}
	}

	// what the sequencer was at once it came back
	restarted := waitForSyncStatus(t, ctx, sequencerRollup, sequencer.name, "for it to answer after the restart",
		func(s *opNodeSyncStatus) bool { return s.UnsafeL2.Number > 0 })
	if restarted.UnsafeL2.Number < before.SafeL2.Number {
		t.Fatalf("%s came back with unsafe l2 head %d, below the safe l2 head %d before the restart",
			sequencer.name, restarted.UnsafeL2.Number, before.SafeL2.Number)
	}

	// The sequencer has to produce new L2 blocks, the batcher has to post
	// them to the L1, and all op-nodes have to derive them from the L1: the
	// safe L2 head has to get past the L2 block that was the unsafe head
	// when the sequencer came back.
	target := restarted.UnsafeL2.Number + 10
	progressed := func(s *opNodeSyncStatus) bool {
		return s.UnsafeL2.Number > target &&
			s.SafeL2.Number > target &&
			s.HeadL1.Number > restarted.HeadL1.Number+2 &&
			s.CurrentL1.Number > restarted.HeadL1.Number+2
	}
	what := fmt.Sprintf("for it to derive l2 block %d from the l1 after the restart", target)
	statuses := make(map[string]*opNodeSyncStatus)
	for _, node := range []opStackNode{sequencer, verifier, fullSync} {
		rollup := dialRPC(t, ctx, node.rollupRPC)
		statuses[node.name] = waitForSyncStatus(t, ctx, rollup, node.name, what, progressed)
		checkOpNodeL1View(t, ctx, l1, node.name, statuses[node.name], false)
	}

	sequencerL2 := dialRPC(t, ctx, sequencer.l2RPC)
	for _, node := range []opStackNode{verifier, fullSync} {
		l2 := dialRPC(t, ctx, node.l2RPC)
		number := min(statuses[sequencer.name].SafeL2.Number, statuses[node.name].SafeL2.Number)
		sequencerHash := l2BlockHash(t, ctx, sequencerL2, sequencer.name, number)
		if hash := l2BlockHash(t, ctx, l2, node.name, number); hash != sequencerHash {
			t.Fatalf("%s has l2 block %d as %s but the sequencer has %s", node.name, number, hash, sequencerHash)
		}
	}

	// the proposer has to propose again
	l1Client := ethclient.NewClient(l1)
	proposedAfter := func() (uint64, error) {
		if testingL2OO() {
			oracle, err := bindings.NewL2OutputOracleCaller(l2OutputOracle(t), l1Client)
			if err != nil {
				return 0, err
			}
			next, err := oracle.NextOutputIndex(&bind.CallOpts{Context: ctx})
			if err != nil || next.Sign() == 0 {
				return 0, err
			}
			output, err := oracle.GetL2Output(&bind.CallOpts{Context: ctx}, new(big.Int).Sub(next, big.NewInt(1)))
			if err != nil {
				return 0, err
			}
			return output.Timestamp.Uint64(), nil
		}
		factory, err := bindings.NewDisputeGameFactoryCaller(disputeGameFactory(t), l1Client)
		if err != nil {
			return 0, err
		}
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
	restartedAt, err := containerStartedAt(ctx, proposerContainer)
	if err != nil {
		t.Fatal(err)
	}
	for {
		proposedAt, err := proposedAfter()
		if err != nil {
			t.Fatal(err)
		}
		if proposedAt > uint64(restartedAt.Unix()) {
			t.Logf("the proposer proposed again at timestamp %d, %d seconds after its restart", proposedAt, proposedAt-uint64(restartedAt.Unix()))
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for a proposal after the proposer restart (latest at timestamp %d)", proposedAt)
		case <-time.After(10 * time.Second):
		}
	}
}

// TestPostRunL1ReorgOnGlamsterdam makes the L1 reorg a few blocks while it is
// on Glamsterdam and ensures that the OP stack follows the new L1 blocks.
// Short reorgs of the L1 are to be expected with ePBS on the consensus layer
// side of Glamsterdam.
func TestPostRunL1ReorgOnGlamsterdam(t *testing.T) {
	if testingFork() || !testingPostRun() {
		t.Skip("only run with HEMI_E2E_POST_RUN=true, after the other tests have passed")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()

	fork := l1GlamsterdamFork(t, ctx)
	l1 := dialRPC(t, ctx, glamsterdamL1RPC)
	sequencer := opStackNodes[0]
	sequencerRollup := dialRPC(t, ctx, sequencer.rollupRPC)

	// The L1 in dev mode finalizes every 32 blocks; a reorg must not go
	// below the finalized block, so wait for a head that is well past one.
	const depth = 3
	var head *l1Header
	for {
		h, err := l1HeaderByTag(ctx, l1, "latest")
		if err != nil {
			t.Fatal(err)
		}
		if uint64(h.Number)%32 >= depth+2 && uint64(h.Number) > uint64(fork.first.Number)+depth {
			head = h
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	before := waitForSyncStatus(t, ctx, sequencerRollup, sequencer.name, "for it to be at the l1 head",
		func(s *opNodeSyncStatus) bool { return s.HeadL1.Number >= uint64(head.Number)-1 })
	dropped := mustL1Header(t, ctx, l1, uint64(head.Number)-depth+1)

	t.Logf("rewinding the l1 from block %d to block %d", head.Number, uint64(head.Number)-depth)
	if err := l1.CallContext(ctx, nil, "debug_setHead", hexutil.EncodeUint64(uint64(head.Number)-depth)); err != nil {
		t.Fatalf("rewind the l1: %v", err)
	}

	// the L1 builds new blocks from there, with other hashes
	var replaced *l1Header
	for {
		h, err := l1HeaderByTag(ctx, l1, "latest")
		if err != nil {
			t.Fatal(err)
		}
		if uint64(h.Number) > uint64(head.Number)+2 {
			replaced = mustL1Header(t, ctx, l1, uint64(dropped.Number))
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the l1 did not build new blocks after the rewind: %v", ctx.Err())
		case <-time.After(time.Second):
		}
	}
	if replaced.Hash == dropped.Hash {
		t.Fatalf("l1 block %d is still %s after the rewind", dropped.Number, dropped.Hash)
	}
	t.Logf("l1 block %d is now %s, it was %s", dropped.Number, replaced.Hash, dropped.Hash)

	// Every op-node has to notice, drop what it derived from the dropped
	// blocks, and derive from the new ones: the L1 blocks it refers to must
	// be the new ones, and its safe L2 head must get past the unsafe L2
	// head from before the reorg, that is the batcher has to post again.
	target := before.UnsafeL2.Number
	for _, node := range opStackNodes {
		rollup := dialRPC(t, ctx, node.rollupRPC)
		status := waitForSyncStatus(t, ctx, rollup, node.name,
			fmt.Sprintf("for it to follow the l1 past the reorg and derive l2 block %d", target),
			func(s *opNodeSyncStatus) bool {
				return s.HeadL1.Number > uint64(head.Number)+2 &&
					s.CurrentL1.Number > uint64(head.Number) &&
					s.SafeL2.Number > target &&
					s.SafeL2.L1Origin.Number > uint64(head.Number)
			})
		checkOpNodeL1View(t, ctx, l1, node.name, status, false)
	}

	sequencerL2 := dialRPC(t, ctx, sequencer.l2RPC)
	for _, node := range opStackNodes[1:] {
		rollup := dialRPC(t, ctx, node.rollupRPC)
		var status *opNodeSyncStatus
		if err := rollup.CallContext(ctx, &status, "optimism_syncStatus"); err != nil {
			t.Fatal(err)
		}
		l2 := dialRPC(t, ctx, node.l2RPC)
		number := status.SafeL2.Number
		sequencerHash := l2BlockHash(t, ctx, sequencerL2, sequencer.name, number)
		if hash := l2BlockHash(t, ctx, l2, node.name, number); hash != sequencerHash {
			t.Fatalf("%s has l2 block %d as %s but the sequencer has %s", node.name, number, hash, sequencerHash)
		}
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

	containers := []string{batcherContainer, proposerContainer}
	for _, node := range opStackNodes {
		containers = append(containers, node.container())
	}
	for _, container := range containers {
		checkContainerNotRestarted(t, ctx, container)
		checkOpStackLogs(t, ctx, container)
	}
}
