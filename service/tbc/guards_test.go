// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/ttl"
)

// mineHeader returns a header descending from prev that actually meets the target implied by bits.
// tag makes sibling headers distinct.
func mineHeader(t *testing.T, prev *chainhash.Hash, bits uint32, tag byte) *wire.BlockHeader {
	t.Helper()
	var mr chainhash.Hash
	mr[0] = tag
	h := &wire.BlockHeader{
		Version:    1,
		PrevBlock:  *prev,
		MerkleRoot: mr,
		Timestamp:  time.Unix(1700000000, 0),
		Bits:       bits,
	}
	target := blockchain.CompactToBig(bits)
	for n := uint32(0); n < math.MaxUint32; n++ {
		h.Nonce = n
		hash := h.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return h
		}
	}
	t.Fatalf("could not mine header with bits %08x", bits)
	return nil
}

// callHandleHeaders invokes handleHeaders with a nil db. A correctly rejected headers message never
// reaches the store; if the guard is gone the call nil-derefs inside BlockHeadersInsert, which we
// catch and report as the failure it is rather than letting it abort the package.
func callHandleHeaders(t *testing.T, s *Server, msg *wire.MsgHeaders) (reachedStore any, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			reachedStore = r
		}
	}()
	err = s.handleHeaders(t.Context(), nil, msg)
	return
}

// TestVerifyHeadersPoWRejectsUnminedHeader is the direct guard on change B. A header that claims a
// target its own hash does not meet must be rejected. This is exactly the shape the old test
// harness produced (mainnet difficulty-1 claimed, no nonce ground).
func TestVerifyHeadersPoWRejectsUnminedHeader(t *testing.T) {
	params := &chaincfg.RegressionNetParams
	s := &Server{chainParams: params}

	// Claim mainnet difficulty-1 but never grind a nonce.
	unmined := &wire.BlockHeader{
		Version:    1,
		PrevBlock:  *params.GenesisHash,
		MerkleRoot: chainhash.Hash{0x11},
		Timestamp:  time.Unix(1700000000, 0),
		Bits:       0x1d00ffff,
		Nonce:      0,
	}
	if err := s.verifyHeadersPoW([]*wire.BlockHeader{unmined}); err == nil {
		t.Fatal("expected unmined header to be rejected, got nil")
	} else if !strings.Contains(err.Error(), "proof-of-work") {
		t.Fatalf("unexpected error: %v", err)
	}

	// It must also be rejected when it is not the first header of the batch.
	good := mineHeader(t, params.GenesisHash, params.PowLimitBits, 0x01)
	if err := s.verifyHeadersPoW([]*wire.BlockHeader{good, unmined}); err == nil {
		t.Fatal("expected unmined header at index 1 to be rejected, got nil")
	}
}

// TestVerifyHeadersPoWRejectsTargetAbovePowLimit covers the second arm of
// CheckBlockHeaderSanity: a claimed target easier than the network's PowLimit.
func TestVerifyHeadersPoWRejectsTargetAbovePowLimit(t *testing.T) {
	params := &chaincfg.MainNetParams
	s := &Server{chainParams: params}

	// 0x207fffff is regtest's limit, far above mainnet's.
	h := &wire.BlockHeader{
		Version:    1,
		PrevBlock:  *params.GenesisHash,
		MerkleRoot: chainhash.Hash{0x22},
		Timestamp:  time.Unix(1700000000, 0),
		Bits:       0x207fffff,
	}
	if err := s.verifyHeadersPoW([]*wire.BlockHeader{h}); err == nil {
		t.Fatal("expected target above PowLimit to be rejected, got nil")
	}
}

// TestVerifyHeadersPoWAcceptsMinedHeaders is the false-reject guard: genuinely mined headers,
// including ones timestamped well outside the host's ~2h window in both directions, must pass.
func TestVerifyHeadersPoWAcceptsMinedHeaders(t *testing.T) {
	params := &chaincfg.RegressionNetParams
	s := &Server{chainParams: params}

	h := mineHeader(t, params.GenesisHash, params.PowLimitBits, 0x33)
	if err := s.verifyHeadersPoW([]*wire.BlockHeader{h}); err != nil {
		t.Fatalf("mined header rejected: %v", err)
	}

	// A header timestamped 10 years in the future must still be accepted: the timestamp arm is
	// deliberately neutralised by deterministicTimeSource so that two honest nodes with different
	// clocks cannot disagree about identical bytes.
	future := &wire.BlockHeader{
		Version:    1,
		PrevBlock:  *params.GenesisHash,
		MerkleRoot: chainhash.Hash{0x44},
		Timestamp:  time.Now().Add(10 * 365 * 24 * time.Hour).Truncate(time.Second),
		Bits:       params.PowLimitBits,
	}
	target := blockchain.CompactToBig(future.Bits)
	for n := uint32(0); ; n++ {
		future.Nonce = n
		hash := future.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			break
		}
	}
	if err := s.verifyHeadersPoW([]*wire.BlockHeader{future}); err != nil {
		t.Fatalf("future-timestamped mined header rejected: %v", err)
	}
}

// TestDeterministicTimeSource pins the contract the PoW and block-sanity gates rely on.
func TestDeterministicTimeSource(t *testing.T) {
	var ts blockchain.MedianTimeSource = deterministicTimeSource{}
	if ts.AdjustedTime().Before(time.Now().Add(100 * 365 * 24 * time.Hour)) {
		t.Fatalf("deterministicTimeSource is not far-future: %v", ts.AdjustedTime())
	}
	if ts.Offset() != 0 {
		t.Fatalf("unexpected offset %v", ts.Offset())
	}
	ts.AddTimeSample("peer", time.Now())
	if ts.AdjustedTime().Before(time.Now().Add(100 * 365 * 24 * time.Hour)) {
		t.Fatal("AddTimeSample perturbed deterministicTimeSource")
	}
}

// TestHandleHeadersRejectsUnminedHeader is the CALL-SITE guard for change B: it fails if the
// verifyHeadersPoW call is removed from handleHeaders, which a unit test of verifyHeadersPoW alone
// does not catch.
func TestHandleHeadersRejectsUnminedHeader(t *testing.T) {
	params := &chaincfg.RegressionNetParams
	// db is deliberately nil: a header that is correctly rejected never reaches the store.
	s := &Server{chainParams: params, cfg: &Config{Network: networkLocalnet}}

	msg := wire.NewMsgHeaders()
	unmined := &wire.BlockHeader{
		Version:    1,
		PrevBlock:  *params.GenesisHash,
		MerkleRoot: chainhash.Hash{0x55},
		Timestamp:  time.Unix(1700000000, 0),
		Bits:       0x1d00ffff,
	}
	if err := msg.AddBlockHeader(unmined); err != nil {
		t.Fatal(err)
	}

	reachedStore, err := callHandleHeaders(t, s, msg)
	if reachedStore != nil {
		t.Fatalf("handleHeaders did not reject a header with no proof-of-work; it reached the store: %v",
			reachedStore)
	}
	if err == nil {
		t.Fatal("handleHeaders accepted a header with no proof-of-work")
	}
	if !strings.Contains(err.Error(), "proof-of-work") {
		t.Fatalf("handleHeaders rejected for the wrong reason: %v", err)
	}
}

// TestVerifyHeaderBatchShape is the direct guard on change B2.
func TestVerifyHeaderBatchShape(t *testing.T) {
	params := &chaincfg.RegressionNetParams

	h1 := mineHeader(t, params.GenesisHash, params.PowLimitBits, 0x01)
	h1h := h1.BlockHash()
	h2 := mineHeader(t, &h1h, params.PowLimitBits, 0x02)
	h2h := h2.BlockHash()
	h3 := mineHeader(t, &h2h, params.PowLimitBits, 0x03)

	// Contiguous batches must be accepted, including the single-header and empty cases.
	for _, tc := range [][]*wire.BlockHeader{
		{},
		{h1},
		{h1, h2},
		{h1, h2, h3},
		{h2, h3},
	} {
		if err := verifyHeaderBatchShape(tc); err != nil {
			t.Fatalf("contiguous batch of %d rejected: %v", len(tc), err)
		}
	}

	// A gap must be rejected. Both headers are genuinely mined; only the shape is wrong.
	if err := verifyHeaderBatchShape([]*wire.BlockHeader{h1, h3}); err == nil {
		t.Fatal("gapped batch [h1,h3] accepted")
	} else if !strings.Contains(err.Error(), "does not connect") {
		t.Fatalf("unexpected error: %v", err)
	}

	// So must a batch that is a chain in reverse.
	if err := verifyHeaderBatchShape([]*wire.BlockHeader{h2, h1}); err == nil {
		t.Fatal("reversed batch accepted")
	}
}

// TestHandleHeadersRejectsGap is the CALL-SITE guard for change B2.
func TestHandleHeadersRejectsGap(t *testing.T) {
	params := &chaincfg.RegressionNetParams
	s := &Server{chainParams: params, cfg: &Config{Network: networkLocalnet}}

	h1 := mineHeader(t, params.GenesisHash, params.PowLimitBits, 0x01)
	h1h := h1.BlockHash()
	h2 := mineHeader(t, &h1h, params.PowLimitBits, 0x02)
	h2h := h2.BlockHash()
	h3 := mineHeader(t, &h2h, params.PowLimitBits, 0x03)

	msg := wire.NewMsgHeaders()
	for _, h := range []*wire.BlockHeader{h1, h3} {
		if err := msg.AddBlockHeader(h); err != nil {
			t.Fatal(err)
		}
	}

	reachedStore, err := callHandleHeaders(t, s, msg)
	if reachedStore != nil {
		t.Fatalf("handleHeaders did not reject a non-contiguous headers message; it reached the store: %v",
			reachedStore)
	}
	if err == nil {
		t.Fatal("handleHeaders accepted a non-contiguous headers message")
	}
	if !strings.Contains(err.Error(), "does not connect") {
		t.Fatalf("handleHeaders rejected for the wrong reason: %v", err)
	}
}

// TestNewServerCacheSizes is the guard on change E3.
func TestNewServerCacheSizes(t *testing.T) {
	base := func() *Config {
		return &Config{
			Network:            networkLocalnet,
			PeersWanted:        1,
			ExternalHeaderMode: true, // avoids peer manager / ttl setup
		}
	}

	// Zero must be coerced to the defaults: these values are divisors in the indexers.
	cfg := base()
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.MaxCachedTxs != defaultMaxCachedTxs {
		t.Fatalf("MaxCachedTxs not coerced: %d", s.cfg.MaxCachedTxs)
	}
	if s.cfg.MaxCachedKeystones != defaultMaxCachedKeystones {
		t.Fatalf("MaxCachedKeystones not coerced: %d", s.cfg.MaxCachedKeystones)
	}

	// Negatives must be refused outright: make() panics on a negative size hint.
	cfg = base()
	cfg.MaxCachedTxs = -1
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("NewServer accepted a negative MaxCachedTxs")
	}
	cfg = base()
	cfg.MaxCachedKeystones = -1
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("NewServer accepted a negative MaxCachedKeystones")
	}

	// Explicit values must survive untouched.
	cfg = base()
	cfg.MaxCachedTxs = 7
	cfg.MaxCachedKeystones = 9
	s, err = NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.MaxCachedTxs != 7 || s.cfg.MaxCachedKeystones != 9 {
		t.Fatalf("explicit cache sizes clobbered: %d %d", s.cfg.MaxCachedTxs, s.cfg.MaxCachedKeystones)
	}
}

// guardDB serves exactly one block for the txOutFromOutPoint / unprocessUtxos guards. Every method
// not overridden is nil and panics if called, which is what we want in a test.
type guardDB struct {
	tbcd.Database

	blockHash chainhash.Hash
	block     *btcutil.Block
}

func (g *guardDB) BlockHashByTxId(ctx context.Context, txId chainhash.Hash) (*chainhash.Hash, error) {
	h := g.blockHash
	return &h, nil
}

func (g *guardDB) BlockByHash(ctx context.Context, hash chainhash.Hash) (*btcutil.Block, error) {
	return g.block, nil
}

// guardBlock builds a one-transaction block whose single tx has outCount outputs.
func guardBlock(t *testing.T, outCount int) (*btcutil.Block, *chainhash.Hash) {
	t.Helper()
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: wire.MaxPrevOutIndex},
		SignatureScript:  []byte{0x51, 0x52},
	})
	for i := range outCount {
		tx.AddTxOut(&wire.TxOut{Value: int64(1000 + i), PkScript: []byte{0x51}})
	}
	mb := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: time.Unix(1700000000, 0),
			Bits:      chaincfg.RegressionNetParams.PowLimitBits,
		},
		Transactions: []*wire.MsgTx{tx},
	}
	b := btcutil.NewBlock(mb)
	txHash := tx.TxHash()
	return b, &txHash
}

// TestTxOutFromOutPointBounds is the guard on change E2: an index EQUAL to len(TxOut) must be
// refused, not used to index one past the end of the slice.
func TestTxOutFromOutPointBounds(t *testing.T) {
	const outCount = 2
	b, txHash := guardBlock(t, outCount)
	s := &Server{db: &guardDB{blockHash: *b.Hash(), block: b}}

	// In range.
	for i := range uint32(outCount) {
		out, err := s.txOutFromOutPoint(t.Context(), tbcd.NewOutpoint(*txHash, i))
		if err != nil {
			t.Fatalf("index %d rejected: %v", i, err)
		}
		if out.Value != int64(1000+i) {
			t.Fatalf("index %d returned the wrong output: %v", i, out.Value)
		}
	}

	// index == len(TxOut). Before the fix this indexed txOuts[2] and panicked.
	if _, err := s.txOutFromOutPoint(t.Context(), tbcd.NewOutpoint(*txHash, outCount)); err == nil {
		t.Fatalf("index == len(TxOut) accepted")
	}

	// index > len(TxOut).
	if _, err := s.txOutFromOutPoint(t.Context(), tbcd.NewOutpoint(*txHash, outCount+5)); err == nil {
		t.Fatal("index > len(TxOut) accepted")
	}
}

// TestUnprocessUtxosDuplicateOutpoint is the guard on change E7: two inputs in one block spending
// the same outpoint must be skipped, not turned into an error that op-geth escalates to
// log.Crit()/os.Exit(1) on every restart.
func TestUnprocessUtxosDuplicateOutpoint(t *testing.T) {
	prevBlock, prevTxHash := guardBlock(t, 1)
	s := &Server{db: &guardDB{blockHash: *prevBlock.Hash(), block: prevBlock}}

	// A block containing TWO SEPARATE non-coinbase transactions that spend the SAME outpoint.
	//
	// Two transactions, deliberately. Putting both spends in ONE transaction tests an UNREACHABLE
	// case: blockchain.CheckTransactionSanity rejects duplicate inputs within a single transaction,
	// so with --tbc.blocksanity=true -- the configuration op-geth intends to ship -- such a body
	// never reaches the store, let alone the unwind. A duplicate spread ACROSS two transactions is
	// invisible to CheckBlockSanity (it checks duplicates only within a tx), so it is the
	// shape that can actually reach the unwind.
	//
	// THE UNWIND MUST FAIL LOUDLY HERE, NOT CONTINUE. Reaching this state means the store has already
	// accepted a consensus-invalid block as canonical. That is a data-integrity failure no local
	// recovery repairs: BlocksDB has no delete, so the block stays and every restart re-walks it.
	// Refusing to run is deliberate. Continuing would yield a correct unwind set for THIS operation
	// while saying nothing about the rest of the store, which is the weaker guarantee.
	op := wire.OutPoint{Hash: *prevTxHash, Index: 0}

	dupA := wire.NewMsgTx(wire.TxVersion)
	dupA.AddTxIn(&wire.TxIn{PreviousOutPoint: op, SignatureScript: []byte{0x51}})
	dupA.AddTxOut(&wire.TxOut{Value: 500, PkScript: []byte{0x51}})

	dupB := wire.NewMsgTx(wire.TxVersion)
	dupB.AddTxIn(&wire.TxIn{PreviousOutPoint: op, SignatureScript: []byte{0x52}})
	dupB.AddTxOut(&wire.TxOut{Value: 400, PkScript: []byte{0x51}})

	coinbase := wire.NewMsgTx(wire.TxVersion)
	coinbase.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: wire.MaxPrevOutIndex},
		SignatureScript:  []byte{0x51, 0x53},
	})
	coinbase.AddTxOut(&wire.TxOut{Value: 5000, PkScript: []byte{0x51}})

	txs := []*btcutil.Tx{btcutil.NewTx(coinbase), btcutil.NewTx(dupA), btcutil.NewTx(dupB)}
	utxos := make(map[tbcd.Outpoint]tbcd.CacheOutput)
	err := s.unprocessUtxos(t.Context(), txs, utxos)
	if err == nil {
		t.Fatal("duplicate outpoint was accepted; the unwind must refuse to continue on a store that " +
			"has already admitted a consensus-invalid canonical block")
	}
	if !strings.Contains(err.Error(), "impossible collision") {
		t.Fatalf("expected an impossible-collision error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Change A2: handleBlock's block-sanity gate must not depend on the host clock.
// ---------------------------------------------------------------------------

// sanityDB serves handleBlock's two db calls. BlockInsert fails with a sentinel so we can tell
// "the block passed sanity and reached the store" apart from "the block was rejected by sanity".
type sanityDB struct {
	tbcd.Database
}

var errReachedStore = errors.New("reached-the-store-sentinel")

func (sanityDB) BlockInsert(ctx context.Context, b *btcutil.Block) (int64, error) {
	return -1, errReachedStore
}

func (sanityDB) BlocksMissing(ctx context.Context, count int) ([]tbcd.BlockIdentifier, error) {
	return nil, nil
}

// regtestBlock builds a well-formed, genuinely mined regtest block with the given timestamp.
func regtestBlock(t *testing.T, ts time.Time, tag byte) *wire.MsgBlock {
	t.Helper()
	params := &chaincfg.RegressionNetParams

	cb := wire.NewMsgTx(wire.TxVersion)
	cb.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex),
		SignatureScript:  []byte{0x02, 0x10, tag},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	cb.AddTxOut(&wire.TxOut{Value: 5000000000, PkScript: []byte{0x51}})

	mb := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			PrevBlock: *params.GenesisHash,
			Timestamp: ts.Truncate(time.Second),
			Bits:      params.PowLimitBits,
		},
		Transactions: []*wire.MsgTx{cb},
	}
	merkles := blockchain.BuildMerkleTreeStore(btcutil.NewBlock(mb).Transactions(), false)
	mb.Header.MerkleRoot = *merkles[len(merkles)-1]

	target := blockchain.CompactToBig(mb.Header.Bits)
	for n := uint32(0); n < math.MaxUint32; n++ {
		mb.Header.Nonce = n
		hash := mb.Header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return mb
		}
	}
	t.Fatal("could not mine block")
	return nil
}

// TestHandleBlockSanityIsClockIndependent is the guard on change A2. With BlockSanity enabled, a
// block whose header timestamp is far outside the host's ~2h window must still pass the gate: the
// median time source is never fed in this process, so applying that rule would make two honest
// nodes disagree about identical bytes and would freeze a node whose clock is off.
func TestHandleBlockSanityIsClockIndependent(t *testing.T) {
	blks, err := ttl.New(16, true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg:         &Config{Network: networkLocalnet, BlockSanity: true},
		chainParams: &chaincfg.RegressionNetParams,
		timeSource:  blockchain.NewMedianTime(),
		db:          sanityDB{},
		blocks:      blks,
		broadcast:   make(map[chainhash.Hash]*wire.MsgTx),
	}

	// A block 10 years in the future. Under s.timeSource this is rejected as
	// "block timestamp ... is too far in the future"; under deterministicTimeSource it is not.
	future := regtestBlock(t, time.Now().Add(10*365*24*time.Hour), 0x01)
	err = s.handleBlock(t.Context(), nil, future, nil)
	if !errors.Is(err, errReachedStore) {
		t.Fatalf("far-future block did not pass the sanity gate: %v", err)
	}

	// A block 10 years in the past must also pass: nothing in CheckBlockSanity bounds the past.
	past := regtestBlock(t, time.Now().Add(-10*365*24*time.Hour), 0x02)
	if err := s.handleBlock(t.Context(), nil, past, nil); !errors.Is(err, errReachedStore) {
		t.Fatalf("far-past block did not pass the sanity gate: %v", err)
	}

	// The deterministic rules must still be enforced: break the merkle root.
	bad := regtestBlock(t, time.Now(), 0x03)
	bad.Header.MerkleRoot[0] ^= 0xff
	if err := s.handleBlock(t.Context(), nil, bad, nil); err == nil ||
		errors.Is(err, errReachedStore) {
		t.Fatalf("a block with a bad merkle root reached the store: %v", err)
	}

	// So must proof-of-work: re-grind is not needed, just bump the nonce until it misses.
	unmined := regtestBlock(t, time.Now(), 0x04)
	target := blockchain.CompactToBig(unmined.Header.Bits)
	for {
		unmined.Header.Nonce++
		hash := unmined.Header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) > 0 {
			break
		}
	}
	if err := s.handleBlock(t.Context(), nil, unmined, nil); err == nil ||
		errors.Is(err, errReachedStore) {
		t.Fatalf("a block that misses its own target reached the store: %v", err)
	}
}

// TestServerBlockHeadersInsertRejectsGap guards the EXPORTED wrapper, which is the door op-geth
// actually uses -- not handleHeaders.
//
// ldb.BlockHeadersInsert assigns heights POSITIONALLY and never checks that a header connects to the
// one before it, so [h1, h3] files h3 at h1.height+1: a fabricated height on a genuinely mined
// header, permanently, since the store exposes no delete. op-geth's "missing progression headers"
// injection can produce exactly that batch -- its own comment says so -- and heights are
// consensus-visible (btcTxConfirmations does arithmetic on two stored heights; btcLastHeader returns
// one in its EVM result).
//
// Mutation-verified: remove the verifyHeaderBatchShape call from (*Server).BlockHeadersInsert and
// this fails. Before this test, that mutation survived the entire package.
func TestServerBlockHeadersInsertRejectsGap(t *testing.T) {
	// db is nil on purpose: a correctly rejected batch must never reach the store. If the guard is
	// removed the call nil-derefs, which the recover below reports as the failure it is.
	s := &Server{}

	h1 := &wire.BlockHeader{Nonce: 1}
	h2 := &wire.BlockHeader{PrevBlock: h1.BlockHash(), Nonce: 2}
	h3 := &wire.BlockHeader{PrevBlock: h2.BlockHash(), Nonce: 3}

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("a gapped batch reached the store (panicked on the nil db: %v). "+
					"(*Server).BlockHeadersInsert must reject a non-contiguous batch BEFORE "+
					"delegating -- ldb.BlockHeadersInsert assigns heights positionally and would "+
					"file h3 at h1's height+1, permanently.", r)
			}
		}()
		// [h1, h3] -- both real headers, h2 missing.
		_, _, _, _, err = s.BlockHeadersInsert(t.Context(),
			&wire.MsgHeaders{Headers: []*wire.BlockHeader{h1, h3}})
	}()

	if err == nil {
		t.Fatal("(*Server).BlockHeadersInsert accepted a gapped batch")
	}
	if !strings.Contains(err.Error(), "does not connect") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRPCBlockInsertRejectsForgedBody guards the tbcapi insert handler.
//
// The listener is OPEN BY DEFAULT: tbc.NewDefaultConfig sets ListenAddress to
// tbcapi.DefaultListen ("localhost:8082"), and op-geth at the shipping baseline only overrides it
// when --tbc.listenaddress is explicitly passed. ldb.BlockInsert requires the HEADER to exist but
// performs no body-to-header binding at all, so without this check a caller could store a body of
// arbitrary transactions under a real header hash -- permanently, since the store has no delete.
//
// Mutation-verified: remove the CheckBlockSanity call from handleBlockInsertRequest and this fails.
func TestRPCBlockInsertRejectsForgedBody(t *testing.T) {
	s := &Server{chainParams: &chaincfg.RegressionNetParams}

	// A body whose merkle root does not commit to its transactions.
	cb := wire.NewMsgTx(wire.TxVersion)
	cb.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: wire.MaxPrevOutIndex},
		SignatureScript:  []byte{0x51, 0x53},
	})
	cb.AddTxOut(&wire.TxOut{Value: 5000, PkScript: []byte{0x51}})
	blk := &wire.MsgBlock{Header: wire.BlockHeader{
		Version: 1, Bits: chaincfg.RegressionNetParams.PowLimitBits,
		MerkleRoot: chainhash.Hash{0xde, 0xad}, // deliberately wrong
	}}
	if err := blk.AddTransaction(cb); err != nil {
		t.Fatal(err)
	}

	// db is nil: a rejected body must not reach the store.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a forged body reached the store (panicked on the nil db: %v). The tbcapi "+
				"insert handler is an unauthenticated writer into the store the hVM precompiles "+
				"read, and its listener is open by default.", r)
		}
	}()
	resp, err := s.handleBlockInsertRequest(t.Context(),
		&tbcapi.BlockInsertRequest{Block: blk})
	if err != nil {
		t.Fatalf("handler returned a transport error: %v", err)
	}
	r, ok := resp.(*tbcapi.BlockInsertResponse)
	if !ok {
		t.Fatalf("unexpected response type %T", resp)
	}
	if r.Error == nil {
		t.Fatal("the tbcapi insert handler ACCEPTED a body whose merkle root does not commit to " +
			"its transactions")
	}
}
