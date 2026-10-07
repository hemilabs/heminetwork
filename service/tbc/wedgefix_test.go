// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

// TestHandleAddrV2SkipsNilAddr verifies that an addrv2 entry with a nil Addr
// is skipped instead of crashing the process, and that valid entries after it
// are still processed.
func TestHandleAddrV2SkipsNilAddr(t *testing.T) {
	pm, err := NewPeerManager(wire.TestNet3, []string{}, 8)
	if err != nil {
		t.Fatalf("peer manager: %v", err)
	}
	s := &Server{
		cfg:         &Config{},
		chainParams: &chaincfg.RegressionNetParams,
		pm:          pm,
	}

	msg := wire.NewMsgAddrV2()
	// A truncated entry decodes with a nil Addr.
	msg.AddrList = append(msg.AddrList, &wire.NetAddressV2{Addr: nil, Port: 8333})
	// A well-formed entry that must still be processed.
	msg.AddrList = append(msg.AddrList, &wire.NetAddressV2{
		Addr: &net.IPAddr{IP: net.ParseIP("198.51.100.1")}, Port: 8333,
	})

	// Must not panic. p is only used for a trace log, so nil is fine here.
	if err := s.handleAddrV2(t.Context(), nil, msg); err != nil {
		t.Fatalf("handleAddrV2 returned error: %v", err)
	}
	if _, good, _ := s.pm.Stats(); good != 1 {
		t.Fatalf("valid entry after the nil one was not processed: good=%d want 1", good)
	}
}

func TestHandleAddrV2NilAddrOnlyDoesNotPanic(t *testing.T) {
	pm, err := NewPeerManager(wire.TestNet3, []string{}, 8)
	if err != nil {
		t.Fatalf("peer manager: %v", err)
	}
	s := &Server{cfg: &Config{}, chainParams: &chaincfg.RegressionNetParams, pm: pm}
	msg := wire.NewMsgAddrV2()
	msg.AddrList = append(msg.AddrList, &wire.NetAddressV2{Addr: nil, Port: 8333})
	if err := s.handleAddrV2(t.Context(), nil, msg); err != nil {
		t.Fatalf("handleAddrV2 returned error: %v", err)
	}
	// Sanity: a genuinely nil net.Addr in the interface is what we guarded.
	a := msg.AddrList[0].Addr
	if a != nil {
		t.Fatalf("premise: entry Addr should be a nil net.Addr")
	}
}

// parentStubDB returns exactly one known parent header; every other lookup is
// not found.
type parentStubDB struct {
	tbcd.Database
	parentHash chainhash.Hash
	parent     *tbcd.BlockHeader
}

func (d *parentStubDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	if h == d.parentHash {
		return d.parent, nil
	}
	return nil, database.NotFoundError("block header not found: " + h.String())
}

// TestVerifyHeaderContextRejectsWrongDifficulty calls verifyHeaderContext
// directly on mainnet params, where it does not early-return. No mining is
// needed since CheckBlockHeaderContext checks the claimed Bits, not the header
// hash. The handleHeaders call site is covered by
// TestHandleHeadersRejectsWrongDifficulty.
func TestVerifyHeaderContextRejectsWrongDifficulty(t *testing.T) {
	parentWire := &wire.BlockHeader{
		Version:   0x20000000,
		Bits:      0x1a05db8b, // a mid-difficulty mainnet target
		Timestamp: time.Unix(1600000000, 0),
	}
	parentHash := parentWire.BlockHash()
	parentBH := &tbcd.BlockHeader{
		Hash:   parentHash,
		Height: 100000, // non-retarget height (100000 % 2016 != 0)
		Header: h2b(parentWire),
	}
	db := &parentStubDB{parentHash: parentHash, parent: parentBH}
	s := &Server{cfg: &Config{}, chainParams: &chaincfg.MainNetParams, db: db}

	mk := func(bits uint32) []*wire.BlockHeader {
		return []*wire.BlockHeader{{
			Version:   0x20000000,
			PrevBlock: parentHash,
			Bits:      bits,
			Timestamp: parentWire.Timestamp.Add(600 * time.Second),
		}}
	}

	// Wrong difficulty (min-difficulty 0x1d00ffff) at a non-retarget height
	// must be rejected; there it must equal the parent's.
	if err := s.verifyHeaderContext(t.Context(), mk(0x1d00ffff)); err == nil {
		t.Fatal("min-difficulty header accepted at a height requiring the parent difficulty")
	}
	// Correct difficulty (== parent) must be accepted.
	if err := s.verifyHeaderContext(t.Context(), mk(0x1a05db8b)); err != nil {
		t.Fatalf("correctly-difficultied header rejected: %v", err)
	}
}

func TestParamsIdentityDetectsWrongParams(t *testing.T) {
	mainnet := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, wireNet: wire.MainNet}
	testnet := &Server{cfg: &Config{Network: "testnet3"}, chainParams: &chaincfg.TestNet3Params, wireNet: wire.TestNet3}
	regtest := &Server{cfg: &Config{Network: "localnet"}, chainParams: &chaincfg.RegressionNetParams, wireNet: wire.TestNet}

	if bytes.Equal(mainnet.paramsIdentity(), testnet.paramsIdentity()) {
		t.Fatal("mainnet and testnet3 params-identity stamps must differ")
	}
	if bytes.Equal(mainnet.paramsIdentity(), regtest.paramsIdentity()) {
		t.Fatal("mainnet and regtest params-identity stamps must differ")
	}
	// A mainnet variant with a trivial PowLimitBits (same genesis) must not
	// share mainnet's stamp.
	soakParams := chaincfg.MainNetParams
	soakParams.PowLimitBits = chaincfg.RegressionNetParams.PowLimitBits
	soak := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &soakParams, wireNet: wire.MainNet}
	if bytes.Equal(mainnet.paramsIdentity(), soak.paramsIdentity()) {
		t.Fatal("soak (trivial-PoW, mainnet genesis) must not share the mainnet stamp")
	}
	// Same params -> same stamp (stable).
	mainnet2 := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, wireNet: wire.MainNet}
	if !bytes.Equal(mainnet.paramsIdentity(), mainnet2.paramsIdentity()) {
		t.Fatal("identical params must produce an identical stamp")
	}
}

// TestHandleHeadersRejectsWrongDifficulty verifies that handleHeaders calls
// verifyHeaderContext. The child is mined to a valid target so it clears
// verifyHeadersPoW, but its bits differ from its parent's at a non-retarget
// height. s.db only implements BlockHeaderByHash, so a header that reaches
// BlockHeadersInsert panics and callHandleHeaders reports it.
func TestHandleHeadersRejectsWrongDifficulty(t *testing.T) {
	// Mainnet params with regtest's easy PoW limit so the child can be
	// mined quickly. Without ReduceMinDifficulty, a header at a non-retarget
	// height must carry its parent's bits.
	params := chaincfg.MainNetParams
	params.PowLimit = chaincfg.RegressionNetParams.PowLimit
	params.PowLimitBits = chaincfg.RegressionNetParams.PowLimitBits

	// Parent at a non-retarget height (100000 % 2016 != 0) carrying harder
	// bits than the child will claim.
	parentWire := &wire.BlockHeader{
		Version:   0x20000000,
		Bits:      0x1f00ffff, // harder than the easy PoW limit
		Timestamp: time.Unix(1600000000, 0),
	}
	parentHash := parentWire.BlockHash()
	parentBH := &tbcd.BlockHeader{
		Hash:   parentHash,
		Height: 100000,
		Header: h2b(parentWire),
	}
	db := &parentStubDB{parentHash: parentHash, parent: parentBH}
	s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &params, db: db}

	// Mine a child at the easy PoW limit so verifyHeadersPoW passes. Its
	// bits differ from the parent's, which is illegal at a non-retarget
	// height. mineHeader grinds the nonce for these fields, so do not
	// mutate the header afterwards.
	child := mineHeader(t, &parentHash, params.PowLimitBits, 0x01)

	msg := wire.NewMsgHeaders()
	if err := msg.AddBlockHeader(child); err != nil {
		t.Fatal(err)
	}

	// Premise: the header really does clear the PoW gate that runs first.
	if n, err := s.verifyHeadersPoW(msg.Headers); err != nil || n != len(msg.Headers) {
		t.Fatalf("premise: mined child must clear verifyHeadersPoW: %v, %v", n, err)
	}

	reachedStore, err := callHandleHeaders(t, s, msg)
	if reachedStore != nil {
		t.Fatalf("call site: wrong-difficulty header reached the store: %v", reachedStore)
	}
	if err == nil {
		t.Fatal("call site: handleHeaders accepted a wrong-difficulty header")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Fatalf("call site: rejected for the wrong reason: %v", err)
	}
}

// TestVerifyHeaderContextNoRetargetEarlyReturn verifies that
// verifyHeaderContext returns nil on PoWNoRetargeting networks without
// touching the store (s.db is nil).
func TestVerifyHeaderContextNoRetargetEarlyReturn(t *testing.T) {
	s := &Server{cfg: &Config{Network: networkLocalnet}, chainParams: &chaincfg.RegressionNetParams}
	// Bits that WOULD be wrong on a retargeting network.
	hdr := &wire.BlockHeader{
		PrevBlock: chainhash.Hash{0x01},
		Bits:      0x1d00ffff,
		Timestamp: time.Unix(1700000000, 0),
	}
	if err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{hdr}); err != nil {
		t.Fatalf("localnet verifyHeaderContext must early-return nil, got %v", err)
	}
}

// ioErrParentDB returns the parent header and fails every other lookup with a
// non-NotFound error, which verifyHeaderContext must report as a store fault.
type ioErrParentDB struct {
	tbcd.Database
	parentHash chainhash.Hash
	parent     *tbcd.BlockHeader
}

func (d *ioErrParentDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	if h == d.parentHash {
		return d.parent, nil
	}
	return nil, errors.New("simulated i/o error")
}

// TestVerifyHeaderContextSurfacesAncestorWalkError verifies that a store fault
// during the ancestor walk is reported as such, not as a context rejection.
// The child's bits match its parent's, so the difficulty check passes and
// median-time-past walks into the failing grandparent lookup. The child's
// timestamp also fails median-time-past; the walk error must be reported
// instead.
func TestVerifyHeaderContextSurfacesAncestorWalkError(t *testing.T) {
	parentWire := &wire.BlockHeader{
		Version:   0x20000000,
		Bits:      0x1a05db8b,
		Timestamp: time.Unix(1600000000, 0),
		PrevBlock: chainhash.Hash{0xaa}, // grandparent: its lookup errors
	}
	parentHash := parentWire.BlockHash()
	parentBH := &tbcd.BlockHeader{
		Hash:   parentHash,
		Height: 100000, // non-retarget: difficulty rule does not walk; MTP does
		Header: h2b(parentWire),
	}
	db := &ioErrParentDB{parentHash: parentHash, parent: parentBH}
	s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, db: db}

	child := &wire.BlockHeader{
		Version:   0x20000000,
		PrevBlock: parentHash,
		Bits:      0x1a05db8b,           // == parent -> difficulty check passes
		Timestamp: parentWire.Timestamp, // not After(median) -> MTP would reject
	}
	err := s.verifyHeaderContext(t.Context(), []*wire.BlockHeader{child})
	if err == nil {
		t.Fatal("expected the ancestor-walk I/O fault to be surfaced")
	}
	if !strings.Contains(err.Error(), "ancestor walk") {
		t.Fatalf("expected retryable ancestor-walk error, got: %v", err)
	}
}

// TestAcceptPeerHeight verifies that the peer gate compares a peer's height
// against our indexed block frontier, not the header tip. The header tip
// routinely leads block download, so gating on it rejects the peers that hold
// the blocks we still need.
func TestAcceptPeerHeight(t *testing.T) {
	// An honest peer near the mainnet tip, our indexed frontier well behind
	// it, and a header tip that leads the frontier.
	const (
		incidentPeer     = int32(965000)
		incidentFrontier = uint64(800000)
		incidentTip      = uint64(970000)
	)

	for _, tc := range []struct {
		name       string
		remoteLast int32
		frontier   uint64
		want       bool
	}{
		{"peer above frontier, tip higher", incidentPeer, incidentFrontier, true},
		{"peer genuinely below frontier", 700000, 800000, false},
		{"peer exactly at frontier", 800000, 800000, true},
		{"peer one below frontier", 799999, 800000, false},
		{"fresh node, zero frontier", 1, 0, true},
	} {
		if got := acceptPeerHeight(tc.remoteLast, tc.frontier); got != tc.want {
			t.Errorf("%s: acceptPeerHeight(%d, %d) = %v, want %v",
				tc.name, tc.remoteLast, tc.frontier, got, tc.want)
		}
	}

	// The same peer is accepted against the frontier but would be rejected
	// against the header tip.
	if !acceptPeerHeight(incidentPeer, incidentFrontier) {
		t.Fatal("peer above the indexed frontier must be accepted")
	}
	if acceptPeerHeight(incidentPeer, incidentTip) {
		t.Fatal("premise: gating on the header tip would false-reject this honest peer")
	}
}

// identityStubDB implements the parts of tbcd.Database that
// verifyDatadirIdentity uses: the canonical tip, index heads, hash lookups and
// a metadata map in which the stamp write can be observed.
type identityStubDB struct {
	tbcd.Database
	best   *tbcd.BlockHeader
	byHash map[chainhash.Hash]*tbcd.BlockHeader
	meta   map[string][]byte
	// Index heads; nil means "never indexed" (NotFound -> genesis fallback).
	utxo, tx, keystone *tbcd.BlockHeader
}

func identityIndex(bh *tbcd.BlockHeader) (*tbcd.BlockHeader, error) {
	if bh == nil {
		return nil, database.NotFoundError("index not found")
	}
	return bh, nil
}

func (d *identityStubDB) BlockHeaderByUtxoIndex(context.Context) (*tbcd.BlockHeader, error) {
	return identityIndex(d.utxo)
}

func (d *identityStubDB) BlockHeaderByTxIndex(context.Context) (*tbcd.BlockHeader, error) {
	return identityIndex(d.tx)
}

func (d *identityStubDB) BlockHeaderByKeystoneIndex(context.Context) (*tbcd.BlockHeader, error) {
	return identityIndex(d.keystone)
}

func (d *identityStubDB) BlockHeaderBest(context.Context) (*tbcd.BlockHeader, error) {
	if d.best == nil {
		return nil, database.NotFoundError("no best header")
	}
	return d.best, nil
}

func (d *identityStubDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	if bh, ok := d.byHash[h]; ok {
		return bh, nil
	}
	return nil, database.NotFoundError("block header not found")
}

func (d *identityStubDB) MetadataGet(_ context.Context, key []byte) ([]byte, error) {
	if v, ok := d.meta[string(key)]; ok {
		return v, nil
	}
	return nil, database.NotFoundError("metadata not found")
}

func (d *identityStubDB) MetadataPut(_ context.Context, key, value []byte) error {
	if d.meta == nil {
		d.meta = make(map[string][]byte)
	}
	d.meta[string(key)] = append([]byte(nil), value...)
	return nil
}

func bhFromWire(w *wire.BlockHeader, height uint64) *tbcd.BlockHeader {
	return &tbcd.BlockHeader{Hash: w.BlockHash(), Height: height, Header: h2b(w)}
}

// TestVerifyDatadirIdentity verifies that on mainnet the datadir-identity gate
// refuses a trivial-PoW tip with no stored checkpoint below it, stamps a legacy
// datadir once, and refuses a datadir stamped for another network or missing
// the configured genesis. Off mainnet it is a no-op.
func TestVerifyDatadirIdentity(t *testing.T) {
	genesis := &chaincfg.MainNetParams.GenesisBlock.Header
	genesisBH := bhFromWire(genesis, 0)

	t.Run("trivial-PoW tip on mainnet is refused", func(t *testing.T) {
		trivial := &wire.BlockHeader{
			Version:   1,
			Bits:      chaincfg.RegressionNetParams.PowLimitBits, // above mainnet PowLimit
			Timestamp: time.Unix(1600000000, 0),
		}
		// The mainnet genesis is present, so the genesis check alone
		// would pass. No checkpoint is stored below the trivial-PoW
		// tip, so the tip proof-of-work check refuses this datadir.
		db := &identityStubDB{
			best:   bhFromWire(trivial, 500000),
			byHash: map[chainhash.Hash]*tbcd.BlockHeader{*chaincfg.MainNetParams.GenesisHash: genesisBH},
		}
		s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, wireNet: wire.MainNet, db: db}
		err := s.verifyDatadirIdentity(t.Context())
		if err == nil {
			t.Fatal("trivial-PoW tip must be refused on mainnet")
		}
		if !strings.Contains(err.Error(), "proof-of-work") && !strings.Contains(err.Error(), "network mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, stamped := db.meta[string(paramsIdentityKey)]; stamped {
			t.Fatal("a refused datadir must not be stamped")
		}
	})

	t.Run("legacy mainnet back-fill is nil and idempotent", func(t *testing.T) {
		db := &identityStubDB{
			best:   genesisBH,
			byHash: map[chainhash.Hash]*tbcd.BlockHeader{*chaincfg.MainNetParams.GenesisHash: genesisBH},
		}
		s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, wireNet: wire.MainNet, db: db}
		if err := s.verifyDatadirIdentity(t.Context()); err != nil {
			t.Fatalf("legacy back-fill must succeed: %v", err)
		}
		got, ok := db.meta[string(paramsIdentityKey)]
		if !ok {
			t.Fatal("legacy back-fill must write the params-identity stamp")
		}
		if !bytes.Equal(got, s.paramsIdentity()) {
			t.Fatal("back-filled stamp must be the configured params identity")
		}
		// Second call: stamp now present -> still nil (idempotent).
		if err := s.verifyDatadirIdentity(t.Context()); err != nil {
			t.Fatalf("idempotent second call must succeed: %v", err)
		}
	})

	t.Run("stamp for the wrong network is refused", func(t *testing.T) {
		testnetStamp := (&Server{chainParams: &chaincfg.TestNet3Params, wireNet: wire.TestNet3}).paramsIdentity()
		db := &identityStubDB{
			best: genesisBH,
			meta: map[string][]byte{string(paramsIdentityKey): testnetStamp},
		}
		s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, wireNet: wire.MainNet, db: db}
		err := s.verifyDatadirIdentity(t.Context())
		if err == nil {
			t.Fatal("a datadir stamped for testnet3 must be refused on mainnet")
		}
		if !strings.Contains(err.Error(), "stamped for a") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("legacy mainnet with configured genesis absent is refused, not stamped", func(t *testing.T) {
		// The tip (the mainnet genesis header) passes the proof-of-work
		// check and there is no stamp, so the legacy path runs, but the
		// configured genesis is not stored, so the datadir must be
		// refused unstamped.
		db := &identityStubDB{
			best:   genesisBH,
			byHash: map[chainhash.Hash]*tbcd.BlockHeader{}, // configured genesis absent
			// meta nil -> MetadataGet returns NotFound -> legacy back-fill path.
		}
		s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, wireNet: wire.MainNet, db: db}
		err := s.verifyDatadirIdentity(t.Context())
		if err == nil {
			t.Fatal("a legacy mainnet datadir missing the configured genesis must be refused")
		}
		if !strings.Contains(err.Error(), "genesis") || !strings.Contains(err.Error(), "absent") {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, stamped := db.meta[string(paramsIdentityKey)]; stamped {
			t.Fatal("a refused datadir must not be stamped")
		}
	})

	t.Run("non-mainnet is a no-op regardless of tip", func(t *testing.T) {
		// best is nil; non-mainnet must return before reading it.
		db := &identityStubDB{}
		s := &Server{cfg: &Config{Network: "testnet3"}, chainParams: &chaincfg.TestNet3Params, wireNet: wire.TestNet3, db: db}
		if err := s.verifyDatadirIdentity(t.Context()); err != nil {
			t.Fatalf("non-mainnet must return nil: %v", err)
		}
	})
}

// peerGateStubDB returns distinct headers for the indexed frontier and the
// header tip, so a test can tell which one the peer-acceptance gate consults.
type peerGateStubDB struct {
	tbcd.Database
	utxo *tbcd.BlockHeader // indexed (UTXO) frontier
	best *tbcd.BlockHeader // header tip
}

func (d *peerGateStubDB) BlockHeaderByUtxoIndex(context.Context) (*tbcd.BlockHeader, error) {
	return d.utxo, nil
}

func (d *peerGateStubDB) BlockHeaderBest(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

// TestPeerHeightAcceptableUsesFrontierNotTip verifies that the peer gate reads
// the indexed frontier (UtxoIndexHash) rather than the header tip
// (BlockHeaderBest).
func TestPeerHeightAcceptableUsesFrontierNotTip(t *testing.T) {
	s := &Server{cfg: &Config{Network: networkLocalnet}, chainParams: &chaincfg.RegressionNetParams}
	mk := func(h uint64) *tbcd.BlockHeader {
		return &tbcd.BlockHeader{Height: h, Header: h2b(&s.chainParams.GenesisBlock.Header)}
	}
	// Frontier well behind the header tip.
	s.db = &peerGateStubDB{utxo: mk(800000), best: mk(970000)}

	// Peer at 965000: above the indexed frontier (800000) but below the
	// header tip (970000). It must be accepted.
	accept, err := s.peerHeightAcceptable(t.Context(), 965000)
	if err != nil {
		t.Fatalf("peerHeightAcceptable: %v", err)
	}
	if !accept {
		t.Fatal("call site: a peer above the indexed frontier was rejected; " +
			"the gate is reading the header tip, not the frontier")
	}

	// A peer genuinely below the frontier is rejected.
	accept, err = s.peerHeightAcceptable(t.Context(), 700000)
	if err != nil {
		t.Fatalf("peerHeightAcceptable: %v", err)
	}
	if accept {
		t.Fatal("a peer below the indexed frontier must be rejected")
	}
}
