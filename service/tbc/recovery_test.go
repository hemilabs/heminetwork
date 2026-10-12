// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
)

// wirePeer wraps a real rawpeer.RawPeer over net.Pipe and decodes what it
// writes. Tests assert on the messages that reach the wire, so they also pin
// the encoding of the request, such as which hashes go into a getheaders block
// locator.
type wirePeer struct {
	rp   *rawpeer.RawPeer
	msgs chan wire.Message
	errs chan error
}

func newWirePeer(t *testing.T, btcnet wire.BitcoinNet, id int) *wirePeer {
	t.Helper()

	local, remote := net.Pipe()
	rp, err := rawpeer.NewFromConn(local, btcnet, wire.ProtocolVersion, id)
	if err != nil {
		t.Fatalf("new from conn: %v", err)
	}
	t.Cleanup(func() {
		local.Close()
		remote.Close()
	})

	wp := &wirePeer{
		rp:   rp,
		msgs: make(chan wire.Message, 64),
		errs: make(chan error, 1),
	}
	go func() {
		for {
			// NewFromConn pins protocolVersion to wire.AddrV2Version;
			// decode with the same version.
			_, msg, _, err := wire.ReadMessageWithEncodingN(remote,
				wire.AddrV2Version, btcnet, wire.LatestEncoding)
			if err != nil {
				select {
				case wp.errs <- err:
				default:
				}
				return
			}
			wp.msgs <- msg
		}
	}()
	return wp
}

func (wp *wirePeer) next(t *testing.T, within time.Duration) wire.Message {
	t.Helper()
	select {
	case m := <-wp.msgs:
		return m
	case err := <-wp.errs:
		t.Fatalf("peer read error: %v", err)
	case <-time.After(within):
		t.Fatalf("nothing was written to the peer within %v", within)
	}
	return nil
}

func (wp *wirePeer) silent(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case m := <-wp.msgs:
		t.Fatalf("unexpected %v written to the peer", m.Command())
	case <-time.After(within):
	}
}

func addPeers(t *testing.T, s *Server, n int) []*wirePeer {
	t.Helper()

	out := make([]*wirePeer, 0, n)
	s.pm.mtx.Lock()
	defer s.pm.mtx.Unlock()
	for i := range n {
		wp := newWirePeer(t, s.wireNet, i)
		out = append(out, wp)
		s.pm.peers[fmt.Sprintf("peer%d", i)] = wp.rp
	}
	return out
}

// recoveryStubDB is an in-memory tbcd.Database stub covering the store calls
// made by headersPeer, the syncBlocks drain, handleBlockExpired, handleInv and
// synced.
type recoveryStubDB struct {
	tbcd.Database

	best    *tbcd.BlockHeader
	headers map[chainhash.Hash]*tbcd.BlockHeader
	missing []tbcd.BlockIdentifier

	// BlockMissingDelete accounting for handleBlockExpired's delete path.
	missingDeletes   int
	lastDeleteHeight int64
	lastDeleteHash   chainhash.Hash

	// headerByHashCalls counts BlockHeaderByHash reads, for the handleInv
	// block-scan cap test.
	headerByHashCalls int

	// blocksMissingErr, when set, is returned by BlocksMissing (for the
	// synced() error-path test).
	blocksMissingErr error
}

func (d *recoveryStubDB) BlockMissingDelete(_ context.Context, height int64, hash chainhash.Hash) error {
	d.missingDeletes++
	d.lastDeleteHeight = height
	d.lastDeleteHash = hash
	return nil
}

func (d *recoveryStubDB) BlockHeaderBest(context.Context) (*tbcd.BlockHeader, error) {
	if d.best == nil {
		return nil, database.NotFoundError("no best block header")
	}
	return d.best, nil
}

func (d *recoveryStubDB) BlockHeaderByHash(_ context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	d.headerByHashCalls++
	if bh, ok := d.headers[h]; ok {
		return bh, nil
	}
	return nil, database.NotFoundError("block header not found: " + h.String())
}

func (d *recoveryStubDB) BlockHeaderByUtxoIndex(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

func (d *recoveryStubDB) BlockHeaderByTxIndex(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

func (d *recoveryStubDB) BlockHeaderByKeystoneIndex(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

func (d *recoveryStubDB) BlocksMissing(_ context.Context, count int) ([]tbcd.BlockIdentifier, error) {
	if d.blocksMissingErr != nil {
		return nil, d.blocksMissingErr
	}
	// Honour count like the real store. syncBlocks asks for
	// defaultPendingBlocks - s.blocks.Len(), and ignoring count would hide
	// an overflow of that budget.
	if count >= 0 && count < len(d.missing) {
		return d.missing[:count], nil
	}
	return d.missing, nil
}

// BlockHeadersByHeight answers from the same map BlockHeaderByHash uses, so a
// locator built from heights resolves whatever the test seeded. A height with
// no header returns NotFound, which getHeadersByHeights skips.
func (d *recoveryStubDB) BlockHeadersByHeight(_ context.Context, height uint64) ([]tbcd.BlockHeader, error) {
	// Return every header at the height, like the real store, so forked
	// heights exercise the per-sibling loop in getHeadersByHeights. Sort by
	// hash so the result does not depend on map iteration order.
	var out []tbcd.BlockHeader
	for _, bh := range d.headers {
		if bh.Height == height {
			out = append(out, *bh)
		}
	}
	if len(out) == 0 {
		return nil, database.NotFoundError("no block headers at height")
	}
	slices.SortFunc(out, func(a, b tbcd.BlockHeader) int {
		return bytes.Compare(a.Hash[:], b.Hash[:])
	})
	return out, nil
}

func newRecoveryServer(t *testing.T) (*Server, *recoveryStubDB) {
	t.Helper()

	cfg := NewDefaultConfig()
	cfg.Network = networkLocalnet
	cfg.MempoolEnabled = false
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Tip is regtest genesis, self-consistent: Hash really is the hash of
	// Header. That matters here because the drain runs the real indexers,
	// which read the header bytes.
	tip := &tbcd.BlockHeader{
		Hash:   *s.chainParams.GenesisHash,
		Height: 0,
		Header: h2b(&s.chainParams.GenesisBlock.Header),
	}
	db := &recoveryStubDB{
		best:    tip,
		headers: map[chainhash.Hash]*tbcd.BlockHeader{tip.Hash: tip},
	}
	s.db = db
	return s, db
}

// ===========================================================================
// getheaders locators, and the syncBlocks drain
// ===========================================================================

// TestGetHeadersByHashesPutsItsArgumentsInTheLocator checks that
// getHeadersByHashes puts its arguments in the block locator, which means "I
// am at these hashes, send what follows". Passing hashes we do not have asks
// for their children, never for the blocks themselves.
func TestGetHeadersByHashesPutsItsArgumentsInTheLocator(t *testing.T) {
	s, _ := newRecoveryServer(t)
	peers := addPeers(t, s, 1)

	a := chainhash.Hash{0xa1}
	b := chainhash.Hash{0xb2}
	go func() {
		if err := s.getHeadersByHashes(t.Context(), peers[0].rp, &a, &b); err != nil {
			t.Errorf("getHeadersByHashes: %v", err)
		}
	}()

	gh, ok := peers[0].next(t, 5*time.Second).(*wire.MsgGetHeaders)
	if !ok {
		t.Fatal("want a getheaders")
	}
	if len(gh.BlockLocatorHashes) != 2 ||
		*gh.BlockLocatorHashes[0] != a || *gh.BlockLocatorHashes[1] != b {
		t.Fatalf("locator = %v, want [%v %v]", gh.BlockLocatorHashes, a, b)
	}
}

// stubHeader builds a tbcd.BlockHeader whose Hash is the hash of its Header
// bytes. getHeadersByHeights hashes the header bytes, not Hash, so a stub
// where the two disagree puts an unexpected hash in the locator.
func stubHeader(t *testing.T, s *Server, height uint64, nonce uint32) *tbcd.BlockHeader {
	t.Helper()
	wh := s.chainParams.GenesisBlock.Header
	wh.Nonce = nonce
	return &tbcd.BlockHeader{
		Hash:   wh.BlockHash(),
		Height: height,
		Header: h2b(&wh),
	}
}

// TestHeadersPeerAnchorsLocatorToOurTip checks that the refresh locator starts
// at our canonical tip and has a zero hash stop.
func TestHeadersPeerAnchorsLocatorToOurTip(t *testing.T) {
	s, db := newRecoveryServer(t)
	tip := stubHeader(t, s, 5, 0x11111111)
	db.best = tip
	db.headers[tip.Hash] = tip
	peers := addPeers(t, s, 1)

	go s.headersPeer(t.Context(), peers[0].rp)

	gh, ok := peers[0].next(t, 5*time.Second).(*wire.MsgGetHeaders)
	if !ok {
		t.Fatal("want a getheaders")
	}
	// The tip must lead the locator. Further anchors may follow; on this
	// short chain only genesis resolves besides the tip.
	if len(gh.BlockLocatorHashes) == 0 || *gh.BlockLocatorHashes[0] != tip.Hash {
		t.Fatalf("locator = %v, want it to start at our own tip %v",
			gh.BlockLocatorHashes, tip.Hash)
	}
	if !gh.HashStop.IsEqual(&chainhash.Hash{}) {
		t.Fatalf("hash stop = %v, want zero", gh.HashStop)
	}
}

// TestHeadersPeerLocatorIncludesAncestors checks that the refresh locator
// carries an ancestor after our tip, so a peer that does not know our tip can
// find a common ancestor instead of replying from genesis.
func TestHeadersPeerLocatorIncludesAncestors(t *testing.T) {
	s, db := newRecoveryServer(t)

	tip := stubHeader(t, s, 2000, 0x22222222)
	anc := stubHeader(t, s, 1000, 0x33333333) // == tip.Height-1000
	db.best = tip
	db.headers[tip.Hash] = tip
	db.headers[anc.Hash] = anc
	peers := addPeers(t, s, 1)

	go s.headersPeer(t.Context(), peers[0].rp)

	gh, ok := peers[0].next(t, 5*time.Second).(*wire.MsgGetHeaders)
	if !ok {
		t.Fatal("want a getheaders")
	}
	if len(gh.BlockLocatorHashes) < 2 {
		t.Fatalf("locator = %v, want our tip plus at least one ancestor; a "+
			"single-hash locator makes a peer that does not know our tip "+
			"reply from genesis, forever", gh.BlockLocatorHashes)
	}
	if *gh.BlockLocatorHashes[0] != tip.Hash {
		t.Fatalf("locator[0] = %v, want our own tip %v",
			gh.BlockLocatorHashes[0], tip.Hash)
	}
	if *gh.BlockLocatorHashes[1] != anc.Hash {
		t.Fatalf("locator[1] = %v, want the ancestor %v",
			gh.BlockLocatorHashes[1], anc.Hash)
	}
}

// drainServer returns a server whose next syncBlocks takes the drain branch,
// with missed preloaded into invBlocks.
func drainServer(t *testing.T, missed ...chainhash.Hash) (*Server, *recoveryStubDB) {
	t.Helper()

	s, db := newRecoveryServer(t)
	s.cfg.AutoIndex = true
	db.missing = nil // nothing to download -> take the indexing/drain branch

	ib := make(map[chainhash.Hash]struct{}, len(missed))
	for i := range missed {
		ib[missed[i]] = struct{}{}
	}
	s.mtx.Lock()
	s.invBlocks = ib
	s.mtx.Unlock()
	return s, db
}

// TestSyncBlocksDrainAsksFromOurTipNotFromTheAnnouncedHashes drives the real
// drain and checks that its getheaders is anchored on our tip. The announced
// hashes are blocks we do not have, so as a locator they would only ask for
// their children, and there can be far more of them than Bitcoin Core's
// 101-entry locator limit.
func TestSyncBlocksDrainAsksFromOurTipNotFromTheAnnouncedHashes(t *testing.T) {
	missedA := chainhash.Hash{0xa1}
	missedB := chainhash.Hash{0xb2}
	s, db := drainServer(t, missedA, missedB)
	peers := addPeers(t, s, 1)

	go s.syncBlocks(t.Context())

	gh, ok := peers[0].next(t, 10*time.Second).(*wire.MsgGetHeaders)
	if !ok {
		t.Fatal("the drain sent no getheaders")
	}
	for _, h := range gh.BlockLocatorHashes {
		if *h == missedA || *h == missedB {
			t.Fatalf("the drain put a hash we do NOT have (%v) in the getheaders "+
				"block locator. A locator means \"this is where I am\", so the "+
				"peer answers with the CHILDREN of that hash and never sends the "+
				"block itself: the gap can never close.", h)
		}
	}
	// The tip must LEAD the locator; further anchors may follow.
	if len(gh.BlockLocatorHashes) == 0 || *gh.BlockLocatorHashes[0] != db.best.Hash {
		t.Fatalf("locator = %v, want it to start at our own tip %v",
			gh.BlockLocatorHashes, db.best.Hash)
	}

	// The drain swaps in a fresh invBlocks before the fan-out and never
	// re-inserts drained hashes, so invBlocks must still be empty.
	time.Sleep(500 * time.Millisecond)
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if len(s.invBlocks) != 0 {
		t.Fatalf("the fan-out went out but invBlocks holds %v; the drain must "+
			"not re-insert drained hashes", s.invBlocks)
	}
}

// TestSyncBlocksDrainFiltersAndClearsInventory checks that the drain clears
// invBlocks even when no request can go out. The drained hashes are dropped,
// not re-inserted; the periodic refresh in Run re-asks the same tip-anchored
// question within headerRefreshInterval.
func TestSyncBlocksDrainFiltersAndClearsInventory(t *testing.T) {
	missedA := chainhash.Hash{0xa1}
	missedB := chainhash.Hash{0xb2}
	// alreadyHave is a header we already store. The have-filter does not
	// count it, but the drain must still clear it with the rest.
	s, db := drainServer(t, missedA, missedB)
	have := stubHeader(t, s, 1, 0x51)
	alreadyHave := have.Hash
	db.headers[alreadyHave] = have
	s.mtx.Lock()
	s.invBlocks[alreadyHave] = struct{}{}
	s.mtx.Unlock()
	// No peers: nothing can go out.

	s.syncBlocks(t.Context())

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.mtx.Lock()
		n := len(s.invBlocks)
		s.mtx.Unlock()
		if n == 0 {
			return // drained and cleared, as designed
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mtx.Lock()
	defer s.mtx.Unlock()
	t.Fatalf("the drain did not run: invBlocks = %v, want it drained and "+
		"cleared (recovery then rides on the periodic refresh)", s.invBlocks)
}

// TestSyncBlocksDrainIsSilentWhenNothingWasMissed pins the missed != 0 gate.
// A synced peer answers getheaders with an empty headers message, which kicks
// syncBlocks again, so an unconditional request loops forever on an idle node.
func TestSyncBlocksDrainIsSilentWhenNothingWasMissed(t *testing.T) {
	s, _ := drainServer(t) // no missed announcements
	peers := addPeers(t, s, 1)

	s.syncBlocks(t.Context())
	peers[0].silent(t, time.Second)
}

// TestSyncBlocksDrainDropsHashesWeAlreadyHave checks the have-filter: an
// announcement whose header we learned during indexing must not trigger a
// fan-out.
func TestSyncBlocksDrainDropsHashesWeAlreadyHave(t *testing.T) {
	s, db := drainServer(t)
	have := stubHeader(t, s, 1, 0x52)
	known := have.Hash
	db.headers[known] = have
	s.mtx.Lock()
	s.invBlocks[known] = struct{}{}
	s.mtx.Unlock()
	peers := addPeers(t, s, 1)

	s.syncBlocks(t.Context())
	peers[0].silent(t, time.Second)
}

// TestSyncBlocksDrainHasNoSharedErrRace is a -race test for the drain:
// invBlocks must be swapped for a fresh map rather than cleared, since peers
// keep inserting while the drain walks the old one.
func TestSyncBlocksDrainHasNoSharedErrRace(t *testing.T) {
	a := chainhash.Hash{0xa1}
	b := chainhash.Hash{0xb2}
	s, _ := drainServer(t, a, b)
	peers := addPeers(t, s, 8)
	for _, p := range peers {
		go func() {
			for range p.msgs {
			}
		}()
	}

	// Concurrent announcements while the drain runs.
	stop := make(chan struct{})
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			h := chainhash.Hash{}
			h[0], h[1] = byte(i), byte(i>>8)
			s.invInsert(h)
		}
	}()

	s.syncBlocks(t.Context())
	time.Sleep(500 * time.Millisecond)
	close(stop)
}

// TestLocatorStaysUnderCoreLimitWhenAHeightIsFlooded floods every locator
// height with siblings and checks that the locator on the wire stays under
// Bitcoin Core's MAX_LOCATOR_SZ (101); Core disconnects a peer that sends more.
// On mainnet verifyHeaderContext rejects difficulty-1 siblings over P2P once
// the difficulty has risen above 1, but the external header APIs and data
// stored before that check can still hold them.
func TestLocatorStaysUnderCoreLimitWhenAHeightIsFlooded(t *testing.T) {
	s, db := newRecoveryServer(t)

	// A tip high enough that all four query heights are distinct.
	tip := stubHeader(t, s, 5000, 0x01)
	db.best = tip
	db.headers[tip.Hash] = tip

	// Flood every height the locator derives.
	for _, h := range []uint64{5000, 4000, 3001, 0} {
		for i := range 150 {
			sib := stubHeader(t, s, h, uint32(0x1000+int(h)+i))
			db.headers[sib.Hash] = sib
		}
	}

	peers := addPeers(t, s, 1)
	go s.headersPeer(t.Context(), peers[0].rp)

	msg, ok := peers[0].next(t, 5*time.Second).(*wire.MsgGetHeaders)
	if !ok {
		t.Fatal("peer did not receive a getheaders")
	}
	n := len(msg.BlockLocatorHashes)
	if n > maxLocatorEntries {
		t.Fatalf("locator carried %v entries, past the %v bound", n, maxLocatorEntries)
	}
	if n >= 101 {
		t.Fatalf("locator carried %v entries; Bitcoin Core disconnects above "+
			"101, and the 60s refresh sends this to EVERY peer, so a single "+
			"poisoned height costs us the whole Core peer set once a minute, "+
			"across restarts", n)
	}
	if n == 0 {
		t.Fatal("locator is empty; the bound truncated everything")
	}
	t.Logf("flooded 4 heights with 150 siblings each -> locator %v entries", n)
}

// TestCanonicalTipSurvivesSiblingFlooding checks that our canonical tip leads
// the locator however many siblings share its height. The per-height cap keeps
// the first siblings in hash order, and an attacker can grind hashes that sort
// first. A locator with none of our chain matches nothing and the peer replies
// from genesis, so headersPeer seeds the tip from BlockHeaderBest.
func TestCanonicalTipSurvivesSiblingFlooding(t *testing.T) {
	s, db := newRecoveryServer(t)

	tip := stubHeader(t, s, 5000, 0x02)
	db.best = tip
	db.headers[tip.Hash] = tip

	// Flood the tip's height and the deeper anchors with siblings, some of
	// which sort ahead of the tip.
	planted := 0
	for _, h := range []uint64{5000, 4000, 3001, 0} {
		for i := range 200 {
			sib := stubHeader(t, s, h, uint32(0x7000+int(h)*7+i))
			if h == tip.Height && sib.Hash == tip.Hash {
				continue
			}
			db.headers[sib.Hash] = sib
			planted++
		}
	}

	peers := addPeers(t, s, 1)
	go s.headersPeer(t.Context(), peers[0].rp)

	msg, ok := peers[0].next(t, 5*time.Second).(*wire.MsgGetHeaders)
	if !ok {
		t.Fatal("peer did not receive a getheaders")
	}
	if len(msg.BlockLocatorHashes) == 0 {
		t.Fatal("locator is empty")
	}
	if len(msg.BlockLocatorHashes) >= 101 {
		t.Fatalf("locator carried %v entries; Core disconnects above 101",
			len(msg.BlockLocatorHashes))
	}

	if !msg.BlockLocatorHashes[0].IsEqual(&tip.Hash) {
		t.Fatalf("locator leads with %v, not our canonical tip %v, after %v "+
			"planted siblings. A locator that contains none of our chain "+
			"matches nothing at the peer, which then answers from GENESIS: "+
			"duplicate headers forever and no progress, with no self-"+
			"correcting path because the planted headers are in OUR store.",
			msg.BlockLocatorHashes[0], tip.Hash, planted)
	}
}

// TestLocatorCapsAreIndependentlyLoadBearing checks maxLocatorPerHeight on its
// own by counting how many of one height's siblings reach the locator. The
// flood test above stays under Core's limit with either cap removed, so it
// cannot tell whether the per-height cap is enforced.
func TestLocatorCapsAreIndependentlyLoadBearing(t *testing.T) {
	s, db := newRecoveryServer(t)

	tip := stubHeader(t, s, 5000, 0x03)
	db.best = tip
	db.headers[tip.Hash] = tip

	// Many siblings at ONE anchor height only. With the per-height cap gone,
	// maxLocatorEntries (16) would still let 15 of them through.
	const planted = 60
	sibs := make(map[chainhash.Hash]struct{}, planted)
	for i := range planted {
		sib := stubHeader(t, s, 4000, uint32(0x9000+i))
		db.headers[sib.Hash] = sib
		sibs[sib.Hash] = struct{}{}
	}

	peers := addPeers(t, s, 1)
	go s.headersPeer(t.Context(), peers[0].rp)
	msg, ok := peers[0].next(t, 5*time.Second).(*wire.MsgGetHeaders)
	if !ok {
		t.Fatal("peer did not receive a getheaders")
	}

	fromThatHeight := 0
	for _, h := range msg.BlockLocatorHashes {
		if _, ok := sibs[*h]; ok {
			fromThatHeight++
		}
	}
	if fromThatHeight > maxLocatorPerHeight {
		t.Fatalf("one height contributed %v locator entries out of %v planted "+
			"siblings; maxLocatorPerHeight is %v. Without a per-height cap a "+
			"single poisoned anchor drives the locator past Core's 101-entry "+
			"limit and we are disconnected by every Core peer, every refresh.",
			fromThatHeight, planted, maxLocatorPerHeight)
	}
	if fromThatHeight == 0 {
		t.Fatal("that height contributed nothing; the fixture is not exercising " +
			"the per-height path")
	}
	t.Logf("locator=%v entries, %v from the flooded height",
		len(msg.BlockLocatorHashes), fromThatHeight)
}

// TestHandleBlockExpiredDiscardsCanonicalErrorAndDeletes checks that an
// isCanonical error is discarded, as upstream does (PR #659): the block is
// treated as not canonical and deleted from blocks-missing. Returning the
// error would close the peer and stall sync.
func TestHandleBlockExpiredDiscardsCanonicalErrorAndDeletes(t *testing.T) {
	s, db := newRecoveryServer(t)
	peers := addPeers(t, s, 1)

	// A known header in blocks-missing. best=nil makes BlockHeaderBest
	// fail, so isCanonical returns (false, err).
	h := chainhash.Hash{0xee}
	db.headers[h] = &tbcd.BlockHeader{Hash: h, Height: 3, Header: h2b(&s.chainParams.GenesisBlock.Header)}
	db.missing = []tbcd.BlockIdentifier{{Height: 3, Hash: &h}}
	db.best = nil

	// Key and value as the TTL expiry callback delivers them: the hash
	// string and the *rawpeer.RawPeer.
	err := s.handleBlockExpired(t.Context(), h.String(), peers[0].rp)
	if err != nil {
		t.Fatalf("isCanonical error must be discarded (peer not closed), got %v", err)
	}
	if db.missingDeletes != 1 {
		t.Fatalf("expected exactly 1 BlockMissingDelete, got %d", db.missingDeletes)
	}
	if db.lastDeleteHeight != 3 || db.lastDeleteHash != h {
		t.Fatalf("delete args = (%d, %v), want (3, %v)", db.lastDeleteHeight, db.lastDeleteHash, h)
	}
}

// TestHandleInvBoundsBlockScan checks that handleInv stops looking up block
// headers after maxInvBlockScan entries. Each block entry costs one
// BlockHeaderByHash read, and an inv may carry up to 50000 entries.
func TestHandleInvBoundsBlockScan(t *testing.T) {
	s, db := newRecoveryServer(t)
	peers := addPeers(t, s, 1)

	const extra = 500
	hashes := make([]chainhash.Hash, 0, maxInvBlockScan+extra)
	for i := range maxInvBlockScan + extra {
		var h chainhash.Hash
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		// Known header, so handleInv skips it after the lookup.
		db.headers[h] = &tbcd.BlockHeader{
			Hash: h, Height: uint64(i + 1), Header: h2b(&s.chainParams.GenesisBlock.Header),
		}
		hashes = append(hashes, h)
	}

	msg := wire.NewMsgInv()
	for i := range hashes {
		if err := msg.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &hashes[i])); err != nil {
			t.Fatalf("add inv vect: %v", err)
		}
	}

	if err := s.handleInv(t.Context(), peers[0].rp, msg, nil); err != nil {
		t.Fatalf("handleInv: %v", err)
	}

	if db.headerByHashCalls > maxInvBlockScan {
		t.Fatalf("handleInv did %v BlockHeaderByHash reads for a %v-entry all-known "+
			"block inv; the scan must stop after maxInvBlockScan=%v",
			db.headerByHashCalls, len(hashes), maxInvBlockScan)
	}
	// Sanity: it really did scan up to the cap (not stop early for another reason).
	if db.headerByHashCalls != maxInvBlockScan {
		t.Fatalf("expected exactly maxInvBlockScan=%v reads, got %v",
			maxInvBlockScan, db.headerByHashCalls)
	}
}
