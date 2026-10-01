// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
)

// TestHandleHeadersContextSkipKeysOnLastHeader verifies that handleHeaders
// keys the context-check skip on the batch's last header being stored. Keyed
// on the first header, [known, new] would admit new with the wrong difficulty.
func TestHandleHeadersContextSkipKeysOnLastHeader(t *testing.T) {
	// Mainnet-shaped retargeting rules with an easy PoW limit, so the batch
	// can be genuinely mined and clear verifyHeadersPoW.
	p := chaincfg.MainNetParams
	p.PowLimit = chaincfg.RegressionNetParams.PowLimit
	p.PowLimitBits = chaincfg.RegressionNetParams.PowLimitBits

	kp := &wire.BlockHeader{
		Version: 1, PrevBlock: chainhash.Hash{0xc1},
		Bits: p.PowLimitBits, Timestamp: time.Unix(1600000000, 0),
	}
	kpHash := kp.BlockHash()
	k := mineHeader(t, &kpHash, p.PowLimitBits, 0xc2) // known, stored
	kHash := k.BlockHash()
	// Validly mined but with a different difficulty than its parent at a
	// non-retarget height, so only the context check rejects it.
	n := mineHeader(t, &kHash, 0x1f00ffff, 0xc3)

	spy := &contextSpyDB{headers: map[chainhash.Hash]*tbcd.BlockHeader{
		kpHash: {Hash: kpHash, Height: 99999, Header: h2b(kp)},
		kHash:  {Hash: kHash, Height: 100000, Header: h2b(k)},
	}}
	s := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &p, db: spy}

	msg := wire.NewMsgHeaders()
	for _, h := range []*wire.BlockHeader{k, n} {
		if err := msg.AddBlockHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	err := s.handleHeaders(t.Context(), fakePeer(t, 0), msg)
	if err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("[known, wrong-difficulty new] = %v; the new header must be "+
			"context-checked because the batch's LAST header is not stored", err)
	}
	if spy.insertCalls != 0 {
		t.Fatalf("the rejected batch reached the store (%d inserts)", spy.insertCalls)
	}
}

// TestRunRefusesSoakDatadirOnMainnet verifies that Run calls
// verifyDatadirIdentity before starting network activity, so it refuses an
// unstamped datadir with the mainnet genesis and a trivial-PoW tip.
func TestRunRefusesSoakDatadirOnMainnet(t *testing.T) {
	home := t.TempDir()

	// Seed the datadir at the path Run will open.
	lcfg, err := level.NewConfig("mainnet", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := level.New(t.Context(), lcfg)
	if err != nil {
		t.Fatal(err)
	}
	gen := chaincfg.MainNetParams.GenesisBlock.Header
	if err := db.BlockHeaderGenesisInsert(t.Context(), gen, 0, nil); err != nil {
		t.Fatal(err)
	}
	soak := &wire.BlockHeader{
		Version: 1, PrevBlock: gen.BlockHash(),
		Bits: chaincfg.RegressionNetParams.PowLimitBits, Timestamp: time.Unix(1700000000, 0),
	}
	m := wire.NewMsgHeaders()
	if err := m.AddBlockHeader(soak); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := db.BlockHeadersInsert(t.Context(), m, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := NewDefaultConfig()
	cfg.Network = "mainnet"
	cfg.LevelDBHome = home
	cfg.ListenAddress = ""
	cfg.PrometheusListenAddress = ""
	cfg.MempoolEnabled = false
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	err = s.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "network mismatch") {
		t.Fatalf("Run on a mainnet soak datadir = %v; it must refuse to start with a "+
			"datadir network mismatch before doing anything else", err)
	}
}

// shutdownStubDB fails the indexer's first store call (a non-whitelisted
// NotFound) and reports nothing to download, so syncBlocks takes the indexing
// branch. called records that the indexer actually reached the store.
type shutdownStubDB struct {
	indexFailStubDB
	called atomic.Bool
}

func (d *shutdownStubDB) BlockHeaderBest(ctx context.Context) (*tbcd.BlockHeader, error) {
	d.called.Store(true)
	return d.indexFailStubDB.BlockHeaderBest(ctx)
}

func (d *shutdownStubDB) BlockHeaderByHash(ctx context.Context, h chainhash.Hash) (*tbcd.BlockHeader, error) {
	d.called.Store(true)
	return d.indexFailStubDB.BlockHeaderByHash(ctx, h)
}

func (*shutdownStubDB) BlocksMissing(context.Context, int) ([]tbcd.BlockIdentifier, error) {
	return nil, nil
}

// TestSyncBlocksShutdownGuard verifies that syncBlocks' indexing goroutine
// logs, rather than panics on, an unclassified store error once the context is
// cancelled. The panic would happen in a goroutine the test cannot recover, so
// the scenario runs in a child copy of the test binary.
func TestSyncBlocksShutdownGuard(t *testing.T) {
	if os.Getenv("TBC_SHUTDOWN_GUARD_CHILD") == "1" {
		s := deferServer(t)
		s.cfg.AutoIndex = true
		db := &shutdownStubDB{}
		s.db = db
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // shutdown already under way
		s.syncBlocks(ctx)
		// Wait for the indexing goroutine to reach the store and finish its
		// pass. Only the error switch is left after that, so a short sleep
		// lets a panic, if any, surface before the child exits.
		deadline := time.Now().Add(10 * time.Second)
		for {
			s.mtx.Lock()
			done := db.called.Load() && !s.indexing
			s.mtx.Unlock()
			if done {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the indexing goroutine never reached the store")
			}
			time.Sleep(time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSyncBlocksShutdownGuard$", "-test.count=1")
	cmd.Env = append(os.Environ(), "TBC_SHUTDOWN_GUARD_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("syncBlocks crashed on a store error during shutdown: %v\n%s", err, tail(out))
	}
	if strings.Contains(string(out), "panic:") {
		t.Fatalf("child panicked:\n%s", tail(out))
	}
}

func tail(b []byte) string {
	const n = 1500
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

// TestSyncedReturnsNotSyncedOnBlockHeaderBestError verifies that synced reports
// not-synced instead of panicking when BlockHeaderBest fails on a live context,
// as happens when op-geth calls Synced while the database is closing.
func TestSyncedReturnsNotSyncedOnBlockHeaderBestError(t *testing.T) {
	s, db := newRecoveryServer(t)
	db.best = nil // BlockHeaderBest -> error

	si := s.synced(t.Context()) // must not panic
	if si.Synced {
		t.Fatal("synced must report not-synced when BlockHeaderBest errors")
	}
}

// TestSyncedReturnsNotSyncedOnBlocksMissingError is the same for BlocksMissing.
func TestSyncedReturnsNotSyncedOnBlocksMissingError(t *testing.T) {
	s, db := newRecoveryServer(t)
	db.blocksMissingErr = errors.New("simulated store fault")

	si := s.synced(t.Context()) // must not panic
	if si.Synced {
		t.Fatal("synced must report not-synced when BlocksMissing errors")
	}
}

// TestFixupCacheChannelReportsCancel verifies that fixupCacheChannel returns
// ctx.Err() on a cancelled context. Returning nil would let the caller flush
// an incomplete utxo set and advance the index hash.
func TestFixupCacheChannelReportsCancel(t *testing.T) {
	s := &Server{chainParams: &chaincfg.RegressionNetParams}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	blk := btcutil.NewBlock(&wire.MsgBlock{Header: chaincfg.RegressionNetParams.GenesisBlock.Header})
	err := s.fixupCacheChannel(ctx, blk, map[tbcd.Outpoint]tbcd.CacheOutput{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("fixupCacheChannel with a cancelled ctx must return context.Canceled, got %v", err)
	}
}

// opCancelStubDB answers ScriptHashByOutpoint with an error so fetchOPParallel
// returns quickly; the test only cares that the slot is handed back.
type opCancelStubDB struct {
	tbcd.Database
}

func (opCancelStubDB) ScriptHashByOutpoint(context.Context, tbcd.Outpoint) (*tbcd.ScriptHash, error) {
	return nil, errors.New("stub: not found")
}

// TestFetchOPParallelReturnsSlotOnCancel verifies that fetchOPParallel returns
// its slot even when the context is cancelled. Dropped slots fail
// fixupCacheChannel's "channel not empty" check or, once all 128 are gone,
// block its "<-c" forever, wedging the indexer.
func TestFetchOPParallelReturnsSlotOnCancel(t *testing.T) {
	s := &Server{chainParams: &chaincfg.RegressionNetParams, db: opCancelStubDB{}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	const n = 128
	c := make(chan struct{}, n)
	w := new(sync.WaitGroup)
	utxos := map[tbcd.Outpoint]tbcd.CacheOutput{}
	for i := 0; i < n; i++ {
		w.Add(1)
		go s.fetchOPParallel(ctx, c, w, tbcd.Outpoint{}, utxos)
	}
	w.Wait()

	if len(c) != n {
		t.Fatalf("fetchOPParallel returned %v/%v slots on a cancelled ctx; slots "+
			"must be returned UNCONDITIONALLY, not dropped on ctx.Done()", len(c), n)
	}
}
