// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btcmempool "github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/dustin/go-humanize"
	"github.com/juju/loggo"
	"github.com/mitchellh/go-homedir"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/database"
	dbnames "github.com/hemilabs/heminetwork/database/level"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
	"github.com/hemilabs/heminetwork/ttl"
)

const (
	logLevel = "INFO"
	appName  = "tbc"

	defaultPeersWanted   = 64
	minPeersRequired     = 64  // minimum number of peers in good map before cache is purged
	defaultPendingBlocks = 128 // 128 * ~4MB max memory use

	// maxInvBlockScan bounds the block entries handleInv looks up per inv
	// message; see handleInv.
	maxInvBlockScan = defaultPendingBlocks

	// maxDeferredHeaderMsgs bounds how many headers messages are held while
	// the indexers run. wire.MaxBlockHeadersPerMsg is 2000 and each decoded
	// header costs 112 bytes (a 104 byte wire.BlockHeader plus its pointer),
	// so 16 full messages retain ~3.4MiB.
	maxDeferredHeaderMsgs = 16

	// maxDeferredPerPeer bounds how many of those slots a single peer
	// (keyed by host) may hold, so one peer flooding headers while indexing
	// cannot push every honest reply onto the hash-only fallback.
	maxDeferredPerPeer = 2

	// maxInvBlocks bounds s.invBlocks.
	//
	// invBlocks holds announced block hashes we may lack: block invs whose
	// header is unknown (handleInv, at any time) and the last header of each
	// batch received while indexing (handleHeaders). Only the syncBlocks
	// drain removes entries, and it runs
	// only with AutoIndex set and once we are synced, so without a cap the
	// map grows for all of IBD, and forever on op-geth's embedded node, which
	// runs with AutoIndex=false.
	//
	// Evicting an entry costs latency, never data. The drain only uses the
	// map to decide whether to ask every peer what follows our tip, which the
	// periodic refresh asks anyway every headerRefreshInterval. Eviction can
	// suppress a drain but never cause one. 8192 is ~57 days of mainnet
	// blocks, about 0.6MiB at the cap.
	maxInvBlocks = 8192

	// maxLocatorPerHeight and maxLocatorEntries bound a getheaders block
	// locator. See getHeadersByHeights.
	//
	// Bitcoin Core disconnects a peer whose locator exceeds MAX_LOCATOR_SZ
	// (101). Mainnet has no height with more than 2 siblings, but the store
	// can still hold cheap difficulty-1 siblings inserted through the
	// external header paths (AddExternalHeaders, BlockHeadersInsert) or by
	// older versions that did not run verifyHeaderContext on P2P headers.
	// previousCheckpointHeight is a fixed anchor, so siblings planted there
	// would inflate every refresh, across restarts, and get us disconnected
	// by every Core peer.
	//
	// Current callers produce at most 9 entries (the lead plus four heights
	// at 2 each); 16 is a backstop.
	maxLocatorPerHeight = 2
	maxLocatorEntries   = 16

	// drainFanoutInterval bounds how often the syncBlocks drain may ask
	// every peer for headers. See drainFanoutDue.
	drainFanoutInterval = time.Second

	// mempoolFanoutInterval bounds how often handleHeaders' empty branch
	// asks every peer for its mempool. See mempoolFanoutDue.
	mempoolFanoutInterval = 5 * time.Minute

	defaultMaxCachedKeystones = 1024 // number of cached keystones prior to flush

	defaultMaxCachedTxs = 1e6 // dual purpose cache, max key 69, max value 36

	networkLocalnet = "localnet" // XXX this needs to be rethought

	defaultCmdTimeout          = 7 * time.Second
	defaultPingTimeout         = 9 * time.Second
	defaultBlockPendingTimeout = 13 * time.Second

	defaultMempoolAge = 2 * 7 * 24 * time.Hour // two weeks
)

// headerRefreshInterval is how often we ask every peer what follows our
// canonical tip, regardless of what else is happening.
//
// Header acquisition is otherwise event driven, and BlocksMissing is built from
// header inserts, so a node idle behind a header gap never learns of the
// headers it is missing. This timer is the backstop.
//
// It must be a timer. Issuing the request off the back of a headers reply
// loops: a peer that agrees we are at the tip replies with an empty headers
// message, which kicks syncBlocks, which asks again.
//
// This is a var only so tests can shorten it.
var headerRefreshInterval = 60 * time.Second

var (
	log = loggo.GetLogger(appName)

	Welcome = true // Use global to enable/disable welcome message

	zeroHash = new(chainhash.Hash) // used to check if a hash is invalid

	// ErrNilElement reports a caller-supplied block or transaction containing a nil element.
	//
	// It is a SENTINEL so the RPC layer can classify it as a CLIENT error. Without it the rejection
	// fell through to protocol.NewInternalError, which handleRequest logs with an unthrottled
	// log.Errorf per message -- so a ~60-byte unauthenticated tbcapi message carrying "TxIn":[null]
	// bought one Error line each, with no rate limit.
	ErrNilElement = errors.New("nil element")

	// ErrBlockMerkleMismatch reports a block body that is not the body of the header it arrived under.
	// It covers THREE conditions, so do not read errors.Is(err, ErrBlockMerkleMismatch) as "the root
	// did not match": zero transactions, a non-coinbase first transaction, and a root mismatch all
	// return it. ErrBlockDuplicateTx reports the CVE-2012-2459 shape described on
	// checkBlockMerkleRoot.
	ErrBlockMerkleMismatch = errors.New("block merkle root mismatch")
	ErrBlockDuplicateTx    = errors.New("block contains a duplicate transaction")

	ErrTxAlreadyBroadcast = errors.New("tx already broadcast")
	ErrTxBroadcastNoPeers = errors.New("can't broadcast tx, no peers")
	ErrNotInDebugMode     = errors.New("debug flag not set")

	// upstreamStateIdKey is used for storing upstream state IDs
	// representing a unique state of an upstream system driving TBC state/
	upstreamStateIdKey = []byte("upstreamstateid")

	mainnetHemiGenesis = &HashHeight{
		Hash:   s2h("000000000000000000001d8132106b63876117569713ef4fe89d5a2f1173c66e"),
		Height: 859303,
	}

	testnet3HemiGenesis = &HashHeight{
		Hash:   s2h("0000000000000014a1717b82329a58e344f1821389d0415601f1b12ebce35881"),
		Height: 2577400,
	}
	localnetHemiGenesis = &HashHeight{
		Hash:   *chaincfg.RegressionNetParams.GenesisHash,
		Height: 0,
	}

	fixupStrategy = 3 // Do not touch unless your name is marco
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	AutoIndex               bool
	BlockCacheSize          string
	BlockheaderCacheSize    string
	BlockSanity             bool
	HemiIndex               bool
	LevelDBHome             string
	ListenAddress           string
	LogLevel                string
	MaxCachedKeystones      int
	MaxCachedTxs            int
	MempoolEnabled          bool
	DatabaseDebug           bool
	Network                 string
	PeersWanted             int
	PrometheusListenAddress string
	PrometheusNamespace     string
	PprofListenAddress      string
	Seeds                   []string

	// Fields used for running TBC in External Header Mode, where P2P is disabled
	// and TBC is used to determine consensus based on headers fed from external
	// code that manages the TBC node.
	ExternalHeaderMode      bool              // Whether Header-Only Mode is enabled
	EffectiveGenesisBlock   *wire.BlockHeader // The header to use as the first block in TBC's consensus view
	GenesisHeightOffset     uint64            // The height of the effective genesis block
	GenesisDifficultyOffset big.Int           // The cumulative difficulty of the effective genesis block
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenAddress:        tbcapi.DefaultListen,
		BlockCacheSize:       "1gb",
		BlockheaderCacheSize: "128mb",
		LogLevel:             logLevel,
		MaxCachedKeystones:   defaultMaxCachedKeystones,
		MaxCachedTxs:         defaultMaxCachedTxs,
		MempoolEnabled:       true,
		PeersWanted:          defaultPeersWanted,
		PrometheusNamespace:  appName,
		ExternalHeaderMode:   false, // Default anyway, but for readability
		DatabaseDebug:        false, // Default anyway, but dangerous so be explicit
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// fixup cache strategy
	fixupCache func(ctx context.Context, b *btcutil.Block, utxos map[tbcd.Outpoint]tbcd.CacheOutput) error

	// stats
	printTime      time.Time
	blocksSize     uint64 // cumulative block size written
	blocksInserted int    // blocks inserted since last print

	// mempool
	mempool *Mempool

	// broadcast
	broadcast map[chainhash.Hash]*wire.MsgTx

	// announced block hashes we may lack; bounded by maxInvBlocks
	invBlocks map[chainhash.Hash]struct{}

	// bitcoin network
	wireNet     wire.BitcoinNet
	chainParams *chaincfg.Params
	timeSource  blockchain.MedianTimeSource
	checkpoints []checkpoint
	hemiGenesis *HashHeight
	pm          *PeerManager

	blocks *ttl.TTL // outstanding block downloads [hash]when/where
	pings  *ttl.TTL // outstanding pings

	indexing bool // when set we are indexing

	// deferredHeaders holds headers messages that arrived while indexing,
	// applied by replayDeferredHeaders once the indexers finish.
	deferredHeaders []deferredHeaderMsg

	// deferredEmpty records that at least one empty headers message was
	// swallowed by the quiesce branch. See replayDeferredHeaders.
	deferredEmpty bool

	// drainFanout is when the syncBlocks drain last asked every peer for
	// headers. See drainFanoutDue.
	drainFanout time.Time

	// drainRetryPending is set while a delayed drain fan-out, armed by a
	// rate-limited drain, is outstanding. See syncBlocks.
	drainRetryPending bool

	// mempoolFanout is when handleHeaders' empty branch last asked every
	// peer for its mempool. See mempoolFanoutDue.
	mempoolFanout time.Time

	db tbcd.Database

	// Prometheus
	promCollectors  []prometheus.Collector
	promPollVerbose bool // set to true to print stats during poll
	prom            struct {
		syncInfo                  SyncInfo
		connected, good, bad      int
		mempoolCount, mempoolSize int
		blockCache                tbcd.CacheStats
		headerCache               tbcd.CacheStats
		diskFree                  uint64
	} // periodically updated by promPoll
	isRunning     bool
	cmdsProcessed prometheus.Counter

	// WebSockets
	sessions       map[string]*tbcWs
	requestTimeout time.Duration

	// futureWarnLast is when handleHeaders last warned about headers dated
	// more than two hours ahead, in UnixNano; 0 means never. See
	// futureWarnDue.
	futureWarnLast atomic.Int64
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}

	// Only populate pings and blocks if not in External Header Mode
	var pings *ttl.TTL
	var blocks *ttl.TTL
	var err error
	if !cfg.ExternalHeaderMode {
		pings, err = ttl.New(cfg.PeersWanted, true)
		if err != nil {
			return nil, err
		}
		blocks, err = ttl.New(defaultPendingBlocks, true)
		if err != nil {
			return nil, err
		}
	}

	defaultRequestTimeout := 10 * time.Second // XXX: make config option?
	s := &Server{
		cfg:        cfg,
		printTime:  time.Now().Add(10 * time.Second),
		blocks:     blocks,
		pings:      pings,
		timeSource: blockchain.NewMedianTime(),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: cfg.PrometheusNamespace,
			Name:      "rpc_calls_total",
			Help:      "The total number of successful RPC commands",
		}),
		sessions:        make(map[string]*tbcWs),
		requestTimeout:  defaultRequestTimeout,
		broadcast:       make(map[chainhash.Hash]*wire.MsgTx, 16),
		invBlocks:       make(map[chainhash.Hash]struct{}, 16),
		promPollVerbose: false,
	}

	// The indexer cache sizes are divisors: crawler.go computes len(x)*100/MaxCachedTxs without
	// a guard against a 0 denominator.

	// Zero means "unset" -- NewDefaultConfig supplies these, but a hand-built Config leaves them at
	// zero.
	if s.cfg.MaxCachedTxs == 0 {
		log.Warningf("MaxCachedTxs value of 0 is invalid, setting to default")
		s.cfg.MaxCachedTxs = defaultMaxCachedTxs
	}
	if s.cfg.MaxCachedKeystones == 0 {
		log.Warningf("MaxCachedKeystones value of 0 is invalid, setting to default")
		s.cfg.MaxCachedKeystones = defaultMaxCachedKeystones
	}
	if s.cfg.MaxCachedTxs < 0 || s.cfg.MaxCachedKeystones < 0 {
		return nil, fmt.Errorf("cache sizes must not be negative (txs %d, keystones %d): they are "+
			"divisors in the indexers and make() size hints", s.cfg.MaxCachedTxs,
			s.cfg.MaxCachedKeystones)
	}

	// Only set pings and blocks if not in External Header Mode
	if !s.cfg.ExternalHeaderMode {
		s.blocks = blocks
		s.pings = pings
	}

	if s.cfg.MempoolEnabled {
		if s.cfg.ExternalHeaderMode {
			// Cannot combine mempool behavior with External Header Mode
			panic("cannot enable mempool on an external-header-only mode TBC instance")
		}
		s.mempool, err = NewMempool()
		if err != nil {
			return nil, err
		}
	}

	wanted := defaultPeersWanted
	switch cfg.Network {
	case "mainnet":
		s.wireNet = wire.MainNet
		s.chainParams = &chaincfg.MainNetParams
		s.checkpoints = mainnetCheckpoints
		s.hemiGenesis = mainnetHemiGenesis

	case "testnet3", "upgradetest":
		// upgradetest is a special mode to verify database upgrades.
		// It pretends to be testnet3, however it hints to the database
		// layer that we do not want user interaction.
		// You probably should not touch this.
		s.wireNet = wire.TestNet3
		s.chainParams = &chaincfg.TestNet3Params
		s.checkpoints = testnet3Checkpoints
		s.hemiGenesis = testnet3HemiGenesis

	case networkLocalnet:
		s.wireNet = wire.TestNet
		s.chainParams = &chaincfg.RegressionNetParams
		s.checkpoints = localnetCheckpoints
		s.hemiGenesis = localnetHemiGenesis
		wanted = 1

	default:
		return nil, fmt.Errorf("invalid network: %v", cfg.Network)
	}

	// Only create a PeerManager if not in External Header Mode
	if !s.cfg.ExternalHeaderMode {
		pm, err := NewPeerManager(s.wireNet, s.cfg.Seeds, wanted)
		if err != nil {
			return nil, err
		}
		s.pm = pm
	}

	switch fixupStrategy {
	case 0:
		s.fixupCache = s.fixupCacheParallel
	case 1:
		s.fixupCache = s.fixupCacheSerial
	case 2:
		s.fixupCache = s.fixupCacheBatched
	case 3:
		s.fixupCache = s.fixupCacheChannel
	}

	return s, nil
}

// deferredHeaderMsg is a headers message that arrived while the indexers were
// running, kept so it can be applied afterwards instead of discarded.
type deferredHeaderMsg struct {
	p   *rawpeer.RawPeer
	msg *wire.MsgHeaders
	// last is msg's final header hash, the dedupe key.
	last chainhash.Hash
}

// peerHost returns a peer's remote host without its port, for use as a
// per-peer resource key. Ports cost an attacker nothing, so a key that
// includes one is not a per-peer key at all. Falls back to the full string
// when there is no port to split, so an unexpected format still groups
// consistently rather than becoming unique per call.
func peerHost(p *rawpeer.RawPeer) string {
	addr := p.String()
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// deferHeadersUnlocked buffers a headers message that arrived while the
// indexers were running, so it can be applied afterwards instead of discarded.
// Caller must hold s.mtx.
//
// Messages are deduped on their last header hash, since a refresh tick asks
// every peer the same question and most replies are identical. Keying on the
// last header rather than the first keeps a fork that diverges past our tip.
// Each peer host may hold at most maxDeferredPerPeer slots, so one flooder
// cannot own the buffer.
func (s *Server) deferHeadersUnlocked(p *rawpeer.RawPeer, msg *wire.MsgHeaders) {
	n := len(msg.Headers)
	if n == 0 {
		return
	}
	// msg must be a contiguous chain (see verifyHeaderBatchShape); callers
	// check that before taking s.mtx or pass messages that already came out
	// of this buffer. The dedupe below prefers the longer message, and
	// without contiguity a peer could prepend garbage to the public tip
	// header and displace an honest answer. Each hash in a contiguous chain
	// is committed to by the next header's PrevBlock, so longer means more
	// real data.
	last := msg.Headers[n-1].BlockHash()

	// Key the per-peer tally on the host, not the peer pointer, which resets
	// on reconnect. Two honest nodes behind one address share a quota, which
	// costs them at most a fallback to the hash-only path.
	addr := peerHost(p)
	mine := 0
	dup := -1
	for k := range s.deferredHeaders {
		if s.deferredHeaders[k].last.IsEqual(&last) {
			dup = k
		}
		if s.deferredHeaders[k].p != nil && peerHost(s.deferredHeaders[k].p) == addr {
			mine++
		}
	}

	// Same answer already held: keep the longer message. The last header of
	// an honest answer is the public network tip, so refusing the newcomer
	// would let a peer claim the key with a 1-header stub and bounce every
	// real answer.
	//
	// The longer data always wins, but the slot only moves to this peer if
	// that respects the per-host cap; otherwise dedupe would be a way
	// around maxDeferredPerPeer.
	if dup >= 0 {
		held := s.deferredHeaders[dup].p
		if n > len(s.deferredHeaders[dup].msg.Headers) {
			owner := held
			if (held != nil && peerHost(held) == addr) || mine < maxDeferredPerPeer {
				owner = p
			}
			s.deferredHeaders[dup] = deferredHeaderMsg{p: owner, msg: msg, last: last}
		}
		return
	}

	if mine >= maxDeferredPerPeer {
		return
	}

	if len(s.deferredHeaders) >= maxDeferredHeaderMsgs {
		// Buffer full. A host holding nothing may take a slot from the
		// host holding the most; otherwise 8 hosts at 2 slots each
		// would lock out every other peer for the whole indexing pass.
		if mine > 0 {
			return
		}
		victim := s.greediestDeferredSlotUnlocked()
		if victim < 0 {
			return
		}
		s.deferredHeaders = slices.Delete(s.deferredHeaders, victim, victim+1)
	}

	s.deferredHeaders = append(s.deferredHeaders,
		deferredHeaderMsg{p: p, msg: msg, last: last})
}

// greediestDeferredSlotUnlocked returns the index of a slot to evict, or -1 if
// the buffer is empty. Callers must hold s.mtx.
//
// It prefers the host holding the most slots, since that is what a flooder
// looks like. If every host holds one slot it falls through to the last slot,
// so an honest newcomer still gets in. Anything evicted is still covered by
// invBlocks, the drain and the periodic refresh.
//
// Among the greediest host's slots it takes the newest, because
// requeueDeferredHeadersUnreplayed seats an unreplayed remainder at the front
// and evicting it would undo the requeue.
func (s *Server) greediestDeferredSlotUnlocked() int {
	counts := make(map[string]int, len(s.deferredHeaders))
	for k := range s.deferredHeaders {
		if s.deferredHeaders[k].p == nil {
			// A slot with no peer belongs to nobody; take it first.
			return k
		}
		counts[peerHost(s.deferredHeaders[k].p)]++
	}

	best, bestCount := -1, 1
	for k := range s.deferredHeaders {
		// >= so that, among hosts tied at the maximum, the LAST slot wins.
		if c := counts[peerHost(s.deferredHeaders[k].p)]; c >= bestCount {
			best, bestCount = k, c
		}
	}
	return best
}

// replayDeferredHeaders applies headers messages that arrived while the
// indexers were running. It must NOT be called while holding s.mtx, since
// handleHeaders takes it.
func (s *Server) replayDeferredHeaders(ctx context.Context) {
	s.mtx.Lock()
	dh := s.deferredHeaders
	// Fresh slice, not dh[:0]: the messages below are handled after the
	// unlock while peer goroutines may append.
	s.deferredHeaders = nil
	// An empty headers message carries no data, only the syncBlocks kick
	// from handleHeaders' empty branch, which turns BlocksMissing into
	// getdata. The quiesce branch records that one was seen and we re-issue
	// the kick once here, not once per message, so it cannot feed itself.
	kick := s.deferredEmpty
	s.deferredEmpty = false
	s.mtx.Unlock()

	if len(dh) != 0 {
		log.Debugf("replaying %v deferred headers messages", len(dh))
	}
	for k := range dh {
		// Bail on shutdown. Cancellation aborts the indexing pass,
		// which fires this replay, and neither is in s.wg, so inserts
		// could land after dbClose and fail with leveldb.ErrClosed.
		// XXX track the indexer and this replay in s.wg.
		if ctx.Err() != nil {
			log.Debugf("replay deferred headers: %v", ctx.Err())
			return
		}
		// Hand handleHeaders a private copy of the message struct.
		// BlockHeadersInsert reslices msg.Headers in place and a
		// message can be owned by two replays at once. Nothing writes
		// into the backing array, so copying the slice header is
		// enough.
		mc := *dh[k].msg
		err := s.handleHeaders(ctx, dh[k].p, &mc)
		if errors.Is(err, ErrAlreadyIndexing) {
			// Indexing restarted underneath us. Put the unreplayed
			// remainder back at the front of the buffer, in order.
			// Continuing would re-buffer it behind newer arrivals,
			// where a later segment could replay before its parent,
			// and the per-peer cap could drop it entirely.
			s.requeueDeferredHeadersUnreplayed(ctx, dh[k:])
			break
		}
		if err != nil {
			log.Debugf("replay deferred headers %v: %v", dh[k].p, err)
		}
	}

	// Fire the kick LAST. Firing it first lets syncBlocks start indexing
	// again, and the replay above would re-buffer everything instead of
	// applying it. Gate on blksMissing: the indexers have just finished,
	// and an ungated kick would start a pointless indexing pass on an idle
	// synced node.
	if kick && ctx.Err() == nil && s.blksMissing(ctx) {
		go s.syncBlocks(ctx)
	}
}

// requeueDeferredHeadersUnreplayed puts an unreplayed remainder back at the
// front of the deferred buffer, ahead of whatever arrived during the replay.
// Must NOT be called while holding s.mtx.
//
// If indexing has already finished by the time the remainder is seated, it
// starts a replay itself, since the finished pass's replay may have run before
// the remainder was back in the buffer. Each such replay is paid for by one
// indexing pass, so this cannot loop. Concurrent replays are race-free but not
// order-preserving; anything dropped is re-fetched by the drain and the
// periodic refresh.
func (s *Server) requeueDeferredHeadersUnreplayed(ctx context.Context, rem []deferredHeaderMsg) {
	if len(rem) == 0 {
		return
	}

	s.mtx.Lock()
	idle := s.requeueDeferredHeadersUnlocked(rem)
	s.mtx.Unlock()

	if idle && ctx.Err() == nil {
		go s.replayDeferredHeaders(ctx)
	}
}

// requeueDeferredHeadersUnlocked seats rem and reports whether indexing was
// idle at that moment. Callers must hold s.mtx.
func (s *Server) requeueDeferredHeadersUnlocked(rem []deferredHeaderMsg) (idle bool) {
	// rem came out of this same buffer, so it is already deduped, already
	// within maxDeferredPerPeer and no longer than maxDeferredHeaderMsgs.
	// Seat it unconditionally; re-running admission could drop it.
	arrived := s.deferredHeaders
	s.deferredHeaders = make([]deferredHeaderMsg, len(rem), maxDeferredHeaderMsgs)
	copy(s.deferredHeaders, rem)
	// Not protected from the fair-share eviction below: that only runs on a
	// FULL buffer, which honest tip-anchored answers do not produce (they
	// dedupe to about one slot). Anything evicted is re-fetched by the drain
	// and the periodic refresh.

	// What arrived during the replay goes behind it, under the normal
	// admission rules, so dedupe and the per-peer cap still hold afterwards.
	// This also drops the copy of rem[0] that the quiesce branch just
	// appended, since deferHeadersUnlocked dedupes on the last header hash.
	for k := range arrived {
		s.deferHeadersUnlocked(arrived[k].p, arrived[k].msg)
	}
	return !s.indexing
}

// invInsertUnlocked records an announced block hash we do not have.
//
// It returns true if h was inserted. Callers must hold s.mtx.
//
// At the cap the new hash is admitted and an arbitrary old one is evicted. The
// drain re-checks which entries are still missing, so which old entry leaves
// does not matter. Dropping the new hash instead could hide that we are behind:
// a full map whose entries have all since been satisfied filters empty and the
// drain stays silent.
func (s *Server) invInsertUnlocked(h chainhash.Hash) bool {
	if _, ok := s.invBlocks[h]; ok {
		return false
	}

	// NewServer makes the map, but a Server built as a struct literal (as
	// in tests) would panic on the write below.
	if s.invBlocks == nil {
		s.invBlocks = make(map[chainhash.Hash]struct{}, 16)
	}

	if len(s.invBlocks) >= maxInvBlocks {
		// Evict an arbitrary, not uniformly random, entry.
		for k := range s.invBlocks {
			delete(s.invBlocks, k)
			break
		}
	}

	// Not found, thus return true for inserted
	s.invBlocks[h] = struct{}{}
	return true
}

func (s *Server) invInsert(h chainhash.Hash) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.invInsertUnlocked(h)
}

func (s *Server) getHeadersByHashes(ctx context.Context, p *rawpeer.RawPeer, hashes ...*chainhash.Hash) error {
	log.Tracef("getHeadersByHashes %v %v", p, hashes)
	defer log.Tracef("getHeadersByHashes exit %v %v", p, hashes)

	ghs := wire.NewMsgGetHeaders()
	for _, hash := range hashes {
		err := ghs.AddBlockLocatorHash(hash)
		if err != nil {
			break
		}
	}
	if len(ghs.BlockLocatorHashes) == 0 {
		return errors.New("no block headers at provided hash")
	}
	if err := p.Write(defaultCmdTimeout, ghs); err != nil {
		return fmt.Errorf("write get headers: %w", err)
	}
	return nil
}

// getHeadersByHeights builds a block locator and asks p for what follows it.
//
// lead, when non-nil, is a hash the caller knows is on our canonical chain (in
// practice BlockHeaderBest's). It is seeded first and unconditionally.
//
// That matters because the rest of the locator is discovered through
// BlockHeadersByHeight, which returns every sibling at a height sorted by raw
// hash bytes, and maxLocatorPerHeight then keeps only the first two. An
// attacker who can store low-difficulty siblings (via AddExternalHeaders or
// BlockHeadersInsert, or before P2P headers were difficulty checked) can grind
// them to sort ahead of the real hash and push it out of the locator. The peer
// then matches nothing and replies from genesis on every refresh. Seeding the
// known-canonical tip gives the peer something of ours to match, so a poisoned
// deeper anchor only wastes entries.
func (s *Server) getHeadersByHeights(ctx context.Context, p *rawpeer.RawPeer, lead *chainhash.Hash, heights ...uint64) error {
	log.Tracef("getHeadersByHeights %v %v", p, heights)
	defer log.Tracef("getHeadersByHeights exit %v %v", p, heights)

	ghs := wire.NewMsgGetHeaders()
	if lead != nil {
		if err := ghs.AddBlockLocatorHash(lead); err != nil {
			return fmt.Errorf("add lead locator hash: %w", err)
		}
	}
	for _, height := range heights {
		// Bail on shutdown. Callers (headersPeer, handlePeer) are not
		// in s.wg, so a store read may land after dbClose and fail
		// with leveldb.ErrClosed.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Skip, do not break. Callers derive heights by subtraction
		// (tip-1000, tip-1999), which underflows on a low node, and
		// breaking there would drop the remaining anchors, including
		// the checkpoint. The store rejects an underflowed height.
		bhs, err := s.BlockHeadersByHeight(ctx, height)
		if err != nil {
			continue
		}
		perHeight := 0
		for _, bh := range bhs {
			if perHeight >= maxLocatorPerHeight ||
				len(ghs.BlockLocatorHashes) >= maxLocatorEntries {
				break
			}
			hash := bh.BlockHash()
			// Skip duplicates. The lead hash reappears here,
			// and on a short chain several heights collapse
			// onto the same header (e.g. genesis). Repeats
			// waste bytes and count against the peer's
			// locator size limit.
			if slices.ContainsFunc(ghs.BlockLocatorHashes,
				func(h *chainhash.Hash) bool { return h.IsEqual(&hash) }) {
				continue
			}
			if err = ghs.AddBlockLocatorHash(&hash); err != nil {
				break
			}
			perHeight++
		}
	}

	if len(ghs.BlockLocatorHashes) == 0 {
		return errors.New("no block headers at provided height")
	}
	if err := p.Write(defaultCmdTimeout, ghs); err != nil {
		return fmt.Errorf("write get headers: %w", err)
	}
	return nil
}

func (s *Server) pingExpired(ctx context.Context, key any, value any) {
	log.Tracef("pingExpired")
	defer log.Tracef("pingExpired exit")

	p, ok := value.(*rawpeer.RawPeer)
	if !ok {
		log.Errorf("invalid ping expired type: %T", value)
		return
	}
	log.Debugf("pingExpired %v", key)
	if err := p.Close(); err != nil {
		log.Debugf("ping %v: %v", key, err)
	}
}

func (s *Server) pingPeer(ctx context.Context, p *rawpeer.RawPeer) {
	log.Tracef("pingPeer %v", p)
	defer log.Tracef("pingPeer %v exit", p)

	// Cancel outstanding ping, should not happen
	peer := p.String()
	// No need to check error; this always races and simply is not an error.
	_ = s.pings.Cancel(peer)

	// We don't really care about the response. We just want to
	// write to the connection to make it fail if the other side
	// went away.
	log.Debugf("Pinging: %v", p)
	err := p.Write(defaultCmdTimeout, wire.NewMsgPing(uint64(time.Now().Unix())))
	if err != nil {
		log.Debugf("ping %v: %v", p, err)
		return
	}

	// Record outstanding ping
	s.pings.Put(ctx, defaultPingTimeout, peer, p, s.pingExpired, nil)
}

// drainFanoutDue rate limits the syncBlocks drain's getheaders fan out to one
// per drainFanoutInterval.
//
// syncBlocks is kicked by empty headers messages, which a peer can send for
// free. We limit the fan out rather than the kick because the kick also
// starts block download, which must not wait on a rate limit.
func (s *Server) drainFanoutDue() bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	now := time.Now()
	if now.Sub(s.drainFanout) < drainFanoutInterval {
		return false
	}
	s.drainFanout = now
	return true
}

// mempoolFanoutDue rate limits handleHeaders' empty-branch mempool fan out to
// one per mempoolFanoutInterval.
//
// The fan out is per reply but asks every peer, so a getheaders round to N
// peers sends N^2 mempool messages. btcd (v0.24.2) charges 33 transient ban
// score per mempool message against a BanThreshold of 100, so a burst of four
// gets us banned. The score halves every 60s, so one message per
// headerRefreshInterval settles at 66, over btcd's warn threshold; one per
// mempoolFanoutInterval settles near 34.
func (s *Server) mempoolFanoutDue() bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	now := time.Now()
	if !s.mempoolFanout.IsZero() && now.Sub(s.mempoolFanout) < mempoolFanoutInterval {
		return false
	}
	s.mempoolFanout = now
	return true
}

func (s *Server) mempoolPeer(ctx context.Context, p *rawpeer.RawPeer) {
	log.Tracef("mempoolPeer %v", p)
	defer log.Tracef("mempoolPeer %v exit", p)

	if !s.cfg.MempoolEnabled {
		return
	}

	// Don't ask for mempool if the other end does not advertise it.
	if !p.HasService(wire.SFNodeBloom) {
		return
	}

	err := p.Write(defaultCmdTimeout, wire.NewMsgMemPool())
	if err != nil {
		log.Debugf("mempool %v: %v", p, err)
		return
	}
}

func (s *Server) headersPeer(ctx context.Context, p *rawpeer.RawPeer) {
	log.Tracef("headersPeer %v", p)
	defer log.Tracef("headersPeer %v exit", p)

	// pm.All runs us untracked, so Run may close the store while we are
	// here and store calls fail with leveldb.ErrClosed. Bail on shutdown.
	if ctx.Err() != nil {
		return
	}
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		log.Errorf("headers peer block header best: %v %v", p, err)
		return
	}
	// A multi-hash locator, the same shape handlePeer builds on connect. A
	// peer that does not recognise a lone tip hash answers from genesis, so
	// a lagging or forked peer would send 2000 duplicate headers on every
	// refresh and never teach us about the fork.
	err = s.getHeadersByHeights(ctx, p, &bhb.Hash, bhb.Height, bhb.Height-1000,
		bhb.Height-1999, previousCheckpointHeight(bhb.Height, s.checkpoints))
	if err != nil {
		log.Errorf("headers peer sync indexers: %v", err)
		return
	}
}

func (s *Server) handleGeneric(ctx context.Context, p *rawpeer.RawPeer, msg wire.Message, raw []byte) error {
	// Do accept addr and ping commands before we consider the peer up.
	switch m := msg.(type) {
	case *wire.MsgAddr:
		if err := s.handleAddr(ctx, p, m); err != nil {
			return fmt.Errorf("handle generic addr: %w", err)
		}
	case *wire.MsgAddrV2:
		if err := s.handleAddrV2(ctx, p, m); err != nil {
			return fmt.Errorf("handle generic addr v2: %w", err)
		}

	case *wire.MsgBlock:
		if err := s.handleBlock(ctx, p, m, raw); err != nil {
			return fmt.Errorf("handle generic block: %w", err)
		}

	case *wire.MsgTx:
		if err := s.handleTx(ctx, p, m, raw); err != nil {
			return fmt.Errorf("handle generic transaction: %w", err)
		}

	case *wire.MsgInv:
		if err := s.handleInv(ctx, p, m, raw); err != nil {
			return fmt.Errorf("handle generic inv: %w", err)
		}

	case *wire.MsgPing:
		if err := s.handlePing(ctx, p, m); err != nil {
			return fmt.Errorf("handle generic ping: %w", err)
		}

	case *wire.MsgPong:
		if err := s.handlePong(ctx, p, m); err != nil {
			return fmt.Errorf("handle generic pong: %w", err)
		}

	case *wire.MsgNotFound:
		if err := s.handleNotFound(ctx, p, m, raw); err != nil {
			return fmt.Errorf("handle generic not found: %w", err)
		}

	case *wire.MsgGetData:
		if err := s.handleGetData(ctx, p, m, raw); err != nil {
			return fmt.Errorf("handle generic get data: %w", err)
		}

	case *wire.MsgMemPool:
		log.Infof("mempool: %v", spew.Sdump(m))

	case *wire.MsgHeaders:
		if err := s.handleHeaders(ctx, p, m); err != nil {
			return err
		}

	default:
		log.Tracef("unhandled message type %v: %T\n", p, msg)
	}
	return nil
}

// acceptPeerHeight returns true if a peer's advertised best block height is
// at or above our indexed block frontier. See peerHeightAcceptable.
func acceptPeerHeight(remoteLast int32, frontier uint64) bool {
	return uint64(remoteLast) >= frontier
}

// peerHeightAcceptable reports whether a peer advertising remoteLast as its
// best block height is worth keeping. The threshold is our indexed block
// frontier (the UTXO index height), not the header tip: the tip routinely
// leads block download (headers-first IBD, op-geth calling
// BlockHeadersInsert), and gating on it rejects the peers holding the bodies
// we need. The indexed height only advances on blocks we processed, so it
// never runs ahead of the live chain. A peer that cannot serve the bodies we
// request is dropped by blockExpired.
func (s *Server) peerHeightAcceptable(ctx context.Context, remoteLast int32) (bool, error) {
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		return false, err
	}
	return acceptPeerHeight(remoteLast, utxoHH.Height), nil
}

func (s *Server) handlePeer(ctx context.Context, p *rawpeer.RawPeer) error {
	log.Tracef("handlePeer %v", p)

	var readError error
	defer func() {
		re := ""
		if readError != nil {
			re = fmt.Sprintf(" error: %v", readError)
		}
		// kill pending blocks and pings
		findPeer := func(value any) bool {
			if pp, ok := value.(*rawpeer.RawPeer); ok && pp.String() == p.String() {
				return true
			}
			return false
		}
		blks := s.blocks.DeleteByValue(findPeer)
		pings := s.pings.DeleteByValue(findPeer)
		log.Infof("Disconnected: %v blocks %v pings %v%v", p, blks, pings, re)

		// Not an interesting error since it races.
		_ = s.pm.Bad(ctx, p.String()) // always close peer
	}()

	// Ensure peer height is greater than ours.
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		readError = err
		return fmt.Errorf("handle peer: %w", err)
	}
	remoteVersion, err := p.RemoteVersion()
	if err != nil {
		readError = err
		return fmt.Errorf("peer remote version: %w", err)
	}
	accept, err := s.peerHeightAcceptable(ctx, remoteVersion.LastBlock)
	if err != nil {
		readError = err
		return fmt.Errorf("utxo index hash: %w", err)
	}
	if !accept {
		// Skip peers behind our indexed frontier: they cannot serve a block
		// we still need. Set readError so the Disconnected line records why.
		readError = errors.New("remote peer height below our indexed frontier")
		return readError
	}
	if err := s.getHeadersByHeights(ctx, p, &bhb.Hash,
		bhb.Height, bhb.Height-1000, bhb.Height-1999,
		previousCheckpointHeight(bhb.Height, s.checkpoints)); err != nil {
		readError = err
		return fmt.Errorf("handle peer heights: %w", err)
	}

	// Get p2p information.
	err = p.Write(defaultCmdTimeout, wire.NewMsgGetAddr())
	if err != nil {
		readError = err
		return err
	}

	// Broadcast all tx's to new node.
	err = s.TxBroadcastAllToPeer(ctx, p)
	if err != nil {
		readError = err
		return err
	}

	// If we are caught up start collecting mempool data.
	if s.cfg.MempoolEnabled && p.HasService(wire.SFNodeBloom) && s.Synced(ctx).Synced {
		err := p.Write(defaultCmdTimeout, wire.NewMsgMemPool())
		if err != nil {
			readError = err
			return fmt.Errorf("mempool %v: %w", p, err)
		}
	}

	// XXX wave hands here for now but we should get 3 peers to agree that
	// this is a fork indeed.

	// Only now can we consider the peer connected
	verbose := false
	log.Infof("Connected: %v version %v agent %v", p,
		remoteVersion.ProtocolVersion, remoteVersion.UserAgent)
	defer log.Debugf("disconnect: %v", p)
	for {
		// See if we were interrupted, for the love of pete add ctx to wire
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Don't set a deadline. There is plenty of write activity that
		// will timeout on its own and cause a close resulting in the
		// err path being taken.
		msg, raw, err := p.Read(0)
		if errors.Is(err, wire.ErrUnknownMessage) {
			// skip unknown message
			continue
		} else if err != nil {
			readError = err
			return err
		}

		if verbose {
			log.Infof("%v: %v", p, spew.Sdump(msg))
		}

		err = s.handleGeneric(ctx, p, msg, raw)
		if err != nil {
			if errors.Is(err, ErrAlreadyIndexing) {
				continue
			}
			return err
		}
	}
}

func (s *Server) Running() bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return s.isRunning
}

func (s *Server) testAndSetRunning(b bool) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	old := s.isRunning
	s.isRunning = b
	return old != s.isRunning
}

func (s *Server) promRunning() float64 {
	r := s.Running()
	if r {
		return 1
	}
	return 0
}

func (s *Server) promBlocksMissing() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat((s.prom.syncInfo.AtLeastMissing))
}

func (s *Server) promSynced() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.prom.syncInfo.Synced {
		return 1
	}
	return 0
}

func (s *Server) promBlockHeader(m *prometheus.GaugeVec) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	bh := s.prom.syncInfo.BlockHeader

	m.Reset()
	m.With(prometheus.Labels{
		"hash":      bh.Hash.String(),
		"timestamp": strconv.Itoa(int(bh.Timestamp)),
	}).Set(deucalion.Uint64ToFloat(bh.Height))
}

func (s *Server) promUtxo() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.Uint64ToFloat(s.prom.syncInfo.Utxo.Height)
}

func (s *Server) promTx() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.Uint64ToFloat(s.prom.syncInfo.Tx.Height)
}

func (s *Server) promKeystone() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.Uint64ToFloat(s.prom.syncInfo.Keystone.Height)
}

func (s *Server) promConnectedPeers() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.connected)
}

func (s *Server) promGoodPeers() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.good)
}

func (s *Server) promBadPeers() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.bad)
}

func (s *Server) promMempoolCount() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.mempoolCount)
}

func (s *Server) promMempoolSize() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.mempoolSize)
}

func (s *Server) promBlockCacheHits() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.blockCache.Hits)
}

func (s *Server) promBlockCacheMisses() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.blockCache.Misses)
}

func (s *Server) promBlockCachePurges() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.blockCache.Purges)
}

func (s *Server) promBlockCacheSize() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.blockCache.Size)
}

func (s *Server) promBlockCacheItems() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.blockCache.Items)
}

func (s *Server) promHeaderCacheHits() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.headerCache.Hits)
}

func (s *Server) promHeaderCacheMisses() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.headerCache.Misses)
}

func (s *Server) promHeaderCachePurges() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.headerCache.Purges)
}

func (s *Server) promHeaderCacheSize() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.headerCache.Size)
}

func (s *Server) promHeaderCacheItems() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.IntToFloat(s.prom.headerCache.Items)
}

func (s *Server) promDiskFree() float64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return deucalion.Uint64ToFloat(s.prom.diskFree)
}

func diskFree(path string) (uint64, error) {
	du, err := disk.Usage(path)
	if err != nil {
		return 0, fmt.Errorf("usage: %w", err)
	}
	return du.Free, nil
}

func (s *Server) promPoll(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}

		s.prom.syncInfo = s.Synced(ctx)
		s.prom.connected, s.prom.good, s.prom.bad = s.pm.Stats()
		s.prom.blockCache = s.db.BlockCacheStats()
		s.prom.headerCache = s.db.BlockHeaderCacheStats()
		if s.cfg.MempoolEnabled {
			s.prom.mempoolCount, s.prom.mempoolSize = s.mempool.stats(ctx)
		}

		if s.promPollVerbose {
			s.mtx.RLock()
			log.Infof("Pending blocks %v/%v connected peers %v "+
				"good peers %v bad peers %v mempool %v %v "+
				"block cache hits: %v misses: %v purges: %v size: %v "+
				"blocks: %v",
				s.blocks.Len(), defaultPendingBlocks, s.prom.connected,
				s.prom.good, s.prom.bad, s.prom.mempoolCount,
				humanize.Bytes(uint64(s.prom.mempoolSize)),
				s.prom.blockCache.Hits, s.prom.blockCache.Misses,
				s.prom.blockCache.Purges,
				humanize.Bytes(uint64(s.prom.blockCache.Size)),
				s.prom.blockCache.Items)
			s.mtx.RUnlock()
		}
	}
}

// blksMissing checks the block cache and the database and returns true if all
// blocks have not been downloaded. This function must be called with the lock
// held.
// XXX do we still need a locked/unlocked version of this code?
func (s *Server) blksMissing(ctx context.Context) bool {
	// Do cheap memory check first
	if s.blocks.Len() != 0 {
		return true
	}

	// Do expensive database check
	bm, err := s.db.BlocksMissing(ctx, 1)
	if err != nil {
		log.Errorf("blocks missing: %v", err)
		return true // this is really kind of terminal
	}
	return len(bm) > 0
}

func (s *Server) handleAddr(_ context.Context, p *rawpeer.RawPeer, msg *wire.MsgAddr) error {
	log.Tracef("handleAddr (%v): %v", p, len(msg.AddrList))
	defer log.Tracef("handleAddr exit (%v)", p)

	peers := make([]string, len(msg.AddrList))
	for i, a := range msg.AddrList {
		peers[i] = net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port)))
	}

	s.pm.HandleAddr(peers)

	return nil
}

func (s *Server) handleAddrV2(_ context.Context, p *rawpeer.RawPeer, msg *wire.MsgAddrV2) error {
	log.Tracef("handleAddrV2 (%v): %v", p, len(msg.AddrList))
	defer log.Tracef("handleAddrV2 exit (%v)", p)

	peers := make([]string, 0, len(msg.AddrList))
	for _, a := range msg.AddrList {
		if a.Addr == nil {
			// Truncated addrv2 entry decodes with a nil Addr; skip it
			// rather than nil-deref and crash the process.
			continue
		}
		addr := net.JoinHostPort(a.Addr.String(), strconv.Itoa(int(a.Port)))
		if len(addr) < 7 {
			// 0.0.0.0
			continue
		}
		peers = append(peers, addr)
	}

	s.pm.HandleAddr(peers)

	return nil
}

func (s *Server) handlePing(ctx context.Context, p *rawpeer.RawPeer, msg *wire.MsgPing) error {
	log.Tracef("handlePing %v", p)
	defer log.Tracef("handlePing exit %v", p)

	pong := wire.NewMsgPong(msg.Nonce)
	err := p.Write(defaultCmdTimeout, pong)
	if err != nil {
		return fmt.Errorf("could not write pong message %v: %w", p, err)
	}
	log.Tracef("handlePing %v: pong %v", p, pong.Nonce)

	return nil
}

func (s *Server) handlePong(ctx context.Context, p *rawpeer.RawPeer, pong *wire.MsgPong) error {
	log.Tracef("handlePong %v", p)
	defer log.Tracef("handlePong exit %v", p)

	if err := s.pings.Cancel(p.String()); err != nil {
		return fmt.Errorf("cancel: %w", err)
	}

	log.Tracef("handlePong %v: pong %v", p, pong.Nonce)
	return nil
}

func (s *Server) downloadBlock(ctx context.Context, p *rawpeer.RawPeer, ch chainhash.Hash) error {
	log.Tracef("downloadBlock")
	defer log.Tracef("downloadBlock exit")

	getData := wire.NewMsgGetData()
	getData.InvList = append(getData.InvList,
		&wire.InvVect{
			Type: wire.InvTypeBlock,
			Hash: ch,
		})

	// Do not hold s.mtx across the write. It can block for
	// defaultCmdTimeout against a peer that stops reading its socket,
	// stalling every other user of the mutex. getData is local and
	// rawpeer.Write serializes on its own mutex.
	err := p.Write(defaultCmdTimeout, getData)
	if err != nil {
		if !errors.Is(err, net.ErrClosed) &&
			!errors.Is(err, os.ErrDeadlineExceeded) &&
			!errors.Is(err, rawpeer.ErrNoConn) {
			log.Errorf("download block write: %v %v", p, err)
		}
	}
	return err
}

func (s *Server) downloadBlockFromRandomPeer(ctx context.Context, block chainhash.Hash) error {
	log.Tracef("downloadBlockFromRandomPeer")
	defer log.Tracef("downloadBlockFromRandomPeer exit")

	rp, err := s.pm.Random()
	if err != nil {
		return fmt.Errorf("random peer %v: %w", block, err)
	}
	s.blocks.Put(ctx, defaultBlockPendingTimeout, block.String(), rp,
		s.blockExpired, nil)
	// Not an error. Checking and logging this will fill up logs with EOF.
	//nolint:errcheck // Error is intentionally ignored.
	go s.downloadBlock(ctx, rp, block)

	return nil
}

func (s *Server) DownloadBlockFromRandomPeers(ctx context.Context, block chainhash.Hash, count uint) (*btcutil.Block, error) {
	log.Tracef("DownloadBlockFromRandomPeers %v %v", count, block)
	defer log.Tracef("DownloadBlockFromRandomPeers %v %v exit", count, block)

	blk, err := s.db.BlockByHash(ctx, block)
	if err != nil {
		if errors.Is(err, database.ErrBlockNotFound) {
			for range count {
				err := s.downloadBlockFromRandomPeer(ctx, block)
				if err != nil {
					log.Errorf("async download: %v", err)
					continue
				}
			}
			return nil, nil
		}
		return nil, err
	}

	return blk, nil
}

func (s *Server) handleBlockExpired(ctx context.Context, key any, value any) error {
	log.Tracef("handleBlockExpired")
	defer log.Tracef("handleBlockExpired exit")

	// handleBlockExpired is called numerous times after SIGTERM. This call
	// will fail with database closed error and is very loud.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	p, ok := value.(*rawpeer.RawPeer)
	if !ok {
		// this really should not happen
		return fmt.Errorf("invalid peer type: %T", value)
	}
	if _, ok := key.(string); !ok {
		// this really should not happen
		return fmt.Errorf("invalid key type: %T", key)
	}

	// Ensure block is on main chain, if it is not it is deleted from
	// blocks missing database.
	hash, err := chainhash.NewHashFromStr(key.(string))
	if err != nil {
		return fmt.Errorf("new hash: %w", err)
	}
	bhX, err := s.db.BlockHeaderByHash(ctx, *hash)
	if err != nil {
		return fmt.Errorf("block header by hash: %w", err)
	}
	// isCanonical's error is deliberately ignored, as in upstream main
	// (heminetwork PR #659). On error canonical is false, so the block is
	// dropped from blocks missing instead of blockExpired killing the peer.
	canonical, _ := s.isCanonical(ctx, bhX)

	if !canonical {
		log.Infof("Deleting from blocks missing database: %v %v %v",
			p, bhX.Height, bhX)
		err := s.db.BlockMissingDelete(ctx, int64(bhX.Height), bhX.Hash)
		if err != nil {
			return fmt.Errorf("block expired delete missing: %w", err)
		}

		// Block exists on a fork, stop downloading it.
		return nil
	}

	log.Infof("Block expired: %v %v", p, hash)

	// Legit timeout, return error so that it can be retried.
	return fmt.Errorf("timeout %v", key)
}

func (s *Server) blockExpired(ctx context.Context, key any, value any) {
	log.Tracef("blockExpired")
	defer log.Tracef("blockExpired exit")

	err := s.handleBlockExpired(ctx, key, value)
	if err != nil {
		// Close peer.
		if p, ok := value.(*rawpeer.RawPeer); ok {
			p.Close() // kill peer
			if !errors.Is(err, leveldb.ErrClosed) {
				log.Errorf("block expired: %v %v", p, err)
			}
		}
	}
}

func (s *Server) downloadMissingTx(ctx context.Context, p *rawpeer.RawPeer) error {
	log.Tracef("downloadMissingTx")
	defer log.Tracef("downloadMissingTx exit")

	getData, err := s.mempool.getDataConstruct(ctx)
	if err != nil {
		return fmt.Errorf("download missing tx: %w", err)
	}
	err = p.Write(defaultCmdTimeout, getData)
	if err != nil {
		// peer dead, make sure it is reaped
		p.Close() // XXX this should not happen here
		if !errors.Is(err, net.ErrClosed) &&
			!errors.Is(err, os.ErrDeadlineExceeded) {
			log.Errorf("download missing tx write: %v %v", p, err)
		}
	}
	return err
}

func (s *Server) handleTx(ctx context.Context, p *rawpeer.RawPeer, msg *wire.MsgTx, raw []byte) error {
	log.Tracef("handleTx")
	defer log.Tracef("handleTx exit")

	if !(s.cfg.MempoolEnabled && s.Synced(ctx).Synced) {
		return nil
	}

	// If we have processed this tx in the past, exit. This is a little
	// racy but it is worth pre-testing to prevent expensive database
	// lookups to determine input values.
	if s.mempool.txProcessed(msg.TxHash()) {
		return nil
	}

	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return err // should not happen so fail
	}

	// Reject obvious bad tx' here
	utx := btcutil.NewTx(msg)
	err = btcmempool.CheckTransactionStandard(utx, int32(bhb.Height)+1, bhb.Timestamp(),
		btcmempool.DefaultMinRelayTxFee, MaxTxVersion)
	if err != nil {
		// do allow runes which are rejected, this is a really shitty test though
		seen := 0
		for k := range msg.TxOut {
			// out 0 op_return
			//     1 witness_v1_taproot
			//     2 witness_v0_scripthash
			//     3 witness_v0_scripthash
			switch k {
			case 0:
				if txscript.IsNullData(msg.TxOut[k].PkScript) {
					seen++
				}
			case 1:
				if txscript.IsPayToTaproot(msg.TxOut[k].PkScript) {
					seen++
				}
			case 2:
				if txscript.IsPayToWitnessScriptHash(msg.TxOut[k].PkScript) {
					seen++
				}
			case 3:
				if txscript.IsPayToWitnessScriptHash(msg.TxOut[k].PkScript) {
					seen++
				}
			default:
				seen = 0 // force failure
			}
		}
		if seen != 4 {
			return nil
		}
	}

	mptx, err := s.mempoolTxNew(ctx, utx)
	if err != nil {
		return fmt.Errorf("new mempool tx: %w", err)
	}
	return s.mempool.TxInsert(ctx, mptx)
}

func (s *Server) syncBlocks(ctx context.Context) {
	log.Tracef("syncBlocks")
	defer log.Tracef("syncBlocks exit")

	// Set to true to disallow blocks to be downloaded in parallel with
	// blockheaders.
	if false {
		// See where best block is at
		bhb, err := s.db.BlockHeaderBest(ctx)
		if err != nil {
			log.Errorf("sync blocks: %v", err)
			return
		}
		if time.Since(bhb.Timestamp()) > 4*time.Hour {
			return
		}
	}

	// Prevent race condition with 'want', which may cause the cache
	// capacity to be exceeded.
	s.mtx.Lock()
	defer s.mtx.Unlock()

	want := defaultPendingBlocks - s.blocks.Len()
	if want <= 0 {
		return
	}
	bm, err := s.db.BlocksMissing(ctx, want)
	if err != nil {
		log.Errorf("blocks missing: %v", err)
		return
	}

	if len(bm) == 0 {
		// Exit if AutoIndex isn't enabled.
		if !s.cfg.AutoIndex {
			return
		}
		// XXX rethink closure, this is because of index flag mutex.
		go func() {
			var (
				eval  database.BlockNotFoundError
				block chainhash.Hash
			)
			err := s.SyncIndexersToBest(ctx)
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, context.Canceled):
				return
			case errors.Is(err, leveldb.ErrClosed):
				return
			case errors.Is(err, ErrAlreadyIndexing):
				return

			case errors.As(err, &eval):
				block = eval.Hash
				err := s.downloadBlockFromRandomPeer(ctx, block)
				if err != nil {
					log.Errorf("download block random peer: %v", err)
				} else {
					log.Infof("Download missed block: %v", block)
				}
				return

			default:
				// Don't panic on errors caused by our own
				// shutdown. This goroutine is not in s.wg,
				// so it can outlive Run closing the store,
				// and some of the resulting errors (e.g.
				// goleveldb's unexported errTransactionDone)
				// cannot be matched above.
				if ctx.Err() != nil {
					log.Debugf("sync blocks during shutdown: %v", err)
					return
				}
				panic(fmt.Errorf("sync blocks: %T %w", err, err))
			}

			// Get block headers that we missed during indexing.
			if s.Synced(ctx).Synced {
				s.mtx.Lock()
				ib := s.invBlocks
				// Fresh map, not clear(s.invBlocks): ib is read
				// below after the unlock while peer goroutines
				// keep inserting via invInsertUnlocked.
				s.invBlocks = make(map[chainhash.Hash]struct{}, 16)
				s.mtx.Unlock()

				// Count announcements whose headers we still
				// lack. Only the count is used; the fan-out
				// below asks for what follows our tip, never
				// for these hashes.
				missed := 0
				for h := range ib {
					if _, _, err := s.BlockHeaderByHash(ctx, h); err != nil {
						missed++
					}
				}

				// Flush out blocks we saw during quiece.
				log.Debugf("download missed block headers %v", missed)

				// This MUST stay gated on missed != 0. A peer
				// at our tip answers getheaders with an empty
				// headers message, which handleHeaders turns
				// into another syncBlocks call that lands
				// here, so an ungated fan-out loops forever on
				// an idle node.
				if missed == 0 {
					log.Debugf("nothing to do")
					return
				}

				// Rate limit the fan-out here, after the
				// have-filter, so a drain with nothing to do
				// never burns the token. A suppressed fan-out
				// is deferred, not lost: arm a single delayed
				// fan-out for when the window reopens. It asks
				// the same tip-anchored question, so it needs
				// none of the hashes.
				if !s.drainFanoutDue() {
					s.mtx.Lock()
					if !s.drainRetryPending {
						s.drainRetryPending = true
						wait := max(0, drainFanoutInterval-time.Since(s.drainFanout))
						time.AfterFunc(wait, func() {
							s.mtx.Lock()
							s.drainRetryPending = false
							s.mtx.Unlock()
							// Skip if another fan-out
							// took the token first; it
							// asked the same question.
							if ctx.Err() == nil && s.drainFanoutDue() {
								s.pm.All(ctx, s.headersPeer)
							}
						})
					}
					s.mtx.Unlock()
					log.Debugf("drain fan-out rate limited, %v missing", missed)
					return
				}

				// Ask every peer for the headers that follow
				// our canonical tip, not for the announced
				// hashes. A locator of hashes we lack makes
				// peers answer with their children, which do
				// not connect, and a locator of more than 101
				// entries gets us disconnected by Bitcoin Core.
				//
				// pm.All, not pm.AllBlock, so one wedged peer
				// cannot stall this goroutine for
				// defaultCmdTimeout. If no request gets out,
				// the periodic header refresh in Run asks
				// again within headerRefreshInterval.
				s.pm.All(ctx, s.headersPeer)
			} else {
				// Not synced: deliberately not rate limited.
				// Sharing drainFanoutDue's token would let
				// these calls starve the synced drain above.
				log.Debugf("handle all")
				s.pm.All(ctx, s.headersPeer)
			}
		}()
		return
	}

	for k := range bm {
		bi := bm[k]
		hash, _ := chainhash.NewHash(bi.Hash[:])
		hashS := hash.String()
		if _, _, err := s.blocks.Get(hashS); err == nil {
			// Already being downloaded.
			continue
		}
		if err := s.downloadBlockFromRandomPeer(ctx, *hash); err != nil {
			// This can happen during startup or when the network
			// is starved.
			// XXX: Probably too loud, remove later.
			select {
			case <-ctx.Done():
				return
			default:
			}
			log.Errorf("random peer %v: %v", hashS, err)
			return
		}
	}
}

// RemoveExternalHeaders removes the provided headers from TBC's state knowledge,
// setting the canonical tip to the provided tip. This method can only be
// used when TBC is running in External Header Mode.
//
// The upstream state id is an optional identifier that the caller can use to track
// some upstream state which represents TBC's own state once this removal is
// performed. For example, op-geth uses this to track the hash of the EVM block
// which cumulatively represents TBC's entire header knowledge after the removal
// is processed, such that re-applying all Bitcoin Attributes Deposited transactions
// in the EVM from genesis to that hash would result in TBC having this state.
//
// This upstream state id is tracked in TBC rather than upstream in the caller so
// that updates to the upstreamCursor are always made atomically with the
// corresponding TBC database state transition. Otherwise, an unexpected termination
// between updating TBC state and recording the updated upstreamCursor could cause
// state corruption.
func (s *Server) RemoveExternalHeaders(ctx context.Context, headers *wire.MsgHeaders, tipAfterRemoval *wire.BlockHeader, upstreamStateId []byte) (tbcd.RemoveType, *tbcd.BlockHeader, error) {
	if !s.cfg.ExternalHeaderMode {
		return tbcd.RTInvalid, nil,
			errors.New("RemoveExternalHeaders called on TBC instance that is not in external header mode")
	}

	if len(headers.Headers) == 0 {
		return tbcd.RTInvalid, nil,
			errors.New("RemoveExternalHeaders called with no headers")
	}

	if upstreamStateId == nil {
		return tbcd.RTInvalid, nil,
			errors.New("upstream state invalid")
	}

	if tipAfterRemoval == nil {
		return tbcd.RTInvalid, nil,
			errors.New("RemoveExternalHeaders called with no tipAfterRemoval")
	}

	// Check that chain is contiguous
	for i := 1; i < len(headers.Headers); i++ {
		bh := headers.Headers[i].PrevBlock
		ph := headers.Headers[i-1].BlockHash()
		if !bh.IsEqual(&ph) {
			// Chain is not contiguous / linear as this block does
			// not connect to parent
			return tbcd.RTInvalid, nil,
				fmt.Errorf("remove external headers: header with hash %s at index %d does not connect to "+
					"previous header with hash %s at index %d",
					bh.String(), i, ph.String(), i-1)
		}
	}

	ph := func(ctx context.Context, batches map[string]tbcd.Batch) error {
		b, ok := batches[dbnames.MetadataDB]
		if !ok {
			return fmt.Errorf("post hook batch not found: %v",
				dbnames.MetadataDB)
		}
		level.BatchAppend(ctx, b.Batch, []tbcd.Row{
			{Key: upstreamStateIdKey, Value: upstreamStateId},
		})
		return nil
	}

	// We aren't checking error because we want to pass everything from db
	// upstream
	it, por, err := s.db.BlockHeadersRemove(ctx, headers, tipAfterRemoval, ph)

	// Caller of RemoveExternalHeaders wants fork geometry info, parent of
	// removal set, and must handle error upstream as an error here
	// generally represents an issue with the header additions/removals
	// provided by upstream code.
	return it, por, err
}

// AddExternalHeaders XXX if we are passing in upstreamStateId then why does
// the default live in tbcd?
func (s *Server) AddExternalHeaders(ctx context.Context, headers *wire.MsgHeaders, upstreamStateId []byte) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	if !s.cfg.ExternalHeaderMode {
		return tbcd.ITInvalid, nil, nil, 0,
			errors.New("AddExternalHeaders called on TBC instance that is not in external header mode")
	}

	if len(headers.Headers) == 0 {
		return tbcd.ITInvalid, nil, nil, 0,
			errors.New("AddExternalHeaders called with no headers")
	}

	if upstreamStateId == nil {
		return tbcd.ITInvalid, nil, nil, 0,
			errors.New("upstream state invalid")
	}

	// Check that chain is contiguous
	for i := 1; i < len(headers.Headers); i++ {
		bh := headers.Headers[i].PrevBlock
		ph := headers.Headers[i-1].BlockHash()
		if !bh.IsEqual(&ph) {
			// Chain is not contiguous / linear as this block does
			// not connect to parent
			return tbcd.ITInvalid, nil, nil, 0,
				fmt.Errorf("add external headers: header with hash %s at index %d does not connect to "+
					"previous header with hash %s at index %d",
					bh.String(), i, ph.String(), i-1)
		}
	}

	ph := func(ctx context.Context, batches map[string]tbcd.Batch) error {
		b, ok := batches[dbnames.MetadataDB]
		if !ok {
			return fmt.Errorf("post hook batch not found: %v",
				dbnames.MetadataDB)
		}
		level.BatchAppend(ctx, b.Batch, []tbcd.Row{
			{Key: upstreamStateIdKey, Value: upstreamStateId},
		})
		return nil
	}

	// We aren't checking error because we want to pass everything from db
	// upstream
	it, cbh, lbh, n, err := s.db.BlockHeadersInsert(ctx, headers, ph)

	// Caller of AddExternalHeaders wants fork geometry change, canonical
	// and last inserted header, and must handle error upstream as an error
	// here generally represents an issue with the header
	// additions/removals provided by upstream code.
	return it, cbh, lbh, n, err
}

// deterministicTimeSource disables the one wall-clock rule in btcd's header and
// block sanity checks: a timestamp more than two hours past AdjustedTime() is
// rejected. Block bodies and RPC inserts use it because they decide what is
// stored for the hVM, and a host clock that is off would make honest nodes
// store different data. The datadir identity check uses it because it checks
// network and proof-of-work identity, not time: a stored header may be any
// distance ahead of the current clock (accepted under an earlier clock, or by
// a body or RPC insert), and a time failure there would wrongly refuse to
// start. P2P headers use wallClockTimeSource instead.
//
// The constant is deliberately larger than the maximum uint32 value.
type deterministicTimeSource struct{}

func (deterministicTimeSource) AdjustedTime() time.Time         { return time.Unix(1<<40, 0) }
func (deterministicTimeSource) AddTimeSample(string, time.Time) {}
func (deterministicTimeSource) Offset() time.Duration           { return 0 }

// wallClockTimeSource is the host clock, for P2P headers. Dropping a header
// that is too far in the future stores nothing, and we ask for it again on a
// later getheaders once its time has come, so a skewed clock only delays sync.
// Without the limit a peer could use future timestamps to lower the required
// difficulty (testnet min-difficulty rule) or to place a far-future tip.
type wallClockTimeSource struct{}

func (wallClockTimeSource) AdjustedTime() time.Time         { return time.Unix(time.Now().Unix(), 0) }
func (wallClockTimeSource) AddTimeSample(string, time.Time) {}
func (wallClockTimeSource) Offset() time.Duration           { return 0 }

// stripLogLimiter throttles the witness-strip INFO lines.
//
// The event is not lost: it is a normal condition on the Bitcoin P2P path (TBC never requests witness,
// but a BIP144 peer may serve it anyway), and the per-transaction count is what an operator needs, not
// the per-block line.
// Deliberately hand-rolled rather than golang.org/x/time/rate: that would add a module dependency to
// heminetwork purely to throttle one log line.
var stripLogLast atomic.Int64

func stripLogAllow() bool {
	const every = int64(5 * time.Second)
	now := time.Now().UnixNano()
	for {
		last := stripLogLast.Load()
		if now-last < every {
			return false
		}
		if stripLogLast.CompareAndSwap(last, now) {
			return true
		}
	}
}

// StripBlockWitness clears segwit witness data from every transaction of a Bitcoin block, in place,
// and returns the number of transactions that carried any.
//
// Note that witness handling has been added in upstream TBC, so these changes can be removed with
// a coordinated op-geth activation timestamp for returning valid witness data.
func StripBlockWitness(blk *wire.MsgBlock) int {
	if blk == nil {
		return 0
	}
	n := 0
	for _, tx := range blk.Transactions {
		if tx == nil {
			continue
		}
		carried := false
		for _, in := range tx.TxIn {
			// A nil *TxIn cannot come off the wire -- btcd's decoder never produces one -- but a
			// JSON-decoded block can carry one, and this function is on that path.
			//
			// THIS GUARD PROTECTS THIS LOOP AND NOTHING ELSE. It does not make the tbcapi insert
			// handler safe: btcd dereferences the same nils a few lines later, in
			// MsgBlock.SerializeSizeStripped under blockchain.CheckBlockSanity. The check that
			// actually closes it is rejectNilBlockElements in rpc.go, which runs ahead of every
			// consumer.
			if in == nil {
				continue
			}
			// len(), not != nil: btcd decodes a witness field as make([][]byte, count), so under
			// BIP144 every input of a witness-serialized body has a NON-NIL slice, including inputs
			// carrying no witness bytes at all. Testing != nil would report honest bodies as stripped.
			if len(in.Witness) != 0 {
				in.Witness = nil
				carried = true
			}
		}
		if carried {
			n++
		}
	}
	return n
}

// futureWarnDue rate limits handleHeaders' warning about headers dated more
// than two hours ahead to one per ten minutes. A peer can trigger the drop at
// will, so the warning must not be per message.
func (s *Server) futureWarnDue() bool {
	const every = int64(10 * time.Minute)
	now := time.Now().UnixNano()
	last := s.futureWarnLast.Load()
	return now-last >= every && s.futureWarnLast.CompareAndSwap(last, now)
}

// verifyHeadersPoW checks headers in order against their own claimed
// proof-of-work target and the two hour future limit, and returns how many
// leading headers may be processed now. A header too far in the future is not
// an error, as in Bitcoin Core: it and everything after it are dropped without
// blaming the peer, and we ask for them again later. Headers after the cut
// are not checked at all. This relies on btcd checking proof-of-work before
// the timestamp, so an unmined first future header is still an error.
func (s *Server) verifyHeadersPoW(headers []*wire.BlockHeader) (int, error) {
	for i, hdr := range headers {
		err := blockchain.CheckBlockHeaderSanity(hdr, s.chainParams.PowLimit,
			wallClockTimeSource{}, blockchain.BFNone)
		if err == nil {
			continue
		}
		var re blockchain.RuleError
		if errors.As(err, &re) && re.ErrorCode == blockchain.ErrTimeTooNew {
			return i, nil
		}
		return 0, fmt.Errorf("header %d of %d proof-of-work: %w", i, len(headers), err)
	}
	return len(headers), nil
}

// verifyHeaderBatchShape rejects a headers message whose headers do not form a single chain.
//
// An honest headers message is a contiguous chain by protocol, so this cannot reject honest data.
func verifyHeaderBatchShape(headers []*wire.BlockHeader) error {
	for i := 1; i < len(headers); i++ {
		prev := headers[i-1].BlockHash()
		if !headers[i].PrevBlock.IsEqual(&prev) {
			return fmt.Errorf("header %d of %d does not connect: prev block %v, expected %v",
				i, len(headers), headers[i].PrevBlock, prev)
		}
	}
	return nil
}

func (s *Server) handleHeaders(ctx context.Context, p *rawpeer.RawPeer, msg *wire.MsgHeaders) error {
	log.Tracef("handleHeaders (%v): %v", p, len(msg.Headers))
	defer log.Tracef("handleHeaders exit (%v): %v", p, len(msg.Headers))

	// Check contiguity once, outside s.mtx: it costs a double-SHA256 per
	// header, the quiesce branch needs it to decide whether to buffer the
	// message, and validation below reuses it.
	shapeErr := verifyHeaderBatchShape(msg.Headers)

	// When quiesced do not handle headers but do cache them.
	s.mtx.Lock()
	if s.indexing {
		// Record only the last header hash. A valid batch is a
		// chain, so its tip is enough to note that we are behind;
		// the drain's have-filter works out the rest.
		if n := len(msg.Headers); n > 0 {
			if s.invInsertUnlocked(msg.Headers[n-1].BlockHash()) {
				log.Debugf("handleHeaders indexing %v %v",
					len(msg.Headers), len(s.invBlocks))
			}
		}

		// An empty headers message means the peer thinks we are at the
		// tip. There is nothing to buffer, but outside quiesce it kicks
		// syncBlocks, which downloads missing blocks. Record it so the
		// replay issues at most one kick for the whole pass.
		if len(msg.Headers) == 0 {
			s.deferredEmpty = true
		}

		// Buffer the header data, not just the hash, so it is applied
		// once indexing finishes. Otherwise recovery depends on a
		// later answer happening to arrive between indexing passes,
		// which may never happen with a busy indexer.
		if shapeErr == nil {
			s.deferHeadersUnlocked(p, msg)
		}

		s.mtx.Unlock()
		return ErrAlreadyIndexing
	}
	s.mtx.Unlock()

	if len(msg.Headers) == 0 {
		// This may signify the end of IBD but isn't 100%.
		if s.blksMissing(ctx) {
			bhb, err := s.db.BlockHeaderBest(ctx)
			if err != nil {
				log.Errorf("blockheaders %v: %v", p, err)
			} else {
				log.Debugf("blockheaders caught up at %v: %v",
					p, bhb.HH())
			}
		} else {
			if s.cfg.MempoolEnabled && s.Synced(ctx).Synced &&
				s.mempoolFanoutDue() {
				// Start building the mempool.
				s.pm.All(ctx, s.mempoolPeer)
			}
		}

		// Always call syncBlocks, it either downloads more blocks or
		// kicks of indexing.
		//
		// Not rate limited: this (or its deferred replay) is what
		// starts block download, as handleBlock's kick needs a block
		// to arrive first. The synced drain's getheaders fan-out is
		// rate limited inside syncBlocks instead.
		go s.syncBlocks(ctx)

		return nil
	}

	// // Diagnostic for a failed get headers command.
	// if s.chainParams.GenesisHash.IsEqual(&msg.Headers[0].PrevBlock) {
	//	bhb, err := s.db.BlockHeaderBest(ctx)
	//	if err != nil {
	//		return fmt.Errorf("blockheaders genesis %v: %w", p, err)
	//	}
	//	if bhb.Height != 0 {
	//		panic("got genesis")
	//	}
	// }

	// This code works because duplicate blockheaders are rejected later on
	// but only after a somewhat expensive parameter setup and database
	// call.
	//
	// There really is no good way of determining if we can escape the
	// expensive calls so we just eat it.
	var pbhHash *chainhash.Hash
	for k := range msg.Headers {
		if pbhHash != nil && pbhHash.IsEqual(&msg.Headers[k].PrevBlock) {
			return fmt.Errorf("cannot connect %v index %v",
				msg.Headers[k].PrevBlock, k)
		}
		pbhHash = &msg.Headers[k].PrevBlock
	}

	// Contiguity must be checked before the context gate below. It lets the
	// gate treat a stored tip as proof that the whole batch is stored;
	// otherwise a crafted batch [garbage, known_tip] would skip the context
	// check. It is checked on the full batch, before future headers are
	// dropped, so a malformed batch is refused whatever it starts with.
	if err := shapeErr; err != nil {
		return fmt.Errorf("handle headers %v: %w", p, err)
	}
	// Validate before the store. ldb.BlockHeadersInsert assigns heights and cumulative work
	// positionally and the store exposes no delete, so anything admitted here is permanent.
	n, err := s.verifyHeadersPoW(msg.Headers)
	if err != nil {
		return fmt.Errorf("handle headers %v: %w", p, err)
	}
	if n < len(msg.Headers) {
		h := msg.Headers[n]
		log.Debugf("handle headers %v: dropping %v of %v headers starting at "+
			"%v, dated more than two hours ahead", p, len(msg.Headers)-n,
			len(msg.Headers), h.BlockHash())
		if s.futureWarnDue() {
			log.Warningf("Header %v is dated %v, more than two hours past "+
				"local time %v; it is ignored for now. If this persists, "+
				"check the system clock.", h.BlockHash(), h.Timestamp.UTC(),
				time.Now().UTC().Truncate(time.Second))
		}
		if n == 0 {
			// Nothing usable for now. An empty reply is what starts block
			// download, and a node whose clock is slow may never get one,
			// so start it here when blocks are missing. Unlike that path,
			// this does not start indexing or the mempool fan-out.
			if s.blksMissing(ctx) {
				go s.syncBlocks(ctx)
			}
			return nil
		}
		msg.Headers = msg.Headers[:n]
	}
	// The context check is expensive: a retarget-boundary header walks ~2015
	// ancestors. Skip it when the batch tip is already stored, since then
	// every header in the batch is too and the insert admits nothing new.
	// This stops a peer from cheaply replaying a known boundary header to
	// force that walk. PoW and contiguity above still run on every message.
	//
	// verifyHeaderContext is a no-op on PoWNoRetargeting networks, so skip
	// the tip lookup there as well.
	if !s.chainParams.PoWNoRetargeting {
		if _, err := s.db.BlockHeaderByHash(ctx, msg.Headers[len(msg.Headers)-1].BlockHash()); err != nil {
			if err := s.verifyHeaderContext(ctx, msg.Headers); err != nil {
				return fmt.Errorf("handle headers context %v: %w", p, err)
			}
		}
	}

	// When running in normal (not External Header) mode, do not set
	// upstream state IDs
	it, cbh, lbh, n, err := s.db.BlockHeadersInsert(ctx, msg, nil)
	if err != nil {
		// This ends the race between peers during IBD. It should
		// starve the slower peers and eventually we end up with one
		// peer for headers download.

		if errors.Is(err, database.ErrDuplicate) {
			// This happens when all block headers we asked for
			// already exist.

			// XXX for now don't do parallel blockheader downloads.
			// Seems to really slow the process down.
			//
			// We already have these headers. Ask for best headers
			// despite racing with other peers. We do that to
			// prevent stalling the download.
			// bhb, err := s.db.BlockHeaderBest(ctx)
			// if err != nil {
			//	log.Errorf("block header best %v: %v", p, err)
			//	return
			// }
			// if err = s.getHeaders(ctx, p, bhb.Header); err != nil {
			//	log.Errorf("get headers %v: %v", p, err)
			//	return
			// }
			return nil
		}
		// Real error, abort header fetch
		return fmt.Errorf("block headers insert: %w", err)
	}

	// Note that BlockHeadersInsert always returns the canonical tip
	// blockheader.
	var height uint64
	switch it {
	case tbcd.ITChainExtend:
		height = cbh.Height

		// Ask for next batch of headers at canonical tip.
		if err = s.getHeadersByHashes(ctx, p, cbh.BlockHash()); err != nil {
			return fmt.Errorf("get headers: %w", err)
		}

	case tbcd.ITForkExtend:
		height = lbh.Height

		// Ask for more block headers at the fork tip and also ask for
		// more block headers at canonical tip.
		if err = s.getHeadersByHashes(ctx, p, lbh.BlockHash(), cbh.BlockHash()); err != nil {
			return fmt.Errorf("get headers fork extend: %w", err)
		}

	case tbcd.ITChainFork:
		height = cbh.Height

		if s.Synced(ctx).Synced {
			// XXX this is racy but is a good enough test
			// to get past most of this.
			panic("chain forked, unwind/rewind indexes")
		}

		// Ask for more block headers at the fork tip and also ask for
		// more block headers at canonical tip.
		if err = s.getHeadersByHashes(ctx, p, lbh.BlockHash(), cbh.BlockHash()); err != nil {
			return fmt.Errorf("get headers fork: %w", err)
		}

	default:
		// Can't happen.
		return fmt.Errorf("invalid insert type: %d", it)
	}

	// log.Infof("Inserted (%v) %v block headers height %v", it, n, height)
	log.Infof("Inserted (%v) %v block headers height %v %v", it, n, height, p)

	return nil
}

// BlockInsert stores a Bitcoin block body.
//
// IT MUTATES blk IN PLACE: segwit witness is stripped from every transaction before the write (see
// StripBlockWitness for why). Callers must not share a *wire.MsgBlock across goroutines while
// calling this -- two concurrent callers on one block is a genuine data race, reproduced under
// -race. Every in-tree caller passes a block it owns exclusively.
//
// Note this is NOT the path tbcapi's block-insert handlers take; they write through s.db.BlockInsert
// directly and carry their own nil-element guard. See rejectNilTxElements.
func (s *Server) BlockInsert(ctx context.Context, blk *wire.MsgBlock) (int64, error) {
	// Reject nil elements before anything dereferences them. Embedders can hand us a block from any
	// source, including a JSON decoder; see rejectNilTxElements.
	if err := rejectNilBlockElements(blk); err != nil {
		return 0, err
	}
	// Embedders reach the block store through here, with bodies they obtained however they like --
	// for example the L2 Bitcoin block back-channel. This is the least-validated of the write paths (it
	// deliberately applies no sanity check, leaving that to the embedder), which makes it the one that
	// most needs the witness strip. See StripBlockWitness.
	if stripped := StripBlockWitness(blk); stripped != 0 && stripLogAllow() {
		log.Infof("BlockInsert: stripped segwit witness from %v transaction(s) of block %v; "+
			"TBC never requests witness data", stripped, blk.BlockHash())
	}
	return s.db.BlockInsert(ctx, btcutil.NewBlock(blk))
}

func (s *Server) BlockHeadersInsert(ctx context.Context, headers *wire.MsgHeaders) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	// Ensure that headers provided from upstream are contiguous
	if err := verifyHeaderBatchShape(headers.Headers); err != nil {
		return tbcd.ITInvalid, nil, nil, 0, err
	}
	// Difficulty is deliberately not checked here nor in AddExternalHeaders.
	// Both are driven by op-geth, which does its own hVM difficulty
	// enforcement and expects TBC to trust what it pushes; checking here
	// would reject headers op-geth considers valid. Untrusted headers arrive
	// via handleHeaders, which checks PoW and verifyHeaderContext.
	return s.db.BlockHeadersInsert(ctx, headers, nil)
}

func (s *Server) handleBlock(ctx context.Context, p *rawpeer.RawPeer, msg *wire.MsgBlock, raw []byte) error {
	log.Tracef("handleBlock (%v)", p)
	defer log.Tracef("handleBlock exit (%v)", p)

	stripped := StripBlockWitness(msg)
	block := btcutil.NewBlock(msg)
	bhs := block.Hash().String()
	// Not an error due to normal racing conditions.
	_, _ = s.blocks.Delete(bhs) // remove block from ttl regardless of insert result

	// Whatever happens, kick cache in the nuts on the way out.
	defer func() {
		// kick cache
		go s.syncBlocks(ctx)
	}()

	// Bind the body to the header before it can reach the store.
	if err := checkBlockMerkleRoot(block); err != nil {
		return fmt.Errorf("handle block %v: %w", bhs, err)
	}

	// Log only after the body is bound to the header, so that a malicious peer cannot
	// cause logging spam with invalid blocks.
	if stripped != 0 && stripLogAllow() {
		log.Infof("handleBlock (%v): stripped segwit witness from %v transaction(s) of block %v; "+
			"this peer sent witness data that was never requested", p, stripped, bhs)
	}

	if s.cfg.BlockSanity {
		// deterministicTimeSource, not wallClockTimeSource, so that the host
		// clock cannot make honest nodes store different blocks.
		err := blockchain.CheckBlockSanity(block, s.chainParams.PowLimit,
			deterministicTimeSource{})
		if err != nil {
			return fmt.Errorf("handle block unable to validate block hash %v: %w",
				bhs, err)
		}

		// Contextual check of block
		//
		// We do want these checks however we download the blockchain
		// out of order this we will have to do something clever for
		// prevNode.
		//
		// header := &block.MsgBlock().Header
		// flags := blockchain.BFNone
		// err := blockchain.CheckBlockHeaderContext(header, prevNode, flags, bctxt, false)
		// if err != nil {
		//	log.Errorf("Unable to validate context of block hash %v: %v", bhs, err)
		//	return
		// }
	}

	height, err := s.db.BlockInsert(ctx, block) // XXX see if we can use raw here
	if err != nil {
		return fmt.Errorf("database block insert %v: %w", bhs, err)
	} else {
		log.Infof("Insert block %v at %v txs %v %v", bhs, height,
			len(msg.Transactions), msg.Header.Timestamp)
	}

	// Reap broadcast messages.
	//
	// USE btcutil's cached hashes, NOT wire's TxHashes(). checkBlockMerkleRoot above already walked
	// every transaction through btcutil.Tx.Hash(), which memoises the txid on the Tx. wire's
	// MsgBlock.TxHashes() shares nothing with that cache and recomputes every double-SHA256 from
	// scratch.
	txs := block.Transactions()
	txHashes := make([]chainhash.Hash, 0, len(txs))
	for _, tx := range txs {
		txHashes = append(txHashes, *tx.Hash())
	}
	s.mtx.Lock()
	for _, v := range txHashes {
		if _, ok := s.broadcast[v]; ok {
			delete(s.broadcast, v)
			log.Infof("broadcast tx %v included in %v %v", v, bhs, height)
		}
	}
	s.mtx.Unlock()

	// Reap txs from mempool for blocks that are within defaultMempoolAge.
	// Sync flag is always false here so don't check it, just remove tx's
	// from mempool.
	blocktime := block.MsgBlock().Header.Timestamp
	now := time.Now()
	mempoolAge := now.Add(-defaultMempoolAge)
	if blocktime.After(mempoolAge) && s.cfg.MempoolEnabled {
		s.mempool.txsRemove(ctx, txHashes)
	}

	log.Debugf("inserted block at height %d, parent hash %s",
		height, block.MsgBlock().Header.PrevBlock)

	s.mtx.Lock()
	// Stats
	s.blocksSize += uint64(len(raw))
	s.blocksInserted++

	if now.After(s.printTime) {
		var (
			mempoolCount   int
			mempoolSize    int
			connectedPeers int
		)
		if s.cfg.MempoolEnabled {
			mempoolCount, mempoolSize = s.mempool.stats(ctx)
		}

		// Grab some peer stats as well
		connectedPeers, goodPeers, badPeers := s.pm.Stats()

		// This is super awkward but prevents calculating N inserts *
		// time.Before(10*time.Second).
		delta := now.Sub(s.printTime.Add(-10 * time.Second))

		log.Infof("Inserted %v blocks (%v) in the last %v",
			s.blocksInserted, humanize.Bytes(s.blocksSize), delta)
		log.Infof("Pending blocks %v/%v connected peers %v good peers %v "+
			"bad peers %v mempool %v %v",
			s.blocks.Len(), defaultPendingBlocks, connectedPeers, goodPeers,
			badPeers, mempoolCount, humanize.Bytes(uint64(mempoolSize)))

		// Reset stats
		s.blocksSize = 0
		s.blocksInserted = 0
		s.printTime = now.Add(10 * time.Second)
	}
	s.mtx.Unlock()

	return nil
}

func (s *Server) handleInv(ctx context.Context, p *rawpeer.RawPeer, msg *wire.MsgInv, raw []byte) error {
	// An empty inv is *legal* on the wire, but should not reach the indexing below.
	// Returning nil rather than an error is deliberate: an empty inv is not misbehaviour worth
	// dropping a peer over, and the loop below is already a no-op for zero items.
	if len(msg.InvList) == 0 {
		return nil
	}

	switch msg.InvList[0].Type {
	case wire.InvTypeTx:
	case wire.InvTypeBlock:
	default:
		// log.Infof("%v: %T", p, m)
		log.Infof("handleInv (%v) %v", p, msg.InvList[0].Type)
	}
	log.Tracef("handleInv (%v)", p)
	defer log.Tracef("handleInv exit (%v)", p)

	// Bound the header lookups an adversarial inv can force: a block inv
	// may carry up to 50000 entries, each costing a BlockHeaderByHash read.
	// We never send getblocks, so real block invs are small tip
	// announcements far below maxInvBlockScan. Anything dropped past the cap
	// is recovered by the periodic header refresh.

	var (
		txsFound     bool
		blockScanned int
	)

	for _, v := range msg.InvList {
		switch v.Type {
		case wire.InvTypeError:
			log.Errorf("inventory error: %v", v.Hash)
		case wire.InvTypeTx:
			// handle these later or else we have to insert txs one
			// at a time while taking a mutex.
			txsFound = true
		case wire.InvTypeBlock:
			// Past the cap, skip the lookup but keep scanning so
			// trailing tx invs are still seen.
			if blockScanned++; blockScanned > maxInvBlockScan {
				if blockScanned == maxInvBlockScan+1 {
					log.Debugf("handleInv (%v): block scan truncated at %v of %v entries",
						p, maxInvBlockScan, len(msg.InvList))
				}
				continue
			}
			// Make sure we haven't seen block header yet.
			//
			// Skip only this entry. Peers batch announcements in
			// ascending height order, so a known hash is often
			// followed by ones we still need, and those are not
			// re-announced.
			_, _, err := s.BlockHeaderByHash(ctx, v.Hash)
			if err == nil {
				continue
			}
			if s.invInsert(v.Hash) {
				log.Debugf("inventory block: %v", v.Hash)
			}
		case wire.InvTypeFilteredBlock:
			log.Debugf("inventory filtered block: %v", v.Hash)
		case wire.InvTypeWitnessBlock:
			log.Infof("inventory witness block: %v", v.Hash)
		case wire.InvTypeWitnessTx:
			log.Infof("inventory witness tx: %v", v.Hash)
		case wire.InvTypeFilteredWitnessBlock:
			log.Debugf("inventory filtered witness block: %v", v.Hash)
		default:
			log.Errorf("inventory unknown: %v", spew.Sdump(v.Hash))
		}
	}

	if s.cfg.MempoolEnabled && txsFound && s.Synced(ctx).Synced {
		if err := s.mempool.invTxsInsert(ctx, msg); err != nil {
			//nolint:errcheck // Error is intentionally ignored.
			go s.downloadMissingTx(ctx, p)
		}
	}

	return nil
}

func (s *Server) handleNotFound(ctx context.Context, p *rawpeer.RawPeer, msg *wire.MsgNotFound, raw []byte) error {
	// log.Infof("handleNotFound %v", spew.Sdump(msg))
	// defer log.Infof("handleNotFound exit")

	// // XXX keep here to see if it spams logs
	// log.Infof("NotFound: %v %v", p, spew.Sdump(msg))

	return nil
}

func (s *Server) handleGetData(ctx context.Context, p *rawpeer.RawPeer, msg *wire.MsgGetData, raw []byte) error {
	log.Tracef("handleGetData %v", p)
	defer log.Tracef("handleGetData %v exit", p)

	for _, v := range msg.InvList {
		switch v.Type {
		case wire.InvTypeError:
			log.Errorf("get data error: %v", v.Hash)
		case wire.InvTypeTx:
			// Copy under the lock and write outside it, otherwise
			// a peer that stops reading its socket stalls every
			// s.mtx writer for defaultCmdTimeout.
			s.mtx.RLock()
			tx, ok := s.broadcast[v.Hash]
			var txc *wire.MsgTx
			if ok {
				txc = tx.Copy()
			}
			s.mtx.RUnlock()
			if ok {
				log.Debugf("handleGetData %v", spew.Sdump(msg))
				if err := p.Write(defaultCmdTimeout, txc); err != nil {
					log.Errorf("write tx: %v", err)
				}
			}
		case wire.InvTypeBlock:
			log.Infof("get data block: %v", v.Hash)
		case wire.InvTypeFilteredBlock:
			log.Infof("get data filtered block: %v", v.Hash)
		case wire.InvTypeWitnessBlock:
			log.Infof("get data witness block: %v", v.Hash)
		case wire.InvTypeWitnessTx:
			log.Infof("get data witness tx: %v", v.Hash)
		case wire.InvTypeFilteredWitnessBlock:
			log.Infof("get data filtered witness block: %v", v.Hash)
		default:
			log.Errorf("get data unknown: %v", spew.Sdump(v.Hash))
		}
	}

	return nil
}

var paramsIdentityKey = []byte("paramsidentity")

// paramsIdentity is a stable fingerprint of the Bitcoin network/params this
// server is configured for. verifyDatadirIdentity stamps it into a mainnet
// datadir and refuses to start on a stamp for other params.
func (s *Server) paramsIdentity() []byte {
	p := s.chainParams
	h := sha256.New()
	// PowLimit (the big.Int the proof-of-work checks actually use) as well as
	// its compact PowLimitBits: a params set can change one without the other.
	fmt.Fprintf(h, "net=%s;magic=%d;genesis=%s;powbits=%08x;powlimit=%s;reducemin=%t;noretarget=%t;timespan=%d;perblock=%d",
		p.Name, s.wireNet, p.GenesisHash, p.PowLimitBits, p.PowLimit.Text(16),
		p.ReduceMinDifficulty, p.PoWNoRetargeting, p.TargetTimespan, p.TargetTimePerBlock)
	return h.Sum(nil)
}

// verifyDatadirIdentity refuses to start when the datadir was built for a
// different Bitcoin network/params than the one configured.
//
// Once written, the params-identity stamp is authoritative: a matching stamp
// means the datadir was verified when stamped, so none of the checks below are
// re-run. op-geth may later push a tip that is not held to our PowLimit, so
// re-checking on every restart would brick a correct node. A stamp for other
// params is refused.
//
// An unstamped (legacy or fresh) datadir is checked once, then stamped:
//
//  1. The stored canonical tip must meet the configured network's proof-of-work
//     limit. This catches a wrong-params datadir even when the genesis hash
//     matches (e.g. a trivial-PoW datadir reusing the mainnet genesis).
//     Exception: a failing tip is accepted when a real mainnet checkpoint at
//     or below it is stored (see below).
//  2. The configured genesis must be present, so a legacy datadir built for a
//     different network whose tip merely happens to meet our PowLimit is not
//     blessed.
//  3. The indexed frontier (utxo, tx and keystone index heads) must meet it
//     too. A trivial-PoW chain later extended with real-PoW headers still
//     carries trivial-PoW headers the indexers already consumed, and the
//     frontier is what peer acceptance and block download key on. The same
//     checkpoint exception as the tip's applies.
func (s *Server) verifyDatadirIdentity(ctx context.Context) error {
	// Mainnet only. Test networks (localnet, upgradetest) use synthetic,
	// unmined headers that legitimately fail a real PowLimit check, so
	// checking there would reject valid test datadirs.
	if s.cfg.Network != "mainnet" {
		return nil
	}

	want := s.paramsIdentity()
	got, err := s.db.MetadataGet(ctx, paramsIdentityKey)
	if err == nil {
		if !bytes.Equal(got, want) {
			return fmt.Errorf("datadir network mismatch: this datadir is stamped for a "+
				"different params set than the configured network %q. Refusing to start; "+
				"wipe the datadir or fix --tbc.network", s.cfg.Network)
		}
		return nil
	}
	if !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("datadir identity get: %w", err)
	}

	// Unstamped: verify before stamping.
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return fmt.Errorf("datadir identity best header: %w", err)
	}
	if err := s.datadirHeaderMeetsPowLimit(bhb, "the stored canonical tip"); err != nil {
		// A failing tip alone does not prove a wrong network, since
		// op-geth headers are not PoW-checked. Accept it when a real
		// checkpoint at or below the tip is stored: a suffix mined at a
		// trivial target has trivial work, so the first real header
		// reorgs it away. (A header planted with inflated claimed Bits
		// is not outweighed, but this check does not make that worse.)
		if !s.datadirHasCheckpoint(ctx, bhb.Height) {
			return err
		}
	}
	if _, _, err := s.BlockHeaderByHash(ctx, *s.chainParams.GenesisHash); err != nil {
		return fmt.Errorf("datadir network mismatch: configured genesis %v is "+
			"absent from this datadir (built for a different network?); refusing "+
			"to start: %w", s.chainParams.GenesisHash, err)
	}
	for _, idx := range []struct {
		name string
		head func(context.Context) (*HashHeight, error)
	}{
		{"the utxo index head", s.UtxoIndexHash},
		{"the tx index head", s.TxIndexHash},
		{"the keystone index head", s.KeystoneIndexHash},
	} {
		hh, err := idx.head(ctx)
		if err != nil {
			return fmt.Errorf("datadir identity %v: %w", idx.name, err)
		}
		if hh.Hash == (chainhash.Hash{}) || hh.Hash.IsEqual(s.chainParams.GenesisHash) {
			continue // never indexed, or indexed only to genesis
		}
		bh, err := s.db.BlockHeaderByHash(ctx, hh.Hash)
		if err != nil {
			return fmt.Errorf("datadir network mismatch: %v %v is not a stored "+
				"header; refusing to start: %w", idx.name, hh.Hash, err)
		}
		if err := s.datadirHeaderMeetsPowLimit(bh, idx.name); err != nil {
			// Same checkpoint exception as the tip. A trivial-PoW suffix
			// is reorged away at any depth and the indexers unwind with it.
			if !s.datadirHasCheckpoint(ctx, bh.Height) {
				return err
			}
		}
	}
	if err := s.db.MetadataPut(ctx, paramsIdentityKey, want); err != nil {
		return fmt.Errorf("datadir identity stamp: %w", err)
	}
	return nil
}

// datadirHasCheckpoint reports whether any non-genesis checkpoint at or below
// height is stored as a header at its checkpoint height.
func (s *Server) datadirHasCheckpoint(ctx context.Context, height uint64) bool {
	for _, cp := range s.checkpoints { // sorted high to low
		if cp.height == 0 || cp.height > height {
			continue
		}
		if bh, err := s.db.BlockHeaderByHash(ctx, cp.hash); err == nil && bh.Height == cp.height {
			return true
		}
	}
	return false
}

// datadirHeaderMeetsPowLimit fails closed, with the datadir-mismatch error, when
// bh does not meet the configured network's proof-of-work limit.
func (s *Server) datadirHeaderMeetsPowLimit(bh *tbcd.BlockHeader, what string) error {
	wbh, err := bh.Wire()
	if err != nil {
		return fmt.Errorf("datadir identity decode %v: %w", what, err)
	}
	if err := blockchain.CheckBlockHeaderSanity(wbh, s.chainParams.PowLimit,
		deterministicTimeSource{}, blockchain.BFNone); err != nil {
		return fmt.Errorf("datadir network mismatch: %v %v does "+
			"not meet the configured network %q proof-of-work limit -- this datadir was "+
			"probably built for a different network/params. Refusing to start. Check "+
			"--tbc.network; if it is correct, do not wipe this datadir -- report this "+
			"error. underlying: %w",
			what, bh.Hash, s.cfg.Network, err)
	}
	return nil
}

func (s *Server) insertGenesis(ctx context.Context, height uint64, diff *big.Int) error {
	log.Tracef("insertGenesis")
	defer log.Tracef("insertGenesis exit")

	// We really should be inserting the block first but block insert
	// verifies that a block header exists.
	log.Infof("Inserting genesis block and header: %v", s.chainParams.GenesisHash)
	err := s.db.BlockHeaderGenesisInsert(ctx, s.chainParams.GenesisBlock.Header, height, diff)
	if err != nil {
		return fmt.Errorf("genesis block header insert: %w", err)
	}

	log.Debugf("Inserting genesis block")
	_, err = s.db.BlockInsert(ctx, btcutil.NewBlock(s.chainParams.GenesisBlock))
	if err != nil {
		return fmt.Errorf("genesis block insert: %w", err)
	}

	return nil
}

// BlockByHash returns a block with the given hash.
func (s *Server) BlockByHash(ctx context.Context, hash chainhash.Hash) (*btcutil.Block, error) {
	log.Tracef("BlockByHash")
	defer log.Tracef("BlockByHash exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call BlockByHash on TBC running in External Header mode")
	}

	return s.db.BlockByHash(ctx, hash)
}

// KeystonesByHeight returns the first occurrence found of keystones
// at a given height + range. The given height is excluded.
func (s *Server) KeystonesByHeight(ctx context.Context, height uint32, depth int) ([]tbcd.Keystone, error) {
	log.Tracef("KeystonesByHeight")
	defer log.Tracef("KeystonesByHeight exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call KeystonesByHeight on TBC running in External Header mode")
	}

	return s.db.KeystonesByHeight(ctx, height, depth)
}

// XXX should we return a form of tbcd.BlockHeader which contains all info? and
// note that the return parameters here are reversed from BlockHeaderBest call.
func (s *Server) BlockHeaderByHash(ctx context.Context, hash chainhash.Hash) (*wire.BlockHeader, uint64, error) {
	log.Tracef("BlockHeaderByHash")
	defer log.Tracef("BlockHeaderByHash exit")

	bh, err := s.db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		return nil, 0, fmt.Errorf("db block header by hash: %w", err)
	}
	bhw, err := bh.Wire()
	if err != nil {
		return nil, 0, fmt.Errorf("bytes to header: %w", err)
	}
	return bhw, bh.Height, nil
}

func (s *Server) BlocksMissing(ctx context.Context, count int) ([]tbcd.BlockIdentifier, error) {
	log.Tracef("BlocksMissing")
	defer log.Tracef("BlocksMissing exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call BlocksMissing on TBC running in External Header mode")
	}

	return s.db.BlocksMissing(ctx, count)
}

func (s *Server) RawBlockHeadersByHeight(ctx context.Context, height uint64) ([]api.ByteSlice, error) {
	log.Tracef("RawBlockHeadersByHeight")
	defer log.Tracef("RawBlockHeadersByHeight exit")

	bhs, err := s.db.BlockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, err
	}

	headers := make([]api.ByteSlice, 0, len(bhs))
	for _, bh := range bhs {
		headers = append(headers, bh.Header[:])
	}
	return headers, nil
}

func (s *Server) BlockHeadersByHeight(ctx context.Context, height uint64) ([]*wire.BlockHeader, error) {
	log.Tracef("BlockHeadersByHeight")
	defer log.Tracef("BlockHeadersByHeight exit")

	blockHeaders, err := s.db.BlockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, err
	}

	wireBlockHeaders := make([]*wire.BlockHeader, 0, len(blockHeaders))
	for _, bh := range blockHeaders {
		w, err := bh.Wire()
		if err != nil {
			return nil, err
		}
		wireBlockHeaders = append(wireBlockHeaders, w)
	}
	return wireBlockHeaders, nil
}

// RawBlockHeaderBest returns the raw header for the best known block.
// XXX should we return cumulative difficulty, hash?
func (s *Server) RawBlockHeaderBest(ctx context.Context) (uint64, api.ByteSlice, error) {
	log.Tracef("RawBlockHeaderBest")
	defer log.Tracef("RawBlockHeaderBest exit")

	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return 0, nil, err
	}
	return bhb.Height, bhb.Header[:], nil
}

func (s *Server) DifficultyAtHash(ctx context.Context, hash chainhash.Hash) (*big.Int, error) {
	log.Tracef("DifficultyAtHash")
	defer log.Tracef("DifficultyAtHash exit")

	blockHeader, err := s.db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	return &blockHeader.Difficulty, nil
}

// BlockHeaderBest returns the headers for the best known blocks.
func (s *Server) BlockHeaderBest(ctx context.Context) (uint64, *wire.BlockHeader, error) {
	log.Tracef("BlockHeadersBest")
	defer log.Tracef("BlockHeadersBest exit")

	blockHeader, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return 0, nil, err
	}
	wbh, err := blockHeader.Wire()
	return blockHeader.Height, wbh, err
}

// MaxAddressLength bounds the encoded Bitcoin address accepted by the address-taking Server methods.
//
// 200 CANNOT REJECT A DECODABLE ADDRESS. btcutil.DecodeAddress has exactly three paths to success:
// bech32 (bech32.DecodeGeneric refuses len > 90 as its first statement), a hex pubkey (gated on
// length 66 or 130 exactly), and base58 at a 20-byte decoded payload -- and a base58 string of n
// characters decodes to at least ~0.732*(n-1) bytes, so a 25-byte payload is encodable only by
// strings of 25 to 35 characters. The longest address form in existence is 64 characters, a regtest
// bcrt1 P2WSH/P2TR (62 is the bc1/tb1 figure).
//
// DO NOT LOWER THIS BELOW 130, as it would make a valid 130-character uncompressed-pubkey address fail to
// decode.
const MaxAddressLength = 200

// ErrAddressTooLong is returned when an encoded address exceeds MaxAddressLength.
//
// It exists so the RPC layer can answer a CLIENT error instead of an internal one. Without it the cap
// returned a plain error, handleBalanceByAddressRequest wrapped it in protocol.NewInternalError, and
// that returns a NON-NIL transport error -- which handleRequest logs with an UNTHROTTLED log.Errorf,
// one line per message.
var ErrAddressTooLong = errors.New("address too long")

func (s *Server) BalanceByAddress(ctx context.Context, encodedAddress string) (uint64, error) {
	log.Tracef("BalanceByAddress")
	defer log.Tracef("BalanceByAddress exit")

	if s.cfg.ExternalHeaderMode {
		return 0, errors.New("cannot call BalanceByAddress on TBC running in External Header mode")
	}

	// Bound before the expensive decoder. See MaxAddressLength.
	if len(encodedAddress) > MaxAddressLength {
		return 0, fmt.Errorf("%w: %v bytes, maximum %v",
			ErrAddressTooLong, len(encodedAddress), MaxAddressLength)
	}

	addr, err := btcutil.DecodeAddress(encodedAddress, s.chainParams)
	if err != nil {
		return 0, err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return 0, err
	}

	balance, err := s.db.BalanceByScriptHash(ctx,
		tbcd.NewScriptHashFromScript(script))
	if err != nil {
		return 0, err
	}

	return balance, nil
}

func (s *Server) BalanceByScriptHash(ctx context.Context, hash tbcd.ScriptHash) (uint64, error) {
	log.Tracef("BalanceByScriptHash")
	defer log.Tracef("BalanceByScriptHash exit")

	if s.cfg.ExternalHeaderMode {
		return 0, errors.New("cannot call BalanceByScriptHash on TBC running in External Header mode")
	}

	balance, err := s.db.BalanceByScriptHash(ctx, hash)
	if err != nil {
		return 0, err
	}

	return balance, nil
}

func (s *Server) UtxosByAddress(ctx context.Context, filterMempool bool, encodedAddress string, start uint64, count uint64) ([]tbcd.Utxo, error) {
	log.Tracef("UtxosByAddress")
	defer log.Tracef("UtxosByAddress exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call UtxosByAddress on TBC running in External Header mode")
	}

	// Bound before the expensive decoder. See MaxAddressLength.
	if len(encodedAddress) > MaxAddressLength {
		return nil, fmt.Errorf("%w: %v bytes, maximum %v",
			ErrAddressTooLong, len(encodedAddress), MaxAddressLength)
	}

	addr, err := btcutil.DecodeAddress(encodedAddress, s.chainParams)
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}
	utxos, err := s.db.UtxosByScriptHash(ctx, tbcd.NewScriptHashFromScript(script),
		start, count)
	if err != nil {
		return nil, err
	}

	// XXX should we return an error if filterMempool
	// is true and mempoolEnabled is false?
	if filterMempool && s.cfg.MempoolEnabled {
		return s.mempool.FilterUtxos(ctx, utxos)
	}
	return utxos, nil
}

func (s *Server) UtxosByScriptHash(ctx context.Context, hash tbcd.ScriptHash, start uint64, count uint64) ([]tbcd.Utxo, error) {
	log.Tracef("UtxosByScriptHash")
	defer log.Tracef("UtxosByScriptHash exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call UtxosByScriptHash on " +
			"TBC running in External Header mode")
	}

	return s.db.UtxosByScriptHash(ctx, hash, start, count)
}

func (s *Server) UtxosByScriptHashCount(ctx context.Context, hash tbcd.ScriptHash) (uint64, error) {
	log.Tracef("UtxosByScriptHashCount")
	defer log.Tracef("UtxosByScriptHashCount exit")

	if s.cfg.ExternalHeaderMode {
		return 0, errors.New("cannot call UtxosByScriptHashCount on " +
			"TBC running in External Header mode")
	}

	return s.db.UtxosByScriptHashCount(ctx, hash)
}

func (s *Server) BlockKeystoneByL2KeystoneAbrevHash(ctx context.Context, abrevhash chainhash.Hash) (*tbcd.Keystone, error) {
	log.Tracef("BlockKeystoneByL2KeystoneAbrevHash")
	defer log.Tracef("BlockKeystoneByL2KeystoneAbrevHash exit")

	return s.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, abrevhash)
}

func (s *Server) KeystoneTxsByL2KeystoneAbrevHash(ctx context.Context, abrevhash chainhash.Hash, depth uint) ([]tbcapi.KeystoneTx, error) {
	log.Tracef("KeystoneTxsByL2KeystoneAbrevHash")
	defer log.Tracef("KeystoneTxsByL2KeystoneAbrevHash exit")

	first, err := s.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, abrevhash)
	if err != nil {
		return nil, err
	}
	_ = first

	return nil, errors.New("noy yet")
}

// ScriptHashAvailableToSpend returns a boolean which indicates whether
// a specific output (uniquely identified by TxId output index) is
// available for spending in the UTXO table.
// This function can return false for two reasons:
//  1. The outpoint was already spent
//  2. The outpoint never existed
func (s *Server) ScriptHashAvailableToSpend(ctx context.Context, txId chainhash.Hash, index uint32) (bool, error) {
	log.Tracef("ScriptHashAvailableToSpend")
	defer log.Tracef("ScriptHashAvailableToSpend exit")
	if s.cfg.ExternalHeaderMode {
		return false, errors.New("cannot call script hash available to spend on TBC running in External Header mode")
	}

	txIdBytes := [32]byte(txId.CloneBytes())
	op := tbcd.NewOutpoint(txIdBytes, index)
	sh, err := s.db.ScriptHashByOutpoint(ctx, op)
	if err != nil {
		return false, err
	}

	if sh != nil {
		// Found it, therefore is unspent
		return true, nil
	}

	// Did not find it, therefore either spent or never existed
	return false, nil
}

func (s *Server) SpentOutputsByTxId(ctx context.Context, txId chainhash.Hash) ([]tbcd.SpentInfo, error) {
	log.Tracef("SpentOutputsByTxId")
	defer log.Tracef("SpentOutputsByTxId exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call SpentOutputsByTxId on TBC running in External Header mode")
	}

	// As it is written now it returns all spent outputs per the tx index view.
	si, err := s.db.SpentOutputsByTxId(ctx, txId)
	if err != nil {
		return nil, err
	}

	return si, nil
}

func (s *Server) BlockInTxIndex(ctx context.Context, blkid chainhash.Hash) (bool, error) {
	log.Tracef("BlockInTxIndex")
	defer log.Tracef("BlockInTxIndex exit")

	if s.cfg.ExternalHeaderMode {
		return false, errors.New("cannot call BlockInTxIndex on TBC running in External Header mode")
	}

	// As it is written now it returns true/false per the tx index view.
	return s.db.BlockInTxIndex(ctx, blkid)
}

func (s *Server) BlockHashByTxId(ctx context.Context, txId chainhash.Hash) (*chainhash.Hash, error) {
	log.Tracef("BlockHashByTxId")
	defer log.Tracef("BlockHashByTxId exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call BlockHashByTxId on TBC running in External Header mode")
	}

	return s.db.BlockHashByTxId(ctx, txId)
}

func (s *Server) TxById(ctx context.Context, txId chainhash.Hash) (*wire.MsgTx, error) {
	log.Tracef("TxById")
	defer log.Tracef("TxById exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call TxById on TBC running in External Header mode")
	}

	blockHash, err := s.db.BlockHashByTxId(ctx, txId)
	if err != nil {
		return nil, err
	}
	block, err := s.db.BlockByHash(ctx, *blockHash)
	if err != nil {
		return nil, err
	}
	for _, tx := range block.Transactions() {
		if tx.Hash().IsEqual(&txId) {
			return tx.MsgTx(), nil
		}
	}

	return nil, database.ErrNotFound
}

func (s *Server) TxBroadcastAllToPeer(ctx context.Context, p *rawpeer.RawPeer) error {
	log.Tracef("TxBroadcastAllToPeer %v", p)
	defer log.Tracef("TxBroadcastAllToPeer %v exit", p)

	if s.cfg.ExternalHeaderMode {
		return errors.New("cannot call TxBroadcastAllToPeer on TBC running in External Header mode")
	}

	s.mtx.RLock()
	if len(s.broadcast) == 0 {
		s.mtx.RUnlock()
		return nil
	}

	invTx := wire.NewMsgInv()
	for k := range s.broadcast {
		err := invTx.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &k))
		if err != nil {
			s.mtx.RUnlock()
			return fmt.Errorf("invalid vector: %w", err)
		}
	}
	s.mtx.RUnlock()

	err := p.Write(defaultCmdTimeout, invTx)
	if err != nil {
		return fmt.Errorf("broadcast all %v: %w", p, err)
	}

	log.Debugf("broadcast all txs to peer %v: tx count %v", p, len(invTx.InvList))

	return nil
}

// rejectNilTxElements refuses a transaction containing a nil input or output.
//
// WHY THIS EXISTS AND WHY IT IS AT THE SERVER BOUNDARY.
//
// A 9-byte body declaring 100,000 inputs returns an error with len(TxIn)==100000 and 99,999 nil
// elements. What actually makes the P2P path safe is that a decode error is always propagated and
// the partially-decoded transaction discarded -- never that nils cannot exist. Anyone who ignores a
// decode error and uses the result gets a nil deref; measured, doing that AND removing this guard
// panics inside btcd's writeTxInBuf.
//
// tbcapi decodes *wire.MsgTx and *wire.MsgBlock straight out of json.Unmarshal,
// and JSON can express "TxIn":[null]. btcd then dereferences it without a nil check: MsgTx.TxHash()
// -> SerializeSizeStripped() -> txIn.SerializeSizeStripped(), and MsgTx.Copy() likewise. There is no
// recover() anywhere in service/tbc or api/, and the RPC dispatcher runs each request in a bare
// goroutine, so a nil element is process death from an unauthenticated caller.
func rejectNilTxElements(tx *wire.MsgTx, idx int) error {
	if tx == nil {
		return fmt.Errorf("%w: transaction %d is null", ErrNilElement, idx)
	}
	for j, in := range tx.TxIn {
		if in == nil {
			return fmt.Errorf("%w: transaction %d input %d is null", ErrNilElement, idx, j)
		}
	}
	for j, out := range tx.TxOut {
		if out == nil {
			return fmt.Errorf("%w: transaction %d output %d is null", ErrNilElement, idx, j)
		}
	}
	return nil
}

// checkBlockMerkleRoot binds a peer-supplied block body to the header it arrived under. See
// ErrBlockMerkleMismatch for why nothing else on the Bitcoin P2P path does.
//
// DO NOT reduce this to the merkle comparison alone. btcd's tree duplicates the last hash when a
// level holds an odd number of nodes (CVE-2012-2459), so the transaction lists [A B C] and [A B C C]
// produce the IDENTICAL root. ([A B] and [A B B] do NOT -- an even level is not duplicated, and the
// three-element form is the minimal shape.) An attacker can therefore append duplicated transactions
// to a genuine body and pass a bare comparison.
func checkBlockMerkleRoot(block *btcutil.Block) error {
	if block == nil {
		return fmt.Errorf("%w: no block provided", ErrNilElement)
	}
	txs := block.Transactions()
	if len(txs) == 0 {
		// Nothing to bind. btcd calls this ErrNoTransactions inside CheckBlockSanity.
		return fmt.Errorf("%w: block has no transactions", ErrBlockMerkleMismatch)
	}
	// A 64-byte transaction whose serialization is exactly txid(P)||txid(Q) is indistinguishable
	// from an interior tree node, so [P Q] and [T] hash to the SAME root with NO duplicate txid --
	// the one collision family the duplicate guard below cannot see (BIP-54). Requiring a coinbase
	// first closes it: the impostor is always at index 0. A colliding forged list is either shallower
	// (its leaf 0 IS an interior honest node, i.e. the impostor), or the same depth with a different
	// leaf count (which forces a duplicate txid, caught below), or deeper (which  needs a second
	// preimage on the coinbase txid). A 64-byte transaction CAN be a valid coinbase on its own; what
	// it cannot be is a coinbase AND an impostor at once, because the impostor layout forces 27 chosen
	// zero bytes inside txid(P) -- 2^216 work, and higher still because txid(Q)'s leading bytes are
	// pinned by the index field.
	//
	// CheckBlockSanity already enforces the same thing (ErrFirstTxNotCoinbase) on the other two
	// ingest paths. DO NOT close this by banning 64-byte transactions instead: they are STILL
	// CONSENSUS-VALID on Bitcoin today (that is what BIP-54 would change; they have merely been
	// non-standard since 2019, and were last seen on mainnet around 2016). Banning them would be a
	// consensus DIVERGENCE from Bitcoin as well as a false-reject on historical blocks.
	if !blockchain.IsCoinBase(txs[0]) {
		return fmt.Errorf("%w: first transaction is not a coinbase", ErrBlockMerkleMismatch)
	}

	seen := make(map[chainhash.Hash]struct{}, len(txs))
	for _, tx := range txs {
		if _, dup := seen[*tx.Hash()]; dup {
			return fmt.Errorf("%w: %v", ErrBlockDuplicateTx, tx.Hash())
		}
		seen[*tx.Hash()] = struct{}{}
	}
	// witness=false: Header.MerkleRoot commits to the TXID tree. The witness merkle root is committed
	// separately, via the coinbase's BIP141 commitment, and witness data is not currently supported.
	got := blockchain.CalcMerkleRoot(txs, false)
	want := block.MsgBlock().Header.MerkleRoot
	if !got.IsEqual(&want) {
		return fmt.Errorf("%w: header %v, computed %v", ErrBlockMerkleMismatch, want, got)
	}
	return nil
}

// rejectNilBlockElements refuses a block containing a nil transaction, input, or output.
// See rejectNilTxElements.
func rejectNilBlockElements(blk *wire.MsgBlock) error {
	if blk == nil {
		return fmt.Errorf("%w: no block provided", ErrNilElement)
	}
	for i, tx := range blk.Transactions {
		if err := rejectNilTxElements(tx, i); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) TxBroadcast(ctx context.Context, tx *wire.MsgTx, force bool) (*chainhash.Hash, error) {
	log.Tracef("TxBroadcast")
	defer log.Tracef("TxBroadcast exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("cannot call TxBroadcast on TBC running in External Header mode")
	}

	if tx == nil {
		return nil, errors.New("tx: nil")
	}
	// A nil INPUT or OUTPUT is not the same as a nil transaction, and it is reachable: this method is
	// fed by tbcapi's TxBroadcast handler straight from json.Unmarshal. tx.TxHash() below panics on
	// one, on a goroutine with no recover. See rejectNilTxElements.
	if err := rejectNilTxElements(tx, 0); err != nil {
		return nil, err
	}

	s.mtx.Lock()
	if _, ok := s.broadcast[tx.TxHash()]; ok && !force {
		s.mtx.Unlock()
		return nil, ErrTxAlreadyBroadcast
	}
	s.broadcast[tx.TxHash()] = tx
	txb := tx.Copy()
	s.mtx.Unlock()

	txHash := txb.TxHash()
	invTx := wire.NewMsgInv()
	err := invTx.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &txHash))
	if err != nil {
		return nil, fmt.Errorf("invalid vector: %w", err)
	}
	var success atomic.Uint64
	inv := func(ctx context.Context, p *rawpeer.RawPeer) {
		log.Tracef("inv %v", p)
		defer log.Tracef("inv %v exit", p)

		err := p.Write(defaultCmdTimeout, invTx)
		if err != nil {
			log.Debugf("inv %v: %v", p, err)
			return
		}
		success.Add(1)
	}
	s.pm.AllBlock(ctx, inv)

	if success.Load() == 0 {
		return nil, ErrTxBroadcastNoPeers
	}

	if s.cfg.MempoolEnabled {
		// Add Tx to our own mempool instead of waiting for it to come
		// over p2p.
		mptx, err := s.mempoolTxNew(ctx, btcutil.NewTx(tx))
		if err != nil {
			log.Errorf("mempool tx: %w", err)
		} else if err := s.mempool.TxInsert(ctx, mptx); err != nil {
			log.Errorf("broacast mempool tx: %w", err)
		}
	}

	return &txHash, nil
}

func (s *Server) DatabaseVersion(ctx context.Context) (int, error) {
	return s.db.Version(ctx)
}

func (s *Server) DatabaseMetadataDel(ctx context.Context, key []byte) error {
	if !s.cfg.DatabaseDebug {
		return ErrNotInDebugMode
	}
	return s.db.MetadataDel(ctx, key)
}

func (s *Server) DatabaseMetadataPut(ctx context.Context, key []byte, value []byte) error {
	if !s.cfg.DatabaseDebug {
		return ErrNotInDebugMode
	}
	return s.db.MetadataPut(ctx, key, value)
}

func (s *Server) DatabaseMetadataGet(ctx context.Context, key []byte) ([]byte, error) {
	return s.db.MetadataGet(ctx, key)
}

func (s *Server) BlockHeaderByUtxoIndex(ctx context.Context) (*tbcd.BlockHeader, error) {
	return s.db.BlockHeaderByUtxoIndex(ctx)
}

func (s *Server) BlockHeaderByTxIndex(ctx context.Context) (*tbcd.BlockHeader, error) {
	return s.db.BlockHeaderByTxIndex(ctx)
}

func (s *Server) BlockHeaderByKeystoneIndex(ctx context.Context) (*tbcd.BlockHeader, error) {
	return s.db.BlockHeaderByKeystoneIndex(ctx)
}

func (s *Server) parseTx(ctx context.Context, tx *wire.MsgTx) (int64, int64, map[wire.OutPoint]struct{}, error) {
	var iv, ov int64
	txins := make(map[wire.OutPoint]struct{}, len(tx.TxIn))
	for _, txIn := range tx.TxIn {
		po := txIn.PreviousOutPoint
		wtxo, err := s.txOutFromOutPoint(ctx, tbcd.NewOutpoint(po.Hash, po.Index))
		if err != nil {
			return 0, 0, nil, err
		}
		iv += wtxo.Value

		txins[po] = struct{}{}
	}

	for _, txOut := range tx.TxOut {
		ov += txOut.Value
	}

	return iv, ov, txins, nil
}

func (s *Server) mempoolTxNew(ctx context.Context, utx *btcutil.Tx) (*MempoolTx, error) {
	// Create mempool tx
	inValue, outValue, txins, err := s.parseTx(ctx, utx.MsgTx())
	if err != nil {
		return nil, fmt.Errorf("cannot obtain values from tx: %w", err)
	}
	return &MempoolTx{
		id:       utx.MsgTx().TxHash(),
		weight:   blockchain.GetTransactionWeight(utx),
		size:     btcmempool.GetTxVirtualSize(utx),
		outValue: outValue,
		inValue:  inValue,
		expires:  time.Now().Add(defaultMempoolAge),
		txins:    txins,
	}, nil
}

// FeesByBlockHash calculates the median fee for the provided block.
func (s *Server) FeesByBlockHash(ctx context.Context, hash chainhash.Hash) (*tbcapi.FeeEstimate, error) {
	log.Tracef("FeesByBlockHash")
	defer log.Tracef("FeesByBlockHash exit")

	if s.cfg.ExternalHeaderMode {
		return nil, errors.New("fees by block hash: external header mode")
	}

	b, err := s.db.BlockByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("fees by block hash block: %w", err)
	}

	mp, err := NewMempool()
	if err != nil {
		return nil, fmt.Errorf("could not create mempool: %w", err)
	}

	// Create mempool txs from block txs
	for _, utx := range b.Transactions() {
		if blockchain.IsCoinBase(utx) {
			// Skip coinbase inputs
			continue
		}
		mptx, err := s.mempoolTxNew(ctx, utx)
		if err != nil {
			return nil, fmt.Errorf("new mempool tx: %w", err)
		}
		if err = mp.TxInsert(ctx, mptx); err != nil {
			return nil, fmt.Errorf("cannot insert tx in mempool: %w", err)
		}
	}

	rf, err := mp.GetRecommendedFees(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get recommended fees: %w", err)
	}

	return rf[0], nil
}

// FullBlockAvailable returns whether TBC has the full block
// corresponding to the specified hash available in its database.
func (s *Server) FullBlockAvailable(ctx context.Context, hash chainhash.Hash) (bool, error) {
	if s.cfg.ExternalHeaderMode {
		return false, errors.New("cannot call full block available on TBC running in External Header mode")
	}

	return s.db.BlockExistsByHash(ctx, hash)
}

// UpstreamStateId fetches the last-stored upstream state ID.  If the last
// header insertion/removal did not specify an upstream state ID, this will
// return the default upstream state ID.
func (s *Server) UpstreamStateId(ctx context.Context) (*[32]byte, error) {
	log.Tracef("UpstreamStateId")
	defer log.Tracef("UpstreamStateId exit")

	if !s.cfg.ExternalHeaderMode {
		return nil, errors.New("upstream state id: " +
			"not running in external header mode")
	}

	usi, err := s.db.MetadataGet(ctx, upstreamStateIdKey)
	if err != nil {
		return nil, err
	}
	var x [32]byte
	copy(x[:], usi)
	return &x, nil
}

// SetUpstreamStateId sets a new upstream state ID without making any other
// state changes to TBC, used when the upstream state is updated without
// requiring any TBC updates.
func (s *Server) SetUpstreamStateId(ctx context.Context, upstreamStateId [32]byte) error {
	log.Tracef("SetUpstreamStateId")
	defer log.Tracef("SetUpstreamStateId exit")

	if !s.cfg.ExternalHeaderMode {
		return errors.New("set upstream state id: " +
			"not running in external header mode")
	}

	return s.db.MetadataPut(ctx, upstreamStateIdKey, upstreamStateId[:])
}

type SyncInfo struct {
	Synced bool `json:"synced"` // True when all indexing is caught up

	AtLeastMissing int `json:"at_least_missing"` // Blocks missing 0-63 is counted, >=64 returns -1

	BlockHeader HashHeight `json:"blockheader_index_height"`
	Keystone    HashHeight `json:"keystone_index_height"`
	Tx          HashHeight `json:"tx_index_height"`
	Utxo        HashHeight `json:"utxo_index_height"`
}

func (s *Server) synced(ctx context.Context) (si SyncInfo) {
	// These values are cached in leveldb so it is ok to call with mutex
	// held.
	//
	// Note that index heights are start indexing values thus they are off
	// by one from the last block height seen.
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		// XXX this happens because we shut down and blocks come in.
		// The context is canceled but wire isn't smart enough so we
		// make it here. We should not be testing for leveldb errors
		// here but the real fix is return an error or add ctx to wire.
		// This is a workaround. Code prints a bunch of crap during IBD
		// when shutdown because of this.
		// XXX make this a function?
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Don't panic. The database may already be closed (ErrClosed) and
		// op-geth calls Synced with its own ctx, which is not cancelled at
		// shutdown. Report not synced instead.
		log.Errorf("synced: block header best: %v", err)
		si.Synced = false
		return
	}
	// Ensure we have genesis or the Synced flag will be true if metadata
	// does not exist.
	if zeroHash.IsEqual(&bhb.Hash) {
		panic("no genesis")
	}
	si.BlockHeader.Hash = bhb.Hash
	si.BlockHeader.Height = bhb.Height
	si.BlockHeader.Timestamp = bhb.Timestamp().Unix()

	// utxo index
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		utxoHH = &HashHeight{}
	}
	si.Utxo = *utxoHH

	// tx index
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		txHH = &HashHeight{}
	}
	si.Tx = *txHH

	// Find out how many blocks are missing.
	var (
		blksMissing = true
		maxMissing  = 64
	)
	// expensive check
	bm, err := s.db.BlocksMissing(ctx, maxMissing)
	if err != nil {
		// Don't panic. Synced is called from peer goroutines and directly
		// by op-geth, so a damaged blocks-missing index or transient read
		// error would kill the process. Report not synced instead; that
		// resolves on the next successful read.
		log.Errorf("synced: blocks missing: %v", err)
		si.Synced = false
		return
	}
	if len(bm) >= maxMissing {
		// -1 is sentinel meaning > 64
		si.AtLeastMissing = -1
	} else {
		si.AtLeastMissing = len(bm)
		if si.AtLeastMissing == 0 {
			blksMissing = false
		}
	}

	if utxoHH.Hash.IsEqual(&bhb.Hash) && txHH.Hash.IsEqual(&bhb.Hash) &&
		!s.indexing && !blksMissing {
		// If keystone indexers are disabled we are synced.
		if !s.cfg.HemiIndex {
			si.Synced = true
			return
		}

		// Perform additional keystone indexer tests.
		keystoneHH, err := s.KeystoneIndexHash(ctx)
		if err != nil {
			keystoneHH = &HashHeight{}
		}
		si.Keystone = *keystoneHH
		if keystoneHH.Hash.IsEqual(&bhb.Hash) {
			si.Synced = true
			return
		}
	}
	return
}

// Synced returns true if all block headers, blocks and all indexes are caught up.
func (s *Server) Synced(ctx context.Context) SyncInfo {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.cfg.ExternalHeaderMode {
		panic("cannot call Synced on TBC running in External Header mode")
	}

	return s.synced(ctx)
}

// dbOpen opens the underlying server database.
func (s *Server) dbOpen(ctx context.Context) error {
	log.Tracef("dbOpen")
	defer log.Tracef("dbOpen exit")

	// This should have been verified but let's not make assumptions.
	switch s.cfg.Network {
	case "testnet3":
	case "mainnet":
	case "upgradetest":
	case networkLocalnet: // XXX why is this here?, this breaks the filepath.Join
	default:
		return fmt.Errorf("unsupported network: %v", s.cfg.Network)
	}

	// Open db.
	cfg, err := level.NewConfig(s.cfg.Network, s.cfg.LevelDBHome,
		s.cfg.BlockheaderCacheSize, s.cfg.BlockCacheSize)
	if err != nil {
		return err
	}
	s.db, err = level.New(ctx, cfg)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) dbClose() error {
	log.Tracef("dbClose")
	defer log.Tracef("dbClose")

	return s.db.Close()
}

// Collectors returns the Prometheus collectors available for the server.
func (s *Server) Collectors() []prometheus.Collector {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.promCollectors == nil {
		// Naming: https://prometheus.io/docs/practices/naming/
		s.promCollectors = []prometheus.Collector{
			s.cmdsProcessed,
			newValueVecFunc(prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "block_height",
				Help:      "Best block canonical height and hash",
			}, []string{"hash", "timestamp"}), s.promBlockHeader),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "blocks_missing",
				Help:      "Number of missing blocks. -1 means more than 64 missing",
			}, s.promBlocksMissing),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "running",
				Help:      "Whether the TBC service is running",
			}, s.promRunning),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "synced",
				Help:      "Whether the TBC service is synced",
			}, s.promSynced),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "utxo_sync_height",
				Help:      "Height of the UTXO indexer",
			}, s.promUtxo),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "tx_sync_height",
				Help:      "Height of transaction indexer",
			}, s.promTx),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "peers_connected",
				Help:      "Number of peers connected",
			}, s.promConnectedPeers),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "peers_good",
				Help:      "Number of good peers",
			}, s.promGoodPeers),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "peers_bad",
				Help:      "Number of bad peers",
			}, s.promBadPeers),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "mempool_count",
				Help:      "Number of transactions in mempool",
			}, s.promMempoolCount),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "mempool_size_bytes",
				Help:      "Size of mempool in bytes",
			}, s.promMempoolSize),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "block_cache_hits",
				Help:      "Block cache hits",
			}, s.promBlockCacheHits),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "block_cache_misses",
				Help:      "Block cache misses",
			}, s.promBlockCacheMisses),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "block_cache_purges",
				Help:      "Block cache purges",
			}, s.promBlockCachePurges),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "block_cache_size",
				Help:      "Block cache size",
			}, s.promBlockCacheSize),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "header_cache_items",
				Help:      "Number of cached blocks",
			}, s.promHeaderCacheItems),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "header_cache_hits",
				Help:      "Header cache hits",
			}, s.promHeaderCacheHits),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "header_cache_misses",
				Help:      "Header cache misses",
			}, s.promHeaderCacheMisses),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "header_cache_purges",
				Help:      "Header cache purges",
			}, s.promHeaderCachePurges),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "header_cache_size",
				Help:      "Header cache size",
			}, s.promHeaderCacheSize),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "block_cache_items",
				Help:      "Number of cached blocks",
			}, s.promBlockCacheItems),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "disk_free",
				Help:      "Disk free",
			}, s.promDiskFree),
		}
		if s.cfg.HemiIndex {
			s.promCollectors = append(s.promCollectors,
				prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Namespace: s.cfg.PrometheusNamespace,
					Name:      "keystone_sync_height",
					Help:      "Height of the keystone indexer",
				}, s.promKeystone))
		}
	}
	return s.promCollectors
}

func (s *Server) isHealthy(_ context.Context) bool {
	connected, _, _ := s.pm.Stats()
	return connected > 0
}

func (s *Server) health(ctx context.Context) (bool, any, error) {
	log.Tracef("health")
	defer log.Tracef("health exit")

	return s.isHealthy(ctx), s.synced(ctx), nil
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if s.cfg.ExternalHeaderMode {
		return errors.New("run called but External Header mode is enabled")
	}

	var err error
	s.cfg.LevelDBHome, err = homedir.Expand(s.cfg.LevelDBHome)
	if err != nil {
		return fmt.Errorf("expand: %w", err)
	}

	// Rely on dbOpen failing if the database is already open.
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()
	err = s.dbOpen(ctx)
	if err != nil {
		return fmt.Errorf("open level database: %w", err)
	}
	defer func() {
		err := s.dbClose()
		if err != nil {
			log.Errorf("db close: %v", err)
		}
	}()

	// Warn user about disk space
	df, err := diskFree(s.cfg.LevelDBHome)
	if err != nil {
		return fmt.Errorf("df: %w", err)
	}
	if df != 0 {
		blockPerDay := uint64(24 * time.Hour / s.chainParams.TargetTimePerBlock)
		blockSize := uint64(2 * 1024 * 1024) // 2MB, a bit over but that's ok
		sizePerDay := blockSize * blockPerDay
		approxAvailable := df / sizePerDay
		log.Infof("Free disk space %v: %v approximate days till full: %v",
			s.cfg.LevelDBHome, humanize.IBytes(df), approxAvailable)
	}

	if !s.testAndSetRunning(true) {
		return errors.New("tbc already running")
	}
	defer s.testAndSetRunning(false)

	// Find out where IBD is at
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("block header best: %w", err)
		}

		// This Run function is only called in regular (not external
		// header) mode, so this is true genesis block @ 0 and we pass
		// in a nil difficulty so it calculates the starting difficulty
		// as the genesis block's own local difficulty.
		if err = s.insertGenesis(ctx, 0, nil); err != nil {
			return fmt.Errorf("insert genesis: %w", err)
		}
		bhb, err = s.db.BlockHeaderBest(ctx)
		if err != nil {
			return err
		}
	}

	// On mainnet, refuse to run against a datadir built for other params.
	if err := s.verifyDatadirIdentity(ctx); err != nil {
		return err
	}

	// HTTP server
	httpErrCh := make(chan error)
	if s.cfg.ListenAddress != "" {
		mux := http.NewServeMux()
		log.Infof("handle (tbc): %s", tbcapi.RouteWebsocket)
		mux.HandleFunc(tbcapi.RouteWebsocket, s.handleWebsocket)

		httpServer := &http.Server{
			Addr:        s.cfg.ListenAddress,
			Handler:     mux,
			BaseContext: func(_ net.Listener) context.Context { return ctx },
		}
		go func() {
			log.Infof("Listening: %s", s.cfg.ListenAddress)
			httpErrCh <- httpServer.ListenAndServe()
		}()
		defer func() {
			if err := httpServer.Shutdown(ctx); err != nil {
				log.Errorf("http server exit: %v", err)
				return
			}
			log.Infof("RPC server shutdown cleanly")
		}()
	}

	// pprof
	if s.cfg.PprofListenAddress != "" {
		p, err := pprof.NewServer(&pprof.Config{
			ListenAddress: s.cfg.PprofListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create pprof server: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := p.Run(ctx); !errors.Is(err, context.Canceled) {
				log.Errorf("pprof server terminated with error: %v", err)
				return
			}
			log.Infof("pprof server clean shutdown")
		}()
	}

	// Prometheus
	if s.cfg.PrometheusListenAddress != "" {
		d, err := deucalion.New(&deucalion.Config{
			ListenAddress: s.cfg.PrometheusListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := d.Run(ctx, s.Collectors(), s.health); !errors.Is(err, context.Canceled) {
				log.Errorf("prometheus terminated with error: %v", err)
				return
			}
			log.Infof("prometheus clean shutdown")
		}()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			err := s.promPoll(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Errorf("prometheus poll terminated with error: %v", err)
				}
				return
			}
		}()
	}

	errC := make(chan error)
	if s.cfg.PeersWanted > 0 {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			err := s.pm.Run(ctx)
			log.Infof("Peer manager shutting down")
			if err != nil {
				select {
				case errC <- err:
				default:
				}
			} else {
				log.Infof("Peer manager clean shutdown")
			}
		}()

		// connected peers
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				p, err := s.pm.RandomConnect(ctx)
				if err != nil {
					if errors.Is(err, context.Canceled) {
						return
					}
					// Should not be reached
					log.Errorf("random connect: %v", err)
					return
				}
				go func(pp *rawpeer.RawPeer) {
					err := s.handlePeer(ctx, pp)
					if err != nil {
						log.Debugf("%v: %v", pp, err)
					}
				}(p)
			}
		}()

		// ping loop
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(13 * time.Second):
				}
				s.pm.All(ctx, s.pingPeer)
			}
		}()

		// header refresh loop; see headerRefreshInterval.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(headerRefreshInterval):
				}
				s.pm.All(ctx, s.headersPeer)
			}
		}()
	}

	// Welcome user.
	if Welcome {
		log.Infof("Genesis: %v", s.chainParams.GenesisHash) // XXX make debug
		log.Infof("Starting block headers sync at %v height: %v time %v",
			bhb, bhb.Height, bhb.Timestamp())
		utxoHH, _ := s.UtxoIndexHash(ctx)
		log.Infof("Utxo index %v", utxoHH)
		txHH, _ := s.TxIndexHash(ctx)
		log.Infof("Tx index %v", txHH)
		if s.cfg.HemiIndex {
			hemiHH, _ := s.KeystoneIndexHash(ctx)
			log.Infof("Keystone index %v", hemiHH)
		}
	}

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errC:
	case err = <-httpErrCh:
	}
	cancel()

	log.Infof("tbc service shutting down")
	s.wg.Wait()
	log.Infof("tbc service clean shutdown")

	return err
}

func (s *Server) ExternalHeaderSetup(ctx context.Context, upstreamStateId []byte) error {
	log.Tracef("ExternalHeaderSetup")
	defer log.Tracef("ExternalHeaderSetup exit")

	if !s.cfg.ExternalHeaderMode {
		return errors.New("ExternalHeaderSetup called but external " +
			"header mode is not enabled in config")
	}

	err := s.dbOpen(ctx)
	if err != nil {
		return fmt.Errorf("open level database: %w", err)
	}

	genesis := s.cfg.EffectiveGenesisBlock
	genesisHeight := s.cfg.GenesisHeightOffset
	genesisDiff := &s.cfg.GenesisDifficultyOffset

	if genesis == nil {
		genesis = &s.chainParams.GenesisBlock.Header
		genesisHeight = 0
		genesisDiff = nil
	}

	// Check if there is already a best header in database
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("block headers best: %w", err)
		}

		// Insert default upstreamStateId
		err := s.db.MetadataPut(ctx, upstreamStateIdKey, upstreamStateId)
		if err != nil {
			return fmt.Errorf("default upstream state id insert: %w",
				err)
		}

		// Getting best header returned ErrNotFound so assume initial
		// startup
		err = s.db.BlockHeaderGenesisInsert(ctx, *genesis, genesisHeight,
			genesisDiff)
		if err != nil {
			return fmt.Errorf("genesis block header insert: %w", err)
		}

		// Ensure after inserting the effective genesis block, ensure
		// we can get the best header
		bhb, err = s.db.BlockHeaderBest(ctx)
		if err != nil {
			return err
		}
	} else {
		// No error getting best header, no genesis insert, so check db
		// genesis matches
		gb, err := s.db.BlockHeadersByHeight(ctx, s.cfg.GenesisHeightOffset)
		if err != nil {
			return fmt.Errorf("error getting effective genesis "+
				"block from db, %w", err)
		}
		if len(gb) > 1 {
			// Impossible to have more than one block at the
			// genesis height
			return fmt.Errorf("invalid state, have %d effective "+
				"genesis blocks", len(gb))
		}
		gh := genesis.BlockHash()
		if !bytes.Equal(gb[0].Hash[:], gh[:]) {
			return fmt.Errorf("effective genesis block hash mismatch, "+
				"db has %v but genesis should be %v", gb[0].Hash, gh)
		}
	}

	log.Infof("External Header Mode, effectiveGenesis=%v, tip=%v",
		genesis.BlockHash(), bhb.Hash)

	return nil
}

func (s *Server) ExternalHeaderTearDown() error {
	log.Tracef("ExternalHeaderTearDown")
	defer log.Tracef("ExternalHeaderTearDown exit")

	if !s.cfg.ExternalHeaderMode {
		return errors.New("ExternalHeaderTearDown called but external " +
			"header mode is not enabled in config")
	}

	err := s.dbClose()
	if err != nil {
		log.Errorf("db close: %v", err)
		return err
	}
	return nil
}
