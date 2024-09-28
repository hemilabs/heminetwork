// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/dustin/go-humanize"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
	"github.com/hemilabs/heminetwork/ttl"
)

const (
	logLevel = "INFO"

	promSubsystem = "tbc_service" // Prometheus

	defaultPeersWanted   = 64
	minPeersRequired     = 64  // minimum number of peers in good map before cache is purged
	defaultPendingBlocks = 128 // 128 * ~4MB max memory use

	defaultMaxCachedTxs = 1e6 // dual purpose cache, max key 69, max value 36

	networkLocalnet = "localnet" // XXX this needs to be rethought

	defaultCmdTimeout          = 4 * time.Second
	defaultPingTimeout         = 3 * time.Second
	defaultBlockPendingTimeout = 13 * time.Second
)

var (
	zeroHash = new(chainhash.Hash) // used to check if a hash is invalid

	localnetSeeds = []string{
		"127.0.0.1:18444",
	}
	testnetSeeds = []string{
		"testnet-seed.bitcoin.jonasschnelli.ch:18333",
		"seed.tbtc.petertodd.org:18333",
		"seed.testnet.bitcoin.sprovoost.nl:18333",
		"testnet-seed.bluematt.me:18333",
	}
	mainnetSeeds = []string{
		"seed.bitcoin.sipa.be:8333",
		"dnsseed.bluematt.me:8333",
		"dnsseed.bitcoin.dashjr.org:8333",
		"seed.bitcoinstats.com:8333",
		"seed.bitnodes.io:8333",
		"seed.bitcoin.jonasschnelli.ch:8333",
	}
)

var log = loggo.GetLogger("tbc")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type Config struct {
	AutoIndex               bool
	BlockCache              int
	BlockheaderCache        int
	BlockSanity             bool
	LevelDBHome             string
	ListenAddress           string
	LogLevel                string
	MaxCachedTxs            int
	MempoolEnabled          bool
	Network                 string
	PeersWanted             int
	PrometheusListenAddress string
	PprofListenAddress      string
	Seeds                   []string
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenAddress:    tbcapi.DefaultListen,
		BlockCache:       250,
		BlockheaderCache: 1e6,
		LogLevel:         logLevel,
		MaxCachedTxs:     defaultMaxCachedTxs,
		MempoolEnabled:   true,
		PeersWanted:      defaultPeersWanted,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	// Note that peers is protected by mtx NOT peersMtx
	// TODO: move to PeerManager?
	peers map[string]*peer // active but not necessarily connected

	cfg *Config

	// stats
	printTime      time.Time
	blocksSize     uint64 // cumulative block size written
	blocksInserted int    // blocks inserted since last print

	// mempool
	mempool *mempool

	// bitcoin network
	wireNet     wire.BitcoinNet
	chainParams *chaincfg.Params
	timeSource  blockchain.MedianTimeSource
	seeds       []string

	pm *PeerManager

	blocks *ttl.TTL // outstanding block downloads [hash]when/where
	pings  *ttl.TTL // outstanding pings

	indexing bool // when set we are indexing

	db tbcd.Database

	// Prometheus
	isRunning     bool
	cmdsProcessed prometheus.Counter

	// WebSockets
	sessions       map[string]*tbcWs
	requestTimeout time.Duration

	// ignoreUlimit will explicitly not check ulimit settings on the host
	// machine, this is useful for very small datasets/chains
	ignoreUlimit bool
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	pings, err := ttl.New(cfg.PeersWanted, true)
	if err != nil {
		return nil, err
	}
	blocks, err := ttl.New(defaultPendingBlocks, true)
	if err != nil {
		return nil, err
	}
	defaultRequestTimeout := 10 * time.Second // XXX: make config option?
	s := &Server{
		cfg:        cfg,
		printTime:  time.Now().Add(10 * time.Second),
		blocks:     blocks,
		peers:      make(map[string]*peer, cfg.PeersWanted),
		pm:         newPeerManager(),
		pings:      pings,
		timeSource: blockchain.NewMedianTime(),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: promSubsystem,
			Name:      "rpc_calls_total",
			Help:      "The total number of successful RPC commands",
		}),
		sessions:       make(map[string]*tbcWs),
		requestTimeout: defaultRequestTimeout,
	}
	if s.cfg.MempoolEnabled {
		s.mempool, err = mempoolNew()
		if err != nil {
			return nil, err
		}
	}

	// We could use a PGURI verification here.

	switch cfg.Network {
	case "mainnet":
		s.wireNet = wire.MainNet
		s.chainParams = &chaincfg.MainNetParams
		s.seeds = mainnetSeeds
	case "testnet3":
		s.wireNet = wire.TestNet3
		s.chainParams = &chaincfg.TestNet3Params
		s.seeds = testnetSeeds
	case networkLocalnet:
		s.wireNet = wire.TestNet
		s.chainParams = &chaincfg.RegressionNetParams
		s.seeds = localnetSeeds
	default:
		return nil, fmt.Errorf("invalid network: %v", cfg.Network)
	}

	if len(cfg.Seeds) > 0 {
		s.seeds = cfg.Seeds
	}

	return s, nil
}

// DB exports the underlying database. This should only be used in tests.
// XXX remove this and deal with the fallout.
func (s *Server) DB() tbcd.Database {
	return s.db
}

func (s *Server) getHeaders(ctx context.Context, p *peer, hash *chainhash.Hash) error {
	log.Tracef("getheaders %v %v", p, hash)
	defer log.Tracef("seed exit %v %v", p, hash)

	ghs := wire.NewMsgGetHeaders()
	ghs.AddBlockLocatorHash(hash)
	if err := p.write(defaultCmdTimeout, ghs); err != nil {
		return fmt.Errorf("write get headers: %w", err)
	}

	return nil
}

// TODO: move to PeerManager?
func (s *Server) seed(pctx context.Context, peersWanted int) ([]string, error) {
	log.Tracef("seed")
	defer log.Tracef("seed exit")

	peers, err := s.pm.PeersRandom(peersWanted)
	if err != nil {
		return nil, fmt.Errorf("peers random: %w", err)
	}
	// return peers from db first
	if len(peers) >= peersWanted {
		return peers, nil
	}

	// Seed
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(pctx, 15*time.Second)
	defer cancel()

	errorsSeen := 0
	var moreSeeds []string
	for _, v := range s.seeds {
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			log.Errorf("Failed to parse host/port: %v", err)
			errorsSeen++
			continue
		}
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			log.Errorf("lookup: %v", err)
			errorsSeen++
			continue
		}

		for _, ip := range ips {
			moreSeeds = append(moreSeeds, net.JoinHostPort(ip.String(), port))
		}
	}

	if errorsSeen == len(s.seeds) {
		return nil, errors.New("could not seed")
	}

	// insert into peers table // TODO: ?
	peers = append(peers, moreSeeds...)

	// return fake peers but don't save them to the database // TODO: ?
	return peers, nil
}

// TODO: move to PeerManager?
func (s *Server) seedForever(ctx context.Context, peersWanted int) ([]string, error) {
	log.Tracef("seedForever")
	defer log.Tracef("seedForever")

	minW := 5
	maxW := 59
	for {
		holdOff := time.Duration(minW+rand.IntN(maxW-minW)) * time.Second
		var em string
		peers, err := s.seed(ctx, peersWanted)
		if err != nil {
			em = fmt.Sprintf("seed error: %v, retrying in %v", err, holdOff)
		} else if peers != nil && len(peers) == 0 {
			em = fmt.Sprintf("no peers found, retrying in %v", holdOff)
		} else {
			// great success!
			return peers, nil
		}
		log.Errorf("%v", em)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(holdOff):
		}
	}
}

// TODO: move to PeerManager?
func (s *Server) peerAdd(p *peer) error {
	log.Tracef("peerAdd: %v", p.address)
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if _, ok := s.peers[p.address]; ok {
		return fmt.Errorf("peer exists: %v", p)
	}
	s.peers[p.address] = p
	return nil
}

// TODO: move to PeerManager?
func (s *Server) peerDelete(address string) {
	log.Tracef("peerDelete: %v", address)
	s.mtx.Lock()
	delete(s.peers, address)
	s.mtx.Unlock()
}

// TODO: move to PeerManager?
func (s *Server) peersLen() int {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return len(s.peers)
}

// TODO: move to PeerManager?
func (s *Server) peerManager(ctx context.Context) error {
	log.Tracef("PeerManager")
	defer log.Tracef("PeerManager exit")

	// Channel for peering signals
	peersWanted := s.cfg.PeersWanted
	peerC := make(chan string, peersWanted)

	log.Infof("Peer manager connecting to %v peers", peersWanted)
	seeds, err := s.seedForever(ctx, peersWanted)
	if err != nil {
		// context canceled
		return fmt.Errorf("seed: %w", err)
	}
	if len(seeds) == 0 {
		// should not happen
		return errors.New("no seeds found")
	}

	// Add a ticker that times out every 13 seconds regardless of what is
	// going on. This will be nice and jittery and detect bad beers
	// peridiocally.
	loopTimeout := 13 * time.Second
	loopTicker := time.NewTicker(loopTimeout)

	x := 0
	for {
		peersActive := s.peersLen()
		log.Debugf("peerManager active %v wanted %v", peersActive, peersWanted)
		if peersActive < peersWanted {
			// XXX we may want to make peers play along with waitgroup

			// Connect peer
			for range peersWanted - peersActive {
				peer, err := NewPeer(s.wireNet, seeds[x])
				if err != nil {
					// This really should not happen
					log.Errorf("new peer: %v", err)
					continue
				} else {
					if err := s.peerAdd(peer); err != nil {
						log.Debugf("add peer: %v", err)
					} else {
						go s.peerConnect(ctx, peerC, peer)
					}
				}

				// Increment x before peer add since we want to
				// move on to the next seed in case the peer is
				// already in connected.
				x++
				if x >= len(seeds) {
					// XXX duplicate code from above
					seeds, err = s.seedForever(ctx, peersWanted)
					if err != nil {
						// Context canceled
						return fmt.Errorf("seed: %w", err)
					}
					if len(seeds) == 0 {
						// should not happen
						return errors.New("no seeds found")
					}
					x = 0
				}

			}
		}

		// Unfortunately we need a timer here to restart the loop.  The
		// error is a laptop goes to sleep, all peers disconnect, RSTs
		// are not seen by sleeping laptop, laptop wakes up. Now the
		// expiration timers are all expired but not noticed by the
		// laptop.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case address := <-peerC:
			// peer exited, connect to new one
			s.peerDelete(address)

			// Expire all blocks for peer
			n := s.blocks.DeleteByValue(func(p any) bool {
				return p.(*peer).address == address
			})
			log.Debugf("peer exited: %v blocks canceled: %v",
				address, n)
		case <-loopTicker.C:
			log.Tracef("pinging active peers: %v", s.peersLen())
			go s.pingAllPeers(ctx)
			loopTicker.Reset(loopTimeout)
		}
	}
}

// TODO: move to PeerManager?
func (s *Server) localPeerManager(ctx context.Context) error {
	log.Tracef("localPeerManager")
	defer log.Tracef("localPeerManager exit")

	if len(s.seeds) != 1 {
		return fmt.Errorf("expecting 1 seed, received %d", len(s.seeds))
	}

	peersWanted := 1
	peerC := make(chan string, peersWanted)

	peer, err := NewPeer(s.wireNet, s.seeds[0])
	if err != nil {
		return fmt.Errorf("new peer: %w", err)
	}

	log.Infof("Local peer manager connecting to %v peers", peersWanted)

	for {
		if err := s.peerAdd(peer); err != nil {
			return err
		}
		go s.peerConnect(ctx, peerC, peer)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case address := <-peerC:
			s.peerDelete(address)
			log.Infof("peer exited: %v", address)
		}

		// hold off on reconnect
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			log.Infof("peer exited: %v", "hold of timeout")
		}
	}
}

// TODO: move to PeerManager?
func (s *Server) startPeerManager(ctx context.Context) error {
	log.Tracef("startPeerManager")
	defer log.Tracef("startPeerManager exit")

	switch s.cfg.Network {
	case networkLocalnet:
		return s.localPeerManager(ctx)
	}
	return s.peerManager(ctx)
}

// TODO: move to PeerManager?
func (s *Server) pingExpired(ctx context.Context, key any, value any) {
	log.Tracef("pingExpired")
	defer log.Tracef("pingExpired exit")

	p, ok := value.(*peer)
	if !ok {
		log.Errorf("invalid ping expired type: %T", value)
		return
	}
	log.Debugf("pingExpired %v", key)
	if err := p.close(); err != nil {
		log.Debugf("ping %v: %v", key, err)
	}
}

// TODO: move to PeerManager?
func (s *Server) pingAllPeers(ctx context.Context) {
	log.Tracef("pingAllPeers")
	defer log.Tracef("pingAllPeers exit")

	// XXX reason and explain why this cannot be reentrant
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for _, p := range s.peers {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !p.isConnected() {
			continue
		}

		// Cancel outstanding ping, should not happen
		peer := p.String()
		s.pings.Cancel(peer)

		// We don't really care about the response. We just want to
		// write to the connection to make it fail if the other side
		// went away.
		log.Debugf("Pinging: %v", p)
		err := p.write(defaultCmdTimeout, wire.NewMsgPing(uint64(time.Now().Unix())))
		if err != nil {
			log.Debugf("ping %v: %v", p, err)
			return
		}

		// Record outstanding ping
		s.pings.Put(ctx, defaultPingTimeout, peer, p, s.pingExpired, nil)
	}
}

func (s *Server) handleGeneric(ctx context.Context, p *peer, msg wire.Message, raw []byte) bool {
	// Do accept addr and ping commands before we consider the peer up.
	switch m := msg.(type) {
	case *wire.MsgAddr:
		if err := s.handleAddr(ctx, p, m); err != nil {
			log.Debugf("handle generic addr: %v", err)
		}
	case *wire.MsgAddrV2:
		if err := s.handleAddrV2(ctx, p, m); err != nil {
			log.Debugf("handle generic addr v2: %v", err)
		}

	case *wire.MsgBlock:
		if err := s.handleBlock(ctx, p, m, raw); err != nil {
			log.Errorf("handle generic block: %v", err)
		}

	case *wire.MsgTx:
		if err := s.handleTx(ctx, p, m, raw); err != nil {
			log.Errorf("handle generic transaction: %v", err)
		}

	case *wire.MsgInv:
		if err := s.handleInv(ctx, p, m, raw); err != nil {
			log.Errorf("handle generic inv: %v", err)
		}

	case *wire.MsgPing:
		if err := s.handlePing(ctx, p, m); err != nil {
			log.Debugf("handle generic ping: %v", err)
		}

	case *wire.MsgPong:
		if err := s.handlePong(ctx, p, m); err != nil {
			log.Debugf("handle generic pong: %v", err)
		}

	case *wire.MsgNotFound:
		if err := s.handleNotFound(ctx, p, m, raw); err != nil {
			log.Errorf("handle generic not found: %v", err)
		}

	default:
		return false
	}
	return true
}

func (s *Server) pollP2P(ctx context.Context, d time.Duration, p *peer, cmd wire.Message, expect any) (any, error) {
	start := time.Now()
	if err := p.write(defaultCmdTimeout, cmd); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	// This function is pretty flawed. We should debate killing it
	// altogether and see if we can replace this with other functionality
	// elsewhere.

	verbose := false
	for {
		// See if we were interrupted, for the love of pete add ctx to wire
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		delta := d - time.Since(start)
		if delta <= 0 {
			return nil, errors.New("poll p2p: timeout")
		}
		msg, raw, err := p.read(delta)
		if errors.Is(err, wire.ErrUnknownMessage) {
			// skip unknown
			continue
		} else if err != nil {
			return nil, fmt.Errorf("poll p2p read: %v %v", p, err)
		}

		if verbose {
			log.Infof("%v: %v", p, spew.Sdump(msg))
		}
		switch m := msg.(type) {
		case *wire.MsgAddr:
			continue
		case *wire.MsgAddrV2:
			continue
		case *wire.MsgSendHeaders:
			continue
		case *wire.MsgFeeFilter:
			continue
		case *wire.MsgPing:
			continue
		case *wire.MsgPong:
			continue
		case *wire.MsgNotFound:
			// XXX sometimes, with emphasis on sometimes when we
			// request a block we go through this code. This does
			// not seem reliable at all and we probably should
			// simply continue to ignore it and detect missing
			// blocks using block headers.
			log.Debugf("not found %v: %v", p, spew.Sdump(m))
		case *wire.MsgInv:
			if len(m.InvList) > 0 {
				if m.InvList[0].Type != wire.InvTypeTx {
					// XXX block notifications go through
					// here. We may not need to react to
					// that and rely solely on block
					// headers.
					log.Debugf(spew.Sdump(msg))
				}
				continue
			}
		case *wire.MsgBlock:
			// panic("block")
		}
		var nf *wire.MsgNotFound
		if reflect.TypeOf(msg) == reflect.TypeOf(expect) ||
			reflect.TypeOf(msg) == reflect.TypeOf(nf) {
			return msg, nil
		}

		s.handleGeneric(ctx, p, msg, raw)
	}
}

func (s *Server) inCanonicalChainP2P(ctx context.Context, p *peer, hash *chainhash.Hash) (bool, error) {
	log.Tracef("inCanonicalChainP2P %v", hash)
	defer log.Tracef("inCanonicalChainP2P exit %v", hash)

	if s.chainParams.GenesisHash.IsEqual(hash) {
		return true, nil
	}

	ghs := wire.NewMsgGetHeaders()
	ghs.AddBlockLocatorHash(hash)
	ghs.HashStop = *s.chainParams.GenesisHash
	var x *wire.MsgHeaders
	msg, err := s.pollP2P(ctx, 5*time.Second, p, ghs, x)
	if err != nil {
		return false, fmt.Errorf("inCanonicalChainP2P: %w", err)
	}
	if m, ok := msg.(*wire.MsgHeaders); ok {
		if len(m.Headers) == 0 {
			// Happens when tip is canonical
			return true, nil
		}
		prevBlockHash := &m.Headers[0].PrevBlock
		if s.chainParams.GenesisHash.IsEqual(prevBlockHash) {
			return false, nil
		}
		zeroHash := chainhash.Hash{}
		if prevBlockHash.IsEqual(&zeroHash) {
			return false, errors.New("poll p2p: invalid header hash")
		}
		return true, nil
	}

	return false, fmt.Errorf("invalid headers type: %T", msg)
}

// findCanonicalP2P asks the p2p network if a block hash is canonical.  Think
// about if this should be removed since it is a bit awkward and prone to
// attack.
func (s *Server) findCanonicalP2P(ctx context.Context, p *peer, hash *chainhash.Hash) (*chainhash.Hash, error) {
	// XXX this function is flawed and needs to be rewritten.
	// XXX memoize results
	for {
		x, err := s.inCanonicalChainP2P(ctx, p, hash)
		if err != nil {
			return nil, fmt.Errorf("find canonical: %v %v", p, err)
		}
		if x {
			return hash, nil
		}

		bh, err := s.db.BlockHeaderByHash(ctx, hash)
		if err != nil {
			return nil, fmt.Errorf("find canonical header: %v %v", p, err)
		}
		wbh, err := bh.Wire()
		if err != nil {
			return nil, fmt.Errorf("find canonical header wire: %v %v", p, err)
		}
		hash = &wbh.PrevBlock
		if s.chainParams.GenesisHash.IsEqual(hash) {
			return nil, errors.New("reached genesis")
		}
	}
}

func (s *Server) fixupUtxoIndex(ctx context.Context, p *peer) error {
	log.Tracef("fixupUtxoIndex")
	defer log.Tracef("fixupUtxoIndex exit")

	utxoHH, err := s.UtxoIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("fixup utxo index hash: %v %v", p, err)
	}
	hash, err := s.findCanonicalP2P(ctx, p, utxoHH.Hash)
	if err != nil {
		return fmt.Errorf("fixup utxo index find: %v %v", p, err)
	}
	if hash.IsEqual(utxoHH.Hash) {
		// Found self, utxo index is on canonical chain.
		return nil
	}

	endBH, err := s.db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("fixup utxo index block header: %v %v", p, err)
	}
	if utxoHH.Height < endBH.Height {
		panic("impossible condition")
	}

	log.Infof("Fixing up utxo index from %v to %v @ %v", utxoHH, endBH, endBH.Height)
	err = s.UtxoIndexer(ctx, endBH.Hash)
	if err != nil {
		// this probably is terminal
		panic(fmt.Errorf("fixup utxo index: %v %v", p, err))
	}
	return nil
}

func (s *Server) fixupTxIndex(ctx context.Context, p *peer) error {
	log.Tracef("fixupTxIndex")
	defer log.Tracef("fixupTxIndex exit")

	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		return fmt.Errorf("fixup tx index hash: %v %v", p, err)
	}
	hash, err := s.findCanonicalP2P(ctx, p, txHH.Hash)
	if err != nil {
		return fmt.Errorf("fixup tx index find: %v %v", p, err)
	}
	if hash.IsEqual(txHH.Hash) {
		// Found self, tx index is on canonical chain.
		return nil
	}

	endBH, err := s.db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("fixup tx index block header: %v %v", p, err)
	}
	if txHH.Height < endBH.Height {
		panic("impossible condition")
	}

	// fixup tx index
	log.Infof("Fixing up tx index from %v to %v @ %v", txHH, endBH, endBH.Height)
	err = s.TxIndexer(ctx, endBH.Hash)
	if err != nil {
		// this probably is terminal
		panic(fmt.Errorf("fixup tx index: %v %v", p, err))
	}
	return nil
}

// fixupIndexes fixes up the index when at start of day the index tip is not on
// the canonical chain. This code remains disabled for now because it uses an
// awkward p2p method to determine if the index tip is canonical. Fix this by
// downloading all blockheaders and then determine using said blockheaders if
// tip needs to be fixed up or not.
func (s *Server) fixupIndexes(ctx context.Context, p *peer) error {
	log.Tracef("fixupIndexes")
	defer log.Tracef("fixupIndexes exit")

	s.mtx.Lock()
	if s.indexing {
		log.Debugf("fixup indexes already indexing")
		s.mtx.Unlock()
		return nil
	}
	s.mtx.Unlock()

	err := s.fixupUtxoIndex(ctx, p)
	if err != nil {
		return fmt.Errorf("fixupUtxoIndex %w", err)
	}
	err = s.fixupTxIndex(ctx, p)
	if err != nil {
		return fmt.Errorf("fixupTxIndex %w", err)
	}

	return nil
}

// sod is Start Of Day. Code runs through bringup of a peer.
func (s *Server) sod(ctx context.Context, p *peer) (*chainhash.Hash, error) {
	log.Tracef("sod")
	defer log.Tracef("sod exit")

	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		return nil, fmt.Errorf("block header best: %v %v", p, err)
	}
	hash, err := s.findCanonicalP2P(ctx, p, bhb.Hash)
	if err != nil {
		return nil, fmt.Errorf("find canonical: %v %v", p, err)
	}
	if hash.IsEqual(bhb.Hash) {
		// Found self, on canonical chain.
		return bhb.Hash, nil
	}
	if bhb.Height > uint64(p.remoteVersion.LastBlock) {
		// XXX debug
		// XXX should we look at cumulative difficulty?
		// XXX unwind indexes?
		log.Infof("sod: %v our tip is greater %v > %v",
			p, bhb.Height, p.remoteVersion.LastBlock)
		return bhb.Hash, nil
	}
	log.Infof("tip not canonical: %v %v common: %v", bhb.Height, bhb, hash)

	return hash, nil
}

// TODO: move to PeerManager?
func (s *Server) peerConnect(ctx context.Context, peerC chan string, p *peer) {
	log.Tracef("peerConnect %v", p)
	defer func() {
		select {
		case peerC <- p.String(): // remove from peer manager
		default:
			log.Tracef("could not signal peer channel: %v", p)
			panic("xx")
		}
		log.Tracef("peerConnect exit %v", p)
	}()

	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := p.connect(tctx)
	defer func() {
		// Remove from database; it's ok to be aggressive if it
		// failed with no route to host or failed with i/o
		// timeout or invalid network (ipv4/ipv6).
		//
		// This does have the side-effect of draining the peer
		// table during network outages but that is ok. The
		// peers table will be rebuild based on DNS seeds.
		//
		// XXX This really belongs in peer manager.
		if err := s.pm.PeerDelete(p.String()); err != nil {
			log.Errorf("peer manager delete (%v): %v", p, err)
		}
		if err := p.close(); err != nil && !errors.Is(err, net.ErrClosed) {
			if errors.Is(err, net.ErrClosed) {
				panic(err)
			}
			log.Errorf("peer disconnect: %v %v", p, err)
		}
	}()
	if err != nil {
		return
	}

	// See if our tip is indeed canonical.
	ch, err := s.sod(ctx, p)
	if err != nil {
		if errors.Is(err, leveldb.ErrClosed) {
			// Database is closed, This is terminal.
			log.Criticalf("sod: %v database closed", p)
			return
		}
	} else if ch != nil {
		err := s.getHeaders(ctx, p, ch)
		if err != nil {
			// Database is closed, This is terminal.
			log.Errorf("sod get headers: %v %v %v", p, ch, err)
			return
		}
	}

	// Get p2p information.
	err = p.write(defaultCmdTimeout, wire.NewMsgGetAddr())
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Errorf("peer get addr: %v", err)
		return
	}

	if s.cfg.MempoolEnabled {
		// Start building the mempool.
		err = p.write(defaultCmdTimeout, wire.NewMsgMemPool())
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorf("peer mempool: %v", err)
			return
		}
	}

	// XXX wave hands here for now but we should get 3 peers to agree that
	// this is a fork indeed.

	// Only now can we consider the peer connected
	log.Debugf("Peer connected: %v", p)
	verbose := false
	for {
		// See if we were interrupted, for the love of pete add ctx to wire
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, raw, err := p.read(5 * time.Second)
		if errors.Is(err, wire.ErrUnknownMessage) {
			// skip unknown
			continue
		} else if err != nil {
			log.Debugf("peer read %v: %v", p, err)
			return
		}

		if verbose {
			log.Infof("%v: %v", p, spew.Sdump(msg))
		}
		//switch m := msg.(type) {
		//case *wire.MsgNotFound:
		//	log.Infof("%v: %v", p, spew.Sdump(m))
		//}
		if s.handleGeneric(ctx, p, msg, raw) {
			continue
		}

		// When quiesced do not handle other p2p commands.
		s.mtx.Lock()
		if s.indexing {
			log.Debugf("indexing %v", s.indexing)
			s.mtx.Unlock()
			continue
		}
		s.mtx.Unlock()

		switch m := msg.(type) {
		case *wire.MsgHeaders:
			if err := s.handleHeaders(ctx, p, m); err != nil {
				log.Errorf("handle headers: %v", err)
			}

		default:
			log.Tracef("unhandled message type %v: %T\n", p, msg)
		}
	}
}

func (s *Server) running() bool {
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
	r := s.running()
	if r {
		return 1
	}
	return 0
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

func (s *Server) handleAddr(_ context.Context, p *peer, msg *wire.MsgAddr) error {
	log.Tracef("handleAddr (%v): %v", p, len(msg.AddrList))
	defer log.Tracef("handleAddr exit (%v)", p)

	peers := make([]string, len(msg.AddrList))
	for i, a := range msg.AddrList {
		peers[i] = net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port)))
	}

	if err := s.pm.PeersInsert(peers); err != nil {
		return fmt.Errorf("insert peers: %w", err)
	}

	return nil
}

func (s *Server) handleAddrV2(_ context.Context, p *peer, msg *wire.MsgAddrV2) error {
	log.Tracef("handleAddrV2 (%v): %v", p, len(msg.AddrList))
	defer log.Tracef("handleAddrV2 exit (%v)", p)

	peers := make([]string, 0, len(msg.AddrList))
	for _, a := range msg.AddrList {
		addr := net.JoinHostPort(a.Addr.String(), strconv.Itoa(int(a.Port)))
		if len(addr) < 7 {
			// 0.0.0.0
			continue
		}
		peers = append(peers, addr)
	}

	if err := s.pm.PeersInsert(peers); err != nil {
		return fmt.Errorf("insert peers: %w", err)
	}

	return nil
}

func (s *Server) handlePing(ctx context.Context, p *peer, msg *wire.MsgPing) error {
	log.Tracef("handlePing %v", p.address)
	defer log.Tracef("handlePing exit %v", p.address)

	pong := wire.NewMsgPong(msg.Nonce)
	err := p.write(defaultCmdTimeout, pong)
	if err != nil {
		return fmt.Errorf("could not write pong message %v: %w", p.address, err)
	}
	log.Tracef("handlePing %v: pong %v", p.address, pong.Nonce)

	return nil
}

func (s *Server) handlePong(ctx context.Context, p *peer, pong *wire.MsgPong) error {
	log.Tracef("handlePong %v", p.address)
	defer log.Tracef("handlePong exit %v", p.address)

	if err := s.pings.Cancel(p.String()); err != nil {
		return fmt.Errorf("cancel: %w", err)
	}

	// XXX might as well ask for missing blocks
	go s.syncBlocks(ctx)

	log.Tracef("handlePong %v: pong %v", p.address, pong.Nonce)
	return nil
}

func (s *Server) downloadBlock(ctx context.Context, p *peer, ch *chainhash.Hash) error {
	log.Tracef("downloadBlock")
	defer log.Tracef("downloadBlock exit")

	getData := wire.NewMsgGetData()
	getData.InvList = append(getData.InvList,
		&wire.InvVect{
			Type: wire.InvTypeBlock,
			Hash: *ch,
		})

	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := p.write(defaultCmdTimeout, getData)
	if err != nil {
		if !errors.Is(err, net.ErrClosed) &&
			!errors.Is(err, os.ErrDeadlineExceeded) {
			log.Errorf("download block write: %v %v", p, err)
		}
	}
	return err
}

func (s *Server) handleBlockExpired(ctx context.Context, key any, value any) error {
	log.Infof("handleBlockExpired %v", key)
	log.Tracef("handleBlockExpired")
	defer log.Tracef("handleBlockExpired exit")

	p, ok := value.(*peer)
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
	bhX, err := s.db.BlockHeaderByHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("block header by hash: %w", err)
	}
	canonical, err := s.isCanonical(ctx, bhX)
	if err != nil {
		return fmt.Errorf("is canonical: %w", err)
	}

	if !canonical {
		log.Infof("deleting from blocks missing: %v %v %v",
			p, bhX.Height, bhX)
		err := s.db.BlockMissingDelete(ctx, int64(bhX.Height), bhX.Hash)
		if err != nil {
			return fmt.Errorf("block expired delete missing: %w", err)
		}

		// Block exists on a fork, stop downloading it.
		return nil
	}

	// Legit timeout, return error so that it can be retried.
	return fmt.Errorf("timeout %v", key)
}

func (s *Server) blockExpired(ctx context.Context, key any, value any) {
	log.Tracef("blockExpired")
	defer log.Tracef("blockExpired exit")

	err := s.handleBlockExpired(ctx, key, value)
	if err != nil {
		// Close peer.
		if p, ok := value.(*peer); ok {
			p.close() // XXX kill peer
			log.Errorf("block expired: %v %v", p, err)
		}
	}
}

func (s *Server) downloadMissingTx(ctx context.Context, p *peer) error {
	log.Tracef("downloadMissingTx")
	defer log.Tracef("downloadMissingTx exit")

	getData, err := s.mempool.getDataConstruct(ctx)
	if err != nil {
		return fmt.Errorf("download missing tx: %w", err)
	}
	err = p.write(defaultCmdTimeout, getData)
	if err != nil {
		// peer dead, make sure it is reaped
		p.close() // XXX this should not happen here
		if !errors.Is(err, net.ErrClosed) &&
			!errors.Is(err, os.ErrDeadlineExceeded) {
			log.Errorf("download missing tx write: %v %v", p, err)
		}
	}
	return err
}

func (s *Server) handleTx(ctx context.Context, p *peer, msg *wire.MsgTx, raw []byte) error {
	log.Tracef("handleTx")
	defer log.Tracef("handleTx exit")

	return s.mempool.txsInsert(ctx, msg, raw)
}

// randomPeer returns a random peer from the map. Must be called with lock
// held.
// XXX move to PeerManager
func (s *Server) randomPeer(ctx context.Context) (*peer, error) {
	log.Tracef("randomPeer")
	defer log.Tracef("randomPeer exit")

	// unassigned slot, download block
	for _, p := range s.peers {
		if !p.isConnected() {
			// Not connected yet
			continue
		}
		return p, nil
	}
	return nil, errors.New("no peers")
}

func (s *Server) syncBlocks(ctx context.Context) {
	log.Tracef("syncBlocks")
	defer log.Tracef("syncBlocks exit")

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
			if err = s.SyncIndexersToBest(ctx); err != nil && err != ErrAlreadyIndexing {
				// XXX this is probably not a panic.
				panic(fmt.Errorf("sync blocks: %w", err))
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
		rp, err := s.randomPeer(ctx)
		if err != nil {
			// This can happen during startup or when the network
			// is starved.
			// XXX: Probably too loud, remove later.
			log.Errorf("random peer %v: %v", hashS, err)
			return
		}
		s.blocks.Put(ctx, defaultBlockPendingTimeout, hashS, rp,
			s.blockExpired, nil)
		go s.downloadBlock(ctx, rp, hash)
	}
}

func (s *Server) handleHeaders(ctx context.Context, p *peer, msg *wire.MsgHeaders) error {
	log.Tracef("handleHeaders (%v): %v", p, len(msg.Headers))
	defer log.Tracef("handleHeaders exit (%v): %v", p, len(msg.Headers))

	if len(msg.Headers) == 0 {
		// This may signify the end of IBD but isn't 100%. We can fart
		// around with mean block time to determine if this peer is
		// just behind or if we are nominally where we should be. This
		// test will never be 100% accurate.

		// only do this if peer is synced, not sure how to detect that.

		go s.syncBlocks(ctx)

		return nil
	}

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
	it, cbh, lbh, n, err := s.db.BlockHeadersInsert(ctx, msg)
	if err != nil {
		// This ends the race between peers during IBD.
		if errors.Is(err, database.ErrDuplicate) {
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

	// Note that BlockHeadersInsert always returns the canonical
	// tip blockheader.
	var height uint64
	switch it {
	case tbcd.ITChainExtend:
		height = cbh.Height

		// Ask for next batch of headers at canonical tip.
		if err = s.getHeaders(ctx, p, cbh.BlockHash()); err != nil {
			return fmt.Errorf("get headers: %w", err)
		}

	case tbcd.ITForkExtend:
		height = lbh.Height

		// Ask for more block headers at the fork tip.
		if err = s.getHeaders(ctx, p, lbh.BlockHash()); err != nil {
			return fmt.Errorf("get headers fork: %w", err)
		}

		// Also ask for more block headers at canonical tip
		if err = s.getHeaders(ctx, p, cbh.BlockHash()); err != nil {
			return fmt.Errorf("get headers canonical: %w", err)
		}

	case tbcd.ITChainFork:
		height = cbh.Height

		if s.Synced(ctx).Synced {
			// XXX this is racy but is a good enough test
			// to get past most of this.
			panic("chain forked, unwind/rewind indexes")
		}

		// Ask for more block headers at the fork tip.
		if err = s.getHeaders(ctx, p, lbh.BlockHash()); err != nil {
			return fmt.Errorf("get headers fork: %w", err)
		}

		// Also ask for more block headers at canonical tip
		if err = s.getHeaders(ctx, p, cbh.BlockHash()); err != nil {
			return fmt.Errorf("get headers canonical: %w", err)
		}

	default:
		// Can't happen.
		return fmt.Errorf("invalid insert type: %d", it)
	}

	log.Infof("Inserted (%v) %v block headers height %v", it, n, height)

	return nil
}

func (s *Server) handleBlock(ctx context.Context, p *peer, msg *wire.MsgBlock, raw []byte) error {
	log.Tracef("handleBlock (%v)", p)
	defer log.Tracef("handleBlock exit (%v)", p)

	block := btcutil.NewBlock(msg)
	bhs := block.Hash().String()
	s.blocks.Delete(bhs) // remove block from ttl regardless of insert result

	// Whatever happens, kick cache in the nuts on the way out.
	defer func() {
		// kick cache
		go s.syncBlocks(ctx)
	}()

	if s.cfg.BlockSanity {
		err := blockchain.CheckBlockSanity(block, s.chainParams.PowLimit,
			s.timeSource)
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

	// Reap txs from mempool, no need to log error.
	if s.cfg.MempoolEnabled {
		txHashes, _ := block.MsgBlock().TxHashes()
		_ = s.mempool.txsRemove(ctx, txHashes)
	}

	log.Debugf("inserted block at height %d, parent hash %s", height, block.MsgBlock().Header.PrevBlock)

	s.mtx.Lock()
	// Stats
	s.blocksSize += uint64(len(raw))
	s.blocksInserted++

	now := time.Now()
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
		goodPeers, badPeers := s.pm.Stats()
		// Gonna take it right into the Danger Zone! (double mutex)
		for _, peer := range s.peers {
			if peer.isConnected() {
				connectedPeers++
			}
		}

		// This is super awkward but prevents calculating N inserts *
		// time.Before(10*time.Second).
		delta := now.Sub(s.printTime.Add(-10 * time.Second))

		log.Infof("Inserted %v blocks (%v) in the last %v",
			s.blocksInserted, humanize.Bytes(s.blocksSize), delta)
		log.Infof("Pending blocks %v/%v active peers %v connected peers %v "+
			"good peers %v bad peers %v mempool %v %v",
			s.blocks.Len(), defaultPendingBlocks, len(s.peers),
			connectedPeers, goodPeers, badPeers, mempoolCount,
			humanize.Bytes(uint64(mempoolSize)))

		// Reset stats
		s.blocksSize = 0
		s.blocksInserted = 0
		s.printTime = now.Add(10 * time.Second)
	}
	s.mtx.Unlock()

	return nil
}

func (s *Server) handleInv(ctx context.Context, p *peer, msg *wire.MsgInv, raw []byte) error {
	log.Tracef("handleInv (%v)", p)
	defer log.Tracef("handleInv exit (%v)", p)

	var txsFound bool

	for _, v := range msg.InvList {
		switch v.Type {
		case wire.InvTypeError:
			log.Errorf("inventory error: %v", v.Hash)
		case wire.InvTypeTx:
			// handle these later or else we have to insert txs one
			// at a time while taking a mutex.
			txsFound = true
		case wire.InvTypeBlock:
			log.Debugf("inventory block: %v", v.Hash)
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

	if s.cfg.MempoolEnabled && txsFound {
		if err := s.mempool.invTxsInsert(ctx, msg); err != nil {
			go s.downloadMissingTx(ctx, p)
		}
	}

	return nil
}

func (s *Server) handleNotFound(ctx context.Context, p *peer, msg *wire.MsgNotFound, raw []byte) error {
	// log.Infof("handleNotFound %v", spew.Sdump(msg))
	// defer log.Infof("handleNotFound exit")

	//// XXX keep here to see if it spams logs
	//log.Infof("NotFound: %v %v", p, spew.Sdump(msg))

	return nil
}

func (s *Server) insertGenesis(ctx context.Context) error {
	log.Tracef("insertGenesis")
	defer log.Tracef("insertGenesis exit")

	// We really should be inserting the block first but block insert
	// verifies that a block header exists.
	log.Infof("Inserting genesis block and header: %v", s.chainParams.GenesisHash)
	err := s.db.BlockHeaderGenesisInsert(ctx, &s.chainParams.GenesisBlock.Header)
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
func (s *Server) BlockByHash(ctx context.Context, hash *chainhash.Hash) (*btcutil.Block, error) {
	log.Tracef("BlockByHash")
	defer log.Tracef("BlockByHash exit")
	return s.db.BlockByHash(ctx, hash)
}

func (s *Server) BlockHeaderByHash(ctx context.Context, hash *chainhash.Hash) (*wire.BlockHeader, uint64, error) {
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

func (s *Server) RawBlockHeadersByHeight(ctx context.Context, height uint64) ([]api.ByteSlice, error) {
	log.Tracef("RawBlockHeadersByHeight")
	defer log.Tracef("RawBlockHeadersByHeight exit")

	bhs, err := s.db.BlockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, err
	}

	var headers []api.ByteSlice
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

func (s *Server) DifficultyAtHash(ctx context.Context, hash *chainhash.Hash) (*big.Int, error) {
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

func (s *Server) BalanceByAddress(ctx context.Context, encodedAddress string) (uint64, error) {
	log.Tracef("BalanceByAddress")
	defer log.Tracef("BalanceByAddress exit")

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

func (s *Server) UtxosByAddress(ctx context.Context, encodedAddress string, start uint64, count uint64) ([]tbcd.Utxo, error) {
	log.Tracef("UtxosByAddress")
	defer log.Tracef("UtxosByAddress exit")

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
	return utxos, nil
}

func (s *Server) SpentOutputsByTxId(ctx context.Context, txId *chainhash.Hash) ([]tbcd.SpentInfo, error) {
	log.Tracef("SpentOutputsByTxId")
	defer log.Tracef("SpentOutputsByTxId exit")

	// XXX investigate if this is indeed correct. As it is written now it
	// returns all spent outputs. The db should always be canonical but
	// assert that.

	si, err := s.db.SpentOutputsByTxId(ctx, txId)
	if err != nil {
		return nil, err
	}

	return si, nil
}

func (s *Server) TxById(ctx context.Context, txId *chainhash.Hash) (*wire.MsgTx, error) {
	log.Tracef("TxById")
	defer log.Tracef("TxById exit")

	blockHashes, err := s.db.BlocksByTxId(ctx, txId)
	if err != nil {
		return nil, err
	}

	if len(blockHashes) > 1 {
		panic("fix me blockhashes len")
	}

	// XXX investigate if this is indeed correct. As it is written now it
	// returns the first block the tx exists in. This however must be the
	// canonical block. This function must also return the blockhash.

	for _, blockHash := range blockHashes {
		block, err := s.db.BlockByHash(ctx, blockHash)
		if err != nil {
			return nil, err
		}
		for _, tx := range block.Transactions() {
			if tx.Hash().IsEqual(txId) {
				return tx.MsgTx(), nil
			}
		}
	}

	return nil, database.ErrNotFound
}

func feesFromTransactions(txs []*btcutil.Tx) error {
	for idx, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if idx == 0 {
				// Skip coinbase inputs
				continue
			}
			_ = txIn
		}
		for outIndex, txOut := range tx.MsgTx().TxOut {
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}
			_ = outIndex
		}
	}

	return nil
}

func (s *Server) FeesAtHeight(ctx context.Context, height, count int64) (uint64, error) {
	log.Tracef("FeesAtHeight")
	defer log.Tracef("FeesAtHeight exit")

	if height-count < 0 {
		return 0, errors.New("height - count is less than 0")
	}
	var fees uint64
	for i := int64(0); i < int64(count); i++ {
		log.Infof("%v", uint64(height-i))
		bhs, err := s.db.BlockHeadersByHeight(ctx, uint64(height-i))
		if err != nil {
			return 0, fmt.Errorf("headers by height: %w", err)
		}
		if len(bhs) != 1 {
			panic("fees at height: unsupported fork")
			// return 0, fmt.Errorf("too many block headers: %v", len(bhs))
		}
		b, err := s.db.BlockByHash(ctx, bhs[0].Hash)
		if err != nil {
			return 0, fmt.Errorf("block by hash: %w", err)
		}

		// walk block tx'
		if err = feesFromTransactions(b.Transactions()); err != nil {
			return 0, fmt.Errorf("fees from transactions %v %v: %v",
				height, b.Hash(), err)
		}
	}

	return fees, errors.New("not yet")
}

type SyncInfo struct {
	Synced      bool // True when all indexing is caught up
	BlockHeader HashHeight
	Utxo        HashHeight
	Tx          HashHeight
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
		// The context is canceled but wire isn't smart enought so we
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
		panic(err)
	}
	// Ensure we have genesis or the Synced flag will be true if metadata
	// does not exist.
	if zeroHash.IsEqual(bhb.Hash) {
		panic("no genesis")
	}
	si.BlockHeader.Hash = bhb.Hash
	si.BlockHeader.Height = bhb.Height

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

	if utxoHH.Hash.IsEqual(bhb.Hash) && txHH.Hash.IsEqual(bhb.Hash) &&
		!s.indexing && !s.blksMissing(ctx) {
		si.Synced = true
	}
	return
}

// Synced returns true if all block headers, blocks and all indexes are caught up.
func (s *Server) Synced(ctx context.Context) SyncInfo {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.synced(ctx)
}

// DBOpen opens the underlying server database. It has been put in its own
// function to make it available during tests and hemictl.
// It would be good if it can be deleted.
// XXX remove and find a different way to do this.
func (s *Server) DBOpen(ctx context.Context) error {
	log.Tracef("DBOpen")
	defer log.Tracef("DBOpen exit")

	// This should have been verified but let's not make assumptions.
	switch s.cfg.Network {
	case "testnet3":
	case "mainnet":
	case networkLocalnet: // XXX why is this here?, this breaks the filepath.Join
	default:
		return fmt.Errorf("unsupported network: %v", s.cfg.Network)
	}

	// Open db.
	var err error
	cfg := level.NewConfig(filepath.Join(s.cfg.LevelDBHome, s.cfg.Network))
	cfg.BlockCache = s.cfg.BlockCache
	cfg.BlockheaderCache = s.cfg.BlockheaderCache
	s.db, err = level.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open level database: %w", err)
	}

	return nil
}

// XXX remove and find a different way to do this.
func (s *Server) DBClose() error {
	log.Tracef("DBClose")
	defer log.Tracef("DBClose")

	return s.db.Close()
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return errors.New("tbc already running")
	}
	defer s.testAndSetRunning(false)

	// We need a lot of open files and memory for the indexes. Best effort
	// to echo to the user what the ulimits are.
	s.ignoreUlimit = true
	if s.ignoreUlimit || s.cfg.Network == networkLocalnet {
		log.Warningf("ignoring ulimit requirements")
	} else if ulimitSupported {
		if err := verifyUlimits(); err != nil {
			return fmt.Errorf("verify ulimits: %w", err)
		}
	} else {
		log.Errorf("This architecture does not supported ulimit verification. " +
			"Consult the README for minimum values.")
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	err := s.DBOpen(ctx)
	if err != nil {
		return fmt.Errorf("open level database: %w", err)
	}
	defer func() {
		err := s.DBClose()
		if err != nil {
			log.Errorf("db close: %v", err)
		}
	}()

	// Find out where IBD is at
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("block header best: %w", err)
		}

		if err = s.insertGenesis(ctx); err != nil {
			return fmt.Errorf("insert genesis: %w", err)
		}
		bhb, err = s.db.BlockHeaderBest(ctx)
		if err != nil {
			return err
		}
	}
	log.Infof("Genesis: %v", s.chainParams.GenesisHash) // XXX make debug
	log.Infof("Starting block headers sync at %v height: %v time %v",
		bhb, bhb.Height, bhb.Timestamp())
	utxoHH, err := s.UtxoIndexHash(ctx)
	if err == nil {
		log.Infof("Utxo index %v", utxoHH)
	}
	txHH, err := s.TxIndexHash(ctx)
	if err == nil {
		log.Infof("Tx index %v", txHH)
	}

	// HTTP server
	mux := http.NewServeMux()
	log.Infof("handle (tbc): %s", tbcapi.RouteWebsocket)
	mux.HandleFunc(tbcapi.RouteWebsocket, s.handleWebsocket)

	httpServer := &http.Server{
		Addr:        s.cfg.ListenAddress,
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	httpErrCh := make(chan error)
	go func() {
		log.Infof("Listening: %s", s.cfg.ListenAddress)
		httpErrCh <- httpServer.ListenAndServe()
	}()
	defer func() {
		if err = httpServer.Shutdown(ctx); err != nil {
			log.Errorf("http server exit: %v", err)
			return
		}
		log.Infof("RPC server shutdown cleanly")
	}()

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
		cs := []prometheus.Collector{
			s.cmdsProcessed,
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Subsystem: promSubsystem,
				Name:      "running",
				Help:      "Is tbc service running.",
			}, s.promRunning),
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := d.Run(ctx, cs); !errors.Is(err, context.Canceled) {
				log.Errorf("prometheus terminated with error: %v", err)
				return
			}
			log.Infof("prometheus clean shutdown")
		}()
	}

	errC := make(chan error)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.startPeerManager(ctx); err != nil {
			select {
			case errC <- err:
			default:
			}
		}
	}()

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
