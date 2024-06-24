// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"net"
	"net/http"
	"path/filepath"
	"slices"
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

	mainnetPort  = "8333"
	testnetPort  = "18333"
	localnetPort = "18444"

	defaultPeersWanted   = 64
	defaultPendingBlocks = 128 // 128 * ~4MB max memory use

	defaultMaxCachedTxs = 1e6 // dual purpose cache, max key 69, max value 36

	networkLocalnet = "localnet" // XXX this needs to be rethought

	defaultCmdTimeout          = 4 * time.Second
	defaultPingTimeout         = 3 * time.Second
	defaultBlockPendingTimeout = 17 * time.Second
)

var (
	zeroHash = new(chainhash.Hash) // used to check if a hash is invalid

	localnetSeeds = []string{
		"bitcoind",
	}
	testnetSeeds = []string{
		"testnet-seed.bitcoin.jonasschnelli.ch",
		"seed.tbtc.petertodd.org",
		"seed.testnet.bitcoin.sprovoost.nl",
		"testnet-seed.bluematt.me",
	}
	mainnetSeeds = []string{
		"seed.bitcoin.sipa.be",
		"dnsseed.bluematt.me",
		"dnsseed.bitcoin.dashjr.org",
		"seed.bitcoinstats.com",
		"seed.bitnodes.io",
		"seed.bitcoin.jonasschnelli.ch",
	}
)

var log = loggo.GetLogger("tbc")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

func tx2Bytes(tx *wire.MsgTx) ([]byte, error) {
	var b bytes.Buffer
	if err := tx.Serialize(&b); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func bytes2Tx(b []byte) (*wire.MsgTx, error) {
	var w wire.MsgTx
	if err := w.Deserialize(bytes.NewReader(b)); err != nil {
		return nil, err
	}

	return &w, nil
}

func header2Slice(wbh *wire.BlockHeader) ([]byte, error) {
	var b bytes.Buffer
	err := wbh.Serialize(&b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func header2Array(wbh *wire.BlockHeader) ([80]byte, error) {
	sb, err := header2Slice(wbh)
	if err != nil {
		return [80]byte{}, err
	}
	return [80]byte(sb), nil
}

func h2b(wbh *wire.BlockHeader) []byte {
	hb, err := header2Slice(wbh)
	if err != nil {
		panic(err)
	}
	return hb
}

func bytes2Header(header []byte) (*wire.BlockHeader, error) {
	var bh wire.BlockHeader
	err := bh.Deserialize(bytes.NewReader(header))
	if err != nil {
		return nil, fmt.Errorf("deserialize block header: %w", err)
	}
	return &bh, nil
}

func sliceChainHash(ch chainhash.Hash) []byte {
	// Fuck you chainhash package
	return ch[:]
}

type Config struct {
	AutoIndex               bool
	BlockSanity             bool
	LevelDBHome             string
	ListenAddress           string
	LogLevel                string
	MaxCachedTxs            int
	Network                 string
	PeersWanted             int
	PrometheusListenAddress string
	PprofListenAddress      string
	Seeds                   []string
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenAddress: tbcapi.DefaultListen,
		LogLevel:      logLevel,
		MaxCachedTxs:  defaultMaxCachedTxs,
		PeersWanted:   defaultPeersWanted,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// stats
	printTime       time.Time
	blocksSize      uint64 // cumulative block size written
	blocksInserted  map[string]struct{}
	blocksDuplicate int

	// bitcoin network
	wireNet     wire.BitcoinNet
	chainParams *chaincfg.Params
	timeSource  blockchain.MedianTimeSource
	port        string
	seeds       []string

	peers  map[string]*peer // active but not necessarily connected
	blocks *ttl.TTL         // outstanding block downloads [hash]when/where
	pings  *ttl.TTL         // outstanding pings

	// reentrancy flags for the indexers
	// utxoIndexerRunning bool
	// txIndexerRunning   bool
	quiesced bool // when set do not accept blockheaders and ot blocks.
	// clipped  bool // XXX kill including all surrounding code, this is for test only
	indexing bool // prevent re-entrant indexing

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
		cfg:            cfg,
		printTime:      time.Now().Add(10 * time.Second),
		blocks:         blocks,
		peers:          make(map[string]*peer, cfg.PeersWanted),
		pings:          pings,
		blocksInserted: make(map[string]struct{}, 8192), // stats XXX rmeove?
		timeSource:     blockchain.NewMedianTime(),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: promSubsystem,
			Name:      "rpc_calls_total",
			Help:      "The total number of successful RPC commands",
		}),
		sessions:       make(map[string]*tbcWs),
		requestTimeout: defaultRequestTimeout,
	}

	// We could use a PGURI verification here.

	switch cfg.Network {
	case "mainnet":
		s.port = mainnetPort
		s.wireNet = wire.MainNet
		s.chainParams = &chaincfg.MainNetParams
		s.seeds = mainnetSeeds
	case "testnet3":
		s.port = testnetPort
		s.wireNet = wire.TestNet3
		s.chainParams = &chaincfg.TestNet3Params
		s.seeds = testnetSeeds
	case networkLocalnet:
		s.port = localnetPort
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
func (s *Server) DB() tbcd.Database {
	return s.db
}

func (s *Server) getHeaders(ctx context.Context, p *peer, lastHeaderHash []byte) error {
	bh, err := bytes2Header(lastHeaderHash)
	if err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}
	hash := bh.BlockHash()
	ghs := wire.NewMsgGetHeaders()
	ghs.AddBlockLocatorHash(&hash)
	if err = p.write(defaultCmdTimeout, ghs); err != nil {
		return fmt.Errorf("write get headers: %w", err)
	}

	return nil
}

func (s *Server) seed(pctx context.Context, peersWanted int) ([]tbcd.Peer, error) {
	log.Tracef("seed")
	defer log.Tracef("seed exit")

	peers, err := s.db.PeersRandom(pctx, peersWanted)
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
	var addrs []net.IP
	for k := range s.seeds {
		ips, err := resolver.LookupIP(ctx, "ip", s.seeds[k])
		if err != nil {
			log.Errorf("lookup: %v", err)
			errorsSeen++
			continue
		}
		addrs = append(addrs, ips...)
	}
	if errorsSeen == len(s.seeds) {
		return nil, errors.New("could not seed")
	}

	// insert into peers table
	for k := range addrs {
		peers = append(peers, tbcd.Peer{
			Host: addrs[k].String(),
			Port: s.port,
		})
	}

	// return fake peers but don't save them to the database
	return peers, nil
}

func (s *Server) seedForever(ctx context.Context, peersWanted int) ([]tbcd.Peer, error) {
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

func (s *Server) peerAdd(p *peer) {
	log.Tracef("peerAdd: %v", p.address)
	s.mtx.Lock()
	s.peers[p.address] = p
	s.mtx.Unlock()
}

func (s *Server) peerDelete(address string) {
	log.Tracef("peerDelete: %v", address)
	s.mtx.Lock()
	delete(s.peers, address)
	s.mtx.Unlock()
}

func (s *Server) peersLen() int {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return len(s.peers)
}

func (s *Server) peerManager(ctx context.Context) error {
	log.Tracef("peerManager")
	defer log.Tracef("peerManager exit")

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
				address := net.JoinHostPort(seeds[x].Host, seeds[x].Port)
				peer, err := NewPeer(s.wireNet, address)
				if err != nil {
					// This really should not happen
					log.Errorf("new peer: %v", err)
					continue
				}
				s.peerAdd(peer)

				go s.peerConnect(ctx, peerC, peer)

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
			log.Debugf("peer exited: %v blocks canceled: %v", address, n)
		case <-loopTicker.C:
			log.Debugf("pinging active peers: %v", s.peersLen())
			go s.pingAllPeers(ctx)
			loopTicker.Reset(loopTimeout)
		}
	}
}

func (s *Server) localPeerManager(ctx context.Context) error {
	log.Tracef("localPeerManager")
	defer log.Tracef("localPeerManager exit")

	if len(s.seeds) != 1 {
		return fmt.Errorf("expecting 1 seed, received %d", len(s.seeds))
	}

	peersWanted := 1
	peerC := make(chan string, peersWanted)
	address := net.JoinHostPort(s.seeds[0], s.port)
	peer, err := NewPeer(s.wireNet, address)
	if err != nil {
		return fmt.Errorf("new peer: %w", err)
	}

	log.Infof("Local peer manager connecting to %v peers", peersWanted)

	for {
		s.peerAdd(peer)
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

func (s *Server) startPeerManager(ctx context.Context) error {
	log.Tracef("startPeerManager")
	defer log.Tracef("startPeerManager exit")

	switch s.cfg.Network {
	case networkLocalnet:
		return s.localPeerManager(ctx)
	}
	return s.peerManager(ctx)
}

func (s *Server) pingExpired(key any, value any) {
	log.Tracef("pingExpired")
	defer log.Tracef("pingExpired exit")

	p, ok := value.(*peer)
	if !ok {
		log.Errorf("invalid ping expired type: %T", value)
		return
	}
	log.Debugf("pingExpired %v", key)
	if err := p.close(); err != nil {
		log.Errorf("ping %v: %v", key, err)
	}
}

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
		if p.conn == nil {
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
			log.Errorf("ping %v: %v", p, err)
		}

		// Record outstanding ping
		s.pings.Put(ctx, defaultPingTimeout, peer, p, s.pingExpired, nil)
	}
}

func (s *Server) peerConnect(ctx context.Context, peerC chan string, p *peer) {
	log.Tracef("peerConnect %v", p)
	defer func() {
		select {
		case peerC <- p.String():
		default:
			log.Tracef("could not signal peer channel: %v", p)
		}
		log.Tracef("peerConnect exit %v", p)
	}()

	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := p.connect(tctx)
	if err != nil {
		go func(pp *peer) {
			// Remove from database; it's ok to be aggressive if it
			// failed with no route to host or failed with i/o
			// timeout or invalid network (ipv4/ipv6).
			//
			// This does have the side-effect of draining the peer
			// table during network outages but that is ok. The
			// peers table will be rebuild based on DNS seeds.
			host, port, err := net.SplitHostPort(pp.String())
			if err != nil {
				log.Errorf("split host port: %v", err)
				return
			}
			if err = s.db.PeerDelete(ctx, host, port); err != nil {
				log.Errorf("peer delete (%v): %v", pp, err)
			} else {
				log.Debugf("Peer delete: %v", pp)
			}
		}(p)
		log.Debugf("connect: %v", err)
		return
	}
	defer func() {
		if err := p.close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorf("peer disconnect: %v %v", p, err)
		}
	}()

	_ = p.write(defaultCmdTimeout, wire.NewMsgSendHeaders()) // Ask peer to send headers
	_ = p.write(defaultCmdTimeout, wire.NewMsgGetAddr())     // Try to get network information

	log.Debugf("Peer connected: %v", p)

	// Pretend we are always in IBD.
	//
	// This obviously will put a pressure on the internet connection and
	// database because each and every peer is racing at start of day.  As
	// multiple answers come in the insert of the headers fails or
	// succeeds. If it fails no more headers will be requested from that
	// peer.
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		log.Errorf("block headers best: %v", err)
		// database is closed, nothing we can do, return here to avoid below
		// panic
		if errors.Is(err, leveldb.ErrClosed) {
			return
		}
	}
	log.Debugf("block header best hash: %s", bhb.Hash)

	if err = s.getHeaders(ctx, p, bhb.Header); err != nil {
		// This should not happen
		log.Errorf("get headers: %v", err)
		return
	}

	verbose := false
	for {
		// See if we were interrupted, for the love of pete add ctx to wire
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := p.read()
		if errors.Is(err, wire.ErrUnknownMessage) {
			// skip unknown
			continue
		} else if err != nil {
			log.Debugf("peer read %v: %v", p, err)
			return
		}

		if verbose {
			spew.Sdump(msg)
		}

		// Commands that are always accepted.
		switch m := msg.(type) {
		case *wire.MsgAddr:
			go s.handleAddr(ctx, p, m)
			continue

		case *wire.MsgAddrV2:
			go s.handleAddrV2(ctx, p, m)
			continue

		case *wire.MsgPing:
			go s.handlePing(ctx, p, m)
			continue

		case *wire.MsgPong:
			go s.handlePong(ctx, p, m)
			continue
		}

		// When quiesced do not handle other p2p commands.
		s.mtx.Lock()
		quiesced := s.quiesced
		s.mtx.Unlock()
		if quiesced {
			continue
		}

		switch m := msg.(type) {
		case *wire.MsgHeaders:
			go s.handleHeaders(ctx, p, m)

		case *wire.MsgBlock:
			go s.handleBlock(ctx, p, m)

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

// blocksMissing checks the block cache and the database and returns true if all
// blocks have not been downloaded.
func (s *Server) blocksMissing(ctx context.Context) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.blksMissing(ctx)
}

func (s *Server) handleAddr(ctx context.Context, p *peer, msg *wire.MsgAddr) {
	log.Tracef("handleAddr (%v): %v", p, len(msg.AddrList))
	defer log.Tracef("handleAddr exit (%v)", p)

	peers := make([]tbcd.Peer, 0, len(msg.AddrList))
	for k := range msg.AddrList {
		peers = append(peers, tbcd.Peer{
			Host: msg.AddrList[k].IP.String(),
			Port: strconv.Itoa(int(msg.AddrList[k].Port)),
		})
	}
	err := s.db.PeersInsert(ctx, peers)
	// Don't log insert 0, its a dup.
	if err != nil && !errors.Is(err, database.ErrZeroRows) {
		log.Errorf("%v", err)
	}
}

func (s *Server) handleAddrV2(ctx context.Context, p *peer, msg *wire.MsgAddrV2) {
	log.Tracef("handleAddrV2 (%v): %v", p, len(msg.AddrList))
	defer log.Tracef("handleAddrV2 exit (%v)", p)

	peers := make([]tbcd.Peer, 0, len(msg.AddrList))
	for k := range msg.AddrList {
		peers = append(peers, tbcd.Peer{
			Host: msg.AddrList[k].Addr.String(),
			Port: strconv.Itoa(int(msg.AddrList[k].Port)),
		})
	}
	err := s.db.PeersInsert(ctx, peers)
	// Don't log insert 0, its a dup.
	if err != nil && !errors.Is(err, database.ErrZeroRows) {
		log.Errorf("%v", err)
	}
}

func (s *Server) handlePing(ctx context.Context, p *peer, msg *wire.MsgPing) {
	log.Tracef("handlePing %v", p.address)
	defer log.Tracef("handlePing exit %v", p.address)

	pong := wire.NewMsgPong(msg.Nonce)
	err := p.write(defaultCmdTimeout, pong)
	if err != nil {
		log.Errorf("could not write pong message %v: %v", p.address, err)
		return
	}
	log.Tracef("handlePing %v: pong %v", p.address, pong.Nonce)
}

func (s *Server) handlePong(ctx context.Context, p *peer, pong *wire.MsgPong) {
	log.Tracef("handlePong %v", p.address)
	defer log.Tracef("handlePong exit %v", p.address)

	s.pings.Cancel(p.String())

	log.Tracef("handlePong %v: pong %v", p.address, pong.Nonce)
}

func (s *Server) downloadBlock(ctx context.Context, p *peer, ch *chainhash.Hash) {
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
		// peer dead, make sure it is reaped
		log.Errorf("write %v: %v", p, err)
		p.close()
	}
}

// blockExpired expires a block download and kills the peer.
func (s *Server) blockExpired(key any, value any) {
	log.Tracef("blockExpired")
	defer log.Tracef("blockExpired exit")

	p, ok := value.(*peer)
	if !ok {
		// this really should not happen
		log.Errorf("block expired no peer: %v", key)
		return
	}
	log.Infof("block expired %v: %v", p, key)

	p.close() // this will tear down peer
}

// randomPeer returns a random peer from the map. Must be called with lock
// held.
func (s *Server) randomPeer(ctx context.Context) (*peer, error) {
	log.Tracef("randomPeer")
	defer log.Tracef("randomPeer exit")

	// unassigned slot, download block
	for _, p := range s.peers {
		if p.conn == nil {
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
		// We can avoid quiescing by verifying if we are already done
		// indexing.
		if si := s.synced(ctx); si.Synced {
			log.Tracef("already synced at %v", si.BlockHeader)
			return
		}

		// Exit if AutoIndex isn't enabled.
		if !s.cfg.AutoIndex {
			return
		}

		bhb, err := s.db.BlockHeaderBest(ctx)
		if err != nil {
			log.Errorf("sync blocks best block header: %v", err)
			return
		}
		s.quiesced = true // XXX if it's set and we exit with an error, what should we do??
		go func() {
			// we really want to push the indexing reentrancy into this call
			log.Infof("quiescing p2p and indexing to: %v @ %v",
				bhb, bhb.Height)
			if err = s.SyncIndexersToHash(ctx, bhb.BlockHash()); err != nil {
				log.Errorf("sync blocks: %v", err)
				return
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

func (s *Server) handleHeaders(ctx context.Context, p *peer, msg *wire.MsgHeaders) {
	log.Tracef("handleHeaders (%v): %v", p, len(msg.Headers))
	defer log.Tracef("handleHeaders exit (%v): %v", p, len(msg.Headers))

	// s.mtx.Lock()
	// if s.clipped {
	//	log.Infof("pretend we are at the height")
	//	msg.Headers = msg.Headers[0:0]
	// }
	// s.mtx.Unlock()

	if len(msg.Headers) == 0 {
		// This may signify the end of IBD but isn't 100%. We can fart
		// around with mean block time to determine if this peer is
		// just behind or if we are nominally where we should be. This
		// test will never be 100% accurate.

		// s.mtx.Lock()
		// lastBH := s.lastBlockHeader.Timestamp()
		// s.mtx.Unlock()
		// if time.Since(lastBH) > 6*s.chainParams.TargetTimePerBlock {
		//	log.Infof("peer not synced: %v", p)
		//	p.close() // get rid of this peer
		//	return
		// }

		// only do this if peer is synced

		go s.syncBlocks(ctx)

		return
	}

	// This code works because duplicate blockheaders are rejected later on
	// but only after a somewhat expensive parameter setup and database
	// call.
	//
	// There really is no good way of determining if we can escape the
	// expensive calls so we just eat it.
	var pbhHash *chainhash.Hash
	headers := make([][80]byte, len(msg.Headers))
	for k := range msg.Headers {
		if pbhHash != nil && pbhHash.IsEqual(&msg.Headers[k].PrevBlock) {
			log.Errorf("cannot connect %v index %v",
				msg.Headers[k].PrevBlock, k)
			p.close() // get rid of this misbehaving peer
			return
		}

		copy(headers[k][0:80], h2b(msg.Headers[k])) // XXX don't double copy
		pbhHash = &msg.Headers[k].PrevBlock
	}

	if len(headers) > 0 {
		it, cbh, lbh, err := s.db.BlockHeadersInsert(ctx, headers)
		if err != nil {
			// This ends the race between peers during IBD.
			if !errors.Is(database.ErrDuplicate, err) {
				// XXX do we need to ask for more headers?
				log.Errorf("block headers insert: %v", err)
			}
			return
		}

		// Note that BlockHeadersInsert always returns the canonical
		// tip blockheader.
		var height uint64
		switch it {
		case tbcd.ITChainExtend:
			height = cbh.Height

			// Ask for next batch of headers at canonical tip.
			if err = s.getHeaders(ctx, p, cbh.Header); err != nil {
				log.Errorf("get headers: %v", err)
				return
			}

		case tbcd.ITForkExtend:
			height = lbh.Height

			// Ask for more block headers at the fork tip.
			if err = s.getHeaders(ctx, p, lbh.Header); err != nil {
				log.Errorf("get headers fork: %v", err)
				return
			}

			// Also ask for more block headers at canonical tip
			if err = s.getHeaders(ctx, p, cbh.Header); err != nil {
				log.Errorf("get headers canonical: %v", err)
				return
			}

		case tbcd.ITChainFork:
			height = cbh.Height

			if s.Synced(ctx).Synced {
				// XXX this is racy but is a good enough test
				// to get past most of this.
				panic("chain forked, unwind/rewind indexes")
			}

			// Ask for more block headers at the fork tip.
			if err = s.getHeaders(ctx, p, lbh.Header); err != nil {
				log.Errorf("get headers fork: %v", err)
				return
			}

			// Also ask for more block headers at canonical tip
			if err = s.getHeaders(ctx, p, cbh.Header); err != nil {
				log.Errorf("get headers canonical: %v", err)
				return
			}

		default:
			// XXX can't happen
			log.Errorf("invalid insert type: %d", it)
			return
		}

		// XXX we probably don't want top print it
		log.Infof("Inserted (%v) %v block headers height %v",
			it, len(headers), height)

		// s.mtx.Lock()
		// s.clipped = true
		// s.mtx.Unlock()
		// log.Infof("clipped at %v", lbh.Height)
	}
}

func (s *Server) handleBlock(ctx context.Context, p *peer, msg *wire.MsgBlock) {
	log.Tracef("handleBlock (%v)", p)
	defer log.Tracef("handleBlock exit (%v)", p)

	block := btcutil.NewBlock(msg)
	bhs := block.Hash().String()
	bb, err := block.Bytes() // XXX we should not being doing this twice but requires a modification to the wire package
	if err != nil {
		log.Errorf("block bytes %v: %v", block.Hash(), err)
		return
	}
	b := &tbcd.Block{
		Hash:  sliceChainHash(*block.Hash()),
		Block: bb,
	}

	if s.cfg.BlockSanity {
		err = blockchain.CheckBlockSanity(block, s.chainParams.PowLimit,
			s.timeSource)
		if err != nil {
			log.Errorf("Unable to validate block hash %v: %v", bhs, err)
			return
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

	height, err := s.db.BlockInsert(ctx, b)
	if err != nil {
		log.Errorf("block insert %v: %v", bhs, err)
	} else {
		log.Infof("Insert block %v at %v txs %v %v", bhs, height,
			len(msg.Transactions), msg.Header.Timestamp)
	}

	// Whatever happens, delete from cache and potentially try again
	log.Infof("inserted block at height %d, parent hash %s", height, block.MsgBlock().Header.PrevBlock)
	var (
		printStats      bool
		blocksSize      uint64
		blocksInserted  int
		blocksDuplicate int // keep track of this until have less of them
		delta           time.Duration

		// blocks pending
		blocksPending int

		// peers
		goodPeers      int
		badPeers       int
		activePeers    int
		connectedPeers int
	)
	// XXX do we need these? s.mtx.Lock()
	// XXX rethink lock here
	s.mtx.Lock()
	s.blocks.Delete(bhs) // remove block from cache regardless of insert result

	// Stats
	if err == nil {
		s.blocksSize += uint64(len(b.Block) + len(b.Hash))
		if _, ok := s.blocksInserted[bhs]; ok {
			s.blocksDuplicate++
		} else {
			s.blocksInserted[bhs] = struct{}{}
		}
	}
	now := time.Now()
	if now.After(s.printTime) {
		printStats = true

		blocksSize = s.blocksSize
		blocksInserted = len(s.blocksInserted)
		blocksDuplicate = s.blocksDuplicate
		// This is super awkward but prevents calculating N inserts *
		// time.Before(10*time.Second).
		delta = now.Sub(s.printTime.Add(-10 * time.Second))

		s.blocksSize = 0
		s.blocksInserted = make(map[string]struct{}, 8192)
		s.blocksDuplicate = 0
		s.printTime = now.Add(10 * time.Second)

		// Grab pending block cache stats
		blocksPending = s.blocks.Len()

		// Grab some peer stats as well
		activePeers = len(s.peers)
		goodPeers, badPeers = s.db.PeersStats(ctx)
		// Gonna take it right into the Danger Zone! (double mutex)
		for _, peer := range s.peers {
			if peer.isConnected() {
				connectedPeers++
			}
		}
	}
	s.mtx.Unlock()

	if printStats {
		// XXX this counts errors somehow after ibd, probably because
		// duplicate blocks are downloaded when an inv comes in.
		log.Infof("Inserted %v blocks (%v, %v duplicates) in the last %v",
			blocksInserted, humanize.Bytes(blocksSize), blocksDuplicate, delta)
		log.Infof("Pending blocks %v/%v active peers %v connected peers %v "+
			"good peers %v bad peers %v",
			blocksPending, defaultPendingBlocks, activePeers, connectedPeers,
			goodPeers, badPeers)
	}

	// kick cache
	go s.syncBlocks(ctx)
}

func (s *Server) insertGenesis(ctx context.Context) error {
	log.Tracef("insertGenesis")
	defer log.Tracef("insertGenesis exit")

	// We really should be inserting the block first but block insert
	// verifies that a block header exists.
	log.Infof("Inserting genesis block and header: %v", s.chainParams.GenesisHash)
	gbh, err := header2Array(&s.chainParams.GenesisBlock.Header)
	if err != nil {
		return fmt.Errorf("serialize genesis block header: %w", err)
	}
	if err = s.db.BlockHeaderGenesisInsert(ctx, gbh); err != nil {
		return fmt.Errorf("genesis block header insert: %w", err)
	}

	log.Debugf("Inserting genesis block")
	gb, err := btcutil.NewBlock(s.chainParams.GenesisBlock).Bytes()
	if err != nil {
		return fmt.Errorf("genesis block encode: %w", err)
	}
	_, err = s.db.BlockInsert(ctx, &tbcd.Block{
		Hash:  s.chainParams.GenesisHash[:],
		Block: gb,
	})
	if err != nil {
		return fmt.Errorf("genesis block insert: %w", err)
	}

	return nil
}

//

func (s *Server) BlockHeaderByHash(ctx context.Context, hash *chainhash.Hash) (*wire.BlockHeader, uint64, error) {
	log.Tracef("BlockHeaderByHash")
	defer log.Tracef("BlockHeaderByHash exit")

	bh, err := s.db.BlockHeaderByHash(ctx, hash[:])
	if err != nil {
		return nil, 0, fmt.Errorf("db block header by hash: %w", err)
	}
	bhw, err := bytes2Header(bh.Header)
	if err != nil {
		return nil, 0, fmt.Errorf("bytes to header: %w", err)
	}
	return bhw, bh.Height, nil
}

func (s *Server) blockHeadersByHeight(ctx context.Context, height uint64) ([]tbcd.BlockHeader, error) {
	log.Tracef("blockHeadersByHeight")
	defer log.Tracef("blockHeadersByHeight exit")

	bhs, err := s.db.BlockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("db block header by height: %w", err)
	}

	return bhs, nil
}

func (s *Server) RawBlockHeadersByHeight(ctx context.Context, height uint64) ([]api.ByteSlice, error) {
	log.Tracef("RawBlockHeadersByHeight")
	defer log.Tracef("RawBlockHeadersByHeight exit")

	bhs, err := s.blockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, err
	}

	var headers []api.ByteSlice
	for _, bh := range bhs {
		headers = append(headers, []byte(bh.Header))
	}

	return headers, nil
}

func (s *Server) BlockHeadersByHeight(ctx context.Context, height uint64) ([]*wire.BlockHeader, error) {
	log.Tracef("BlockHeadersByHeight")
	defer log.Tracef("BlockHeadersByHeight exit")

	blockHeaders, err := s.blockHeadersByHeight(ctx, height)
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
	return bhb.Height, api.ByteSlice(bhb.Header[:]), nil
}

func (s *Server) DifficultyAtHash(ctx context.Context, hash *chainhash.Hash) (*big.Int, error) {
	log.Tracef("DifficultyAtHash")
	defer log.Tracef("DifficultyAtHash exit")

	blockHeader, err := s.db.BlockHeaderByHash(ctx, hash[:])
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
	wbh, err := bytes2Header(blockHeader.Header)
	return blockHeader.Height, wbh, err
}

func (s *Server) BalanceByAddress(ctx context.Context, encodedAddress string) (uint64, error) {
	addr, err := btcutil.DecodeAddress(encodedAddress, s.chainParams)
	if err != nil {
		return 0, err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return 0, err
	}

	balance, err := s.db.BalanceByScriptHash(ctx, sha256.Sum256(script))
	if err != nil {
		return 0, err
	}

	return balance, nil
}

func (s *Server) UtxosByAddress(ctx context.Context, encodedAddress string, start uint64, count uint64) ([]tbcd.Utxo, error) {
	addr, err := btcutil.DecodeAddress(encodedAddress, s.chainParams)
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	scriptHash := sha256.Sum256(script)

	utxos, err := s.db.UtxosByScriptHash(ctx, scriptHash, start, count)
	if err != nil {
		return nil, err
	}
	return utxos, nil
}

func (s *Server) TxById(ctx context.Context, txId tbcd.TxId) (*wire.MsgTx, error) {
	blockHashes, err := s.db.BlocksByTxId(ctx, txId)
	if err != nil {
		return nil, err
	}

	// chain hash stores the bytes in reverse order
	revTxId := bytes.Clone(txId[:])
	slices.Reverse(revTxId)
	ch, err := chainhash.NewHashFromStr(hex.EncodeToString(revTxId[:]))
	if err != nil {
		return nil, err
	}

	for _, blockHash := range blockHashes {
		block, err := s.db.BlockByHash(ctx, blockHash[:])
		if err != nil {
			return nil, err
		}

		parsedBlock, err := btcutil.NewBlockFromBytes(block.Block)
		if err != nil {
			return nil, err
		}

		for _, tx := range parsedBlock.Transactions() {
			if tx.Hash().IsEqual(ch) {
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
		be, err := s.db.BlockByHash(ctx, bhs[0].Hash)
		if err != nil {
			return 0, fmt.Errorf("block by hash: %w", err)
		}
		b, err := btcutil.NewBlockFromBytes(be.Block)
		if err != nil {
			ch, _ := chainhash.NewHash(bhs[0].Hash)
			return 0, fmt.Errorf("could not decode block %v %v: %v",
				height, ch, err)
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
	// BlockHeaderHeight uint64 // last block header height
	// UtxoHeight        uint64 // last indexed utxo block height
	// TxHeight          uint64 // last indexed tx block height
}

func (s *Server) synced(ctx context.Context) (si SyncInfo) {
	// These values are cached in leveldb so it is ok to call with mutex
	// held.
	//
	// Note that index heights are start indexing values thus they are off
	// by one from the last block height seen.
	bhb, err := s.db.BlockHeaderBest(ctx)
	if err != nil {
		panic(err)
	}
	bhHash, err := chainhash.NewHash(bhb.Hash)
	if err != nil {
		panic(err)
	}
	// Ensure we have genesis or the Synced flag will be true if metadata
	// does not exist.
	if zeroHash.IsEqual(bhHash) {
		panic("no genesis")
	}
	si.BlockHeader.Hash = *bhHash
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

	if utxoHH.Hash.IsEqual(bhHash) && txHH.Hash.IsEqual(bhHash) &&
		!s.blksMissing(ctx) {
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
	s.db, err = level.New(ctx, filepath.Join(s.cfg.LevelDBHome, s.cfg.Network))
	if err != nil {
		return fmt.Errorf("open level database: %w", err)
	}

	return nil
}

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
			return fmt.Errorf("block headers best: %w", err)
		}

		if err = s.insertGenesis(ctx); err != nil {
			return fmt.Errorf("insert genesis: %w", err)
		}
		bhb, err = s.db.BlockHeaderBest(ctx)
		if err != nil {
			return err
		}
	}
	log.Infof("Starting block headers sync at height: %v time %v",
		bhb.Height, bhb.Timestamp())

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
