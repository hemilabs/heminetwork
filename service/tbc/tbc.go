// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
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

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/service/deucalion"
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
)

var (
	localnetSeeds = []string{
		"localhost",
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
	rand.Seed(time.Now().UnixNano()) // used for seeding, ok to be math.rand
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

func header2Bytes(wbh *wire.BlockHeader) ([]byte, error) {
	var b bytes.Buffer
	err := wbh.Serialize(&b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func h2b(wbh *wire.BlockHeader) []byte {
	hb, err := header2Bytes(wbh)
	if err != nil {
		panic(err)
	}
	return hb
}

func bytes2Header(header []byte) (*wire.BlockHeader, error) {
	var bh wire.BlockHeader
	err := bh.Deserialize(bytes.NewReader(header))
	if err != nil {
		return nil, fmt.Errorf("Deserialize: %v", err)
	}
	return &bh, nil
}

func headerTime(header []byte) *time.Time {
	h, err := bytes2Header(header)
	if err != nil {
		return nil
	}
	return &h.Timestamp
}

func hashEqual(h1 chainhash.Hash, h2 chainhash.Hash) bool {
	// Fuck you chainhash package
	return h1.IsEqual(&h2)
}

func sliceChainHash(ch chainhash.Hash) []byte {
	// Fuck you chainhash package
	return ch[:]
}

type blockPeer struct {
	expire time.Time // when does this command expire
	peer   string    // who was handling it
}

type Config struct {
	LevelDBHome             string
	ListenAddress           string
	LogLevel                string
	PgURI                   string
	PrometheusListenAddress string
	Network                 string
	BlockSanity             bool
	ForceSeedPort           string
	MaxCachedTxs            int
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenAddress: tbcapi.DefaultListen,
		LogLevel:      logLevel,
		MaxCachedTxs:  defaultMaxCachedTxs,
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

	peers  map[string]*peer      // active but not necessarily connected
	blocks map[string]*blockPeer // outstanding block downloads [hash]when/where

	// IBD hints
	lastBlockHeader tbcd.BlockHeader

	// reentrancy flags for the indexers
	utxoIndexerRunning bool
	txIndexerRunning   bool

	db tbcd.Database

	// Prometheus
	isRunning     bool
	cmdsProcessed prometheus.Counter

	// WebSockets
	sessions map[string]*tbcWs
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg:            cfg,
		printTime:      time.Now().Add(10 * time.Second),
		blocks:         make(map[string]*blockPeer, defaultPendingBlocks),
		peers:          make(map[string]*peer, defaultPeersWanted),
		blocksInserted: make(map[string]struct{}, 8192), // stats
		timeSource:     blockchain.NewMedianTime(),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: promSubsystem,
			Name:      "rpc_calls_total",
			Help:      "The total number of successful RPC commands",
		}),
		sessions: make(map[string]*tbcWs),
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
		if s.cfg.ForceSeedPort != "" {
			s.port = s.cfg.ForceSeedPort
		} else {
			s.port = localnetPort
		}
		s.wireNet = wire.TestNet
		s.chainParams = &chaincfg.RegressionNetParams
		s.seeds = localnetSeeds
	default:
		return nil, fmt.Errorf("invalid network: %v", cfg.Network)
	}

	return s, nil
}

// DB exports the underlying database. This should only be used in tests.
func (s *Server) DB() tbcd.Database {
	return s.db
}

// blockPeerExpire removes expired block downloads from the cache and returns
// the number of used cache slots. Lock must be held.
func (s *Server) blockPeerExpire() int {
	log.Tracef("blockPeerExpire exit")
	defer log.Tracef("blockPeerExpire exit")

	now := time.Now()
	for k, v := range s.blocks {
		if v == nil {
			// not assigned a peer yet
			continue
		}
		if !now.After(v.expire) {
			continue
		}

		// mark block as unassigned but do not give up cache slot
		s.blocks[k] = nil
		log.Infof("expired block: %v", k) // XXX maybe remove but add to stats

		// kill peer as well since it is slow
		if p := s.peers[v.peer]; p != nil && p.conn != nil {
			p.conn.Close() // this will tear down peer
		}
	}
	return len(s.blocks)
}

func (s *Server) getHeaders(ctx context.Context, p *peer, lastHeaderHash []byte) error {
	bh, err := bytes2Header(lastHeaderHash)
	if err != nil {
		return fmt.Errorf("invalid header: %v", err)
	}
	hash := bh.BlockHash()
	ghs := wire.NewMsgGetHeaders()
	ghs.AddBlockLocatorHash(&hash)
	err = p.write(ghs)
	if err != nil {
		return fmt.Errorf("write get headers: %v", err)
	}

	return nil
}

func (s *Server) seed(pctx context.Context, peersWanted int) ([]tbcd.Peer, error) {
	log.Tracef("seed")
	defer log.Tracef("seed exit")

	peers, err := s.db.PeersRandom(pctx, peersWanted)
	if err != nil {
		return nil, fmt.Errorf("peers random: %v", err)
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
		log.Infof("DNS seeding %v", s.seeds[k])
		// XXX localhost ipv4 and ipv6 is invalid in p2p.Add a
		// localhost mode to peermanager.
		if s.seeds[k] == "localhost" {
			log.Infof("seed is localhost, using 127.0.0.1")
			addrs = append(addrs, net.IPv4(127, 0, 0, 1))
		} else {
			ips, err := resolver.LookupIP(ctx, "ip", s.seeds[k])
			if err != nil {
				log.Errorf("lookup: %v", err)
				errorsSeen++
				continue
			}
			addrs = append(addrs, ips...)
		}
	}
	if errorsSeen == len(s.seeds) {
		return nil, fmt.Errorf("could not seed")
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
		holdOff := time.Duration(minW+rand.Intn(maxW-minW)) * time.Second
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
	peersWanted := defaultPeersWanted
	peerC := make(chan string, peersWanted)

	log.Infof("Peer manager connecting to %v peers", peersWanted)
	seeds, err := s.seedForever(ctx, peersWanted)
	if err != nil {
		// context canceled
		return fmt.Errorf("seed: %w", err)
	}
	if len(seeds) == 0 {
		// should not happen
		return fmt.Errorf("no seeds found")
	}

	// Add a ticker that times out every 27 seconds regardless of what is
	// going on. This will be nice and jittery and detect bad beers
	// peridiocally.
	loopTimeout := 27 * time.Second
	loopTicker := time.NewTicker(loopTimeout)

	x := 0
	for {
		peersActive := s.peersLen()
		log.Debugf("peerManager active %v wanted %v", peersActive, peersWanted)
		if peersActive < peersWanted {
			// XXX we may want to make peers play along with waitgroup

			// Connect peer
			for i := 0; i < peersWanted-peersActive; i++ {
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
						return fmt.Errorf("no seeds found")
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
			log.Debugf("peer exited: %v", address)
		case <-loopTicker.C:
			log.Debugf("pinging active peers: %v", s.peersLen())
			go s.pingAllPeers(ctx)
			loopTicker.Reset(loopTimeout)
		}
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

		// We don't really care about the response. We just want to
		// write to the connection to make it fail if the other side
		// went away.
		log.Debugf("Pinging: %v", p)
		err := p.write(wire.NewMsgPing(uint64(time.Now().Unix())))
		if err != nil {
			log.Errorf("ping %v: %v", p, err)
		}
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
			err = s.db.PeerDelete(ctx, host, port)
			if err != nil {
				log.Errorf("peer delete (%v): %v", pp, err)
			} else {
				log.Debugf("Peer delete: %v", pp)
			}
		}(p)
		log.Debugf("connect: %v", err)
		return
	}
	defer func() {
		err := p.close()
		if err != nil {
			log.Errorf("peer disconnect: %v %v", p, err)
		}
	}()

	_ = p.write(wire.NewMsgSendHeaders()) // Ask peer to send headers
	_ = p.write(wire.NewMsgGetAddr())     // Try to get network information

	log.Debugf("Peer connected: %v", p)

	// Pretend we are always in IBD.
	//
	// This obviously will put a pressure on the internet connection and
	// database because each and every peer is racing at start of day.  As
	// multiple answers come in the insert of the headers fails or
	// succeeds. If it fails no more headers will be requested from that
	// peer.
	bhs, err := s.db.BlockHeadersBest(ctx)
	if err != nil {
		log.Errorf("block headers best: %v", err)
	}
	if len(bhs) != 1 {
		// XXX fix multiple tips
		panic(len(bhs))
	}
	log.Debugf("block header best hash: %s", bhs[0].Hash)

	err = s.getHeaders(ctx, p, bhs[0].Header)
	if err != nil {
		// This should not happen
		log.Errorf("get headers: %v", err)
		return
	}

	// XXX kickstart block download, should happen in getHeaders

	verbose := false
	for {
		// See if we were interrupted, for the love of pete add ctx to wire
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := p.read()
		if err == wire.ErrUnknownMessage {
			// skip unknown
			continue
		} else if err != nil {
			// reevaluate pending blocks cache
			log.Debugf("peer read %v: %v", p, err)
			go s.syncBlocks(ctx)
			return
		}

		if verbose {
			spew.Dump(msg)
		}

		// XXX send wire message to pool reader
		switch m := msg.(type) {
		case *wire.MsgAddr:
			go s.handleAddr(ctx, p, m)

		case *wire.MsgAddrV2:
			go s.handleAddrV2(ctx, p, m)

		case *wire.MsgBlock:
			go s.handleBlock(ctx, p, m)

		case *wire.MsgFeeFilter:
			// XXX shut up

		case *wire.MsgInv:
			go s.handleInv(ctx, p, m)

		case *wire.MsgHeaders:
			go s.handleHeaders(ctx, p, m)

		case *wire.MsgPing:
			go s.handlePing(ctx, p, m)
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

func (s *Server) blocksMissing(ctx context.Context) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Do cheap memory check first
	if len(s.blocks) != 0 {
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
	if err != nil && !database.ErrZeroRows.Is(err) {
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
	if err != nil && !database.ErrZeroRows.Is(err) {
		log.Errorf("%v", err)
	}
}

func (s *Server) handlePing(ctx context.Context, p *peer, msg *wire.MsgPing) {
	log.Tracef("handlePing %v", p.address)
	defer log.Tracef("handlePing exit %v", p.address)

	pong := wire.NewMsgPong(msg.Nonce)
	err := p.write(pong)
	if err != nil {
		log.Errorf("could not write pong message %v: %v", p.address, err)
		return
	}
	log.Tracef("handlePing %v: pong %v", p.address, pong.Nonce)
}

func (s *Server) handleInv(ctx context.Context, p *peer, msg *wire.MsgInv) {
	log.Tracef("handleInv (%v)", p)
	defer log.Tracef("handleInv exit (%v)", p)

	var bis []tbcd.BlockIdentifier
	for k := range msg.InvList {
		switch msg.InvList[k].Type {
		case wire.InvTypeBlock:

			// XXX height is missing here, looks right but assert
			// that this isn't broken.
			log.Infof("handleInv: block %v", msg.InvList[k].Hash)

			bis = append(bis, tbcd.BlockIdentifier{
				Hash: msg.InvList[k].Hash[:], // fake out
			})
			log.Infof("handleInv: block %v", msg.InvList[k].Hash)
		case wire.InvTypeTx:
			// XXX silence mempool for now
			return
		default:
			log.Infof("handleInv: skipping inv type %v", msg.InvList[k].Type)
			return
		}
	}

	// XXX This happens during block header download, we should not react
	// Probably move into the invtype switch
	log.Infof("download blocks if we like them")
	//if len(bis) > 0 {
	//	s.mtx.Lock()
	//	defer s.mtx.Unlock()
	//	err := s.downloadBlocks(ctx, bis)
	//	if err != nil {
	//		log.Errorf("download blocks: %v", err)
	//		return
	//	}
	//}
}

func (s *Server) txIndexer(ctx context.Context) {
	log.Tracef("txIndexer")
	defer log.Tracef("txIndexer exit")

	// only one txIndexer may run at any given time
	s.mtx.Lock()
	if s.txIndexerRunning {
		s.mtx.Unlock()
		return
	}
	s.txIndexerRunning = true
	s.mtx.Unlock()

	// mark txIndexer not running on exit
	defer func() {
		s.mtx.Lock()
		s.txIndexerRunning = false
		s.mtx.Unlock()
	}()

	if s.blocksMissing(ctx) {
		return
	}

	// Get height from db
	he, err := s.db.MetadataGet(ctx, TxIndexHeightKey)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			log.Errorf("tx indexer metadata get: %v", err)
			return
		}
		he = make([]byte, 8)
	}
	h := binary.BigEndian.Uint64(he)

	// Skip txIndexer if we are at best block height. This is a bit racy.
	bhs, err := s.db.BlockHeadersBest(ctx)
	if err != nil {
		log.Errorf("utxo indexer block headers best: %v", err)
		return
	}
	if len(bhs) != 1 {
		log.Errorf("utxo indexer block headers best: unsuported fork")
		return
	}

	if h < bhs[0].Height {
		err = s.TxIndexer(ctx, h, 0)
		if err != nil {
			log.Errorf("tx indexer: %v", err)
			return
		}
	}
}

func (s *Server) utxoIndexer(ctx context.Context) {
	log.Tracef("utxoIndexer")
	defer log.Tracef("utxoIndexer exit")

	// only one utxoIndexer may run at any given time
	s.mtx.Lock()
	if s.utxoIndexerRunning {
		s.mtx.Unlock()
		return
	}
	s.utxoIndexerRunning = true
	s.mtx.Unlock()

	// mark utxoIndexer not running on exit
	defer func() {
		s.mtx.Lock()
		s.utxoIndexerRunning = false
		s.mtx.Unlock()
	}()

	// exit if we aren't synced
	if s.blocksMissing(ctx) {
		return
	}

	// Index all utxos

	// Get height from db
	he, err := s.db.MetadataGet(ctx, UtxoIndexHeightKey)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			log.Errorf("utxo indexer metadata get: %v", err)
			return
		}
		he = make([]byte, 8)
	}
	h := binary.BigEndian.Uint64(he)

	// Skip UtxoIndex if we are at best block height. This is a bit racy.
	bhs, err := s.db.BlockHeadersBest(ctx)
	if err != nil {
		log.Errorf("utxo indexer block headers best: %v", err)
		return
	}
	if len(bhs) != 1 {
		log.Errorf("utxo indexer block headers best: unsuported fork")
		return
	}

	if h < bhs[0].Height {
		err = s.UtxoIndexer(ctx, h, 0)
		if err != nil {
			log.Errorf("utxo indexer: %v", err)
			return
		}
	}

	// When utxo sync completes kick off tx sync
	go s.txIndexer(ctx)
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
	err := p.write(getData)
	if err != nil {
		// peer dead, make sure it is reaped
		log.Errorf("write %v: %v", p, err)
		p.close()
	}
}

func (s *Server) downloadBlocks(ctx context.Context) {
	log.Tracef("downloadBlocks")
	defer log.Tracef("downloadBlocks exit")

	now := time.Now()

	defer func() {
		// if we are complete we need to kick off utxo sync
		go s.utxoIndexer(ctx)
	}()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	for k, v := range s.blocks {
		if v != nil && now.After(v.expire) {
			// kill peer as well since it is slow
			if p := s.peers[v.peer]; p != nil && p.conn != nil {
				p.conn.Close() // this will tear down peer
			}

			// block expired, download block
			s.blocks[k] = nil
			v = nil // this will redownload the block
		}
		if v != nil {
			// block already being downloaded and is not expired
			continue
		}
		// unassigned slot, download block
		for _, peer := range s.peers {
			if peer.conn == nil {
				// Not connected yet
				continue
			}
			ch, err := chainhash.NewHashFromStr(k)
			if err != nil {
				// really should not happen
				log.Errorf("download blocks hash: %v", err)
				delete(s.blocks, k)
				continue
			}

			// sufficiently validated, record in cache
			s.blocks[k] = &blockPeer{
				expire: time.Now().Add(37 * time.Second), // XXX make variable?
				peer:   peer.String(),
			}

			go s.downloadBlock(ctx, peer, ch)

			break
		}
	}
}

func (s *Server) syncBlocks(ctx context.Context) {
	log.Tracef("syncBlocks")
	defer log.Tracef("syncBlocks exit")

	// regardless of cache being full or no more missing blocks kick the
	// downloader just to make sure we are making forward progress.
	defer func() {
		go s.downloadBlocks(ctx)
	}()

	// Hold lock to fill blocks cache
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Deal with expired block downloads
	used := s.blockPeerExpire()
	want := defaultPendingBlocks - used
	if want <= 0 {
		return
	}

	bm, err := s.db.BlocksMissing(ctx, want)
	if err != nil {
		log.Errorf("blocks missing: %v", err)
		return
	}
	for k := range bm {
		bi := bm[k]
		hash, _ := chainhash.NewHash(bi.Hash[:])
		hashS := hash.String()
		if _, ok := s.blocks[hashS]; ok {
			continue
		}
		s.blocks[hashS] = nil // pending block
	}
}

func (s *Server) handleHeaders(ctx context.Context, p *peer, msg *wire.MsgHeaders) {
	log.Tracef("handleHeaders %v", p)
	defer log.Tracef("handleHeaders exit %v", p)

	log.Debugf("handleHeaders (%v): %v", p, len(msg.Headers))

	if len(msg.Headers) == 0 {
		// This may signify the end of IBD but isn't 100%. We can fart
		// around with mean block time to determine if this peer is
		// just behind or if we are nominally where we should be. This
		// test will never be 100% accurate.

		s.mtx.Lock()
		lastBH := s.lastBlockHeader.Timestamp()
		s.mtx.Unlock()
		if time.Now().Sub(lastBH) > 6*s.chainParams.TargetTimePerBlock {
			log.Infof("peer not synced: %v", p)
			return
		}

		go s.syncBlocks(ctx)

		return
	}

	// This code works because duplicate blockheaders are rejected later on
	// but only after a somewhat expensive parameter setup and database
	// call.
	//
	// There really is no good way of determining if we can escape the
	// expensive calls so we just eat it.

	// Make sure we can connect these headers in database
	dbpbh, err := s.db.BlockHeaderByHash(ctx, msg.Headers[0].PrevBlock[:])
	if err != nil {
		log.Errorf("handle headers no previous block header: %v",
			msg.Headers[0].BlockHash())
		return
	}
	pbh, err := bytes2Header(dbpbh.Header)
	if err != nil {
		log.Errorf("invalid block header: %v", err)
		return
	}

	// Construct insert list and nominally validate headers
	headers := make([]tbcd.BlockHeader, 0, len(msg.Headers))
	height := dbpbh.Height + 1
	for k := range msg.Headers {
		if !hashEqual(msg.Headers[k].PrevBlock, pbh.BlockHash()) {
			log.Errorf("cannot connect %v at height %v",
				msg.Headers[k].PrevBlock, height)
			return
		}

		headers = append(headers, tbcd.BlockHeader{
			Hash:   sliceChainHash(msg.Headers[k].BlockHash()),
			Height: height,
			Header: h2b(msg.Headers[k]),
		})

		pbh = msg.Headers[k]
		height++
	}

	if len(headers) > 0 {
		err := s.db.BlockHeadersInsert(ctx, headers)
		if err != nil {
			// This ends the race between peers during IBD.
			if !database.ErrDuplicate.Is(err) {
				log.Errorf("block headers insert: %v", err)
			}
			return
		}

		// If we get here try to store the last blockheader that was
		// inserted. This may race so we have to take the mutex and
		// check height.
		lbh := headers[len(headers)-1]

		s.mtx.Lock()
		if lbh.Height > s.lastBlockHeader.Height {
			s.lastBlockHeader = lbh
		}
		s.mtx.Unlock()

		log.Infof("Inserted %v block headers height %v",
			len(headers), lbh.Height)

		// Ask for next batch of headers
		err = s.getHeaders(ctx, p, lbh.Header)
		if err != nil {
			log.Errorf("get headers: %v", err)
			return
		}
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

	// Whatever happens,, delete from cache and potentially try again
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
	s.mtx.Lock()
	delete(s.blocks, bhs) // remove block from cache regardless of insert result

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
		blocksPending = len(s.blocks)

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

func (s *Server) insertGenesis(ctx context.Context) ([]tbcd.BlockHeader, error) {
	log.Tracef("insertGenesis")
	defer log.Tracef("insertGenesis exit")

	// We really should be inserting the block first but block insert
	// verifies that a block header exists.
	log.Infof("Inserting genesis block and header: %v", s.chainParams.GenesisHash)
	gbh, err := header2Bytes(&s.chainParams.GenesisBlock.Header)
	if err != nil {
		return nil, fmt.Errorf("serialize genesis block header: %v", err)
	}

	genesisBlockHeader := &tbcd.BlockHeader{
		Height: 0,
		Hash:   s.chainParams.GenesisHash[:],
		Header: gbh,
	}
	err = s.db.BlockHeadersInsert(ctx, []tbcd.BlockHeader{*genesisBlockHeader})
	if err != nil {
		return nil, fmt.Errorf("genesis block header insert: %v", err)
	}

	log.Debugf("Inserting genesis block")
	gb, err := btcutil.NewBlock(s.chainParams.GenesisBlock).Bytes()
	if err != nil {
		return nil, fmt.Errorf("genesis block encode: %v", err)
	}
	_, err = s.db.BlockInsert(ctx, &tbcd.Block{
		Hash:  s.chainParams.GenesisHash[:],
		Block: gb,
	})
	if err != nil {
		return nil, fmt.Errorf("genesis block insert: %v", err)
	}

	return []tbcd.BlockHeader{*genesisBlockHeader}, nil
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

func (s *Server) BlockHeadersByHeight(ctx context.Context, height uint64) ([]wire.BlockHeader, error) {
	log.Tracef("BlockHeadersByHeight")
	defer log.Tracef("BlockHeadersByHeight exit")

	bhs, err := s.blockHeadersByHeight(ctx, height)
	if err != nil {
		return nil, err
	}

	bhsw := make([]wire.BlockHeader, 0, len(bhs))
	for k := range bhs {
		bhw, err := bytes2Header(bhs[k].Header)
		if err != nil {
			return nil, fmt.Errorf("bytes to header: %w", err)
		}
		bhsw = append(bhsw, *bhw)
	}
	return bhsw, nil
}

// BlockHeadersBest returns the headers for the best known blocks.
func (s *Server) BlockHeadersBest(ctx context.Context) (uint64, []wire.BlockHeader, error) {
	log.Tracef("LastBlockMetadata")
	defer log.Tracef("LastBlockMetadata exit")

	bhs, err := s.db.BlockHeadersBest(ctx)
	if err != nil {
		return 0, nil, err
	}

	var height uint64
	if len(bhs) > 0 {
		height = bhs[0].Height
	}

	bhsw := make([]wire.BlockHeader, 0, len(bhs))
	for k := range bhs {
		bhw, err := bytes2Header(bhs[k].Header)
		if err != nil {
			return 0, nil, fmt.Errorf("bytes to header: %w", err)
		}
		bhsw = append(bhsw, *bhw)
	}

	return height, bhsw, nil
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

	scriptHash := sha256.Sum256(script)

	balance, err := s.db.BalanceByScriptHash(ctx, scriptHash)
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

	return nil, errors.New("tx not found")
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
		return 0, fmt.Errorf("height - count is less than 0")
	}
	var fees uint64
	for i := int64(0); i < int64(count); i++ {
		log.Infof("%v", uint64(height-i))
		bhs, err := s.db.BlockHeadersByHeight(ctx, uint64(height-i))
		if err != nil {
			return 0, fmt.Errorf("headers by height: %w", err)
		}
		if len(bhs) != 1 {
			return 0, fmt.Errorf("too many block headers: %v", len(bhs))
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
		err = feesFromTransactions(b.Transactions())
		if err != nil {
			return 0, fmt.Errorf("fees from transactions %v %v: %v",
				height, b.Hash(), err)
		}
	}

	return fees, fmt.Errorf("not yet")
}

// DBOpen opens the underlying server database. It has been put in its own
// function to make it available during tests and hemictl.
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
		return fmt.Errorf("open level database: %v", err)
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
		return fmt.Errorf("tbc already running")
	}
	defer s.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	err := s.DBOpen(ctx)
	if err != nil {
		return fmt.Errorf("Failed to open level database: %w", err)
	}
	defer func() {
		err := s.DBClose()
		if err != nil {
			log.Errorf("db close: %v", err)
		}
	}()

	// Find out where IBD is at
	bhs, err := s.db.BlockHeadersBest(ctx)
	if err != nil {
		return fmt.Errorf("block headers best: %v", err)
	}
	// No entries means we are at genesis
	if len(bhs) == 0 {
		bhs, err = s.insertGenesis(ctx)
		if err != nil {
			return fmt.Errorf("insert genesis: %v", err)
		}
		bhs, err = s.db.BlockHeadersBest(ctx)
		if err != nil {
			return err
		}
	} else if len(bhs) > 1 {
		return fmt.Errorf("blockheaders best: unsupported fork")
	}
	s.lastBlockHeader = bhs[0] // Prime last seen block header
	log.Infof("Starting block headers sync at height: %v time %v",
		bhs[0].Height, bhs[0].Timestamp())

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

	// Prometheus
	if s.cfg.PrometheusListenAddress != "" {
		d, err := deucalion.New(&deucalion.Config{
			ListenAddress: s.cfg.PrometheusListenAddress,
		})
		if err != nil {
			return fmt.Errorf("failed to create server: %w", err)
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
			if err := d.Run(ctx, cs); err != context.Canceled {
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
		err := s.peerManager(ctx)
		if err != nil {
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
