// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/postgres"
)

const (
	logLevel = "INFO"

	promSubsystem = "tbc_service" // Prometheus

	mainnetPort = "8333"
	testnetPort = "18333"

	defaultPeersWanted   = 16 // XXX go with 64
	defaultPendingBlocks = 16 // XXX go with 64
)

var testnetSeeds = []string{
	"testnet-seed.bitcoin.jonasschnelli.ch",
	"seed.tbtc.petertodd.org",
	"seed.testnet.bitcoin.sprovoost.nl",
	"testnet-seed.bluematt.me",
}

var log = loggo.GetLogger("tbc")

func init() {
	loggo.ConfigureLoggers(logLevel)
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
	LogLevel                string
	PgURI                   string
	PrometheusListenAddress string
	Network                 string
}

func NewDefaultConfig() *Config {
	return &Config{
		LogLevel: logLevel,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// bitcoin network
	wireNet     wire.BitcoinNet
	chainParams *chaincfg.Params
	port        string
	seeds       []string

	peers  map[string]*peer      // active but not necessarily connected
	blocks map[string]*blockPeer // outstanding block downloads [hash]when/where

	isWorking bool // reentrancy flag

	db tbcd.Database

	// Prometheus
	isRunning bool
}

var (
	errCacheFull     = errors.New("cache full")
	errNoPeers       = errors.New("no peers")
	errAlreadyCached = errors.New("already cached")
	errExpiredPeer   = errors.New("expired peer")
)

// blockPeerAdd adds a block to the pending list at the selected peer. Lock
// must be held.
func (s *Server) blockPeerAdd(hash, peer string) error {
	t := time.Now().Add(defaultPendingBlocks * time.Second) // ~1 block per second

	if _, ok := s.peers[peer]; !ok {
		return errExpiredPeer // XXX should not happen
	}
	if _, ok := s.blocks[hash]; ok {
		return errAlreadyCached
	}
	s.blocks[hash] = &blockPeer{
		expire: t,
		peer:   peer,
	}
	return nil
}

// blockPeerExpire removes expired block downloads from the cache and returns
// the number of used cache slots.
func (s *Server) blockPeerExpire() int {
	log.Tracef("blockPeerExpire exit")
	defer log.Tracef("blockPeerExpire exit")

	now := time.Now()
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for k, v := range s.blocks {
		if !now.After(v.expire) {
			continue
		}
		delete(s.blocks, k)

		// kill peer as well since it is slow
		if p := s.peers[v.peer]; p != nil && p.conn != nil {
			p.conn.Close() // this will tear down peer
		}
	}
	return len(s.blocks)
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg:    cfg,
		blocks: make(map[string]*blockPeer, defaultPendingBlocks),
		peers:  make(map[string]*peer, defaultPeersWanted),
	}

	// We could use a PGURI verification here.

	switch cfg.Network {
	case "mainnet":
		s.port = mainnetPort
		s.wireNet = wire.MainNet
		s.chainParams = &chaincfg.MainNetParams
		panic("no seeds")
	case "testnet", "testnet3":
		s.port = testnetPort
		s.wireNet = wire.TestNet3
		s.chainParams = &chaincfg.TestNet3Params
		s.seeds = testnetSeeds
	default:
		return nil, fmt.Errorf("invalid network: %v", cfg.Network)
	}

	return s, nil
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
		// XXX use pool
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
		ips, err := resolver.LookupIP(ctx, "ip", s.seeds[k])
		if err != nil {
			log.Errorf("lookup: %v", err)
			errorsSeen++
			continue
		}
		addrs = append(addrs, ips...)
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

func (s *Server) randPeerWrite(ctx context.Context, hash string, msg wire.Message) error {
	log.Tracef("randPeerWrite")
	defer log.Tracef("randPeerWrite")

	var p *peer
	// Select random peer
	s.mtx.Lock()
	if len(s.blocks) >= defaultPendingBlocks {
		s.mtx.Unlock()
		return errCacheFull
	}
	for k, v := range s.peers {
		if v.conn == nil {
			// Not connected yet
			continue
		}

		// maybe insert into cache
		err := s.blockPeerAdd(hash, k)
		if err != nil {
			continue
		}

		// cached, now execute
		p = v
		break
	}
	s.mtx.Unlock()

	if p == nil {
		return errNoPeers
	}
	return p.write(msg)
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
	seeds, err := s.seed(ctx, peersWanted)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	if len(seeds) == 0 {
		// probably retry
		return fmt.Errorf("no seeds found")
	}

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
					seeds, err = s.seed(ctx, peersWanted)
					if err != nil {
						return fmt.Errorf("seed: %w", err)
					}
					if len(seeds) == 0 {
						// probably retry
						return fmt.Errorf("no seeds found")
					}
					x = 0
				}
			}
		}

		// XXX unfortunately we need a timer here to halt looping when
		// there is no internet connection but with a functioning DNS
		// server.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case address := <-peerC:
			// peer exited, connect to new one
			s.peerDelete(address)
			log.Debugf("peer exited: %v", address)
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
				log.Debugf("peer delete (%v): %v", pp, err)
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

	log.Infof("Peer connected: %v", p)

	// Pretend we are always in IBD.
	//
	// This obviously will put a pressure on the internet connection and
	// database because each and every peer is racing at start of day.  As
	// multiple answers come in the insert of the headers fails or
	// succeeds. If it fails no more headers will be requested from that
	// peer.
	bhs, err := s.blockHeadersBest(ctx)
	if err != nil {
		// This should not happen
		log.Errorf("block headers best: %v", err)
		return
	}
	if len(bhs) != 1 {
		// XXX fix multiple tips
		panic(len(bhs))
	}
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
			// Expire pending block downloads from this host
			cacheUsed := s.blockPeerExpire()
			log.Errorf("read (%v): %v -- cache %v", p, err, cacheUsed)
			return
		}

		if verbose {
			spew.Dump(msg)
		}

		// XXX send wire message to pool reader
		switch m := msg.(type) {
		case *wire.MsgAddr:
			go s.handleAddr(ctx, m)

		case *wire.MsgAddrV2:
			go s.handleAddrV2(ctx, m)

		case *wire.MsgBlock:
			go s.handleBlock(ctx, m)

		case *wire.MsgFeeFilter:
			// XXX shut up

		case *wire.MsgInv:
			go s.handleInv(ctx, m)

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

func (s *Server) handleAddr(ctx context.Context, msg *wire.MsgAddr) {
	log.Tracef("handleAddr: %v", len(msg.AddrList))
	defer log.Tracef("handleAddr exit")

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

func (s *Server) handleAddrV2(ctx context.Context, msg *wire.MsgAddrV2) {
	log.Tracef("handleAddrV2: %v", len(msg.AddrList))
	defer log.Tracef("handleAddrV2 exit")

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

func (s *Server) handleInv(ctx context.Context, msg *wire.MsgInv) {
	log.Tracef("handleInv")
	defer log.Tracef("handleInv exit")

	var mb []tbcd.BlockHeader
	for k := range msg.InvList {
		switch msg.InvList[k].Type {
		case wire.InvTypeBlock:
			log.Infof("handleInv: block %v", msg.InvList[k].Hash)

			mb = append(mb, tbcd.BlockHeader{
				Hash: msg.InvList[k].Hash[:], // fake out
			})
		case wire.InvTypeTx:
			// XXX silence for now
		default:
			log.Infof("handleInv: skipping inv type %v", msg.InvList[k].Type)
		}
	}

	if len(mb) > 0 {
		err := s.downloadBlocks(ctx, mb)
		if err != nil {
			log.Errorf("download blocks: %v", err)
			return
		}
	}
}

// XXX see how we send in peer, that is not what we want
func (s *Server) handleHeaders(ctx context.Context, p *peer, msg *wire.MsgHeaders) {
	log.Tracef("handleHeaders")
	defer log.Tracef("handleHeaders exit")

	log.Debugf("handleHeaders (%v): %v", p, len(msg.Headers))

	// XXX debug
	if len(msg.Headers) > 0 && len(msg.Headers) < 2000 {
		log.Infof("handleHeaders (%v): %v", p, len(msg.Headers))
	}

	if len(msg.Headers) == 0 {
		s.checkBlockCache(ctx)
		return
	}

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

		lbh := headers[len(headers)-1]
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

func (s *Server) handleBlock(ctx context.Context, msg *wire.MsgBlock) {
	log.Tracef("handleBlock")
	defer log.Tracef("handleBlock exit")

	block := &bytes.Buffer{}
	err := msg.Serialize(block) // XXX we should not being doing this twice
	if err != nil {
		log.Errorf("block serialize: %v", err)
		return
	}

	bh := msg.Header.BlockHash()
	bhs := bh.String()
	b := &tbcd.Block{
		Hash:  sliceChainHash(bh),
		Block: block.Bytes(),
	}

	height, err := s.db.BlockInsert(ctx, b)
	if err != nil {
		// XXX ignore duplicate error printing since we will hit that
		log.Errorf("block insert %v: %v", bhs, err)
	} else {
		log.Infof("Insert block %v at %v txs %v %v", bhs, height,
			len(msg.Transactions), msg.Header.Timestamp)
	}

	// Whatever happens,, delete from cache and potentially try again
	s.mtx.Lock()
	delete(s.blocks, bhs) // remove inserted block
	s.mtx.Unlock()

	s.checkBlockCache(ctx)
}

func (s *Server) checkBlockCache(ctx context.Context) {
	// Deal with expired block downloads
	used := s.blockPeerExpire()
	if defaultPendingBlocks-used <= 0 {
		return
	}

	// XXX make better reentrant
	s.mtx.Lock()
	if s.isWorking {
		s.mtx.Unlock()
		return
	}
	s.isWorking = true
	s.mtx.Unlock()
	defer func() {
		s.mtx.Lock()
		s.isWorking = false
		s.mtx.Unlock()
	}()

	mb, err := s.db.BlockHeadersMissing(ctx, defaultPendingBlocks)
	if err != nil {
		log.Errorf("block headers missing: %v", err)
		return
	}
	// downdloadBlocks will only insert unseen in the cache
	err = s.downloadBlocks(ctx, mb)
	if err != nil {
		log.Errorf("download blocks: %v", err)
		return
	}
}

func (s *Server) blockHeadersBest(ctx context.Context) ([]tbcd.BlockHeader, error) {
	log.Tracef("blockHeadersBest")
	defer log.Tracef("blockHeadersBest exit")

	// Find out where IBD is at
	bhs, err := s.db.BlockHeadersBest(ctx)
	if err != nil {
		return nil, fmt.Errorf("block headers best: %v", err)
	}

	// No entries means we are at genesis
	// XXX this can hit several times on tart of day. Figure out if we want
	// to insert geneis earlier to prevent this error.
	if len(bhs) == 0 {
		gbh, err := header2Bytes(&s.chainParams.GenesisBlock.Header)
		if err != nil {
			return nil, fmt.Errorf("serialize genesis block header: %v", err)
		}
		bhs = append(bhs, tbcd.BlockHeader{
			Height: 0,
			Hash:   s.chainParams.GenesisHash[:],
			Header: gbh,
		})

		log.Infof("Inserting genesis hash: %v", s.chainParams.GenesisHash)
		err = s.db.BlockHeadersInsert(ctx, bhs)
		if err != nil {
			return nil, fmt.Errorf("genesis block header insert: %v", err)
		}
	}

	if len(bhs) != 1 {
		// XXX this needs to be handled.
		return nil, fmt.Errorf("unhandled best tip count: %v", bhs)
	}

	return bhs, nil
}

func (s *Server) downloadBlocks(ctx context.Context, bhs []tbcd.BlockHeader) error {
	log.Tracef("downloadBlocks")
	defer log.Tracef("downloadBlocks exit")

	for k := range bhs {
		bh := bhs[k]
		hash, _ := chainhash.NewHash(bh.Hash[:])
		hashS := hash.String()
		getData := wire.NewMsgGetData()
		getData.InvList = append(getData.InvList,
			&wire.InvVect{
				Type: wire.InvTypeBlock,
				Hash: *hash,
			})
		err := s.randPeerWrite(ctx, hashS, getData)
		switch err {
		case nil:
			continue
		case errCacheFull:
			// XXX certainly too loud
			log.Tracef("cache full")
			break
		case errNoPeers:
			// XXX certainly too loud
			log.Tracef("could not write, no peers")
			break
		default:
			// XXX probably too loud
			log.Errorf("write error: %v", err)
		}
	}

	return nil
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

	// Connect to db.
	// XXX should we reconnect?
	var err error
	s.db, err = postgres.New(ctx, s.cfg.PgURI)
	if err != nil {
		return fmt.Errorf("Failed to connect to database: %v", err)
	}
	defer s.db.Close()

	// Prometheus
	if s.cfg.PrometheusListenAddress != "" {
		d, err := deucalion.New(&deucalion.Config{
			ListenAddress: s.cfg.PrometheusListenAddress,
		})
		if err != nil {
			return fmt.Errorf("failed to create server: %w", err)
		}
		cs := []prometheus.Collector{
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
	case e := <-errC:
		err = e
	}
	cancel()

	log.Infof("tbc service shutting down")
	s.wg.Wait()
	log.Infof("tbc service clean shutdown")

	return err
}
