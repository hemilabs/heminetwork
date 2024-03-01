// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/postgres"
)

const (
	logLevel = "INFO"

	promSubsystem = "tbc_service" // Prometheus
)

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

func (s *Server) getHeaders(lastHeaderHash []byte) error {
	bh, err := bytes2Header(lastHeaderHash)
	if err != nil {
		return fmt.Errorf("invalid header: %v", err)
	}
	hash := bh.BlockHash()
	ghs := wire.NewMsgGetHeaders()
	ghs.AddBlockLocatorHash(&hash)
	err = s.peer.write(ghs)
	if err != nil {
		// XXX use pool
		return fmt.Errorf("write get headers: %v", err)
	}

	return nil
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
	peer        *peer // make plural

	expire  time.Time
	pending map[string]time.Time

	db tbcd.Database

	// Prometheus
	isRunning bool
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg:     cfg,
		pending: make(map[string]time.Time, 16), // XXX this sucks, kill
	}
	// We could use a PGURI verification here.
	// single peer for now

	mainnetPort := "8333"
	testnetPort := "18333"
	var port string
	switch cfg.Network {
	case "mainnet":
		port = mainnetPort
		s.wireNet = wire.MainNet
		s.chainParams = &chaincfg.MainNetParams
	case "testnet", "testnet3":
		port = testnetPort
		s.wireNet = wire.TestNet3
		s.chainParams = &chaincfg.TestNet3Params
	default:
		return nil, fmt.Errorf("invalid network: %v", cfg.Network)
	}

	var err error
	s.peer, err = NewPeer(s.wireNet, "140.238.169.133:"+port)
	if err != nil {
		return nil, fmt.Errorf("new peer: %v", err)
	}

	return s, nil
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
	log.Tracef("handleAddr")
	defer log.Tracef("handleAddr exit")

	log.Infof("handleAddr: %v", len(msg.AddrList))
}

func (s *Server) handleAddrV2(ctx context.Context, msg *wire.MsgAddrV2) {
	log.Tracef("handleAddrV2")
	defer log.Tracef("handleAddrV2 exit")

	log.Infof("handleAddrV2: %v", len(msg.AddrList))
}

func (s *Server) handlePing(ctx context.Context, msg *wire.MsgPing) {
	log.Tracef("handlePing")
	defer log.Tracef("handlePing exit")

	pong := wire.NewMsgPong(msg.Nonce)
	err := s.peer.write(pong)
	if err != nil {
		fmt.Printf("could not write pong message: %v", err)
		return
	}
	log.Debugf("handlePing: pong %v", pong.Nonce)
}

func (s *Server) handleInvBlock(p *peer, msg *wire.MsgInv) {
}

func (s *Server) handleInv(ctx context.Context, msg *wire.MsgInv) {
	log.Tracef("handleInv")
	defer log.Tracef("handleInv exit")

	log.Debugf("handleInv: %v %v", len(msg.InvList), msg.InvList[0].Type) // XXX this will crash with no items

	//// XXX fix height
	//blocks := make([]tbcd.BlockHeaders, 0, len(msg.InvList))
	for k := range msg.InvList {
		switch msg.InvList[k].Type {
		case wire.InvTypeBlock:
			log.Infof("handleInv: block")
			//log.Tracef("handleInv block: height %v hash %v",
			//	k+1, msg.InvList[k].Hash)
			////err := downloadBlock(p, k+1, msg.InvList[k].Hash)
			////if err != nil {
			////	log.Errorf("download block at %v: %v", k+1, err)
			////}
			//blocks = append(blocks, tbcd.BlockHeaders{
			//	Hash:   msg.InvList[k].Hash[:], // XXX this is wireformat
			//	Height: uint64(k + 1),
			//})
		default:
			log.Tracef("handleInv: skipping inv type %v", msg.InvList[k].Type)
		}
	}

	//if len(blocks) > 0 {
	//	err := s.db.BlockHeadersInsert(ctx, blocks)
	//	if err != nil {
	//		log.Errorf("BlockHeadersInsert: %v", err)
	//	}
	//}
}

func (s *Server) handleHeaders(ctx context.Context, msg *wire.MsgHeaders) {
	log.Tracef("handleHeaders")
	defer log.Tracef("handleHeaders exit")

	log.Debugf("handleHeaders: %v", len(msg.Headers))

	if len(msg.Headers) == 0 {
		// XXX DEBUG SHIT
		if false {
			// We have all headers, retrieve missing blocks
			mb, err := s.db.BlockHeadersMissing(ctx, 16)
			if err != nil {
				log.Errorf("block headers missing: %v", err)
				return
			}
			err = s.downloadBlocks(mb)
			if err != nil {
				log.Errorf("download blocks: %v", err)
				return
			}
		}
		log.Infof("=== DISABLED BLOCK DOWNLOAD ===")
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
			log.Errorf("block headers insert: %v", err)
			return
		}

		lbh := headers[len(headers)-1]
		log.Infof("Inserted %v block headers height %v",
			len(headers), lbh.Height)

		// Ask for next batch of headers
		err = s.getHeaders(lbh.Header)
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
	b := &tbcd.Block{
		Hash:  sliceChainHash(bh),
		Block: block.Bytes(),
	}

	height, err := s.db.BlockInsert(ctx, b)
	if err != nil {
		// XXX ignore duplicate error printing since we will hit that
		log.Errorf("block insert: %v", err)
		return
	}

	bhs := bh.String()
	log.Infof("Insert block %v at %v txs %v", bhs, height, len(msg.Transactions))

	// Poor man's cache that sucks
	s.mtx.Lock()
	delete(s.pending, bhs)
	pendingLen := len(s.pending)
	expire := s.expire
	s.mtx.Unlock()

	// XXX this needs a time component as well
	if pendingLen <= 0 || time.Now().After(expire) {
		// XXX this is duplicate code, make a function
		log.Infof("now %v expire %v length %v", time.Now(), expire, pendingLen)
		// We have all headers, retrieve missing blocks
		mb, err := s.db.BlockHeadersMissing(ctx, 16)
		if err != nil {
			log.Errorf("block headers missing: %v", err)
			return
		}
		err = s.downloadBlocks(mb)
		if err != nil {
			log.Errorf("download blocks: %v", err)
			return
		}
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

func (s *Server) downloadBlocks(bhs []tbcd.BlockHeader) error {
	log.Tracef("downloadBlocks")
	defer log.Tracef("downloadBlocks exit")

	getData := wire.NewMsgGetData()
	for k := range bhs {
		bh := bhs[k]
		hash, _ := chainhash.NewHash(bh.Hash[:])
		getData.InvList = append(getData.InvList,
			&wire.InvVect{
				Type: wire.InvTypeBlock,
				Hash: *hash,
			})
		// poor man's cache outstanding blocks
		// XXX this sucks, make better
		hs := hash.String()
		expire := time.Now().Add(30 * time.Second) // expiration
		s.mtx.Lock()
		s.pending[hs] = expire
		s.expire = expire
		s.mtx.Unlock()
	}
	err := s.peer.write(getData)
	if err != nil {
		return fmt.Errorf("could not write get block message: %v", err)
	}

	return nil
}

func (s *Server) p2p(ctx context.Context) {
	defer s.wg.Done()

	log.Tracef("p2p")
	defer log.Tracef("p2p exit")

	err := s.peer.connect(ctx)
	if err != nil {
		// XXX use a pool
		log.Errorf("connect: %v", err)
		return
	}
	log.Debugf("p2p handshake complete with: %v\n", s.peer.address)

	// Get network information
	getAddr := wire.NewMsgGetAddr()
	err = s.peer.write(getAddr)
	if err != nil {
		// XXX recover
		log.Errorf("write getaddrv2: %v", err)
	}

	// Resume headers/blocks download
	bhs, err := s.blockHeadersBest(ctx)
	if err != nil {
		log.Errorf("block headers best: %v", err)
		return
	}
	if len(bhs) != 1 {
		// XXX fix multiple tips
		panic(len(bhs))
	}

	log.Infof("Resume header download at height %v", bhs[0].Height)
	err = s.getHeaders(bhs[0].Header)
	if err != nil {
		// XXX use pool
		log.Errorf("write get headers: %v", err)
		return
	}

	verbose := false
	for {
		// see if we were interrupted
		select {
		case <-ctx.Done():
			log.Errorf("p2p: %v", ctx.Err())
			return
		default:
		}

		msg, err := s.peer.read()
		if err == wire.ErrUnknownMessage {
			// skip unknown
			continue
		} else if err != nil {
			// XXX this is why we need a pool
			log.Errorf("read: %v", err)
			return
		}

		if verbose {
			spew.Dump(msg)
		}

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
			go s.handleHeaders(ctx, m)

		case *wire.MsgPing:
			go s.handlePing(ctx, m)

		default:
			log.Errorf("unhandled message type: %T\n", msg)
		}
	}
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

	s.wg.Add(1)
	go s.p2p(ctx)

	select {
	case <-ctx.Done():
		err = ctx.Err()
	}
	cancel()

	log.Infof("tbc service shutting down")
	s.wg.Wait()
	log.Infof("tbc service clean shutdown")

	return err
}
