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

	db tbcd.Database

	// Prometheus
	isRunning bool
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg: cfg,
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

func (s *Server) handlePing(p *peer, msg *wire.MsgPing) {
	log.Tracef("handlePing")
	defer log.Tracef("handlePing exit")

	pong := wire.NewMsgPong(msg.Nonce)
	err := p.write(pong)
	if err != nil {
		fmt.Printf("could not write pong message: %v", err)
		return
	}
	log.Debugf("handlePing: pong %v", pong.Nonce)
}

func (s *Server) handleInvBlock(p *peer, msg *wire.MsgInv) {
}

func (s *Server) handleInv(ctx context.Context, p *peer, msg *wire.MsgInv) {
	log.Tracef("handleInv")
	defer log.Tracef("handleInv exit")

	log.Debugf("handleInv: %v", len(msg.InvList))

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

func (s *Server) handleHeaders(ctx context.Context, p *peer, msg *wire.MsgHeaders) {
	log.Tracef("handleHeaders")
	defer log.Tracef("handleHeaders exit")

	log.Debugf("handleHeaders: %v", len(msg.Headers))

	if len(msg.Headers) == 0 {
		// We have all headers, retrieve missing blocks
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

func (s *Server) handleBlock(p *peer, msg *wire.MsgBlock) {
	log.Tracef("handleBlock")
	defer log.Tracef("handleBlock exit")

	log.Debugf("handleBlock: %v txs %v\n", msg.Header.BlockHash(),
		len(msg.Transactions))
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

// XXX remove/fix
func downloadBlock(p *peer, height int, hash chainhash.Hash) error {
	log.Tracef("downloadBlock")
	defer log.Tracef("downloadBlock exit")

	log.Debugf("downloadBlock at %v: %v", height, hash)

	getData := wire.NewMsgGetData()
	getData.InvList = append(getData.InvList,
		&wire.InvVect{
			Type: wire.InvTypeBlock,
			Hash: hash,
		})
	err := p.write(getData)
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

	//// send ibv start using get blocks
	//log.Debugf("genesis hash: %v\n", s.chainParams.GenesisHash)
	//getBlocks := wire.NewMsgGetBlocks(s.chainParams.GenesisHash)
	//err = s.peer.write(getBlocks)
	//if err != nil {
	//	log.Errorf("write getBlocks: %v", err)
	//	return
	//}

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
			log.Errorf("read: %w", err)
			return
		}

		if verbose {
			spew.Dump(msg)
		}

		switch m := msg.(type) {
		case *wire.MsgPing:
			go s.handlePing(s.peer, m)

		case *wire.MsgInv:
			go s.handleInv(ctx, s.peer, m)

		case *wire.MsgBlock:
			go s.handleBlock(s.peer, m)

		case *wire.MsgHeaders:
			go s.handleHeaders(ctx, s.peer, m)

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
