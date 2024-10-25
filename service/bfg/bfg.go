// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfg

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/auth"
	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/bitcoin"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/bfgd"
	"github.com/hemilabs/heminetwork/database/bfgd/postgres"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/hemi/electrs"
	"github.com/hemilabs/heminetwork/hemi/pop"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
)

// XXX this code needs to be a bit smarter when syncing bitcoin. We should
// return a "not ready" error whe that is the case.

type notificationId string

const (
	logLevel = "INFO"

	promNamespace = "bfg" // Prometheus

	notifyBtcBlocks     notificationId = "btc_blocks"
	notifyBtcFinalities notificationId = "btc_finalities"
	notifyL2Keystones   notificationId = "l2_keystones"
)

var log = loggo.GetLogger("bfg")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

func NewDefaultConfig() *Config {
	return &Config{
		EXBTCAddress:         "localhost:18001",
		EXBTCInitialConns:    5,
		EXBTCMaxConns:        100,
		PrivateListenAddress: ":8080",
		PublicListenAddress:  ":8383",
		RequestLimit:         bfgapi.DefaultRequestLimit,
		RequestTimeout:       bfgapi.DefaultRequestTimeout,
	}
}

// XXX figure out if this needs to be moved out into the electrs package.
type btcClient interface {
	Metrics() []prometheus.Collector
	Balance(ctx context.Context, scriptHash []byte) (*electrs.Balance, error)
	Broadcast(ctx context.Context, rtx []byte) ([]byte, error)
	Height(ctx context.Context) (uint64, error)
	RawBlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error)
	RawTransaction(ctx context.Context, txHash []byte) ([]byte, error)
	Transaction(ctx context.Context, txHash []byte) ([]byte, error)
	TransactionAtPosition(ctx context.Context, height, index uint64) ([]byte, []string, error)
	UTXOs(ctx context.Context, scriptHash []byte) ([]*electrs.UTXO, error)
	Close() error
}

type Config struct {
	BTCStartHeight          uint64
	EXBTCAddress            string
	EXBTCInitialConns       int
	EXBTCMaxConns           int
	PrivateListenAddress    string
	PublicListenAddress     string
	LogLevel                string
	PgURI                   string
	PrometheusListenAddress string
	PprofListenAddress      string
	PublicKeyAuth           bool
	RequestLimit            int
	RequestTimeout          int // in seconds
	RemoteIPHeaders         []string
	TrustedProxies          []string
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	// requests
	requestLimiter chan bool // Maximum in progress websocket commands
	// requestTimeout time.Duration

	remoteIPHeaders []string
	trustedProxies  []*net.IPNet

	btcHeight uint64

	server       *http.ServeMux
	publicServer *http.ServeMux

	btcClient btcClient // XXX evaluate if this is ok

	db bfgd.Database

	// Prometheus
	metrics   *metrics
	isRunning bool

	// sessions is a record of websocket connections and their
	// respective request contexts
	sessions map[string]*bfgWs

	// record the last known canonical chain height,
	// if this grows we need to notify subscribers
	canonicalChainHeight uint64

	checkForInvalidBlocks chan struct{}

	l2keystonesCache []hemi.L2Keystone

	btcHeightCache uint64
}

// metrics stores prometheus metrics.
type metrics struct {
	popBroadcasts    prometheus.Counter       // Total number of PoP transaction broadcasts
	rpcCallsTotal    *prometheus.CounterVec   // Total number of successful RPC commands
	rpcCallsDuration *prometheus.HistogramVec // RPC calls duration in seconds
	rpcConnections   *prometheus.GaugeVec     // Number of active RPC WebSocket connections
}

// newMetrics returns a new metrics struct containing prometheus collectors.
func newMetrics() *metrics {
	// When adding a metric here, remember to add it to metrics.collectors().
	return &metrics{
		popBroadcasts: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: promNamespace,
			Name:      "pop_broadcasts_total",
			Help:      "Total number of PoP transaction broadcasts",
		}),
		rpcCallsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: promNamespace,
				Name:      "rpc_calls_total",
				Help:      "Total number of successful RPC commands",
			},
			[]string{"listener", "command"},
		),
		rpcCallsDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: promNamespace,
				Name:      "rpc_calls_duration_seconds",
				Help:      "RPC call durations in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"listener", "command"},
		),
		rpcConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: promNamespace,
				Name:      "rpc_connections",
				Help:      "Number of active RPC WebSocket connections",
			},
			[]string{"listener"},
		),
	}
}

// collectors returns all prometheus collectors.
func (m *metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.popBroadcasts,
		m.rpcCallsTotal,
		m.rpcCallsDuration,
		m.rpcConnections,
	}
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	if cfg.RequestLimit <= 0 {
		return nil, fmt.Errorf("invalid request limit: %v", cfg.RequestLimit)
	}
	minRequestTimeout := 3
	if cfg.RequestTimeout <= minRequestTimeout {
		return nil, fmt.Errorf("invalid request timeout (minimum %v): %v",
			minRequestTimeout, cfg.RequestTimeout)
	}
	s := &Server{
		cfg:                   cfg,
		requestLimiter:        make(chan bool, cfg.RequestLimit),
		btcHeight:             cfg.BTCStartHeight,
		server:                http.NewServeMux(),
		publicServer:          http.NewServeMux(),
		metrics:               newMetrics(),
		sessions:              make(map[string]*bfgWs),
		checkForInvalidBlocks: make(chan struct{}),
	}
	for range cfg.RequestLimit {
		s.requestLimiter <- true
	}

	var err error
	s.btcClient, err = electrs.NewClient(cfg.EXBTCAddress, &electrs.ClientOptions{
		InitialConnections: cfg.EXBTCInitialConns,
		MaxConnections:     cfg.EXBTCMaxConns,
		PromNamespace:      promNamespace,
	})
	if err != nil {
		return nil, fmt.Errorf("create electrs client: %w", err)
	}

	// We could use a PGURI verification here.

	return s, nil
}

func (s *Server) queueCheckForInvalidBlocks() {
	select {
	case s.checkForInvalidBlocks <- struct{}{}:
	default:
	}
}

func (s *Server) invalidBlockChecker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.checkForInvalidBlocks:
			heights, err := s.db.BtcBlocksHeightsWithNoChildren(ctx)
			if err != nil {
				log.Errorf("error trying to get heights for btc blocks: %s", err)
				return
			}

			log.Infof("received %d heights with no children, will re-check", len(heights))
			for _, height := range heights {
				log.Infof("reprocessing block at height %d", height)
				if err := s.processBitcoinBlock(ctx, height); err != nil {
					log.Errorf("error processing bitcoin block: %s", err)
				}
			}
		}
	}
}

// handleRequest is called as a go routine to handle a long-lived command.
func (s *Server) handleRequest(parentCtx context.Context, bws *bfgWs, wsid string, cmd protocol.Command, handler func(ctx context.Context) (any, error)) {
	log.Tracef("handleRequest: %v", bws.addr)
	defer log.Tracef("handleRequest exit: %v", bws.addr)

	ctx, cancel := context.WithTimeout(bws.requestContext,
		time.Duration(s.cfg.RequestTimeout)*time.Second)
	defer cancel()

	select {
	case <-s.requestLimiter:
	default:
		log.Infof("Request limiter hit %v: %v", bws.addr, cmd)
		select {
		case <-s.requestLimiter:
		case <-ctx.Done():
			log.Infof("request context done %v: %v", bws.addr, cmd)
			return
		}
	}
	defer func() { s.requestLimiter <- true }()

	start := time.Now()
	defer func() {
		s.metrics.rpcCallsDuration.With(prometheus.Labels{
			"listener": bws.listenerName,
			"command":  string(cmd),
		}).Observe(time.Since(start).Seconds())
	}()

	log.Tracef("Handling request %v: %v", bws.addr, cmd)

	response, err := handler(ctx)
	if err != nil {
		log.Errorf("Failed to handle %v request %v: %v", cmd, bws.addr, err)
	}
	if response == nil {
		return
	}

	log.Debugf("Responding to %v request with %v", cmd, spew.Sdump(response))
	if err := bfgapi.Write(ctx, bws.conn, wsid, response); err != nil {
		log.Errorf("Failed to handle %v request: protocol write failed: %v",
			cmd, err)
	}
}

func (s *Server) handleBitcoinBalance(ctx context.Context, bbr *bfgapi.BitcoinBalanceRequest) (any, error) {
	log.Tracef("handleBitcoinBalance")
	defer log.Tracef("handleBitcoinBalance exit")

	balance, err := s.btcClient.Balance(ctx, bbr.ScriptHash)
	if err != nil {
		e := protocol.NewInternalErrorf("bitcoin balance: %w", err)
		return &bfgapi.BitcoinBalanceResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &bfgapi.BitcoinBalanceResponse{
		Confirmed:   balance.Confirmed,
		Unconfirmed: balance.Unconfirmed,
	}, nil
}

func (s *Server) handleOneBroadcastRequest(ctx context.Context, highPriority bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	serializedTx, err := s.db.BtcTransactionBroadcastRequestGetNext(ctx, highPriority)
	if err != nil {
		log.Errorf("error getting next broadcast request: %v", err)
		return
	}

	// if there are no new serialized txs, backoff a bit
	if serializedTx == nil {
		select {
		case <-time.After(1 * time.Second):
			return
		case <-ctx.Done():
			return
		}
	}

	rr := bytes.NewReader(serializedTx)
	mb := wire.MsgTx{}
	if err := mb.Deserialize(rr); err != nil {
		log.Errorf("failed to deserialize tx: %v", err)
		return
	}

	var tl2 *pop.TransactionL2
	for _, v := range mb.TxOut {
		tl2, err = pop.ParseTransactionL2FromOpReturn(v.PkScript)
		if err == nil {
			break // Found the pop transaction.
		}
	}

	if tl2 == nil {
		log.Errorf("could not find pop tx")
		return
	}

	_, err = pop.ParsePublicKeyFromSignatureScript(mb.TxIn[0].SignatureScript)
	if err != nil {
		log.Errorf("could not parse public key from signature script: %v", err)
		return
	}

	hash := mb.TxHash()

	_, err = s.btcClient.Broadcast(ctx, serializedTx)
	if err != nil {
		log.Errorf("broadcast tx %s: %s", mb.TxID(), err)
		err = s.db.BtcTransactionBroadcastRequestSetLastError(ctx, mb.TxID(), err.Error())
		if err != nil {
			log.Errorf("could not delete %v", err)
		}
		return
	}

	s.metrics.popBroadcasts.Inc()

	log.Tracef("hash is %s", hex.EncodeToString(hash[:]))

	err = s.db.BtcTransactionBroadcastRequestConfirmBroadcast(ctx, mb.TxID())
	if err != nil {
		log.Errorf("could not confirm broadcast: %v", err)
		return
	}

	log.Infof("successfully broadcast tx %s, for l2 keystone %s", mb.TxID(), hex.EncodeToString(tl2.L2Keystone.Hash()))
}

func (s *Server) bitcoinBroadcastWorker(ctx context.Context, highPriority bool) {
	log.Tracef("bitcoinBroadcastWorker")
	defer log.Tracef("bitcoinBroadcastWorker exit")

	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			s.handleOneBroadcastRequest(ctx, highPriority)
		}
	}
}

func (s *Server) handleBitcoinBroadcast(ctx context.Context, bbr *bfgapi.BitcoinBroadcastRequest) (any, error) {
	log.Tracef("handleBitcoinBroadcast")
	defer log.Tracef("handleBitcoinBroadcast exit")

	rr := bytes.NewReader(bbr.Transaction)
	mb := wire.MsgTx{}
	if err := mb.Deserialize(rr); err != nil {
		return &bfgapi.BitcoinBroadcastResponse{Error: protocol.RequestErrorf(
			"failed to deserialize tx: %s", err,
		)}, nil
	}

	var (
		tl2 *pop.TransactionL2
		err error
	)
	for _, v := range mb.TxOut {
		tl2, err = pop.ParseTransactionL2FromOpReturn(v.PkScript)
		if err == nil {
			break // Found the pop transaction.
		}
	}

	if tl2 == nil {
		return &bfgapi.BitcoinBroadcastResponse{
			Error: protocol.RequestErrorf("could not find l2 keystone abbrev in btc tx"),
		}, nil
	}

	_, err = pop.ParsePublicKeyFromSignatureScript(mb.TxIn[0].SignatureScript)
	if err != nil {
		return &bfgapi.BitcoinBroadcastResponse{
			Error: protocol.RequestErrorf("could not parse signature script: %v", err),
		}, nil
	}

	err = s.db.BtcTransactionBroadcastRequestInsert(ctx, bbr.Transaction, mb.TxID())
	if err != nil && !errors.Is(err, database.ErrDuplicate) {
		e := protocol.NewInternalErrorf("insert broadcast request : %w", err)
		return &bfgapi.BitcoinBroadcastResponse{
			Error: e.ProtocolError(),
		}, e
	}

	hash := mb.TxHash()
	return &bfgapi.BitcoinBroadcastResponse{TXID: hash[:]}, nil
}

func (s *Server) updateBtcHeightCache(height uint64) {
	log.Tracef("updateBtcHeightCache")
	defer log.Tracef("updateBtcHeightCache exit")

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.btcHeightCache = height
}

func (s *Server) getBtcHeightCache() uint64 {
	log.Tracef("getBtcHeightCache")
	defer log.Tracef("getBtcHeightCache exit")

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.btcHeightCache
}

func (s *Server) handleBitcoinInfo(ctx context.Context, bir *bfgapi.BitcoinInfoRequest) (any, error) {
	log.Tracef("handleBitcoinInfo")
	defer log.Tracef("handleBitcoinInfo exit")

	height := s.getBtcHeightCache()

	return &bfgapi.BitcoinInfoResponse{
		Height: height,
	}, nil
}

func (s *Server) handleBitcoinUTXOs(ctx context.Context, bur *bfgapi.BitcoinUTXOsRequest) (any, error) {
	log.Tracef("handleBitcoinUTXOs")
	defer log.Tracef("handleBitcoinUTXOs exit")

	utxos, err := s.btcClient.UTXOs(ctx, bur.ScriptHash)
	if err != nil {
		e := protocol.NewInternalErrorf("bitcoin utxos: %w", err)
		return &bfgapi.BitcoinUTXOsResponse{
			Error: e.ProtocolError(),
		}, e

	}
	buResp := bfgapi.BitcoinUTXOsResponse{}
	for _, utxo := range utxos {
		buResp.UTXOs = append(buResp.UTXOs, &bfgapi.BitcoinUTXO{
			Hash:  utxo.Hash,
			Index: utxo.Index,
			Value: utxo.Value,
		})
	}

	return buResp, nil
}

func (s *Server) handleAccessPublicKeyCreateRequest(ctx context.Context, acpkc *bfgapi.AccessPublicKeyCreateRequest) (any, error) {
	log.Tracef("handleAccessPublicKeyCreateRequest")
	defer log.Tracef("handleAccessPublicKeyCreateRequest exit")

	publicKey, err := hex.DecodeString(acpkc.PublicKey)
	if err != nil {
		return &bfgapi.AccessPublicKeyCreateResponse{
			Error: protocol.RequestErrorf("public key decode: %v", err),
		}, nil
	}

	if err := s.db.AccessPublicKeyInsert(ctx, &bfgd.AccessPublicKey{
		PublicKey: publicKey,
	}); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			return &bfgapi.AccessPublicKeyCreateResponse{
				Error: protocol.RequestErrorf("public key already exists"),
			}, nil
		}

		if errors.Is(err, database.ErrValidation) {
			return &bfgapi.AccessPublicKeyCreateResponse{
				Error: protocol.RequestErrorf("invalid access public key"),
			}, nil
		}

		e := protocol.NewInternalErrorf("insert public key: %w", err)
		return &bfgapi.AccessPublicKeyCreateResponse{
			Error: protocol.RequestErrorf("invalid access public key"),
		}, e
	}

	return &bfgapi.AccessPublicKeyCreateResponse{}, nil
}

func (s *Server) handleAccessPublicKeyDelete(ctx context.Context, payload any) (any, error) {
	log.Tracef("handleAccessPublicKeyDelete")
	defer log.Tracef("handleAccessPublicKeyDelete exit")

	accessPublicKeyDeleteRequest, ok := payload.(*bfgapi.AccessPublicKeyDeleteRequest)
	if !ok {
		return nil, fmt.Errorf("incorrect type %T", payload)
	}

	b, err := hex.DecodeString(accessPublicKeyDeleteRequest.PublicKey)
	if err != nil {
		return &bfgapi.AccessPublicKeyDeleteResponse{
			Error: protocol.RequestErrorf("public key decode: %v", err),
		}, nil
	}

	if err := s.db.AccessPublicKeyDelete(ctx, &bfgd.AccessPublicKey{
		PublicKey: b,
	}); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			// XXX not sure I like giving this information away.
			return &bfgapi.AccessPublicKeyDeleteResponse{
				Error: protocol.RequestErrorf("public key not found"),
			}, nil
		}
		e := protocol.NewInternalErrorf("error deleting access public key: %w",
			err)
		return &bfgapi.AccessPublicKeyDeleteResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &bfgapi.AccessPublicKeyDeleteResponse{}, nil
}

func (s *Server) processBitcoinBlock(ctx context.Context, height uint64) error {
	log.Tracef("Processing Bitcoin block at height %d...", height)

	rbh, err := s.btcClient.RawBlockHeader(ctx, height)
	if err != nil {
		return fmt.Errorf("get block header at height %v: %v",
			height, err)
	}

	// grab the merkle root from the header, I am not sure if there is a
	// better way to do this, I couldn't find one and this works
	merkleRoot := bitcoin.MerkleRootFromBlockHeader(rbh)
	merkleRootEncoded := hex.EncodeToString(merkleRoot)

	btcHeaderHash := chainhash.DoubleHashB(rbh[:])
	btcHeight := height
	btcHeader := rbh

	btcBlock := bfgd.BtcBlock{
		Hash:   btcHeaderHash,
		Header: btcHeader[:],
		Height: btcHeight,
	}

	err = s.db.BtcBlockInsert(ctx, &btcBlock)
	if err != nil {
		// XXX  don't return err here so we keep counting up, need to be smarter
		if errors.Is(err, database.ErrDuplicate) {
			log.Errorf("could not insert btc block: %s", err)
			return nil
		}
	}

	for index := uint64(0); ; index++ {
		txHash, merkleHashes, err := s.btcClient.TransactionAtPosition(ctx,
			height, index)
		if err != nil {
			if errors.Is(err, electrs.ErrNoTxAtPosition) {
				// There is no way to tell how many transactions are
				// in a block, so hopefully we've got them all...
				return nil
			}
			return fmt.Errorf("get transaction at position (height %v, index %v): %w", height, index, err)
		}

		txHashEncoded := hex.EncodeToString(txHash)
		log.Tracef("the raw block header is: %v", rbh)
		log.Tracef("the txhash is: %v", txHashEncoded)
		log.Tracef("the merkle root is: %v", merkleRootEncoded)
		log.Tracef("the merkle hashes are: %v", merkleHashes)
		log.Tracef("Processing Bitcoin block %d, transaction %d...",
			height, index)
		log.Tracef("validating bitcoin tx")

		err = bitcoin.ValidateMerkleRoot(txHashEncoded, merkleHashes,
			uint32(index), merkleRootEncoded)
		if err != nil {
			log.Errorf("merkle root validation failed for tx %s: %s",
				txHashEncoded, err)
		} else {
			log.Infof("btc tx is valid with hash %s", txHashEncoded)
		}

		rtx, err := s.btcClient.RawTransaction(ctx, txHash)
		if err != nil {
			return fmt.Errorf("get raw transaction with txid %x: %w", txHash, err)
		}

		log.Infof("got raw transaction with txid %x", txHash)

		mtx := &wire.MsgTx{}
		if err := mtx.Deserialize(bytes.NewReader(rtx)); err != nil {
			log.Tracef("Failed to deserialize transaction: %v", err)
			continue
		}

		var tl2 *pop.TransactionL2

		for _, txo := range mtx.TxOut {
			tl2, err = pop.ParseTransactionL2FromOpReturn(txo.PkScript)
			if err == nil {
				break
			}
		}

		if tl2 == nil {
			log.Infof("not pop tx found")
			continue
		}

		btcTxIndex := index
		log.Infof("found tl2: %v at position %d", tl2, btcTxIndex)

		publicKeyUncompressed, err := pop.ParsePublicKeyFromSignatureScript(mtx.TxIn[0].SignatureScript)
		if err != nil {
			return fmt.Errorf("could not parse signature script: %s", err)
		}

		popTxIdFull := []byte{}
		popTxIdFull = append(popTxIdFull, txHash...)
		popTxIdFull = append(popTxIdFull, btcHeader[:]...)
		popTxIdFull = binary.AppendUvarint(popTxIdFull, btcTxIndex) // is this correct?

		popTxId := chainhash.DoubleHashB(popTxIdFull)
		log.Infof("hashed pop transaction id: %v from %v", popTxId, popTxIdFull)
		log.Infof("with merkle hashes %v", merkleHashes)

		popBasis := bfgd.PopBasis{
			BtcTxId:             txHash,
			BtcHeaderHash:       btcHeaderHash,
			BtcTxIndex:          &btcTxIndex,
			PopTxId:             popTxId,
			L2KeystoneAbrevHash: tl2.L2Keystone.Hash(),
			BtcRawTx:            rtx,
			PopMinerPublicKey:   publicKeyUncompressed,
			BtcMerklePath:       merkleHashes,
		}

		// first, try to update a pop_basis row with NULL btc fields
		rowsAffected, err := s.db.PopBasisUpdateBTCFields(ctx, &popBasis)
		if err != nil {
			return err
		}

		// if we didn't find any, then we will attempt an insert
		if rowsAffected == 0 {
			err = s.db.PopBasisInsertFull(ctx, &popBasis)

			// if the insert fails due to a duplicate, this means
			// that something else has inserted the row before us
			// (i.e. a race condition), this is ok, as it should
			// have the same values, so we no-op
			if err != nil && !errors.Is(err, database.ErrDuplicate) {
				return err
			}
		}

	}
}

func (s *Server) processBitcoinBlocks(ctx context.Context, start, end uint64) error {
	for i := start; i <= end; i++ {
		if err := s.processBitcoinBlock(ctx, i); err != nil {
			return fmt.Errorf("process bitcoin block at height %d: %w", i, err)
		}
		s.btcHeight = i
	}
	s.queueCheckForInvalidBlocks()
	return nil
}

func (s *Server) trackBitcoin(ctx context.Context) {
	defer s.wg.Done()

	log.Tracef("trackBitcoin")
	defer log.Tracef("trackBitcoin exit")

	btcInterval := 5 * time.Second
	ticker := time.NewTicker(btcInterval)
	printMsg := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Tracef("Checking BTC height...")

			btcHeight, err := s.btcClient.Height(ctx)
			if err != nil {
				if printMsg {
					// XXX add this to prometheus
					log.Errorf("Failed to get Bitcoin height: %v", err)
					printMsg = false
				}
				continue
			}

			s.updateBtcHeightCache(btcHeight)

			printMsg = true
			if s.btcHeight > btcHeight {
				// XXX do we need this check?
				log.Errorf("invalid height: current %v > requested %v",
					btcHeight, s.btcHeight)
				continue
			}
			if btcHeight <= s.btcHeight {
				continue
			}

			log.Infof("Bitcoin block height increased to %v", btcHeight)

			if err := s.processBitcoinBlocks(ctx, s.btcHeight+1, btcHeight); err != nil {
				log.Errorf("Failed to process Bitcoin blocks: %v", err)
				continue
			}
		}
	}
}

type bfgWs struct {
	wg             sync.WaitGroup
	addr           string
	conn           *protocol.WSConn
	sessionId      string
	listenerName   string // "public" or "private"
	requestContext context.Context
	notify         map[notificationId]struct{}
	publicKey      []byte
}

func (s *Server) handleWebsocketPrivateRead(ctx context.Context, bws *bfgWs) {
	defer bws.wg.Done()

	log.Tracef("handleWebsocketPrivateRead: %v", bws.addr)
	defer log.Tracef("handleWebsocketPrivateRead exit: %v", bws.addr)

	for {
		cmd, id, payload, err := bfgapi.Read(ctx, bws.conn)
		if err != nil {
			// Don't log normal close errors.
			var ce websocket.CloseError
			if !errors.As(err, &ce) {
				log.Errorf("handleWebsocketPrivateRead: %v", err)
			} else {
				log.Tracef("handleWebsocketPrivateRead: %v", err)
			}
			return
		}

		// May be too loud.
		log.Tracef("handleWebsocketRead read %v: %v %v %v",
			bws.addr, cmd, id, spew.Sdump(payload))

		switch cmd {
		case bfgapi.CmdPingRequest:
			if err := s.handlePingRequest(ctx, bws, payload, id); err != nil {
				// Terminal error, exit.
				log.Errorf("handleWebsocketRead %v %v %v: %v",
					bws.addr, cmd, id, err)
				return
			}
		case bfgapi.CmdPopTxForL2BlockRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.PopTxsForL2BlockRequest)
				return s.handlePopTxsForL2Block(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdNewL2KeystonesRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.NewL2KeystonesRequest)
				return s.handleNewL2Keystones(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdBTCFinalityByRecentKeystonesRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.BTCFinalityByRecentKeystonesRequest)
				return s.handleBtcFinalityByRecentKeystonesRequest(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdBTCFinalityByKeystonesRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.BTCFinalityByKeystonesRequest)
				return s.handleBtcFinalityByKeystonesRequest(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdAccessPublicKeyCreateRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.AccessPublicKeyCreateRequest)
				return s.handleAccessPublicKeyCreateRequest(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdAccessPublicKeyDeleteRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.AccessPublicKeyDeleteRequest)
				return s.handleAccessPublicKeyDelete(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		default:
			// Terminal error, exit.
			log.Errorf("handleWebsocketRead %v %v %v: unknown command",
				bws.addr, cmd, id)
			return
		}

		s.metrics.rpcCallsTotal.With(prometheus.Labels{
			"listener": "private",
			"command":  string(cmd),
		}).Inc()
	}
}

func (s *Server) handleWebsocketPublicRead(ctx context.Context, bws *bfgWs) {
	defer bws.wg.Done()

	log.Tracef("handleWebsocketPublicRead: %v", bws.addr)
	defer log.Tracef("handleWebsocketPublicRead exit: %v", bws.addr)

	for {
		cmd, id, payload, err := bfgapi.Read(ctx, bws.conn)
		if err != nil {
			// Don't log normal close errors.
			var ce websocket.CloseError
			if !errors.As(err, &ce) {
				log.Debugf("handleWebsocketPublicRead: %v", err)
			} else {
				log.Tracef("handleWebsocketPublicRead: %v", err)
			}
			return
		}

		switch cmd {
		case bfgapi.CmdPingRequest:
			if err := s.handlePingRequest(ctx, bws, payload, id); err != nil {
				// Terminal error, exit.
				log.Errorf("handleWebsocketRead %v %v %v: %v",
					bws.addr, cmd, id, err)
				return
			}
		case bfgapi.CmdL2KeystonesRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.L2KeystonesRequest)
				return s.handleL2KeystonesRequest(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdBitcoinBalanceRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.BitcoinBalanceRequest)
				return s.handleBitcoinBalance(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdBitcoinBroadcastRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.BitcoinBroadcastRequest)
				return s.handleBitcoinBroadcast(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdBitcoinInfoRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.BitcoinInfoRequest)
				return s.handleBitcoinInfo(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		case bfgapi.CmdBitcoinUTXOsRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bfgapi.BitcoinUTXOsRequest)
				return s.handleBitcoinUTXOs(c, msg)
			}

			go s.handleRequest(ctx, bws, id, cmd, handler)
		default:
			// Terminal error, exit.
			log.Errorf("handleWebsocketRead %v %v %v: unknown command",
				bws.addr, cmd, id)
			return
		}

		s.metrics.rpcCallsTotal.With(prometheus.Labels{
			"listener": "public",
			"command":  string(cmd),
		}).Inc()
	}
}

func (s *Server) newSession(bws *bfgWs) (string, error) {
	b := make([]byte, 16)

	for {
		// create random value and encode to string
		_, err := rand.Read(b)
		if err != nil {
			return "", err
		}
		id := hex.EncodeToString(b)

		// does this random value exist? if so try again
		s.mtx.Lock()
		if _, ok := s.sessions[id]; ok {
			s.mtx.Unlock()
			continue
		}
		s.sessions[id] = bws
		s.mtx.Unlock()

		return id, nil
	}
}

func (s *Server) deleteSession(id string) {
	log.Tracef("deleteSession")
	defer log.Tracef("deleteSession exit")

	s.mtx.Lock()
	_, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mtx.Unlock()

	if !ok {
		log.Errorf("deleteSession: id not found in sessions %s", id)
	}
}

func (s *Server) handleWebsocketPrivate(w http.ResponseWriter, r *http.Request) {
	remoteAddr := s.remoteIP(r)
	log.Tracef("handleWebsocketPrivate: %v", remoteAddr)
	defer log.Tracef("handleWebsocketPrivate exit: %v", remoteAddr)

	wao := &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
		OriginPatterns:  []string{"localhost"},
	}

	conn, err := websocket.Accept(w, r, wao)
	if err != nil {
		log.Errorf("Failed to accept websocket connection for %v: %v",
			remoteAddr, err)
		return
	}
	defer conn.Close(websocket.StatusProtocolError, "")

	bws := &bfgWs{
		addr: remoteAddr,
		conn: protocol.NewWSConn(conn),
		notify: map[notificationId]struct{}{
			notifyBtcBlocks:     {},
			notifyBtcFinalities: {},
		},
		listenerName:   "private",
		requestContext: r.Context(),
	}

	if bws.sessionId, err = s.newSession(bws); err != nil {
		log.Errorf("error occurred creating key: %s", err)
		return
	}
	s.metrics.rpcConnections.WithLabelValues("private").Inc()

	defer func() {
		s.deleteSession(bws.sessionId)
		s.metrics.rpcConnections.WithLabelValues("private").Dec()
	}()

	bws.wg.Add(1)
	go s.handleWebsocketPrivateRead(r.Context(), bws)

	// Always ping, required by protocol.
	ping := &bfgapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	log.Tracef("responding with %s", spew.Sdump(ping))
	if err := bfgapi.Write(r.Context(), bws.conn, "0", ping); err != nil {
		log.Errorf("Write: %v", err)
	}

	log.Infof("Unauthenticated connection from %v", remoteAddr)
	bws.wg.Wait()
	log.Infof("Unauthenticated connection terminated from %v", remoteAddr)
}

func (s *Server) handleWebsocketPublic(w http.ResponseWriter, r *http.Request) {
	remoteAddr := s.remoteIP(r)
	log.Tracef("handleWebsocketPublic: %v", remoteAddr)
	defer log.Tracef("handleWebsocketPublic exit: %v", remoteAddr)

	wao := &websocket.AcceptOptions{
		CompressionMode:    websocket.CompressionContextTakeover,
		OriginPatterns:     []string{"localhost:43111"},
		InsecureSkipVerify: true, // XXX sucks but we don't want to whitelist every locahost port
	}

	conn, err := websocket.Accept(w, r, wao)
	if err != nil {
		log.Errorf("Failed to accept websocket connection for %v: %v",
			remoteAddr, err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	bws := &bfgWs{
		addr:           remoteAddr,
		conn:           protocol.NewWSConn(conn),
		listenerName:   "public",
		requestContext: r.Context(),
		notify: map[notificationId]struct{}{
			notifyL2Keystones: {},
		},
	}

	// Must complete handshake in WSHandshakeTimeout.
	hsCtx, hsCancel := context.WithTimeout(context.Background(),
		protocol.WSHandshakeTimeout)
	defer hsCancel()

	authenticator, err := auth.NewSecp256k1AuthServer()
	if err != nil {
		log.Errorf("Handshake failed for %v: %s", bws.addr, err)
		return
	}
	if err := authenticator.HandshakeServer(hsCtx, bws.conn); err != nil {
		log.Errorf("Handshake Server failed for %v: %s", bws.addr, err)
		return
	}

	publicKey := authenticator.RemotePublicKey().SerializeCompressed()
	publicKeyEncoded := hex.EncodeToString(publicKey)
	log.Tracef("successful handshake with public key: %s", publicKeyEncoded)

	userAgent := r.UserAgent()
	if ua := authenticator.RemoteUserAgent(); ua != "" {
		userAgent = ua
	}

	if s.cfg.PublicKeyAuth {
		log.Tracef("will enforce auth")

		// XXX this code should be a function that returns just true
		// and false; that function logs errors.
		exists, err := s.db.AccessPublicKeyExists(hsCtx, &bfgd.AccessPublicKey{
			PublicKey: publicKey,
		})
		if err != nil {
			log.Errorf("error occurred checking if public key exists: %s", err)
			return
		}
		if !exists {
			log.Errorf("unauthorized public key: %s", publicKeyEncoded)
			conn.Close(protocol.PublicKeyAuthError.Code, protocol.PublicKeyAuthError.Reason)
			return
		}
	}

	bws.publicKey = publicKey
	if bws.sessionId, err = s.newSession(bws); err != nil {
		log.Errorf("error occurred creating key: %s", err)
		return
	}
	s.metrics.rpcConnections.WithLabelValues("public").Inc()

	defer func() {
		s.deleteSession(bws.sessionId)
		s.metrics.rpcConnections.WithLabelValues("public").Dec()
	}()

	// Always ping, required by protocol.
	ping := &bfgapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	if err := bfgapi.Write(r.Context(), bws.conn, "0", ping); err != nil {
		log.Errorf("Write: %v", err)
	}

	bws.wg.Add(1)
	go s.handleWebsocketPublicRead(r.Context(), bws)

	log.Infof("Authenticated session %s from %s public key %x (%s)",
		bws.sessionId, remoteAddr, bws.publicKey, userAgent)
	bws.wg.Wait()
	log.Infof("Terminated session %s from %s public key %x (%s)",
		bws.sessionId, remoteAddr, bws.publicKey, userAgent)
}

func (s *Server) handlePingRequest(ctx context.Context, bws *bfgWs, payload any, id string) error {
	log.Tracef("handlePingRequest: %v", bws.addr)
	defer log.Tracef("handlePingRequest exit: %v", bws.addr)

	p, ok := payload.(*bfgapi.PingRequest)
	if !ok {
		return fmt.Errorf("handlePingRequest invalid payload type: %T", payload)
	}
	response := &bfgapi.PingResponse{
		OriginTimestamp: p.Timestamp,
		Timestamp:       time.Now().Unix(),
	}

	log.Tracef("responding with %v", spew.Sdump(response))

	if err := bfgapi.Write(ctx, bws.conn, id, response); err != nil {
		return fmt.Errorf("handlePingRequest write: %v %v",
			bws.addr, err)
	}
	return nil
}

func (s *Server) handlePopTxsForL2Block(ctx context.Context, ptl2 *bfgapi.PopTxsForL2BlockRequest) (any, error) {
	log.Tracef("handlePopTxsForL2Block")
	defer log.Tracef("handlePopTxsForL2Block exit")

	hash := hemi.HashSerializedL2KeystoneAbrev(ptl2.L2Block)
	var h [32]byte
	copy(h[:], hash)

	response := &bfgapi.PopTxsForL2BlockResponse{}

	popTxs, err := s.db.PopBasisByL2KeystoneAbrevHash(ctx, h, true, ptl2.Page)
	if err != nil {
		e := protocol.NewInternalErrorf("error getting pop basis: %w", err)
		return &bfgapi.PopTxsForL2BlockResponse{
			Error: e.ProtocolError(),
		}, e
	}

	for k := range popTxs {
		response.PopTxs = append(response.PopTxs, bfgapi.PopTx{
			BtcTxId:             api.ByteSlice(popTxs[k].BtcTxId),
			BtcRawTx:            api.ByteSlice(popTxs[k].BtcRawTx),
			BtcHeaderHash:       api.ByteSlice(popTxs[k].BtcHeaderHash),
			BtcTxIndex:          popTxs[k].BtcTxIndex,
			BtcMerklePath:       popTxs[k].BtcMerklePath,
			PopTxId:             api.ByteSlice(popTxs[k].PopTxId),
			PopMinerPublicKey:   api.ByteSlice(popTxs[k].PopMinerPublicKey),
			L2KeystoneAbrevHash: api.ByteSlice(popTxs[k].L2KeystoneAbrevHash),
		})
	}

	return response, nil
}

func (s *Server) handleBtcFinalityByRecentKeystonesRequest(ctx context.Context, bfrk *bfgapi.BTCFinalityByRecentKeystonesRequest) (any, error) {
	log.Tracef("handleBtcFinalityByRecentKeystonesRequest")
	defer log.Tracef("handleBtcFinalityByRecentKeystonesRequest exit")

	finalities, err := s.db.L2BTCFinalityMostRecent(ctx, bfrk.NumRecentKeystones)
	if err != nil {
		e := protocol.NewInternalErrorf("error getting finality: %w", err)
		return &bfgapi.BTCFinalityByRecentKeystonesResponse{
			Error: e.ProtocolError(),
		}, e
	}

	apiFinalities := make([]hemi.L2BTCFinality, 0, len(finalities))
	for k, finality := range finalities {
		apiFinality, err := hemi.L2BTCFinalityFromBfgd(
			&finality,
			finality.BTCTipHeight,
			finality.EffectiveHeight,
		)
		if err != nil {
			e := protocol.NewInternalErrorf("error getting finality (%v): %w",
				k, err)
			return &bfgapi.BTCFinalityByRecentKeystonesResponse{
				Error: e.ProtocolError(),
			}, e
		}
		apiFinalities = append(apiFinalities, *apiFinality)
	}

	return &bfgapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: apiFinalities,
	}, nil
}

func (s *Server) handleBtcFinalityByKeystonesRequest(ctx context.Context, bfkr *bfgapi.BTCFinalityByKeystonesRequest) (any, error) {
	log.Tracef("handleBtcFinalityByKeystonesRequest")
	defer log.Tracef("handleBtcFinalityByKeystonesRequest exit")

	l2KeystoneAbrevHashes := make([]database.ByteArray, 0, len(bfkr.L2Keystones))
	for _, l := range bfkr.L2Keystones {
		a := hemi.L2KeystoneAbbreviate(l)
		l2KeystoneAbrevHashes = append(l2KeystoneAbrevHashes, a.Hash())
	}

	finalities, err := s.db.L2BTCFinalityByL2KeystoneAbrevHash(
		ctx,
		l2KeystoneAbrevHashes,
		bfkr.Page,
		bfkr.Limit,
	)
	if err != nil {
		e := protocol.NewInternalErrorf("l2 keystones: %w", err)
		return &bfgapi.BTCFinalityByKeystonesResponse{
			Error: e.ProtocolError(),
		}, e
	}

	apiFinalities := make([]hemi.L2BTCFinality, 0, len(finalities))
	for _, finality := range finalities {
		apiFinality, err := hemi.L2BTCFinalityFromBfgd(
			&finality,
			finality.BTCTipHeight,
			finality.EffectiveHeight,
		)
		if err != nil {
			e := protocol.NewInternalErrorf("l2 btc finality: %w", err)
			return &bfgapi.BTCFinalityByKeystonesResponse{
				Error: e.ProtocolError(),
			}, e
		}
		apiFinalities = append(apiFinalities, *apiFinality)
	}

	return &bfgapi.BTCFinalityByKeystonesResponse{
		L2BTCFinalities: apiFinalities,
	}, nil
}

func (s *Server) getL2KeystonesCache() []hemi.L2Keystone {
	log.Tracef("getL2KeystonesCache")
	defer log.Tracef("getL2KeystonesCache exit")

	s.mtx.Lock()
	defer s.mtx.Unlock()

	results := make([]hemi.L2Keystone, len(s.l2keystonesCache))
	copy(results, s.l2keystonesCache)

	return results
}

func (s *Server) refreshL2KeystoneCache(ctx context.Context) {
	log.Tracef("refreshL2KeystoneCache")
	defer log.Tracef("refreshL2KeystoneCache exit")

	s.mtx.Lock()
	defer s.mtx.Unlock()

	results, err := s.db.L2KeystonesMostRecentN(ctx, 100)
	if err != nil {
		log.Errorf("error getting keystones %v", err)
		return
	}

	l2Keystones := make([]hemi.L2Keystone, 0, len(results))
	for _, v := range results {
		l2Keystones = append(l2Keystones, hemi.L2Keystone{
			Version:            uint8(v.Version),
			L1BlockNumber:      v.L1BlockNumber,
			L2BlockNumber:      v.L2BlockNumber,
			ParentEPHash:       api.ByteSlice(v.ParentEPHash),
			PrevKeystoneEPHash: api.ByteSlice(v.PrevKeystoneEPHash),
			StateRoot:          api.ByteSlice(v.StateRoot),
			EPHash:             api.ByteSlice(v.EPHash),
		})
	}

	s.l2keystonesCache = l2Keystones
}

func (s *Server) handleL2KeystonesRequest(ctx context.Context, l2kr *bfgapi.L2KeystonesRequest) (any, error) {
	log.Tracef("handleL2KeystonesRequest")
	defer log.Tracef("handleL2KeystonesRequest exit")

	results := []hemi.L2Keystone{}
	for i, v := range s.getL2KeystonesCache() {
		if uint64(i) < l2kr.NumL2Keystones {
			results = append(results, v)
		} else {
			break
		}
	}

	return &bfgapi.L2KeystonesResponse{
		L2Keystones: results,
	}, nil
}

func writeNotificationResponse(bws *bfgWs, response any) {
	if err := bfgapi.Write(bws.requestContext, bws.conn, "", response); err != nil {
		log.Errorf("handleBtcFinalityNotification write: %v %v", bws.addr, err)
	}
}

func (s *Server) handleBtcFinalityNotification() error {
	log.Tracef("handleBtcFinalityNotification")
	defer log.Tracef("handleBtcFinalityNotification exit")

	s.mtx.Lock()
	for _, bws := range s.sessions {
		if _, ok := bws.notify[notifyBtcFinalities]; !ok {
			continue
		}
		go writeNotificationResponse(bws, &bfgapi.BTCFinalityNotification{})
	}
	s.mtx.Unlock()

	return nil
}

func (s *Server) handleBtcBlockNotification() error {
	log.Tracef("handleBtcBlockNotification")
	defer log.Tracef("handleBtcBlockNotification exit")

	s.mtx.Lock()
	for _, bws := range s.sessions {
		if _, ok := bws.notify[notifyBtcBlocks]; !ok {
			continue
		}
		go writeNotificationResponse(bws, &bfgapi.BTCNewBlockNotification{})
	}
	s.mtx.Unlock()

	return nil
}

func (s *Server) handleL2KeystonesNotification() error {
	log.Tracef("handleL2KeystonesNotification")
	defer log.Tracef("handleL2KeystonesNotification exit")

	s.mtx.Lock()
	for _, bws := range s.sessions {
		if _, ok := bws.notify[notifyL2Keystones]; !ok {
			continue
		}
		go writeNotificationResponse(bws, &bfgapi.L2KeystonesNotification{})
	}
	s.mtx.Unlock()

	return nil
}

func hemiL2KeystoneToDb(l2ks hemi.L2Keystone) bfgd.L2Keystone {
	return bfgd.L2Keystone{
		Hash:               hemi.L2KeystoneAbbreviate(l2ks).Hash(),
		Version:            uint32(l2ks.Version),
		L1BlockNumber:      l2ks.L1BlockNumber,
		L2BlockNumber:      l2ks.L2BlockNumber,
		ParentEPHash:       database.ByteArray(l2ks.ParentEPHash),
		PrevKeystoneEPHash: database.ByteArray(l2ks.PrevKeystoneEPHash),
		StateRoot:          database.ByteArray(l2ks.StateRoot),
		EPHash:             database.ByteArray(l2ks.EPHash),
	}
}

func hemiL2KeystonesToDb(l2ks []hemi.L2Keystone) []bfgd.L2Keystone {
	dbks := make([]bfgd.L2Keystone, 0, len(l2ks))
	for k := range l2ks {
		dbks = append(dbks, hemiL2KeystoneToDb(l2ks[k]))
	}
	return dbks
}

func (s *Server) handleNewL2Keystones(ctx context.Context, nlkr *bfgapi.NewL2KeystonesRequest) (any, error) {
	log.Tracef("handleNewL2Keystones")
	defer log.Tracef("handleNewL2Keystones exit")

	response := bfgapi.NewL2KeystonesResponse{}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ks := hemiL2KeystonesToDb(nlkr.L2Keystones)
		err := s.db.L2KeystonesInsert(ctx, ks)
		if err != nil {
			log.Errorf("error saving keystone %v", err)
			return
		}

		s.refreshL2KeystoneCache(ctx)
	}()

	return response, nil
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

func handle(service string, mux *http.ServeMux, pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandleFunc(pattern, handler)
	log.Infof("handle (%v): %v", service, pattern)
}

func (s *Server) handleStateUpdates(table string, action string, payload, payloadOld interface{}) {
	ctx := context.Background()

	// get the last known canonical chain height
	s.mtx.RLock()
	heightBefore := s.canonicalChainHeight
	s.mtx.RUnlock()

	// get the current canoncial chain height from the db
	heightAfter, err := s.db.BtcBlockCanonicalHeight(ctx)
	if err != nil {
		log.Errorf("error occurred getting canonical height: %s", err)
	}

	// the canonical chain grew from the last insert, then we assume there is a
	// new block on the canonical chain, and finalities of existing blocks
	// will change
	if heightAfter > heightBefore {
		go s.handleBtcFinalityNotification()
		go s.handleBtcBlockNotification()
	}

	s.mtx.Lock()
	s.canonicalChainHeight = heightAfter
	s.mtx.Unlock()
}

func (s *Server) handleAccessPublicKeys(table string, action string, payload, payloadOld interface{}) {
	log.Tracef("received payloads: %v, %v", payload, payloadOld)

	if action != "DELETE" {
		return
	}

	accessPublicKey, ok := payloadOld.(*bfgd.AccessPublicKey)
	if !ok {
		log.Errorf("incorrect type %T", payload)
	}

	if accessPublicKey == nil {
		return
	}

	s.mtx.Lock()
	for _, v := range s.sessions {
		// if public key does not exist on session, it's not an authenticated
		// session so we don't close it because it didn't use a public key
		if len(v.publicKey) == 0 {
			continue
		}

		// the database value will be passed with \x prefixed to denote hex
		// encoding, ensure that the session string does for an equal comparison
		sessionPublicKeyEncoded := fmt.Sprintf("\\x%s", hex.EncodeToString(v.publicKey))
		if sessionPublicKeyEncoded == accessPublicKey.PublicKeyEncoded {
			v.conn.CloseStatus(websocket.StatusProtocolError, "killed")
		}
	}
	s.mtx.Unlock()
}

func (s *Server) handleL2KeystonesChange(table string, action string, payload, payloadOld any) {
	go s.handleL2KeystonesNotification()
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return errors.New("bfg already running")
	}
	defer s.testAndSetRunning(false)

	// XXX this funciton seems a bit heavy. Trim it by moving functionality to functions.
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// Connect to db.
	// XXX should we reconnect?
	var err error
	s.db, err = postgres.New(ctx, s.cfg.PgURI)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer s.db.Close()

	if s.btcHeight, err = s.db.BtcBlockCanonicalHeight(ctx); err != nil {
		return err
	}

	// if there is no height in the db, check the config
	if s.btcHeight == 0 {
		s.btcHeight = s.cfg.BTCStartHeight
		log.Infof("received height of 0 from the db, height of %v from config",
			s.cfg.BTCStartHeight)
	}

	// if the config doesn't set a height, error
	if s.btcHeight == 0 {
		return errors.New("could not determine btc start height")
	}
	log.Debugf("resuming at height %d", s.btcHeight)

	// Database notifications
	btcBlocksPayload, ok := bfgd.NotificationPayload(bfgd.NotificationBtcBlocks)
	if !ok {
		return fmt.Errorf("could not obtain type: %v", bfgd.NotificationBtcBlocks)
	}
	// XXX rename handler function and don't be generic
	if err := s.db.RegisterNotification(ctx, bfgd.NotificationBtcBlocks,
		s.handleStateUpdates, btcBlocksPayload); err != nil {
		return err
	}

	accessPublicKeysPayload, ok := bfgd.NotificationPayload(bfgd.NotificationAccessPublicKeyDelete)
	if !ok {
		return fmt.Errorf("could not obtain type: %v", bfgd.NotificationAccessPublicKeyDelete)
	}
	if err := s.db.RegisterNotification(ctx, bfgd.NotificationAccessPublicKeyDelete,
		s.handleAccessPublicKeys, accessPublicKeysPayload); err != nil {
		return err
	}

	l2KeystonesPayload, ok := bfgd.NotificationPayload(bfgd.NotificationL2Keystones)
	if !ok {
		return fmt.Errorf("could not obtain type: %v", bfgd.NotificationL2Keystones)
	}
	if err := s.db.RegisterNotification(ctx, bfgd.NotificationL2Keystones,
		s.handleL2KeystonesChange, l2KeystonesPayload); err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-time.After(1 * time.Minute):
				log.Infof("sending notifications of l2 keystones")
				go s.handleL2KeystonesNotification()
			case <-ctx.Done():
				return
			}
		}
	}()

	for _, p := range []bool{true, false} {
		for range 4 {
			s.wg.Add(1)
			go s.bitcoinBroadcastWorker(ctx, p)
		}
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
				s.refreshL2KeystoneCache(ctx)
			}
		}
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Minute):
				if err := s.db.BtcTransactionBroadcastRequestTrim(ctx); err != nil {
					log.Errorf("error trimming old requests: %v", err)
				}

			}
		}
	}()

	// Setup websockets and HTTP routes
	privateMux := s.server
	publicMux := s.publicServer

	handle("bfgpriv", privateMux, bfgapi.RouteWebsocketPrivate, s.handleWebsocketPrivate)
	handle("bfgpub", publicMux, bfgapi.RouteWebsocketPublic, s.handleWebsocketPublic)

	// Parse remote IP headers.
	s.remoteIPHeaders = make([]string, len(s.cfg.RemoteIPHeaders))
	for i, h := range s.cfg.RemoteIPHeaders {
		s.remoteIPHeaders[i] = http.CanonicalHeaderKey(h)
	}

	// Parse trusted proxies.
	s.trustedProxies, err = parseTrustedProxies(s.cfg.TrustedProxies)
	if err != nil {
		return fmt.Errorf("parse trusted proxies: %w", err)
	}

	publicHttpServer := &http.Server{
		Addr:        s.cfg.PublicListenAddress,
		Handler:     publicMux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	publicHttpErrCh := make(chan error)

	privateHttpServer := &http.Server{
		Addr:        s.cfg.PrivateListenAddress,
		Handler:     privateMux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	privateHttpErrCh := make(chan error)

	go func() {
		log.Infof("Listening: %v", s.cfg.PrivateListenAddress)
		privateHttpErrCh <- privateHttpServer.ListenAndServe()
	}()

	go func() {
		log.Infof("Listening: %v", s.cfg.PublicListenAddress)
		publicHttpErrCh <- publicHttpServer.ListenAndServe()
	}()

	defer func() {
		if err := privateHttpServer.Shutdown(ctx); err != nil {
			log.Errorf("http private Server exit: %v", err)
			return
		}
		log.Infof("private RPC Server shutdown cleanly")
	}()

	defer func() {
		if err := publicHttpServer.Shutdown(ctx); err != nil {
			log.Errorf("http public Server exit: %v", err)
			return
		}
		log.Infof("public RPC Server shutdown cleanly")
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
			return fmt.Errorf("create prometheus server: %w", err)
		}
		cs := append(
			append(s.metrics.collectors(), s.btcClient.Metrics()...),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: promNamespace,
				Name:      "running",
				Help:      "Whether the BFG service is running",
			}, s.promRunning),
		)
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

	defer func() {
		if err := s.btcClient.Close(); err != nil {
			log.Errorf("bitcoin client closed with error: %v", err)
			return
		}
		log.Errorf("bitcoin client clean shutdown")
	}()

	s.wg.Add(1)
	go s.trackBitcoin(ctx)
	go s.invalidBlockChecker(ctx)

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-privateHttpErrCh:
	case err = <-publicHttpErrCh:
	}
	cancel()

	log.Infof("bfg service shutting down")
	s.wg.Wait()
	log.Infof("bfg service clean shutdown")

	return err
}

// remoteIP returns the remote client IP address for the http request.
func (s *Server) remoteIP(req *http.Request) string {
	remoteAddr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	remoteIP := net.ParseIP(remoteAddr)
	if remoteIP == nil {
		return req.RemoteAddr
	}

	// If the remote IP is a trusted proxy, attempt parsing remote IP headers.
	if s.isTrustedProxy(remoteIP) {
		for _, headerName := range s.remoteIPHeaders {
			values := req.Header.Values(headerName)
			if ip, valid := s.parseForwardedHeader(values); valid {
				return ip
			}
		}
	}

	return remoteIP.String()
}

// parseForwardedHeader parses the given value of an X-Forwarded-For header and
// returns the client IP address.
//
// The header value is searched in reverse order, skipping all addresses that
// are trusted proxies. The first untrusted address is returned.
func (s *Server) parseForwardedHeader(values []string) (string, bool) {
	if len(values) < 1 {
		return "", false
	}

	// There can be multiple headers present in the request, and the IP
	// addresses in the headers must be treated as a single list of IP
	// addresses, starting with the first IP of the first header, and
	// ending with the last IP of the last header.
	var addrs []string
	for _, v := range values {
		addrs = append(addrs, strings.Split(v, ",")...)
	}

	for i := len(addrs) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(addrs[i])
		ip := net.ParseIP(ipStr)
		if ip == nil {
			// Invalid header value.
			return "", false
		}

		if i == 0 || !s.isTrustedProxy(ip) {
			// Return last value or untrusted address.
			return ipStr, true
		}
	}

	return "", false
}

// isTrustedProxy returns whether the IP address is included in the list of
// trusted proxies.
func (s *Server) isTrustedProxy(ip net.IP) bool {
	for _, cidr := range s.trustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// parseTrustedProxies parses a list of trusted proxy IP addresses or CIDR
// ranges.
func parseTrustedProxies(trustedProxies []string) ([]*net.IPNet, error) {
	if len(trustedProxies) < 1 {
		return nil, nil
	}

	cidr := make([]*net.IPNet, len(trustedProxies))
	for i, trustedProxy := range trustedProxies {
		var err error
		if !strings.Contains(trustedProxy, "/") {
			// Not a CIDR, create a CIDR representing the single address.
			trustedProxy, err = singleCIDR(trustedProxy)
			if err != nil {
				return nil, err
			}
		}

		// Parse CIDR.
		_, cidr[i], err = net.ParseCIDR(trustedProxy)
		if err != nil {
			return nil, err
		}
	}

	return cidr, nil
}

// singleCIDR returns a CIDR representing a single IP address.
func singleCIDR(ip string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if ipv4 := parsedIP.To4(); ipv4 != nil {
		// Use 4-byte representation of IP address if using IPv4.
		parsedIP = ipv4
	}
	if parsedIP == nil {
		return "", &net.ParseError{Type: "IP address", Text: ip}
	}

	switch len(parsedIP) {
	case net.IPv4len:
		ip += "/32"
	case net.IPv6len:
		ip += "/128"
	}
	return ip, nil
}
