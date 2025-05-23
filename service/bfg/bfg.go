// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfg

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
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
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
	"github.com/hemilabs/heminetwork/version"
)

// XXX this code needs to be a bit smarter when syncing bitcoin. We should
// return a "not ready" error when that is the case.

type notificationId string

const (
	logLevel = "INFO"
	appName  = "bfg" // Prometheus

	notifyBtcBlocks     notificationId = "btc_blocks"
	notifyBtcFinalities notificationId = "btc_finalities"
	notifyL2Keystones   notificationId = "l2_keystones"
)

var (
	log = loggo.GetLogger(appName)

	ErrBTCPrivateKeyMissing = errors.New("you must specify a BTC private key")
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

func NewDefaultConfig() *Config {
	return &Config{
		EXBTCAddress:         "localhost:18001",
		EXBTCInitialConns:    5,
		EXBTCMaxConns:        100,
		PrivateListenAddress: ":8080",
		PrometheusNamespace:  appName,
		PublicListenAddress:  ":8383",
		RequestLimit:         bfgapi.DefaultRequestLimit,
		RequestTimeout:       bfgapi.DefaultRequestTimeout,
		BFGURL:               "",
		BTCWindowFromTip:     1000,
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

// Wrap for calling bfg commands
type bfgCmd struct {
	msg any
	ch  chan any
}

type Config struct {
	EXBTCAddress             string
	EXBTCInitialConns        int
	EXBTCMaxConns            int
	PrivateListenAddress     string
	PublicListenAddress      string
	LogLevel                 string
	PgURI                    string
	PrometheusListenAddress  string
	PrometheusNamespace      string
	PprofListenAddress       string
	RequestLimit             int
	RequestTimeout           int // in seconds
	RemoteIPHeaders          []string
	TrustedProxies           []string
	BFGURL                   string
	BTCPrivateKey            string
	DisablePublicConns       bool
	BaselineL2BlockHeight    int64
	BaselineL2BlockTimestamp int64
	BTCWindowFromTip         uint64
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

	l2keystonesCache []hemi.L2Keystone

	btcHeightCache uint64

	bfgWG sync.WaitGroup // wait group for connecting to other bfgs

	holdoffTimeout time.Duration // Time in between connections attempt to BFG
	bfgCallTimeout time.Duration

	bfgCmdCh chan bfgCmd // commands to send to bfg

	btcPrivateKey *secp256k1.PrivateKey
}

// metrics stores prometheus metrics.
type metrics struct {
	canonicalHeight  prometheus.Gauge         // Total number of PoP transaction broadcasts
	popBroadcasts    prometheus.Counter       // Total number of PoP transaction broadcasts
	rpcCallsTotal    *prometheus.CounterVec   // Total number of successful RPC commands
	rpcCallsDuration *prometheus.HistogramVec // RPC calls duration in seconds
	rpcConnections   *prometheus.GaugeVec     // Number of active RPC WebSocket connections
}

// newMetrics returns a new metrics struct containing prometheus collectors.
func newMetrics(cfg *Config) *metrics {
	// When adding a metric here, remember to add it to metrics.collectors().
	return &metrics{
		canonicalHeight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: cfg.PrometheusNamespace,
			Name:      "canonical_height",
			Help:      "Last measured canonical height.",
		}),
		popBroadcasts: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: cfg.PrometheusNamespace,
			Name:      "pop_broadcasts_total",
			Help:      "Total number of PoP transaction broadcasts",
		}),
		rpcCallsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: cfg.PrometheusNamespace,
				Name:      "rpc_calls_total",
				Help:      "Total number of successful RPC commands",
			},
			[]string{"listener", "command"},
		),
		rpcCallsDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: cfg.PrometheusNamespace,
				Name:      "rpc_calls_duration_seconds",
				Help:      "RPC call durations in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"listener", "command"},
		),
		rpcConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: cfg.PrometheusNamespace,
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
		m.canonicalHeight,
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

	if cfg.BTCPrivateKey == "" && cfg.BFGURL != "" {
		return nil, errors.Join(
			ErrBTCPrivateKeyMissing,
			errors.New("btc private key required when connecting to another BFG"),
		)
	}
	s := &Server{
		cfg:            cfg,
		requestLimiter: make(chan bool, cfg.RequestLimit),
		server:         http.NewServeMux(),
		publicServer:   http.NewServeMux(),
		metrics:        newMetrics(cfg),
		sessions:       make(map[string]*bfgWs),
		holdoffTimeout: 6 * time.Second,
		bfgCallTimeout: 20 * time.Second,
		bfgCmdCh:       make(chan bfgCmd),
	}
	for range cfg.RequestLimit {
		s.requestLimiter <- true
	}

	var err error

	if cfg.BTCPrivateKey != "" {
		s.btcPrivateKey, err = bitcoin.PrivKeyFromHexString(cfg.BTCPrivateKey)
		if err != nil {
			return nil, err
		}
	}

	// XXX this is not right. NewServer should always return. The call to
	// electrs.NewClient should be in Run. Or, electrs should be a service
	// so that we can mirror the New/Run paradigm, the New/Run paradigm,
	s.btcClient, err = electrs.NewClient(cfg.EXBTCAddress, &electrs.ClientOptions{
		InitialConnections:  cfg.EXBTCInitialConns,
		MaxConnections:      cfg.EXBTCMaxConns,
		PrometheusNamespace: cfg.PrometheusNamespace,
	})
	if err != nil {
		return nil, fmt.Errorf("create electrs client: %w", err)
	}

	// We could use a PGURI verification here.

	return s, nil
}

// handleRequest is called as a go routine to handle a long-lived command.
func (s *Server) handleRequest(pctx context.Context, bws *bfgWs, wsid string, cmd protocol.Command, handler func(ctx context.Context) (any, error)) {
	log.Tracef("handleRequest: %v", bws.addr)
	defer log.Tracef("handleRequest exit: %v", bws.addr)

	ctx, cancel := context.WithTimeout(pctx, time.Duration(s.cfg.RequestTimeout)*time.Second)
	defer cancel()

	select {
	case <-s.requestLimiter:
	default:
		log.Tracef("Request limiter hit %v: %v", bws.addr, cmd)
		select {
		case <-s.requestLimiter:
		case <-ctx.Done():
			log.Debugf("request context done %v: %v", bws.addr, cmd)
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

func (s *Server) handleOneBroadcastRequest(pctx context.Context, highPriority bool) {
	ctx, cancel := context.WithTimeout(pctx, 5*time.Second)
	defer cancel()

	serializedTx, err := s.db.BtcTransactionBroadcastRequestGetNext(ctx, highPriority)
	if err != nil {
		log.Errorf("error getting next broadcast request: %v", err)

		// if there is a communication error, backoff a bit
		select {
		case <-time.After(1 * time.Second):
			return
		case <-ctx.Done():
			return
		}
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

	// attempt to insert the abbreviated keystone, this is in case we have
	// not heard of this keystone from op node yet
	if err := s.db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{
		hemiL2KeystoneAbrevToDb(*tl2.L2Keystone),
	}); err != nil {
		log.Infof("could not insert l2 keystone: %s", err)
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

	log.Infof("successfully broadcast tx %s, for l2 keystone %s", mb.TxID(), tl2.L2Keystone.Hash())
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

var ErrAlreadyProcessed = errors.New("already processed bitcoin block")

func (s *Server) processBitcoinBlock(ctx context.Context, height uint64) error {
	log.Tracef("Processing Bitcoin block at height %d...", height)

	netCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	rbh, err := s.btcClient.RawBlockHeader(netCtx, height)
	cancel()
	if err != nil {
		return fmt.Errorf("get block header at height %v: %w", height, err)
	}

	// grab the merkle root from the header, I am not sure if there is a
	// better way to do this, I couldn't find one and this works
	merkleRoot := bitcoin.MerkleRootFromBlockHeader(rbh)
	merkleRootEncoded := hex.EncodeToString(merkleRoot)

	btcHeaderHash := chainhash.DoubleHashB(rbh[:])
	btcHeight := height
	btcHeader := rbh

	btcBlockTmpChk, err := s.db.BtcBlockByHash(ctx, [32]byte(btcHeaderHash))
	if err != nil && !errors.Is(err, database.ErrNotFound) {
		return err
	}

	// block with hash is already at height, no-reorg
	if btcBlockTmpChk != nil && btcBlockTmpChk.Height == btcHeight {
		return fmt.Errorf("already processed block block: %w", ErrAlreadyProcessed)
	}

	btcBlock := bfgd.BtcBlock{
		Hash:   btcHeaderHash,
		Header: btcHeader[:],
		Height: btcHeight,
	}

	// these might get quite large; we store all found keystones and
	// pop bases here to insert at the end
	// we will likely find many of the same keystones so store them in a map
	// to remove duplicates
	l2Keystones := map[string]bfgd.L2Keystone{}
	popBases := []bfgd.PopBasis{}

	for index := uint64(0); ; index++ {
		log.Tracef("calling tx at pos")
		netCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		txHash, merkleHashes, err := s.btcClient.TransactionAtPosition(netCtx,
			height, index)
		cancel()
		log.Tracef("done calling tx as pos")
		if err != nil {
			if errors.Is(err, electrs.ErrNoTxAtPosition) || strings.HasSuffix(err.Error(), "no tx at position") {
				// There is no way to tell how many transactions are
				// in a block, so hopefully we've got them all...
				break
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

		netCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		rtx, err := s.btcClient.RawTransaction(netCtx, txHash)
		cancel()
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

		l2kdb := hemiL2KeystoneAbrevToDb(*tl2.L2Keystone)
		l2Keystones[hex.EncodeToString(l2kdb.Hash)] = l2kdb

		publicKeyUncompressed, err := pop.ParsePublicKeyFromSignatureScript(mtx.TxIn[0].SignatureScript)
		if err != nil {
			log.Errorf("could not parse signature script: %w", err)
			continue
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
			L2KeystoneAbrevHash: tl2.L2Keystone.HashB(),
			BtcRawTx:            rtx,
			PopMinerPublicKey:   publicKeyUncompressed,
			BtcMerklePath:       merkleHashes,
		}

		popBases = append(popBases, popBasis)
	}

	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return err
	}

	defer func() {
		err := s.db.Rollback(tx)
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Errorf("processBitcoinBlock could not rollback db tx: %v",
				err)
			return
		}
	}()

	rowsAffected, err := s.db.BtcBlockReplaceWithTx(ctx, tx, &btcBlock)
	if err != nil {
		return fmt.Errorf("error replacing bitcoin block: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no rows affected: %w", ErrAlreadyProcessed)
	}

	// this for loop seems weird but its used to check errors per keystone
	for _, l2Keystone := range l2Keystones {
		// attempt to insert the abbreviated keystone, this is in case we have
		// not heard of this keystone from op node yet
		if err := s.db.L2KeystonesInsertWithTx(ctx, tx, []bfgd.L2Keystone{l2Keystone}); err != nil {
			// this is not necessarily an error, should it be trace?
			log.Infof("could not insert l2 keystone: %s", err)
		}
	}

	for _, popBasis := range popBases {
		// first, try to update a pop_basis row with NULL btc fields
		rowsAffected, err := s.db.PopBasisUpdateBTCFieldsWithTx(ctx, tx, &popBasis)
		if err != nil {
			return err
		}

		// if we didn't find any, then we will attempt an insert
		if rowsAffected == 0 {
			err = s.db.PopBasisInsertFullWithTx(ctx, tx, &popBasis)

			// if the insert fails due to a duplicate, this means
			// that something else has inserted the row before us
			// (i.e. a race condition), this is ok, as it should
			// have the same values, so we no-op
			if err != nil && !errors.Is(err, database.ErrDuplicate) {
				return err
			}
		}
	}

	if err := s.db.Commit(tx); err != nil {
		return err
	}

	return nil
}

func (s *Server) trackBitcoin(ctx context.Context) {
	defer s.wg.Done()

	log.Tracef("trackBitcoin")
	defer log.Tracef("trackBitcoin exit")

	// upon startup we walk every block between the tip and our
	// configured start block.  IMPORTANT NOTE: we ONLY process
	// transactions in blocks that we have not seen, so whilst we
	// walk quite a few blocks, most will be essentially no-ops
	// except for when you have an empty database table
	initialWalk := true

	btcInterval := 5 * time.Second
	ticker := time.NewTicker(btcInterval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Tracef("Checking BTC height...")

			netCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			btcHeight, err := s.btcClient.Height(netCtx)
			cancel()
			if err != nil {
				// XXX add this to prometheus
				log.Errorf("Failed to get Bitcoin height: %v", err)
				continue
			}

			s.updateBtcHeightCache(btcHeight)

			err = s.walkChain(ctx, btcHeight, !initialWalk)
			if err != nil {
				log.Errorf("could not walk chain: %s", err)
				continue
			}

			// after we have done the initial walk with no errors,
			// in the future we only walk back until a block that we've seen
			initialWalk = false

			log.Tracef("will trim blocks lower than %d", btcHeight-s.cfg.BTCWindowFromTip)

			rowsAffected, err := s.db.BtcBlocksTrimLowerThan(ctx, btcHeight-s.cfg.BTCWindowFromTip)
			if err != nil {
				log.Errorf("could not trim blocks: %s", err)
				continue
			}

			log.Tracef("trimmed %d blocks from db", rowsAffected)
		}
	}
}

func (s *Server) walkChain(ctx context.Context, tip uint64, exitFast bool) error {
	log.Tracef("walkChain")
	defer log.Tracef("walkChain exit")

	windowStart := tip - s.cfg.BTCWindowFromTip

	log.Tracef("starting to walk chain; tip=%d, windowStart=%d, exitFast=%b", tip, windowStart, exitFast)
	for tip >= windowStart {
		log.Tracef("walkChain progress; processing block at height %d", tip)
		err := s.processBitcoinBlock(ctx, tip)
		if errors.Is(err, ErrAlreadyProcessed) {
			log.Tracef("block known at height %d", tip)

			// if we have already seen the block, and the caller wishes
			// to exit on first known block, do so
			if exitFast {
				return nil
			}
		} else if err != nil {
			return err
		}

		tip--
	}

	return nil
}

type bfgWs struct {
	wg             sync.WaitGroup
	addr           string
	conn           *protocol.WSConn
	sessionId      string
	listenerName   string          // "public" or "private"
	requestContext context.Context // XXX get rid of this
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
		InsecureSkipVerify: true, // XXX sucks but we don't want to whitelist every localhost port
	}

	conn, err := websocket.Accept(w, r, wao)
	if err != nil {
		log.Errorf("Failed to accept websocket connection for %v: %v",
			remoteAddr, err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	if s.cfg.DisablePublicConns {
		_ = conn.Close(protocol.ErrPublicKeyAuth.Code, protocol.ErrPublicKeyAuth.Reason)
		return
	}

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
	hsCtx, hsCancel := context.WithTimeout(r.Context(), protocol.WSHandshakeTimeout)
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
		return fmt.Errorf("handlePingRequest write: %v %w", bws.addr, err)
	}
	return nil
}

func (s *Server) handlePopTxsForL2Block(ctx context.Context, ptl2 *bfgapi.PopTxsForL2BlockRequest) (any, error) {
	log.Tracef("handlePopTxsForL2Block")
	defer log.Tracef("handlePopTxsForL2Block exit")

	hash := hemi.HashSerializedL2KeystoneAbrev(ptl2.L2Block)
	var h [32]byte
	copy(h[:], hash[:])

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

	finalities, err := s.db.L2BTCFinalityMostRecent(ctx, bfrk.NumRecentKeystones, s.l2KeystoneIgnoreAfter())
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
		l2KeystoneAbrevHashes = append(l2KeystoneAbrevHashes, a.HashB())
	}

	finalities, err := s.db.L2BTCFinalityByL2KeystoneAbrevHash(
		ctx,
		l2KeystoneAbrevHashes,
		s.l2KeystoneIgnoreAfter(),
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

	results, err := s.db.L2KeystonesMostRecentN(ctx, 100, 0)
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
		log.Tracef("handleBtcFinalityNotification write: %v %v", bws.addr, err)
	}
}

func (s *Server) handleBtcFinalityNotification() {
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
}

func (s *Server) handleBtcBlockNotification() {
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
}

func (s *Server) handleL2KeystonesNotification() {
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
}

func hemiL2KeystoneAbrevToDb(l2ks hemi.L2KeystoneAbrev) bfgd.L2Keystone {
	padBytes := func(s []byte) database.ByteArray {
		// allocated zeroed array
		r := make([]byte, 32)
		// copy s into r, this will pad the ending bytes with 0s
		copy(r, s)
		return database.ByteArray(r)
	}

	return bfgd.L2Keystone{
		Hash:               l2ks.HashB(),
		Version:            uint32(l2ks.Version),
		L1BlockNumber:      l2ks.L1BlockNumber,
		L2BlockNumber:      l2ks.L2BlockNumber,
		ParentEPHash:       padBytes(l2ks.ParentEPHash[:]),
		PrevKeystoneEPHash: padBytes(l2ks.PrevKeystoneEPHash[:]),
		StateRoot:          padBytes(l2ks.StateRoot[:]),
		EPHash:             padBytes(l2ks.EPHash[:]),
	}
}

func hemiL2KeystoneToDb(l2ks hemi.L2Keystone) bfgd.L2Keystone {
	return bfgd.L2Keystone{
		Hash:               hemi.L2KeystoneAbbreviate(l2ks).HashB(),
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

func (s *Server) refreshCacheAndNotifiyL2Keystones(pctx context.Context) {
	ctx, cancel := context.WithTimeout(pctx, 10*time.Second)
	defer cancel()

	s.refreshL2KeystoneCache(ctx)
	go s.handleL2KeystonesNotification()
}

// to prevent against keystones being mined too far in the future, determine
// a cutoff time 10 minutes in the future.  calculate the l2 block height at
// that time, don't include keystones higher than that
func (s *Server) l2KeystoneIgnoreAfter() int64 {
	log.Tracef("refreshL2KeystoneIgnoreAfter")
	defer log.Tracef("refreshL2KeystoneIgnoreAfter exit")

	// set cut off 10 minutes in the future
	// calculate the number of expected blocks between then and our baseline
	// block

	cutoff := time.Now().Add(10 * time.Minute).Unix()
	expectedTimeElapsedInBlocks := (cutoff - s.cfg.BaselineL2BlockTimestamp) / hemi.L2BlockTimeSeconds
	expectedHighestBlock := s.cfg.BaselineL2BlockHeight + expectedTimeElapsedInBlocks

	log.Tracef("the time is cut off at %d, we expected %d to be the highest block", cutoff, expectedHighestBlock)

	if (expectedHighestBlock) < 0 {
		panic(fmt.Sprintf("expectedHighestBlock is negative: %d", expectedHighestBlock))
	}

	return expectedHighestBlock
}

func (s *Server) saveL2Keystones(pctx context.Context, l2k []hemi.L2Keystone) {
	ctx, cancel := context.WithTimeout(pctx, 5*time.Second)
	defer cancel()

	ks := hemiL2KeystonesToDb(l2k)

	err := s.db.L2KeystonesInsert(ctx, ks)
	if err != nil {
		log.Errorf("error saving keystone %v", err)
		return
	}

	go s.refreshCacheAndNotifiyL2Keystones(pctx)
}

func (s *Server) handleNewL2Keystones(ctx context.Context, nlkr *bfgapi.NewL2KeystonesRequest) (any, error) {
	log.Tracef("handleNewL2Keystones")
	defer log.Tracef("handleNewL2Keystones exit")

	response := bfgapi.NewL2KeystonesResponse{}

	go s.saveL2Keystones(context.Background(), nlkr.L2Keystones)

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

func (s *Server) handleStateUpdates(ctx context.Context, table string, action string, payload, payloadOld interface{}) {
	// get the last known canonical chain height
	s.mtx.RLock()
	heightBefore := s.canonicalChainHeight
	s.mtx.RUnlock()

	// get the current canonical chain height from the db
	heightAfter, err := s.BtcBlockCanonicalHeight(ctx)
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

func (s *Server) handleAccessPublicKeys(ctx context.Context, table string, action string, payload, payloadOld interface{}) {
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
			_ = v.conn.CloseStatus(websocket.StatusProtocolError, "killed")
		}
	}
	s.mtx.Unlock()
}

func (s *Server) handleL2KeystonesChange(ctx context.Context, table string, action string, payload, payloadOld any) {
	go s.refreshCacheAndNotifiyL2Keystones(ctx)
}

func (s *Server) fetchRemoteL2Keystones(pctx context.Context) {
	ctx, cancel := context.WithTimeout(pctx, 10*time.Second)
	defer cancel()

	resp, err := s.callBFG(ctx, &bfgapi.L2KeystonesRequest{
		NumL2Keystones: 3,
	})
	if err != nil {
		log.Errorf("callBFG error: %v", err)
		return
	}

	l2ksr := resp.(*bfgapi.L2KeystonesResponse)
	s.saveL2Keystones(ctx, l2ksr.L2Keystones)
}

func (s *Server) handleBFGWebsocketReadUnauth(ctx context.Context, conn *protocol.Conn) {
	defer s.bfgWG.Done()

	log.Tracef("handleBFGWebsocketReadUnauth")
	defer log.Tracef("handleBFGWebsocketReadUnauth exit")
	for {
		log.Tracef("handleBFGWebsocketReadUnauth %v", "ReadConn")
		cmd, _, _, err := bfgapi.ReadConn(ctx, conn)
		if err != nil {
			// See if we were terminated
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.holdoffTimeout):
			}
			continue
		}
		log.Tracef("handleBFGWebsocketReadUnauth %v", cmd)

		switch cmd {
		case bfgapi.CmdL2KeystonesNotification:
			go s.fetchRemoteL2Keystones(ctx)
		default:
			log.Errorf("unknown command: %v", cmd)
			return
		}
	}
}

func (s *Server) callBFG(pctx context.Context, msg any) (any, error) {
	log.Tracef("callBFG %T", msg)
	defer log.Tracef("callBFG exit %T", msg)

	bc := bfgCmd{
		msg: msg,
		ch:  make(chan any),
	}

	ctx, cancel := context.WithTimeout(pctx, s.bfgCallTimeout)
	defer cancel()

	// attempt to send
	select {
	case <-ctx.Done():
		return nil, protocol.NewInternalErrorf("callBFG send context error: %w",
			ctx.Err())
	case s.bfgCmdCh <- bc:
	default:
		return nil, protocol.NewInternalErrorf("bfg command queue full")
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, protocol.NewInternalErrorf("callBFG received context error: %w",
			ctx.Err())
	case payload := <-bc.ch:
		if err, ok := payload.(error); ok {
			return nil, err // XXX is this an error or internal error
		}
		return payload, nil
	}

	// Won't get here
}

func (s *Server) handleBFGCallCompletion(pctx context.Context, conn *protocol.Conn, bc bfgCmd) {
	log.Tracef("handleBFGCallCompletion")
	defer log.Tracef("handleBFGCallCompletion exit")

	ctx, cancel := context.WithTimeout(pctx, s.bfgCallTimeout)
	defer cancel()

	log.Tracef("handleBFGCallCompletion: %v", spew.Sdump(bc.msg))

	_, _, payload, err := bfgapi.Call(ctx, conn, bc.msg)
	if err != nil {
		log.Errorf("handleBFGCallCompletion %T: %v", bc.msg, err)
		select {
		case bc.ch <- err:
		default:
		}
	}
	select {
	case bc.ch <- payload:
		log.Tracef("handleBFGCallCompletion returned: %v", spew.Sdump(payload))
	default:
	}
}

func (s *Server) handleBFGWebsocketCallUnauth(ctx context.Context, conn *protocol.Conn) {
	defer s.bfgWG.Done()

	log.Tracef("handleBFGWebsocketCallUnauth")
	defer log.Tracef("handleBFGWebsocketCallUnauth exit")
	for {
		select {
		case <-ctx.Done():
			return
		case bc := <-s.bfgCmdCh:
			go s.handleBFGCallCompletion(ctx, conn, bc)
		}
	}
}

func (s *Server) connectBFG(pctx context.Context) error {
	log.Tracef("connectBFG")
	defer log.Tracef("connectBFG exit")

	headers := http.Header{}
	headers.Add("User-Agent", version.UserAgent())

	authenticator, err := auth.NewSecp256k1AuthClient(s.btcPrivateKey)
	if err != nil {
		return err
	}

	conn, err := protocol.NewConn(s.cfg.BFGURL, &protocol.ConnOptions{
		Authenticator: authenticator,
		Headers:       headers,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	err = conn.Connect(ctx)
	if err != nil {
		return err
	}

	s.bfgWG.Add(1)
	go s.handleBFGWebsocketCallUnauth(ctx, conn)

	s.bfgWG.Add(1)
	go s.handleBFGWebsocketReadUnauth(ctx, conn)

	// Wait for exit
	s.bfgWG.Wait()

	return nil
}

func (s *Server) bfg(ctx context.Context) {
	defer s.wg.Done()

	log.Tracef("bfg")
	defer log.Tracef("bfg exit")

	for {
		if err := s.connectBFG(ctx); err != nil {
			// Do nothing
			log.Tracef("connectBFG: %v", err)
		} else {
			log.Infof("Connected to BFG: %s", s.cfg.BFGURL)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.holdoffTimeout):
		}

		log.Debugf("Reconnecting to: %v", s.cfg.BFGURL)
	}
}

func (s *Server) BtcBlockCanonicalHeight(ctx context.Context) (uint64, error) {
	height, err := s.db.BtcBlockCanonicalHeight(ctx)
	if err != nil {
		return 0, err
	}
	s.metrics.canonicalHeight.Set(float64(height))
	return height, nil
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if s.cfg.BaselineL2BlockHeight == 0 {
		log.Warningf("baseline l2 block height is 0")
	}

	if s.cfg.BaselineL2BlockTimestamp == 0 {
		log.Warningf("baseline l2 block timestamp is 0")
	}

	if !s.testAndSetRunning(true) {
		return errors.New("bfg already running")
	}
	defer s.testAndSetRunning(false)

	// XXX this function seems a bit heavy. Trim it by moving functionality to functions.
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
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "running",
				Help:      "Whether the BFG service is running",
			}, s.promRunning),
		)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := d.Run(ctx, cs, nil); !errors.Is(err, context.Canceled) {
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

	if s.cfg.BFGURL != "" {
		s.wg.Add(1)
		go s.bfg(ctx)
	}

	s.wg.Add(1)
	go s.trackBitcoin(ctx)

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
