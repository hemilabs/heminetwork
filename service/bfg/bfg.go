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
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	btcwire "github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"
	"nhooyr.io/websocket"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/auth"
	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/bitcoin"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/bfgd"
	"github.com/hemilabs/heminetwork/database/bfgd/postgres"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/hemi/electrumx"
	"github.com/hemilabs/heminetwork/hemi/pop"
	"github.com/hemilabs/heminetwork/service/deucalion"
)

// XXX this code needs to be a bit smarter when syncing bitcoin. We should
// return a "not ready" error whe that is the case.

type notificationId string

const (
	logLevel = "INFO"

	promSubsystem = "bfg_service" // Prometheus

	btcFinalityDelay = 9

	notifyBtcBlocks     notificationId = "btc_blocks"
	notifyBtcFinalities notificationId = "btc_finalities"
	notifyL2Keystones   notificationId = "l2_keystones"
)

var log = loggo.GetLogger("bfg")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

// InternalError is an error type to differentiates between caller and callee
// errors. An internal error is used whne something internal to the application
// fails.
type InternalError struct {
	internal *protocol.Error
	actual   error
}

// Err return the protocol.Error that can be sent over the wire.
func (ie InternalError) Err() *protocol.Error {
	return ie.internal
}

// String return the actual underlying error.
func (ie InternalError) String() string {
	i := ie.internal
	return fmt.Sprintf("%v [%v:%v]", ie.actual.Error(), i.Trace, i.Timestamp)
}

// Error satifies the error interface.
func (ie InternalError) Error() string {
	if ie.internal == nil {
		return "internal error"
	}
	return ie.internal.String()
}

func NewInternalErrorf(msg string, args ...interface{}) *InternalError {
	return &InternalError{
		internal: protocol.Errorf("internal error"),
		actual:   fmt.Errorf(msg, args...),
	}
}

func NewDefaultConfig() *Config {
	return &Config{
		EXBTCAddress:         "localhost:18001",
		PrivateListenAddress: ":8080",
		PublicListenAddress:  ":8383",
	}
}

// XXX this needs documenting. It isn't obvious if this needs tags or not
// because of lack of documentation.
type popTX struct {
	btcHeight         uint64
	keystone          *hemi.Header
	merkleHashes      [][]byte
	popMinerPublicKey []byte
	rawBlockHeader    []byte
	rawTransaction    []byte
	txHash            []byte
	txIndex           uint32
}

// XXX figure out if this needs to be moved out into the electrumx package.
type btcClient interface {
	Balance(ctx context.Context, scriptHash []byte) (*electrumx.Balance, error)
	Broadcast(ctx context.Context, rtx []byte) ([]byte, error)
	Height(ctx context.Context) (uint64, error)
	RawBlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error)
	RawTransaction(ctx context.Context, txHash []byte) ([]byte, error)
	Transaction(ctx context.Context, txHash []byte) ([]byte, error)
	TransactionAtPosition(ctx context.Context, height, index uint64) ([]byte, []string, error)
	UTXOs(ctx context.Context, scriptHash []byte) ([]*electrumx.UTXO, error)
}

type Config struct {
	BTCStartHeight          uint64
	EXBTCAddress            string
	PrivateListenAddress    string
	PublicListenAddress     string
	LogLevel                string
	PgURI                   string
	PrometheusListenAddress string
	PublicKeyAuth           bool
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	btcHeight  uint64
	hemiHeight uint32

	// PoP transactions by BTC finality block height.
	popTXFinality map[uint64][]*popTX // XXX does this need to go away? either because of persistence (thus read from disk every time) or because bitcoin finality notifications are going away

	// PoP transactions that have reached finality, sorted
	// by HEMI keystone block height. PoP transactions will
	// be added to this slice if they reach BTC finality,
	// however we're missing a HEMI keystone.
	popTXAtFinality []*popTX // XXX see previous XXX

	keystonesLock sync.RWMutex // XXX this probably needs to be an sql query
	keystones     []*hemi.Header

	server       *http.ServeMux
	publicServer *http.ServeMux

	btcClient btcClient // XXX evaluate if this is ok

	db bfgd.Database

	// Prometheus
	cmdsProcessed prometheus.Counter
	isRunning     bool

	// sessions is a record of websocket connections and their
	// respective request contexts
	sessions map[string]*bfgWs

	// record the last known canonical chain height,
	// if this grows we need to notify subscribers
	canonicalChainHeight uint64
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg:           cfg,
		popTXFinality: make(map[uint64][]*popTX),
		btcHeight:     cfg.BTCStartHeight,
		server:        http.NewServeMux(),
		publicServer:  http.NewServeMux(),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: promSubsystem,
			Name:      "rpc_calls_total",
			Help:      "The total number of succesful RPC commands",
		}),
		sessions: make(map[string]*bfgWs),
	}

	var err error
	s.btcClient, err = electrumx.NewClient(cfg.EXBTCAddress)
	if err != nil {
		return nil, fmt.Errorf("Failed to create electrumx client: %v", err)
	}

	// We could use a PGURI verification here.

	return s, nil
}

func (s *Server) writeResponse(ctx context.Context, conn protocol.APIConn, response any, id string) error {
	if err := bfgapi.Write(ctx, conn, id, response); err != nil {
		log.Errorf("error occurred writing bfgapi: %s", err)
		return err
	}

	return nil
}

func (s *Server) handleBitcoinBalance(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	log.Tracef("handleBitcoinBalance")
	defer log.Tracef("handleBitcoinBalance exit")
	// Increade command count
	defer s.cmdsProcessed.Inc()

	br, ok := payload.(*bfgapi.BitcoinBalanceRequest)
	if !ok {
		return nil, fmt.Errorf("not BitcoinBalanceRequest: %T", br)
	}

	bResp := &bfgapi.BitcoinBalanceResponse{}

	balance, err := s.btcClient.Balance(ctx, br.ScriptHash)
	if err != nil {
		ie := NewInternalErrorf("error getting bitcoin balance: %s", err)
		log.Errorf(ie.actual.Error())
		bResp.Error = ie.internal
		return bResp, nil
	}
	bResp.Confirmed = balance.Confirmed
	bResp.Unconfirmed = balance.Unconfirmed

	return bResp, nil
}

func (s *Server) handleBitcoinBroadcast(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	log.Tracef("handleBitcoinBroadcast")
	defer log.Tracef("handleBitcoinBroadcast exit")
	// Increade command count
	defer s.cmdsProcessed.Inc()

	bbr, ok := payload.(*bfgapi.BitcoinBroadcastRequest)
	if !ok {
		return nil, fmt.Errorf("not a BitcoinBroadcastRequest: %T", bbr)
	}

	bbResp := &bfgapi.BitcoinBroadcastResponse{}

	rr := bytes.NewReader(bbr.Transaction)
	mb := wire.MsgTx{}
	if err := mb.Deserialize(rr); err != nil {
		bbResp.Error = protocol.Errorf("failed to deserialized tx: %s", err)
		return bbResp, nil
	}

	var tl2 *pop.TransactionL2
	var err error
	for _, v := range mb.TxOut {
		tl2, err = pop.ParseTransactionL2FromOpReturn(v.PkScript)
		if err != nil {
			log.Errorf(err.Error()) // handle real error below
		}
	}
	if tl2 == nil {
		bbResp.Error = protocol.Errorf("could not find l2 keystone abbrev in btc tx")
		return bbResp, nil
	}

	publicKeyUncompressed, err := pop.ParsePublicKeyFromSignatureScript(mb.TxIn[0].SignatureScript)
	if err != nil {
		bbResp.Error = protocol.Errorf("could not parse signature script: %s", err)
		return bbResp, nil
	}

	txHash, err := s.btcClient.Broadcast(context.TODO(), bbr.Transaction)
	if err != nil {
		ie := NewInternalErrorf("error broadcasting to bitcoin: %s", err)
		log.Errorf(ie.actual.Error())
		bbResp.Error = ie.internal
		return bbResp, nil
	}
	bbResp.TXID = txHash

	if err := s.db.PopBasisInsertPopMFields(ctx, &bfgd.PopBasis{
		BtcTxId:             txHash,
		BtcRawTx:            database.ByteArray(bbr.Transaction),
		PopMinerPublicKey:   publicKeyUncompressed,
		L2KeystoneAbrevHash: tl2.L2Keystone.Hash(),
	}); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			bbResp.Error = protocol.Errorf("pop_basis already exists")
			return bbResp, nil
		}

		if errors.Is(err, database.ErrValidation) {
			log.Errorf("invalid pop basis: %s", err)
			bbResp.Error = protocol.Errorf("invalid pop_basis")
			return bbResp, nil
		}

		ie := NewInternalErrorf("error inserting pop basis: %s", err)
		bbResp.Error = ie.internal
		log.Errorf(ie.actual.Error())
		return bbResp, nil
	}

	return bbResp, nil
}

func (s *Server) handleBitcoinInfo(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	log.Tracef("handleBitcoinInfo")
	defer log.Tracef("handleBitcoinInfo exit")
	// Increade command count
	defer s.cmdsProcessed.Inc()

	_, ok := payload.(*bfgapi.BitcoinInfoRequest)
	if !ok {
		return nil, fmt.Errorf("not a BitcoinInfoRequest %T", payload)
	}

	biResp := &bfgapi.BitcoinInfoResponse{}

	height, err := s.btcClient.Height(ctx)
	if err != nil {
		ie := NewInternalErrorf("error getting bitcoin height: %s", err)
		log.Errorf(ie.actual.Error())
		biResp.Error = ie.internal
		return biResp, nil
	}
	biResp.Height = height

	return biResp, nil
}

func (s *Server) handleBitcoinUTXOs(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	log.Tracef("handleBitcoinUTXOs")
	defer log.Tracef("handleBitcoinUTXOs exit")
	// Increade command count
	defer s.cmdsProcessed.Inc()

	bur, ok := payload.(*bfgapi.BitcoinUTXOsRequest)
	if !ok {
		err := fmt.Errorf("not a BitcoinUTXOsRequest %T", payload)
		log.Errorf(err.Error())
		return nil, err
	}

	buResp := &bfgapi.BitcoinUTXOsResponse{}

	utxos, err := s.btcClient.UTXOs(context.TODO(), bur.ScriptHash)
	if err != nil {
		ie := NewInternalErrorf("error getting bitcoin utxos: %s", err)
		log.Errorf(ie.actual.Error())
		buResp.Error = ie.internal
		return buResp, nil
	}
	for _, utxo := range utxos {
		buResp.UTXOs = append(buResp.UTXOs, &bfgapi.BitcoinUTXO{
			Hash:  utxo.Hash,
			Index: utxo.Index,
			Value: utxo.Value,
		})
	}

	return buResp, nil
}

func (s *Server) handleAccessPublicKeyCreateRequest(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	log.Tracef("handleAccessPublicKeyCreateRequest")
	defer log.Tracef("handleAccessPublicKeyCreateRequest exit")

	accessPublicKeyCreateRequest, ok := payload.(*bfgapi.AccessPublicKeyCreateRequest)
	if !ok {
		err := fmt.Errorf("incorrect type: %T", payload)
		return nil, err
	}

	response := &bfgapi.AccessPublicKeyCreateResponse{}

	publicKey, err := hex.DecodeString(accessPublicKeyCreateRequest.PublicKey)
	if err != nil {
		response.Error = protocol.Errorf(err.Error())
		return response, nil
	}

	if err := s.db.AccessPublicKeyInsert(ctx, &bfgd.AccessPublicKey{
		PublicKey: publicKey,
	}); err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			response.Error = protocol.Errorf("public key already exists")
			return response, nil
		}

		if errors.Is(err, database.ErrValidation) {
			response.Error = protocol.Errorf("invalid access public key")
			return response, nil
		}

		ie := NewInternalErrorf("error inserting access public key: %s", err)
		response.Error = ie.internal
		log.Errorf(ie.actual.Error())
		return response, nil
	}

	return response, nil
}

func (s *Server) handleAccessPublicKeyDelete(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	log.Tracef("handleAccessPublicKeyDelete")
	defer log.Tracef("handleAccessPublicKeyDelete exit")

	accessPublicKeyDeleteRequest, ok := payload.(*bfgapi.AccessPublicKeyDeleteRequest)
	if !ok {
		return nil, fmt.Errorf("incorrect type %T", payload)
	}

	response := &bfgapi.AccessPublicKeyDeleteResponse{}

	b, err := hex.DecodeString(accessPublicKeyDeleteRequest.PublicKey)
	if err != nil {
		response.Error = protocol.Errorf(err.Error())
		return response, nil
	}

	if err := s.db.AccessPublicKeyDelete(ctx, &bfgd.AccessPublicKey{
		PublicKey: b,
	}); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			response.Error = protocol.Errorf("public key not found")
			return response, nil
		}
		ie := NewInternalErrorf("error deleting access public key: %s", err)
		response.Error = ie.internal
		log.Errorf(ie.actual.Error())
		return response, nil
	}

	return response, nil
}

func (s *Server) processBitcoinBlock(ctx context.Context, height uint64) error {
	log.Infof("Processing Bitcoin block at height %d...", height)

	rbh, err := s.btcClient.RawBlockHeader(ctx, height)
	if err != nil {
		return fmt.Errorf("failed to get block header at height %v: %v",
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
			if errors.Is(err, electrumx.ErrNoTxAtPosition) {
				// There is no way to tell how many transactions are
				// in a block, so hopefully we've got them all...
				return nil
			}
			return fmt.Errorf("failed to get transaction at position (height %v, index %v): %v", height, index, err)
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
			return fmt.Errorf("failed to get raw transaction with txid %x: %v", txHash, err)
		}

		log.Infof("got raw transaction with txid %x", txHash)

		mtx := &btcwire.MsgTx{}
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
			if err != nil && errors.Is(database.ErrDuplicate, err) == false {
				return err
			}
		}

	}
}

func (s *Server) processBitcoinBlocks(ctx context.Context, start, end uint64) error {
	for i := start; i <= end; i++ {
		if err := s.processBitcoinBlock(ctx, i); err != nil {
			return fmt.Errorf("failed to process bitcoin block at height %d: %v", i, err)
		}
		s.btcHeight = i
	}
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
	requestContext context.Context
	notify         map[notificationId]struct{}
	publicKey      []byte
}

func (s *Server) handleWebsocketPrivateRead(ctx context.Context, bws *bfgWs) {
	defer bws.wg.Done()

	log.Tracef("handleWebsocketPrivateRead: %v", bws.addr)
	defer log.Tracef("handleWebsocketPrivateRead exit: %v", bws.addr)

	// Command completed
	defer s.cmdsProcessed.Inc()

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

		var response any

		switch cmd {
		case bfgapi.CmdPingRequest:
			response, err = s.handlePing(ctx, bws, payload, id)
		case bfgapi.CmdPopTxForL2BlockRequest:
			response, err = s.handlePopTxForL2Block(ctx, bws, payload, id)
		case bfgapi.CmdNewL2KeystonesRequest:
			response, err = s.handleNewL2Keystones(ctx, bws, payload, id)
		case bfgapi.CmdBTCFinalityByRecentKeystonesRequest:
			response, err = s.handleBtcFinalityByRecentKeystonesRequest(ctx, bws, payload, id)
		case bfgapi.CmdBTCFinalityByKeystonesRequest:
			response, err = s.handleBtcFinalityByKeystonesRequest(ctx, bws, payload, id)
		case bfgapi.CmdAccessPublicKeyCreateRequest:
			response, err = s.handleAccessPublicKeyCreateRequest(ctx, bws, payload, id)
		case bfgapi.CmdAccessPublicKeyDeleteRequest:
			response, err = s.handleAccessPublicKeyDelete(ctx, bws, payload, id)
		default:
			err = fmt.Errorf("unknown command")
		}

		// if there was an error, close the websocket, only do this if we
		// can't continue
		if err != nil {
			log.Errorf("handleWebsocketPrivateRead error %v %v: %v", bws.addr, cmd, err)
			bws.conn.CloseStatus(websocket.StatusProtocolError,
				err.Error())
			return
		} else {
			if err := s.writeResponse(ctx, bws.conn, response, id); err != nil {
				bws.conn.CloseStatus(websocket.StatusProtocolError, err.Error())
				return
			}
		}

	}
}

func (s *Server) handleWebsocketPublicRead(ctx context.Context, bws *bfgWs) {
	defer bws.wg.Done()

	log.Tracef("handleWebsocketPublicRead: %v", bws.addr)
	defer log.Tracef("handleWebsocketPublicRead exit: %v", bws.addr)

	// Command completed
	defer s.cmdsProcessed.Inc()

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

		var response any

		switch cmd {
		case bfgapi.CmdPingRequest:
			response, err = s.handlePing(ctx, bws, payload, id)
		case bfgapi.CmdL2KeystonesRequest:
			response, err = s.handleL2KeystonesRequest(ctx, bws, payload, id)
		case bfgapi.CmdBitcoinBalanceRequest:
			response, err = s.handleBitcoinBalance(ctx, bws, payload, id)
		case bfgapi.CmdBitcoinBroadcastRequest:
			response, err = s.handleBitcoinBroadcast(ctx, bws, payload, id)
		case bfgapi.CmdBitcoinInfoRequest:
			response, err = s.handleBitcoinInfo(ctx, bws, payload, id)
		case bfgapi.CmdBitcoinUTXOsRequest:
			response, err = s.handleBitcoinUTXOs(ctx, bws, payload, id)
		default:
			err = fmt.Errorf("unknown command")
		}

		if err != nil {
			log.Errorf("handleWebsocketPublicRead %v %v: %v", bws.addr, cmd, err)
			bws.conn.CloseStatus(websocket.StatusProtocolError,
				err.Error())
			return
		} else {
			if err := s.writeResponse(ctx, bws.conn, response, id); err != nil {
				bws.conn.CloseStatus(websocket.StatusProtocolError, err.Error())
				return
			}
		}

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

func (s *Server) killSession(id string, why websocket.StatusCode) {
	s.mtx.Lock()
	bws, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mtx.Unlock()

	if !ok {
		log.Errorf("killSession: id not found in sessions %s", id)
	} else {
		if err := bws.conn.CloseStatus(why, ""); err != nil {
			// XXX this is too noisy.
			log.Debugf("session close %v: %v", id, err)
		}
	}
}

func (s *Server) handleWebsocketPrivate(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWebsocketPrivate: %v", r.RemoteAddr)
	defer log.Tracef("handleWebsocketPrivate exit: %v", r.RemoteAddr)

	wao := &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
		OriginPatterns:  []string{"localhost"},
	}

	conn, err := websocket.Accept(w, r, wao)
	if err != nil {
		log.Errorf("Failed to accept websocket connection for %v: %v",
			r.RemoteAddr, err)
		return
	}

	bws := &bfgWs{
		addr: r.RemoteAddr,
		conn: protocol.NewWSConn(conn),
		notify: map[notificationId]struct{}{
			notifyBtcBlocks:     {},
			notifyBtcFinalities: {},
		},
		requestContext: r.Context(),
	}

	if bws.sessionId, err = s.newSession(bws); err != nil {
		log.Errorf("error occurred creating key: %s", err)
		return
	}

	defer func() {
		s.killSession(bws.sessionId, websocket.StatusNormalClosure)
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

	log.Infof("Unauthenticated connection from %v", r.RemoteAddr)
	bws.wg.Wait()
	log.Infof("Unauthenticated connection terminated from %v", r.RemoteAddr)
}

func (s *Server) handleWebsocketPublic(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWebsocketPublic: %v", r.RemoteAddr)
	defer log.Tracef("handleWebsocketPublic exit: %v", r.RemoteAddr)

	wao := &websocket.AcceptOptions{
		CompressionMode:    websocket.CompressionContextTakeover,
		OriginPatterns:     []string{"localhost:43111"},
		InsecureSkipVerify: true, // XXX sucks but we don't want to whitelist every locahost port
	}

	conn, err := websocket.Accept(w, r, wao)
	if err != nil {
		log.Errorf("Failed to accept websocket connection for %v: %v",
			r.RemoteAddr, err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	bws := &bfgWs{
		addr:           r.RemoteAddr,
		conn:           protocol.NewWSConn(conn),
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
	defer func() {
		s.killSession(bws.sessionId, websocket.StatusNormalClosure)
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

	log.Infof("Authenticated session %s from %s public key %x",
		bws.sessionId, r.RemoteAddr, bws.publicKey)
	bws.wg.Wait()
	log.Infof("Terminated session %s from %s public key %x",
		bws.sessionId, r.RemoteAddr, bws.publicKey)
}

func (s *Server) handlePing(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	log.Tracef("handlePing: %v", bws.addr)
	defer log.Tracef("handlePing exit: %v", bws.addr)

	p, ok := payload.(*bfgapi.PingRequest)
	if !ok {
		return nil, fmt.Errorf("handlePing invalid payload type: %T", payload)
	}
	response := &bfgapi.PingResponse{
		OriginTimestamp: p.Timestamp,
		Timestamp:       time.Now().Unix(),
	}

	return response, nil
}

func (s *Server) handlePopTxForL2Block(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	log.Tracef("handlePopTxForL2Block: %v", bws.addr)
	defer log.Tracef("handlePopTxForL2Block exit: %v", bws.addr)

	p, ok := payload.(*bfgapi.PopTxsForL2BlockRequest)
	if !ok {
		return nil, fmt.Errorf("handlePopTxForL2Block invalid payload type: %T",
			payload)
	}

	response := bfgapi.PopTxsForL2BlockResponse{}

	hash := hemi.HashSerializedL2KeystoneAbrev(p.L2Block)
	var h [32]byte
	copy(h[:], hash)
	popTxs, err := s.db.PopBasisByL2KeystoneAbrevHash(ctx, h, true)
	if err != nil {
		ie := NewInternalErrorf("error getting pop basis: %s", err)
		response.Error = ie.internal
		log.Errorf(ie.actual.Error())
		return response, nil
	}

	response.PopTxs = make([]bfgapi.PopTx, 0, len(popTxs))

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

func (s *Server) handleBtcFinalityByRecentKeystonesRequest(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	p, ok := payload.(*bfgapi.BTCFinalityByRecentKeystonesRequest)
	if ok == false {
		return nil, fmt.Errorf(
			"handleBtcFinalityByRecentKeystonesRequest invalid payload type %T",
			payload,
		)
	}

	response := bfgapi.BTCFinalityByRecentKeystonesResponse{}

	finalities, err := s.db.L2BTCFinalityMostRecent(ctx, p.NumRecentKeystones)
	if err != nil {
		ie := NewInternalErrorf("error getting finality: %s", err)
		response.Error = ie.internal
		log.Errorf(ie.actual.Error())
		return response, nil
	}

	apiFinalities := []hemi.L2BTCFinality{}
	for _, finality := range finalities {
		apiFinality, err := hemi.L2BTCFinalityFromBfgd(
			&finality,
			finality.BTCTipHeight,
			finality.EffectiveHeight,
		)
		if err != nil {
			return nil, err
		}
		apiFinalities = append(apiFinalities, *apiFinality)
	}

	response.L2BTCFinalities = apiFinalities

	return response, nil
}

func (s *Server) handleBtcFinalityByKeystonesRequest(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	p, ok := payload.(*bfgapi.BTCFinalityByKeystonesRequest)
	if ok == false {
		return nil, fmt.Errorf(
			"handleBtcFinalityByKeystonesRequest invalid payload type %T",
			payload,
		)
	}

	response := bfgapi.BTCFinalityByKeystonesResponse{}

	l2KeystoneAbrevHashes := []database.ByteArray{}

	for _, l := range p.L2Keystones {
		a := hemi.L2KeystoneAbbreviate(l)
		l2KeystoneAbrevHashes = append(l2KeystoneAbrevHashes, a.Hash())
	}

	finalities, err := s.db.L2BTCFinalityByL2KeystoneAbrevHash(
		ctx,
		l2KeystoneAbrevHashes,
	)
	if err != nil {
		ie := NewInternalErrorf("error getting l2 keystones: %s", err)
		response.Error = ie.internal
		log.Errorf(ie.actual.Error())
		return response, nil
	}

	apiFinalities := []hemi.L2BTCFinality{}
	for _, finality := range finalities {
		apiFinality, err := hemi.L2BTCFinalityFromBfgd(
			&finality,
			finality.BTCTipHeight,
			finality.EffectiveHeight,
		)
		if err != nil {
			return nil, err
		}
		apiFinalities = append(apiFinalities, *apiFinality)
	}

	response.L2BTCFinalities = apiFinalities

	return response, nil
}

func (s *Server) handleL2KeystonesRequest(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	p, ok := payload.(*bfgapi.L2KeystonesRequest)
	if ok == false {
		return nil, fmt.Errorf(
			"handleL2KeystonesRequest invalid payload type %T",
			payload,
		)
	}

	gkhResp := &bfgapi.L2KeystonesResponse{}

	results, err := s.db.L2KeystonesMostRecentN(ctx,
		uint32(p.NumL2Keystones))
	if err != nil {
		ie := NewInternalErrorf("error getting l2 keystones: %s", err)
		gkhResp.Error = ie.internal
		log.Errorf(ie.actual.Error())
		return gkhResp, nil
	}

	for _, v := range results {
		gkhResp.L2Keystones = append(gkhResp.L2Keystones, hemi.L2Keystone{
			Version:            uint8(v.Version),
			L1BlockNumber:      v.L1BlockNumber,
			L2BlockNumber:      v.L2BlockNumber,
			ParentEPHash:       api.ByteSlice(v.ParentEPHash),
			PrevKeystoneEPHash: api.ByteSlice(v.PrevKeystoneEPHash),
			StateRoot:          api.ByteSlice(v.StateRoot),
			EPHash:             api.ByteSlice(v.EPHash),
		})
	}

	return gkhResp, nil
}

func writeNotificationResponse(bws *bfgWs, response any) {
	if err := bfgapi.Write(bws.requestContext, bws.conn, "", response); err != nil {
		log.Errorf(
			"handleBtcFinalityNotification write: %v %v",
			bws.addr,
			err,
		)
	}
}

func (s *Server) handleBtcFinalityNotification() error {
	response := bfgapi.BTCFinalityNotification{}

	s.mtx.Lock()
	for _, bws := range s.sessions {
		if _, ok := bws.notify[notifyBtcFinalities]; !ok {
			continue
		}
		go writeNotificationResponse(bws, response)
	}
	s.mtx.Unlock()

	return nil
}

func (s *Server) handleBtcBlockNotification() error {
	response := bfgapi.BTCNewBlockNotification{}

	s.mtx.Lock()
	for _, bws := range s.sessions {
		if _, ok := bws.notify[notifyBtcBlocks]; !ok {
			continue
		}
		go writeNotificationResponse(bws, response)
	}
	s.mtx.Unlock()

	return nil
}

func (s *Server) handleL2KeystonesNotification() error {
	response := bfgapi.L2KeystonesNotification{}

	s.mtx.Lock()
	for _, bws := range s.sessions {
		if _, ok := bws.notify[notifyL2Keystones]; !ok {
			continue
		}
		go writeNotificationResponse(bws, response)
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

func (s *Server) handleNewL2Keystones(ctx context.Context, bws *bfgWs, payload any, id string) (any, error) {
	ks := hemiL2KeystonesToDb(payload.(*bfgapi.NewL2KeystonesRequest).L2Keystones)
	err := s.db.L2KeystonesInsert(ctx, ks)
	response := bfgapi.NewL2KeystonesResponse{}
	if err != nil {
		if errors.Is(err, database.ErrDuplicate) {
			response.Error = protocol.Errorf("l2 keystone already exists")
			return response, nil
		}
		if errors.Is(err, database.ErrValidation) {
			log.Errorf("error inserting l2 keystone: %s", err)
			response.Error = protocol.Errorf("invalid l2 keystone")
			return response, nil
		}

		return nil, err
	}

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

	// XXX this is racing with killSession but protected. We should
	// create a killSessions that takes an encoded PublicKey
	s.mtx.Lock()
	for _, v := range s.sessions {
		// if public key does not exist on session, it's not an authenticated
		// session so we don't close it because it didn't use a public key
		if v.publicKey == nil || len(v.publicKey) == 0 {
			continue
		}

		// the database value will be passed with \x prefixed to denote hex
		// encoding, ensure that the session string does for an equal comparison
		sessionPublicKeyEncoded := fmt.Sprintf("\\x%s", hex.EncodeToString(v.publicKey))
		if sessionPublicKeyEncoded == accessPublicKey.PublicKeyEncoded {
			sessionId := v.sessionId
			go s.killSession(sessionId, protocol.StatusHandshakeErr)
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
		return fmt.Errorf("bfg already running")
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
		return fmt.Errorf("Failed to connect to database: %v", err)
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

	// Setup websockets and HTTP routes
	privateMux := s.server
	publicMux := s.publicServer

	handle("bfgpriv", privateMux, bfgapi.RouteWebsocketPrivate, s.handleWebsocketPrivate)
	handle("bfgpub", publicMux, bfgapi.RouteWebsocketPublic, s.handleWebsocketPublic)

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
				Help:      "Is bfg service running.",
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
