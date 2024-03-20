// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bss

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"
	"nhooyr.io/websocket"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/ethereum"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/service/deucalion"
)

const (
	logLevel = "bss=INFO"
	verbose  = false

	promSubsystem = "bss_service" // Prometheus

)

var log = loggo.GetLogger("bss")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

// Wrap for calling bfg commands
type bfgCmd struct {
	msg any
	ch  chan any
}

func NewDefaultConfig() *Config {
	return &Config{
		BFGURL:        bfgapi.DefaultPrivateURL,
		ListenAddress: bssapi.DefaultListen,
	}
}

type Config struct {
	BFGURL                  string
	ListenAddress           string
	LogLevel                string
	PrometheusListenAddress string
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	currentKeystone  *hemi.Header
	previousKeystone *hemi.Header

	// requests
	requestLimit   int       // Request limiter queue depth
	requestLimiter chan bool // Maximum in progress websocket commands

	// BFG
	bfgWG          sync.WaitGroup // websocket read exit
	bfgCmdCh       chan bfgCmd    // commands to send to bfg
	bfgCallTimeout time.Duration  // BFG call timeout
	holdoffTimeout time.Duration  // Time in between connections attempt to BFG

	// Prometheus
	cmdsProcessed prometheus.Counter
	isRunning     bool
	bfgConnected  bool

	// sessions is a record of websocket connections and their respective
	// request contexts
	requestTimeout time.Duration     // Request timeout, must be 2X BFG call timeout
	sessions       map[string]*bssWs // Session id to connections map
}

func DerivePopPayoutFromPopTx(popTx bfgapi.PopTx) bssapi.PopPayout {
	amount := big.NewInt(hemi.HEMIBase)

	return bssapi.PopPayout{
		// as of now, this is static at 10^18 atomic units == 1 HEMI
		Amount:       amount,
		MinerAddress: ethereum.PublicKeyToAddress(popTx.PopMinerPublicKey),
	}
}

// XXX this function needs documentation. It is not obvious what it does.
func ConvertPopTxsToPopPayouts(popTxs []bfgapi.PopTx) []bssapi.PopPayout {
	popPayoutsMapping := make(map[string]bssapi.PopPayout)

	for _, v := range popTxs {
		popPayout := DerivePopPayoutFromPopTx(v)
		key := popPayout.MinerAddress.String()
		existingPopPayout, ok := popPayoutsMapping[key]
		if !ok {
			popPayoutsMapping[key] = popPayout
			continue
		}

		popPayoutsMapping[key] = bssapi.PopPayout{
			MinerAddress: existingPopPayout.MinerAddress,
			Amount:       existingPopPayout.Amount.Add(existingPopPayout.Amount, popPayout.Amount),
		}
	}

	popPayouts := []bssapi.PopPayout{}

	for k := range popPayoutsMapping {
		popPayouts = append(popPayouts, popPayoutsMapping[k])
	}

	return popPayouts
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	defaultRequestTimeout := 11 * time.Second // XXX
	requestLimit := 1000                      // XXX
	s := &Server{
		cfg:            cfg,
		requestLimiter: make(chan bool, requestLimit),
		bfgCmdCh:       make(chan bfgCmd, 10),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: promSubsystem,
			Name:      "rpc_calls_total",
			Help:      "The total number of succesful RPC commands",
		}),
		requestTimeout: defaultRequestTimeout,
		bfgCallTimeout: defaultRequestTimeout / 2,
		holdoffTimeout: 6 * time.Second,
		requestLimit:   requestLimit,
		sessions:       make(map[string]*bssWs),
	}
	for i := 0; i < requestLimit; i++ {
		s.requestLimiter <- true
	}

	return s, nil
}

// handleRequest is called as a go routine to handle a long lived command.
func (s *Server) handleRequest(parrentCtx context.Context, bws *bssWs, wsid string, requestType string, handler func(ctx context.Context) (any, error)) {
	log.Tracef("handleRequest: %v", bws.addr)
	defer log.Tracef("handleRequest exit: %v", bws.addr)

	ctx, cancel := context.WithTimeout(parrentCtx, s.requestTimeout)
	defer cancel()

	select {
	case <-s.requestLimiter:
	default:
		log.Infof("Request limiter hit %v: %v", bws.addr, requestType)
		<-s.requestLimiter
	}
	defer func() { s.requestLimiter <- true }()

	log.Tracef("Handling request %v: %v", bws.addr, requestType)

	response, err := handler(ctx)
	if err != nil {
		log.Errorf("Failed to handle %v request %v: %v",
			requestType, bws.addr, err)
	}
	if response == nil {
		return
	}

	log.Debugf("Responding to %v request with %v", requestType, spew.Sdump(response))

	if err := bssapi.Write(ctx, bws.conn, wsid, response); err != nil {
		log.Errorf("Failed to handle %v request: protocol write failed: %v",
			requestType, err)
	}
}

type bssWs struct {
	wg             sync.WaitGroup
	addr           string
	conn           *protocol.WSConn
	sessionId      string
	requestContext context.Context
}

func (s *Server) handlePingRequest(ctx context.Context, bws *bssWs, payload any, id string) error {
	log.Tracef("handlePingRequest: %v", bws.addr)
	defer log.Tracef("handlePingRequest exit: %v", bws.addr)

	p, ok := payload.(*bssapi.PingRequest)
	if !ok {
		return fmt.Errorf("handlePingRequest invalid payload type: %T", payload)
	}
	response := &bssapi.PingResponse{
		OriginTimestamp: p.Timestamp,
		Timestamp:       time.Now().Unix(),
	}

	log.Tracef("responding with %v", spew.Sdump(response))

	if err := bssapi.Write(ctx, bws.conn, id, response); err != nil {
		return fmt.Errorf("handlePingRequest write: %v %v",
			bws.addr, err)
	}
	return nil
}

func (s *Server) handlePopPayoutsRequest(ctx context.Context, msg *bssapi.PopPayoutsRequest) (*bssapi.PopPayoutsResponse, error) {
	log.Tracef("handlePopPayoutsRequest")
	defer log.Tracef("handlePopPayoutsRequest exit")

	popTxsForL2BlockRes, err := s.callBFG(ctx, bfgapi.PopTxsForL2BlockRequest{
		L2Block: msg.L2BlockForPayout,
	})
	if err != nil {
		e := protocol.NewInternalErrorf("pop tx for l2: block %w", err)
		return &bssapi.PopPayoutsResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &bssapi.PopPayoutsResponse{
		PopPayouts: ConvertPopTxsToPopPayouts(
			(popTxsForL2BlockRes.(*bfgapi.PopTxsForL2BlockResponse)).PopTxs,
		),
	}, nil
}

func (s *Server) handleL2KeytoneRequest(ctx context.Context, msg *bssapi.L2KeystoneRequest) (*bssapi.L2KeystoneResponse, error) {
	log.Tracef("handleL2KeytoneRequest")
	defer log.Tracef("handleL2KeytoneRequest exit")

	_, err := s.callBFG(ctx, &bfgapi.NewL2KeystonesRequest{
		L2Keystones: []hemi.L2Keystone{msg.L2Keystone},
	})
	if err != nil {
		e := protocol.NewInternalErrorf("new l2 keytsones: %w", err)
		return &bssapi.L2KeystoneResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &bssapi.L2KeystoneResponse{}, nil
}

func (s *Server) handleBtcFinalityByRecentKeystonesRequest(ctx context.Context, msg *bssapi.BTCFinalityByRecentKeystonesRequest) (*bssapi.BTCFinalityByRecentKeystonesResponse, error) {
	log.Tracef("handleBtcFinalityByRecentKeystonesRequest")
	defer log.Tracef("handleBtcFinalityByRecentKeystonesRequest exit")

	response, err := s.callBFG(ctx, &bfgapi.BTCFinalityByRecentKeystonesRequest{
		NumRecentKeystones: msg.NumRecentKeystones,
	})
	if err != nil {
		e := protocol.NewInternalErrorf("btc finality recent: %w", err)
		return &bssapi.BTCFinalityByRecentKeystonesResponse{
			Error: e.ProtocolError(),
		}, err
	}

	return &bssapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: response.(*bfgapi.BTCFinalityByRecentKeystonesResponse).L2BTCFinalities,
	}, nil
}

func (s *Server) handleBtcFinalityByKeystonesRequest(ctx context.Context, msg *bssapi.BTCFinalityByKeystonesRequest) (*bssapi.BTCFinalityByKeystonesResponse, error) {
	log.Tracef("handleBtcFinalityByKeystonesRequest")
	defer log.Tracef("handleBtcFinalityByKeystonesRequest exit")

	response, err := s.callBFG(ctx, &bfgapi.BTCFinalityByKeystonesRequest{
		L2Keystones: msg.L2Keystones,
	})
	if err != nil {
		e := protocol.NewInternalErrorf("btc finality keystones: %w", err)
		return &bssapi.BTCFinalityByKeystonesResponse{
			Error: e.ProtocolError(),
		}, err
	}

	return &bssapi.BTCFinalityByKeystonesResponse{
		L2BTCFinalities: response.(*bfgapi.BTCFinalityByKeystonesResponse).L2BTCFinalities,
	}, nil
}

func (s *Server) handleWebsocketRead(ctx context.Context, bws *bssWs) {
	defer bws.wg.Done()

	log.Tracef("handleWebsocketRead: %v", bws.addr)
	defer log.Tracef("handleWebsocketRead exit: %v", bws.addr)

	for {
		cmd, id, payload, err := bssapi.Read(ctx, bws.conn)
		if err != nil {
			// Don't log normal close errors.
			var ce websocket.CloseError
			if !errors.As(err, &ce) {
				log.Errorf("handleWebsocketRead: %v", err)
			} else {
				log.Tracef("handleWebsocketRead: %v", err)
			}
			return
		}

		// May be too loud.
		log.Tracef("handleWebsocketRead read %v: %v %v %v",
			bws.addr, cmd, id, spew.Sdump(payload))

		// Note, we MUST NOT shadow ctx in the callbacks. ctx *is* the
		// base context in the callback thus if we shadow it we
		// overwrite the correct context that has a reasonable timeout.
		//
		// Make dead sure all contexts folloing in this code are not
		// shadowed.
		switch cmd {
		case bssapi.CmdPingRequest:
			// quick call
			err = s.handlePingRequest(ctx, bws, payload, id)
		case bssapi.CmdPopPayoutRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bssapi.PopPayoutsRequest)
				return s.handlePopPayoutsRequest(c, msg)
			}

			go s.handleRequest(ctx, bws, id, "handle pop payouts request", handler)
		case bssapi.CmdL2KeystoneRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bssapi.L2KeystoneRequest)
				return s.handleL2KeytoneRequest(c, msg)
			}

			go s.handleRequest(ctx, bws, id, "handle l2 keystone request", handler)
		case bssapi.CmdBTCFinalityByRecentKeystonesRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bssapi.BTCFinalityByRecentKeystonesRequest)
				return s.handleBtcFinalityByRecentKeystonesRequest(c, msg)
			}

			go s.handleRequest(ctx, bws, id, "handle handleBtcFinalityByRecentKeystonesRequest", handler)
		case bssapi.CmdBTCFinalityByKeystonesRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*bssapi.BTCFinalityByKeystonesRequest)
				return s.handleBtcFinalityByKeystonesRequest(c, msg)
			}

			go s.handleRequest(ctx, bws, id, "handle handleBtcFinalityByKeystonesRequest", handler)
		default:
			err = fmt.Errorf("unknown command: %v", cmd)
		}

		// If set, it is a terminal error.
		if err != nil {
			log.Errorf("handleWebsocketRead %v %v %v: %v",
				bws.addr, cmd, id, err)
			return
		}

		// Command completed
		s.cmdsProcessed.Inc()
	}
}

func (s *Server) handleWebsocket(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWebsocket: %v", r.RemoteAddr)
	defer log.Tracef("handleWebsocket exit: %v", r.RemoteAddr)

	wao := &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
		OriginPatterns:  []string{"localhost"},
		// InsecureSkipVerify: true, // XXX - configure OriginPatterns instead
	}
	conn, err := websocket.Accept(w, r, wao)
	if err != nil {
		log.Errorf("Failed to accept websocket connection for %v: %v",
			r.RemoteAddr, err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "") // Force shutdown connection

	// Increase read limit to 128KB
	conn.SetReadLimit(128 * 1024) // XXX push this into protocol

	bws := &bssWs{
		addr:           r.RemoteAddr,
		conn:           protocol.NewWSConn(conn),
		requestContext: r.Context(),
	}

	if bws.sessionId, err = s.newSession(bws); err != nil {
		log.Errorf("error occurred creating key: %s", err)
		return
	}

	defer func() {
		s.deleteSession(bws.sessionId)
	}()

	bws.wg.Add(1)
	go s.handleWebsocketRead(r.Context(), bws)

	// Always ping, required by protocol.
	ping := &bssapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	log.Tracef("responding with %v", spew.Sdump(ping))
	if err := bssapi.Write(r.Context(), bws.conn, "0", ping); err != nil {
		log.Errorf("Write: %v", err)
	}

	log.Infof("Unauthenticated connection from %v", r.RemoteAddr)

	// Wait for termination
	bws.wg.Wait()

	log.Infof("Unauthenticated connection terminated from %v", r.RemoteAddr)
}

func (s *Server) newSession(bws *bssWs) (string, error) {
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
	s.mtx.Lock()
	_, ok := s.sessions[id]
	delete(s.sessions, id)
	s.mtx.Unlock()

	if !ok {
		log.Errorf("id not found in sessions %s", id)
	}
}

func writeNotificationResponse(bws *bssWs, response any) {
	if err := bssapi.Write(bws.requestContext, bws.conn, "", response); err != nil {
		log.Errorf(
			"handleBtcFinalityNotification write: %v %v",
			bws.addr,
			err,
		)
	}
}

func (s *Server) handleBtcFinalityNotification() error {
	s.mtx.Lock()
	for _, bws := range s.sessions {
		go writeNotificationResponse(bws, &bssapi.BTCFinalityNotification{})
	}
	s.mtx.Unlock()

	return nil
}

func (s *Server) handleBtcBlockNotification() error {
	s.mtx.Lock()
	for _, bws := range s.sessions {
		go writeNotificationResponse(bws, &bssapi.BTCNewBlockNotification{})
	}
	s.mtx.Unlock()

	return nil
}

func handle(service string, mux *http.ServeMux, pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandleFunc(pattern, handler)
	log.Infof("handle (%v): %v", service, pattern)
}

func (s *Server) handleBFGWebsocketReadUnauth(ctx context.Context, conn *protocol.Conn) {
	defer s.bfgWG.Done()

	log.Tracef("handleBFGWebsocketReadUnauth")
	defer log.Tracef("handleBFGWebsocketReadUnauth exit")
	s.setBFGConnected(conn.IsOnline()) // this is a bit inaccurate because on reconeect the code does not get past the ReadConn call. Moving the call into the for would be bouncing so let's assume bfg chatters soon so that the connection is marked online.
	for {
		log.Infof("handleBFGWebsocketReadUnauth %v", "ReadConn")
		cmd, rid, payload, err := bfgapi.ReadConn(ctx, conn)
		if err != nil {
			s.setBFGConnected(conn.IsOnline())
			// See if we were terminated
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.holdoffTimeout):
			}
			continue
		}
		s.setBFGConnected(conn.IsOnline())
		log.Infof("handleBFGWebsocketReadUnauth %v", cmd)

		switch cmd {
		case bfgapi.CmdPingRequest:
			p := payload.(*bfgapi.PingRequest)
			response := &bfgapi.PingResponse{
				OriginTimestamp: p.Timestamp,
				Timestamp:       time.Now().Unix(),
			}
			if err := bfgapi.Write(ctx, conn, rid, response); err != nil {
				log.Errorf("handleBFGWebsocketReadUnauth write: %v",
					err)
			}
		case bfgapi.CmdBTCFinalityNotification:
			go s.handleBtcFinalityNotification()
		case bfgapi.CmdBTCNewBlockNotification:
			go s.handleBtcBlockNotification()
		default:
			log.Errorf("unknown command: %v", cmd)
			return
		}
	}
}

func (s *Server) handleBFGCallCompletion(parrentCtx context.Context, conn *protocol.Conn, bc bfgCmd) {
	log.Tracef("handleBFGCallCompletion")
	defer log.Tracef("handleBFGCallCompletion exit")

	ctx, cancel := context.WithTimeout(parrentCtx, s.bfgCallTimeout)
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

func (s *Server) callBFG(parrentCtx context.Context, msg any) (any, error) {
	log.Tracef("callBFG %T", msg)
	defer log.Tracef("callBFG exit %T", msg)

	bc := bfgCmd{
		msg: msg,
		ch:  make(chan any),
	}

	ctx, cancel := context.WithTimeout(parrentCtx, s.bfgCallTimeout)
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

func (s *Server) connectBFG(ctx context.Context) error {
	log.Tracef("connectBFG")
	defer log.Tracef("connectBFG exit")

	conn, err := protocol.NewConn(s.cfg.BFGURL, nil)
	if err != nil {
		return err
	}
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

func (s *Server) running() bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
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

func (s *Server) setBFGConnected(x bool) {
	s.mtx.Lock()
	s.bfgConnected = x
	s.mtx.Unlock()
}

func (s *Server) isBFGConnected() float64 {
	s.mtx.Lock()
	c := s.bfgConnected
	s.mtx.Unlock()
	if c {
		return 1
	}
	return 0
}

func (s *Server) Run(parrentCtx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return fmt.Errorf("bss already running")
	}
	defer s.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(parrentCtx)
	defer cancel() // just in case

	mux := http.NewServeMux()
	handle("bss", mux, bssapi.RouteWebsocket, s.handleWebsocket)

	httpServer := &http.Server{
		Addr:        s.cfg.ListenAddress,
		Handler:     mux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	httpErrCh := make(chan error)
	go func() {
		log.Infof("Listening: %v", s.cfg.ListenAddress)
		httpErrCh <- httpServer.ListenAndServe()
	}()
	defer func() {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Errorf("http server exit: %v", err)
			return
		}
		log.Infof("RPC server shutdown cleanly")
	}()

	s.wg.Add(1)
	go s.bfg(ctx) // Attempt to talk to bfg

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
				Help:      "Is bss service running.",
			}, s.promRunning),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Subsystem: promSubsystem,
				Name:      "bfg_connected",
				Help:      "Is bss connected to bfg.",
			}, s.isBFGConnected),
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

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-httpErrCh:
	}
	cancel()

	log.Infof("bss service shutting down")

	s.wg.Wait()
	log.Infof("bss service clean shutdown")

	return err
}
