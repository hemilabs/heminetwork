// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package twc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/twcapi"
)

const (
	logLevel = "INFO"
	appName  = "twc"

	// defaultCmdTimeout = 7 * time.Second
)

var log = loggo.GetLogger(appName)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

/*
type btcClient interface {
	Metrics() []prometheus.Collector
	Balance(ctx context.Context, scriptHash []byte) (*electrs.Balance, error)
	Broadcast(ctx context.Context, rtx []byte) ([]byte, error)
	UTXOs(ctx context.Context, scriptHash []byte) ([]*electrs.UTXO, error)
	Close() error
}
*/

type Config struct {
	LevelDBHome             string
	ListenAddress           string
	LogLevel                string
	Network                 string
	PrometheusListenAddress string
	PrometheusNamespace     string
	RequestLimit            int
	// RequestTimeout       twcapi.DefaultRequestTimeout
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenAddress:       twcapi.DefaultListen,
		LogLevel:            logLevel,
		PrometheusNamespace: appName,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	requestLimiter chan bool

	// stats
	printTime time.Time

	// WebSockets
	sessions       map[string]*twcWs
	requestTimeout time.Duration

	isRunning bool
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}

	defaultRequestTimeout := 10 * time.Second // XXX: make config option?
	s := &Server{
		cfg:            cfg,
		requestLimiter: make(chan bool, cfg.RequestLimit),
		printTime:      time.Now().Add(10 * time.Second),
		requestTimeout: defaultRequestTimeout,
		sessions:       make(map[string]*twcWs),
	}
	for range cfg.RequestLimit {
		s.requestLimiter <- true
	}

	return s, nil
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	if !s.testAndSetRunning(true) {
		return errors.New("twc already running")
	}
	defer s.testAndSetRunning(false)

	var err error

	// HTTP server
	mux := http.NewServeMux()
	log.Infof("handle (twc): %s", twcapi.RouteWebsocket)
	mux.HandleFunc(twcapi.RouteWebsocket, s.handleWebsocket)

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
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Errorf("http server exit: %v", err)
			return
		}
		log.Infof("RPC server shutdown cleanly")
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-httpErrCh:
	}
	cancel()

	log.Infof("twc service shutting down")
	s.wg.Wait()
	log.Infof("twc service clean shutdown")

	return err
}

/*
func (s *Server) handleBitcoinBalance(ctx context.Context, bbr *twcapi.BitcoinBalanceRequest) (any, error) {
	log.Tracef("handleBitcoinBalance")
	defer log.Tracef("handleBitcoinBalance exit")

	balance, err := s.btcClient.Balance(ctx, bbr.ScriptHash)
	if err != nil {
		e := protocol.NewInternalErrorf("bitcoin balance: %w", err)
		return &twcapi.BitcoinBalanceResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &twcapi.BitcoinBalanceResponse{
		Confirmed:   balance.Confirmed,
		Unconfirmed: balance.Unconfirmed,
	}, nil
}

func (s *Server) handleBitcoinUTXOs(ctx context.Context, bur *twcapi.BitcoinUTXOsRequest) (any, error) {
	log.Tracef("handleBitcoinUTXOs")
	defer log.Tracef("handleBitcoinUTXOs exit")

	utxos, err := s.btcClient.UTXOs(ctx, bur.ScriptHash)
	if err != nil {
		e := protocol.NewInternalErrorf("bitcoin utxos: %w", err)
		return &twcapi.BitcoinUTXOsResponse{
			Error: e.ProtocolError(),
		}, e

	}
	buResp := twcapi.BitcoinUTXOsResponse{}
	for _, utxo := range utxos {
		buResp.UTXOs = append(buResp.UTXOs, &twcapi.BitcoinUTXO{
			Hash:  utxo.Hash,
			Index: utxo.Index,
			Value: utxo.Value,
		})
	}

	return buResp, nil
}*/

func (s *Server) Running() bool {
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
