// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer/blockstream"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer/tbcgozer"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
)

const (
	logLevel = "INFO"
	appName  = "bfg" // Prometheus

	bitcoinSourceBlockstream = "blockstream"
	bitcoinSourceTBC         = "tbc"
)

var log = loggo.GetLogger(appName)

type HttpError struct {
	Timestamp int64  `json:"timestamp"`
	Trace     string `json:"trace"`
	Error     string `json:"error"`
}

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	BitcoinSource           string // gozer types
	BitcoinURL              string // only used for certain types
	ListenAddress           string
	LogLevel                string
	Network                 string // bitcoin network
	PprofListenAddress      string
	PrometheusListenAddress string
	PrometheusNamespace     string
	OpgethURL               string
}

func NewDefaultConfig() *Config {
	return &Config{
		BitcoinSource:       bitcoinSourceBlockstream,
		ListenAddress:       bfgapi.DefaultListenAddress,
		LogLevel:            logLevel,
		Network:             "mainnet",
		PrometheusNamespace: appName,
		OpgethURL:           "http://127.0.0.1:9999/v1/ws", // XXX set this using defaults
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	params *chaincfg.Params

	g gozer.Gozer

	server *http.ServeMux

	// opgeth
	opgethClient *ethclient.Client // XXX evaluate if ok

	// Prometheus
	promCollectors  []prometheus.Collector
	promPollVerbose bool // set to true to print stats during poll
	isRunning       bool
	cmdsProcessed   prometheus.Counter
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	s := &Server{
		cfg:    cfg,
		server: http.NewServeMux(),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: cfg.PrometheusNamespace,
			Name:      "web_calls_total",
			Help:      "The total number of successful web commands",
		}),
	}

	return s, nil
}

func random(n int) []byte {
	buffer := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		panic("random")
	}
	return buffer
}

func Error(format string, args ...any) (*HttpError, []byte, error) {
	e := &HttpError{
		Timestamp: time.Now().Unix(),
		Trace:     hex.EncodeToString(random(8)),
		Error:     fmt.Sprintf(format, args...),
	}
	je, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return e, je, err
}

func BadRequestF(w http.ResponseWriter, format string, args ...any) {
	e, je, err := Error(format, args...)
	if err != nil {
		panic(err)
	}
	log.Errorf("bad request: %v trace %v error %v", e.Timestamp, e.Trace, e.Error)
	http.Error(w, string(je), http.StatusBadRequest)
}

func NotFound(w http.ResponseWriter, format string, args ...any) {
	e, je, err := Error(format, args...)
	if err != nil {
		panic(err)
	}
	log.Tracef("not found: %v trace %v error %v", e.Timestamp, e.Trace, e.Error)
	http.Error(w, string(je), http.StatusNotFound)
}

func calculateFinality(btcTipHeight uint32, pubHeight uint32, pubHeaderHash chainhash.Hash) (*bfgapi.L2BTCFinality, error) {
	if pubHeight > btcTipHeight {
		return nil, fmt.Errorf("effective height greater than btc height (%d > %d)", pubHeight, btcTipHeight)
	}

	log.Infof("%v, %v", btcTipHeight, pubHeight)

	fin := int64(-9)
	if pubHeight > 0 {
		fin = int64(btcTipHeight) - int64(pubHeight) - 9 + 1
	}

	// set a reasonable upper bound so we can safely convert to int32
	if fin > 100 {
		fin = 100
	}

	return &bfgapi.L2BTCFinality{
		BTCPubHeight:     int64(pubHeight),
		BTCPubHeaderHash: api.ByteSlice(pubHeaderHash[:]),
		BTCFinality:      int32(fin),
	}, nil
}

func (s *Server) handleKeystoneFinality(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleKeystoneFinality: %v", r.RemoteAddr)
	defer log.Tracef("handleKeystoneFinality exit: %v", r.RemoteAddr)

	keystone := r.PathValue("hash")
	if keystone == "" {
		fmt.Fprintf(w, "this is the last keystone")
		return
	}

	if len(keystone) != chainhash.MaxHashStringSize {
		BadRequestF(w, "invalid keystone length")
		return
	}
	ks, err := chainhash.NewHashFromStr(keystone)
	if err != nil {
		BadRequestF(w, "invalid keystone: %v", err)
		return
	}

	resp := bfgapi.L2KeystoneValidityResponse{}

	err = s.opgethClient.Client().Call(&resp, "kss_getKeystone", keystone)
	if err != nil {
		log.Errorf("error calling opgeth: %v", err)
		fmt.Fprintf(w, "internal BFG error")
		return
	}

	if resp.Error != nil {
		BadRequestF(w, "invalid keystone: %v", resp.Error)
		return
	}

	for _, kss := range resp.L2KeystonesHashes {
		// XXX might need a different call which takes
		// into account the fork resolution algorithm
		aks, err := s.g.BlockKeystoneByL2KeystoneAbrevHash(r.Context(), kss)
		if err != nil {
			log.Errorf("keystone not found: %v", ks)
			continue
		}

		fin, err := calculateFinality(uint32(aks.BtcTipBlockHeight), uint32(aks.L2KeystoneBlockHeight), aks.L2KeystoneBlockHash)
		if err != nil {
			log.Errorf("calculate finality: %v", err)
			continue
		}

		if err := json.NewEncoder(w).Encode(fin); err != nil {
			log.Errorf("encode: %v", err)
		}

		s.cmdsProcessed.Inc()
		return
	}

	NotFound(w, "keystone not found: %v", ks)
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

func (s *Server) connectOpgeth(pctx context.Context) error {
	log.Tracef("connectOpgeth")
	defer log.Tracef("connectOpgeth exit")

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	var err error
	s.opgethClient, err = ethclient.DialContext(ctx, s.cfg.OpgethURL)
	if err != nil {
		return err
	}
	defer s.opgethClient.Close()

	log.Debugf("connected to opgeth: %s", s.cfg.OpgethURL)

	<-ctx.Done()
	err = ctx.Err()

	return err
}

func (s *Server) opgeth(ctx context.Context) {
	log.Tracef("opgeth")
	defer log.Tracef("opgeth exit")

	for {
		log.Tracef("connecting to: %v", s.cfg.OpgethURL)
		if err := s.connectOpgeth(ctx); err != nil {
			// Do nothing
			log.Tracef("connectOpgeth: %v", err)
		} else {
			log.Infof("Connected to opgeth: %s", s.cfg.OpgethURL)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		log.Debugf("reconnecting to: %v", s.cfg.OpgethURL)
	}
}

// Collectors returns the Prometheus collectors available for the server.
func (s *Server) Collectors() []prometheus.Collector {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.promCollectors == nil {
		// Naming: https://prometheus.io/docs/practices/naming/
		s.promCollectors = []prometheus.Collector{
			s.cmdsProcessed,
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "running",
				Help:      "Whether the BFG service is running",
			}, s.promRunning),
		}
	}
	return s.promCollectors
}

func (s *Server) promPoll(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}

		if s.promPollVerbose {
			s.mtx.RLock()
			log.Infof("FIXME PROMETHEUS POLL")
			s.mtx.RUnlock()
		}

	}
}

func (s *Server) Run(pctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return errors.New("bfg already running")
	}
	defer s.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// Setup gozer
	switch s.cfg.Network {
	case "mainnet":
		s.params = &chaincfg.MainNetParams
	case "testnet3":
		s.params = &chaincfg.TestNet3Params
	default:
		return fmt.Errorf("invalid network: %v", s.cfg.Network)
	}

	switch s.cfg.BitcoinSource {
	case bitcoinSourceBlockstream:
		var err error
		s.g, err = blockstream.BlockstreamNew(s.params)
		if err != nil {
			return fmt.Errorf("could not setup %v blockstream: %w",
				s.cfg.Network, err)
		}
	case bitcoinSourceTBC:
		var err error
		s.g, err = tbcgozer.TBCGozerNew(ctx, s.cfg.BitcoinURL)
		if err != nil {
			return fmt.Errorf("could not setup %v tbc: %w",
				s.cfg.Network, err)
		}
	default:
		return fmt.Errorf("invalid bitcoin source: %v", s.cfg.BitcoinSource)
	}

	// HTTP server
	httpErrCh := make(chan error)
	if s.cfg.ListenAddress != "" {
		mux := http.NewServeMux()
		log.Infof("handle keystone finality: %s", bfgapi.RouteKeystoneFinality)
		mux.HandleFunc(bfgapi.RouteKeystoneFinality, s.handleKeystoneFinality)

		httpServer := &http.Server{
			Addr:        s.cfg.ListenAddress,
			Handler:     mux,
			BaseContext: func(_ net.Listener) context.Context { return ctx },
		}
		go func() {
			log.Infof("Listening: %s", s.cfg.ListenAddress)
			httpErrCh <- httpServer.ListenAndServe()
		}()
		defer func() {
			if err := httpServer.Shutdown(ctx); err != nil {
				log.Errorf("http server exit: %v", err)
				return
			}
			log.Infof("web server shutdown cleanly")
		}()
	}

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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := d.Run(ctx, s.Collectors()); !errors.Is(err, context.Canceled) {
				log.Errorf("prometheus terminated with error: %v", err)
				return
			}
			log.Infof("prometheus clean shutdown")
		}()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			err := s.promPoll(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Errorf("prometheus poll terminated with error: %v", err)
				}
				return
			}
		}()
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.opgeth(ctx)
	}()

	// Welcome user.

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-httpErrCh:
	}
	cancel()

	log.Infof("bfg service shutting down")
	s.wg.Wait()
	log.Infof("bfg service clean shutdown")

	return err
}
