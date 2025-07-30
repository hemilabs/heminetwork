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
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/v2/api/bfgapi"
	"github.com/hemilabs/heminetwork/v2/api/gethapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer/blockstream"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer/tbcgozer"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/service/deucalion"
	"github.com/hemilabs/heminetwork/v2/service/pprof"
)

const (
	logLevel = "INFO"
	appName  = "bfg" // Prometheus

	bitcoinSourceBlockstream = "blockstream"
	bitcoinSourceTBC         = "tbc"

	defaultKeystoneCount = 10

	maxBlockAge = 30 * time.Second // XXX make this configurable?

	// finality short circuit constants
	ultraFinalityDepth = 20
	minSearchDepth     = -100 // PNOOMA

	defaultOpgethURL = "http://127.0.0.1:9999/v1/ws"
	defaultNetwork   = "mainnet"
)

var log = loggo.GetLogger(appName)

type health struct {
	BitcoinBestHeight  uint64    `json:"bitcoin_best_height"`
	BitcoinBestHash    string    `json:"bitcoin_best_hash"`
	BitcoinBestTime    time.Time `json:"bitcoin_best_time"`
	EthereumBestHeight uint64    `json:"ethereum_best_height"`
	EthereumBestHash   string    `json:"ethereum_best_hash"`
	EthereumBestTime   time.Time `json:"ethereum_best_time"`
	GozerConnected     bool      `json:"gozer_connected"`
	GethConnected      bool      `json:"geth_connected"`
}

type HTTPError struct {
	Timestamp int64  `json:"timestamp"`
	Trace     string `json:"trace"`
	Message   string `json:"error"`
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s [%d:%s]", e.Message, e.Timestamp, e.Trace)
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
		BitcoinSource:       bitcoinSourceTBC,
		ListenAddress:       bfgapi.DefaultListenAddress,
		LogLevel:            logLevel,
		Network:             defaultNetwork,
		PrometheusNamespace: appName,
		OpgethURL:           defaultOpgethURL,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	params *chaincfg.Params
	gozer  gozer.Gozer
	server *http.ServeMux

	// opgeth
	opgethClient *ethclient.Client // access via Server.geth

	// Prometheus
	promPolling     bool
	promCollectors  []prometheus.Collector
	promPollVerbose bool // set to true to print stats during poll
	isRunning       bool
	cmdsProcessed   prometheus.Counter
	promHealth      health
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

	// Setup gozer
	switch s.cfg.Network {
	case "mainnet":
		s.params = &chaincfg.MainNetParams
	case "testnet3":
		s.params = &chaincfg.TestNet3Params
	case "localnet":
		s.params = &chaincfg.RegressionNetParams
	case "testnet4":
		s.params = &chaincfg.TestNet4Params
	default:
		return nil, fmt.Errorf("invalid network: %v", s.cfg.Network)
	}

	switch s.cfg.BitcoinSource {
	case bitcoinSourceBlockstream:
		var err error
		s.gozer, err = blockstream.New(s.params)
		if err != nil {
			return nil, fmt.Errorf("could not setup %v blockstream: %w",
				s.cfg.Network, err)
		}
	case bitcoinSourceTBC:
		if s.cfg.BitcoinURL == "" {
			return nil, fmt.Errorf("invalid bitcoin url")
		}
		s.gozer = tbcgozer.New(s.cfg.BitcoinURL)
	default:
		return nil, fmt.Errorf("invalid bitcoin source: %v", s.cfg.BitcoinSource)
	}

	return s, nil
}

func (s *Server) geth() (*ethclient.Client, error) {
	s.mtx.RLock()
	geth := s.opgethClient
	s.mtx.RUnlock()
	if geth == nil {
		return nil, fmt.Errorf("no connected")
	}
	return geth, nil
}

func (s *Server) Connected() bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if s.gozer != nil {
		return s.gozer.Connected()
	}
	return false
}

func random(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Errorf("read random: %w", err))
	}
	return buf
}

func Errorf(format string, args ...any) *HTTPError {
	return &HTTPError{
		Timestamp: time.Now().Unix(),
		Trace:     hex.EncodeToString(random(8)),
		Message:   fmt.Sprintf(format, args...),
	}
}

// InternalErrorf writes an HTTP 500 response with "internal error" to the
// client and logs the given error.
func InternalErrorf(w http.ResponseWriter, err error) {
	log.Errorf("internal server error: %v", err)
	writeHTTPError(w, http.StatusInternalServerError, Errorf("internal error"))
}

func BadRequestf(w http.ResponseWriter, format string, args ...any) {
	err := Errorf(format, args...)
	log.Debugf("bad request: %v", err)
	writeHTTPError(w, http.StatusBadRequest, err)
}

func NotFoundf(w http.ResponseWriter, format string, args ...any) {
	err := Errorf(format, args...)
	log.Tracef("not found: %v", err)
	writeHTTPError(w, http.StatusNotFound, err)
}

func writeHTTPError(w http.ResponseWriter, code int, httpError *HTTPError) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(httpError); err != nil {
		log.Errorf("writeHTTPError: %v", err)
	}
}

func (s *Server) callOpgeth(pctx context.Context, request any) (any, error) {
	log.Tracef("callOpgeth %T", request)
	defer log.Tracef("callOpgeth exit %T", request)

	if !s.Connected() {
		return nil, errors.New("not connected to opgeth")
	}

	ctx, cancel := context.WithTimeout(pctx, gethapi.DefaultCommandTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		switch cmd := request.(type) {
		case gethapi.L2KeystoneValidityRequest:
			resp := gethapi.L2KeystoneValidityResponse{}

			// Check if N count within bounds
			if cmd.KeystoneCount > 1000 {
				return nil, fmt.Errorf("invalid keystone count: %v",
					cmd.KeystoneCount)
			}
			geth, err := s.geth()
			if err != nil {
				return nil, err
			}
			err = geth.Client().CallContext(ctx, &resp, "kss_getKeystone",
				cmd.L2KeystoneHash, cmd.KeystoneCount)
			if err != nil {
				return nil, fmt.Errorf("error calling opgeth: %w", err)
			}
			return &resp, nil
		default:
			return nil, fmt.Errorf("unknown opgeth command: %T", request)
		}
	}
}

func calculateFinality(bestHeight uint, publishedHeight uint, hash chainhash.Hash) (bfgapi.L2KeystoneBitcoinFinalityResponse, error) {
	if publishedHeight > bestHeight {
		fin := bfgapi.L2KeystoneBitcoinFinalityResponse{}
		return fin, fmt.Errorf("invalid published height: %v best height %v",
			publishedHeight, bestHeight)
	}

	confirmations := bestHeight - publishedHeight
	superFinality := confirmations >= bfgapi.BitcoinSuperFinality
	return bfgapi.L2KeystoneBitcoinFinalityResponse{
		BlockHeight:            publishedHeight,
		BlockHash:              hash[:],
		EffectiveConfirmations: confirmations,
		SuperFinality:          &superFinality,
	}, nil
}

func (s *Server) opgethL2KeystoneValidity(ctx context.Context, hash chainhash.Hash, keystones uint) (*gethapi.L2KeystoneValidityResponse, error) {
	log.Tracef("opgethL2KeystoneValidity: %v", hash)
	defer log.Tracef("opgethL2KeystoneValidity exit: %v", hash)

	// Call op-geth to retrieve keystone and descendants.
	rp, err := s.callOpgeth(ctx, gethapi.L2KeystoneValidityRequest{
		L2KeystoneHash: hash,
		KeystoneCount:  keystones,
	})
	if err != nil {
		return nil, err
	}
	resp, ok := rp.(*gethapi.L2KeystoneValidityResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", rp)
	}
	return resp, nil
}

func (s *Server) gethBestHeightHash(pctx context.Context) (uint64, *chainhash.Hash, time.Time, error) {
	log.Tracef("gethBestHeightHash")
	defer log.Tracef("gethBestHeightHash exit")

	var t time.Time

	height := big.NewInt(int64(rpc.LatestBlockNumber))
	geth, err := s.geth()
	if err != nil {
		return 0, nil, t, err
	}

	ctx, cancel := context.WithTimeout(pctx, gethapi.DefaultCommandTimeout)
	defer cancel()
	header, err := geth.HeaderByNumber(ctx, height)
	if err != nil {
		return 0, nil, t, fmt.Errorf("error calling opgeth: %w", err)
	}
	commonHash := header.Hash()
	ch, err := chainhash.NewHash(commonHash[:])
	if err != nil {
		return 0, nil, t, err
	}
	h := header.Number.Uint64()
	t = time.Unix(int64(header.Time), 0)

	return h, ch, t, nil
}

// When enabled, short-circuiting will check for the latest keystones to achieve
// ultrafinality. If any of them are more recent (higher L2 number) than
// the keystone whose finality is being queried for, it will inherit that value.
// This attempts to prevent a hypothetical worst-case scenario where neither the
// keystone nor any close descendants have reached ultrafinality, requiring
// N amount of checks for the finality value of N descendants.
//
//nolint:unused // hyphotetically useful, but currently unused
func (s *Server) shortCircuitFinality(ctx context.Context, kss *hemi.L2Keystone, tip uint32) (*bfgapi.L2KeystoneBitcoinFinalityResponse, error) {
	// Depth must be > 0 but height + depth > 0
	// so min height is 2 and "min" depth is -1
	if tip-ultraFinalityDepth <= 0 {
		return nil, nil
	}

	height := tip - ultraFinalityDepth + 1

	// if height < 100, depth is 1 - height
	// else it is minSearchDepth
	depth := max(minSearchDepth, 1-int(height))

	// Find keystones at height beyond ultra finality
	bl, err := s.gozer.KeystonesByHeight(ctx, height, depth)
	if err != nil {
		// If error on the gozer side, return the error
		return nil, err
	}

	//nolint:nilerr // If error on the computation side, don't short circuit
	if bl.Error != nil {
		// XXX change this when protocol errors get revised
		log.Tracef("keystones by height: %w", bl.Error)
		return nil, nil
	}

	// If one of the retrieved keystones is more recent than the one we
	// queried for confirm it is valid with opgeth and, if so, short circuit.
	for _, ks := range bl.L2KeystoneAbrevs {
		if ks.L2BlockNumber >= kss.L2BlockNumber {
			valid, err := s.opgethL2KeystoneValidity(ctx, *ks.Hash(), 0)
			if err != nil {
				log.Errorf("opgeth: %v", err)
				return nil, err
			}

			if valid.Error != nil || len(valid.L2Keystones) < 1 {
				continue
			}

			rk := hemi.L2KeystoneAbbreviate(valid.L2Keystones[0])
			// Sanity check if op-geth returned the correct keystone.
			if !ks.Hash().IsEqual(rk.Hash()) {
				return nil, fmt.Errorf("opgeth mismatch keystone sent %v and retrieved %v",
					ks.Hash().String(), rk.Hash().String())
			}

			// Get block info
			res := s.gozer.BlocksByL2AbrevHashes(ctx, []chainhash.Hash{*rk.Hash()})
			if res.Error != nil {
				return nil, fmt.Errorf("retrieve block info: %w", err)
			}

			if len(res.L2KeystoneBlocks) < 1 {
				return nil, errors.New("no block info retrieved")
			}

			info := res.L2KeystoneBlocks[0]
			if info.Error != nil {
				return nil, info.Error
			}

			fin, err := calculateFinality(uint(tip), info.L2KeystoneBlockHeight,
				info.L2KeystoneBlockHash)
			if err != nil {
				return nil, err
			}

			fin.L2Keystone = *kss
			return &fin, err
		}
	}
	return nil, nil
}

func (s *Server) handleKeystoneFinality(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleKeystoneFinality: %v", r.RemoteAddr)
	defer log.Tracef("handleKeystoneFinality exit: %v", r.RemoteAddr)

	// validate input.
	qh, err := chainhash.NewHashFromStr(r.PathValue("hash"))
	if err != nil {
		BadRequestf(w, "invalid keystone length")
		return
	}

	hash := qh
	fin := &bfgapi.L2KeystoneBitcoinFinalityResponse{}
	// attempt short circuit during first loop
	// firstLoop := true
	for {
		// Call opgeth to retrieve keystones
		resp, err := s.opgethL2KeystoneValidity(r.Context(), *hash, defaultKeystoneCount)
		if err != nil {
			InternalErrorf(w, fmt.Errorf("opgeth: %w", err))
			return
		}
		if resp.Error != nil {
			NotFoundf(w, "unknown keystone: %v", resp.Error)
			return
		}

		// from Clayton: the finality must only ever be for the l2keystone
		// that we're querying for, it may inherit effective height from another
		// but is still the keystone being queried for
		if hash.IsEqual(qh) && len(resp.L2Keystones) > 0 {
			for i, k := range resp.L2Keystones {
				if hemi.L2KeystoneAbbreviate(k).Hash().IsEqual(qh) {
					fin.L2Keystone = resp.L2Keystones[i]
					log.Tracef("responding with keystone %s", spew.Sdump(k))
				}
			}
		}

		// Uncomment this out to add a shortcircuit if there are large gaps
		// between keystones getting mined.
		//
		// // During our first loop, after we retrieve the BTC Tip from our
		// // gozer call, check for possible finality short circuit.
		// if firstLoop && fin != nil {
		// 	firstLoop = false

		// 	btcTip, err := s.gozer.BtcHeight(r.Context())
		// 	if err != nil {
		// 		InternalErrorf(w, fmt.Errorf("retrieve btc tip: %w", err))
		// 		return
		// 	}
		// 	scf, err := s.shortCircuitFinality(r.Context(), &fin.L2Keystone, uint32(btcTip))
		// 	if err != nil {
		// 		InternalErrorf(w, fmt.Errorf("short circuit: %w", err)
		// 		return
		// 	}

		// 	if scf != nil {
		// 		if err := json.NewEncoder(w).Encode(scf); err != nil {
		// 			log.Errorf("encode: %v", err)
		// 		}
		// 		return
		// 	}
		// }

		// Generate abbreviated hashes from received keystones
		abrevKeystones := make([]chainhash.Hash, 0, len(resp.L2Keystones))
		km := make(map[chainhash.Hash]hemi.L2Keystone, len(resp.L2Keystones))
		for _, kss := range resp.L2Keystones {
			khash := hemi.L2KeystoneAbbreviate(kss).Hash()
			abrevKeystones = append(abrevKeystones, *khash)

			// Use state root for lookup, this is unique.
			km[chainhash.HashH(kss.StateRoot)] = kss
		}

		// Get abbreviated keystones from gozer
		aks := s.gozer.BlocksByL2AbrevHashes(r.Context(), abrevKeystones)
		if aks.Error != nil {
			InternalErrorf(w, fmt.Errorf("blocks by l2abrev hashes: %w", aks.Error))
			return
		}

		var hh *chainhash.Hash

		// Cycle through each response and replace finality value for the best
		// finality value of its descendants or itself
		for _, bk := range aks.L2KeystoneBlocks {
			if bk.Error != nil {
				log.Tracef("keystone not found: %v", bk.Error)
				continue
			}

			ks, ok := km[chainhash.HashH(bk.L2KeystoneAbrev.StateRoot)]
			if !ok {
				// This really shouldn't happen
				InternalErrorf(w, fmt.Errorf("cannot find stateroot: %v", spew.Sdump(bk)))
				return
			}

			altFin, err := calculateFinality(aks.BtcTipBlockHeight,
				bk.L2KeystoneBlockHeight, bk.L2KeystoneBlockHash)
			if err != nil {
				log.Errorf("calculate finality: %v", err)
				continue
			}
			altFin.L2Keystone = fin.L2Keystone

			if altFin.EffectiveConfirmations > fin.EffectiveConfirmations {
				fin = &altFin
			}

			// If this keystone has a higher l2 number, store the
			// abrev hash for future descendant queries to op-geth.
			// The height check is a sanity check in case the keystones
			// are not ordered.
			if ks.L2BlockNumber > fin.L2Keystone.L2BlockNumber {
				hh = hemi.L2KeystoneAbbreviate(ks).Hash()
			}
		}

		// If the last used hash for descendant queries is the
		// highest hash, then we can assume there are no more
		// descendants, and we can return the current best finality.
		// If keystone or descendant has ultrafinality then
		// we no longer have to keep iterating.
		if hh == nil || hash.IsEqual(hh) ||
			fin.EffectiveConfirmations >= ultraFinalityDepth {
			break
		}
		hash = hh
	}

	if err := json.NewEncoder(w).Encode(fin); err != nil {
		log.Errorf("encode: %v", err)
		return
	}

	s.cmdsProcessed.Inc()
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

	opgethClient, err := ethclient.DialContext(ctx, s.cfg.OpgethURL)
	if err != nil {
		return err
	}
	defer opgethClient.Close()

	s.mtx.Lock()
	s.opgethClient = opgethClient
	s.promHealth.GethConnected = true
	s.mtx.Unlock()
	defer func() {
		s.mtx.Lock()
		s.opgethClient = nil
		s.promHealth.GethConnected = false
		s.mtx.Unlock()
	}()

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
		case <-time.Tick(5 * time.Second):
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
			newValueVecFunc(prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "bitcoin_block_height",
				Help:      "Best bitcoin block canonical height and hash",
			}, []string{"hash", "timestamp"}), s.promBitcoinTime),
			newValueVecFunc(prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "ethereum_block_height",
				Help:      "Best ethereum block canonical height and hash",
			}, []string{"hash", "timestamp"}), s.promEthereumTime),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "geth_connected",
				Help:      "Whether the pop miner is connected to geth",
			}, s.promGethConnected),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "gozer_connected",
				Help:      "Whether the pop miner is connected to gozer",
			}, s.promGozerConnected),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "running",
				Help:      "Whether the BFG service is running",
			}, s.promRunning),
		}
	}
	return s.promCollectors
}

func (s *Server) promGethConnected() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if s.promHealth.GethConnected {
		return 1
	}
	return 0
}

func (s *Server) promGozerConnected() float64 {
	if s.gozer.Connected() {
		return 1
	}
	return 0
}

func (s *Server) promBitcoinTime(m *prometheus.GaugeVec) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	m.Reset()
	m.With(prometheus.Labels{
		"hash":      s.promHealth.BitcoinBestHash,
		"timestamp": strconv.Itoa(int(s.promHealth.BitcoinBestTime.Unix())),
	}).Set(deucalion.Uint64ToFloat(s.promHealth.BitcoinBestHeight))
}

func (s *Server) promEthereumTime(m *prometheus.GaugeVec) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	m.Reset()
	m.With(prometheus.Labels{
		"hash":      s.promHealth.EthereumBestHash,
		"timestamp": strconv.Itoa(int(s.promHealth.EthereumBestTime.Unix())),
	}).Set(deucalion.Uint64ToFloat(s.promHealth.EthereumBestHeight))
}

func (s *Server) promPoll(pctx context.Context) error {
	promPollFrequency := 5 * time.Second
	ticker := time.NewTicker(promPollFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-pctx.Done():
			return pctx.Err()
		case <-ticker.C:
		}

		s.mtx.Lock()
		gozer := s.gozer
		if gozer == nil {
			// Not ready
			s.promHealth = health{}
			s.mtx.Unlock()
			continue
		}
		if s.promPolling {
			s.mtx.Unlock()
			continue
		}
		s.promPolling = true
		s.mtx.Unlock()

		ctx, cancel := context.WithTimeout(pctx, promPollFrequency-time.Second)

		var h health
		if height, hash, t, err := s.gozer.BestHeightHashTime(ctx); err == nil {
			h.BitcoinBestHeight = height
			h.BitcoinBestHash = hash.String()
			h.BitcoinBestTime = t
			h.GozerConnected = true
		} else {
			log.Debugf("btc height hash: %v", err)
			h.BitcoinBestHeight = 0
			h.BitcoinBestHash = ""
			h.BitcoinBestTime = time.Time{}
			h.GozerConnected = false
		}

		if height, hash, t, err := s.gethBestHeightHash(ctx); err == nil {
			h.EthereumBestHeight = height
			h.EthereumBestHash = hash.String()
			h.EthereumBestTime = t
			h.GethConnected = true
		} else {
			log.Debugf("geth height hash: %v", err)
			h.EthereumBestHeight = 0
			h.EthereumBestHash = ""
			h.EthereumBestTime = time.Time{}
			h.GethConnected = false
		}

		cancel()

		s.mtx.Lock()
		s.promHealth = h
		s.promPolling = false
		s.mtx.Unlock()

		if s.promPollVerbose {
			log.Infof("gozer connected: %v geth connected %v",
				h.GozerConnected, h.GethConnected)
		}
		ticker.Reset(promPollFrequency)
	}
}

func (s *Server) isHealthy(_ context.Context) bool {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if age := time.Since(s.promHealth.EthereumBestTime); age > maxBlockAge ||
		!s.promHealth.GozerConnected || !s.promHealth.GethConnected {
		return false
	}
	return true
}

func (s *Server) health(ctx context.Context) (bool, any, error) {
	log.Tracef("health")
	defer log.Tracef("health exit")

	s.mtx.RLock()
	h := s.promHealth
	s.mtx.RUnlock()

	return s.isHealthy(ctx), h, nil
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

	err := s.gozer.Run(ctx, nil)
	if err != nil {
		return fmt.Errorf("gozer run: %w", err)
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
			if err := d.Run(ctx, s.Collectors(), s.health); !errors.Is(err, context.Canceled) {
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
