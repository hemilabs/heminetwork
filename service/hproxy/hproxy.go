// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/v2/service/deucalion"
	"github.com/hemilabs/heminetwork/v2/service/pprof"
)

type Node struct {
	NodeURL string `json:"node_url"`
}

type NodeError struct {
	NodeURL string `json:"node_url"`
	Error   string `json:"error"`
}

type NodeHealth struct {
	NodeURL     string `json:"node_url"`
	Status      string `json:"status"`
	Connections int    `json:"connections"`
}

const (
	appName = "hproxy" // Prometheus

	logLevel = "INFO"

	// XXX think about these durations
	DefaultClientIdleTimeout = 5 * time.Minute  // Reap timer for client persistence
	DefaultRequestTimeout    = 9 * time.Second  // Smaller than 12s
	DefaultPollFrequency     = 11 * time.Second // Smaller than 12s
	DefaultListenAddress     = "localhost:8545" // Default geth port
	DefaultControlAddress    = "localhost:1337" // Default control port

	expectedClients = 1000

	routeControl       = "/v1/control"
	RouteControlAdd    = routeControl + "/add"
	RouteControlRemove = routeControl + "/remove"
	RouteControlList   = routeControl + "/list"
)

var (
	log            = loggo.GetLogger(appName)
	measureLatency = true
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type ForbiddenMethodError struct {
	method string
}

func (fme ForbiddenMethodError) Error() string {
	return fmt.Sprintf("method not allowed: %s", fme.method)
}

func (fme ForbiddenMethodError) Is(target error) bool {
	_, ok := target.(ForbiddenMethodError)
	return ok
}

var ErrForbiddenMethod ForbiddenMethodError

func handle(service string, mux *http.ServeMux, pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandleFunc(pattern, handler)
	log.Infof("handle (%v): %v", service, pattern)
}

func dialer(pctx context.Context, network, addr string) (net.Conn, error) {
	log.Tracef("handleProxyDial: %v %v", network, addr)
	defer log.Tracef("handleProxyDial exit: %v %v", network, addr)

	defaultDialTimeout := 5 * time.Second
	d := &net.Dialer{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     7 * time.Second,
			Interval: 7 * time.Second,
			Count:    2,
		},
	}
	ctx, cancel := context.WithTimeout(pctx, defaultDialTimeout)
	defer cancel()
	return d.DialContext(ctx, network, addr)
}

// client structure handles persistence and client timeouts. We can't use TTL
// here because we need to be able to reset the timer.
type client struct {
	node   int // persistent node
	ticker *time.Ticker
}

// newClient creates a new client that has a timeout callback function. This
// can be used to construct a idle timeout reaper.
//
// XXX this function is remarkably slow, we should call it sparingly unlike
// we do now. Reaped clients should be halted and returned to a pool for
// future use.
func newClient(ctx context.Context, node int, duration time.Duration, timeout func()) *client {
	c := &client{
		node:   node,
		ticker: time.NewTicker(duration),
	}
	go func() {
		select {
		case <-ctx.Done():
			c.ticker.Stop()
		case <-c.ticker.C:
			timeout()
		}
	}()
	return c
}

func (c *client) reset(duration time.Duration) {
	c.ticker.Reset(duration)
}

func (c *client) abort() {
	c.ticker.Stop()
}

type Config struct {
	ClientIdleTimeout       time.Duration
	ControlAddress          string
	HVMURLs                 []string
	ListenAddress           string
	LogLevel                string
	MethodFilter            []string
	Network                 string
	PollFrequency           time.Duration
	PrometheusListenAddress string
	PrometheusNamespace     string
	PprofListenAddress      string
	RequestTimeout          time.Duration
}

func NewDefaultConfig() *Config {
	return &Config{
		ClientIdleTimeout:   DefaultClientIdleTimeout,
		ControlAddress:      DefaultControlAddress,
		ListenAddress:       DefaultListenAddress,
		PollFrequency:       DefaultPollFrequency,
		Network:             "mainnet",
		PrometheusNamespace: appName,
		RequestTimeout:      DefaultRequestTimeout,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	httpServer *http.Server // We need the BaseContext in client requests

	cfg *Config

	hvmHandlers []HVMHandler       // hvm nodes
	clients     map[string]*client // [ip_address]server_id

	// method whitelist
	// doesn't require locking as it's created on
	// startup, and isn't modified further
	whitelist map[string]interface{}

	// Prometheus
	promCollectors        []prometheus.Collector
	promPollVerbose       bool // set to true to print stats during poll
	isRunning             bool
	cmdsProcessed         prometheus.Counter
	promHealth            health
	persistentConnections uint64
	setupDuration         int64
	proxyDuration         int64
	proxyCalls            int64
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}

	s := &Server{
		cfg:     cfg,
		clients: make(map[string]*client, expectedClients),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: cfg.PrometheusNamespace,
			Name:      "proxy_calls",
			Help:      "The total number of successful proxy calls",
		}),
		whitelist: make(map[string]any, len(cfg.MethodFilter)),
	}

	switch strings.ToLower(cfg.Network) {
	case "mainnet":
	case "sepolia":
	default:
		return nil, fmt.Errorf("unknown network %q", cfg.Network)
	}

	for _, m := range cfg.MethodFilter {
		s.whitelist[m] = nil
	}

	return s, nil
}

func (s *Server) promHVMNew() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return deucalion.IntToFloat(s.promHealth.NewNodes)
}

func (s *Server) promHVMHealthy() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return deucalion.IntToFloat(s.promHealth.HealthyNodes)
}

func (s *Server) promHVMUnhealthy() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return deucalion.IntToFloat(s.promHealth.UnhealthyNodes)
}

func (s *Server) promHVMRemoved() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return deucalion.IntToFloat(s.promHealth.RemovedNodes)
}

func (s *Server) promConnections() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return deucalion.Uint64ToFloat(s.persistentConnections)
}

func (s *Server) promAvgClientSetupLatency() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if s.proxyCalls == 0 {
		return 0
	}
	return math.Round(float64(s.setupDuration) / float64(s.proxyCalls))
}

func (s *Server) promAvgProxyLatency() float64 {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if s.proxyCalls == 0 {
		return 0
	}
	return math.Round(float64(s.proxyDuration) / float64(s.proxyCalls))
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
				Help:      "Whether the hproxy service is running",
			}, s.promRunning),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "hvm_new",
				Help:      "Number of new HVMs",
			}, s.promHVMNew),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "hvm_healthy",
				Help:      "Number of healthy HVMs",
			}, s.promHVMHealthy),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "hvm_unhealthy",
				Help:      "Number of unhealthy HVMs",
			}, s.promHVMUnhealthy),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "hvm_removed",
				Help:      "Number of removed HVMs",
			}, s.promHVMRemoved),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Namespace: s.cfg.PrometheusNamespace,
				Name:      "connections",
				Help:      "Number of active client connections",
			}, s.promConnections),
		}
		if measureLatency {
			s.promCollectors = append(s.promCollectors,
				prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Namespace: s.cfg.PrometheusNamespace,
					Name:      "avg_client_setup_latency",
					Help:      "Average client setup latency in nanoseconds",
				}, s.promAvgClientSetupLatency),
				prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Namespace: s.cfg.PrometheusNamespace,
					Name:      "avg_proxy_latency",
					Help:      "Average proxy latency in nanoseconds",
				}, s.promAvgProxyLatency),
			)
		}
	}
	return s.promCollectors
}

func (s *Server) promPoll(ctx context.Context) error {
	promPollFrequency := 5 * time.Second
	ticker := time.NewTicker(promPollFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		var (
			h           health
			connections uint64
		)
		s.mtx.Lock()
		for k := range s.hvmHandlers {
			if measureLatency {
				s.setupDuration += s.hvmHandlers[k].setupDuration
				s.proxyDuration += s.hvmHandlers[k].proxyDuration
				s.proxyCalls += s.hvmHandlers[k].proxyCalls
			}
			switch s.hvmHandlers[k].state {
			case StateNew:
				h.NewNodes++
			case StateHealthy:
				h.HealthyNodes++
				connections += uint64(s.hvmHandlers[k].connections)
			case StateUnhealthy:
				h.UnhealthyNodes++
			case StateRemoved:
				h.RemovedNodes++
			}
		}
		s.promHealth = h
		s.persistentConnections = connections
		s.mtx.Unlock()

		if s.promPollVerbose {
			log.Infof("new: %v healthy: %v unhealthy: %v removed: %v "+
				"persistent connections: %v", h.NewNodes,
				h.HealthyNodes, h.UnhealthyNodes, h.RemovedNodes,
				connections)
		}
		ticker.Reset(promPollFrequency)
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

func (s *Server) isHealthy(_ context.Context) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for k := range s.hvmHandlers {
		// If we see a single hvm unhealthy bail with unhealthy
		// status.
		//
		// XXX i think this is technically correct but we do return
		// 503 to the caller here.
		if s.hvmHandlers[k].state == StateUnhealthy {
			return false
		}
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

type HVMState int

type health struct {
	NewNodes       int `json:"new_nodes"`
	HealthyNodes   int `json:"healthy_nodes"`
	UnhealthyNodes int `json:"unhealthy_nodes"`
	RemovedNodes   int `json:"removed_nodes"`
}

const (
	StateNew       HVMState = 0
	StateHealthy   HVMState = 1
	StateUnhealthy HVMState = 2
	StateRemoved   HVMState = 3
)

var stateString = map[HVMState]string{
	StateNew:       "new",
	StateHealthy:   "healthy",
	StateUnhealthy: "unhealthy",
	StateRemoved:   "removed",
}

type HVMHandler struct {
	id int // node id

	rp *httputil.ReverseProxy
	u  *url.URL     // Connection URL for HVM
	c  *http.Client // In here to reuse connection

	connections uint // Open connections

	poking bool // true when getting health
	poker  Proxy
	state  HVMState // Do NOT directly set, use utility functions!

	// latency stats
	setupDuration int64 // Time spent on setting up and routing call
	proxyDuration int64 // Time spent sending the call over the wall
	proxyCalls    int64 // Total number of calls
}

func (s *Server) handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProxyRequest: %v", r.RemoteAddr)
	defer log.Tracef("handleProxyRequest exit: %v", r.RemoteAddr)

	startTime := time.Now()

	if err := s.filterRequest(r); err != nil {
		if errors.Is(err, ErrForbiddenMethod) {
			w.Header().Set("Allow", strings.Join(s.cfg.MethodFilter, ", "))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Select host to call
	s.mtx.Lock()
	id := -1
	if v, ok := s.clients[r.RemoteAddr]; ok {
		// Only call same host when healthy
		if s.hvmHandlers[v.node].state == StateHealthy {
			id = v.node
			v.reset(s.cfg.ClientIdleTimeout) // reset timer for reuse here
		} else {
			// hvm died, remove persisted client
			s._clientRemove(r.RemoteAddr)
		}
	}

	// Find suitable candidate
	if id == -1 {
		var leastConnections uint = math.MaxUint
		for k := range s.hvmHandlers {
			if s.hvmHandlers[k].state == StateHealthy {
				if s.hvmHandlers[k].connections < leastConnections {
					leastConnections = s.hvmHandlers[k].connections
					id = k
				}
			}
		}
		if id >= 0 {
			// Add connection to candidate.
			//
			// We need global context here, not request context
			// since that one goes away prior the client idle
			// timeout.
			// XXX newClient is very expensive. See function for
			// additional comments.
			s.clients[r.RemoteAddr] = newClient(s.httpServer.BaseContext(nil), id,
				s.cfg.ClientIdleTimeout, func() {
					s.clientRemove(r.RemoteAddr)
				})
			s.hvmHandlers[id].connections++
		}
	}
	s.mtx.Unlock()

	// If no candidate was found return error
	if id == -1 {
		// No candidates, exit with error
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// XXX this is expensive
	log.Debugf("handleProxyRequest: remote %v url '%v' -> node %v",
		r.RemoteAddr, r.URL, id)

	setupDuration := time.Since(startTime)

	// Throw call over the fence
	w.Header().Set("X-Hproxy", strconv.Itoa(id))
	s.hvmHandlers[id].rp.ServeHTTP(w, r)
	s.cmdsProcessed.Inc()

	proxyDuration := time.Since(startTime)

	// XXX this is where we need to rethink using a single mutex.
	if measureLatency {
		s.mtx.Lock()
		s.hvmHandlers[id].setupDuration += int64(setupDuration)
		s.hvmHandlers[id].proxyDuration += int64(proxyDuration)
		s.hvmHandlers[id].proxyCalls += 1
		s.mtx.Unlock()
	}
}

// func (s *Server) handleProxyError(w http.ResponseWriter, r *http.Request, e error) {
//	log.Tracef("handleProxyError: %v", r.RemoteAddr)
//	defer log.Tracef("handleProxyError exit: %v", r.RemoteAddr)
//
//	// XXX only called when ModifyResponse is used.
//
//	//cs := spew.ConfigState{
//	//	DisableMethods:        true,
//	//	DisablePointerMethods: true,
//	//	ContinueOnMethod:      true,
//	//}
//
//	// log.Errorf("proxy error: %T", e)
//	// log.Errorf("proxy error: %v", cs.Sdump(e))
//
//	// connection errors
//	// XXX or is this all ohio?
//	var netErr net.Error
//	switch {
//	case errors.As(e, &netErr) && netErr.Timeout():
//		w.WriteHeader(http.StatusBadGateway)
//	case errors.Is(e, net.ErrClosed):
//		w.WriteHeader(http.StatusBadGateway)
//	case errors.Is(e, net.ErrWriteToConnected):
//		w.WriteHeader(http.StatusBadGateway)
//	case errors.Is(e, syscall.ECONNREFUSED):
//		w.WriteHeader(http.StatusBadGateway)
//	default:
//		panic(e)
//	}
// }

func (s *Server) filterRequest(r *http.Request) error {
	// copy and reset body
	const byteLimit = 5 * 1024 * 1024 // 5 MiB
	lr := io.LimitReader(r.Body, byteLimit)
	data, err := io.ReadAll(lr)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(data))

	var j EthereumRequest
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&j); err != nil {
		return errors.New("unknown request type")
	}
	if _, ok := s.whitelist[j.Method]; !ok {
		return ForbiddenMethodError{method: j.Method}
	}
	return nil
}

func (s *Server) _clientRemove(remoteAddr string) {
	if v, ok := s.clients[remoteAddr]; ok {
		v.abort()
		delete(s.clients, remoteAddr)
	}
}

func (s *Server) clientRemove(remoteAddr string) {
	s.mtx.Lock()
	s._clientRemove(remoteAddr)
	s.mtx.Unlock()
}

func (s *Server) nodeAdd(node string) error {
	u, err := url.Parse(node)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported scheme: %v", u.Scheme)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// make sure it isn't a dupe
	for k := range s.hvmHandlers {
		if s.hvmHandlers[k].u.String() == u.String() {
			if s.hvmHandlers[k].state == StateRemoved {
				s._newNode(k) // add it back
				return nil
			}
			return errors.New("duplicate")
		}
	}

	hvmHandler := HVMHandler{
		id:    len(s.hvmHandlers),
		state: StateNew,
		u:     u,
		c: &http.Client{
			Transport: &http.Transport{
				DialContext:           dialer,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: s.cfg.RequestTimeout,
			},
		},
		// Ethereum only needs what is set. If we want to make this
		// generic we may have to fart with this a bit.
		rp: &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(u)
				r.SetXForwarded()
			},
			Director: nil, // not needed
			Transport: &http.Transport{
				DialContext:           dialer,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: s.cfg.RequestTimeout,
				MaxIdleConnsPerHost:   1, // XXX think about this
				MaxConnsPerHost:       1, // XXX think about this
			},
			FlushInterval:  0,
			ErrorLog:       nil, // XXX wrap in loggo
			BufferPool:     nil, // not useful for different sized calls
			ModifyResponse: nil, // not needed
			ErrorHandler:   nil, // s.handleProxyError, ModifyResponse only
		},
	}

	// For now, everything is ethereum, but we can use the poker function
	// to handle different types health checks.
	hvmHandler.poker = NewEthereumProxy(newEthereumPoker(hvmHandler.c, hvmHandler.u.String()))

	s.hvmHandlers = append(s.hvmHandlers, hvmHandler)

	return nil
}

// newEthereumPoker returns a new poker which checks the health of an
// Ethereum node. The health of the node is determined by the age of the
// latest block.
func newEthereumPoker(client *http.Client, url string) func(ctx context.Context) error {
	const maxBlockAge = 30 * time.Second // TODO: make this configurable?

	// TODO: Improve health checks.

	return func(ctx context.Context) error {
		blockRes, err := CallEthereum(ctx, client, url,
			"eth_getBlockByNumber", "latest", false)
		if err != nil {
			return err
		}
		if blockRes.Error != nil {
			var eErr struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if err = json.Unmarshal(blockRes.Error, &eErr); err != nil {
				return fmt.Errorf("eth_getBlockByNumber error: %w", err)
			}
			return fmt.Errorf("ethereum call failed code %v, message %v",
				eErr.Code, eErr.Message)
		}

		var block struct {
			Timestamp string `json:"timestamp"`
		}
		if err = json.Unmarshal(blockRes.Result, &block); err != nil {
			return fmt.Errorf("eth_getBlockByNumber result: %w", err)
		}

		ts, err := strconv.ParseInt(block.Timestamp, 0, 64)
		if err != nil {
			return fmt.Errorf("eth_getBlockByNumber timestamp: %w", err)
		}

		if age := time.Since(time.Unix(ts, 0)); age > maxBlockAge {
			return fmt.Errorf("eth_getBlockByNumber timestamp "+
				"too old: %v (%v ago)", block.Timestamp, age)
		}

		return nil
	}
}

func (s *Server) removeNode(node string) error {
	u, err := url.Parse(node)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported scheme: %v", u.Scheme)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// make sure it isn't a dupe
	for k := range s.hvmHandlers {
		if s.hvmHandlers[k].u.String() == u.String() {
			if s.hvmHandlers[k].state != StateRemoved {
				s._nodeRemoved(k)
				return nil
			}
			return errors.New("already removed")
		}
	}
	return errors.New("not found")
}

// _countNode must be called with the mutex held.
func (s *Server) _countNode(id int) int {
	var count int
	for _, v := range s.clients {
		if v.node == id {
			count++
		}
	}
	return count
}

// _reapNode must be called with the mutex held.
func (s *Server) _reapNode(id int) {
	for k, v := range s.clients {
		if v.node == id {
			delete(s.clients, k)
		}
	}
}

// _newNode must be called with lock held.
func (s *Server) _newNode(id int) {
	if s.hvmHandlers[id].state != StateNew {
		s.hvmHandlers[id].connections = 0 // reset connections
		s.hvmHandlers[id].state = StateNew
		s._reapNode(id)
		log.Infof("Marking hvm new %v: %v", id, s.hvmHandlers[id].u)
	}
}

// _nodeRemoved must be called with lock held.
func (s *Server) _nodeRemoved(id int) {
	if s.hvmHandlers[id].state != StateRemoved {
		s.hvmHandlers[id].connections = 0 // reset connections
		s.hvmHandlers[id].state = StateRemoved
		s._reapNode(id)
		log.Infof("Marking hvm removed %v: %v", id, s.hvmHandlers[id].u)
	}
}

func (s *Server) nodeHealthy(id int) {
	s.mtx.Lock()
	if s.hvmHandlers[id].state != StateHealthy {
		s.hvmHandlers[id].connections = 0 // reset connections
		s.hvmHandlers[id].state = StateHealthy
		s._reapNode(id)
		log.Infof("Marking hvm healthy %v: %v", id, s.hvmHandlers[id].u)
	}
	s.mtx.Unlock()
}

func (s *Server) nodeUnhealthy(id int, err error) {
	s.mtx.Lock()
	if s.hvmHandlers[id].state != StateUnhealthy {
		s.hvmHandlers[id].connections = 0 // reset connections
		s.hvmHandlers[id].state = StateUnhealthy
		s._reapNode(id)
		log.Infof("Marking hvm unhealthy %v: %v reason: %v",
			id, s.hvmHandlers[id].u, err)
	}
	s.mtx.Unlock()
}

func (s *Server) poke(ctx context.Context, id int) {
	log.Tracef("poke: %v", id)
	defer log.Tracef("poke exit: %v", id)

	s.mtx.Lock()
	if s.hvmHandlers[id].poking {
		s.mtx.Unlock()
		return
	}
	s.hvmHandlers[id].poking = true
	poker := s.hvmHandlers[id].poker
	s.mtx.Unlock()
	defer func() {
		s.mtx.Lock()
		s.hvmHandlers[id].poking = false
		s.mtx.Unlock()
	}()

	err := poker.Poke(ctx)
	if err != nil {
		s.nodeUnhealthy(id, err)
	} else {
		s.nodeHealthy(id)
	}
}

func (s *Server) monitor(ctx context.Context) {
	log.Tracef("monitor")
	defer log.Tracef("monitor exit")
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.PollFrequency)
	defer ticker.Stop()
	for {
		// Poke hvms
		s.mtx.Lock()
		for k := range s.hvmHandlers {
			if s.hvmHandlers[k].state != StateRemoved {
				go s.poke(ctx, k)
			}
		}
		s.mtx.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		ticker.Reset(s.cfg.PollFrequency)
	}
}

func (s *Server) handleControlAddRequest(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleControlAddRequest: %v", r.RemoteAddr)
	defer log.Tracef("handleControlAddRequest exit: %v", r.RemoteAddr)

	ns := make([]Node, 0, 16)
	err := json.NewDecoder(r.Body).Decode(&ns)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Errorf("%v %v: %v", RouteControlAdd, r.RemoteAddr, err) // too loud?
		return
	}

	nes := make([]NodeError, len(ns))
	for k := range ns {
		nes[k].NodeURL = ns[k].NodeURL
		err = s.nodeAdd(ns[k].NodeURL)
		if err != nil {
			nes[k].Error = err.Error()
			continue
		}
	}
	err = json.NewEncoder(w).Encode(nes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errorf("%v %v: %v", RouteControlAdd, r.RemoteAddr, err) // too loud?
		return
	}
}

func (s *Server) handleControlRemoveRequest(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleControlRemoveRequest: %v", r.RemoteAddr)
	defer log.Tracef("handleControlRemoveRequest exit: %v", r.RemoteAddr)

	ns := make([]Node, 0, 16)
	err := json.NewDecoder(r.Body).Decode(&ns)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Errorf("%v %v: %v", RouteControlRemove, r.RemoteAddr, err) // too loud?
		return
	}

	nes := make([]NodeError, len(ns))
	for k := range ns {
		nes[k].NodeURL = ns[k].NodeURL
		err = s.removeNode(ns[k].NodeURL)
		if err != nil {
			nes[k].Error = err.Error()
			continue
		}
	}
	err = json.NewEncoder(w).Encode(nes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errorf("%v %v: %v", RouteControlRemove, r.RemoteAddr, err) // too loud?
		return
	}
}

func (s *Server) handleControlListRequest(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleControlListRequest: %v", r.RemoteAddr)
	defer log.Tracef("handleControlListRequest exit: %v", r.RemoteAddr)

	s.mtx.Lock()
	nhs := make([]NodeHealth, 0, len(s.hvmHandlers))
	for k := range s.hvmHandlers {
		nhs = append(nhs, NodeHealth{
			NodeURL:     s.hvmHandlers[k].u.String(),
			Status:      stateString[s.hvmHandlers[k].state],
			Connections: s._countNode(k),
		})
	}
	s.mtx.Unlock()

	err := json.NewEncoder(w).Encode(nhs)
	if err != nil {
		log.Errorf("encode %v: %v", r.RemoteAddr, err)
		return
	}
}

func (s *Server) Run(pctx context.Context) error {
	if !s.testAndSetRunning(true) {
		return errors.New("hproxy already running")
	}
	defer s.testAndSetRunning(false)

	// Validate urls
	if len(s.cfg.HVMURLs) == 0 {
		return errors.New("must provide hvm url(s)")
	}
	s.hvmHandlers = make([]HVMHandler, 0, len(s.cfg.HVMURLs))
	for k := range s.cfg.HVMURLs {
		err := s.nodeAdd(s.cfg.HVMURLs[k])
		if err != nil {
			return fmt.Errorf("node add: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// Launch hvm monitor
	s.wg.Add(1)
	go s.monitor(ctx)

	// HTTP server
	httpErrCh := make(chan error)
	if s.cfg.ListenAddress == "" {
		return errors.New("must provide listen address")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleProxyRequest)

	s.httpServer = &http.Server{
		Addr:        s.cfg.ListenAddress,
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	go func() {
		log.Infof("Listening: %s", s.cfg.ListenAddress)
		httpErrCh <- s.httpServer.ListenAndServe()
	}()
	defer func() {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Errorf("http server exit: %v", err)
			return
		}
		log.Infof("web server shutdown cleanly")
	}()

	// Control HTTP server
	ctrlHttpErrCh := make(chan error)
	if s.cfg.ControlAddress != "" {
		cmux := http.NewServeMux()
		handle("Control", cmux, RouteControlAdd, s.handleControlAddRequest)
		handle("Control", cmux, RouteControlRemove, s.handleControlRemoveRequest)
		handle("Control", cmux, RouteControlList, s.handleControlListRequest)

		ctrlHttpServer := &http.Server{
			Addr:        s.cfg.ControlAddress,
			Handler:     cmux,
			BaseContext: func(_ net.Listener) context.Context { return ctx },
		}
		go func() {
			log.Infof("Control listening: %s", s.cfg.ControlAddress)
			ctrlHttpErrCh <- ctrlHttpServer.ListenAndServe()
		}()
		defer func() {
			if err := ctrlHttpServer.Shutdown(ctx); err != nil {
				log.Errorf("control http server exit: %v", err)
				return
			}
			log.Infof("control web server shutdown cleanly")
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

	runtime.Gosched() // just for pretty print
	log.Infof("Starting hproxy")

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-httpErrCh:
	case err = <-ctrlHttpErrCh:
	}
	cancel()

	log.Infof("hproxy shutting down...")
	s.wg.Wait()
	log.Infof("hproxy shutdown cleanly")

	return err
}
