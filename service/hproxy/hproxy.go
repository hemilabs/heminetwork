// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/hemilabs/heminetwork/service/pprof"
)

type Node struct {
	NodeURL string `json:"node_url"`
}

type NodeError struct {
	NodeURL string `json:"node_url"`
	Error   string `json:"error"`
}

type NodeHealth struct {
	NodeURL string `json:"node_url"`
	Status  string `json:"status"`
}

const (
	appName = "hproxy" // Prometheus

	logLevel = "INFO"

	promSubsystem = "hproxy_service" // Prometheus

	// XXX think about these durations
	DefaultRequestTimeout = 9 * time.Second  // Smaller than 12s
	DefaultPollFrequency  = 11 * time.Second // Smaller than 12s
	DefaultListenAddress  = "localhost:8545" // Default geth port
	DefaultControlAddress = "localhost:1337" // Default control port

	expectedClients = 1000

	routeControl       = "/v1/control"
	routeControlAdd    = routeControl + "/add"
	routeControlRemove = routeControl + "/remove"
	routeControlList   = routeControl + "/list"
)

var log = loggo.GetLogger(appName)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

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

type Config struct {
	ControlAddress          string
	HVMURLs                 []string
	ListenAddress           string
	LogLevel                string
	Network                 string
	PollFrequency           time.Duration
	PrometheusListenAddress string
	PrometheusNamespace     string
	PprofListenAddress      string
	RequestTimeout          time.Duration
}

func NewDefaultConfig() *Config {
	return &Config{
		ControlAddress:      DefaultControlAddress,
		ListenAddress:       DefaultListenAddress,
		Network:             "mainnet",
		PrometheusNamespace: appName,
		RequestTimeout:      DefaultRequestTimeout,
	}
}

type Server struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	hvmHandlers []HVMHandler   // hvm nodes
	clients     map[string]int // [ip_address]server_id

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
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}

	s := &Server{
		cfg:     cfg,
		clients: make(map[string]int, expectedClients),
		cmdsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: cfg.PrometheusNamespace,
			Name:      "proxy_calls",
			Help:      "The total number of successful proxy calls",
		}),
	}

	switch strings.ToLower(cfg.Network) {
	case "mainnet":
	case "sepolia":
	default:
		return nil, fmt.Errorf("unknown network %q", cfg.Network)
	}

	return s, nil
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

		if s.promPollVerbose {
			s.mtx.RLock()
			log.Infof("FIXME PROMETHEUS POLL")
			s.mtx.RUnlock()
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
		if s.hvmHandlers[k].state == StateHealthy {
			return true
		}
	}
	return false
}

func (s *Server) health(ctx context.Context) (bool, any, error) {
	log.Tracef("health")
	defer log.Tracef("health exit")

	type health struct {
		HealthyNodes   int `json:"healthy_nodes"`
		UnhealthyNodes int `json:"unhealthy_nodes"`
	}

	var h health
	s.mtx.Lock()
	for k := range s.hvmHandlers {
		if s.hvmHandlers[k].state == StateHealthy {
			h.HealthyNodes++
		} else {
			h.UnhealthyNodes++
		}
	}
	s.mtx.Unlock()

	return s.isHealthy(ctx), h, nil
}

type HVMState int

const (
	StateNew       HVMState = 0
	StateHealthy            = 1
	StateUnhealthy          = 2
	StateRemoved            = 3
)

var stateString = map[HVMState]string{
	StateNew:       "new",
	StateHealthy:   "healthy",
	StateUnhealthy: "unhealthy",
	StateRemoved:   "removed",
}

type HVMHandler struct {
	id int // server id

	rp *httputil.ReverseProxy
	u  *url.URL     // Connection URL for HVM
	c  *http.Client // In here to reuse connection

	connections uint // Open connections, XXX not being reaped yet

	poking bool // true when getting health
	poker  Proxy
	state  HVMState
}

func (s *Server) lowest(x []int) int {
	if len(x) == 0 {
		return -1
	}

	minIndex := 0
	for i := 1; i < len(x); i++ {
		if x[i] < x[minIndex] {
			minIndex = i
		}
	}
	return minIndex
}

func (s *Server) handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProxyRequest: %v", r.RemoteAddr)
	defer log.Tracef("handleProxyRequest exit: %v", r.RemoteAddr)

	// XXX expire client connections at some point

	// Select host to call
	s.mtx.Lock()
	id := -1
	if v, ok := s.clients[r.RemoteAddr]; ok {
		// Only call same host when healthy
		if s.hvmHandlers[v].state == StateHealthy {
			id = v
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
			// Add connection to candidate
			s.clients[r.RemoteAddr] = id
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

	log.Debugf("handleProxyRequest: remote %v url '%v' -> node %v",
		r.RemoteAddr, r.URL, id)

	// Throw call over the fence
	w.Header().Set("X-Hproxy", strconv.Itoa(id))
	s.hvmHandlers[id].rp.ServeHTTP(w, r)

	s.cmdsProcessed.Inc()
}

//func (s *Server) handleProxyError(w http.ResponseWriter, r *http.Request, e error) {
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
//}

func (s *Server) nodeAdd(node string) error {
	u, err := url.Parse(node)
	if err != nil {
		return fmt.Errorf("invalid url: %v", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("unsuported scheme: %v", u.Scheme)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// make sure it isn't a dupe
	for k := range s.hvmHandlers {
		if s.hvmHandlers[k].u.String() == u.String() {
			if s.hvmHandlers[k].state == StateRemoved {
				s.hvmHandlers[k].state = StateNew // add it back
				log.Infof("Marking hvm new %v: %v",
					s.hvmHandlers[k].id, s.hvmHandlers[k].u)
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
			},
			FlushInterval:  0,
			ErrorLog:       nil, // XXX wrap in loggo
			BufferPool:     nil, // not useful for different sized calls
			ModifyResponse: nil, // not needed
			ErrorHandler:   nil, // s.handleProxyError, ModifyResponse only
		},
	}

	// For now, everything is ethereum but we can use the poker function to
	// handle different types health checks.
	hvmHandler.poker = NewEthereumProxy(func(ctx context.Context) error {
		resp, err := CallEthereum(hvmHandler.c, hvmHandler.u.String(),
			"eth_blockNumber", nil)
		if err != nil {
			return err
		}

		j := make(map[string]any)
		err = json.Unmarshal(resp, &j)
		if err != nil {
			return err
		}

		// Make sure we have "result"
		if _, ok := j["result"]; !ok {
			return errors.New("no result")
		}
		return nil
	})

	s.hvmHandlers = append(s.hvmHandlers, hvmHandler)

	return nil
}

func (s *Server) nodeRemove(node string) error {
	u, err := url.Parse(node)
	if err != nil {
		return fmt.Errorf("invalid url: %v", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("unsuported scheme: %v", u.Scheme)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// make sure it isn't a dupe
	for k := range s.hvmHandlers {
		if s.hvmHandlers[k].u.String() == u.String() {
			if s.hvmHandlers[k].state != StateRemoved {
				s.hvmHandlers[k].state = StateRemoved
				log.Infof("Marking hvm removed %v: %v",
					s.hvmHandlers[k].id, s.hvmHandlers[k].u)
				return nil
			}
			return errors.New("already removed")
		}
	}
	return errors.New("not found")
}

func (s *Server) nodeHealthy(id int) {
	s.mtx.Lock()
	if s.hvmHandlers[id].state != StateHealthy {
		s.hvmHandlers[id].state = StateHealthy
		log.Infof("Marking hvm healthy %v: %v", id, s.hvmHandlers[id].u)
	}
	s.mtx.Unlock()
}

func (s *Server) nodeUnhealthy(id int) {
	s.mtx.Lock()
	if s.hvmHandlers[id].state != StateUnhealthy {
		s.hvmHandlers[id].state = StateUnhealthy
		log.Infof("Marking hvm unhealthy %v: %v", id, s.hvmHandlers[id].u)
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
		s.nodeUnhealthy(id)
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
		log.Errorf("%v %v: %v", routeControlAdd, r.RemoteAddr, err) // too loud?
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
		log.Errorf("%v %v: %v", routeControlAdd, r.RemoteAddr, err) // too loud?
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
		log.Errorf("%v %v: %v", routeControlRemove, r.RemoteAddr, err) // too loud?
		return
	}

	nes := make([]NodeError, len(ns))
	for k := range ns {
		nes[k].NodeURL = ns[k].NodeURL
		err = s.nodeRemove(ns[k].NodeURL)
		if err != nil {
			nes[k].Error = err.Error()
			continue
		}
	}
	err = json.NewEncoder(w).Encode(nes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errorf("%v %v: %v", routeControlRemove, r.RemoteAddr, err) // too loud?
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
			NodeURL: s.hvmHandlers[k].u.String(),
			Status:  stateString[s.hvmHandlers[k].state],
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
			return fmt.Errorf("node add: %v", err)
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

	// Control HTTP server
	ctrlHttpErrCh := make(chan error)
	if s.cfg.ControlAddress != "" {
		cmux := http.NewServeMux()
		handle("Control", cmux, routeControlAdd, s.handleControlAddRequest)
		handle("Control", cmux, routeControlRemove, s.handleControlRemoveRequest)
		handle("Control", cmux, routeControlList, s.handleControlListRequest)

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
