// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package dash

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/api/dashapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/service/deucalion"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"
	"nhooyr.io/websocket"
)

const (
	logLevel = "dash=INFO"
	verbose  = false

	promSubsystem = "dash_service" // Prometheus
)

var log = loggo.GetLogger("dash")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenAddress: dashapi.DefaultListen,
	}
}

type Config struct {
	ListenAddress           string
	LogLevel                string
	PrometheusListenAddress string
}

type Server struct {
	mtx       sync.RWMutex
	isRunning bool

	wg sync.WaitGroup

	cfg *Config

	requestTimeout time.Duration // Request timeout

	// requests
	requestLimit   int       // Request limiter queue depth
	requestLimiter chan bool // Maximum in progress websocket commands
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
		requestTimeout: defaultRequestTimeout,
		requestLimit:   requestLimit,
	}
	for i := 0; i < requestLimit; i++ {
		s.requestLimiter <- true
	}

	return s, nil
}

func handle(service string, mux *http.ServeMux, pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandleFunc(pattern, handler)
	log.Infof("handle (%v): %v", service, pattern)
}

// handleRequest is called as a go routine to handle a long lived command.
func (s *Server) handleRequest(parrentCtx context.Context, dws *dashWs, wsid string, requestType string, handler func(ctx context.Context) (any, error)) {
	log.Tracef("handleRequest: %v", dws.addr)
	defer log.Tracef("handleRequest exit: %v", dws.addr)

	ctx, cancel := context.WithTimeout(parrentCtx, s.requestTimeout)
	defer cancel()

	select {
	case <-s.requestLimiter:
	default:
		log.Infof("Request limiter hit %v: %v", dws.addr, requestType)
		<-s.requestLimiter
	}
	defer func() { s.requestLimiter <- true }()

	log.Tracef("Handling request %v: %v", dws.addr, requestType)

	response, err := handler(ctx)
	if err != nil {
		log.Errorf("Failed to handle %v request %v: %v",
			requestType, dws.addr, err)
	}
	if response == nil {
		return
	}

	log.Debugf("Responding to %v request with %v", requestType, spew.Sdump(response))

	if err := dashapi.Write(ctx, dws.conn, wsid, response); err != nil {
		log.Errorf("Failed to handle %v request: protocol write failed: %v", requestType, err)
	}
}

type dashWs struct {
	wg             sync.WaitGroup
	addr           string
	conn           *protocol.WSConn
	sessionId      string
	requestContext context.Context
}

func (s *Server) handlePingRequest(ctx context.Context, dws *dashWs, payload any, id string) error {
	log.Tracef("handlePingRequest: %v", dws.addr)
	defer log.Tracef("handlePingRequest exit: %v", dws.addr)

	p, ok := payload.(*dashapi.PingRequest)
	if !ok {
		return fmt.Errorf("handlePingRequest invalid payload type: %T", payload)
	}
	response := &dashapi.PingResponse{
		OriginTimestamp: p.Timestamp,
		Timestamp:       time.Now().Unix(),
	}

	log.Tracef("responding with %v", spew.Sdump(response))

	if err := dashapi.Write(ctx, dws.conn, id, response); err != nil {
		return fmt.Errorf("handlePingRequest write: %v %v",
			dws.addr, err)
	}
	return nil
}

func (s *Server) handleHeartbeatRequest(ctx context.Context, msg *dashapi.HeartbeatRequest) (*dashapi.HeartbeatResponse, error) {
	log.Tracef("handleHeartbeatRequest")
	defer log.Tracef("handleHeartbeatRequest exit")

	err := errors.New("fuck off")
	errorType := 0
	switch errorType {
	case 0:
		// internal error
		x := 1
		var e *protocol.InternalError
		if x == 0 {
			e = protocol.NewInternalErrorf("my error: %v", err)
		} else {
			e = protocol.NewInternalError(err)
		}

		return &dashapi.HeartbeatResponse{
			Error: e.WireError(),
		}, e
	case 1:
		// user error
		return &dashapi.HeartbeatResponse{Error: protocol.WireError(err)}, nil
	}

	return &dashapi.HeartbeatResponse{}, nil
}

func (s *Server) handleWebsocketRead(ctx context.Context, dws *dashWs) {
	defer dws.wg.Done()

	log.Tracef("handleWebsocketRead: %v", dws.addr)
	defer log.Tracef("handleWebsocketRead exit: %v", dws.addr)

	for {
		cmd, id, payload, err := dashapi.Read(ctx, dws.conn)
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
			dws.addr, cmd, id, spew.Sdump(payload))

		// Note, we MUST NOT shadow ctx in the callbacks. ctx *is* the
		// base context in the callback thus if we shadow it we
		// overwrite the correct context that has a reasonable timeout.
		//
		// Make dead sure all contexts folloing in this code are not
		// shadowed.
		switch cmd {
		case dashapi.CmdPingRequest:
			// quick call
			err = s.handlePingRequest(ctx, dws, payload, id)
		case dashapi.CmdHeartbeatRequest:
			handler := func(c context.Context) (any, error) {
				msg := payload.(*dashapi.HeartbeatRequest)
				return s.handleHeartbeatRequest(c, msg)
			}

			go s.handleRequest(ctx, dws, id, "handle handleHeartbeatRequest",
				handler)
		default:
			err = fmt.Errorf("unknown command: %v", cmd)
		}

		// If set, it is a terminal error.
		if err != nil {
			log.Errorf("handleWebsocketRead %v %v %v: %v",
				dws.addr, cmd, id, err)
			return
		}
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

	dws := &dashWs{
		addr:           r.RemoteAddr,
		conn:           protocol.NewWSConn(conn),
		requestContext: r.Context(),
	}

	defer func() {
		conn.Close(websocket.StatusNormalClosure, "") // Force shutdown connection
	}()

	dws.wg.Add(1)
	go s.handleWebsocketRead(r.Context(), dws)

	// Always ping, required by protocol.
	ping := &dashapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	log.Tracef("responding with %v", spew.Sdump(ping))
	if err := dashapi.Write(r.Context(), dws.conn, "0", ping); err != nil {
		log.Errorf("Write: %v", err)
	}

	log.Infof("Unauthenticated connection from %v", r.RemoteAddr)

	// Wait for termination
	dws.wg.Wait()

	log.Infof("Unauthenticated connection terminated from %v", r.RemoteAddr)
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

func (s *Server) Run(parrentCtx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run exit")

	if !s.testAndSetRunning(true) {
		return fmt.Errorf("dash already running")
	}
	defer s.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(parrentCtx)
	defer cancel() // just in case

	mux := http.NewServeMux()
	handle("dash", mux, dashapi.RouteWebsocket, s.handleWebsocket)

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
				Help:      "Is dash service running.",
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

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-httpErrCh:
	}
	cancel()

	log.Infof("dash service shutting down")

	s.wg.Wait()
	log.Infof("dash service clean shutdown")

	return err
}
