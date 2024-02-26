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
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	defaultRequestTimeout := 11 * time.Second // XXX
	s := &Server{
		cfg:            cfg,
		requestTimeout: defaultRequestTimeout,
	}

	return s, nil
}

func handle(service string, mux *http.ServeMux, pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandleFunc(pattern, handler)
	log.Infof("handle (%v): %v", service, pattern)
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
		default:
			err = fmt.Errorf("unknown command: %v", cmd)
		}

		// If set, it is a terminal error.
		if err != nil {
			log.Errorf("handleWebsocketRead %v %v %v: %v",
				dws.addr, cmd, id, err)
			dws.conn.CloseStatus(websocket.StatusProtocolError,
				err.Error())
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

	//if dws.sessionId, err = s.newSession(dws); err != nil {
	//	log.Errorf("error occurred creating key: %s", err)
	//	return
	//}

	defer func() {
		// s.deleteSession(dws.sessionId)
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
