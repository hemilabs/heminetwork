// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package mock

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/juju/loggo/v2"
)

const (
	logLevel         = "INFO"
	InfiniteDuration = time.Duration(math.MaxInt64)
)

var (
	log                 = loggo.GetLogger("mock")
	DefaultNtfnDuration = 250 * time.Millisecond
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

var ErrConnectionClosed = errors.New("mock server closed")

type mockHandler struct {
	handleFunc func(w http.ResponseWriter, r *http.Request) error
	errCh      chan error  // use notifyErr to write to it
	msgCh      chan string // use notifyMsg to write to it
	name       string
	pctx       context.Context
	conns      []*websocket.Conn
	server     *httptest.Server
	mtx        sync.RWMutex
	isRunning  bool
}

func (f *mockHandler) Running() bool {
	f.mtx.RLock()
	defer f.mtx.RUnlock()
	return f.isRunning
}

func (f *mockHandler) notifyMsg(ctx context.Context, msg string) {
	if f.msgCh == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	case f.msgCh <- msg:
	}
}

func (f *mockHandler) notifyErr(ctx context.Context, err error) {
	if f.errCh == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	case f.errCh <- err:
	}
}

func (f *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !f.Running() {
		log.Infof("%v: %v connection to closed server", f.name, r.RemoteAddr)
		http.Error(w, ErrConnectionClosed.Error(), http.StatusServiceUnavailable)
		f.notifyErr(f.pctx, ErrConnectionClosed)
		return
	}
	log.Infof("serving %v: %v", r.RemoteAddr, r.RequestURI)
	if err := f.handleFunc(w, r); err != nil {
		f.notifyErr(f.pctx, fmt.Errorf("%s error: %w", f.name, err))
	}
}

// Close all websocket connection to the test server
func (f *mockHandler) CloseConnections(force bool) error {
	f.mtx.Lock()
	defer func() {
		f.mtx.Unlock()
		f.server.CloseClientConnections()
	}()

	log.Infof("%v: websocket connections closed", f.name)
	for _, c := range f.conns {
		if force {
			err := c.CloseNow()
			if err != nil {
				return err
			}
			continue
		}
		err := c.Close(websocket.StatusNormalClosure, "")
		if err != nil {
			return err
		}
	}

	return nil
}

// Allow the test server to accept incoming websocket connection
func (f *mockHandler) Start() {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.isRunning = true
	log.Infof("%v: server started", f.name)
}

// Stop the test server from accept incoming websocket connection
func (f *mockHandler) Stop() {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.isRunning = false
	log.Infof("%v: server stopped", f.name)
}

// Fully shutdown the test server
func (f *mockHandler) Shutdown() {
	log.Infof("%v: server shutting down", f.name)
	f.Stop()
	f.server.Close()

	if err := f.CloseConnections(true); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			// should never happen
			panic(err)
		}
	}
}
