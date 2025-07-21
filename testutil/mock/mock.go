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
	"github.com/juju/loggo"
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

type mockHandler struct {
	handleFunc func(w http.ResponseWriter, r *http.Request) error
	errCh      chan error
	msgCh      chan string
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

func (f *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !f.Running() {
		log.Infof("%v: %v connection to closed server", f.name, r.RemoteAddr)
		http.Error(w, string("mock server closed"), http.StatusServiceUnavailable)
		return
	}
	if err := f.handleFunc(w, r); err != nil {
		f.errCh <- fmt.Errorf("%s error: %w", f.name, err)
	}
}

// Close all websocket connection to the test server
func (f *mockHandler) CloseConnections(force bool) error {
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
	log.Tracef("%v: server started", f.name)
}

// Stop the test server from accept incoming websocket connection
func (f *mockHandler) Stop() {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.isRunning = false
	log.Tracef("%v: server stopped", f.name)
}

// Fully shutdown the test server
func (f *mockHandler) Shutdown() {
	log.Tracef("%v: server shutting down", f.name)
	f.Stop()
	f.server.Close()
	if err := f.CloseConnections(true); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			// should never happen
			panic(err)
		}
	}
}
