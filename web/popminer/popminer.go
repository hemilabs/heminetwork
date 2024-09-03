// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall/js"

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/service/popm"
	versionPkg "github.com/hemilabs/heminetwork/version"
)

var (
	// version and gitCommit are set via ldflags at link-time.
	version   = ""
	gitCommit = ""

	logLevel = "WARN" // Can be set with `-ldflags "-X main.logLevel=TRACE"`
	log      = loggo.GetLogger("@hemilabs/pop-miner")
)

// svc is a global object storing data for the WebAssembly service.
// This can be accessed concurrently, however certain mutexes must be used to
// read/write certain fields.
var svc Service

// Service is a global struct used to store data for the WebAssembly service.
type Service struct {
	minerMtx sync.RWMutex
	miner    *Miner

	listenersMtx sync.RWMutex
	listeners    map[EventType][]js.Value
}

// handleMinerEvent handles an event dispatched by the PoP miner.
func (s *Service) handleMinerEvent(popmEventType popm.EventType, data any) {
	eventType, ok := popmEvents[popmEventType]
	if !ok {
		log.Errorf("unknown popm event type: %v", popmEventType)
		return
	}
	s.dispatchEvent(eventType, convertEvent(data))
}

func (s *Service) dispatchEvent(eventType EventType, data any) {
	s.listenersMtx.RLock()
	defer s.listenersMtx.RUnlock()
	allHs, aok := s.listeners["*"] // Special handlers that receive all events.
	hs, ok := s.listeners[eventType]
	if !ok && !aok {
		// There are no listeners for this event type.
		return
	}

	jsEvent := jsValueOf(data)
	if jsEvent.IsNull() {
		jsEvent = objectConstructor.New()
	} else if jsEvent.Type() != js.TypeObject {
		log.Errorf("Invalid event data: %s, must be %s",
			jsEvent.Type(), js.TypeObject)
		return
	}
	jsEvent.Set("type", jsValueOf(eventType))

	// Dispatch to all handlers for this event type.
	for _, h := range hs {
		h.Invoke(jsEvent)
	}

	// Dispatch to handlers that receive all events, after dispatching to
	// handlers specific to this event type.
	for _, h := range allHs {
		h.Invoke(jsEvent)
	}
}

// Miner represents a running PoP Miner along with its context.
// Errors encountered while starting the miner should be sent to the errCh channel.
type Miner struct {
	ctx    context.Context
	cancel context.CancelFunc
	*popm.Miner

	// httpClient is the HTTP client used for accessing the mempool.space API
	// if automaticFees is enabled.
	httpClient *http.Client

	// mempoolSpaceURL is the base URL for mempool.space, for the current
	// network.
	mempoolSpaceURL string

	errCh chan error
	wg    sync.WaitGroup
}

func (m *Miner) shutdown() error {
	m.cancel()
	m.wg.Wait()

	select {
	case err := <-m.errCh:
		return err
	default:
	}
	close(m.errCh)

	return nil
}

func init() {
	loggo.ConfigureLoggers(logLevel)
	versionPkg.Component = "popm-web"
}

func main() {
	log.Tracef("main")
	defer log.Tracef("main exit")

	// Create event listeners map
	svc.listeners = make(map[EventType][]js.Value)

	log.Infof("%s %s", filepath.Base(os.Args[0]), versionPkg.BuildInfo())
	log.Infof("Logging level: %v", logLevel)

	// Set global variable
	module := objectConstructor.New()
	module.Set("dispatch", js.FuncOf(dispatch))
	js.Global().Set("@hemilabs/pop-miner", module)

	<-make(chan struct{}) // prevents the program from exiting
}

func runningMiner() (*Miner, error) {
	svc.minerMtx.RLock()
	defer svc.minerMtx.RUnlock()
	if m := svc.miner; m != nil {
		return m, nil
	}
	return nil, errors.New("miner not running")
}
