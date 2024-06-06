// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall/js"

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/service/popm"
)

var (
	// version and gitCommit are set via ldflags at link-time.
	version   = ""
	gitCommit = ""

	logLevel = "ERROR" // Can be set with `-ldflags "-X main.logLevel=TRACE"`
	log      = loggo.GetLogger("@hemilabs/pop-miner")
)

var (
	pmMtx sync.Mutex
	pm    *Miner // Global Miner instance.
)

// Miner is a global instance of [popm.Miner].
type Miner struct {
	// Don't like adding these into the object but c'est la wasm
	ctx    context.Context
	cancel context.CancelFunc
	miner  *popm.Miner

	wg  sync.WaitGroup
	err error
}

func init() {
	loggo.ConfigureLoggers(logLevel)
}

func main() {
	log.Tracef("main")
	defer log.Tracef("main exit")

	// Enable function dispatcher
	log.Infof("=== Start of Day ===")
	log.Infof("%v version %v compiled with go version %v %v/%v revision %v",
		filepath.Base(os.Args[0]), version, runtime.Version(),
		runtime.GOOS, runtime.GOARCH, gitCommit)
	log.Infof("Logging level: %v", logLevel)

	// Set global variable
	module := objectConstructor.New()
	module.Set("dispatch", js.FuncOf(dispatch))
	js.Global().Set("@hemilabs/pop-miner", module)

	<-make(chan struct{}) // prevents the program from exiting
}

func activeMiner() (*Miner, error) {
	pmMtx.Lock()
	defer pmMtx.Unlock()
	if pm == nil {
		return nil, errors.New("pop miner not running")
	}
	return pm, nil
}
