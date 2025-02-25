// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/service/bfg"
	"github.com/hemilabs/heminetwork/version"
)

const (
	daemonName      = "bfgd"
	defaultLogLevel = daemonName + "=INFO;bfg=INFO"
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = bfg.NewDefaultConfig()
	cm  = config.CfgMap{
		"BFG_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"BFG_LISTEN_ADDRESS": config.Config{
			Value:        &cfg.ListenAddress,
			DefaultValue: bfgapi.DefaultListenAddress,
			Help:         "address and port bfgd listens on for http connections",
			Print:        config.PrintAll,
		},
		"BFG_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port bfgd prometheus listens on",
			Print:        config.PrintAll,
		},
		"BFG_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port bfgd pprof listens on (open <address>/debug/pprof to see available profiles)",
			Print:        config.PrintAll,
		},
	}
)

func HandleSignals(ctx context.Context, cancel context.CancelFunc, callback func(os.Signal)) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()

	select {
	case <-ctx.Done():
	case s := <-signalChan: // First signal, cancel context.
		if callback != nil {
			callback(s) // Do whatever caller wants first.
			cancel()
		}
	}
	<-signalChan // Second signal, hard exit.
	os.Exit(2)
}

func _main() error {
	// Parse configuration from environment
	if err := config.Parse(cm); err != nil {
		return err
	}

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		return err
	}
	log.Infof(welcome)

	pc := config.PrintableConfig(cm)
	for k := range pc {
		log.Infof("%v", pc[k])
	}

	ctx, cancel := context.WithCancel(context.Background())
	go HandleSignals(ctx, cancel, func(s os.Signal) {
		log.Infof("bfg service received signal: %s", s)
	})

	server, err := bfg.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create BFG server: %w", err)
	}
	if err = server.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("bfg server terminated: %w", err)
	}

	return nil
}

func init() {
	version.Component = "bfgd"
	welcome = "Hemi Bitcoin Finality Governor " + version.BuildInfo()
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "%v\n", welcome)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "\thelp (this help)\n")
		fmt.Fprintf(os.Stderr, "Environment:\n")
		config.Help(os.Stderr, cm)
		os.Exit(1)
	}

	if err := _main(); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}
