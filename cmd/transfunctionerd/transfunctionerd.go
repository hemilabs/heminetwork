// Copyright (c) 2025 Hemi Labs, Inc.
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

	"github.com/hemilabs/heminetwork/v2/config"
	"github.com/hemilabs/heminetwork/v2/service/continuum"
	"github.com/hemilabs/heminetwork/v2/version"
)

const (
	daemonName      = "trfd"
	defaultLogLevel = daemonName + "=INFO"
	// defaultNetwork  = "mainnet"
	defaultHome = "~/." + daemonName
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = continuum.NewDefaultConfig()
	cm  = config.CfgMap{
		"TRF_HOME": config.Config{
			Value:        &cfg.Home,
			DefaultValue: defaultHome,
			Help:         "data directory",
			Print:        config.PrintAll,
		},
		"TRF_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"TRF_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port transfunctionerd prometheus listens on",
			Print:        config.PrintAll,
		},
		"TRF_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port transfunctionerd pprof listens on (open <address>/debug/pprof to see available profiles)",
			Print:        config.PrintAll,
		},
	}
)

func init() {
	version.Component = daemonName
	welcome = "Hemi Continuum Transfunctioner Daemon " + version.BuildInfo()
}

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
	log.Infof("%v", welcome)

	pc := config.PrintableConfig(cm)
	for k := range pc {
		log.Infof("%v", pc[k])
	}

	ctx, cancel := context.WithCancel(context.Background())
	go HandleSignals(ctx, cancel, func(s os.Signal) {
		log.Infof("continuum service received signal: %s", s)
	})

	server, err := continuum.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create continuum server: %w", err)
	}

	if err := server.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("continuum server terminated: %w", err)
	}

	return nil
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
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
