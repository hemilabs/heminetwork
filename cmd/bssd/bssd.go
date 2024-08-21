// Copyright (c) 2024 Hemi Labs, Inc.
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
	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/service/bss"
	"github.com/hemilabs/heminetwork/version"
)

const (
	daemonName      = "bssd"
	defaultLogLevel = daemonName + "=INFO;protocol=INFO;bss=INFO"
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = bss.NewDefaultConfig()
	cm  = config.CfgMap{
		"BSS_BFG_URL": config.Config{
			Value:        &cfg.BFGURL,
			DefaultValue: bfgapi.DefaultPrivateURL,
			Help:         "bfgd endpoint",
			Print:        config.PrintAll,
		},
		"BSS_ADDRESS": config.Config{
			Value:        &cfg.ListenAddress,
			DefaultValue: bssapi.DefaultListen,
			Help:         "address and port bssd listens on",
			Print:        config.PrintAll,
		},
		"BSS_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"BSS_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "", // bssapi.DefaultPrometheusListen,
			Help:         "address and port bssd prometheus listens on",
			Print:        config.PrintAll,
		},
		"BSS_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port bssd pprof listens on (open <address>/debug/pprof to see available profiles)",
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

	loggo.ConfigureLoggers(cfg.LogLevel)
	log.Infof("%v", welcome)

	pc := config.PrintableConfig(cm)
	for k := range pc {
		log.Infof("%v", pc[k])
	}

	ctx, cancel := context.WithCancel(context.Background())
	go HandleSignals(ctx, cancel, func(s os.Signal) {
		log.Infof("bss service received signal: %s", s)
	})

	server, err := bss.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create BSS server: %w", err)
	}
	if err := server.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("bss server terminated: %w", err)
	}

	return nil
}

func init() {
	version.Component = "bssd"
	welcome = "Hemi Bitcoin Secure Sequencer " + version.BuildInfo()
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
