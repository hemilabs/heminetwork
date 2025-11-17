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

	"github.com/hemilabs/heminetwork/v2/api/bfgapi"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/config"
	"github.com/hemilabs/heminetwork/v2/service/bfg"
	"github.com/hemilabs/heminetwork/v2/version"
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
		"BFG_BITCOIN_SOURCE": config.Config{
			Value:        &cfg.BitcoinSource,
			DefaultValue: "tbc",
			Help:         "bitcoin source of truth used (tbc only for now)",
			Print:        config.PrintAll,
		},
		"BFG_BITCOIN_URL": config.Config{
			Value:        &cfg.BitcoinURL,
			DefaultValue: tbcapi.DefaultURL,
			Help:         "connection url for bitcoin source if needed e.g. ws://localhost:8082/v1/ws",
			Print:        config.PrintAll,
		},
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
		"BFG_NETWORK": config.Config{
			Value:        &cfg.Network,
			DefaultValue: "mainnet",
			Help:         "network bfg is working on (mainnet|testnet3|testnet4)",
			Print:        config.PrintAll,
		},
		"BFG_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port bfgd pprof listens on (open <address>/debug/pprof to see available profiles)",
			Print:        config.PrintAll,
		},
		"BFG_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port bfgd prometheus listens on",
			Print:        config.PrintAll,
		},
		"BFG_OPGETH_URL": config.Config{
			Value:        &cfg.OpgethURL,
			DefaultValue: "",
			Help:         "connection url for opgeth e.g. http://127.0.0.1:9999/v1/ws",
			Print:        config.PrintAll,
		},
	}
)

func _main() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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

	go func() {
		// Stop receiving signals as soon as possible.
		<-ctx.Done()
		cancel()
	}()

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
