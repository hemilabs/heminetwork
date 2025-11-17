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

	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/config"
	"github.com/hemilabs/heminetwork/v2/service/popm"
	"github.com/hemilabs/heminetwork/v2/version"
)

const (
	daemonName      = "popmd"
	defaultLogLevel = daemonName + "=INFO;popm=INFO"
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = popm.NewDefaultConfig()
	cm  = config.CfgMap{
		"POPM_BITCOIN_NETWORK": config.Config{
			Value:        &cfg.Network,
			DefaultValue: "mainnet",
			Help:         "bitcoin chain to connect to (ex. \"mainnet\", \"testnet3|testnet4\")",
			Print:        config.PrintAll,
		},
		"POPM_BITCOIN_SECRET": config.Config{
			Value:        &cfg.BitcoinSecret,
			Required:     true,
			DefaultValue: "",
			Help:         "bitcoin secret (mnemonic, seed, xpriv)",
			Print:        config.PrintSecret,
		},
		"POPM_BITCOIN_URL": config.Config{
			Value:        &cfg.BitcoinURL,
			DefaultValue: tbcapi.DefaultURL,
			Help:         "tbc bitcoin url to connect to",
			Print:        config.PrintAll,
		},
		"POPM_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"POPM_OPGETH_URL": config.Config{
			Value:        &cfg.OpgethURL,
			DefaultValue: "localhost:9999",
			Help:         "URL for opgeth",
			Print:        config.PrintAll,
		},
		"POPM_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port popm pprof listens on (open <address>/debug/pprof to see available profiles)",
			Print:        config.PrintAll,
		},
		"POPM_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port popm prometheus listens on",
			Print:        config.PrintAll,
		},
		"POPM_REMINE_THRESHOLD": config.Config{
			Value:        &cfg.RetryMineThreshold,
			DefaultValue: uint(0),
			Help:         "the number of L2 Keystones behind the latest seen that we are willing to remine, this is handy for re-orgs",
			Print:        config.PrintAll,
		},
		"POPM_STATIC_FEE": config.Config{
			Value:        &cfg.StaticFee,
			DefaultValue: float64(0),
			Help:         "static fee amount in sats/byte; overrides fee estimation if greater than 0. Can be decimal (ex. 1.5 sats/byte)",
			Print:        config.PrintAll,
		},
	}
)

func _main() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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

	go func() {
		// Stop receiving signals as soon as possible.
		<-ctx.Done()
		cancel()
	}()

	miner, err := popm.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create POP miner: %w", err)
	}
	if err := miner.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("pop miner terminated: %w", err)
	}

	return nil
}

func init() {
	version.Component = "popmd"
	welcome = "Hemi Proof-of-Proof Miner " + version.BuildInfo()
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
