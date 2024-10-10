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
	"time"

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/service/popm"
	"github.com/hemilabs/heminetwork/version"
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
		"POPM_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"POPM_BTC_PRIVKEY": config.Config{
			Value:        &cfg.BTCPrivateKey,
			Required:     true,
			DefaultValue: "",
			Help:         "bitcoin private key",
			Print:        config.PrintSecret,
		},
		"POPM_BFG_URL": config.Config{
			Value:        &cfg.BFGWSURL,
			DefaultValue: cfg.BFGWSURL,
			Help:         "url for BFG (Bitcoin Finality Governor)",
			Print:        config.PrintAll,
		},
		"POPM_BFG_REQUEST_TIMEOUT": config.Config{
			Value:        &cfg.BFGRequestTimeout,
			DefaultValue: cfg.BFGRequestTimeout,
			Help:         "request timeout for BFG (Bitcoin Finality Governor)",
			Print:        config.PrintAll,
			Parse: func(envValue string) (any, error) {
				return time.ParseDuration(envValue)
			},
		},
		"POPM_BTC_CHAIN_NAME": config.Config{
			Value:        &cfg.BTCChainName,
			DefaultValue: popm.NewDefaultConfig().BTCChainName,
			Help:         "the name of the bitcoin chain to connect to (ex. \"mainnet\", \"testnet3\")",
			Print:        config.PrintAll,
		},
		"POPM_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port popm prometheus listens on",
			Print:        config.PrintAll,
		},
		"POPM_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port popm pprof listens on (open <address>/debug/pprof to see available profiles)",
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
			DefaultValue: uint(1),
			Help:         "specify the number of sats/vB the PoP Miner will pay for fees",
			Print:        config.PrintAll,
		},
	}
)

func handleSignals(ctx context.Context, cancel context.CancelFunc, callback func(os.Signal)) {
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
	go handleSignals(ctx, cancel, func(s os.Signal) {
		log.Infof("popm service received signal: %s", s)
	})

	miner, err := popm.NewMiner(cfg)
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
