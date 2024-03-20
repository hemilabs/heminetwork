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
	welcome = fmt.Sprintf("Hemi Proof of Proof miner: v%v", version.String())

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
			DefaultValue: popm.NewDefaultConfig().BFGWSURL,
			Help:         "url for BFG (Bitcoin Finality Governor)",
			Print:        config.PrintAll,
		},
		"POPM_BTC_CHAIN_NAME": config.Config{
			Value:        &cfg.BTCChainName,
			DefaultValue: popm.NewDefaultConfig().BTCChainName,
			Help:         "the name of the bitcoing chain to connect to (ex. \"mainnet\", \"testnet3\")",
			Print:        config.PrintAll,
		},
		"POPM_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port bssd prometheus listens on",
			Print:        config.PrintAll,
		},
	}
)

func handleSignals(ctx context.Context, cancel context.CancelFunc, callback func(os.Signal)) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	signal.Notify(signalChan, os.Kill)
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
		return fmt.Errorf("failed to create POP miner: %w", err)
	}
	if err := miner.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("POP miner terminated: %w", err)
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
