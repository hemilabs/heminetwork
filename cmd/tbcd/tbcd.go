// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/hemilabs/heminetwork/version"
	"github.com/juju/loggo"
)

const (
	daemonName      = "tbcd"
	defaultLogLevel = daemonName + "=INFO;postgres=INFO;tbcpostgres=INFO;tbc=INFO"
	defaultNetwork  = "testnet3" // XXX make this mainnet
	defaultHome     = "~/." + daemonName
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome = fmt.Sprintf("Hemi Tiny Bitcoin Daemon: v%v", version.String())

	cfg = tbc.NewDefaultConfig()
	cm  = config.CfgMap{
		"TBC_LEVELDB_HOME": config.Config{
			Value:        &cfg.LevelDBHome,
			DefaultValue: defaultHome,
			Help:         "data directory for leveldb",
			Print:        config.PrintAll,
		},
		"TBC_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"TBC_NETWORK": config.Config{
			Value:        &cfg.Network,
			DefaultValue: defaultNetwork,
			Help:         "bitcoin network; mainnet or testnet",
			Print:        config.PrintAll,
		},
		"TBC_POSTGRES_URI": config.Config{
			Value:        &cfg.PgURI,
			DefaultValue: "",
			Help:         "postgres connection URI",
			Print:        config.PrintSecret,
			Required:     false,
		},
		"TBC_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port tbcd prometheus listens on",
			Print:        config.PrintAll,
		},
	}
)

func HandleSignals(ctx context.Context, cancel context.CancelFunc, callback func(os.Signal)) {
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
		log.Infof("tbc service received signal: %s", s)
	})

	server, err := tbc.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("Failed to create tbc server: %v", err)
	}
	if err := server.Run(ctx); err != context.Canceled {
		return fmt.Errorf("tbc server terminated: %v", err)
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
		log.Errorf("%v", err)
		os.Exit(1)
	}
}
