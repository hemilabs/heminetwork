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

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/service/bfg"
	"github.com/hemilabs/heminetwork/version"
)

const (
	daemonName      = "bfgd"
	defaultLogLevel = daemonName + "=INFO;postgres=INFO;bfgpostgres=INFO;bfg=INFO"
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome = fmt.Sprintf("Hemi Bitcoin Finality Governor: v%v", version.String())

	cfg = bfg.NewDefaultConfig()
	cm  = config.CfgMap{
		"BFG_EXBTC_ADDRESS": config.Config{
			Value:        &cfg.EXBTCAddress,
			DefaultValue: "localhost:18001",
			Help:         "electrumx endpoint",
			Print:        config.PrintAll,
		},
		"BFG_PUBLIC_KEY_AUTH": config.Config{
			Value:        &cfg.PublicKeyAuth,
			DefaultValue: false,
			Help:         "enable enforcing of public key auth handshake",
			Print:        config.PrintAll,
		},
		"BFG_BTC_START_HEIGHT": config.Config{
			Value:        &cfg.BTCStartHeight,
			DefaultValue: uint64(0),
			Help:         "bitcoin start height that serves as genesis",
			Print:        config.PrintAll,
			Required:     true,
		},
		"BFG_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"BFG_POSTGRES_URI": config.Config{
			Value:        &cfg.PgURI,
			DefaultValue: "",
			Help:         "postgres connection URI",
			Print:        config.PrintSecret,
			Required:     true,
		},
		"BFG_PUBLIC_ADDRESS": config.Config{
			Value:        &cfg.PublicListenAddress,
			DefaultValue: bfgapi.DefaultPublicListen,
			Help:         "address and port bfgd listens on for public, authenticated, websocket connections",
			Print:        config.PrintAll,
		},
		"BFG_PRIVATE_ADDRESS": config.Config{
			Value:        &cfg.PrivateListenAddress,
			DefaultValue: bfgapi.DefaultPrivateListen,
			Help:         "address and port bfgd listens on for private, unauthenticated, websocket connections",
			Print:        config.PrintAll,
		},
		"BFG_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port bfgd prometheus listens on",
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
		log.Infof("bfg service received signal: %s", s)
	})

	server, err := bfg.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create BFG server: %w", err)
	}
	if err = server.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("BFG server terminated: %w", err)
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
