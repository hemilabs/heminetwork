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
	defaultLogLevel = daemonName + "=INFO;postgres=INFO;bfgpostgres=INFO;bfg=INFO"
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = bfg.NewDefaultConfig()
	cm  = config.CfgMap{
		"BFG_EXBTC_ADDRESS": config.Config{
			Value:        &cfg.EXBTCAddress,
			DefaultValue: "localhost:18001",
			Help:         "electrs endpoint",
			Print:        config.PrintAll,
		},
		"BFG_EXBTC_INITIAL_CONNECTIONS": config.Config{
			Value:        &cfg.EXBTCInitialConns,
			DefaultValue: 5,
			Help:         "electrs initial connections",
			Print:        config.PrintAll,
		},
		"BFG_EXBTC_MAX_CONNECTIONS": config.Config{
			Value:        &cfg.EXBTCMaxConns,
			DefaultValue: 100,
			Help:         "electrs max connections",
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
		"BFG_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port bfgd pprof listens on (open <address>/debug/pprof to see available profiles)",
			Print:        config.PrintAll,
		},
		"BFG_REQUEST_LIMIT": config.Config{
			Value:        &cfg.RequestLimit,
			DefaultValue: bfgapi.DefaultRequestLimit,
			Help:         "maximum request queue depth",
			Print:        config.PrintAll,
		},
		"BFG_REQUEST_TIMEOUT": config.Config{
			Value:        &cfg.RequestTimeout,
			DefaultValue: bfgapi.DefaultRequestTimeout,
			Help:         "request timeout in seconds",
			Print:        config.PrintAll,
		},
		"BFG_TRUSTED_PROXIES": config.Config{
			Value:        &cfg.TrustedProxies,
			DefaultValue: []string{},
			Help:         "trusted proxies IP addresses or CIDRs",
			Print:        config.PrintAll,
		},
		"BFG_REMOTE_IP_HEADERS": config.Config{
			Value:        &cfg.RemoteIPHeaders,
			DefaultValue: []string{},
			Help:         "list of headers used to obtain the client IP address (requires trusted proxies)",
			Print:        config.PrintAll,
		},
		"BFG_BFG_URL": config.Config{
			Value:        &cfg.BFGURL,
			DefaultValue: "",
			Help:         "public websocket address of another BFG you'd like to receive L2Keystones from",
			Print:        config.PrintAll,
		},
		"BFG_BTC_PRIVKEY": config.Config{
			Value:        &cfg.BTCPrivateKey,
			DefaultValue: "",
			Help:         "a btc private key, this is only needed when connecting to another BFG",
			Print:        config.PrintSecret,
		},
		"BFG_DISABLE_PUBLIC_CONNS": config.Config{
			Value:        &cfg.DisablePublicConns,
			DefaultValue: false,
			Help:         "disable public connections",
			Print:        config.PrintAll,
		},
		"BFG_BASELINE_L2_BLOCK_HEIGHT": config.Config{
			Value:        &cfg.BaselineL2BlockHeight,
			DefaultValue: int64(0),
			Help:         "the block height at which to safely count up from when cutting off invalid keystones for finality",
			Print:        config.PrintAll,
		},
		"BFG_BASELINE_L2_BLOCK_TIMESTAMP": config.Config{
			Value:        &cfg.BaselineL2BlockTimestamp,
			DefaultValue: int64(0),
			Help:         "the timestamp of the baseline l2 block",
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
