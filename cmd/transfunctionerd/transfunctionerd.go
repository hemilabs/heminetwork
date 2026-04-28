// Copyright (c) 2025-2026 Hemi Labs, Inc.
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

	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/config"
	"github.com/hemilabs/heminetwork/v2/service/continuum"
	"github.com/hemilabs/heminetwork/v2/version"
)

const (
	daemonName      = "transfunctionerd"
	defaultLogLevel = daemonName + "=INFO"
	// defaultNetwork  = "mainnet"
	defaultHome        = "~/." + daemonName
	defaultPeersWanted = 8
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = continuum.NewDefaultConfig()
	cm  = config.CfgMap{
		"TRF_CONNECT": config.Config{
			Value:        &cfg.Connect,
			DefaultValue: []string{},
			Help:         "connect to provided hosts directly, this bypasses seeding",
			Print:        config.PrintAll,
		},
		"TRF_HOME": config.Config{
			Value:        &cfg.Home,
			DefaultValue: defaultHome,
			Help:         "data directory",
			Print:        config.PrintAll,
		},
		"TRF_LISTEN_ADDRESS": config.Config{
			Value:        &cfg.ListenAddress,
			DefaultValue: "",
			Help:         "address and port transfunctionerd listens on for incoming tcp connections",
			Print:        config.PrintAll,
		},
		"TRF_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"TRF_PEERS_WANTED": config.Config{
			Value:        &cfg.PeersWanted,
			DefaultValue: defaultPeersWanted,
			Help:         "target number of peer connections to maintain",
			Print:        config.PrintAll,
		},
		"TRF_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port transfunctionerd pprof listens on (open <address>/debug/pprof to see available profiles)",
			Print:        config.PrintAll,
		},
		"TRF_PREPARAMS_TIMEOUT": config.Config{
			Value:        &cfg.PreParamsTimeout,
			DefaultValue: time.Duration(0),
			Help:         "timeout for Paillier safe prime generation on first run (e.g. \"5m\"); 0 uses default 1m",
			Print:        config.PrintAll,
			Parse: func(envValue string) (any, error) {
				return time.ParseDuration(envValue)
			},
		},
		"TRF_PRIVATE_KEY": config.Config{
			Value:        &cfg.PrivateKey,
			DefaultValue: "",
			Help:         "secp256k1 private key",
			Print:        config.PrintSecret,
		},
		"TRF_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port transfunctionerd prometheus listens on",
			Print:        config.PrintAll,
		},
		"TRF_DNS": config.Config{
			Value:        &cfg.DNS,
			DefaultValue: "forward",
			Help: "DNS verification mode. Controls how peer identity is " +
				"verified via DNS TXT records.\n" +
				"  \"forward\" - verify peers via forward TXT lookup on " +
				"their advertised hostname; reject IP-only peers (default)\n" +
				"  \"reverse\" - verify peers via reverse DNS lookup on " +
				"their IP address\n" +
				"  \"all\"     - forward verify hostname peers, reverse " +
				"verify IP peers\n" +
				"  \"off\"     - no DNS verification (insecure)\n" +
				"Requires TRF_HOSTNAME when set to \"forward\" or \"all\".",
			Print: config.PrintAll,
		},
		"TRF_HOSTNAME": config.Config{
			Value:        &cfg.Hostname,
			DefaultValue: "",
			Help: "Hostname to advertise in peer gossip. When set, other " +
				"nodes in forward/all DNS mode can verify this node via " +
				"TXT record lookup. The TXT record must contain " +
				"\"v=transfunctioner; identity=<identity>\". Required " +
				"when TRF_DNS is \"forward\" or \"all\".",
			Print: config.PrintAll,
		},
		"TRF_SEEDS": config.Config{
			Value:        &cfg.Seeds,
			DefaultValue: []string{},
			Help:         "DNS seed hostnames (host:port), ignored when TRF_CONNECT is set",
			Print:        config.PrintAll,
		},
		// XXX add max queue depth per connection
		// XXX maybe add max commands / second
		// XXX maybe add white/black list of ips/hosts
	}
)

func init() {
	version.Component = daemonName
	welcome = "Hemi Continuum Transfunctioner Daemon " + version.BuildInfo()
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt,
		syscall.SIGTERM)
	defer cancel()
	go func() {
		// Stop receiving signals as soon as possible.
		<-ctx.Done()
		log.Infof("continuum transfunctioner activated, ending universe.")
		cancel()
	}()

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
