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
	"time"

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/v2/config"
	"github.com/hemilabs/heminetwork/v2/service/hproxy"
	"github.com/hemilabs/heminetwork/v2/version"
)

const (
	daemonName      = "hproxyd"
	defaultLogLevel = daemonName + "=INFO;hproxy=INFO"
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = hproxy.NewDefaultConfig()
	cm  = config.CfgMap{
		"HPROXY_CLIENT_IDLE_TIMEOUT": config.Config{
			Value:        &cfg.ClientIdleTimeout,
			DefaultValue: hproxy.DefaultClientIdleTimeout,
			Help:         "max idle time to persists hvm reuse per client",
			Print:        config.PrintAll,
		},
		"HPROXY_HVM_URLS": config.Config{
			Value:        &cfg.HVMURLs,
			DefaultValue: cfg.HVMURLs,
			Help:         "comma separated HVM URLs",
			Print:        config.PrintAll,
		},
		"HPROXY_METHOD_WHITELIST": config.Config{
			Value:        &cfg.MethodFilter,
			DefaultValue: cfg.MethodFilter,
			Help:         "comma separated methods allowed by eth node RPCs",
			Print:        config.PrintAll,
		},
		"HPROXY_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"HPROXY_CONTROL_ADDRESS": config.Config{
			Value:        &cfg.ControlAddress,
			DefaultValue: hproxy.DefaultControlAddress,
			Help:         "control address for incoming commands",
			Print:        config.PrintAll,
		},
		"HPROXY_LISTEN_ADDRESS": config.Config{
			Value:        &cfg.ListenAddress,
			DefaultValue: hproxy.DefaultListenAddress,
			Help:         "listen address for incoming connections",
			Print:        config.PrintAll,
		},
		"HPROXY_NETWORK": config.Config{
			Value:        &cfg.Network,
			DefaultValue: "sepolia", // XXX
			Help:         "ethereum network (ex. \"mainnet\", \"sepolia\")",
			Print:        config.PrintAll,
		},
		"HPROXY_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port hproxy prometheus listens on",
			Print:        config.PrintAll,
		},
		"HPROXY_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port hproxy pprof listens on (open <address>/debug/pprof to see available profiles)",
			Print:        config.PrintAll,
		},
		"HPROXY_POLL_FREQUENCY": config.Config{
			Value:        &cfg.PollFrequency,
			DefaultValue: hproxy.DefaultPollFrequency,
			Help:         "frequency that hproxy pokes nodes for health information",
			Print:        config.PrintAll,
		},
		"HPROXY_REQUEST_SIZE": config.Config{
			Value:        &cfg.MaxRequestSize,
			DefaultValue: cfg.MaxRequestSize,
			Help:         "HVM request max size",
			Print:        config.PrintAll,
		},
		"HPROXY_REQUEST_TIMEOUT": config.Config{
			Value:        &cfg.RequestTimeout,
			DefaultValue: cfg.RequestTimeout,
			Help:         "HVM request timeout",
			Print:        config.PrintAll,
			Parse: func(envValue string) (any, error) {
				return time.ParseDuration(envValue)
			},
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

	hp, err := hproxy.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create hproxy: %w", err)
	}
	if err := hp.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("hproxy service terminated: %w", err)
	}

	return nil
}

func init() {
	version.Component = "hproxyd"
	welcome = "Hemi Proxy" + version.BuildInfo()
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
