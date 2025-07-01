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

	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/service/hproxy"
	"github.com/hemilabs/heminetwork/version"
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
		"HPROXY_LOG_LEVEL": config.Config{
			Value:        &cfg.LogLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
		"HPROXY_HVM_URLS": config.Config{
			Value:        &cfg.HVMURLs,
			DefaultValue: cfg.HVMURLs,
			Help:         "comma separated HVM URLs",
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
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port hproxy pprof listens on (open <address>/debug/pprof to see available profiles)",
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

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		return err
	}
	log.Infof("%v", welcome)

	pc := config.PrintableConfig(cm)
	for k := range pc {
		log.Infof("%v", pc[k])
	}

	ctx, cancel := context.WithCancel(context.Background())
	go handleSignals(ctx, cancel, func(s os.Signal) {
		log.Infof("hproxy service received signal: %s", s)
	})

	hp, err := hproxy.NewHProxy(cfg)
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
