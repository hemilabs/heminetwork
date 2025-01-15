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

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/twcapi"
	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/service/twc"
	"github.com/hemilabs/heminetwork/version"
)

const (
	daemonName      = "twcd"
	defaultLogLevel = daemonName + "=INFO;twc=INFO;level=INFO"
	defaultNetwork  = "testnet3" // XXX make this mainnet
	defaultHome     = "~/." + daemonName
	bhsDefault      = int(1e6) // enough for mainnet
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = twc.NewDefaultConfig()
	cm  = config.CfgMap{
		"TWC_ADDRESS": config.Config{
			Value:        &cfg.ListenAddress,
			DefaultValue: twcapi.DefaultListen,
			Help:         "address port to listen on",
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
	log.Infof("%v", welcome)

	pc := config.PrintableConfig(cm)
	for k := range pc {
		log.Infof("%v", pc[k])
	}

	ctx, cancel := context.WithCancel(context.Background())
	go HandleSignals(ctx, cancel, func(s os.Signal) {
		log.Infof("twc service received signal: %s", s)
	})

	server, err := twc.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create twc server: %w", err)
	}

	if err := server.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("twc server terminated: %w", err)
	}

	return nil
}

func init() {
	version.Component = "twcd"
	welcome = "Hemi Tiny Wallet Daemon " + version.BuildInfo()
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
