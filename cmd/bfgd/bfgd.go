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
	welcome = fmt.Sprintf("Hemi Bitcoin Finality Governor %s", version.BuildInfo())
	cfg     = bfg.NewDefaultConfig()
	cm      = initializeConfigMap()
)

// initializeConfigMap initializes the configuration map for the application.
func initializeConfigMap() config.CfgMap {
	return config.CfgMap{
		"BFG_EXBTC_ADDRESS": config.Config{
			Value:        &cfg.EXBTCAddress,
			DefaultValue: "localhost:18001",
			Help:         "electrs endpoint",
			Print:        config.PrintAll,
		},
		// Other configuration options here...
	}
}

// handleSignals gracefully shuts down the application on OS signals.
func handleSignals(ctx context.Context, cancel context.CancelFunc, callback func(os.Signal)) {
	signalChan := make(chan os.Signal, 1)
	defer close(signalChan)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()

	select {
	case <-ctx.Done():
	case s := <-signalChan:
		if callback != nil {
			callback(s)
		}
		cancel()
	}
	<-signalChan
	log.Errorf("Received second termination signal, forcing exit.")
	os.Exit(2)
}

// initializeLogger configures logging for the application.
func initializeLogger(logLevel string) {
	loggo.ConfigureLoggers(logLevel)
	log.Infof("Logger initialized with level: %s", logLevel)
}

// parseConfig parses environment variables into the configuration map.
func parseConfig() error {
	if err := config.Parse(cm); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}
	return nil
}

// runServer starts the BFG server with the provided configuration.
func runServer(ctx context.Context) error {
	server, err := bfg.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create BFG server: %w", err)
	}
	if err = server.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("server terminated unexpectedly: %w", err)
	}
	return nil
}

func main() {
	// Verify command-line arguments
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, welcome)
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "\thelp (this help)")
		fmt.Fprintln(os.Stderr, "Environment:")
		config.Help(os.Stderr, cm)
		os.Exit(1)
	}

	// Initialize context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start signal handling in a separate goroutine
	go handleSignals(ctx, cancel, func(s os.Signal) {
		log.Infof("Received signal: %s", s)
	})

	// Parse configuration
	if err := parseConfig(); err != nil {
		log.Errorf("Configuration error: %v", err)
		os.Exit(1)
	}

	// Initialize logger
	initializeLogger(cfg.LogLevel)

	// Print welcome message and configuration
	log.Infof(welcome)
	pc := config.PrintableConfig(cm)
	for k, v := range pc {
		log.Infof("%s: %v", k, v)
	}

	// Run the server
	if err := runServer(ctx); err != nil {
		log.Errorf("Application error: %v", err)
		os.Exit(1)
	}
}
