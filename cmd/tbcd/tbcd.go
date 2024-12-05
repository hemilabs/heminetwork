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

	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/hemilabs/heminetwork/version"
)

const (
	daemonName      = "tbcd"
	defaultLogLevel = daemonName + "=INFO;tbc=INFO;level=INFO"
	defaultNetwork  = "testnet3" // XXX make this mainnet
	defaultHome     = "~/." + daemonName
	bhsDefault      = int(1e6) // enough for mainnet
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	cfg = tbc.NewDefaultConfig()
	cm  = config.CfgMap{
		"TBC_ADDRESS": config.Config{
			Value:        &cfg.ListenAddress,
			DefaultValue: tbcapi.DefaultListen,
			Help:         "address port to listen on",
			Print:        config.PrintAll,
		},
		"TBC_AUTO_INDEX": config.Config{
			Value:        &cfg.AutoIndex,
			DefaultValue: true,
			Help:         "enable auto utxo and tx indexes",
			Print:        config.PrintAll,
		},
		"TBC_BLOCK_CACHE": config.Config{
			Value:        &cfg.BlockCache,
			DefaultValue: 250,
			Help:         "number of cached blocks",
			Print:        config.PrintAll,
		},
		"TBC_BLOCKHEADER_CACHE": config.Config{
			Value:        &cfg.BlockheaderCache,
			DefaultValue: bhsDefault,
			Help:         "number of cached blockheaders",
			Print:        config.PrintAll,
		},
		"TBC_BLOCK_SANITY": config.Config{
			Value:        &cfg.BlockSanity,
			DefaultValue: false,
			Help:         "enable/disable block sanity checks before inserting",
			Print:        config.PrintAll,
		},
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
		"TBC_MAX_CACHED_TXS": config.Config{
			Value:        &cfg.MaxCachedTxs,
			DefaultValue: int(1e6),
			Help:         "maximum cached utxos and/or txs during indexing",
			Print:        config.PrintAll,
		},
		"TBC_MEMPOOL_ENABLED": config.Config{
			Value:        &cfg.MempoolEnabled,
			DefaultValue: true,
			Help:         "bitcoin network mempool enable/disable switch",
			Print:        config.PrintAll,
		},
		"TBC_NETWORK": config.Config{
			Value:        &cfg.Network,
			DefaultValue: defaultNetwork,
			Help:         "bitcoin network; mainnet or testnet3",
			Print:        config.PrintAll,
		},
		"TBC_PEERS_WANTED": config.Config{
			Value:        &cfg.PeersWanted,
			DefaultValue: 64,
			Help:         "number of wanted p2p peers",
			Print:        config.PrintAll,
		},
		"TBC_PROMETHEUS_ADDRESS": config.Config{
			Value:        &cfg.PrometheusListenAddress,
			DefaultValue: "",
			Help:         "address and port tbcd prometheus listens on",
			Print:        config.PrintAll,
		},
		"TBC_PPROF_ADDRESS": config.Config{
			Value:        &cfg.PprofListenAddress,
			DefaultValue: "",
			Help:         "address and port tbcd pprof listens on (open <address>/debug/pprof to see available profiles)",
			Print:        config.PrintAll,
		},
		"TBC_SEEDS": config.Config{
			Value:        &cfg.Seeds,
			DefaultValue: []string{},
			Help:         "list of seed domains for Bitcoin P2P, in the format '<host>:<port>' (for localnet, must be a single host:port)",
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
		return fmt.Errorf("create tbc server: %w", err)
	}

	// XXX remove, this is an illustration of calling the direct API of server
	// go func() {
	//	for {
	//		select {
	//		case <-ctx.Done():
	//			return
	//		case <-time.After(2 * time.Second):
	//		}

	//		log.Infof("synced: %v", spew.Sdump(server.Synced(ctx)))
	//		hashS := "000000001a4c2c64beded987790ab0c00675b4bc467cd3574ad455b1397c967c"
	//		ch, err := chainhash.NewHashFromStr(hashS)
	//		if err != nil {
	//			panic(err)
	//		}
	//		bh, height, err := server.BlockHeaderByHash(ctx, ch)
	//		if err != nil {
	//			panic(err)
	//		}
	//		log.Infof("height %v hash %v%v", height, bh.BlockHash(), spew.Sdump(bh))

	//		bhbh, err := server.BlockHeadersByHeight(ctx, height)
	//		if err != nil {
	//			panic(err)
	//		}
	//		log.Infof("height %v headers %v", height, spew.Sdump(bhbh))
	//	}
	// }()
	if err := server.Run(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("tbc server terminated: %w", err)
	}

	return nil
}

func init() {
	version.Component = "tbcd"
	welcome = "Hemi Tiny Bitcoin Daemon " + version.BuildInfo()
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
