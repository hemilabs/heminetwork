// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/mitchellh/go-homedir"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/database/bfgd/postgres"
	ldb "github.com/hemilabs/heminetwork/database/level"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/hemilabs/heminetwork/version"
)

const (
	daemonName      = "hemictl"
	defaultLogLevel = daemonName + "=INFO;bfgpostgres=INFO;postgres=INFO;protocol=INFO"
)

var (
	log     = loggo.GetLogger(daemonName)
	welcome string

	bssURL   string
	logLevel string
	cm       = config.CfgMap{
		"HEMICTL_BSS_URL": config.Config{
			Value:        &bssURL,
			DefaultValue: bssapi.DefaultURL,
			Help:         "BSS websocket server host and route",
			Print:        config.PrintAll,
		},
		"HEMICTL_LOG_LEVEL": config.Config{
			Value:        &logLevel,
			DefaultValue: defaultLogLevel,
			Help:         "loglevel for various packages; INFO, DEBUG and TRACE",
			Print:        config.PrintAll,
		},
	}

	callTimeout = 100 * time.Second
)

// handleBSSWebsocketReadUnauth discards all reads but has to exist in order to
// be able to use bssapi.Call.
func handleBSSWebsocketReadUnauth(ctx context.Context, conn *protocol.Conn) {
	for {
		if _, _, _, err := bssapi.ReadConn(ctx, conn); err != nil {
			return
		}
	}
}

// handleBSSWebsocketReadUnauth discards all reads but has to exist in order to
// be able to use bfgapi.Call.
func handleBFGWebsocketReadUnauth(ctx context.Context, conn *protocol.Conn) {
	for {
		if _, _, _, err := bfgapi.ReadConn(ctx, conn); err != nil {
			return
		}
	}
}

// handleTBCWebsocketRead discards all reads but has to exist in order to
// be able to use tbcapi.Call.
func handleTBCWebsocketRead(ctx context.Context, conn *protocol.Conn) {
	for {
		if _, _, _, err := tbcapi.ReadConn(ctx, conn); err != nil {
			return
		}
	}
}

func bfgdb() error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	pgURI := os.Getenv("PGURI") // XXX mpve into config
	if pgURI == "" {
		// construct pgURI based on reasonable defaults.
		home, err := homedir.Dir()
		if err != nil {
			return fmt.Errorf("dir: %w", err)
		}
		user, err := user.Current()
		if err != nil {
			return fmt.Errorf("current: %w", err)
		}

		filename := filepath.Join(home, ".pgsql-bfgdb-"+user.Username)
		password, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		pgURI = fmt.Sprintf("database=bfgdb password=%s", password)
	}

	db, err := postgres.New(ctx, pgURI)
	if err != nil {
		return fmt.Errorf("new: %w", err)
	}
	defer db.Close()

	param := flag.Arg(2)
	c := flag.Arg(1)
	out := make(map[string]any, 10)
	switch c {
	case "version":
		out["bfgdb_version"], err = db.Version(ctx)
		if err != nil {
			return fmt.Errorf("error received getting version: %s", err.Error())
		}
	default:
		return fmt.Errorf("invalid bfgdb command: %v", c)
	}
	_ = param

	o, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	fmt.Printf("%s\n", o)

	return nil
}

func parseArgs(args []string) (string, map[string]string, error) {
	if len(args) < 1 {
		flag.Usage()
		return "", nil, errors.New("action required")
	}

	action := args[0]
	parsed := make(map[string]string, 10)

	for _, v := range args[1:] {
		s := strings.Split(v, "=")
		if len(s) != 2 {
			return "", nil, fmt.Errorf("invalid argument: %v", v)
		}
		if len(s[0]) == 0 || len(s[1]) == 0 {
			return "", nil, fmt.Errorf("expected a=b, got %v", v)
		}
		parsed[s[0]] = s[1]
	}

	return action, parsed, nil
}

func tbcdb() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	action, args, err := parseArgs(flag.Args()[1:])
	if err != nil {
		return err
	}

	// special commands
	// switch action {
	// case "crossreference":
	//	return crossReference(ctx)
	// }

	// create fake service to call crawler
	cfg := tbc.NewDefaultConfig()
	cfg.LevelDBHome = "~/.tbcd"
	cfg.Network = "testnet3"
	s, err := tbc.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}
	// Open db.
	err = s.DBOpen(ctx) // XXX kill this and verify all reversed hashes as parameters
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}
	defer func() {
		err := s.DBClose()
		if err != nil {
			fmt.Fprintf(os.Stderr, "db close: %v\n", err)
			os.Exit(1)
		}
	}()

	// commands
	switch action {
	case "blockheaderbyhash":
		hash := args["hash"]
		if hash == "" {
			return errors.New("hash: must be set")
		}
		ch, err := chainhash.NewHashFromStr(hash)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}
		bh, height, err := s.BlockHeaderByHash(ctx, ch)
		if err != nil {
			return fmt.Errorf("block header by hash: %w", err)
		}
		fmt.Printf("hash  : %v\n", bh)
		fmt.Printf("height: %v\n", height)

	case "blockheaderbest":
		height, bh, err := s.BlockHeaderBest(ctx)
		if err != nil {
			return fmt.Errorf("block header best: %w", err)
		}
		fmt.Printf("hash  : %v\n", bh.BlockHash())
		fmt.Printf("height: %v\n", height)

	case "blockheadersbyheight":
		height := args["height"]
		if height == "" {
			return errors.New("height: must be set")
		}
		h, err := strconv.ParseUint(height, 10, 64)
		if err != nil {
			return fmt.Errorf("parse uint: %w", err)
		}
		bh, err := s.BlockHeadersByHeight(ctx, h)
		if err != nil {
			return fmt.Errorf("block header by height: %w", err)
		}
		spew.Dump(bh)

	// case "blockheadersinsert":

	case "blocksmissing":
		count := args["count"]
		c, err := strconv.ParseInt(count, 10, 32)
		if len(count) > 0 && err != nil {
			return fmt.Errorf("parse uint: %w", err)
		}
		bi, err := s.BlocksMissing(ctx, int(c))
		if err != nil {
			return fmt.Errorf("blocks missing: %w", err)
		}
		for k := range bi {
			fmt.Printf("%v: %v\n", bi[k].Height, bi[k].Hash)
		}

	// case "blockinsert":

	case "blockbyhash":
		hash := args["hash"]
		if hash == "" {
			return errors.New("hash: must be set")
		}
		ch, err := chainhash.NewHashFromStr(hash)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}
		b, err := s.BlockByHash(ctx, ch)
		if err != nil {
			return fmt.Errorf("block by hash: %w", err)
		}
		spew.Dump(b)

	case "deletemetadata":
		key := args["key"]
		if key == "" {
			return errors.New("key: must be set")
		}

		s.DBClose()

		levelDBHome := "~/.tbcd" // XXX
		network := "testnet3"
		db, err := level.New(ctx, level.NewConfig(filepath.Join(levelDBHome, network)))
		if err != nil {
			return err
		}
		defer db.Close()
		pool := db.DB()
		mdDB := pool[ldb.MetadataDB]
		err = mdDB.Delete([]byte(key), nil)
		if err != nil {
			return err
		}

	case "dumpmetadata":
		s.DBClose()

		levelDBHome := "~/.tbcd" // XXX
		network := "testnet3"
		db, err := level.New(ctx, level.NewConfig(filepath.Join(levelDBHome, network)))
		if err != nil {
			return err
		}
		defer db.Close()
		pool := db.DB()
		mdDB := pool[ldb.MetadataDB]
		it := mdDB.NewIterator(nil, nil)
		defer it.Release()
		for it.Next() {
			fmt.Printf("metadata key %vvalue %v", spew.Sdump(it.Key()), spew.Sdump(it.Value()))
		}

	case "dumpoutputs":
		s.DBClose()

		levelDBHome := "~/.tbcd" // XXX
		network := "testnet3"
		db, err := level.New(ctx, level.NewConfig(filepath.Join(levelDBHome, network)))
		if err != nil {
			return err
		}
		defer db.Close()
		prefix := args["prefix"]
		if len(prefix) > 1 {
			return errors.New("prefix must be one byte")
		} else if len(prefix) == 1 && !(prefix[0] == 'h' || prefix[0] == 'u') {
			return errors.New("prefix must be h or u")
		}
		pool := db.DB()
		outsDB := pool[ldb.OutputsDB]
		it := outsDB.NewIterator(&util.Range{Start: []byte(prefix)}, nil)
		defer it.Release()
		for it.Next() {
			fmt.Printf("outputs key %vvalue %v", spew.Sdump(it.Key()), spew.Sdump(it.Value()))
		}

	case "feesbyheight":
		height := args["height"]
		if height == "" {
			return errors.New("height: must be set")
		}
		h, err := strconv.ParseInt(height, 10, 64)
		if err != nil {
			return fmt.Errorf("parse uint: %w", err)
		}
		count := args["count"]
		c, err := strconv.ParseInt(count, 10, 64)
		if len(count) > 0 && err != nil {
			return fmt.Errorf("parse uint: %w", err)
		}
		if c == 0 {
			c = 1
		}
		bh, err := s.FeesAtHeight(ctx, h, c)
		if err != nil {
			return fmt.Errorf("fees by height: %w", err)
		}
		spew.Dump(bh)

	case "help", "h":
		fmt.Println("tbcd db manipulator commands:")
		fmt.Println("\tbalancebyscripthash [hash]")
		fmt.Println("\tblockbyhash [hash]")
		fmt.Println("\tblockheaderbyhash [hash]")
		fmt.Println("\tblockheaderbest")
		fmt.Println("\tblockheadersbyheight [height]")
		fmt.Println("\tblocksbytxid [hash]")
		fmt.Println("\tblocksmissing [count]")
		fmt.Println("\tdeletemetadata")
		fmt.Println("\tdumpmetadata")
		fmt.Println("\tdumpoutputs <prefix>")
		fmt.Println("\thelp")
		fmt.Println("\tscripthashbyoutpoint [txid] [index]")
		fmt.Println("\tspentoutputsbytxid <txid>")
		fmt.Println("\ttxbyid <hash>")
		fmt.Println("\ttxindex <height> <count> <maxcache>")
		fmt.Println("\tutxoindex <height> <count> <maxcache>")
		fmt.Println("\tutxosbyscripthash [hash]")

	case "utxoindex":
		hash := args["hash"]
		if hash == "" {
			return errors.New("must provide hash")
		}
		eh, err := chainhash.NewHashFromStr(hash)
		if err != nil {
			return fmt.Errorf("parse hash: %w", err)
		}

		maxCache := args["maxcache"]
		var mc uint64
		if maxCache != "" {
			if mc, err = strconv.ParseUint(maxCache, 10, 64); err != nil {
				return fmt.Errorf("maxCache: %w", err)
			}
			cfg.MaxCachedTxs = int(mc)
		}
		err = s.UtxoIndexer(ctx, eh)
		if err != nil {
			return fmt.Errorf("indexer: %w", err)
		}

	case "txindex":
		hash := args["hash"]
		if hash == "" {
			return errors.New("must provide hash")
		}
		eh, err := chainhash.NewHashFromStr(hash)
		if err != nil {
			return fmt.Errorf("parse hash: %w", err)
		}

		maxCache := args["maxcache"]
		var mc uint64
		if maxCache != "" {
			if mc, err = strconv.ParseUint(maxCache, 10, 64); err != nil {
				return fmt.Errorf("maxCache: %w", err)
			}
			cfg.MaxCachedTxs = int(mc)
		}
		if err = s.TxIndexer(ctx, eh); err != nil {
			return fmt.Errorf("indexer: %w", err)
		}

	case "blockhashbytxid":
		txid := args["txid"]
		if txid == "" {
			return errors.New("txid: must be set")
		}
		chtxid, err := chainhash.NewHashFromStr(txid)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}

		bh, err := s.BlockHashByTxId(ctx, chtxid)
		if err != nil {
			return fmt.Errorf("block by txid: %w", err)
		}
		fmt.Printf("%v\n", bh)

	case "txbyid":
		txid := args["txid"]
		if txid == "" {
			return errors.New("txid: must be set")
		}
		chtxid, err := chainhash.NewHashFromStr(txid)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}

		tx, err := s.TxById(ctx, chtxid)
		if err != nil {
			return fmt.Errorf("block by txid: %w", err)
		}
		fmt.Printf("%v\n", spew.Sdump(tx))

	case "spentoutputsbytxid":
		txid := args["txid"]
		if txid == "" {
			return errors.New("txid: must be set")
		}
		chtxid, err := chainhash.NewHashFromStr(txid)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}

		si, err := s.SpentOutputsByTxId(ctx, chtxid)
		if err != nil {
			return fmt.Errorf("spend outputs by txid: %w", err)
		}
		for k := range si {
			fmt.Printf("%v\n", si[k])
		}

	case "scripthashbyoutpoint":
		txid := args["txid"]
		if txid == "" {
			return errors.New("txid: must be set")
		}
		chtxid, err := chainhash.NewHashFromStr(txid)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}

		si, err := s.SpentOutputsByTxId(ctx, chtxid)
		if err != nil {
			return fmt.Errorf("spend outputs by txid: %w", err)
		}
		for k := range si {
			fmt.Printf("%v\n", si[k])
		}

	case "blockintxindex":
		blkid := args["blkid"]
		if blkid == "" {
			return errors.New("blkid: must be set")
		}
		blkhash, err := chainhash.NewHashFromStr(blkid)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}
		ok, err := s.BlockInTxIndex(ctx, blkhash)
		if err != nil {
			return fmt.Errorf("block in transaction index: %w", err)
		}
		fmt.Printf("%v\n", ok)

	case "balancebyscripthash":
		address := args["address"]
		hash := args["hash"]
		if address == "" && hash == "" {
			return errors.New("hash or address: must be set")
		} else if address != "" && hash != "" {
			return errors.New("hash or address: both set")
		}

		var sh tbcd.ScriptHash
		if hash != "" {
			sh, err = tbcd.NewScriptHashFromString(hash)
			if err != nil {
				return fmt.Errorf("new scripthash from string: %w", err)
			}
		}
		if address != "" {
			// XXX set params
			a, err := btcutil.DecodeAddress(address, &chaincfg.TestNet3Params)
			if err != nil {
				return err
			}
			h, err := txscript.PayToAddrScript(a)
			if err != nil {
				return err
			}
			sh = tbcd.NewScriptHashFromScript(h)
		}

		balance, err := s.BalanceByScriptHash(ctx, sh)
		if err != nil {
			return fmt.Errorf("block by hash: %w", err)
		}
		spew.Dump(balance)

	case "utxosbyscripthash":
		address := args["address"]
		hash := args["hash"]
		count := args["count"]
		start := args["start"]

		if address == "" && hash == "" {
			return errors.New("hash or address: must be set")
		} else if address != "" && hash != "" {
			return errors.New("hash or address: both set")
		}

		if count == "" {
			count = "100"
		}

		if start == "" {
			start = "0"
		}

		countNum, err := strconv.ParseUint(count, 10, 64)
		if err != nil {
			return err
		}

		startNum, err := strconv.ParseUint(start, 10, 64)
		if err != nil {
			return err
		}

		var sh tbcd.ScriptHash
		if hash != "" {
			sh, err = tbcd.NewScriptHashFromString(hash)
			if err != nil {
				return err
			}
		}
		if address != "" {
			// XXX set params
			a, err := btcutil.DecodeAddress(address, &chaincfg.TestNet3Params)
			if err != nil {
				return err
			}
			h, err := txscript.PayToAddrScript(a)
			if err != nil {
				return err
			}
			sh = tbcd.NewScriptHashFromScript(h)
		}

		utxos, err := s.UtxosByScriptHash(ctx, sh, startNum, countNum)
		if err != nil {
			return fmt.Errorf("block by hash: %w", err)
		}
		var balance uint64
		for k := range utxos {
			fmt.Printf("%v\n", utxos[k])
			balance += utxos[k].Value()
		}
		fmt.Printf("utxos: %v total: %v\n", len(utxos), balance)

	default:
		return fmt.Errorf("invalid action: %v", action)
	}

	return nil
}

type bssClient struct {
	wg     *sync.WaitGroup
	bssURL string
}

func (bsc *bssClient) handleBSSWebsocketReadUnauth(ctx context.Context, conn *protocol.Conn) {
	defer bsc.wg.Done()

	log.Tracef("handleBSSWebsocketReadUnauth")
	defer log.Tracef("handleBSSWebsocketReadUnauth exit")
	for {
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		default:
		}

		cmd, rid, payload, err := bssapi.ReadConn(ctx, conn)
		if err != nil {
			log.Errorf("handleBSSWebsocketReadUnauth: %v", err)
			time.Sleep(3 * time.Second)
			continue
			// return
		}
		log.Infof("cmd: %v rid: %v payload: %T", cmd, rid, payload)
	}
}

func (bsc *bssClient) connect(ctx context.Context) error {
	log.Tracef("connect")
	defer log.Tracef("connect exit")

	conn, err := protocol.NewConn(bsc.bssURL, nil)
	if err != nil {
		return err
	}
	err = conn.Connect(ctx)
	if err != nil {
		return err
	}

	bsc.wg.Add(1)
	go bsc.handleBSSWebsocketReadUnauth(ctx, conn)

	// Required ping
	// _, _, _, err = bssapi.Call(ctx, conn, bssapi.PingRequest{
	//	Timestamp: time.Now().Unix(),
	// })
	// if err != nil {
	//	return fmt.Errorf("ping error: %w", err)
	// }

	simulatePingPong := false
	if simulatePingPong {
		bsc.wg.Add(1)
		go func() {
			defer bsc.wg.Done()
			for {
				// See if we were terminated
				select {
				case <-ctx.Done():
					return
				default:
				}

				time.Sleep(5 * time.Second)
				_, _, _, err = bssapi.Call(ctx, conn, bssapi.PingRequest{
					Timestamp: time.Now().Unix(),
				})
				if err != nil {
					log.Errorf("ping error: %v", err)
					continue
					// return fmt.Errorf("ping error: %w", err)
				}
			}
		}()
	}

	// Wait for exit
	bsc.wg.Wait()

	return nil
}

func (bsc *bssClient) connectBSS(ctx context.Context) {
	log.Tracef("bssClient")
	defer log.Tracef("bssClient exit")

	bssURI := filepath.Join(bsc.bssURL)
	log.Infof("Connecting to: %v", bssURI)
	for {
		if err := bsc.connect(ctx); err != nil {
			// Do nothing
			log.Errorf("connect: %v", err) // remove this, too loud
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		default:
		}

		// hold off reconnect for a couple of seconds
		time.Sleep(5 * time.Second)
		log.Debugf("Reconnecting to: %v", bssURI)
	}
}

func bssLong(ctx context.Context) error {
	bsc := &bssClient{
		wg:     new(sync.WaitGroup),
		bssURL: bssURL,
	}

	go bsc.connectBSS(ctx)

	<-ctx.Done()
	if !errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}

	return nil
}

func client(which string) error {
	log.Debugf("client %v", which)
	defer log.Debugf("client %v exit", which)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	simulateCtrlC := false
	if simulateCtrlC {
		// XXX add signal handler instead of this poop
		go func() {
			time.Sleep(3 * time.Second)
			cancel()
		}()

		defer func() {
			log.Infof("waiting for exit")
			time.Sleep(3 * time.Second)
		}()
	}

	switch which {
	case "bss":
		return bssLong(ctx)
	}
	return fmt.Errorf("invalid client: %v", which)
}

var (
	reSkip         = regexp.MustCompile(`(?i)(Response|Notification)$`)
	allCommands    = make(map[string]reflect.Type)
	sortedCommands []string
)

func init() {
	version.Component = "hemictl"
	welcome = "Hemi Network Controller " + version.BuildInfo()

	// merge all command maps
	for k, v := range bssapi.APICommands() {
		allCommands[string(k)] = v
	}
	for k, v := range bfgapi.APICommands() {
		allCommands[string(k)] = v
	}
	for k, v := range tbcapi.APICommands() {
		allCommands[string(k)] = v
	}

	sortedCommands = make([]string, 0, len(allCommands))
	for k := range allCommands {
		sortedCommands = append(sortedCommands, k)
	}
	sort.Strings(sortedCommands)
}

func usage() {
	fmt.Fprintf(os.Stderr, "%v\n", welcome)
	fmt.Fprintf(os.Stderr, "\t%v <command> [payload]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "\tbfgdb database connection\n")
	fmt.Fprintf(os.Stderr, "\tbss-client long connection to bss\n")
	fmt.Fprintf(os.Stderr, "\thelp (this help)\n")
	fmt.Fprintf(os.Stderr, "\thelp-verbose JSON print RPC default request/response\n")
	fmt.Fprintf(os.Stderr, "\ttbcdb datase open (tbcd must not be running)\n")
	fmt.Fprintf(os.Stderr, "Environment:\n")
	config.Help(os.Stderr, cm)
	fmt.Fprintf(os.Stderr, "Commands:\n")
	for _, v := range sortedCommands {
		if reSkip.MatchString(v) {
			continue
		}
		fmt.Fprintf(os.Stderr, "\t%v [%v]\n", v, allCommands[v])
	}
}

func helpVerbose() {
	fmt.Fprintf(os.Stderr, "%v\n", welcome)
	fmt.Fprintf(os.Stderr, "\t%v <command> [payload]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Payload request/response/notification:\n")
	for _, v := range sortedCommands {
		cmdType := allCommands[v]
		clone := reflect.New(cmdType).Interface()
		fmt.Fprintf(os.Stderr, "%v:\n", v)
		printJSON(os.Stderr, "  ", clone)
		fmt.Fprintf(os.Stderr, "\n")
	}
}

func printJSON(where io.Writer, indent string, payload any) error {
	w := &bytes.Buffer{}
	fmt.Fprintf(where, indent) // lol first line doesnt work
	e := json.NewEncoder(w)
	e.SetIndent(indent, "    ")
	if err := e.Encode(payload); err != nil {
		return fmt.Errorf("can't encode payload %T: %w", payload, err)
	}
	fmt.Fprintf(where, "%s", w.Bytes())
	return nil
}

func _main() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("not enough parameters")
	}

	if err := config.Parse(cm); err != nil {
		return err
	}

	loggo.ConfigureLoggers(logLevel)
	log.Debugf("%v", welcome)

	pc := config.PrintableConfig(cm)
	for k := range pc {
		log.Debugf("%v", pc[k])
	}

	cmd := flag.Arg(0) // command provided by user

	// Deal with non-generic commands
	switch cmd {
	case "bfgdb":
		return bfgdb()
	case "bss-client":
		return client("bss")
	case "help":
		usage()
		return nil
	case "help-verbose":
		helpVerbose()
		return nil
	case "tbcdb":
		return tbcdb()
	}

	// Deal with generic commands
	cmdType, ok := allCommands[cmd]
	if !ok {
		return fmt.Errorf("unknown command: %v", cmd)
	}
	// Figure out where and what we are calling based on command.
	var (
		u           string
		callHandler func(context.Context, *protocol.Conn)
		call        func(context.Context, *protocol.Conn, any) (protocol.Command, string, any, error)
	)
	switch {
	case strings.HasPrefix(cmd, "bssapi"):
		u = bssapi.DefaultURL
		callHandler = handleBSSWebsocketReadUnauth
		call = bssapi.Call // XXX yuck
	case strings.HasPrefix(cmd, "bfgapi"):
		u = bfgapi.DefaultPrivateURL
		callHandler = handleBFGWebsocketReadUnauth
		call = bfgapi.Call // XXX yuck
	case strings.HasPrefix(cmd, "tbcapi"):
		u = tbcapi.DefaultURL
		callHandler = handleTBCWebsocketRead
		call = tbcapi.Call // XXX yuck?
	default:
		return fmt.Errorf("can't derive URL from command: %v", cmd)
	}
	conn, err := protocol.NewConn(u, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	go callHandler(ctx, conn) // Make sure we can use Call

	clone := reflect.New(cmdType).Interface()
	log.Debugf("%v", spew.Sdump(clone))
	if flag.Arg(1) != "" {
		err := json.Unmarshal([]byte(flag.Arg(1)), &clone)
		if err != nil {
			return fmt.Errorf("invalid payload: %w", err)
		}
	}
	_, _, payload, err := call(ctx, conn, clone)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	log.Debugf("%v", spew.Sdump(payload))

	return printJSON(os.Stdout, "", payload)
}

func main() {
	flag.Parse()
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	if err := _main(); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v: %v\n", daemonName, err)
		os.Exit(1)
	}
}
