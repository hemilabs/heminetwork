// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
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

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/mitchellh/go-homedir"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/config"
	"github.com/hemilabs/heminetwork/database"
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
	welcome = fmt.Sprintf("Hemi Network Controller: v%v", version.String())

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

var api string

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
		return "", nil, fmt.Errorf("action required")
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
	//switch action {
	//case "crossreference":
	//	return crossReference(ctx)
	//}

	// create fake service to call crawler
	cfg := tbc.NewDefaultConfig()
	cfg.LevelDBHome = "~/.tbcd"
	cfg.Network = "testnet3"
	s, err := tbc.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}
	// Open db.
	err = s.DBOpen(ctx)
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
			return fmt.Errorf("hash: must be set")
		}
		ch, err := chainhash.NewHashFromStr(hash)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}
		bh, err := s.DB().BlockHeaderByHash(ctx, ch[:])
		if err != nil {
			return fmt.Errorf("block header by hash: %w", err)
		}
		spew.Dump(bh)

	case "blockheadersbest":
		bhs, err := s.DB().BlockHeadersBest(ctx)
		if err != nil {
			return fmt.Errorf("block headers best: %w", err)
		}
		spew.Dump(bhs)

	case "blockheadersbyheight":
		height := args["height"]
		if height == "" {
			return fmt.Errorf("height: must be set")
		}
		h, err := strconv.ParseUint(height, 10, 64)
		if err != nil {
			return fmt.Errorf("parse uint: %w", err)
		}
		bh, err := s.DB().BlockHeadersByHeight(ctx, h)
		if err != nil {
			return fmt.Errorf("block header by height: %w", err)
		}
		spew.Dump(bh)

	// case "blockheadersinsert":

	case "blocksmissing":
		count := args["count"]
		c, err := strconv.ParseUint(count, 10, 64)
		if len(count) > 0 && err != nil {
			return fmt.Errorf("parse uint: %w", err)
		}
		if c == 0 {
			c = 1
		}
		bh, err := s.DB().BlocksMissing(ctx, int(c))
		if err != nil {
			return fmt.Errorf("block header by height: %w", err)
		}
		spew.Dump(bh)

	// case "blockinsert":

	case "blockbyhash":
		hash := args["hash"]
		if hash == "" {
			return fmt.Errorf("hash: must be set")
		}
		ch, err := chainhash.NewHashFromStr(hash)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}
		b, err := s.DB().BlockByHash(ctx, ch[:])
		if err != nil {
			return fmt.Errorf("block by hash: %w", err)
		}
		spew.Dump(b)

	case "dumpmetadata":
		s.DBClose()

		levelDBHome := "~/.tbcd" // XXX
		network := "testnet3"
		db, err := level.New(ctx, filepath.Join(levelDBHome, network))
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
		db, err := level.New(ctx, filepath.Join(levelDBHome, network))
		if err != nil {
			return err
		}
		defer db.Close()
		prefix := args["prefix"]
		if len(prefix) > 1 {
			return fmt.Errorf("prefix must be one byte")
		} else if len(prefix) == 1 && !(prefix[0] == 'h' || prefix[0] == 'u') {
			return fmt.Errorf("prefix must be h or u")
		}
		pool := db.DB()
		outsDB := pool[ldb.OutputsDB]
		it := outsDB.NewIterator(&util.Range{Start: []byte(prefix)}, nil)
		defer it.Release()
		for it.Next() {
			fmt.Printf("outputs key %vvalue %v", spew.Sdump(it.Key()), spew.Sdump(it.Value()))
		}

	case "help", "h":
		fmt.Printf("tbcd db manipulator commands:\n")
		fmt.Printf("\tbalancebyscripthash [hash]\n")
		fmt.Printf("\tblockbyhash [hash]\n")
		fmt.Printf("\tblockheaderbyhash [hash]\n")
		fmt.Printf("\tblockheadersbest\n")
		fmt.Printf("\tblockheadersbyheight [height]\n")
		fmt.Printf("\tblocksbytxid [hash]\n")
		fmt.Printf("\tblocksmissing [count]\n")
		fmt.Printf("\tdumpmetadata\n")
		fmt.Printf("\tdumpoutputs <prefix>\n")
		fmt.Printf("\thelp\n")
		fmt.Printf("\tscripthashbyoutpoint [txid] [index]\n")
		fmt.Printf("\tutxoindex <height> <count>\n")

	case "utxoindex":
		var h, c uint64
		height := args["height"]
		if height == "" {
			// Get height from db
			he, err := s.DB().MetadataGet(ctx, tbc.UtxoIndexHeightKey)
			if err != nil {
				if errors.Is(err, database.ErrNotFound) {
					return fmt.Errorf("metadata %v: %w",
						string(tbc.UtxoIndexHeightKey), err)
				}
				he = make([]byte, 8)
			}
			h = binary.BigEndian.Uint64(he)
		} else if h, err = strconv.ParseUint(height, 10, 64); err != nil {
			return fmt.Errorf("height: %w", err)
		}
		count := args["count"]
		if count == "" {
			c = 0
		} else if c, err = strconv.ParseUint(count, 10, 64); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		err = s.UtxoIndexer(ctx, h, c)
		if err != nil {
			return fmt.Errorf("indexer: %w", err)
		}

	case "txindex":
		var h, c uint64
		height := args["height"]
		if height == "" {
			// Get height from db
			he, err := s.DB().MetadataGet(ctx, tbc.TxIndexHeightKey)
			if err != nil {
				if errors.Is(err, database.ErrNotFound) {
					return fmt.Errorf("metadata %v: %w",
						string(tbc.TxIndexHeightKey), err)
				}
				he = make([]byte, 8)
			}
			h = binary.BigEndian.Uint64(he)
		} else if h, err = strconv.ParseUint(height, 10, 64); err != nil {
			return fmt.Errorf("height: %w", err)
		}
		count := args["count"]
		if count == "" {
			c = 0
		} else if c, err = strconv.ParseUint(count, 10, 64); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		err = s.TxIndexer(ctx, h, c)
		if err != nil {
			return fmt.Errorf("indexer: %w", err)
		}

	case "blocksbytxid":
		txid := args["txid"]
		if txid == "" {
			return fmt.Errorf("txid: must be set")
		}
		chtxid, err := chainhash.NewHashFromStr(txid)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}
		var revTxId [32]byte
		copy(revTxId[:], chtxid[:])

		bh, err := s.DB().BlocksByTxId(ctx, revTxId)
		if err != nil {
			return fmt.Errorf("block by txid: %w", err)
		}
		for k := range bh {
			fmt.Printf("%v\n", bh[k])
		}

	case "scripthashbyoutpoint":
		txid := args["txid"]
		if txid == "" {
			return fmt.Errorf("txid: must be set")
		}
		chtxid, err := chainhash.NewHashFromStr(txid)
		if err != nil {
			return fmt.Errorf("chainhash: %w", err)
		}
		var revTxId [32]byte
		copy(revTxId[:], chtxid[:])

		index := args["index"]
		if index == "" {
			return fmt.Errorf("index: must be set")
		}
		idx, err := strconv.ParseUint(index, 10, 32)
		if err != nil {
			return fmt.Errorf("index: %w", err)
		}
		op := tbcd.NewOutpoint(revTxId, uint32(idx))
		sh, err := s.DB().ScriptHashByOutpoint(ctx, op)
		if err != nil {
			return fmt.Errorf("block by hash: %w", err)
		}
		spew.Dump(sh)

	case "balancebyscripthash":
		hash := args["hash"]
		if hash == "" {
			return fmt.Errorf("hash: must be set")
		}
		h, err := hex.DecodeString(hash)
		if err != nil {
			return fmt.Errorf("decode hex: %w", err)
		}
		var hh [32]byte
		copy(hh[:], h)
		balance, err := s.DB().BalanceByScriptHash(ctx, hh)
		if err != nil {
			return fmt.Errorf("block by hash: %w", err)
		}
		spew.Dump(balance)

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
	sort.Sort(sort.StringSlice(sortedCommands))
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
		return fmt.Errorf("not enough parameters")
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
