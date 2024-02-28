package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/cmd/btctool/bdf"
	"github.com/hemilabs/heminetwork/cmd/btctool/blockstream"
	"github.com/hemilabs/heminetwork/cmd/btctool/btctool"
	"github.com/juju/loggo"
	"github.com/mitchellh/go-homedir"
)

var log = loggo.GetLogger("bdf")

func parseBlock(ctx context.Context, filename string) (*btcutil.Block, error) {
	heb, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	eb, err := hex.DecodeString(strings.Trim(string(heb), "\n"))
	if err != nil {
		return nil, err
	}
	fmt.Printf("len %v\n", len(eb))

	// decode
	b, err := btcutil.NewBlockFromBytes(eb)
	if err != nil {
		return nil, err
	}

	return b, nil
}

type peer struct {
	mtx     sync.RWMutex
	address string
	conn    net.Conn

	protocolVersion uint32
	network         wire.BitcoinNet

	remoteVersion *wire.MsgVersion
	addrV2        bool
}

func NewPeer(network wire.BitcoinNet, address string) (*peer, error) {
	return &peer{
		protocolVersion: wire.ProtocolVersion,
		network:         network,
		address:         address,
	}, nil
}

func (p *peer) connect(ctx context.Context) error {
	p.mtx.Lock()
	if p.conn != nil {
		p.mtx.Unlock()
		return fmt.Errorf("already open")
	}
	p.mtx.Unlock()
	// XXX this races

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", p.address)
	if err != nil {
		return err
	}
	p.mtx.Lock()
	p.conn = conn
	p.mtx.Unlock()

	return nil
}

func (p *peer) close() error {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.conn != nil {
		defer func() { p.conn = nil }()
		return p.conn.Close()
	}
	return fmt.Errorf("already closed")
}

func (p *peer) write(msg wire.Message) error {
	_, err := wire.WriteMessageWithEncodingN(p.conn, msg, p.protocolVersion,
		p.network, wire.LatestEncoding)
	return err
}

func (p *peer) read() (wire.Message, error) {
	_, msg, _, err := wire.ReadMessageWithEncodingN(p.conn, p.protocolVersion,
		p.network, wire.LatestEncoding)
	return msg, err
}

func (p *peer) handshake(ctx context.Context) error {
	// 1. send our version
	// 2. receive version
	// 3. send sendaddrv2
	// 4. send verack
	// 5. receive sendaddrv2, verack or ignore

	us := &wire.NetAddress{Timestamp: time.Now()}
	them := &wire.NetAddress{Timestamp: time.Now()}
	msg := wire.NewMsgVersion(us, them, uint64(rand.Int63()), 0)
	err := p.write(msg)
	if err != nil {
		return fmt.Errorf("could not write version message: %v", err)
	}

	// 2. receive version
	rmsg, err := p.read()
	if err != nil {
		return fmt.Errorf("could not read version message: %v", err)
	}
	v, ok := rmsg.(*wire.MsgVersion)
	if !ok {
		return fmt.Errorf("expected version message")
	}
	p.remoteVersion = v

	// 3. send sendaddrv2
	if v.ProtocolVersion >= 70016 {
		err = p.write(wire.NewMsgSendAddrV2())
		if err != nil {
			return fmt.Errorf("could not send sendaddrv2: %v", err)
		}
	}

	// 4. send verack
	err = p.write(wire.NewMsgVerAck())
	if err != nil {
		return fmt.Errorf("could not send verack: %v", err)
	}

	for count := 0; count < 3; count++ {
		msg, err := p.read()
		if err == wire.ErrUnknownMessage {
			continue
		} else if err != nil {
			return err
		}

		switch msg.(type) {
		case *wire.MsgVerAck:
			return nil
		case *wire.MsgSendAddrV2:
			p.addrV2 = true
			continue
		default:
			return fmt.Errorf("unexpected message type: %T", msg)
		}
	}

	return fmt.Errorf("handshake failed")
}

func handlePing(p *peer, msg *wire.MsgPing) {
	fmt.Printf("ping %v\n", msg.Nonce)
	pong := wire.NewMsgPong(msg.Nonce)
	err := p.write(pong)
	if err != nil {
		fmt.Printf("could not write pong message: %v", err)
		return
	}
	fmt.Printf("wrote pong %v\n", pong.Nonce)
}

func downloadBlock(p *peer, height int, hash chainhash.Hash) error {
	fmt.Printf("get block at %v: %v\n", height, hash)

	getData := wire.NewMsgGetData()
	getData.InvList = append(getData.InvList,
		&wire.InvVect{
			Type: wire.InvTypeBlock,
			Hash: hash,
		})
	err := p.write(getData)
	if err != nil {
		return fmt.Errorf("could not write get block message: %v", err)
	}
	fmt.Printf("wrote get block %v\n", hash)

	return nil
}

func handleInv(p *peer, msg *wire.MsgInv) {
	fmt.Printf("inv: %v\n", len(msg.InvList))

	for k := range msg.InvList {
		switch msg.InvList[k].Type {
		case wire.InvTypeBlock:
			fmt.Printf("height %v hash %v\n", k+1, msg.InvList[k].Hash)
			err := downloadBlock(p, k+1, msg.InvList[k].Hash)
			if err != nil {
				fmt.Printf("download block at %v: %v\n", k+1, err)
			}
		default:
			fmt.Printf("skipping inv type: %v\n", msg.InvList[k].Type)
		}
	}
}

func handleBlock(p *peer, msg *wire.MsgBlock) {
	fmt.Printf("handle block: %v txs %v\n", msg.Header.BlockHash(),
		len(msg.Transactions))
}

func btcConnect(ctx context.Context, btcNet string) error {
	//ips, err := net.LookupIP("seed.bitcoin.sipa.be")
	//if err != nil {
	//	return err
	//}

	mainnetPort := "8333"
	testnetPort := "18333"
	var (
		port        string
		wireNet     wire.BitcoinNet
		chainParams *chaincfg.Params
	)
	switch btcNet {
	case "mainnet":
		port = mainnetPort
		wireNet = wire.MainNet
		chainParams = &chaincfg.MainNetParams
	case "testnet", "testnet3":
		port = testnetPort
		wireNet = wire.TestNet3
		chainParams = &chaincfg.TestNet3Params
	default:
		return fmt.Errorf("invalid network: %v", btcNet)
	}

	p, err := NewPeer(wireNet, "140.238.169.133"+port)
	if err != nil {
		return fmt.Errorf("new peer: %v", err)
	}

	err = p.connect(ctx)
	if err != nil {
		return fmt.Errorf("connect: %v", err)
	}

	err = p.handshake(ctx)
	if err != nil {
		return fmt.Errorf("connect: %v", err)
	}

	fmt.Printf("handshake complete with: %v\n", p.address)

	// send ibd start using get blocks
	fmt.Printf("genesis hash: %v\n", chainParams.GenesisHash)
	getBlocks := wire.NewMsgGetBlocks(chainParams.GenesisHash)
	err = p.write(getBlocks)
	if err != nil {
		fmt.Printf("could not write getBlocks  message: %v", err)
	}

	verbose := false
	for {
		// see if we were interrupted
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := p.read()
		if err == wire.ErrUnknownMessage {
			// skip unknown
			continue
		} else if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		if verbose {
			spew.Dump(msg)
		}

		switch m := msg.(type) {
		case *wire.MsgPing:
			go handlePing(p, m)

		case *wire.MsgInv:
			go handleInv(p, m)

		case *wire.MsgBlock:
			go handleBlock(p, m)

		default:
			fmt.Printf("unhandled message type: %T\n", msg)
		}
	}

	//fmt.Printf("waiting for exit\n")
	//<-ctx.Done()
	//return nil

	//peers := make(map[string]*peer, len(ips))
	//ips = []net.IP{
	//	net.ParseIP("140.238.169.133"),
	//	// net.ParseIP("84.250.91.34"),
	//	// net.ParseIP("3.14.15.90"),
	//	// net.ParseIP("104.182.210.230"),
	//}
	//for _, ip := range ips {
	//	address := ip.To4()
	//	if address == nil {
	//		continue
	//	}
	//	// XXX this does not test for link local and other exclusions

	//	// Should be an IPv4 address here
	//	ma := fmt.Sprintf("%v:%v", address, port)
	//	p := &peer{address: ma}
	//	peers[ma] = p

	//	// connect
	//	go func(pp *peer) {
	//		err := pp.connect(ctx)
	//		if err != nil {
	//			fmt.Printf("err: %v\n", err)
	//		} else {
	//			fmt.Printf("connected: %v\n", pp.address)

	//			pver := wire.ProtocolVersion

	//			// write ver
	//			me := &wire.NetAddress{
	//				Timestamp: time.Now(),
	//				Services:  wire.SFNodeNetwork,
	//				// IP: net.ParseIP("193.218.159.178"),
	//				// Port:      18333,

	//			}
	//			// spew.Dump(pp.conn.LocalAddr())
	//			// theirIP := pp.conn.RemoteAddr().String()
	//			you := &wire.NetAddress{
	//				Timestamp: time.Now(),
	//				// IP:        ips[0],
	//				// Port:      18333,
	//				// Services:  wire.SFNodeNetwork,
	//			}
	//			// spew.Dump(me)
	//			// spew.Dump(theirIP)
	//			wmsg := wire.NewMsgVersion(me, you, uint64(rand.Int63()), 0)
	//			wmsg.Services = wire.SFNodeNetwork
	//			wmsg.DisableRelayTx = true
	//			spew.Dump(wmsg)
	//			n, err := wire.WriteMessageWithEncodingN(pp.conn, wmsg, pver, wireNet, wire.LatestEncoding)
	//			if err != nil {
	//				fmt.Printf("write error: %v\n", err)
	//				return
	//			}
	//			fmt.Printf("write n NewMsgVersion: %v\n", n)

	//			n, rmsg, rawPayload, err := wire.ReadMessageWithEncodingN(pp.conn, pver, wireNet, wire.LatestEncoding)
	//			fmt.Printf("read n %T: %v\n", rmsg, n)
	//			if err != nil {
	//				fmt.Printf("read error: %v\n", err)
	//				return

	//			}
	//			_ = rawPayload
	//			fmt.Printf("%v\n", spew.Sdump(rmsg))
	//			// fmt.Printf("%v\n", spew.Sdump(rawPayload))
	//			v := rmsg.(*wire.MsgVersion)
	//			if v.ProtocolVersion >= 70016 {
	//				fmt.Printf("sendaddrv2\n")
	//				sendAddrMsg := wire.NewMsgSendAddrV2()
	//				n, err := wire.WriteMessageWithEncodingN(pp.conn, sendAddrMsg, pver, wireNet, wire.LatestEncoding)
	//				if err != nil {
	//					fmt.Printf("write error: %v\n", err)
	//					return
	//				}
	//				fmt.Printf("write n MsgSendAddrV2: %v\n", n)
	//			}

	//			// send verack
	//			verack := wire.NewMsgVerAck()
	//			n, err = wire.WriteMessageWithEncodingN(pp.conn, verack, pver, wireNet, wire.LatestEncoding)
	//			if err != nil {
	//				fmt.Printf("write error: %v\n", err)
	//				return
	//			}
	//			fmt.Printf("write n MsgVerAck: %v\n", n)

	//			for {
	//				// read what comes back
	//				n, rmsg, rawPayload, err = wire.ReadMessageWithEncodingN(pp.conn, pver, wireNet, wire.LatestEncoding)
	//				fmt.Printf("read n %T: %v\n", rmsg, n)
	//				if err != nil {
	//					fmt.Printf("read error continue: %v\n", err)
	//					// XXX exit if eof
	//					continue

	//				}
	//				_ = rawPayload
	//				fmt.Printf("%v\n", spew.Sdump(rmsg))
	//			}
	//		}
	//	}(p)
	//}

	//<-ctx.Done()

	// return nil
}

func StoreBlockHeaders(ctx context.Context, endHeight, blockCount int, dir string) error {
	for h := 0; h < blockCount; h++ {
		height := endHeight - blockCount + h + 1
		hash, err := btctool.GetAndStoreBlockHeader(ctx, height, dir)
		if err != nil {
			return err
		}
		fmt.Printf("%v: %v\n", height, hash)
	}
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

func init() {
}

func _main() error {
	flag.Usage = func() {
		f := flag.CommandLine.Output()
		fmt.Fprintf(f, "Usage of %v <action>\n", os.Args[0])
		fmt.Fprintf(f, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(f, "Actions:\n")
		fmt.Fprintf(f, "  block <hash=hash> [json=bool]             - retrieve block for hash\n")
		fmt.Fprintf(f, "  blockheader <hash=string>                 - retrieve blockheader for hash\n")
		fmt.Fprintf(f, "  blockheighthash <heigh=int>               - block hash at height\n")
		fmt.Fprintf(f, "  storeblockheaders [start=int] [count=int] - store block headers\n")
		fmt.Fprintf(f, "  tip                                       - retrieve tip height\n")
	}

	//var (
	//	endHeight, blockCount int
	//	downloadDir             string
	//)
	//flag.IntVar(&endHeight, "startblock", -1, "Height to start downloading, negative means start at current max height")
	//flag.IntVar(&blockCount, "count", -1024, "number of blocks to download, negative goes backwards from height")
	//flag.StringVar(&downloadDir, "downloaddir", "", "Directory to download block header and data to. Leave empty to dump to stdout.")
	flag.Parse()

	err := loggo.ConfigureLoggers("info") // XXX make flag
	if err != nil {
		return fmt.Errorf("ConfigureLoggers: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel

	action, args, err := parseArgs(flag.Args())
	if err != nil {
		return err
	}

	switch action {
	case "block":
		raw := true
		jsonSet := args["json"]
		// When set we'll try to catch up to tip
		if jsonSet == "1" || strings.ToLower(jsonSet) == "true" {
			raw = false
		}
		hash := args["hash"]
		if hash == "" {
			return fmt.Errorf("hash: must be set")
		}
		var b string
		b, err = blockstream.Block(ctx, hash, raw)
		if err == nil {
			fmt.Printf("%v\n", b)
		}
	case "blockheader":
		hash := args["hash"]
		if hash == "" {
			return fmt.Errorf("hash: must be set")
		}
		var bh string
		bh, err = blockstream.BlockHeader(ctx, hash)
		if err == nil {
			fmt.Printf("%v\n", bh)
		}
	case "blockheighthash":
		height := args["height"]
		if height == "" {
			return fmt.Errorf("height: must be set")
		}
		var bh string
		bh, err = blockstream.BlockHeightHash(ctx, height)
		if err == nil {
			fmt.Printf("%v\n", bh)
		}
	case "tip":
		var height int
		height, err = blockstream.Tip(ctx)
		if err == nil {
			fmt.Printf("%v\n", height)
		}

	case "p2p":
		err = btcConnect(ctx, "testnet3")

	case "parseblock":
		filename := args["filename"]
		if filename == "" {
			return fmt.Errorf("filename: must be set")
		}
		var block *btcutil.Block
		block, err = parseBlock(ctx, filename)
		if err == nil {
			spew.Dump(block)
		}

	case "storeblockheaders":
		// XXX remove + kill bfd
		downloadDir := filepath.Join("~/.mocksicle", bdf.DefaultDataDir)
		downloadDir, err = homedir.Expand(downloadDir)
		if err != nil {
			return fmt.Errorf("invalid directory: %v", err)
		}

		err = os.MkdirAll(downloadDir, 0o700)
		if err != nil {
			return fmt.Errorf("MkdirAll: %v", err)
		}

		blockCount := int(1024)
		count := args["count"]
		if count != "" {
			bc, err := strconv.ParseInt(count, 10, 64)
			if err != nil {
				return fmt.Errorf("count: %v", err)
			}
			if bc < 0 {
				return fmt.Errorf("count must not be negative: %v", bc)
			}
			blockCount = int(bc)
		}

		// Where do we end
		var endHeight int
		end := args["end"]
		if end == "" {
			endHeight, err = blockstream.Tip(ctx)
			if err != nil {
				return fmt.Errorf("tip: %v", err)
			}
		} else {
			e, err := strconv.ParseInt(end, 10, 64)
			if err != nil {
				return fmt.Errorf("end: %v", err)
			}
			if e < 0 {
				bh, err := blockstream.Tip(ctx)
				if err != nil {
					return fmt.Errorf("tip: %v", err)
				}
				e = int64(bh) + e
				if e < 0 {
					return fmt.Errorf("end height must not be "+
						"negative: %v", e)
				}
				fmt.Printf("tip at %v, downloading to %v\n", bh, e)
			}
			endHeight = int(e)
		}
		err = StoreBlockHeaders(ctx, endHeight, blockCount, downloadDir)
	default:
		return fmt.Errorf("invalid action: %v", os.Args[1])
	}

	return err
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	return
}
