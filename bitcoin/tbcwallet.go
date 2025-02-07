package bitcoin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/juju/loggo"
)

const (
	logLevel = "INFO"
)

var (
	log = loggo.GetLogger("tbcwallet")
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

type Config struct {
	// TBCWSURL specifies the URL of the TBC private websocket endpoint
	TBCWSURL string

	// BTCChainName specifies the name of the Bitcoin chain that
	// this PoP miner is operating on.
	BTCChainName string // XXX are we brave enough to rename this BTCNetwork?

	TBCRequestTimeout time.Duration

	LogLevel string

	PprofListenAddress string
}

const DefaultTBCRequestTimeout = 15 * time.Second

func NewDefaultConfig() *Config {
	return &Config{
		TBCWSURL:          "http://localhost:8082/v1/ws",
		TBCRequestTimeout: DefaultTBCRequestTimeout,
		BTCChainName:      "testnet3",
	}
}

// Wrap for calling tbc commands
type tbcCmd struct {
	msg any
	ch  chan any
}

type tbcNode struct {
	mtx sync.RWMutex
	wg  sync.WaitGroup

	cfg *Config

	holdoffTimeout time.Duration
	requestTimeout time.Duration

	tbcCmdCh     chan tbcCmd // commands to send to tbc
	tbcWg        sync.WaitGroup
	tbcConnected atomic.Bool

	isRunning bool
}

func (t *tbcNode) UtxosByAddress(ctx context.Context, addr btcutil.Address) ([]*tbcapi.UTXO, error) {

	maxUint64 := ^uint64(0)
	bur := &tbcapi.UTXOsByAddressRequest{
		Address: addr.String(),
		Start:   0,
		Count:   uint(maxUint64), //xxx hack
	}

	res, err := t.callTBC(ctx, t.requestTimeout, bur)
	if err != nil {
		return nil, err
	}

	buResp, ok := res.(*tbcapi.UTXOsByAddressResponse)
	if !ok {
		return nil, fmt.Errorf("not a buResp %T", res)
	}

	if buResp.Error != nil {
		return nil, buResp.Error
	}

	return buResp.UTXOs, nil

}

func TBCNodeNew(pctx context.Context, cfg *Config, autoStart bool) (Bitcoin, error) {
	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	if cfg.TBCRequestTimeout <= 0 {
		cfg.TBCRequestTimeout = DefaultTBCRequestTimeout
	}
	switch strings.ToLower(cfg.BTCChainName) {
	case "testnet", "testnet3", "mainnet":
	default:
		return nil, fmt.Errorf("unknown BTC chain name %q", cfg.BTCChainName)
	}

	tbcnode := &tbcNode{
		cfg:            cfg,
		tbcCmdCh:       make(chan tbcCmd, 10),
		holdoffTimeout: 5 * time.Second,
		requestTimeout: cfg.TBCRequestTimeout,
	}

	if autoStart {
		go func() {
			err := tbcnode.Run(pctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				panic(err)
			}
		}()
	}
	return tbcnode, nil
}

func (t *tbcNode) callTBC(pctx context.Context, timeout time.Duration, msg any) (any, error) {
	log.Tracef("callTBC %T", msg)
	defer log.Tracef("callTBC exit %T", msg)

	if !t.running() {
		return nil, errors.New("tbc node not running")
	}
	/* if !t.Connected() {
		return nil, errors.New("tbcNode not connected")
	} */

	bc := tbcCmd{
		msg: msg,
		ch:  make(chan any),
	}

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	// attempt to send
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case t.tbcCmdCh <- bc:
	default:
		return nil, errors.New("tbc command queue full")
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case payload := <-bc.ch:
		if err, ok := payload.(error); ok {
			return nil, err
		}
		return payload, nil
	}

	// Won't get here
}

func (t *tbcNode) handleTBCWebsocketRead(ctx context.Context, conn *protocol.Conn) error {
	defer t.tbcWg.Done()

	log.Tracef("handleTBCWebsocketRead")
	defer log.Tracef("handleTBCWebsocketRead exit")
	for {
		_, _, _, err := tbcapi.ReadConn(ctx, conn)
		if err != nil {

			// See if we were terminated
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(t.holdoffTimeout):
			}

			log.Infof("Connection with TBC server was lost, reconnecting...")
			continue
		}
	}
}

func (t *tbcNode) handleTBCCallCompletion(pctx context.Context, conn *protocol.Conn, bc tbcCmd) {

	log.Tracef("handleTBCCallCompletion")
	defer log.Tracef("handleTBCCallCompletion exit")

	ctx, cancel := context.WithTimeout(pctx, t.requestTimeout)
	defer cancel()

	log.Tracef("handleTBCCallCompletion: %v", spew.Sdump(bc.msg))

	_, _, payload, err := tbcapi.Call(ctx, conn, bc.msg)
	if err != nil {
		log.Errorf("handleTBCCallCompletion %T: %v", bc.msg, err)
		select {
		case bc.ch <- err:
		default:
		}
	}
	select {
	case bc.ch <- payload:
		log.Tracef("handleTBCCallCompletion returned: %v", spew.Sdump(payload))
	default:
	}

}

func (t *tbcNode) handleTBCWebsocketCallUnauth(ctx context.Context, conn *protocol.Conn) {
	defer t.tbcWg.Done()

	log.Tracef("handleTBCWebsocketCallUnauth")
	defer log.Tracef("handleTBCWebsocketCallUnauth exit")
	for {
		select {
		case <-ctx.Done():
			return
		case bc := <-t.tbcCmdCh:
			go t.handleTBCCallCompletion(ctx, conn, bc)
		}
	}
}

func (t *tbcNode) connectTBC(pctx context.Context) error {
	log.Tracef("connectTBC")
	defer log.Tracef("connectTBC exit")

	conn, err := protocol.NewConn(t.cfg.TBCWSURL, &protocol.ConnOptions{
		ReadLimit: 6 * (1 << 20), // 6 MiB
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	err = conn.Connect(ctx)
	if err != nil {
		return err
	}

	t.tbcWg.Add(1)
	go t.handleTBCWebsocketCallUnauth(ctx, conn)

	t.tbcWg.Add(1)
	t.handleTBCWebsocketRead(ctx, conn)

	log.Debugf("Connected to TBC: %s", t.cfg.TBCWSURL)
	t.tbcConnected.Store(true)

	// Wait for exit
	t.tbcWg.Wait()
	t.tbcConnected.Store(false)

	return nil
}

func (t *tbcNode) tbc(ctx context.Context) {
	defer t.wg.Done()

	log.Tracef("tbc")
	defer log.Tracef("tbc exit")

	for {
		if err := t.connectTBC(ctx); err != nil {
			// Do nothing
			log.Tracef("connectTBC: %v", err)
		} else {
			log.Infof("Connected to TBC: %s", t.cfg.TBCWSURL)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.After(t.holdoffTimeout):
		}

		log.Debugf("Reconnecting to: %v", t.cfg.TBCWSURL)
	}
}

func (t *tbcNode) Run(pctx context.Context) error {
	if !t.testAndSetRunning(true) {
		return errors.New("tbcwallet already running")
	}
	defer t.testAndSetRunning(false)

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	/* // pprof
	if t.cfg.PprofListenAddress != "" {
		p, err := pprof.NewServer(&pprof.Config{
			ListenAddress: t.cfg.PprofListenAddress,
		})
		if err != nil {
			return fmt.Errorf("create pprof server: %w", err)
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			if err := p.Run(ctx); !errors.Is(err, context.Canceled) {
				log.Errorf("pprof server terminated with error: %v", err)
				return
			}
			log.Infof("pprof server clean shutdown")
		}()
	} */

	log.Infof("Starting connection to TBC Node: %v",
		t.cfg.TBCWSURL)

	t.wg.Add(1)
	go t.tbc(ctx) // Attempt to talk to TBC

	<-ctx.Done()
	err := ctx.Err()

	log.Infof("Terminating connection to TBC Node: %v",
		t.cfg.TBCWSURL)

	t.wg.Wait()
	log.Infof("Connection to TBC Node cleanly")

	return err
}

func (t *tbcNode) running() bool {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	return t.isRunning
}

func (t *tbcNode) testAndSetRunning(b bool) bool {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	old := t.isRunning
	t.isRunning = b
	return old != t.isRunning
}

func (t *tbcNode) Connected() bool {
	return t.tbcConnected.Load()
}
