// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package cookedpeer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/service/tbc/peer"
)

const (
	logLevel = "DEBUG"
)

var (
	log = loggo.GetLogger("peer")

	ErrInvalidType = errors.New("invalid type")
	ErrPending     = errors.New("pending")
	ErrUnknown     = errors.New("unknown")

	defaultCmdTimeout = 5 * time.Second
)

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type CookedPeer struct {
	mtx sync.Mutex

	wg          *sync.WaitGroup
	p           *peer.Peer
	chainParams *chaincfg.Params

	feeFilterLast *wire.MsgFeeFilter // last seen fee filter message

	// pending commands awaiting results
	getHeaders map[uint64]chan *wire.MsgHeaders // [0]reply
	pings      map[uint64]chan *wire.MsgPong    // [nonce]reply

	// default events
	handlers map[string]func(context.Context, wire.Message) error
}

func (c *CookedPeer) dummyHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("dummyHandler %v", msg.Command())
	defer log.Tracef("dummyHandler %v exit", msg.Command())

	log.Debugf("dummy handler: %v", msg.Command())

	return nil
}

func (c *CookedPeer) onFeeFilterHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onFeeFilterHandler")
	defer log.Tracef("onFeeFilterHandler exit")

	if m, ok := msg.(*wire.MsgFeeFilter); ok {
		log.Debugf("fee filter: %v", m.MinFee)
		c.mtx.Lock()
		c.feeFilterLast = m
		c.mtx.Unlock()
		return nil
	}

	return ErrInvalidType
}

func (c *CookedPeer) onPingHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onPingHandler")
	defer log.Tracef("onPingHandler exit")

	m, ok := msg.(*wire.MsgPing)
	if !ok {
		return ErrInvalidType
	}

	err := c.p.Write(defaultCmdTimeout, wire.NewMsgPong(m.Nonce))
	if err != nil {
		return fmt.Errorf("could not write pong message %v: %w", c.p, err)
	}
	log.Debugf("onPingHandler %v: pong %v", c.p, m.Nonce)

	return nil
}

func (c *CookedPeer) onPongHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onPongHandler")
	defer log.Tracef("onPongHandler exit")

	m, ok := msg.(*wire.MsgPong)
	if !ok {
		return ErrInvalidType
	}
	log.Debugf("onPongHandler: nonce %v", m.Nonce)

	c.mtx.Lock()
	defer c.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.pings[m.Nonce] <- m:
	default:
		return fmt.Errorf("no reader pong: %v", m.Nonce)
	}

	return nil
}

func (c *CookedPeer) onHeadersHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onHeadersHandler")
	defer log.Tracef("onHeadersHandler exit")

	m, ok := msg.(*wire.MsgHeaders)
	if !ok {
		return ErrInvalidType
	}
	log.Debugf("onHeadersHandler: %v", 0)

	c.mtx.Lock()
	defer c.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.getHeaders[0] <- m:
	default:
		return fmt.Errorf("no reader headers: %v", 0)
	}

	return nil
}

func (c *CookedPeer) Ping(pctx context.Context, timeout time.Duration, nonce uint64) (*wire.MsgPong, error) {
	log.Tracef("Ping %v", nonce)
	defer log.Tracef("Ping %v exit", nonce)

	// Setup call back, we have to do this here or inside the mutex.
	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	pongC := make(chan *wire.MsgPong)
	defer close(pongC)

	// Record outstanding pings
	c.mtx.Lock()
	if _, ok := c.pings[nonce]; ok {
		c.mtx.Unlock()
		return nil, fmt.Errorf("pending nonce: %v", nonce)
	}
	c.pings[nonce] = pongC
	c.mtx.Unlock()
	defer func() {
		c.mtx.Lock()
		delete(c.pings, nonce)
		c.mtx.Unlock()
	}()

	// Send message to peer
	err := c.p.Write(timeout, &wire.MsgPing{Nonce: nonce})
	if err != nil {
		return nil, err
	}

	// Wait for reply
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case pong := <-pongC:
		return pong, nil
	}
}

func (c *CookedPeer) GetHeaders(pctx context.Context, timeout time.Duration, hashes []*chainhash.Hash, stop *chainhash.Hash) (*wire.MsgHeaders, error) {
	log.Tracef("GetHeaders")
	defer log.Tracef("GetHeaders exit")

	if len(hashes) == 0 {
		return nil, errors.New("no hashes")
	}

	// Setup call back, we have to do this here or inside the mutex.
	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	headersC := make(chan *wire.MsgHeaders)
	defer close(headersC)

	// Record outstanding headers
	c.mtx.Lock()
	if _, ok := c.getHeaders[0]; ok {
		c.mtx.Unlock()
		return nil, errors.New("pending headers")
	}
	c.getHeaders[0] = headersC
	c.mtx.Unlock()
	defer func() {
		c.mtx.Lock()
		delete(c.getHeaders, 0)
		c.mtx.Unlock()
	}()

	// Prepare message
	gh := wire.NewMsgGetHeaders()
	if stop != nil {
		gh.HashStop = *stop
	}
	for k := range hashes {
		err := gh.AddBlockLocatorHash(hashes[k])
		if err != nil {
			return nil, err
		}
	}

	// Send get headers message to peer
	err := c.p.Write(timeout, gh)
	if err != nil {
		return nil, err
	}

	// Wait for reply
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case m := <-headersC:
		// catch standard responses
		if len(m.Headers) == 0 {
			return m, nil // Peer caught up
		}
		// deal with genesis
		if c.chainParams.GenesisHash.IsEqual(&m.Headers[0].PrevBlock) {
			if m.Headers[0].PrevBlock.IsEqual(hashes[0]) {
				// Got genesis and asked for genesis.
				return m, nil
			}
			return nil, ErrUnknown
		}
		return m, nil
	}
}

func (c *CookedPeer) callback(msg wire.Message) func(context.Context, wire.Message) error {
	log.Tracef("callback %v", msg.Command())
	defer log.Tracef("callback %v exit", msg.Command())

	c.mtx.Lock()
	cb := c.handlers[msg.Command()]
	c.mtx.Unlock()
	if cb == nil {
		cb = c.dummyHandler
	}
	return cb
}

func (c *CookedPeer) readLoop(ctx context.Context) {
	log.Tracef("readLoop")
	defer log.Tracef("readLoop exit")

	defer c.wg.Done()

	for {
		msg, raw, err := c.p.Read(0)
		if errors.Is(err, wire.ErrUnknownMessage) {
			continue
		} else if err != nil {
			log.Errorf("%v: %v", c.p, err)
			return
		}
		_ = raw

		// See if we were interrupted
		select {
		case <-ctx.Done():
			return
		default:
		}

		cb := c.callback(msg)
		if err := cb(ctx, msg); err != nil {
			log.Errorf("%v: %v", msg.Command(), err)
		}
	}
}

func (c *CookedPeer) Connect(ctx context.Context) error {
	log.Tracef("Connect")
	defer log.Tracef("Connect exit")

	err := c.p.Connect(ctx)
	if err != nil {
		return err
	}

	c.wg.Add(1)
	go c.readLoop(ctx)

	return nil
}

func (c *CookedPeer) SetHandler(cmd string, f func(context.Context, wire.Message) error) {
	log.Tracef("SetHandler %v", cmd)
	defer log.Tracef("SetHandler %v exit", cmd)

	c.mtx.Lock()
	if f == nil {
		delete(c.handlers, cmd)
	} else {
		c.handlers[cmd] = f
	}
	c.mtx.Unlock()
}

func New(network wire.BitcoinNet, id int, address string) (*CookedPeer, error) {
	p, err := peer.New(network, id, address)
	if err != nil {
		return nil, err
	}
	cp := &CookedPeer{
		wg: new(sync.WaitGroup),
		p:  p,

		// Event handlers
		handlers: make(map[string]func(context.Context, wire.Message) error, 16),

		// Pending commands
		getHeaders: make(map[uint64]chan *wire.MsgHeaders, 1),
		pings:      make(map[uint64]chan *wire.MsgPong, 16),
	}

	switch network {
	case wire.MainNet:
		cp.chainParams = &chaincfg.MainNetParams
	case wire.TestNet3:
		cp.chainParams = &chaincfg.TestNet3Params
	case wire.TestNet:
		cp.chainParams = &chaincfg.RegressionNetParams
	default:
		return nil, fmt.Errorf("unsuported network: %v", network)
	}

	// Set default handlers
	cp.SetHandler(wire.CmdFeeFilter, cp.onFeeFilterHandler)
	cp.SetHandler(wire.CmdHeaders, cp.onHeadersHandler)
	cp.SetHandler(wire.CmdPong, cp.onPongHandler)
	cp.SetHandler(wire.CmdPong, cp.onPongHandler)

	return cp, nil
}
