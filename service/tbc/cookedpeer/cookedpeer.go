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
	logLevel = "INFO"
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

func tag(prefix string, suffix any) string {
	return fmt.Sprintf("%v_%v", prefix, suffix)
}

type CookedPeer struct {
	mtx sync.Mutex

	wg          *sync.WaitGroup
	p           *peer.Peer
	chainParams *chaincfg.Params

	feeFilterLast *wire.MsgFeeFilter // last seen fee filter message

	// pending commands awaiting results
	pending map[string]chan wire.Message // [tag]replyC

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

func (c *CookedPeer) onAddrHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onAddrHandler")
	defer log.Tracef("onAddrHandler exit")

	switch msg.(type) {
	case *wire.MsgAddr:
	case *wire.MsgAddrV2:
	default:
		return ErrInvalidType
	}
	id := tag(wire.CmdGetAddr, 0)
	log.Debugf("onAddrHandler (%T): %v", msg, id)

	c.mtx.Lock()
	defer c.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.pending[id] <- msg:
	default:
		return fmt.Errorf("no reader addr: %v", id)
	}

	return nil
}

func (c *CookedPeer) onPongHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onPongHandler")
	defer log.Tracef("onPongHandler exit")

	m, ok := msg.(*wire.MsgPong)
	if !ok {
		return ErrInvalidType
	}
	id := tag(msg.Command(), m.Nonce)
	log.Debugf("onPongHandler: %v", id)

	c.mtx.Lock()
	defer c.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.pending[id] <- m:
	default:
		return fmt.Errorf("no reader pong: %v", m.Nonce)
	}

	return nil
}

func (c *CookedPeer) onBlockHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onBlockHandler")
	defer log.Tracef("onBlockHandler exit")

	m, ok := msg.(*wire.MsgBlock)
	if !ok {
		return ErrInvalidType
	}
	id := tag(wire.CmdInv+"-"+wire.InvTypeBlock.String(), m.Header.BlockHash())
	log.Debugf("onBlockHandler: %v", id)

	c.mtx.Lock()
	defer c.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.pending[id] <- m:
	default:
		return fmt.Errorf("no reader block: %v", m.Header.BlockHash())
	}

	return nil
}

func (c *CookedPeer) onInvHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onInvHandler")
	defer log.Tracef("onInvHandler exit")

	m, ok := msg.(*wire.MsgInv)
	if !ok {
		return ErrInvalidType
	}

	// XXX this is no longer correct but will flow through here when
	// unsolicited inv comes through.

	c.mtx.Lock()
	defer c.mtx.Unlock()
	for _, v := range m.InvList {
		id := tag(wire.CmdInv+"-"+v.Type.String(), v.Hash)
		log.Debugf("onInvHandler: %v", id)
		replyC, ok := c.pending[id]
		if !ok {
			continue
		}
		log.Debugf("onInvHandler: %v", id)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case replyC <- m:
			return nil
		default:
			return fmt.Errorf("no reader inv: %v", 0)
		}
	}

	return nil
}

func (c *CookedPeer) onNotFoundHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onNotFoundHandler")
	defer log.Tracef("onNotFoundHandler exit")

	m, ok := msg.(*wire.MsgNotFound)
	if !ok {
		return ErrInvalidType
	}

	// XXX this is no longer correct but will flow through here when
	// unsolicited inv comes through.

	c.mtx.Lock()
	defer c.mtx.Unlock()
	for _, v := range m.InvList {
		id := tag(wire.CmdInv+"-"+v.Type.String(), v.Hash)
		log.Debugf("onInvHandler: %v", id)
		replyC, ok := c.pending[id]
		if !ok {
			continue
		}
		log.Debugf("onInvHandler: %v", id)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case replyC <- m:
			return nil
		default:
			return fmt.Errorf("no reader inv: %v", 0)
		}
	}

	return nil
}

func (c *CookedPeer) onTxHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onTxHandler")
	defer log.Tracef("onTxHandler exit")

	m, ok := msg.(*wire.MsgTx)
	if !ok {
		return ErrInvalidType
	}
	id := tag(wire.CmdInv+"-"+wire.InvTypeTx.String(), m.TxHash())
	log.Debugf("onTxHandler: %v", id)

	c.mtx.Lock()
	defer c.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.pending[id] <- m:
	default:
		return fmt.Errorf("no reader tx: %v", m.TxHash())
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
	id := tag(msg.Command(), 0)
	log.Debugf("onHeadersHandler: %v", id)

	c.mtx.Lock()
	defer c.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.pending[id] <- m:
	default:
		return fmt.Errorf("no reader headers: %v", 0)
	}

	return nil
}

func (c *CookedPeer) setPending(id string) (chan wire.Message, error) {
	log.Tracef("setPending %v", id)
	defer log.Tracef("setPending %v exit", id)

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if _, ok := c.pending[id]; ok {
		return nil, fmt.Errorf("pending: %v", id)
	}
	replyC := make(chan wire.Message)
	c.pending[id] = replyC

	return replyC, nil
}

func (c *CookedPeer) killPending(id string) {
	c.mtx.Lock()
	delete(c.pending, id)
	c.mtx.Unlock()
}

func (c *CookedPeer) GetAddr(pctx context.Context, timeout time.Duration) (any, error) {
	log.Tracef("GetAddr")
	defer log.Tracef("GetAddr exit")

	// Setup call back, we have to do this here or inside the mutex.
	id := tag(wire.CmdGetAddr, 0)
	getAddrC, err := c.setPending(id)
	if err != nil {
		return nil, err
	}
	defer close(getAddrC)
	defer c.killPending(id)

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	// Send message to peer
	err = c.p.Write(timeout, &wire.MsgGetAddr{})
	if err != nil {
		return nil, err
	}

	// Wait for reply
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-getAddrC:
		if addrV2, ok := msg.(*wire.MsgAddrV2); ok {
			return addrV2, nil
		}
		if addr, ok := msg.(*wire.MsgAddr); ok {
			return addr, nil
		}
		return nil, fmt.Errorf("invalid addr type: %T", msg)
	}
}

// GetBlocks is really a legacy call; debating if we should bring it back.
//func (c *CookedPeer) GetBlocks(pctx context.Context, timeout time.Duration, blockHash *chainhash.Hash) (*wire.MsgInv, error) {
//	log.Tracef("GetBlock %v", blockHash)
//	defer log.Tracef("GetBlocks %v exit", blockHash)
//
//	// Setup call back, we have to do this here or inside the mutex.
//	id := tag(wire.CmdInv+"-"+wire.InvTypeBlock.String(), blockHash)
//	getBlocksC, err := c.setPending(id)
//	log.Infof("GetBlocks: %v", id)
//	if err != nil {
//		return nil, err
//	}
//	defer close(getBlocksC)
//	defer c.killPending(id)
//
//	ctx, cancel := context.WithTimeout(pctx, timeout)
//	defer cancel()
//
//	// Send message to peer
//	gb := wire.NewMsgGetBlocks(&chainhash.Hash{})
//	if err := gb.AddBlockLocatorHash(blockHash); err != nil {
//		return nil, err
//	}
//	err = c.p.Write(timeout, gb)
//	if err != nil {
//		return nil, err
//	}
//
//	// Wait for reply
//	select {
//	case <-ctx.Done():
//		return nil, ctx.Err()
//	case msg := <-getBlocksC:
//		if blocks, ok := msg.(*wire.MsgInv); ok {
//			return blocks, nil
//		}
//		return nil, fmt.Errorf("invalid blocks type: %T", msg)
//	}
//}

func (c *CookedPeer) GetData(pctx context.Context, timeout time.Duration, vector *wire.InvVect) (any, error) {
	log.Tracef("GetData %v: %v", vector.Type, vector.Hash)
	defer log.Tracef("GetData %v: %v exit", vector.Type, vector.Hash)

	// Setup call back, we have to do this here or inside the mutex.
	id := tag(wire.CmdInv+"-"+vector.Type.String(), vector.Hash)
	getDataC, err := c.setPending(id)
	if err != nil {
		return nil, err
	}
	defer close(getDataC)
	defer c.killPending(id)

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	// Send message to peer
	gd := wire.NewMsgGetData()
	if err := gd.AddInvVect(vector); err != nil {
		return nil, err
	}
	err = c.p.Write(timeout, gd)
	if err != nil {
		return nil, err
	}

	// Wait for reply
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-getDataC:
		switch x := msg.(type) {
		case *wire.MsgBlock:
			return x, nil
		case *wire.MsgTx:
			return x, nil
		case *wire.MsgNotFound:
			return x, nil
		}
		return nil, fmt.Errorf("invalid get data type: %T", msg)
	}
}

func (c *CookedPeer) GetBlock(pctx context.Context, timeout time.Duration, blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	log.Tracef("GetBlock %v", blockHash)
	defer log.Tracef("GetBlock %v exit", blockHash)

	// GetBlock is a compounded call. First it calls getheaders(hash)
	// followed by a getdata(hash).

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()
	headers, err := c.GetHeaders(ctx, timeout, []*chainhash.Hash{blockHash}, nil)
	if err != nil {
		return nil, err
	}
	// XXX we should cash the blocks the peer advertises since then we can
	// skip the getheaders call.
	if len(headers.Headers) == 0 {
		return nil, ErrUnknown
	}
	if !blockHash.IsEqual(&headers.Headers[0].PrevBlock) {
		return nil, ErrUnknown
	}

	blk, err := c.GetData(ctx, timeout, wire.NewInvVect(wire.InvTypeBlock, blockHash))
	if err != nil {
		return nil, err
	}
	if b, ok := blk.(*wire.MsgBlock); ok {
		return b, nil
	}

	return nil, fmt.Errorf("invalid block type: %T", blk)
}

func (c *CookedPeer) GetTx(pctx context.Context, timeout time.Duration, txId *chainhash.Hash) (*wire.MsgTx, error) {
	log.Tracef("GetTx %v", txId)
	defer log.Tracef("GetTx %v exit", txId)

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	tx, err := c.GetData(ctx, timeout, wire.NewInvVect(wire.InvTypeTx, txId))
	if err != nil {
		return nil, err
	}
	switch t := tx.(type) {
	case *wire.MsgTx:
		return t, nil
	case *wire.MsgNotFound:
		return nil, ErrUnknown
	}

	return nil, fmt.Errorf("invalid tx type: %T", tx)
}

func (c *CookedPeer) Ping(pctx context.Context, timeout time.Duration, nonce uint64) (*wire.MsgPong, error) {
	log.Tracef("Ping %v", nonce)
	defer log.Tracef("Ping %v exit", nonce)

	// Setup call back, we have to do this here or inside the mutex.
	id := tag(wire.CmdPong, nonce)
	pongC, err := c.setPending(id)
	if err != nil {
		return nil, err
	}
	defer close(pongC)
	defer c.killPending(id)

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	// Send message to peer
	err = c.p.Write(timeout, &wire.MsgPing{Nonce: nonce})
	if err != nil {
		return nil, err
	}

	// Wait for reply
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-pongC:
		if pong, ok := msg.(*wire.MsgPong); ok {
			return pong, nil
		}
		return nil, fmt.Errorf("invalid pong type: %T", msg)
	}
}

func (c *CookedPeer) GetHeaders(pctx context.Context, timeout time.Duration, hashes []*chainhash.Hash, stop *chainhash.Hash) (*wire.MsgHeaders, error) {
	log.Tracef("GetHeaders")
	defer log.Tracef("GetHeaders exit")

	if len(hashes) == 0 {
		return nil, errors.New("no hashes")
	}

	// Record outstanding headers
	id := tag(wire.CmdHeaders, 0)
	headersC, err := c.setPending(id)
	if err != nil {
		return nil, err
	}
	defer close(headersC)
	defer c.killPending(id)

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

	// Setup call back, we have to do this here or inside the mutex.
	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	// Send get headers message to peer
	err = c.p.Write(timeout, gh)
	if err != nil {
		return nil, err
	}

	// Wait for reply
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-headersC:
		m, ok := msg.(*wire.MsgHeaders)
		if !ok {
			return nil, fmt.Errorf("invalid headers type: %T", msg)
		}
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

func (c *CookedPeer) setHandler(cmd string, f func(context.Context, wire.Message) error) {
	log.Tracef("setHandler %v", cmd)
	defer log.Tracef("setHandler %v exit", cmd)

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
		pending: make(map[string]chan wire.Message, 64),
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
	cp.setHandler(wire.CmdAddr, cp.onAddrHandler)
	cp.setHandler(wire.CmdAddrV2, cp.onAddrHandler)
	cp.setHandler(wire.CmdBlock, cp.onBlockHandler)
	cp.setHandler(wire.CmdInv, cp.onInvHandler)
	cp.setHandler(wire.CmdFeeFilter, cp.onFeeFilterHandler)
	cp.setHandler(wire.CmdHeaders, cp.onHeadersHandler)
	cp.setHandler(wire.CmdNotFound, cp.onNotFoundHandler)
	cp.setHandler(wire.CmdPing, cp.onPingHandler)
	cp.setHandler(wire.CmdPong, cp.onPongHandler)
	cp.setHandler(wire.CmdTx, cp.onTxHandler)

	return cp, nil
}
