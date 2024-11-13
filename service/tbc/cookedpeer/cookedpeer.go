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

	ErrPending = errors.New("pending")
	ErrUnknown = errors.New("unknown")
)

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type CookedPeer struct {
	mtx sync.Mutex

	wg          *sync.WaitGroup
	p           *peer.Peer
	chainParams *chaincfg.Params

	getHeadersPending func(context.Context, *wire.MsgHeaders) // only one pending get headers allowed
}

type CookedMessage struct {
	ctx   context.Context
	reply chan wire.Message
	msg   wire.Message
}

func (c *CookedPeer) GetHeaders(pctx context.Context, timeout time.Duration, hashes []*chainhash.Hash, stop *chainhash.Hash) (*wire.MsgHeaders, error) {
	log.Infof("GetHeaders")
	defer log.Infof("GetHeaders exit")

	if len(hashes) == 0 {
		return nil, errors.New("no hashes")
	}

	// Setup call back
	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	replyC := make(chan wire.Message)
	defer close(replyC)

	hp := func(ctx context.Context, msg *wire.MsgHeaders) {
		select {
		case <-ctx.Done():
			return
		case replyC <- msg:
		}
	}

	// Set callback if it doesnt exist
	c.mtx.Lock()
	if c.getHeadersPending != nil {
		c.mtx.Unlock()
		return nil, ErrPending
	}
	c.getHeadersPending = hp
	c.mtx.Unlock()

	defer func() {
		c.mtx.Lock()
		c.getHeadersPending = nil
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

	// Send message to peer
	err := c.p.Write(timeout, gh)
	if err != nil {
		return nil, err
	}

	// Read response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-replyC:
		m, ok := msg.(*wire.MsgHeaders)
		if !ok {
			return nil, fmt.Errorf("get headers protocol error: %T", msg)
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

func (c *CookedPeer) handleQueues(ctx context.Context) {
	log.Infof("handleQueues")
	defer log.Infof("handleQueues exit")

	defer c.wg.Done()

	for {
		msg, raw, err := c.p.Read(0)
		log.Infof("read %v", err)
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

		// handle
		switch m := msg.(type) {
		case *wire.MsgHeaders:
			c.mtx.Lock()
			c.getHeadersPending(ctx, m)
			c.mtx.Unlock()
		default:
			log.Errorf("unhandled message: %T", msg)
		}
	}
}

func (c *CookedPeer) Connect(ctx context.Context) error {
	log.Infof("Connect")
	defer log.Infof("Connect exit")

	err := c.p.Connect(ctx)
	if err != nil {
		return err
	}

	c.wg.Add(1)
	go c.handleQueues(ctx)

	return nil
}

func New(network wire.BitcoinNet, id int, address string) (*CookedPeer, error) {
	p, err := peer.New(network, id, address)
	if err != nil {
		return nil, err
	}
	cp := &CookedPeer{
		wg: new(sync.WaitGroup),
		p:  p,
	}
	switch network {
	case wire.TestNet3:
		cp.chainParams = &chaincfg.TestNet3Params
	}
	return cp, nil
}
