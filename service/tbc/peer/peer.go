// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package peer

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/service/tbc/peer/rawpeer"
)

const (
	logLevel = "INFO"
)

var (
	log = loggo.GetLogger("peer")

	ErrInvalidType    = new(InvalidTypeError)
	ErrAlreadyPending = new(AlreadyPendingError)
	ErrUnknown        = new(UnknownError)

	defaultCmdTimeout = 5 * time.Second
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

// AlreadyPendingError is an error returned when a message is already pending
// and cannot be called more than once at a given time.
type AlreadyPendingError struct {
	id string
}

// Error returns the error string.
func (e *AlreadyPendingError) Error() string {
	return "already pending: " + e.id
}

// UnknownError is an error returned when the requested data cannot be found.
type UnknownError struct {
	typ    string
	hashes []*chainhash.Hash
}

// newUnknownError returns a new UnknownError.
func newUnknownError(typ string, hashes ...*chainhash.Hash) *UnknownError {
	return &UnknownError{
		typ:    typ,
		hashes: hashes,
	}
}

// Error returns the error string.
func (e *UnknownError) Error() string {
	var hashes string
	if len(e.hashes) > 0 {
		hashes = e.hashes[0].String()
		for _, h := range e.hashes[1:] {
			hashes += ", " + h.String()
		}
	}
	return fmt.Sprintf("unknown %s: %s", e.typ, hashes)
}

// InvalidTypeError is an error returned when a message was received and was not
// of the expected type.
type InvalidTypeError struct {
	actual   string
	expected []string
}

// newInvalidTypeError returns a new InvalidTypeError.
func newInvalidTypeError(msg any, expected ...string) error {
	return &InvalidTypeError{reflect.TypeOf(msg).String(), expected}
}

// Error returns the error string.
func (e *InvalidTypeError) Error() string {
	switch {
	case len(e.expected) == 0:
		return fmt.Sprintf("invalid type: %s", e.actual)
	case len(e.expected) == 1:
		return fmt.Sprintf("invalid type: %s, expected %s",
			e.actual, e.expected[0])
	default:
		return fmt.Sprintf("invalid type: %s, expected one of: %s",
			e.actual, strings.Join(e.expected, ", "))
	}
}

func tag(prefix string, suffix any) string {
	return fmt.Sprintf("%v_%v", prefix, suffix)
}

type Peer struct {
	mtx sync.Mutex

	wg          *sync.WaitGroup
	p           *rawpeer.RawPeer
	chainParams *chaincfg.Params

	feeFilterLast *wire.MsgFeeFilter // last seen fee filter message

	// pending commands awaiting results
	pending map[string]chan wire.Message // [tag]replyC

	// default events
	handlers map[string]func(context.Context, wire.Message) error
}

func (p *Peer) String() string {
	return p.p.String()
}

func (p *Peer) IsConnected() bool {
	log.Tracef("IsConnected")
	defer log.Tracef("IsConnected exit")

	return p.p.IsConnected()
}

func (p *Peer) HasService(f wire.ServiceFlag) bool {
	log.Tracef("HasService 0x%0x", f)
	defer log.Tracef("HasService exit 0x%0x", f)

	v, err := p.p.RemoteVersion()
	if err != nil {
		return false
	}
	return v.HasService(f)
}

func (p *Peer) dummyHandler(_ context.Context, msg wire.Message) error {
	log.Tracef("dummyHandler %v", msg.Command())
	defer log.Tracef("dummyHandler %v exit", msg.Command())

	log.Debugf("dummy handler: %v", msg.Command())

	return nil
}

func (p *Peer) onFeeFilterHandler(_ context.Context, msg wire.Message) error {
	log.Tracef("onFeeFilterHandler")
	defer log.Tracef("onFeeFilterHandler exit")

	if m, ok := msg.(*wire.MsgFeeFilter); ok {
		log.Debugf("fee filter: %v", m.MinFee)
		p.mtx.Lock()
		p.feeFilterLast = m
		p.mtx.Unlock()
		return nil
	}

	return newInvalidTypeError(msg, "*wire.MsgFeeFilter")
}

func (p *Peer) onPingHandler(_ context.Context, msg wire.Message) error {
	log.Tracef("onPingHandler")
	defer log.Tracef("onPingHandler exit")

	m, ok := msg.(*wire.MsgPing)
	if !ok {
		return newInvalidTypeError(msg, "*wire.MsgPing")
	}

	err := p.p.Write(defaultCmdTimeout, wire.NewMsgPong(m.Nonce))
	if err != nil {
		return fmt.Errorf("could not write pong message %v: %w", p.p, err)
	}
	log.Debugf("onPingHandler %v: pong %v", p.p, m.Nonce)

	return nil
}

func (p *Peer) onAddrHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onAddrHandler")
	defer log.Tracef("onAddrHandler exit")

	switch msg.(type) {
	case *wire.MsgAddr:
	case *wire.MsgAddrV2:
	default:
		return newInvalidTypeError(msg, "*wire.MsgAddr", "*wire.MsgAddrV2")
	}
	id := tag(wire.CmdGetAddr, 0)
	log.Debugf("onAddrHandler (%T): %v", msg, id)

	p.mtx.Lock()
	defer p.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.pending[id] <- msg:
	default:
		return fmt.Errorf("no reader addr: %v", id)
	}

	return nil
}

func (p *Peer) onPongHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onPongHandler")
	defer log.Tracef("onPongHandler exit")

	m, ok := msg.(*wire.MsgPong)
	if !ok {
		return newInvalidTypeError(msg, "*wire.MsgPong")
	}
	id := tag(msg.Command(), m.Nonce)
	log.Debugf("onPongHandler: %v", id)

	p.mtx.Lock()
	defer p.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.pending[id] <- m:
	default:
		return fmt.Errorf("no reader pong: %v", m.Nonce)
	}

	return nil
}

func (p *Peer) onBlockHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onBlockHandler")
	defer log.Tracef("onBlockHandler exit")

	m, ok := msg.(*wire.MsgBlock)
	if !ok {
		return newInvalidTypeError(msg, "*wire.MsgBlock")
	}
	id := tag(wire.CmdInv+"-"+wire.InvTypeBlock.String(), m.Header.BlockHash())
	log.Debugf("onBlockHandler: %v", id)

	p.mtx.Lock()
	defer p.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.pending[id] <- m:
	default:
		return fmt.Errorf("no reader block: %v", m.Header.BlockHash())
	}

	return nil
}

func (p *Peer) onInvHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onInvHandler")
	defer log.Tracef("onInvHandler exit")

	m, ok := msg.(*wire.MsgInv)
	if !ok {
		return newInvalidTypeError(msg, "*wire.MsgInv")
	}

	// XXX this is no longer correct but will flow through here when
	// unsolicited inv comes through.

	p.mtx.Lock()
	defer p.mtx.Unlock()
	// See if we have a mempool command pending and if we received a bunch of TX'
	id := tag(wire.CmdMemPool, 0)
	if replyC, ok := p.pending[id]; ok {
		if len(m.InvList) > 1 {
			// Assume this was a mempool call
			select {
			case <-ctx.Done():
				return ctx.Err()
			case replyC <- m:
				return nil
			default:
				return fmt.Errorf("no reader mempool: %v", 0)
			}
		}
	}

	for _, v := range m.InvList {
		id := tag(wire.CmdInv+"-"+v.Type.String(), v.Hash)
		log.Tracef("onInvHandler: %v", id)
		replyC, ok := p.pending[id]
		if !ok {
			continue
		}
		log.Debugf("onInvHandler found: %v", id)

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

func (p *Peer) onNotFoundHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onNotFoundHandler")
	defer log.Tracef("onNotFoundHandler exit")

	m, ok := msg.(*wire.MsgNotFound)
	if !ok {
		return newInvalidTypeError(msg, "*wire.MsgNotFound")
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	for _, v := range m.InvList {
		id := tag(wire.CmdInv+"-"+v.Type.String(), v.Hash)
		log.Debugf("onInvHandler: %v", id)
		replyC, ok := p.pending[id]
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

func (p *Peer) onTxHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onTxHandler")
	defer log.Tracef("onTxHandler exit")

	m, ok := msg.(*wire.MsgTx)
	if !ok {
		return newInvalidTypeError(msg, "*wire.MsgTx")
	}
	id := tag(wire.CmdInv+"-"+wire.InvTypeTx.String(), m.TxHash())
	log.Debugf("onTxHandler: %v", id)

	p.mtx.Lock()
	defer p.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.pending[id] <- m:
	default:
		return fmt.Errorf("no reader tx: %v", m.TxHash())
	}

	return nil
}

func (p *Peer) onHeadersHandler(ctx context.Context, msg wire.Message) error {
	log.Tracef("onHeadersHandler")
	defer log.Tracef("onHeadersHandler exit")

	m, ok := msg.(*wire.MsgHeaders)
	if !ok {
		return newInvalidTypeError(msg, "*wire.MsgHeaders")
	}
	id := tag(msg.Command(), 0)
	log.Debugf("onHeadersHandler: %v", id)

	p.mtx.Lock()
	defer p.mtx.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.pending[id] <- m:
	default:
		return fmt.Errorf("no reader headers: %v", 0)
	}

	return nil
}

func (p *Peer) setPending(id string) (chan wire.Message, error) {
	log.Tracef("setPending %v", id)
	defer log.Tracef("setPending %v exit", id)

	p.mtx.Lock()
	defer p.mtx.Unlock()

	if _, ok := p.pending[id]; ok {
		return nil, &AlreadyPendingError{id: id}
	}
	replyC := make(chan wire.Message)
	p.pending[id] = replyC

	return replyC, nil
}

func (p *Peer) killPending(id string) {
	p.mtx.Lock()
	delete(p.pending, id)
	p.mtx.Unlock()
}

func (p *Peer) GetAddr(ctx context.Context) (any, error) {
	log.Tracef("GetAddr")
	defer log.Tracef("GetAddr exit")

	// Send message to peer and receive response
	id := tag(wire.CmdGetAddr, 0)
	msg, err := p.call(ctx, id, &wire.MsgGetAddr{})
	if err != nil {
		return nil, err
	}

	switch x := msg.(type) {
	case *wire.MsgGetAddr:
		return x, nil
	case *wire.MsgAddrV2:
		return x, nil
	default:
		return nil, newInvalidTypeError(msg,
			"*wire.MsgGetAddr", "*wire.MsgAddrV2")
	}
}

// GetBlocks is really a legacy call; debating if we should bring it back.
// func (p *Peer) GetBlocks(ctx context.Context, blockHash *chainhash.Hash) (*wire.MsgInv, error) {
// 	log.Tracef("GetBlock %v", blockHash)
// 	defer log.Tracef("GetBlocks %v exit", blockHash)
//
// 	// Prepare message
// 	gb := wire.NewMsgGetBlocks(&chainhash.Hash{})
// 	if err := gb.AddBlockLocatorHash(blockHash); err != nil {
// 		return nil, err
// 	}
//
// 	// Send message to peer and receive response
// 	id := tag(wire.CmdInv+"-"+wire.InvTypeBlock.String(), blockHash)
// 	actual, err := p.call(ctx, id, gb)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	if blocks, ok := actual.(*wire.MsgInv); ok {
// 		return blocks, nil
// 	}
// 	return nil, fmt.Errorf("invalid blocks type: %T", actual)
// }

func (p *Peer) FeeFilter() (*wire.MsgFeeFilter, error) {
	log.Tracef("FeeFilter")
	defer log.Tracef("FeeFilter exit")

	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.feeFilterLast == nil {
		return nil, fmt.Errorf("no fee filter received")
	}

	ff := *p.feeFilterLast
	return &ff, nil
}

func (p *Peer) GetData(ctx context.Context, vector *wire.InvVect) (any, error) {
	log.Tracef("GetData %v: %v", vector.Type, vector.Hash)
	defer log.Tracef("GetData %v: %v exit", vector.Type, vector.Hash)

	// Prepare message
	gd := wire.NewMsgGetData()
	if err := gd.AddInvVect(vector); err != nil {
		return nil, err
	}

	// Send message to peer and receive response
	id := tag(wire.CmdInv+"-"+vector.Type.String(), vector.Hash)
	msg, err := p.call(ctx, id, gd)
	if err != nil {
		return nil, err
	}

	switch x := msg.(type) {
	case *wire.MsgBlock:
		return x, nil
	case *wire.MsgTx:
		return x, nil
	case *wire.MsgNotFound:
		return x, nil
	default:
		return nil, newInvalidTypeError(msg,
			"*wire.MsgBlock", "*wire.MsgTx", "*wire.MsgNotFound")
	}
}

// GetBlock sends a getheaders(hash) call, then a getdata(hash) call to the peer
// and returns the block.
func (p *Peer) GetBlock(ctx context.Context, blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	log.Tracef("GetBlock %v", blockHash)
	defer log.Tracef("GetBlock %v exit", blockHash)

	// GetBlock is a compounded call. First it calls getheaders(hash)
	// followed by a getdata(hash).

	// Retrieve headers for the block.
	headers, err := p.GetHeaders(ctx, []*chainhash.Hash{blockHash}, nil)
	if err != nil {
		return nil, err
	}
	// XXX we should cache the blocks the peer advertises since then we can
	//  skip the getheaders call.
	if len(headers.Headers) == 0 {
		return nil, newUnknownError("block header", blockHash)
	}
	if !blockHash.IsEqual(&headers.Headers[0].PrevBlock) {
		return nil, newUnknownError("block header", blockHash)
	}

	// Retrieve block.
	blk, err := p.GetData(ctx, wire.NewInvVect(wire.InvTypeBlock, blockHash))
	if err != nil {
		return nil, err
	}

	if b, ok := blk.(*wire.MsgBlock); ok {
		return b, nil
	}
	return nil, newInvalidTypeError(blk, "*wire.MsgBlock")
}

// GetTx writes a tx message to the peer and returns the response.
func (p *Peer) GetTx(ctx context.Context, txID *chainhash.Hash) (*wire.MsgTx, error) {
	log.Tracef("GetTx %v", txID)
	defer log.Tracef("GetTx %v exit", txID)

	tx, err := p.GetData(ctx, wire.NewInvVect(wire.InvTypeTx, txID))
	if err != nil {
		return nil, err
	}
	switch t := tx.(type) {
	case *wire.MsgTx:
		return t, nil
	case *wire.MsgNotFound:
		return nil, newUnknownError("tx", txID)
	default:
		return nil, newInvalidTypeError(tx, "*wire.MsgTx", "*wire.MsgNotFound")
	}
}

// Ping writes a ping message to the peer and returns the pong.
func (p *Peer) Ping(ctx context.Context, nonce uint64) (*wire.MsgPong, error) {
	log.Tracef("Ping %v", nonce)
	defer log.Tracef("Ping %v exit", nonce)

	// Send message to peer and receive response
	id := tag(wire.CmdPong, nonce)
	msg, err := p.call(ctx, id, &wire.MsgPing{Nonce: nonce})
	if err != nil {
		return nil, err
	}

	if pong, ok := msg.(*wire.MsgPong); ok {
		return pong, nil
	}
	return nil, newInvalidTypeError(msg, "*wire.MsgPong")
}

// GetHeaders writes a getheaders message to the peer and returns the headers.
func (p *Peer) GetHeaders(ctx context.Context, hashes []*chainhash.Hash, stop *chainhash.Hash) (*wire.MsgHeaders, error) {
	log.Tracef("GetHeaders")
	defer log.Tracef("GetHeaders exit")

	if len(hashes) == 0 {
		return nil, errors.New("no hashes")
	}

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

	// Send message to peer and receive response
	id := tag(wire.CmdHeaders, 0)
	msg, err := p.call(ctx, id, gh)
	if err != nil {
		return nil, err
	}

	m, ok := msg.(*wire.MsgHeaders)
	if !ok {
		return nil, newInvalidTypeError(msg, "*wire.MsgHeaders")
	}
	// catch standard responses
	if len(m.Headers) == 0 {
		return m, nil // Peer caught up
	}
	// deal with genesis
	if p.chainParams.GenesisHash.IsEqual(&m.Headers[0].PrevBlock) {
		if m.Headers[0].PrevBlock.IsEqual(hashes[0]) {
			// Got genesis and asked for genesis.
			return m, nil
		}
		return nil, newUnknownError("block headers", hashes...)
	}

	return m, nil
}

// MemPool writes a mempool message to the peer and returns the inv response.
func (p *Peer) MemPool(ctx context.Context) (*wire.MsgInv, error) {
	log.Tracef("MemPool")
	defer log.Tracef("MemPool exit")

	// Send message to peer and receive response
	id := tag(wire.CmdMemPool, 0)
	msg, err := p.call(ctx, id, &wire.MsgMemPool{})
	if err != nil {
		return nil, err
	}

	if inv, ok := msg.(*wire.MsgInv); ok {
		return inv, nil
	}
	return nil, newInvalidTypeError(msg, "*wire.MsgInv")
}

func (p *Peer) Remote() (*wire.MsgVersion, error) {
	log.Tracef("Remote")
	defer log.Tracef("Remote exit")

	// raw peer returns a copy of the struct so just pass it on.
	return p.p.RemoteVersion()
}

// call writes a message to the peer and waits for a response.
func (p *Peer) call(ctx context.Context, id string, m wire.Message) (any, error) {
	c, err := p.setPending(id)
	if err != nil {
		return nil, err
	}
	defer close(c)
	defer p.killPending(id)

	// Get timeout from context
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	// Send message to peer
	if err = p.p.Write(timeout, m); err != nil {
		return nil, err
	}

	// Wait for reply
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-c:
		return msg, nil
	}
}

func (p *Peer) callback(msg wire.Message) func(context.Context, wire.Message) error {
	log.Tracef("callback %v", msg.Command())
	defer log.Tracef("callback %v exit", msg.Command())

	p.mtx.Lock()
	cb := p.handlers[msg.Command()]
	p.mtx.Unlock()
	if cb == nil {
		cb = p.dummyHandler
	}
	return cb
}

func (p *Peer) readLoop(ctx context.Context) {
	log.Tracef("readLoop")
	defer log.Tracef("readLoop exit")

	defer p.wg.Done()

	for {
		msg, raw, err := p.p.Read(0)
		if errors.Is(err, wire.ErrUnknownMessage) {
			continue
		} else if err != nil {
			log.Debugf("%v: %v", p.p, err)
			return
		}
		_ = raw

		// See if we were interrupted
		select {
		case <-ctx.Done():
			return
		default:
		}

		cb := p.callback(msg)
		if err := cb(ctx, msg); err != nil {
			log.Errorf("%v: %v", msg.Command(), err)
		}
	}
}

func (p *Peer) Connect(ctx context.Context) error {
	log.Tracef("Connect")
	defer log.Tracef("Connect exit")

	err := p.p.Connect(ctx)
	if err != nil {
		return err
	}

	p.wg.Add(1)
	go p.readLoop(ctx)

	return nil
}

func (p *Peer) Close() error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	return p.p.Close()
}

func (p *Peer) setHandler(cmd string, f func(context.Context, wire.Message) error) {
	log.Tracef("setHandler %v", cmd)
	defer log.Tracef("setHandler %v exit", cmd)

	p.mtx.Lock()
	if f == nil {
		delete(p.handlers, cmd)
	} else {
		p.handlers[cmd] = f
	}
	p.mtx.Unlock()
}

func New(network wire.BitcoinNet, id int, address string) (*Peer, error) {
	p, err := rawpeer.New(network, id, address)
	if err != nil {
		return nil, err
	}
	cp := &Peer{
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
	case wire.TestNet4:
		cp.chainParams = &chaincfg.TestNet4Params
	case wire.TestNet:
		cp.chainParams = &chaincfg.RegressionNetParams
	default:
		return nil, fmt.Errorf("unsupported network: %v", network)
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
