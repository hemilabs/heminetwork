// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package tbcgozer provides an implementation of [gozer.Gozer] which receives
// Bitcoin data from a TBC server over RPC.
package tbcgozer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer"
)

const (
	logLevel = "tbcgozer=INFO"

	DefaultURL = "ws://localhost:8082/v1/ws"

	DefaultCommandQueueDepth = 10
)

var (
	log                   = loggo.GetLogger("tbcgozer")
	DefaultRequestTimeout = 5 * time.Second
)

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

// tbcCmd wraps tbc commands.
type tbcCmd struct {
	msg     any
	ch      chan any
	timeout time.Duration
}

// tbcGozer implements [gozer.Gozer] and retrieves Bitcoin data from a TBC
// server over RPC.
type tbcGozer struct {
	mtx       sync.Mutex
	wg        sync.WaitGroup
	url       string
	cmdCh     chan tbcCmd // commands to send to tbc
	connected bool
}

var _ gozer.Gozer = (*tbcGozer)(nil)

func New(tbcUrl string) gozer.Gozer {
	return &tbcGozer{
		url:   tbcUrl,
		cmdCh: make(chan tbcCmd, DefaultCommandQueueDepth),
	}
}

// Run returns and starts a new TBC Gozer.
func (t *tbcGozer) Run(ctx context.Context, connected func()) error {
	go t.run(ctx, connected)
	return nil
}

func (t *tbcGozer) Connected() bool {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	return t.connected
}

func (t *tbcGozer) BestHeightHashTime(ctx context.Context) (uint64, *chainhash.Hash, time.Time, error) {
	bur := &tbcapi.BlockHeaderBestRawRequest{}

	var ts time.Time
	res, err := t.callTBC(ctx, DefaultRequestTimeout, bur)
	if err != nil {
		return 0, nil, ts, err
	}

	buResp, ok := res.(*tbcapi.BlockHeaderBestRawResponse)
	if !ok {
		return 0, nil, ts, fmt.Errorf("not a blockheader best raw response %T",
			res)
	}
	if buResp.Error != nil {
		return 0, nil, ts, buResp.Error
	}

	bh := &wire.BlockHeader{}
	err = bh.Deserialize(bytes.NewReader(buResp.BlockHeader))
	if err != nil {
		return 0, nil, ts, err
	}
	blockHash := bh.BlockHash()

	return buResp.Height, &blockHash, bh.Timestamp, nil
}

func (t *tbcGozer) FeeEstimates(ctx context.Context) ([]*tbcapi.FeeEstimate, error) {
	bur := &tbcapi.FeeEstimateRequest{}

	res, err := t.callTBC(ctx, DefaultRequestTimeout, bur)
	if err != nil {
		return nil, err
	}

	buResp, ok := res.(*tbcapi.FeeEstimateResponse)
	if !ok {
		return nil, fmt.Errorf("not a fee estimate response %T", res)
	}

	if buResp.Error != nil {
		return nil, buResp.Error
	}

	return buResp.FeeEstimates, nil
}

func (t *tbcGozer) BroadcastTx(ctx context.Context, tx *wire.MsgTx) (*chainhash.Hash, error) {
	bur := &tbcapi.TxBroadcastRequest{
		Tx:    tx,
		Force: false, // XXX allow this to be passed in some way
	}

	res, err := t.callTBC(ctx, DefaultRequestTimeout, bur)
	if err != nil {
		return nil, err
	}

	buResp, ok := res.(*tbcapi.TxBroadcastResponse)
	if !ok {
		return nil, fmt.Errorf("not a broadcast response %T", res)
	}

	if buResp.Error != nil {
		return nil, buResp.Error
	}

	return buResp.TxID, nil
}

func (t *tbcGozer) UtxosByAddress(ctx context.Context, filterMempool bool, addr btcutil.Address, start, count uint) ([]*tbcapi.UTXO, error) {
	maxCount := uint(1000)
	if count > maxCount {
		return nil, fmt.Errorf("count must not exceed %v", maxCount)
	}

	bur := &tbcapi.UTXOsByAddressRequest{
		FilterMempool: filterMempool,
		Address:       addr.String(),
		Start:         start,
		Count:         count,
	}

	res, err := t.callTBC(ctx, DefaultRequestTimeout, bur)
	if err != nil {
		return nil, err
	}

	buResp, ok := res.(*tbcapi.UTXOsByAddressResponse)
	if !ok {
		return nil, fmt.Errorf("not a utxos by address respose %T", res)
	}

	if buResp.Error != nil {
		return nil, buResp.Error
	}

	return buResp.UTXOs, nil
}

func (t *tbcGozer) BlocksByL2AbrevHashes(ctx context.Context, hashes []chainhash.Hash) *gozer.BlocksByL2AbrevHashesResponse {
	ksr := &tbcapi.BlocksByL2AbrevHashesRequest{
		L2KeystoneAbrevHashes: hashes,
	}

	res, err := t.callTBC(ctx, DefaultRequestTimeout, ksr)
	if err != nil {
		r := &gozer.BlocksByL2AbrevHashesResponse{
			Error: protocol.Errorf("%v", err),
		}
		return r
	}

	bksr, ok := res.(*tbcapi.BlocksByL2AbrevHashesResponse)
	if !ok {
		r := &gozer.BlocksByL2AbrevHashesResponse{
			Error: protocol.Errorf("not a keystone response %T", res),
		}
		return r
	}
	if bksr.Error != nil {
		r := &gozer.BlocksByL2AbrevHashesResponse{
			Error: bksr.Error,
		}
		return r
	}
	return gozer.TBC2Gozer(bksr)
}

func (t *tbcGozer) KeystonesByHeight(ctx context.Context, height uint32, depth int) (*gozer.KeystonesByHeightResponse, error) {
	ksr := &tbcapi.KeystonesByHeightRequest{
		Height: height,
		Depth:  depth,
	}

	res, err := t.callTBC(ctx, DefaultRequestTimeout, ksr)
	if err != nil {
		r := &gozer.KeystonesByHeightResponse{
			Error: protocol.Errorf("%v", err),
		}
		return r, err
	}

	bksr, ok := res.(*tbcapi.KeystonesByHeightResponse)
	if !ok {
		err = fmt.Errorf("not a keystone by height response %T", res)
		r := &gozer.KeystonesByHeightResponse{
			Error: protocol.Errorf("%v", err),
		}
		return r, err
	}
	//nolint:nilerr // only return internal error
	if bksr.Error != nil {
		r := &gozer.KeystonesByHeightResponse{
			Error: bksr.Error,
		}
		return r, nil
	}

	r := &gozer.KeystonesByHeightResponse{
		L2KeystoneAbrevs: bksr.L2KeystoneAbrevs,
		BTCTipHeight:     bksr.BTCTipHeight,
	}
	return r, nil
}

func (t *tbcGozer) callTBC(pctx context.Context, timeout time.Duration, msg any) (any, error) {
	log.Tracef("callTBC %T", msg)
	defer log.Tracef("callTBC exit %T", msg)

	if !t.Connected() {
		return nil, errors.New("not connected to tbc")
	}

	if timeout == 0 {
		timeout = DefaultRequestTimeout
	}

	bc := tbcCmd{
		msg:     msg,
		ch:      make(chan any),
		timeout: timeout,
	}

	ctx, cancel := context.WithTimeout(pctx, timeout)
	defer cancel()

	// attempt to send
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case t.cmdCh <- bc:
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

func (t *tbcGozer) handleTBCWebsocketCall(pctx context.Context, conn *protocol.Conn) {
	defer t.wg.Done()

	log.Tracef("handleTBCWebsocketCall")
	defer log.Tracef("handleTBCWebsocketCall exit")
	for {
		select {
		case <-pctx.Done():
			return
		case c := <-t.cmdCh:
			// Parallelize calls. There is no reason to do them
			// in order and wait for potentially slow completion.
			go func(bc tbcCmd) {
				if bc.timeout == 0 {
					bc.timeout = DefaultRequestTimeout
				}
				ctx, cancel := context.WithTimeout(pctx, bc.timeout)
				defer cancel()

				_, _, payload, err := tbcapi.Call(ctx, conn, bc.msg)
				if err != nil {
					// XXX very loud
					log.Errorf("handleTBCWebsocketCall %T: %v",
						bc.msg, err)
					select {
					case <-ctx.Done():
					case bc.ch <- err:
					}
					return
				}
				select {
				case <-ctx.Done():
				case bc.ch <- payload:
					log.Tracef("handleTBCWebsocketCall returned: %v",
						spew.Sdump(payload))
				}
			}(c)
		}
	}
}

func (t *tbcGozer) handleTBCWebsocketRead(ctx context.Context, conn *protocol.Conn) {
	defer t.wg.Done()

	log.Tracef("handleTBCWebsocketRead")
	defer log.Tracef("handleTBCWebsocketRead exit")
	pcc := conn.ConnectCount()
	for {
		_, _, _, err := tbcapi.ReadConn(ctx, conn)
		if err != nil {
			// See if we were terminated
			select {
			case <-ctx.Done():
				return
			case <-time.Tick(5 * time.Second):
			}

			cc := conn.ConnectCount()
			if pcc == cc {
				log.Infof("Connection with TBC server was lost, reconnecting...")
				pcc++
			}
			continue
		}
	}
}

func (t *tbcGozer) connectTBC(pctx context.Context, connected func()) error {
	log.Tracef("connectTBC")
	defer log.Tracef("connectTBC exit")

	conn, err := protocol.NewConn(t.url, &protocol.ConnOptions{
		ReadLimit: 6 * (1 << 20), // 6 MiB
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// TODO: implement exponential backoff retry
	if err = conn.Connect(ctx); err != nil {
		return err
	}

	t.mtx.Lock()
	t.connected = true
	t.mtx.Unlock()
	defer func() {
		t.mtx.Lock()
		t.connected = false
		t.mtx.Unlock()
	}()

	t.wg.Add(1)
	go t.handleTBCWebsocketRead(ctx, conn)

	t.wg.Add(1)
	go t.handleTBCWebsocketCall(ctx, conn)

	log.Debugf("Connected to tbc: %s", t.url)

	// Callback after connection if set.
	if connected != nil {
		connected()
	}

	// Wait for exit
	t.wg.Wait()

	return nil
}

func (t *tbcGozer) run(ctx context.Context, connected func()) {
	for {
		if err := t.connectTBC(ctx, connected); err != nil {
			log.Errorf("Failed to connect to TBC: %v", err)
		}

		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.Tick(5 * time.Second):
		}

		log.Debugf("Reconnecting to: %v", t.url)
	}
}
