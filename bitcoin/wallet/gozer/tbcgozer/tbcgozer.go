// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcgozer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
)

const (
	logLevel              = "INFO"
	defaultRequestTimeout = 3 * time.Second
)

var log = loggo.GetLogger("tbcgozer")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}

// Wrap for calling tbc commands
type tbcCmd struct {
	msg any
	ch  chan any
}

type tbcGozer struct {
	mtx       sync.Mutex
	wg        sync.WaitGroup
	url       string
	cmdCh     chan tbcCmd // commands to send to tbc
	connected bool
}

func (t *tbcGozer) Connected() bool {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	return t.connected
}

func (t *tbcGozer) FeeEstimates(ctx context.Context) ([]gozer.FeeEstimate, error) {
	bur := &tbcapi.FeeEstimateRequest{}

	res, err := t.callTBC(ctx, defaultRequestTimeout, bur)
	if err != nil {
		return nil, err
	}

	buResp, ok := res.(*tbcapi.FeeEstimateResponse)
	if !ok {
		return nil, fmt.Errorf("not a buResp %T", res)
	}

	if buResp.Error != nil {
		return nil, buResp.Error
	}

	frv := make([]gozer.FeeEstimate, 0, len(*buResp.FeeEstimates))
	for k, v := range *buResp.FeeEstimates {
		frv = append(frv, gozer.FeeEstimate{Blocks: k, SatsPerByte: v})
	}

	return frv, nil
}

func (t *tbcGozer) UtxosByAddress(ctx context.Context, addr btcutil.Address, start, count uint) ([]*tbcapi.UTXO, error) {
	maxCount := uint(1000)
	if count > maxCount {
		return nil, fmt.Errorf("count must not exceed %v", maxCount)
	}

	bur := &tbcapi.UTXOsByAddressRequest{
		Address: addr.String(),
		Start:   start,
		Count:   count,
	}

	res, err := t.callTBC(ctx, defaultRequestTimeout, bur)
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

func (t *tbcGozer) callTBC(pctx context.Context, timeout time.Duration, msg any) (any, error) {
	log.Tracef("callTBC %T", msg)
	defer log.Tracef("callTBC exit %T", msg)

	if !t.Connected() {
		return nil, errors.New("not connected to tbc")
	}

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
	case t.cmdCh <- bc:
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

func (t *tbcGozer) handleTBCWebsocketCall(ctx context.Context, conn *protocol.Conn) {
	defer t.wg.Done()

	log.Tracef("handleTBCWebsocketCall")
	defer log.Tracef("handleTBCWebsocketCall exit")
	for {
		select {
		case <-ctx.Done():
			return
		case bc := <-t.cmdCh:
			_, _, payload, err := tbcapi.Call(ctx, conn, bc.msg)
			if err != nil {
				log.Errorf("handleTBCWebsocketCall %T: %v", bc.msg, err)
				select {
				case bc.ch <- err:
				default:
				}
			}
			select {
			case bc.ch <- payload:
				log.Tracef("handleTBCWebsocketCall returned: %v", spew.Sdump(payload))
			default:
			}
		}
	}
}

func (t *tbcGozer) handleTBCWebsocketRead(ctx context.Context, conn *protocol.Conn) {
	defer t.wg.Done()

	log.Tracef("handleTBCWebsocketRead")
	defer log.Tracef("handleTBCWebsocketRead exit")
	for {
		_, _, _, err := tbcapi.ReadConn(ctx, conn)
		if err != nil {

			// See if we were terminated
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}

			log.Infof("Connection with TBC server was lost, reconnecting...")
			continue
		}
	}
}

func (t *tbcGozer) connectTBC(pctx context.Context) error {
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

	err = conn.Connect(ctx)
	if err != nil {
		log.Infof("%v", err)
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

	// Wait for exit
	t.wg.Wait()

	return nil
}

func (t *tbcGozer) run(ctx context.Context) {
	for {
		if err := t.connectTBC(ctx); err != nil {
			log.Tracef("connectTBC: %v", err)
		}
		// See if we were terminated
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		log.Debugf("Reconnecting to: %v", t.url)
	}
}

func TBCGozerNew(ctx context.Context, tbcUrl string) (gozer.Gozer, error) {
	t := &tbcGozer{
		url:   tbcUrl,
		cmdCh: make(chan tbcCmd, 10),
	}

	go t.run(ctx) // XXX rethink this

	return t, nil
}
