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
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
)

const (
	logLevel              = "INFO"
	defaultRequestTimeout = 3 * time.Second

	DefaultURL = "ws://localhost:8082/v1/ws"
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

func (t *tbcGozer) BtcHeight(ctx context.Context) (uint64, error) {
	bur := &tbcapi.BlockHeaderBestRequest{}

	res, err := t.callTBC(ctx, defaultRequestTimeout, bur)
	if err != nil {
		return 0, err
	}

	buResp, ok := res.(*tbcapi.BlockHeaderBestResponse)
	if !ok {
		return 0, fmt.Errorf("not a fee estimate response %T", res)
	}

	if buResp.Error != nil {
		return 0, buResp.Error
	}

	return buResp.Height, nil
}

func (t *tbcGozer) FeeEstimates(ctx context.Context) ([]*tbcapi.FeeEstimate, error) {
	bur := &tbcapi.FeeEstimateRequest{}

	res, err := t.callTBC(ctx, defaultRequestTimeout, bur)
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

	res, err := t.callTBC(ctx, defaultRequestTimeout, bur)
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
		return nil, fmt.Errorf("not a utxos by address respose %T", res)
	}

	if buResp.Error != nil {
		return nil, buResp.Error
	}

	return buResp.UTXOs, nil
}

// XXX Make this a batch call at the tbc layer rather than making a call per hash
func (t *tbcGozer) BlockKeystoneByL2KeystoneAbrevHash(ctx context.Context, hashes []chainhash.Hash) []*gozer.BlockKeystoneByL2KeystoneAbrevHashResponse {
	responses := make([]*gozer.BlockKeystoneByL2KeystoneAbrevHashResponse, 0, len(hashes))
	for _, h := range hashes {
		ksr := &tbcapi.BlockKeystoneByL2KeystoneAbrevHashRequest{
			L2KeystoneAbrevHash: h,
		}

		res, err := t.callTBC(ctx, defaultRequestTimeout, ksr)
		if err != nil {
			r := &gozer.BlockKeystoneByL2KeystoneAbrevHashResponse{Error: protocol.Errorf("%v", err)}
			responses = append(responses, r)
			continue
		}

		bksr, ok := res.(*tbcapi.BlockKeystoneByL2KeystoneAbrevHashResponse)
		if !ok {
			r := &gozer.BlockKeystoneByL2KeystoneAbrevHashResponse{Error: protocol.Errorf("not a keystone response %T", res)}
			responses = append(responses, r)
			continue
		}
		if bksr.Error != nil {
			r := &gozer.BlockKeystoneByL2KeystoneAbrevHashResponse{Error: bksr.Error}
			responses = append(responses, r)
			continue
		}
		r := &gozer.BlockKeystoneByL2KeystoneAbrevHashResponse{
			L2KeystoneAbrev: gozer.L2KeystoneAbrev{
				Version:            uint(bksr.L2KeystoneAbrev.Version),
				L1BlockNumber:      uint(bksr.L2KeystoneAbrev.L1BlockNumber),
				L2BlockNumber:      uint(bksr.L2KeystoneAbrev.L2BlockNumber),
				ParentEPHash:       bksr.L2KeystoneAbrev.ParentEPHash[:],
				PrevKeystoneEPHash: bksr.L2KeystoneAbrev.PrevKeystoneEPHash[:],
				StateRoot:          bksr.L2KeystoneAbrev.StateRoot[:],
				EPHash:             bksr.L2KeystoneAbrev.EPHash[:],
			},
			L2KeystoneBlockHash:   *bksr.L2KeystoneBlockHash,
			L2KeystoneBlockHeight: bksr.L2KeystoneBlockHeight,
			BtcTipBlockHash:       *bksr.BtcTipBlockHash,
			BtcTipBlockHeight:     bksr.BtcTipBlockHeight,
		}

		responses = append(responses, r)
	}

	return responses
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
	pcc := conn.ConnectCount()
	for {
		_, _, _, err := tbcapi.ReadConn(ctx, conn)
		if err != nil {
			// See if we were terminated
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
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
			log.Infof("%v", err)
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

func Run(ctx context.Context, tbcUrl string) (gozer.Gozer, error) {
	t := &tbcGozer{
		url:   tbcUrl,
		cmdCh: make(chan tbcCmd, 10),
	}

	go t.run(ctx)

	return t, nil
}
