// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package mock

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
	"github.com/hemilabs/heminetwork/v2/service/tbc"
	"github.com/hemilabs/heminetwork/v2/testutil"
)

type TBCMockHandler struct {
	mockHandler
	keystones map[chainhash.Hash]*hemi.L2KeystoneAbrev
	btcTip    uint
	utxoNum   uint
	kssMtx    sync.RWMutex
}

func (f *TBCMockHandler) GetKeystones() map[chainhash.Hash]*hemi.L2KeystoneAbrev {
	f.kssMtx.RLock()
	cpy := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)
	maps.Copy(cpy, f.keystones)
	f.kssMtx.RUnlock()
	return cpy
}

func NewMockTBC(pctx context.Context, errCh chan error, msgCh chan string, keystones map[chainhash.Hash]*hemi.L2KeystoneAbrev, btcTip, utxoNum uint) *TBCMockHandler {
	th := TBCMockHandler{
		mockHandler: mockHandler{
			errCh: errCh,
			msgCh: msgCh,
			name:  "mockTBC",
			pctx:  pctx,
			conns: make([]*websocket.Conn, 0),
		},
		keystones: keystones,
		btcTip:    btcTip,
		utxoNum:   utxoNum,
	}
	th.handleFunc = th.mockTBCHandleFunc
	th.server = httptest.NewServer(&th)
	th.Start()
	return &th
}

func (f *TBCMockHandler) handle(c protocol.APIConn, utxos []tbcd.Utxo, mp *tbc.Mempool, w http.ResponseWriter, r *http.Request) (string, error) {
	cmd, id, payload, err := tbcapi.Read(f.pctx, c)
	if err != nil {
		var ce websocket.CloseError
		if errors.As(err, &ce) {
			panic(fmt.Errorf("handleWebsocketRead: %w", err))
		}
		if errors.Is(err, io.EOF) {
			panic(fmt.Errorf("handleWebsocketRead: EOF"))
		}

		return "", fmt.Errorf("handleWebsocketRead: %w", err)
	}
	log.Tracef("%v: command is %v", f.name, cmd)

	var resp any
	switch cmd {
	case tbcapi.CmdBlockHeaderBestRequest:
		resp = &tbcapi.BlockHeaderBestResponse{
			Height:      8,
			BlockHeader: nil,
		}
	case tbcapi.CmdUTXOsByAddressRequest:
		filtered, err := mp.FilterUtxos(f.pctx, utxos)
		if err != nil {
			panic(fmt.Errorf("filter utxos: %w", err))
		}

		respUtxos := make([]*tbcapi.UTXO, 0)
		for _, utxo := range filtered {
			txID := utxo.ScriptHash()
			txHash, err := chainhash.NewHash(txID[:])
			if err != nil {
				panic(err)
			}
			value, err := newAmountFromUint64(utxo.Value())
			if err != nil {
				panic(fmt.Errorf("amount from utxo value: %w", err))
			}
			respUtxos = append(respUtxos, &tbcapi.UTXO{
				TxId:     *txHash,
				Value:    value,
				OutIndex: utxo.OutputIndex(),
			})
		}
		resp = &tbcapi.UTXOsByAddressResponse{
			UTXOs: respUtxos,
		}
	case tbcapi.CmdTxBroadcastRequest:
		pl, ok := payload.(*tbcapi.TxBroadcastRequest)
		if !ok {
			panic(fmt.Errorf("unexpected payload format: %v", payload))
		}

		ph := make([]byte, 32)
		_, err := rand.Read(ph)
		if err != nil {
			panic(err)
		}

		ch, err := chainhash.NewHash(ph)
		if err != nil {
			panic(ch)
		}
		resp = tbcapi.TxBroadcastResponse{TxID: ch}

		for _, txOut := range pl.Tx.TxOut {
			aPoPTx, err := pop.ParseTransactionL2FromOpReturn(txOut.PkScript)
			if err != nil {
				continue
			}
			f.kssMtx.Lock()
			f.keystones[*aPoPTx.L2Keystone.Hash()] = aPoPTx.L2Keystone
			f.kssMtx.Unlock()
			break
		}

		opp := pl.Tx.TxIn[0].PreviousOutPoint
		mptx := tbc.NewMempoolTx(*ch, map[wire.OutPoint]struct{}{opp: {}})
		err = mp.TxInsert(f.pctx, &mptx)
		if err != nil {
			panic(fmt.Errorf("mempool tx insert: %w", err))
		}
	case tbcapi.CmdBlocksByL2AbrevHashesRequest:
		pl, ok := payload.(*tbcapi.BlocksByL2AbrevHashesRequest)
		if !ok {
			panic(fmt.Errorf("unexpected payload format: %v", payload))
		}

		blkInfos := make([]*tbcapi.L2KeystoneBlockInfo, 0, len(pl.L2KeystoneAbrevHashes))
		for _, hash := range pl.L2KeystoneAbrevHashes {
			f.kssMtx.RLock()
			kss, ok := f.keystones[hash]
			f.kssMtx.RUnlock()
			if !ok {
				blkInfos = append(blkInfos, &tbcapi.L2KeystoneBlockInfo{
					Error: protocol.NotFoundError("keystone", hash),
				})
			} else {
				ch, err := chainhash.NewHash(testutil.SHA256([]byte{byte(kss.L1BlockNumber)}))
				if err != nil {
					panic(err)
				}
				blkInfos = append(blkInfos, &tbcapi.L2KeystoneBlockInfo{
					L2KeystoneAbrev:       kss,
					L2KeystoneBlockHash:   ch,
					L2KeystoneBlockHeight: uint(kss.L1BlockNumber),
				})
			}
		}
		tch, err := chainhash.NewHash(testutil.SHA256([]byte{byte(f.btcTip)}))
		if err != nil {
			panic(err)
		}
		resp = &tbcapi.BlocksByL2AbrevHashesResponse{
			L2KeystoneBlocks:  blkInfos,
			BtcTipBlockHash:   tch,
			BtcTipBlockHeight: f.btcTip,
		}

	case tbcapi.CmdFeeEstimateRequest:
		resp = tbcapi.FeeEstimateResponse{
			FeeEstimates: []*tbcapi.FeeEstimate{
				{Blocks: 1, SatsPerByte: 1},
				{Blocks: 2, SatsPerByte: 1},
				{Blocks: 3, SatsPerByte: 1},
				{Blocks: 4, SatsPerByte: 1},
				{Blocks: 5, SatsPerByte: 1},
				{Blocks: 6, SatsPerByte: 1},
				{Blocks: 7, SatsPerByte: 1},
				{Blocks: 8, SatsPerByte: 1},
				{Blocks: 9, SatsPerByte: 1},
				{Blocks: 10, SatsPerByte: 1},
			},
		}
	case tbcapi.CmdKeystonesByHeightRequest:
		pl, ok := payload.(*tbcapi.KeystonesByHeightRequest)
		if !ok {
			panic(fmt.Errorf("unexpected payload format: %v", payload))
		}
		height := int64(pl.Height)
		depth := int64(pl.Depth)
		kssList := make([]*hemi.L2KeystoneAbrev, 0, 16)
		start := min(height, height+depth)
		end := max(height, height+depth)
		for i := start; i != end; i++ {
			if i == height {
				continue
			}
			f.kssMtx.Lock()
			for _, ks := range f.keystones {
				if int64(ks.L1BlockNumber) == i {
					kssList = append(kssList, ks)
				}
			}
			f.kssMtx.Unlock()
		}

		if len(kssList) < 1 {
			resp = tbcapi.KeystonesByHeightResponse{
				Error: protocol.RequestErrorf("%v", database.ErrNotFound),
			}
		} else {
			resp = tbcapi.KeystonesByHeightResponse{
				L2KeystoneAbrevs: kssList,
				BTCTipHeight:     uint64(f.btcTip),
			}
		}
	default:
		panic(fmt.Errorf("unknown command: %v", cmd))
	}

	if err = tbcapi.Write(f.pctx, c, id, resp); err != nil {
		return "", fmt.Errorf("failed to handle %s request: %w",
			cmd, err)
	}

	return string(cmd), nil
}

func (f *TBCMockHandler) mockTBCHandleFunc(w http.ResponseWriter, r *http.Request) error {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		panic(fmt.Errorf("failed to accept websocket connection for %s: %w",
			r.RemoteAddr, err))
	}
	defer conn.Close(websocket.StatusNormalClosure, "") // Force close connection

	// Always ping, required by protocol.
	ping := &tbcapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	wsConn := protocol.NewWSConn(conn)
	if err = tbcapi.Write(r.Context(), wsConn, "0", ping); err != nil {
		panic(fmt.Errorf("write ping: %w", err))
	}

	f.mtx.Lock()
	f.conns = append(f.conns, conn)
	f.mtx.Unlock()

	log.Infof("%v: new connection to %v", f.name, r.RemoteAddr)

	// create utxos
	utxos := make([]tbcd.Utxo, 0, f.utxoNum)
	for k := range f.utxoNum {
		uniqueBytes := make([]byte, 32)
		binary.BigEndian.PutUint32(uniqueBytes[0:32], uint32(k))
		utxo := tbcd.NewUtxo([32]byte(uniqueBytes), 10000, 0)
		utxos = append(utxos, utxo)
	}

	// create mempool
	mp, err := tbc.NewMempool()
	if err != nil {
		panic(fmt.Errorf("create mempool: %w", err))
	}

	for {
		// Handle command
		method, err := f.handle(wsConn, utxos, mp, w, r)
		if err != nil {
			log.Errorf("exiting mockTBCHandleFunc: %v", err)
			return err
		}
		f.notifyMsg(f.pctx, method)
	}
}

func newAmountFromUint64(u uint64) (btcutil.Amount, error) {
	if u > math.MaxInt64 {
		return 0, errors.New("invalid amount")
	}
	return btcutil.Amount(int64(u)), nil
}
