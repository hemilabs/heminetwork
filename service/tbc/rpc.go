// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"nhooyr.io/websocket"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
)

type tbcWs struct {
	wg             sync.WaitGroup
	addr           string
	conn           *protocol.WSConn
	sessionID      string
	requestContext context.Context
}

func (s *Server) handleWebsocketRead(ctx context.Context, ws *tbcWs) {
	defer ws.wg.Done()

	log.Tracef("handleWebsocketRead: %v", ws.addr)
	defer log.Tracef("handleWebsocketRead exit: %v", ws.addr)

	for {
		cmd, id, payload, err := tbcapi.Read(ctx, ws.conn)
		if err != nil {
			var ce websocket.CloseError
			if errors.As(err, &ce) {
				log.Tracef("handleWebsocketRead: %v", err)
				return
			}

			log.Errorf("handleWebsocketRead: %v", err)
			return
		}

		switch cmd {
		case tbcapi.CmdPingRequest:
			err = s.handlePingRequest(ctx, ws, payload, id)
		case tbcapi.CmdBlockHeadersByHeightRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BlockHeadersByHeightRequest)
				return s.handleBlockHeadersByHeightRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdBlockHeadersBestRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BlockHeadersBestRequest)
				return s.handleBlockHeadersBestRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdBalanceByAddressRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BalanceByAddressRequest)
				return s.handleBalanceByAddressRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdUtxosByAddressRawRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.UtxosByAddressRawRequest)
				return s.handleUtxosByAddressRawRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdUtxosByAddressRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.UtxosByAddressRequest)
				return s.handleUtxosByAddressRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdTxByIdRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.TxByIdRequest)
				return s.handleTxByIdRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdTxByIdRawRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.TxByIdRawRequest)
				return s.handleTxByIdRawRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		default:
			err = fmt.Errorf("unknown command: %v", cmd)
		}

		// Command failed
		if err != nil {
			log.Errorf("handleWebsocketRead %s %s %s: %v",
				ws.addr, cmd, id, err)
			return
		}
	}
}

func (s *Server) handleRequest(ctx context.Context, ws *tbcWs, id string, cmd protocol.Command, handler func(ctx context.Context) (any, error)) {
	log.Tracef("handleRequest: %s: %s", ws.addr, cmd)
	defer log.Tracef("handleRequest exit: %s: %s", ws.addr, cmd)

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	// TODO(joshuasing): add rate limiting?

	res, err := handler(ctx)
	if err != nil {
		log.Errorf("Failed to handle %s request for %s: %v", cmd, ws.addr, err)
	}

	if res == nil {
		return
	}

	// XXX: spew.Sdump should only be called when the log level is enabled.
	log.Debugf("Responding to %s request with %v", cmd, spew.Sdump(res))

	if err = tbcapi.Write(ctx, ws.conn, id, res); err != nil {
		log.Errorf("Failed to handle %s request for %s: protocol write failed: %v",
			cmd, ws.addr, err)
	}

	// Request processed successfully
	s.cmdsProcessed.Inc()
}

func (s *Server) handlePingRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handlePingRequest: %v", ws.addr)
	defer log.Tracef("handlePingRequest exit: %v", ws.addr)

	p, ok := payload.(*tbcapi.PingRequest)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", payload)
	}

	res := &tbcapi.PingResponse{
		OriginTimestamp: p.Timestamp,
		Timestamp:       time.Now().Unix(),
	}

	// XXX: spew.Sdump should only be called when the log level is enabled.
	log.Tracef("responding with %v", spew.Sdump(res))

	if err := tbcapi.Write(ctx, ws.conn, id, res); err != nil {
		return fmt.Errorf("handlePingRequest write: %v %v",
			ws.addr, err)
	}

	// Ping request processed successfully
	s.cmdsProcessed.Inc()
	return nil
}

func (s *Server) handleBlockHeadersByHeightRequest(ctx context.Context, req *tbcapi.BlockHeadersByHeightRequest) (any, error) {
	log.Tracef("handleBtcBlockHeadersByHeightRequest")
	defer log.Tracef("handleBtcBlockHeadersByHeightRequest exit")

	blockHeaders, err := s.BlockHeadersByHeight(ctx, uint64(req.Height))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return &tbcapi.BlockHeadersByHeightResponse{
				Error: protocol.RequestErrorf("block headers not found at height %d", req.Height),
			}, nil
		}

		e := protocol.NewInternalError(err)
		return &tbcapi.BlockHeadersByHeightResponse{
			Error: e.ProtocolError(),
		}, e
	}

	var encodedBlockHeaders []api.ByteSlice
	for _, bh := range blockHeaders {
		bytes, err := header2Bytes(&bh)
		if err != nil {
			e := protocol.NewInternalError(err)
			return &tbcapi.BlockHeadersByHeightResponse{
				Error: e.ProtocolError(),
			}, e
		}
		encodedBlockHeaders = append(encodedBlockHeaders, bytes)
	}

	return tbcapi.BlockHeadersByHeightResponse{
		BlockHeaders: encodedBlockHeaders,
	}, nil
}

func (s *Server) handleBlockHeadersBestRequest(ctx context.Context, _ *tbcapi.BlockHeadersBestRequest) (any, error) {
	log.Tracef("handleBlockHeadersBestRequest")
	defer log.Tracef("handleBlockHeadersBestRequest exit")

	height, blockHeaders, err := s.BlockHeadersBest(ctx)
	if err != nil {
		e := protocol.NewInternalError(err)
		return &tbcapi.BlockHeadersBestResponse{
			Error: e.ProtocolError(),
		}, e
	}

	var encodedBlockHeaders []api.ByteSlice
	for _, bh := range blockHeaders {
		bytes, err := header2Bytes(&bh)
		if err != nil {
			e := protocol.NewInternalError(err)
			return &tbcapi.BlockHeadersByHeightResponse{
				Error: e.ProtocolError(),
			}, e
		}
		encodedBlockHeaders = append(encodedBlockHeaders, bytes)
	}

	return &tbcapi.BlockHeadersBestResponse{
		Height:       height,
		BlockHeaders: encodedBlockHeaders,
	}, nil
}

func (s *Server) handleBalanceByAddressRequest(ctx context.Context, req *tbcapi.BalanceByAddressRequest) (any, error) {
	log.Tracef("handleBalanceByAddressRequest")
	defer log.Tracef("handleBalanceByAddressRequest exit")

	balance, err := s.BalanceByAddress(ctx, req.Address)
	if err != nil {
		e := protocol.NewInternalError(err)
		return &tbcapi.BalanceByAddressResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &tbcapi.BalanceByAddressResponse{
		Balance: balance,
	}, nil
}

func (s *Server) handleUtxosByAddressRawRequest(ctx context.Context, req *tbcapi.UtxosByAddressRawRequest) (any, error) {
	log.Tracef("handleUtxosByAddressRawRequest")
	defer log.Tracef("handleUtxosByAddressRawRequest exit")

	utxos, err := s.UtxosByAddress(ctx, req.Address, uint64(req.Start), uint64(req.Count))
	if err != nil {
		if errors.Is(err, level.ErrIterator) {
			e := protocol.NewInternalError(err)
			return &tbcapi.UtxosByAddressRawResponse{
				Error: e.ProtocolError(),
			}, err
		}

		return &tbcapi.UtxosByAddressRawResponse{
			Error: protocol.RequestErrorf("error getting utxos for address: %s", req.Address),
		}, nil
	}

	var responseUtxos []api.ByteSlice
	for _, utxo := range utxos {
		responseUtxos = append(responseUtxos, utxo[:])
	}

	return &tbcapi.UtxosByAddressRawResponse{
		Utxos: responseUtxos,
	}, nil
}

func (s *Server) handleUtxosByAddressRequest(ctx context.Context, req *tbcapi.UtxosByAddressRequest) (any, error) {
	log.Tracef("handleUtxosByAddressRequest")
	defer log.Tracef("handleUtxosByAddressRequest exit")

	utxos, err := s.UtxosByAddress(ctx, req.Address, uint64(req.Start), uint64(req.Count))
	if err != nil {
		if errors.Is(err, level.ErrIterator) {
			e := protocol.NewInternalError(err)
			return &tbcapi.UtxosByAddressResponse{
				Error: e.ProtocolError(),
			}, e
		}

		return &tbcapi.UtxosByAddressResponse{
			Error: protocol.RequestErrorf("error getting utxos for address: %s", req.Address),
		}, nil
	}

	var responseUtxos []tbcapi.Utxo
	for _, utxo := range utxos {
		responseUtxos = append(responseUtxos, tbcapi.Utxo{
			TxId:     api.ByteSlice(utxo.ScriptHashSlice()),
			Value:    utxo.Value(),
			OutIndex: utxo.OutputIndex(),
		})
	}

	return &tbcapi.UtxosByAddressResponse{
		Utxos: responseUtxos,
	}, nil
}

func (s *Server) handleTxByIdRawRequest(ctx context.Context, req *tbcapi.TxByIdRawRequest) (any, error) {
	log.Tracef("handleTxByIdRawRequest")
	defer log.Tracef("handleTxByIdRawRequest exit")

	if len(req.TxId) != 32 {
		responseErr := protocol.RequestErrorf("invalid tx id")
		return &tbcapi.TxByIdRawResponse{
			Error: responseErr,
		}, nil
	}

	tx, err := s.TxById(ctx, [32]byte(req.TxId))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			responseErr := protocol.RequestErrorf("tx not found: %s", hex.EncodeToString(req.TxId))
			return &tbcapi.TxByIdRawResponse{
				Error: responseErr,
			}, nil
		}

		responseErr := protocol.NewInternalError(err)
		return &tbcapi.TxByIdRawResponse{
			Error: responseErr.ProtocolError(),
		}, responseErr
	}

	b, err := tx2Bytes(tx)
	if err != nil {
		e := protocol.NewInternalError(err)
		return &tbcapi.TxByIdRawResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &tbcapi.TxByIdRawResponse{
		Tx: b,
	}, nil
}

func (s *Server) handleTxByIdRequest(ctx context.Context, req *tbcapi.TxByIdRequest) (any, error) {
	log.Tracef("handleTxByIdRequest")
	defer log.Tracef("handleTxByIdRequest exit")

	if len(req.TxId) != 32 {
		responseErr := protocol.RequestErrorf("invalid tx id")
		return &tbcapi.TxByIdResponse{
			Error: responseErr,
		}, nil
	}

	tx, err := s.TxById(ctx, [32]byte(req.TxId))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			responseErr := protocol.RequestErrorf("not found: %s", hex.EncodeToString(req.TxId))
			return &tbcapi.TxByIdResponse{
				Error: responseErr,
			}, nil
		}

		responseErr := protocol.NewInternalError(err)
		return &tbcapi.TxByIdResponse{
			Error: responseErr.ProtocolError(),
		}, responseErr
	}

	return &tbcapi.TxByIdResponse{
		Tx: *wireTxToTbcapiTx(tx),
	}, nil
}

func (s *Server) handleWebsocket(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleWebsocket: %v", r.RemoteAddr)
	defer log.Tracef("handleWebsocket exit: %v", r.RemoteAddr)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		log.Errorf("Failed to accept websocket connection for %s: %v",
			r.RemoteAddr, err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "") // Force close connection

	ws := &tbcWs{
		addr:           r.RemoteAddr,
		conn:           protocol.NewWSConn(conn),
		requestContext: r.Context(),
	}

	if ws.sessionID, err = s.newSession(ws); err != nil {
		log.Errorf("An error occurred while creating session: %v", err)
		return
	}
	defer s.deleteSession(ws.sessionID)

	ws.wg.Add(1)
	go s.handleWebsocketRead(r.Context(), ws)

	// Always ping, required by protocol.
	ping := &tbcapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	log.Tracef("Responding with %v", spew.Sdump(ping))
	if err = tbcapi.Write(r.Context(), ws.conn, "0", ping); err != nil {
		log.Errorf("Write ping: %v", err)
	}

	log.Infof("Connection from %v", r.RemoteAddr)

	// Wait for termination
	ws.wg.Wait()

	log.Infof("Connection terminated from %v", r.RemoteAddr)
}

func (s *Server) newSession(ws *tbcWs) (string, error) {
	b := make([]byte, 16)

	for {
		// Create random hexadecimal string to use as an ID
		_, err := rand.Read(b)
		if err != nil {
			return "", err
		}
		id := hex.EncodeToString(b)

		// Ensure the key is not already in use, if it is then try again.
		s.mtx.Lock()
		if _, ok := s.sessions[id]; ok {
			s.mtx.Unlock()
			continue
		}
		s.sessions[id] = ws
		s.mtx.Unlock()

		return id, nil
	}
}

func (s *Server) deleteSession(id string) {
	s.mtx.Lock()
	_, ok := s.sessions[id]
	delete(s.sessions, id)
	s.mtx.Unlock()

	if !ok {
		log.Errorf("id not found in sessions %s", id)
	}
}

func wireTxToTbcapiTx(w *wire.MsgTx) *tbcapi.Tx {
	a := &tbcapi.Tx{
		Version:  w.Version,
		LockTime: w.LockTime,
		TxIn:     []*tbcapi.TxIn{},
		TxOut:    []*tbcapi.TxOut{},
	}

	for _, v := range w.TxIn {
		a.TxIn = append(a.TxIn, &tbcapi.TxIn{
			Sequence:        v.Sequence,
			SignatureScript: api.ByteSlice(v.SignatureScript),
			PreviousOutPoint: tbcapi.OutPoint{
				Hash:  api.ByteSlice(v.PreviousOutPoint.Hash[:]),
				Index: v.PreviousOutPoint.Index,
			},
		})

		for _, b := range v.Witness {
			a.TxIn[len(a.TxIn)-1].Witness = append(a.TxIn[len(a.TxIn)-1].Witness,
				api.ByteSlice(b))
		}
	}

	for _, v := range w.TxOut {
		a.TxOut = append(a.TxOut, &tbcapi.TxOut{
			Value:    v.Value,
			PkScript: api.ByteSlice(v.PkScript),
		})
	}

	return a
}
