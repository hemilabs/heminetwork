// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"nhooyr.io/websocket"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
)

type tbcWs struct {
	wg             sync.WaitGroup
	addr           string
	conn           *protocol.WSConn
	sessionID      string
	requestContext context.Context
}

func (s *Server) handlePingRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handlePingRequest: %v", ws.addr)
	defer log.Tracef("handlePingRequest exit: %v", ws.addr)

	p, ok := payload.(*tbcapi.PingRequest)
	if !ok {
		return fmt.Errorf("handlePingRequest invalid payload type: %T", payload)
	}
	response := &tbcapi.PingResponse{
		OriginTimestamp: p.Timestamp,
		Timestamp:       time.Now().Unix(),
	}

	log.Tracef("responding with %v", spew.Sdump(response))

	if err := tbcapi.Write(ctx, ws.conn, id, response); err != nil {
		return fmt.Errorf("handlePingRequest write: %v %v",
			ws.addr, err)
	}
	return nil
}

func (s *Server) handleBlockHeadersByHeightRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handleBtcBlockHeadersByHeightRequest: %v", ws.addr)
	defer log.Tracef("handleBtcBlockHeadersByHeightRequest exit: %v", ws.addr)

	// "decode" the input
	p, ok := payload.(*tbcapi.BlockHeadersByHeightRequest)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", payload)
	}

	blockHeaders, err := s.BlockHeadersByHeight(ctx, uint64(p.Height))
	if err != nil {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.BlockHeadersByHeightResponse{
			Error: protocol.Errorf("error getting block at height %d: %s", p.Height, err),
		})
	}

	var encodedBlockHeaders []api.ByteSlice
	for _, bh := range blockHeaders {
		bytes, err := header2Bytes(&bh)
		if err != nil {
			return err
		}
		encodedBlockHeaders = append(encodedBlockHeaders, bytes)
	}

	// "encode" output and write response
	return tbcapi.Write(ctx, ws.conn, id, tbcapi.BlockHeadersByHeightResponse{
		BlockHeaders: encodedBlockHeaders,
	})
}

func (s *Server) handleBlockHeadersBestRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handleBlockHeadersBestRequest: %v", ws.addr)
	defer log.Tracef("handleBlockHeadersBestRequest exit: %v", ws.addr)

	if _, ok := payload.(*tbcapi.BlockHeadersBestRequest); !ok {
		return fmt.Errorf("invalid payload type: %T", payload)
	}

	height, blockHeaders, err := s.BlockHeadersBest(ctx)
	if err != nil {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.BlockHeadersBestResponse{
			Error: protocol.Errorf("error getting best block headers: %v", err),
		})
	}

	var encodedBlockHeaders []api.ByteSlice
	for _, bh := range blockHeaders {
		bytes, err := header2Bytes(&bh)
		if err != nil {
			return err
		}
		encodedBlockHeaders = append(encodedBlockHeaders, bytes)
	}

	return tbcapi.Write(ctx, ws.conn, id, tbcapi.BlockHeadersBestResponse{
		Height:       height,
		BlockHeaders: encodedBlockHeaders,
	})
}

func (s *Server) handleBalanceByAddrRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handleBtcBalanceByAddrRequest: %v", ws.addr)
	defer log.Tracef("handleBtcBalanceByAddrRequest exit: %v", ws.addr)

	p, ok := payload.(*tbcapi.BalanceByAddressRequest)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", payload)
	}

	balance, err := s.BalanceByAddress(ctx, p.Address)
	if err != nil {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.BalanceByAddressResponse{
			Error: protocol.Errorf("error getting balance for address: %s", err),
		})
	}

	return tbcapi.Write(ctx, ws.conn, id, tbcapi.BalanceByAddressResponse{
		Balance: balance,
	})
}

func (s *Server) handleUtxosByAddressRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handleUtxosByAddressRequest: %v", ws.addr)
	defer log.Tracef("handleUtxosByAddressRequest exit: %v", ws.addr)

	p, ok := payload.(*tbcapi.UtxosByAddressRequest)
	if !ok {
		return fmt.Errorf("handleUtxosByAddressRequest invalid payload type: %T", payload)
	}

	utxos, err := s.UtxosByAddress(ctx, p.Address, uint64(p.Start), uint64(p.Count))
	if err != nil {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.UtxosByAddressResponse{
			Error: protocol.Errorf("error getting utxos for address: %s", err),
		})
	}

	var responseUtxos []api.ByteSlice
	for _, utxo := range utxos {
		responseUtxos = append(responseUtxos, utxo[:])
	}

	return tbcapi.Write(ctx, ws.conn, id, tbcapi.UtxosByAddressResponse{
		Utxos: responseUtxos,
	})
}

func (s *Server) handleTxByIdRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handleTxByIdRequest: %v", ws.addr)
	defer log.Tracef("handleTxByIdRequest exit: %v", ws.addr)

	p, ok := payload.(*tbcapi.TxByIdRequest)
	if !ok {
		return fmt.Errorf("handleTxByIdRequest invalid payload type: %T", payload)
	}

	if len(p.TxId) != 32 {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.TxByIdResponse{
			Error: protocol.Errorf("invalid tx id"),
		})
	}

	tx, err := s.TxById(ctx, [32]byte(p.TxId))
	if err != nil {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.TxByIdResponse{
			Error: protocol.Errorf("error getting tx by id: %s", err),
		})
	}

	b, err := tx2Bytes(tx)
	if err != nil {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.TxByIdResponse{
			Error: protocol.NewInternalError(err).ProtocolError(),
		})
	}

	return tbcapi.Write(ctx, ws.conn, id, tbcapi.TxByIdResponse{
		Tx: b,
	})
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
			err = s.handleBlockHeadersByHeightRequest(ctx, ws, payload, id)
		case tbcapi.CmdBlockHeadersBestRequest:
			err = s.handleBlockHeadersBestRequest(ctx, ws, payload, id)
		case tbcapi.CmdBalanceByAddressRequest:
			err = s.handleBalanceByAddrRequest(ctx, ws, payload, id)
		case tbcapi.CmdUtxosByAddressRequest:
			err = s.handleUtxosByAddressRequest(ctx, ws, payload, id)
		case tbcapi.CmdTxByIdRequest:
			err = s.handleTxByIdRequest(ctx, ws, payload, id)
		default:
			err = fmt.Errorf("unknown command: %v", cmd)
		}

		// Command failed
		if err != nil {
			log.Errorf("handleWebsocketRead %s %s %s: %v",
				ws.addr, cmd, id, err)
			return
		}

		// Command successfully completed
		s.cmdsProcessed.Inc()
	}
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
