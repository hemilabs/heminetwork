// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
)

func tx2Bytes(tx *wire.MsgTx) ([]byte, error) {
	var b bytes.Buffer
	if err := tx.Serialize(&b); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

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
			if errors.Is(err, io.EOF) {
				log.Tracef("handleWebsocketRead: EOF")
				return
			}

			log.Errorf("handleWebsocketRead: %v", err)
			return
		}

		switch cmd {
		case tbcapi.CmdPingRequest:
			err = s.handlePingRequest(ctx, ws, payload, id)
		case tbcapi.CmdBlockByHashRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BlockByHashRequest)
				return s.handleBlockByHashRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdBlockByHashRawRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BlockByHashRawRequest)
				return s.handleBlockByHashRawRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdBlockHeadersByHeightRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BlockHeadersByHeightRequest)
				return s.handleBlockHeadersByHeightRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdBlockHeadersByHeightRawRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BlockHeadersByHeightRawRequest)
				return s.handleBlockHeadersByHeightRawRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdBlockHeaderBestRawRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BlockHeaderBestRawRequest)
				return s.handleBlockHeaderBestRawRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdBlockHeaderBestRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BlockHeaderBestRequest)
				return s.handleBlockHeaderBestRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdBalanceByAddressRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.BalanceByAddressRequest)
				return s.handleBalanceByAddressRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdUTXOsByAddressRawRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.UTXOsByAddressRawRequest)
				return s.handleUtxosByAddressRawRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdUTXOsByAddressRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.UTXOsByAddressRequest)
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
		case tbcapi.CmdTxBroadcastRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.TxBroadcastRequest)
				return s.handleTxBroadcastRequest(ctx, req)
			}

			go s.handleRequest(ctx, ws, id, cmd, handler)
		case tbcapi.CmdTxBroadcastRawRequest:
			handler := func(ctx context.Context) (any, error) {
				req := payload.(*tbcapi.TxBroadcastRawRequest)
				return s.handleTxBroadcastRawRequest(ctx, req)
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

func (s *Server) handleBlockByHashRequest(ctx context.Context, req *tbcapi.BlockByHashRequest) (any, error) {
	log.Tracef("handleBlockByHashRequest")
	defer log.Tracef("handleBlockByHashRequest exit")

	block, err := s.BlockByHash(ctx, req.Hash)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return &tbcapi.BlockByHashResponse{
				Error: protocol.RequestErrorf("block not found with hash %s", req.Hash),
			}, nil
		}

		e := protocol.NewInternalError(err)
		return &tbcapi.BlockByHashResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &tbcapi.BlockByHashResponse{
		Block: wireBlockToTBC(block.MsgBlock()),
	}, nil
}

func (s *Server) handleBlockByHashRawRequest(ctx context.Context, req *tbcapi.BlockByHashRawRequest) (any, error) {
	log.Tracef("handleBlockByHashRawRequest")
	defer log.Tracef("handleBlockByHashRawRequest exit")

	block, err := s.BlockByHash(ctx, req.Hash)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return &tbcapi.BlockByHashRawResponse{
				Error: protocol.RequestErrorf("block not found with hash: %s", req.Hash),
			}, nil
		}

		e := protocol.NewInternalError(err)
		return &tbcapi.BlockByHashRawResponse{
			Error: e.ProtocolError(),
		}, e
	}

	b, err := block.Bytes()
	if err != nil {
		e := protocol.NewInternalError(err)
		return &tbcapi.BlockByHashRawResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &tbcapi.BlockByHashRawResponse{
		Block: b,
	}, nil
}

func (s *Server) handleBlockHeadersByHeightRequest(ctx context.Context, req *tbcapi.BlockHeadersByHeightRequest) (any, error) {
	log.Tracef("handleBtcBlockHeadersByHeightRequest")
	defer log.Tracef("handleBtcBlockHeadersByHeightRequest exit")

	wireBlockHeaders, err := s.BlockHeadersByHeight(ctx, uint64(req.Height))
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

	return &tbcapi.BlockHeadersByHeightResponse{
		BlockHeaders: wireBlockHeadersToTBC(wireBlockHeaders),
	}, nil
}

func (s *Server) handleBlockHeadersByHeightRawRequest(ctx context.Context, req *tbcapi.BlockHeadersByHeightRawRequest) (any, error) {
	log.Tracef("handleBtcBlockHeadersByHeightRawRequest")
	defer log.Tracef("handleBtcBlockHeadersByHeightRawRequest exit")

	rawBlockHeaders, err := s.RawBlockHeadersByHeight(ctx, uint64(req.Height))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return &tbcapi.BlockHeadersByHeightRawResponse{
				Error: protocol.RequestErrorf("block headers not found at height %d", req.Height),
			}, nil
		}

		e := protocol.NewInternalError(err)
		return &tbcapi.BlockHeadersByHeightRawResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &tbcapi.BlockHeadersByHeightRawResponse{
		BlockHeaders: rawBlockHeaders,
	}, nil
}

func (s *Server) handleBlockHeaderBestRawRequest(ctx context.Context, _ *tbcapi.BlockHeaderBestRawRequest) (any, error) {
	log.Tracef("handleBlockHeaderBestRawRequest")
	defer log.Tracef("handleBlockHeaderBestRawRequest exit")

	height, blockHeader, err := s.RawBlockHeaderBest(ctx)
	if err != nil {
		e := protocol.NewInternalError(err)
		return &tbcapi.BlockHeaderBestRawResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &tbcapi.BlockHeaderBestRawResponse{
		Height:      height,
		BlockHeader: blockHeader,
	}, nil
}

func (s *Server) handleBlockHeaderBestRequest(ctx context.Context, _ *tbcapi.BlockHeaderBestRequest) (any, error) {
	log.Tracef("handleBlockHeaderBestRequest")
	defer log.Tracef("handleBlockHeaderBestRequest exit")

	height, blockHeader, err := s.BlockHeaderBest(ctx)
	if err != nil {
		e := protocol.NewInternalError(err)
		return &tbcapi.BlockHeaderBestResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &tbcapi.BlockHeaderBestResponse{
		Height:      height,
		BlockHeader: wireBlockHeaderToTBC(blockHeader),
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

func (s *Server) handleUtxosByAddressRawRequest(ctx context.Context, req *tbcapi.UTXOsByAddressRawRequest) (any, error) {
	log.Tracef("handleUtxosByAddressRawRequest")
	defer log.Tracef("handleUtxosByAddressRawRequest exit")

	utxos, err := s.UtxosByAddress(ctx, req.Address, uint64(req.Start), uint64(req.Count))
	if err != nil {
		if errors.Is(err, level.ErrIterator) {
			e := protocol.NewInternalError(err)
			return &tbcapi.UTXOsByAddressRawResponse{
				Error: e.ProtocolError(),
			}, err
		}

		return &tbcapi.UTXOsByAddressRawResponse{
			Error: protocol.RequestErrorf("error getting utxos for address: %s", req.Address),
		}, nil
	}

	var responseUtxos []api.ByteSlice
	for _, utxo := range utxos {
		responseUtxos = append(responseUtxos, utxo[:])
	}

	return &tbcapi.UTXOsByAddressRawResponse{
		UTXOs: responseUtxos,
	}, nil
}

func (s *Server) handleUtxosByAddressRequest(ctx context.Context, req *tbcapi.UTXOsByAddressRequest) (any, error) {
	log.Tracef("handleUtxosByAddressRequest")
	defer log.Tracef("handleUtxosByAddressRequest exit")

	utxos, err := s.UtxosByAddress(ctx, req.Address, uint64(req.Start), uint64(req.Count))
	if err != nil {
		if errors.Is(err, level.ErrIterator) {
			e := protocol.NewInternalError(err)
			return &tbcapi.UTXOsByAddressResponse{
				Error: e.ProtocolError(),
			}, e
		}

		return &tbcapi.UTXOsByAddressResponse{
			Error: protocol.RequestErrorf("error getting utxos for address: %s", req.Address),
		}, nil
	}

	var responseUtxos []*tbcapi.UTXO
	for _, utxo := range utxos {
		txId, err := chainhash.NewHash(utxo.ScriptHashSlice())
		if err != nil {
			e := protocol.NewInternalError(err)
			return &tbcapi.UTXOsByAddressResponse{
				Error: e.ProtocolError(),
			}, e
		}

		responseUtxos = append(responseUtxos, &tbcapi.UTXO{
			TxId:     *txId,
			Value:    utxo.Value(),
			OutIndex: utxo.OutputIndex(),
		})
	}

	return &tbcapi.UTXOsByAddressResponse{
		UTXOs: responseUtxos,
	}, nil
}

func (s *Server) handleTxByIdRawRequest(ctx context.Context, req *tbcapi.TxByIdRawRequest) (any, error) {
	log.Tracef("handleTxByIdRawRequest")
	defer log.Tracef("handleTxByIdRawRequest exit")

	tx, err := s.TxById(ctx, req.TxID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			responseErr := protocol.RequestErrorf("tx not found: %s", req.TxID)
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

	tx, err := s.TxById(ctx, req.TxID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			responseErr := protocol.RequestErrorf("tx not found: %s", req.TxID)
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
		Tx: wireTxToTBC(tx),
	}, nil
}

func (s *Server) handleTxBroadcastRequest(ctx context.Context, req *tbcapi.TxBroadcastRequest) (any, error) {
	log.Tracef("handleTxBroadcastRequest")
	defer log.Tracef("handleTxBroadcastRequest exit")

	txid, err := s.TxBroadcast(ctx, req.Tx, req.Force)
	if err != nil {
		if errors.Is(err, ErrTxAlreadyBroadcast) || errors.Is(err, ErrTxBroadcastNoPeers) {
			return &tbcapi.TxBroadcastResponse{Error: protocol.RequestError(err)}, err
		}
		e := protocol.NewInternalError(err)
		return &tbcapi.TxBroadcastResponse{Error: e.ProtocolError()}, e
	}

	return &tbcapi.TxBroadcastResponse{TxID: txid}, nil
}

func (s *Server) handleTxBroadcastRawRequest(ctx context.Context, req *tbcapi.TxBroadcastRawRequest) (any, error) {
	log.Tracef("handleTxBroadcastRawRequest")
	defer log.Tracef("handleTxBroadcastRawRequest exit")

	tx := wire.NewMsgTx(0)
	err := tx.Deserialize(bytes.NewBuffer(req.Tx))
	if err != nil {
		return &tbcapi.TxBroadcastResponse{
			Error: protocol.RequestError(err),
		}, nil
	}
	txid, err := s.TxBroadcast(ctx, tx, req.Force)
	if err != nil {
		if errors.Is(err, ErrTxAlreadyBroadcast) || errors.Is(err, ErrTxBroadcastNoPeers) {
			return &tbcapi.TxBroadcastResponse{Error: protocol.RequestError(err)}, err
		}
		e := protocol.NewInternalError(err)
		return &tbcapi.TxBroadcastResponse{Error: e.ProtocolError()}, e
	}

	return &tbcapi.TxBroadcastResponse{TxID: txid}, nil
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
	for {
		// Create random hexadecimal string to use as an ID
		id, err := randHexId(16)
		if err != nil {
			return "", fmt.Errorf("generate session id: %w", err)
		}

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

func randHexId(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// wireBlockToTBC converts a wire.MsgBlock to a tbcapi.Block.
func wireBlockToTBC(block *wire.MsgBlock) *tbcapi.Block {
	txs := make([]tbcapi.Tx, len(block.Transactions))
	for i, tx := range block.Transactions {
		txs[i] = *wireTxToTBC(tx)
	}
	return &tbcapi.Block{
		Hash:   block.BlockHash(),
		Header: *wireBlockHeaderToTBC(&block.Header),
		Txs:    txs,
	}
}

// wireBlockHeadersToBTC converts []*wire.BlockHeader to []*tbcapi.BlockHeader.
func wireBlockHeadersToTBC(bhs []*wire.BlockHeader) []*tbcapi.BlockHeader {
	blockHeaders := make([]*tbcapi.BlockHeader, len(bhs))
	for i, bh := range bhs {
		blockHeaders[i] = wireBlockHeaderToTBC(bh)
	}
	return blockHeaders
}

// wireBlockHeaderToTBC converts a wire.BlockHeader to a tbcapi.BlockHeader.
func wireBlockHeaderToTBC(bh *wire.BlockHeader) *tbcapi.BlockHeader {
	return &tbcapi.BlockHeader{
		Version:    bh.Version,
		PrevHash:   bh.PrevBlock,
		MerkleRoot: bh.MerkleRoot,
		Timestamp:  bh.Timestamp.Unix(),
		Bits:       fmt.Sprintf("%x", bh.Bits),
		Nonce:      bh.Nonce,
	}
}

// wireTxToTBC converts a wire.MsgTx to tbcapi.Tx.
func wireTxToTBC(w *wire.MsgTx) *tbcapi.Tx {
	tx := &tbcapi.Tx{
		Version:  w.Version,
		LockTime: w.LockTime,
		TxIn:     make([]*tbcapi.TxIn, len(w.TxIn)),
		TxOut:    make([]*tbcapi.TxOut, len(w.TxOut)),
	}

	for i, txIn := range w.TxIn {
		tx.TxIn[i] = &tbcapi.TxIn{
			Sequence:        txIn.Sequence,
			SignatureScript: txIn.SignatureScript,
			PreviousOutPoint: tbcapi.OutPoint{
				Hash:  txIn.PreviousOutPoint.Hash,
				Index: txIn.PreviousOutPoint.Index,
			},
			Witness: make(tbcapi.TxWitness, len(txIn.Witness)),
		}

		for wi, witness := range txIn.Witness {
			tx.TxIn[i].Witness[wi] = witness
		}
	}

	for i, txOut := range w.TxOut {
		tx.TxOut[i] = &tbcapi.TxOut{
			Value:    txOut.Value,
			PkScript: txOut.PkScript,
		}
	}

	return tx
}
