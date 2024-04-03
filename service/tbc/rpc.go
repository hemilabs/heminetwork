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

func (s *Server) handleBtcBlockMetadataByNumRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handleBtcBlockMetadataByNumRequest: %v", ws.addr)
	defer log.Tracef("handleBtcBlockMetadataByNumRequest exit: %v", ws.addr)

	// "decode" the input
	p, ok := payload.(*tbcapi.BtcBlockMetadataByNumRequest)
	if !ok {
		return fmt.Errorf("handleBtcBlockMetadataByNumRequest invalid payload type: %T", payload)
	}

	// use the api to get the block metadata by height
	btcBlockMetadata, err := s.BlockMetadataByHeight(ctx, uint64(p.Height))
	if err != nil {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.BtcBlockMetadataByNumResponse{
			Error: protocol.Errorf("error getting block at height %d: %s", p.Height, err),
		})
	}

	// "encode" output and write response
	return tbcapi.Write(ctx, ws.conn, id, tbcapi.BtcBlockMetadataByNumResponse{
		Block: *btcBlockMetadata,
	})
}

func (s *Server) handleBtcBalanceByAddrRequest(ctx context.Context, ws *tbcWs, payload any, id string) error {
	log.Tracef("handleBtcBalanceByAddrRequest: %v", ws.addr)
	defer log.Tracef("handleBtcBalanceByAddrRequest exit: %v", ws.addr)

	p, ok := payload.(*tbcapi.BtcAddrBalanceRequest)
	if !ok {
		return fmt.Errorf("handleBtcBlockMetadataByNumRequest invalid payload type: %T", payload)
	}

	balance, err := s.AddressBalance(ctx, p.Address)
	if err != nil {
		return tbcapi.Write(ctx, ws.conn, id, tbcapi.BtcAddrBalanceResponse{
			Error: protocol.Errorf("error getting balance for address: %s", err),
		})
	}

	return tbcapi.Write(ctx, ws.conn, id, tbcapi.BtcAddrBalanceResponse{
		Balance: balance,
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
		case tbcapi.CmdBtcBlockMetadataByNumRequest:
			err = s.handleBtcBlockMetadataByNumRequest(ctx, ws, payload, id)
		case tbcapi.CmdBtcAddrBalanceRequest:
			err = s.handleBtcBalanceByAddrRequest(ctx, ws, payload, id)
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
