// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package twc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/twcapi"
)

type twcWs struct {
	wg             sync.WaitGroup
	addr           string
	conn           *protocol.WSConn
	requestContext context.Context
}

func (s *Server) handleWebsocketRead(ctx context.Context, ws *twcWs) {
	defer ws.wg.Done()

	log.Tracef("handleWebsocketRead: %v", ws.addr)
	defer log.Tracef("handleWebsocketRead exit: %v", ws.addr)

	for {
		cmd, id, payload, err := twcapi.Read(ctx, ws.conn)
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
		case twcapi.CmdPingRequest:
			err = s.handlePingRequest(ctx, ws, payload, id)

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

func (s *Server) handlePingRequest(ctx context.Context, ws *twcWs, payload any, id string) error {
	log.Tracef("handlePingRequest: %v", ws.addr)
	defer log.Tracef("handlePingRequest exit: %v", ws.addr)

	p, ok := payload.(*twcapi.PingRequest)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", payload)
	}

	res := &twcapi.PingResponse{
		OriginTimestamp: p.Timestamp,
		Timestamp:       time.Now().Unix(),
	}

	// XXX: spew.Sdump should only be called when the log level is enabled.
	log.Tracef("responding with %v", spew.Sdump(res))

	if err := twcapi.Write(ctx, ws.conn, id, res); err != nil {
		return fmt.Errorf("handlePingRequest write: %v %w", ws.addr, err)
	}

	// Ping request processed successfully
	return nil
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

	ws := &twcWs{
		addr:           r.RemoteAddr,
		conn:           protocol.NewWSConn(conn),
		requestContext: r.Context(),
	}

	ws.wg.Add(1)
	go s.handleWebsocketRead(r.Context(), ws)

	// Always ping, required by protocol.
	ping := &twcapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	log.Tracef("Responding with %v", spew.Sdump(ping))
	if err = twcapi.Write(r.Context(), ws.conn, "0", ping); err != nil {
		log.Errorf("Write ping: %v", err)
	}

	log.Infof("Connection from %v", r.RemoteAddr)

	// Wait for termination
	ws.wg.Wait()

	log.Infof("Connection terminated from %v", r.RemoteAddr)
}
