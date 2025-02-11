package popm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/api/popapi"
	"github.com/hemilabs/heminetwork/api/protocol"
)

type opnode struct{}

type opnodeWs struct {
	wg             sync.WaitGroup
	addr           string
	conn           *protocol.WSConn
	requestContext context.Context
}

func (o *opnode) handlePingRequest(ctx context.Context, ws *opnodeWs, payload any, id string) error {
	p, ok := payload.(*popapi.PingRequest)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", payload)
	}

	res := &popapi.PingResponse{
		OriginTimestamp: p.Timestamp,
		Timestamp:       time.Now().Unix(),
	}

	if err := popapi.Write(ctx, ws.conn, id, res); err != nil {
		return fmt.Errorf("handlePingRequest write: %v %w", ws.addr, err)
	}

	return nil
}

func (o *opnode) handleL2KeystoneRequest(ctx context.Context, ws *opnodeWs, payload any, id string) (any, error) {
	p, ok := payload.(*popapi.L2KeystoneRequest)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", payload), nil
	}

	_ = p
	res := &popapi.L2KeystoneResponse{
		Error: protocol.RequestErrorf("not yet"),
	}

	return res, nil
}

func (o *opnode) handleRequest(ctx context.Context, ws *opnodeWs, id string, cmd protocol.Command, handler func(ctx context.Context) (any, error)) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	res, err := handler(ctx)
	if err != nil {
		log.Errorf("Failed to handle %s request for %s: %v", cmd, ws.addr, err)
	}
	if res == nil {
		return
	}

	if err = popapi.Write(ctx, ws.conn, id, res); err != nil {
		log.Errorf("Failed to handle %s request for %s: protocol write failed: %v",
			cmd, ws.addr, err)
	}
}

func (o *opnode) handleWebsocketRead(ctx context.Context, ws *opnodeWs) {
	defer ws.wg.Done()

	for {
		cmd, id, payload, err := popapi.Read(ctx, ws.conn)
		if err != nil {
			var ce websocket.CloseError
			if errors.As(err, &ce) {
				panic(fmt.Errorf("handleWebsocketRead: %v", err))
				return
			}
			if errors.Is(err, io.EOF) {
				panic(fmt.Errorf("handleWebsocketRead: EOF"))
				return
			}

			log.Errorf("handleWebsocketRead: %v", err)
			return
		}

		switch cmd {
		case popapi.CmdPingRequest:
			err = o.handlePingRequest(ctx, ws, payload, id)
		case popapi.CmdL2KeystoneRequest:
			handler := func(ctx context.Context) (any, error) {
				return o.handleL2KeystoneRequest(ctx, ws, payload, "")
			}

			go o.handleRequest(ctx, ws, id, cmd, handler)
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

func (o *opnode) handleWebsocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		panic(fmt.Errorf("Failed to accept websocket connection for %s: %v",
			r.RemoteAddr, err))
	}
	defer conn.Close(websocket.StatusNormalClosure, "") // Force close connection

	ws := &opnodeWs{
		addr:           r.RemoteAddr,
		conn:           protocol.NewWSConn(conn),
		requestContext: r.Context(),
	}

	ws.wg.Add(1)
	go o.handleWebsocketRead(r.Context(), ws)

	// Always ping, required by protocol.
	ping := &popapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	log.Tracef("Responding with %v", spew.Sdump(ping))
	if err = popapi.Write(r.Context(), ws.conn, "0", ping); err != nil {
		log.Errorf("Write ping: %v", err)
	}

	log.Infof("Connection from %v", r.RemoteAddr)

	// Wait for termination
	ws.wg.Wait()

	log.Infof("Connection terminated from %v", r.RemoteAddr)
}

func opnodeLaunch(ctx context.Context, wg *sync.WaitGroup, listenAddress string) {
	defer wg.Done()

	o := opnode{}

	mux := http.NewServeMux()
	log.Infof("handle (opnode): %s", popapi.RouteWebsocket)
	mux.HandleFunc(popapi.RouteWebsocket, o.handleWebsocket)

	httpServer := &http.Server{
		Addr:        listenAddress,
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	httpErrCh := make(chan error)
	go func() {
		log.Infof("Listening: %s", listenAddress)
		httpErrCh <- httpServer.ListenAndServe()
	}()
	defer func() {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Errorf("http server exit: %v", err)
			return
		}
		log.Infof("RPC server shutdown cleanly")
	}()

	select {
	case <-ctx.Done():
		return
	case err := <-httpErrCh:
		panic(err)
	}
}

func TestPopMiner(t *testing.T) {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup fake op-node
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				panic("ploink")
			}
		}
	}()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634cb0602599b867332dfec245547baafae40dad247f21564a0de925527f2445a086fd"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	wg.Wait()
}
