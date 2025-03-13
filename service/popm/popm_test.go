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
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/popapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/hemi"
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

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       fillOutBytes("parentephash", 32),
		PrevKeystoneEPHash: fillOutBytes("prevkeystoneephash", 32),
		StateRoot:          fillOutBytes("stateroot", 32),
		EPHash:             fillOutBytes("ephash", 32),
	}

	_ = p
	res := &popapi.L2KeystoneResponse{
		L2Keystones: []*hemi.L2Keystone{&l2Keystone},
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
		case popapi.CmdPingResponse:
			log.Infof("Received ping response from: %v", ws.addr)
			continue
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

	if err = popapi.Write(r.Context(), ws.conn, "0", ping); err != nil {
		log.Errorf("Write ping: %v", err)
	}

	ws.wg.Add(1)
	go func() {
		defer ws.wg.Done()
		for {
			select {
			case <-ws.requestContext.Done():
				return
			case <-time.After(time.Second):
				kssNotif := popapi.L2KeystoneNotfication{}
				if err := popapi.Write(ws.requestContext, ws.conn, "opnode", kssNotif); err != nil {
					panic(fmt.Errorf("handleL2KeystoneNotification write: %v %w", ws.addr, err))
				}
			}
		}
	}()

	// Wait for termination
	ws.wg.Wait()

	log.Infof("Connection terminated from %v", r.RemoteAddr)
}

func opnodeLaunch(ctx context.Context, t *testing.T, wg *sync.WaitGroup, listenAddress string) {
	defer wg.Done()

	o := opnode{}

	mux := http.NewServeMux()
	t.Logf("handle (opnode): %s", popapi.RouteWebsocket)
	mux.HandleFunc(popapi.RouteWebsocket, o.handleWebsocket)

	httpServer := &http.Server{
		Addr:        listenAddress,
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	httpErrCh := make(chan error)
	go func() {
		t.Logf("Listening: %s", listenAddress)
		httpErrCh <- httpServer.ListenAndServe()
	}()
	defer func() {
		if err := httpServer.Shutdown(ctx); err != nil {
			panic(fmt.Errorf("http server exit: %v", err))
		}
		t.Logf("RPC server shutdown cleanly")
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
		opnodeLaunch(ctx, t, &wg, "127.0.0.1:9999")
	}()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634cb0602599b867332dfec245547baafae40dad247f21564a0de925527f2445a086fd"
	// cfg.LogLevel = "popm=TRACE"
	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}
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

	time.Sleep(5 * time.Second)
}

// fillOutBytes will take a string and return a slice of bytes
// with values from the string suffixed until a size with bytes '_'
func fillOutBytes(prefix string, size int) []byte {
	result := []byte(prefix)
	for len(result) < size {
		result = append(result, '_')
	}

	return result
}
