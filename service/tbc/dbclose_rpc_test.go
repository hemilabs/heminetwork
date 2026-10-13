// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcadminapi"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// pipeAddr is the address of a pipeListener.
type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// pipeListener is an in-memory listener.  Its connections are pipes,
// so a goroutine that waits on one is durably blocked in a synctest
// bubble.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		conns: make(chan net.Conn),
		done:  make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddr{}
}

// dial connects to the listener.
func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.done:
	case <-ctx.Done():
	}
	client.Close()
	server.Close()
	return nil, net.ErrClosed
}

// newRPCTestServer returns a server with the state that the RPC and
// admin RPC handlers use.  Its admin hub runs jobs the way Run does.
func newRPCTestServer(t *testing.T, ctx context.Context, db tbcd.Database) *Server {
	t.Helper()

	s := newPeerTestServer(t, db)
	s.cmdsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "rpc_calls_total",
		Help: "The total number of successful RPC commands",
	})
	s.sessions = make(map[string]*tbcWs)
	s.requestTimeout = defaultRequestTimeout
	s.notifier = NewNotifier(false)
	s.adminJWTSecret = testJWTSecret
	s.adminSessions = *newHub(ctx, s.goDB)
	s.ui = NewUtxoIndexer(s.g, 0, nil, nil, nil)
	return s
}

// serveRPC serves the RPC and admin RPC routes of s on an in-memory
// listener until ctx is canceled, the way Run does.  It returns a
// client that connects to that listener.
func serveRPC(t *testing.T, ctx context.Context, s *Server) *http.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc(tbcapi.RouteWebsocket, s.handleWebsocket)
	mux.HandleFunc(tbcadminapi.RouteAdminWs, s.handleAdminWebsocket)
	srv := &http.Server{
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	ln := newPipeListener()
	go func() { _ = srv.Serve(ln) }()
	context.AfterFunc(ctx, func() { _ = srv.Close() })

	return &http.Client{
		Transport: &http.Transport{DialContext: ln.dial},
	}
}

// dialRPC connects to route and reads the ping that the server sends
// first.  It drains every later message, so that the server never
// blocks on a write, and closes the returned channel when the
// connection ends.
func dialRPC(t *testing.T, ctx context.Context, client *http.Client, route string, header http.Header) (*protocol.WSConn, <-chan struct{}) {
	t.Helper()

	c, _, err := websocket.Dial(ctx, "ws://pipe"+route, &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: header,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	conn := protocol.NewWSConn(c)

	cmd, _, _, err := tbcadminapi.Read(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != tbcapi.CmdPingRequest {
		t.Fatalf("first message: got %v, want %v", cmd,
			tbcapi.CmdPingRequest)
	}
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		for {
			if _, _, _, err := tbcadminapi.Read(ctx, conn); err != nil {
				return
			}
		}
	}()
	return conn, ended
}

// adminHeader returns the header that authenticates an admin RPC
// connection.
func adminHeader(t *testing.T) http.Header {
	t.Helper()

	return http.Header{
		"Authorization": []string{"Bearer " + createAdminToken(t)},
	}
}

// TestDBCloseJoinsRPCRequest verifies that the server does not close
// the database while an RPC request still uses it.
func TestDBCloseJoinsRPCRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		db := newParkDB()
		s := newRPCTestServer(t, ctx, bestParkDB{db})
		conn, _ := dialRPC(t, ctx, serveRPC(t, ctx, s),
			tbcapi.RouteWebsocket, nil)

		err := tbcapi.Write(ctx, conn, "1", tbcapi.BlockHeaderBestRequest{})
		if err != nil {
			t.Fatal(err)
		}
		assertCloseJoins(t, s, db)
	})
}

// TestDBCloseJoinsAdminRPCRequest verifies that the server does not
// close the database while an admin RPC request still uses it.
func TestDBCloseJoinsAdminRPCRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		db := newParkDB()
		s := newRPCTestServer(t, ctx, bestParkDB{db})
		conn, _ := dialRPC(t, ctx, serveRPC(t, ctx, s),
			tbcadminapi.RouteAdminWs, adminHeader(t))

		err := tbcadminapi.Write(ctx, conn, "1",
			tbcapi.BlockHeaderBestRequest{})
		if err != nil {
			t.Fatal(err)
		}
		assertCloseJoins(t, s, db)
	})
}

// TestDBCloseJoinsAdminJob verifies that the server does not close the
// database while an admin indexing job still uses it.
func TestDBCloseJoinsAdminJob(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		db := newParkDB()
		s := newRPCTestServer(t, ctx, hashParkDB{db})
		conn, _ := dialRPC(t, ctx, serveRPC(t, ctx, s),
			tbcadminapi.RouteAdminWs, adminHeader(t))

		err := tbcadminapi.Write(ctx, conn, "1",
			tbcadminapi.SyncIndexersToHashRequest{
				Hash: *chaincfg.MainNetParams.GenesisHash,
			})
		if err != nil {
			t.Fatal(err)
		}
		assertCloseJoins(t, s, db)
	})
}

// TestAdminJobNotStartedAfterClose verifies that an admin job does not
// start once dbClose has started, and that the hub reports it.
func TestAdminJobNotStartedAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Server{g: geometryParams{db: newParkDB()}}
		h := newHub(t.Context(), s.goDB)
		if err := s.dbClose(); err != nil {
			t.Fatal(err)
		}

		ran := make(chan struct{})
		jid, err := h.NewJob(SyncIndexersToHashJob,
			func(context.Context, string) { close(ran) })
		if err != nil {
			t.Fatal(err)
		}
		if err := h.StartJob(jid); !errors.Is(err, ErrJobNotStarted) {
			t.Fatalf("start job: got %v, want %v", err,
				ErrJobNotStarted)
		}
		synctest.Wait()
		select {
		case <-ran:
			t.Fatal("job ran after dbClose")
		default:
		}
	})
}

// TestRPCReadStopsAfterClose verifies that the RPC read loop does not
// start a request once dbClose has started, and that the connection
// then ends.
func TestRPCReadStopsAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		db := newParkDB()
		s := newRPCTestServer(t, ctx, bestParkDB{db})
		conn, ended := dialRPC(t, ctx, serveRPC(t, ctx, s),
			tbcapi.RouteWebsocket, nil)
		if err := s.dbClose(); err != nil {
			t.Fatal(err)
		}

		err := tbcapi.Write(ctx, conn, "1", tbcapi.BlockHeaderBestRequest{})
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-db.entered:
			t.Fatal("request handled after dbClose")
		default:
		}
		select {
		case <-ended:
		default:
			t.Fatal("connection did not end")
		}
	})
}

// TestAdminRPCReadStopsAfterClose verifies that the admin RPC read loop
// returns, and does not start the request, when it reads a request
// after dbClose has started.
func TestAdminRPCReadStopsAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		db := newParkDB()
		s := newRPCTestServer(t, ctx, bestParkDB{db})

		// Hand the server end of a websocket connection to the test,
		// so that the test runs the read loop itself.
		accepted := make(chan *websocket.Conn, 1)
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				t.Error(err)
				return
			}
			accepted <- c
		})
		srv := &http.Server{Handler: mux}
		ln := newPipeListener()
		go func() { _ = srv.Serve(ln) }()
		defer srv.Close()

		c, _, err := websocket.Dial(ctx, "ws://pipe/", &websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: &http.Transport{DialContext: ln.dial},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.CloseNow() }()
		sc := <-accepted
		defer func() { _ = sc.CloseNow() }()

		if err := s.dbClose(); err != nil {
			t.Fatal(err)
		}

		ws := &tbcAdminWs{
			tbcWs: tbcWs{addr: "pipe", conn: protocol.NewWSConn(sc)},
		}
		ws.wg.Add(1)
		returned := make(chan struct{})
		go func() {
			s.handleAdminWebsocketRead(ctx, ws)
			close(returned)
		}()

		err = tbcadminapi.Write(ctx, protocol.NewWSConn(c), "1",
			tbcapi.BlockHeaderBestRequest{})
		if err != nil {
			t.Fatal(err)
		}
		// The read loop either returned or waits in its next read.
		synctest.Wait()
		select {
		case <-returned:
		default:
			t.Fatal("read loop did not return after dbClose")
		}
		ws.wg.Wait()
		select {
		case <-db.entered:
			t.Fatal("request handled after dbClose")
		default:
		}
	})
}
