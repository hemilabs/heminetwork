// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hemilabs/heminetwork/v2/internal/testutil/mock"
)

type serverReply struct {
	ID    int   `json:"id"`
	Error error `json:"error,omitempty"`
}

func defaultNodeState() (int, time.Time) {
	return http.StatusOK, time.Now()
}

func newServer(x int, state func() (int, time.Time)) *httptest.Server {
	if state == nil {
		state = defaultNodeState
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		if r.Header.Get("X-Forwarded-Host") == "" ||
			r.Header.Get("X-Forwarded-For") == "" ||
			r.Header.Get("X-Forwarded-Proto") == "" {
			// When we get here we are getting a health
			// check which does not have headers set. Check
			// to see if the check is expected and panic if
			// it isn't.

			// Decode the request
			var j EthereumRequest
			if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
				panic(err)
			}

			if j.Method != "eth_getBlockByNumber" {
				panic(fmt.Errorf("unexpected health method: %s", j.Method))
			}

			status, blockTime := state()
			result, err := json.Marshal(map[string]any{
				"timestamp": "0x" + strconv.FormatInt(blockTime.Unix(), 16),
			})
			if err != nil {
				panic(fmt.Errorf("marshal result: %w", err))
			}

			w.WriteHeader(status)
			res := &EthereumResponse{
				Version: EthereumVersion,
				ID:      j.ID,
				Result:  result,
			}
			if err := json.NewEncoder(w).Encode(res); err != nil {
				panic(err)
			}
		}

		id := serverReply{ID: x}
		if err := json.NewEncoder(w).Encode(id); err != nil {
			panic(err)
		}
	}))
}

func newHproxy(t *testing.T, servers []string, filter []string) (*Server, *Config) {
	return newHproxyWithPollFrequency(t, servers, filter, time.Second)
}

func newHproxyWithPollFrequency(t *testing.T, servers []string, filter []string, pollFrequency time.Duration) (*Server, *Config) {
	hpCfg := NewDefaultConfig()
	hpCfg.HVMURLs = servers
	hpCfg.LogLevel = "hproxy=TRACE" // XXX figure out why this isn't working
	hpCfg.RequestTimeout = time.Second
	hpCfg.PollFrequency = pollFrequency
	hpCfg.ListenAddress = "127.0.0.1:0"
	hpCfg.ControlAddress = "127.0.0.1:0"
	hpCfg.MethodFilter = filter
	hp, err := NewServer(hpCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err = hp.Run(t.Context())
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// Wait for HTTP server to start
	for {
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(10 * time.Millisecond):
		}
		if addr := hp.HTTPAddress(); addr != nil {
			hpCfg.ListenAddress = addr.String()
			break
		}
	}

	return hp, hpCfg
}

func TestNobodyHome(t *testing.T) {
	servers := []string{"http://localhost:1"}
	_, hpCfg := newHproxy(t, servers, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	c := &http.Client{}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://"+hpCfg.ListenAddress, newEthReq("ping"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	reply, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer reply.Body.Close()

	// Expect 503
	if reply.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("http error mismatch: got %v wanted %v",
			reply.StatusCode, http.StatusServiceUnavailable)
	}

	// Expect EOF
	var jr serverReply
	if err = json.NewDecoder(reply.Body).Decode(&jr); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

// func TestDialTimeout(t *testing.T) {
// XXX tried to build a test for this but did not succeed. Remove or fix.
// }
// clientCount returns the number of tracked clients.
func (s *Server) clientCount() int {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return len(s.clients)
}

// waitClients polls until the client count equals want or the context
// expires.  Returns the final count.
func waitClients(ctx context.Context, hp *Server, want int) int {
	for {
		n := hp.clientCount()
		if n == want {
			return n
		}
		select {
		case <-ctx.Done():
			return n
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// doRequest sends one JSON-RPC request through the proxy using a
// fresh transport (so hproxy sees a distinct client).  Panics on
// failure because t.Fatal in a goroutine only kills that goroutine.
func doRequest(ctx context.Context, addr string, id int) {
	c := &http.Client{Transport: &http.Transport{}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+addr, newEthReq("ping"))
	if err != nil {
		panic(fmt.Errorf("client %d: new request: %w", id, err))
	}
	reply, err := c.Do(req)
	if err != nil {
		panic(fmt.Errorf("client %d: do: %w", id, err))
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusOK {
		panic(fmt.Errorf("client %d: status %d", id, reply.StatusCode))
	}
	hdr := reply.Header.Get("X-Hproxy")
	if hdr == "" {
		panic(fmt.Errorf("client %d: missing X-Hproxy header", id))
	}
	var jr serverReply
	if err = json.NewDecoder(reply.Body).Decode(&jr); err != nil {
		panic(fmt.Errorf("client %d: decode: %w", id, err))
	}
	if strconv.Itoa(jr.ID) != hdr {
		panic(fmt.Errorf("client %d: id mismatch header=%s json=%d", id, hdr, jr.ID))
	}
}

func TestClientReap(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	hpCfg := NewDefaultConfig()
	hpCfg.HVMURLs = []string{s.URL}
	hpCfg.ClientIdleTimeout = mock.InfiniteDuration
	hpCfg.RequestTimeout = time.Second
	hpCfg.PollFrequency = time.Second
	hpCfg.ListenAddress = "127.0.0.1:0"
	hpCfg.ControlAddress = "127.0.0.1:0"
	hpCfg.MethodFilter = []string{"ping"}
	hp, err := NewServer(hpCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := hp.Run(t.Context()); err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	for {
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(10 * time.Millisecond):
		}
		if addr := hp.HTTPAddress(); addr != nil {
			hpCfg.ListenAddress = addr.String()
			break
		}
	}

	const clientCount = 5

	// Phase 1: establish clients with infinite idle timeout.
	var wg sync.WaitGroup
	for i := range clientCount {
		wg.Go(func() {
			doRequest(t.Context(), hpCfg.ListenAddress, i)
		})
	}
	wg.Wait()

	if n := hp.clientCount(); n != clientCount {
		t.Fatalf("after requests: got %d clients, want %d", n, clientCount)
	}

	// Phase 2: reset all timers to 1ns — reaper fires almost immediately.
	hp.mtx.Lock()
	for _, v := range hp.clients {
		v.reset(1 * time.Nanosecond)
	}
	hp.mtx.Unlock()

	got := waitClients(t.Context(), hp, 0)
	if got != 0 {
		t.Fatalf("after reap: got %d clients, want 0", got)
	}

	// Phase 3: new requests after reap must create fresh clients.
	for i := range clientCount {
		wg.Go(func() {
			doRequest(t.Context(), hpCfg.ListenAddress, i+clientCount)
		})
	}
	wg.Wait()

	if n := hp.clientCount(); n != clientCount {
		t.Fatalf("after re-register: got %d clients, want %d", n, clientCount)
	}

	// Phase 4: verify that activity resets the idle timer.  Set a
	// short timeout, then send a request before it expires — the
	// client must survive because the request resets the ticker.
	hp.mtx.Lock()
	for _, v := range hp.clients {
		v.reset(200 * time.Millisecond)
	}
	hp.mtx.Unlock()

	time.Sleep(100 * time.Millisecond)
	doRequest(t.Context(), hpCfg.ListenAddress, 99)
	time.Sleep(150 * time.Millisecond)

	if n := hp.clientCount(); n == 0 {
		t.Fatal("activity should have prevented reap but all clients were reaped")
	}
}

func TestRequestTimeout(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wg.Wait() // Stupid test server is stupid

		// exit so that we can complete the test. If we don't exit the
		// httptest server just sits there.
	}))
	defer s.Close()

	servers := []string{s.URL}
	_, hpCfg := newHproxy(t, servers, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	c := &http.Client{}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://"+hpCfg.ListenAddress, newEthReq("ping"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	reply, err := c.Do(req)
	wg.Done()
	if err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%T", err)
		}
	}
	reply.Body.Close() // shut linter up
}

func newEthReq(method string) io.Reader {
	ec := EthereumRequest{
		Method:  method,
		Params:  nil,
		ID:      ethID(),
		Version: EthereumVersion,
	}
	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(ec); err != nil {
		panic(err)
	}
	return b
}

func TestProxy(t *testing.T) {
	type hpReq struct {
		content        io.Reader
		expectedStatus int
	}

	type testTableItem struct {
		name         string
		requests     []hpReq
		sizeOverride int64
		whitelist    []string
	}

	invalidBody := new(bytes.Buffer)
	invalidBody.Write([]byte("{message: test!}"))

	testTable := []testTableItem{
		{
			name: "invalid format",
			requests: []hpReq{
				{
					content:        invalidBody,
					expectedStatus: http.StatusUnsupportedMediaType,
				},
			},
			whitelist: []string{"valid"},
		},
		{
			name: "request too large",
			requests: []hpReq{
				{
					content:        newEthReq("valid"),
					expectedStatus: http.StatusRequestEntityTooLarge,
				},
			},
			sizeOverride: 1,
			whitelist:    []string{"valid"},
		},
		{
			name: "valid request",
			requests: []hpReq{
				{
					content:        newEthReq("valid"),
					expectedStatus: http.StatusOK,
				},
			},
			whitelist: []string{"valid"},
		},
		{
			name: "filtered method",
			requests: []hpReq{
				{
					content:        newEthReq("invalid"),
					expectedStatus: http.StatusForbidden,
				},
			},
			whitelist: []string{"valid"},
		},
		{
			name: "mixed methods",
			requests: []hpReq{
				{
					content:        newEthReq("valid"),
					expectedStatus: http.StatusOK,
				},
				{
					content:        newEthReq("invalid"),
					expectedStatus: http.StatusForbidden,
				},
			},
			whitelist: []string{"valid"},
		},
		{
			name: "empty whitelist",
			requests: []hpReq{
				{
					content:        newEthReq("valid"),
					expectedStatus: http.StatusForbidden,
				},
				{
					content:        newEthReq("invalid"),
					expectedStatus: http.StatusForbidden,
				},
			},
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			serverID := 1337
			s := newServer(serverID, nil)
			defer s.Close()
			servers := []string{s.URL}

			// Setup hproxy
			hps, hpCfg := newHproxy(t, servers, tti.whitelist)
			time.Sleep(250 * time.Millisecond)

			if tti.sizeOverride != 0 {
				hps.maxRequestSize = tti.sizeOverride
			}

			for i, hpr := range tti.requests {
				c := &http.Client{}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet,
					"http://"+hpCfg.ListenAddress, hpr.content)
				if err != nil {
					t.Error(fmt.Errorf("get %v: %w", i, err))
					continue
				}

				reply, err := c.Do(req)
				if err != nil {
					t.Errorf("get %v: %v", i, err)
					continue
				}
				defer reply.Body.Close()

				if reply.StatusCode != hpr.expectedStatus {
					t.Errorf("status code %v: got %v, expected %v", i,
						reply.StatusCode, hpr.expectedStatus)
					continue
				}

				if reply.StatusCode != http.StatusOK {
					continue
				}

				// Require X-Hproxy
				ids := reply.Header.Get("X-Hproxy")
				if ids == "" {
					t.Errorf("header get %v: expected X-Hproxy being set", i)
					continue
				}

				// Read body
				var jr serverReply
				if err = json.NewDecoder(reply.Body).Decode(&jr); err != nil {
					t.Errorf("decode: %v", err)
					continue
				}
				if jr.ID != serverID {
					t.Errorf("invalid response %v: got %v, wanted %v", i, jr.ID, serverID)
				}
			}
		})
	}
}

func TestFanout(t *testing.T) {
	serverCount := 5
	servers := make([]string, 0, serverCount)
	for i := range serverCount {
		s := newServer(i, nil)
		defer s.Close()

		// Verify url
		_, err := url.Parse(s.URL)
		if err != nil {
			t.Fatalf("server %v: %v", i, err)
		}
		servers = append(servers, s.URL)
	}

	testDuration := 5 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), testDuration)
	_ = ctx
	defer cancel()

	// Setup hproxy
	_, hpCfg := newHproxy(t, servers, []string{"ping"})
	time.Sleep(500 * time.Millisecond) // Let proxies be marked healthy

	// clients
	var (
		wg sync.WaitGroup
		am sync.Mutex
	)
	clientCount := serverCount * 100
	answers := make([]int, serverCount)
	for i := range clientCount {
		wg.Add(1)
		go func(x int) {
			defer wg.Done()
			c := &http.Client{}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				"http://"+hpCfg.ListenAddress, newEthReq("ping"))
			if err != nil {
				panic(fmt.Errorf("get %v: %w", x, err))
			}
			reply, err := c.Do(req)
			if err != nil {
				panic(fmt.Errorf("do %v: %w", x, err))
			}
			defer reply.Body.Close()
			switch reply.StatusCode {
			case http.StatusOK:
			default:
				panic(fmt.Errorf("%v replied %v",
					hpCfg.ListenAddress, reply.StatusCode))
			}

			// Require X-Hproxy
			ids := reply.Header.Get("X-Hproxy")
			if ids == "" {
				panic("expected X-Hproxy being set")
			}

			var jr serverReply
			if err = json.NewDecoder(reply.Body).Decode(&jr); err != nil {
				panic(fmt.Errorf("decode %v: %w", x, err))
			}
			am.Lock()
			answers[jr.ID]++
			am.Unlock()

			// Verify that json id matches header id, a bit silly
			// but keeps us honest.
			if strconv.Itoa(jr.ID) != ids {
				panic(fmt.Errorf("id mismatch header: %s, json: %d", ids, jr.ID))
			}
		}(i)
		runtime.Gosched()
	}

	wg.Wait()
	cancel()

	// Allow 50% variance, this is to accommodate trash CI boxes.
	acceptable := (clientCount / serverCount) / (100 / 50)
	upperBound := (clientCount / serverCount) + acceptable
	lowerBound := (clientCount / serverCount) - acceptable
	total := 0
	for k, v := range answers {
		if v < lowerBound || v > upperBound {
			t.Fatalf("%v out of bounds lower %v upper %v got %v",
				k, lowerBound, upperBound, v)
		}
		t.Logf("node %v: %v", k, v)
		total += v
	}
	if total != clientCount {
		t.Fatalf("expected %v connections, got %v", clientCount, total)
	}
}

func TestPersistence(t *testing.T) {
	serverCount := 5

	servers := make([]string, 0, serverCount)
	for i := range serverCount {
		s := newServer(i, nil)
		defer s.Close()

		// Verify url
		_, err := url.Parse(s.URL)
		if err != nil {
			t.Fatalf("server %v: %v", i, err)
		}
		servers = append(servers, s.URL)
	}

	testDuration := 5 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), testDuration)
	_ = ctx
	defer cancel()

	// Setup hproxy
	_, hpCfg := newHproxy(t, servers, []string{"ping"})
	time.Sleep(500 * time.Millisecond) // Let proxies be marked healthy

	// single client
	var am sync.Mutex
	clientCount := serverCount * 100
	answers := make([]int, serverCount)
	c := &http.Client{
		Transport: http.DefaultTransport,
	}
	for i := range clientCount {
		x := i
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://"+hpCfg.ListenAddress, newEthReq("ping"))
		if err != nil {
			t.Fatalf("get %v: %v", x, err)
		}
		reply, err := c.Do(req)
		if err != nil {
			t.Fatalf("do %v: %v", x, err)
		}
		defer reply.Body.Close()
		switch reply.StatusCode {
		case http.StatusOK:
		default:
			panic(fmt.Errorf("%v replied %v",
				hpCfg.ListenAddress, reply.StatusCode))
		}

		// Require X-Hproxy
		ids := reply.Header.Get("X-Hproxy")
		if ids == "" {
			panic("expected X-Hproxy being set")
		}

		var jr serverReply
		if err = json.NewDecoder(reply.Body).Decode(&jr); err != nil {
			t.Fatalf("decode %v: %v", x, err)
		}
		// Discard so that we can reuse connection
		if _, err := io.Copy(io.Discard, reply.Body); err != nil {
			t.Fatal(err)
		}

		am.Lock()
		answers[jr.ID]++
		am.Unlock()

		// Verify that json id matches header id, a bit silly
		// but keeps us honest.
		if strconv.Itoa(jr.ID) != ids {
			panic(fmt.Errorf("id mismatch header: %s, json: %d", ids, jr.ID))
		}
	}

	cancel()

	total := 0
	for k, v := range answers {
		t.Logf("node %v: %v", k, v)
		total += v
		if k != 0 && v != 0 {
			t.Fatalf("connection was not persisted, node %v was used", k)
		}
	}
	if total != clientCount {
		t.Fatalf("expected %v connections, got %v", clientCount, total)
	}
}

func TestFailover(t *testing.T) {
	serverCount := 5

	servers := make([]string, 0, serverCount)
	for i := range serverCount {
		s := newServer(i, nil)
		defer s.Close()

		// Verify url
		_, err := url.Parse(s.URL)
		if err != nil {
			t.Fatalf("server %v: %v", i, err)
		}
		servers = append(servers, s.URL)
	}

	testDuration := 5 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), testDuration)
	defer cancel()

	// Setup hproxy with long poll frequency to prevent monitor from
	// re-marking nodes as healthy after we force them unhealthy.
	hp, hpCfg := newHproxyWithPollFrequency(t, servers, []string{"ping"}, time.Hour)
	time.Sleep(500 * time.Millisecond) // Let proxies be marked healthy

	// Do 10 command and fail node 0

	// single client
	var am sync.Mutex
	clientCount := serverCount * 100
	answers := make([]int, serverCount)
	c := &http.Client{
		Transport: http.DefaultTransport,
	}
	var nextUnhealthy int
	for i := range clientCount {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://"+hpCfg.ListenAddress, newEthReq("ping"))
		if err != nil {
			t.Fatal(err)
		}
		reply, err := c.Do(req)
		if err != nil {
			t.Fatalf("get %v: %v", i, err)
		}
		defer reply.Body.Close()
		switch reply.StatusCode {
		case http.StatusOK:
		default:
			panic(fmt.Errorf("%v replied %v",
				hpCfg.ListenAddress, reply.StatusCode))
		}

		// Require X-Hproxy
		ids := reply.Header.Get("X-Hproxy")
		if ids == "" {
			panic("expected X-Hproxy being set")
		}

		var jr serverReply
		if err = json.NewDecoder(reply.Body).Decode(&jr); err != nil {
			t.Fatalf("decode %v: %v", i, err)
		}
		// Discard so that we can reuse connection
		if _, err := io.Copy(io.Discard, reply.Body); err != nil {
			t.Fatal(err)
		}

		am.Lock()
		answers[jr.ID]++
		count := answers[jr.ID]
		am.Unlock()

		// Verify that json id matches header id, a bit silly
		// but keeps us honest.
		if strconv.Itoa(jr.ID) != ids {
			panic(fmt.Errorf("id mismatch header: %s, json: %d", ids, jr.ID))
		}

		// Mark node unhealthy after it has received 100 requests
		if jr.ID == nextUnhealthy && count == 100 && nextUnhealthy < serverCount-1 {
			t.Logf("marking node unhealthy: %v", nextUnhealthy)
			hp.nodeUnhealthy(nextUnhealthy, errors.New("forced"))
			nextUnhealthy++
		}
	}

	cancel()

	total := 0
	for k, got := range answers {
		t.Logf("node %v: %v", k, got)
		if want := 100; got != want {
			t.Fatalf("unexpected number of calls node %v: got %v, want %v",
				k, got, want)
		}
		total += got
	}
	if total != clientCount {
		t.Fatalf("got %v answers, want %v", total, clientCount)
	}
}

func TestNodePoking(t *testing.T) {
	const (
		healthyCount   = 5
		unhealthyCount = 4
	)

	servers := make([]string, 0, 5)
	for i := range healthyCount {
		s := newServer(i, nil)
		t.Cleanup(s.Close)
		servers = append(servers, s.URL)
	}
	for i := range unhealthyCount / 2 {
		s := newServer(i, func() (int, time.Time) {
			// Block timestamp is 5 seconds ago, 500 status
			return http.StatusInternalServerError, time.Now().Add(-5 * time.Second)
		})
		t.Cleanup(s.Close)
		servers = append(servers, s.URL)
	}
	for i := range unhealthyCount / 2 {
		s := newServer(i, func() (int, time.Time) {
			// Block timestamp is 45 seconds ago, OK status
			return http.StatusOK, time.Now().Add(-45 * time.Second)
		})
		t.Cleanup(s.Close)
		servers = append(servers, s.URL)
	}

	// Setup hproxy
	hp, _ := newHproxy(t, servers, []string{"ping"})
	time.Sleep(500 * time.Millisecond) // Let healthcheck happen

	// Count healthy and unhealthy nodes
	var healthy, unhealthy int
	hp.mtx.RLock()
	for _, h := range hp.hvmHandlers {
		if h.state == StateHealthy {
			healthy++
			continue
		}
		unhealthy++
	}
	hp.mtx.RUnlock()
	t.Logf("healthy: %v, unhealthy: %v", healthy, unhealthy)

	if healthy != healthyCount {
		t.Errorf("got %v healthy, want %v", healthy, healthyCount)
	}
	if unhealthy != unhealthyCount {
		t.Errorf("got %v unhealthy, want %v", unhealthy, unhealthyCount)
	}
}

func TestServerTimeoutsConfigured(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	hp, _ := newHproxy(t, []string{s.URL}, []string{"ping"})

	hp.mtx.RLock()
	srv := hp.httpServer
	hp.mtx.RUnlock()

	if srv.ReadHeaderTimeout != DefaultReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, DefaultReadHeaderTimeout)
	}
	if srv.ReadTimeout != DefaultReadTimeout {
		t.Fatalf("ReadTimeout = %v, want %v", srv.ReadTimeout, DefaultReadTimeout)
	}
	if srv.WriteTimeout != DefaultWriteTimeout {
		t.Fatalf("WriteTimeout = %v, want %v", srv.WriteTimeout, DefaultWriteTimeout)
	}
	if srv.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", srv.IdleTimeout, DefaultIdleTimeout)
	}
}

func TestServerTimeoutsCustom(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	cfg := NewDefaultConfig()
	cfg.HVMURLs = []string{s.URL}
	cfg.RequestTimeout = time.Second
	cfg.PollFrequency = time.Second
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.ControlAddress = "127.0.0.1:0"
	cfg.ReadHeaderTimeout = 5 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 20 * time.Second
	cfg.IdleTimeout = 45 * time.Second

	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := hp.Run(t.Context()); err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	for {
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(10 * time.Millisecond):
		}
		if hp.HTTPAddress() != nil {
			break
		}
	}

	hp.mtx.RLock()
	srv := hp.httpServer
	hp.mtx.RUnlock()

	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want 5s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 15*time.Second {
		t.Fatalf("ReadTimeout = %v, want 15s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 20*time.Second {
		t.Fatalf("WriteTimeout = %v, want 20s", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 45*time.Second {
		t.Fatalf("IdleTimeout = %v, want 45s", srv.IdleTimeout)
	}
}

func TestControlAddBodyLimit(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	buf.WriteByte('[')
	entry := []byte(`{"node_url":"http://x.example.com:8545"},`)
	for buf.Len() < int(DefaultMaxControlBodySize)+1 {
		buf.Write(entry)
	}
	buf.Truncate(buf.Len() - 1)
	buf.WriteByte(']')

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader(buf.Bytes()))
	rec := httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", rec.Code)
	}
}

// --- NewServer edge cases --------------------------------------------------

func TestNewServerNilConfig(t *testing.T) {
	s, err := NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg == nil {
		t.Fatal("expected default config")
	}
}

func TestNewServerBadNetwork(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.Network = "krypton"
	_, err := NewServer(cfg)
	if err == nil {
		t.Fatal("expected error for unknown network")
	}
}

func TestNewServerBadMaxRequestSize(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.MaxRequestSize = "not-a-size"
	_, err := NewServer(cfg)
	if err == nil {
		t.Fatal("expected error for bad max request size")
	}
}

func TestNewServerZeroRequestTimeout(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.RequestTimeout = 0
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.RequestTimeout != DefaultRequestTimeout {
		t.Fatalf("expected default timeout, got %v", s.cfg.RequestTimeout)
	}
}

// --- ForbiddenMethodError --------------------------------------------------

func TestForbiddenMethodError(t *testing.T) {
	e := ForbiddenMethodError{method: "debug_traceCall"}
	if e.Error() != "method not allowed: debug_traceCall" {
		t.Fatalf("unexpected error string: %v", e.Error())
	}
	if !errors.Is(e, ErrForbiddenMethod) {
		t.Fatal("ForbiddenMethodError should match ErrForbiddenMethod")
	}
}

// --- Prometheus gauge helpers ----------------------------------------------

func TestPromGauges(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	hp.mtx.Lock()
	hp.promHealth = health{
		NewNodes:       1,
		HealthyNodes:   2,
		UnhealthyNodes: 3,
		RemovedNodes:   4,
	}
	hp.persistentConnections = 5
	hp.proxyCalls = 10
	hp.setupDuration = 100
	hp.proxyDuration = 200
	hp.mtx.Unlock()

	if v := hp.promHVMNew(); v != 1 {
		t.Fatalf("promHVMNew = %v, want 1", v)
	}
	if v := hp.promHVMHealthy(); v != 2 {
		t.Fatalf("promHVMHealthy = %v, want 2", v)
	}
	if v := hp.promHVMUnhealthy(); v != 3 {
		t.Fatalf("promHVMUnhealthy = %v, want 3", v)
	}
	if v := hp.promHVMRemoved(); v != 4 {
		t.Fatalf("promHVMRemoved = %v, want 4", v)
	}
	if v := hp.promConnections(); v != 5 {
		t.Fatalf("promConnections = %v, want 5", v)
	}
	if v := hp.promAvgClientSetupLatency(); v != 10 {
		t.Fatalf("promAvgClientSetupLatency = %v, want 10", v)
	}
	if v := hp.promAvgProxyLatency(); v != 20 {
		t.Fatalf("promAvgProxyLatency = %v, want 20", v)
	}
}

func TestPromLatencyZeroCalls(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v := hp.promAvgClientSetupLatency(); v != 0 {
		t.Fatalf("expected 0 with zero calls, got %v", v)
	}
	if v := hp.promAvgProxyLatency(); v != 0 {
		t.Fatalf("expected 0 with zero calls, got %v", v)
	}
}

func TestCollectors(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c1 := hp.Collectors()
	if len(c1) == 0 {
		t.Fatal("expected collectors")
	}
	c2 := hp.Collectors()
	if len(c1) != len(c2) {
		t.Fatal("collectors should be cached")
	}
}

// --- Running / promRunning -------------------------------------------------

func TestRunningAndPromRunning(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if hp.running() {
		t.Fatal("should not be running initially")
	}
	if v := hp.promRunning(); v != 0 {
		t.Fatalf("promRunning = %v, want 0", v)
	}

	hp.testAndSetRunning(true)

	if !hp.running() {
		t.Fatal("should be running after set")
	}
	if v := hp.promRunning(); v != 1 {
		t.Fatalf("promRunning = %v, want 1", v)
	}
}

// --- isHealthy / health ----------------------------------------------------

func TestIsHealthy(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	hp, _ := newHproxy(t, []string{s.URL}, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	if !hp.isHealthy(t.Context()) {
		t.Fatal("expected healthy with one live backend")
	}

	ok, _, err := hp.health(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("health should report healthy")
	}
}

func TestIsHealthyUnhealthy(t *testing.T) {
	hp, _ := newHproxy(t, []string{"http://localhost:1"}, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	if hp.isHealthy(t.Context()) {
		t.Fatal("expected unhealthy with dead backend")
	}
}

// --- Control add/remove/list via handler -----------------------------------

func TestControlAddRemoveList(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	addBody := `[{"node_url":"http://add1.example.com:8545"},{"node_url":"http://add2.example.com:8545"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte(addBody)))
	rec := httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("add: expected 200, got %d", rec.Code)
	}

	// List should return 2 nodes.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteControlList, nil)
	rec = httptest.NewRecorder()
	hp.handleControlListRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.Code)
	}
	var listed []NodeHealth
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("list: expected 2 nodes, got %d", len(listed))
	}

	// Remove one.
	removeBody := `[{"node_url":"http://add1.example.com:8545"}]`
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader([]byte(removeBody)))
	rec = httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove: expected 200, got %d", rec.Code)
	}

	// List again — still 2 entries but one is "removed".
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteControlList, nil)
	rec = httptest.NewRecorder()
	hp.handleControlListRequest(rec, req)
	var listed2 []NodeHealth
	if err := json.NewDecoder(rec.Body).Decode(&listed2); err != nil {
		t.Fatal(err)
	}
	removed := 0
	for _, n := range listed2 {
		if n.Status == "removed" {
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("expected 1 removed node, got %d", removed)
	}
}

func TestControlAddDuplicate(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `[{"node_url":"http://dup.example.com:8545"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first add: expected 200, got %d", rec.Code)
	}

	// Second add — duplicate error in response body.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte(body)))
	rec = httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second add: expected 200, got %d", rec.Code)
	}
	var nes []NodeError
	if err := json.NewDecoder(rec.Body).Decode(&nes); err != nil {
		t.Fatal(err)
	}
	if len(nes) != 1 || nes[0].Error != "duplicate" {
		t.Fatalf("expected duplicate error, got %+v", nes)
	}
}

func TestControlAddBadScheme(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `[{"node_url":"ftp://bad.example.com"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)
	var nes []NodeError
	if err := json.NewDecoder(rec.Body).Decode(&nes); err != nil {
		t.Fatal(err)
	}
	if len(nes) != 1 || nes[0].Error == "" {
		t.Fatalf("expected unsupported scheme error, got %+v", nes)
	}
}

func TestControlAddBadJSON(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestControlRemoveBadJSON(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestControlRemoveNotFound(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `[{"node_url":"http://ghost.example.com:8545"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)
	var nes []NodeError
	if err := json.NewDecoder(rec.Body).Decode(&nes); err != nil {
		t.Fatal(err)
	}
	if len(nes) != 1 || nes[0].Error != "not found" {
		t.Fatalf("expected not found error, got %+v", nes)
	}
}

func TestControlRemoveAlreadyRemoved(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `[{"node_url":"http://once.example.com:8545"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader([]byte(body)))
	rec = httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)

	// Remove again.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader([]byte(body)))
	rec = httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)
	var nes []NodeError
	if err := json.NewDecoder(rec.Body).Decode(&nes); err != nil {
		t.Fatal(err)
	}
	if len(nes) != 1 || nes[0].Error != "already removed" {
		t.Fatalf("expected already removed error, got %+v", nes)
	}
}

func TestControlAddReAddsRemovedNode(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `[{"node_url":"http://comeback.example.com:8545"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader([]byte(body)))
	rec = httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)

	// Re-add — should succeed (re-adds the removed node).
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte(body)))
	rec = httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)
	var nes []NodeError
	if err := json.NewDecoder(rec.Body).Decode(&nes); err != nil {
		t.Fatal(err)
	}
	if len(nes) != 1 || nes[0].Error != "" {
		t.Fatalf("expected no error on re-add, got %+v", nes)
	}
}

func TestControlRemoveBodyLimit(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	buf.WriteByte('[')
	entry := []byte(`{"node_url":"http://x.example.com:8545"},`)
	for buf.Len() < int(DefaultMaxControlBodySize)+1 {
		buf.Write(entry)
	}
	buf.Truncate(buf.Len() - 1)
	buf.WriteByte(']')

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader(buf.Bytes()))
	rec := httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", rec.Code)
	}
}

// --- Run double-start ------------------------------------------------------

func TestRunDoubleStart(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	hp, _ := newHproxy(t, []string{s.URL}, []string{"ping"})

	// hp is already running via newHproxy. Try to run again.
	err := hp.Run(t.Context())
	if err == nil {
		t.Fatal("expected error on double start")
	}
}

// --- CallEthereum ----------------------------------------------------------

func TestCallEthereum(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EthereumRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			panic(err)
		}
		resp := EthereumResponse{
			Version: EthereumVersion,
			ID:      req.ID,
			Result:  json.RawMessage(`"0x1"`),
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			panic(err)
		}
	}))
	defer srv.Close()

	resp, err := CallEthereum(t.Context(), srv.Client(), srv.URL, "eth_blockNumber")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Result) != `"0x1"` {
		t.Fatalf("unexpected result: %s", resp.Result)
	}
}

func TestCallEthereumBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := CallEthereum(t.Context(), srv.Client(), srv.URL, "eth_blockNumber")
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
}

func TestCallEthereumBadVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EthereumRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			panic(err)
		}
		resp := EthereumResponse{
			Version: "1.0",
			ID:      req.ID,
			Result:  json.RawMessage(`"0x1"`),
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			panic(err)
		}
	}))
	defer srv.Close()

	_, err := CallEthereum(t.Context(), srv.Client(), srv.URL, "eth_blockNumber")
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestCallEthereumBadID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := EthereumResponse{
			Version: EthereumVersion,
			ID:      "wrong-id",
			Result:  json.RawMessage(`"0x1"`),
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			panic(err)
		}
	}))
	defer srv.Close()

	_, err := CallEthereum(t.Context(), srv.Client(), srv.URL, "eth_blockNumber")
	if err == nil {
		t.Fatal("expected error for mismatched ID")
	}
}

func TestCallEthereumBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := CallEthereum(t.Context(), srv.Client(), srv.URL, "eth_blockNumber")
	if err == nil {
		t.Fatal("expected error for bad JSON response")
	}
}

func TestCallEthereumBadURL(t *testing.T) {
	_, err := CallEthereum(t.Context(), http.DefaultClient, "://bad", "eth_blockNumber")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

func TestRemoveBadScheme(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `[{"node_url":"ftp://bad.example.com"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)
	var nes []NodeError
	if err := json.NewDecoder(rec.Body).Decode(&nes); err != nil {
		t.Fatal(err)
	}
	if len(nes) != 1 || nes[0].Error == "" {
		t.Fatalf("expected unsupported scheme error, got %+v", nes)
	}
}

func TestNewServerOverflowRequestSize(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.MaxRequestSize = "10EiB"
	_, err := NewServer(cfg)
	if err == nil {
		t.Fatal("expected error for overflow request size")
	}
}

func TestControlListWithConnectedClients(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	hp, hpCfg := newHproxy(t, []string{s.URL}, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	body := `{"jsonrpc":"2.0","method":"ping","id":"1"}`
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+hpCfg.ListenAddress+"/", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteControlList, nil)
	rec := httptest.NewRecorder()
	hp.handleControlListRequest(rec, req)
	var listed []NodeHealth
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected 1 node, got %d", len(listed))
	}
	if listed[0].Connections < 1 {
		t.Fatalf("expected at least 1 connection, got %d", listed[0].Connections)
	}
}

func TestHTTPAddressNil(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if hp.HTTPAddress() != nil {
		t.Fatal("expected nil address before Run")
	}
}

func TestNodeAddBadURL(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `[{"node_url":"://bad-url"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlAdd,
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	hp.handleControlAddRequest(rec, req)
	var nes []NodeError
	if err := json.NewDecoder(rec.Body).Decode(&nes); err != nil {
		t.Fatal(err)
	}
	if len(nes) != 1 || nes[0].Error == "" {
		t.Fatalf("expected invalid url error, got %+v", nes)
	}
}

func TestRemoveBadURL(t *testing.T) {
	cfg := NewDefaultConfig()
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `[{"node_url":"://bad-url"}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteControlRemove,
		bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	hp.handleControlRemoveRequest(rec, req)
	var nes []NodeError
	if err := json.NewDecoder(rec.Body).Decode(&nes); err != nil {
		t.Fatal(err)
	}
	if len(nes) != 1 || nes[0].Error == "" {
		t.Fatalf("expected invalid url error, got %+v", nes)
	}
}

func postProxy(t *testing.T, addr string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+addr+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestFilterRequestMaxBytes(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	hp, hpCfg := newHproxy(t, []string{s.URL}, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	big := make([]byte, hp.maxRequestSize+1)
	for i := range big {
		big[i] = 'x'
	}

	resp := postProxy(t, hpCfg.ListenAddress, big)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}
}

func TestFilterRequestBadJSON(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	_, hpCfg := newHproxy(t, []string{s.URL}, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	resp := postProxy(t, hpCfg.ListenAddress, []byte("not json"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", resp.StatusCode)
	}
}

func TestFilterRequestForbiddenMethod(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	_, hpCfg := newHproxy(t, []string{s.URL}, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	body := `{"jsonrpc":"2.0","method":"debug_traceCall","id":"1"}`
	resp := postProxy(t, hpCfg.ListenAddress, []byte(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxyNoCandidates(t *testing.T) {
	_, hpCfg := newHproxy(t, []string{"http://localhost:1"}, []string{"ping"})
	time.Sleep(250 * time.Millisecond)

	body := `{"jsonrpc":"2.0","method":"ping","id":"1"}`
	resp := postProxy(t, hpCfg.ListenAddress, []byte(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestRunNoURLs(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.HVMURLs = nil
	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = hp.Run(t.Context())
	if err == nil {
		t.Fatal("expected error for no HVM URLs")
	}
}

func TestRunWithPrometheus(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	cfg := NewDefaultConfig()
	cfg.HVMURLs = []string{s.URL}
	cfg.MethodFilter = []string{"ping"}
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.ControlAddress = "127.0.0.1:0"
	cfg.PrometheusListenAddress = "127.0.0.1:0"
	cfg.RequestTimeout = time.Second
	cfg.PollFrequency = time.Second

	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()

	go func() {
		err := hp.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			panic(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for server to start")
		case <-time.After(10 * time.Millisecond):
		}
		if addr := hp.HTTPAddress(); addr != nil {
			break
		}
	}

	time.Sleep(5500 * time.Millisecond)
	cancel()
}

func TestRunWithPprof(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()

	cfg := NewDefaultConfig()
	cfg.HVMURLs = []string{s.URL}
	cfg.MethodFilter = []string{"ping"}
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.ControlAddress = "127.0.0.1:0"
	cfg.PprofListenAddress = "127.0.0.1:0"
	cfg.RequestTimeout = time.Second
	cfg.PollFrequency = time.Second

	hp, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		err := hp.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for server to start")
		case <-time.After(10 * time.Millisecond):
		}
		if addr := hp.HTTPAddress(); addr != nil {
			break
		}
	}

	time.Sleep(250 * time.Millisecond)
	cancel()
}
