// Copyright (c) 2025 Hemi Labs, Inc.
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

	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/v2/internal/testutil"
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
	hpCfg.ListenAddress = "127.0.0.1:" + testutil.FreePort()
	hpCfg.ControlAddress = "127.0.0.1:" + testutil.FreePort()
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
func TestClientReap(t *testing.T) {
	s := newServer(0, nil)
	defer s.Close()
	servers := []string{s.URL}

	hpCfg := NewDefaultConfig()
	hpCfg.HVMURLs = servers
	hpCfg.LogLevel = "hproxy=TRACE"                 // XXX figure out why this isn't working
	hpCfg.ClientIdleTimeout = mock.InfiniteDuration // will timeout manually later
	hpCfg.RequestTimeout = time.Second
	hpCfg.PollFrequency = time.Second
	hpCfg.ListenAddress = "127.0.0.1:" + testutil.FreePort()
	hpCfg.ControlAddress = "127.0.0.1:" + testutil.FreePort()
	hpCfg.MethodFilter = []string{"ping"}
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

	time.Sleep(250 * time.Millisecond)

	testDuration := 5 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), testDuration)
	defer cancel()

	// Launch 5 clients
	var wg sync.WaitGroup
	clientCount := 5
	for i := 0; i < clientCount; i++ {
		wg.Add(1)
		go func(x int) {
			defer wg.Done()
			// This uses a new http.Transport to prevent using idle connections,
			// which would result in a new client not being created.
			c := &http.Client{Transport: &http.Transport{}}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
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

			// Verify that json id matches header id, a bit silly
			// but keeps us honest.
			if strconv.Itoa(jr.ID) != ids {
				panic(fmt.Errorf("id mismatch header: %s, json: %d", ids, jr.ID))
			}
		}(i)
	}

	wg.Wait()
	hp.mtx.RLock()
	if len(hp.clients) != clientCount {
		t.Fatalf("got %v clients, want %v", len(hp.clients), clientCount)
	}
	hp.mtx.RUnlock()

	hp.mtx.Lock()
	for _, v := range hp.clients {
		v.reset(1 * time.Nanosecond)
	}
	hp.mtx.Unlock()

	time.Sleep(250 * time.Millisecond)

	hp.mtx.RLock()
	if len(hp.clients) != 0 {
		t.Logf("not reaped clients: %v", spew.Sdump(hp.clients))
		time.Sleep(50 * time.Millisecond)
	}
	hp.mtx.RUnlock()
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
	for i := 0; i < serverCount; i++ {
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
	for i := 0; i < clientCount; i++ {
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
	for i := 0; i < serverCount; i++ {
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
	for i := 0; i < clientCount; i++ {
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
	for i := 0; i < serverCount; i++ {
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
	for i := 0; i < clientCount; i++ {
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
