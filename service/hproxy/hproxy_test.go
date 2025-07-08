package hproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

type serverReply struct {
	ID    int   `json:"id"`
	Error error `json:"error,omitempty"`
}

func newServer(x int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Host") == "" ||
			r.Header.Get("X-Forwarded-For") == "" ||
			r.Header.Get("X-Forwarded-Proto") == "" {
			// When we get here we are getting a health
			// check which does not have headers set. Check
			// to see if the check is expected and panic if
			// it isn't.
			defer r.Body.Close()
			jr := json.NewDecoder(r.Body)
			var j map[string]any
			err := jr.Decode(&j)
			if err != nil {
				panic(err)
			}
			if x, ok := j["method"]; !ok || x != "eth_blockNumber" {
				panic("invalid health command")
			}
			// return some bs
			err = json.NewEncoder(w).Encode(
				map[string]any{
					"jsonrpc": "2.0",
					"id":      1,
					"result":  "0x37af32",
					"health":  1,
				})
			if err != nil {
				panic(err)
			}
			return
		}
		id := serverReply{ID: x}
		err := json.NewEncoder(w).Encode(id)
		if err != nil {
			panic(err)
		}
	}))
}

func newHproxy(t *testing.T, servers []string) (*Server, *Config) {
	hpCfg := NewDefaultConfig()
	hpCfg.HVMURLs = servers
	hpCfg.LogLevel = "hproxy=TRACE" // XXX figure out why this isn't working
	hpCfg.RequestTimeout = time.Second
	hpCfg.PollFrequency = time.Second
	hp, err := NewServer(hpCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err = hp.Run(t.Context())
		if err != nil && err != context.Canceled {
			panic(err)
		}
	}()
	return hp, hpCfg
}

func TestNobodyHome(t *testing.T) {
	servers := []string{"http://localhost:1"}
	_, hpCfg := newHproxy(t, servers)
	time.Sleep(250 * time.Millisecond)

	reply, err := http.Get("http://" + hpCfg.ListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()

	// Expect 503
	if reply.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("http error mismatch: got %v wanted %v",
			reply.StatusCode, http.StatusServiceUnavailable)
	}

	// Expect EOF
	var jr serverReply
	err = json.NewDecoder(reply.Body).Decode(&jr)
	if err != io.EOF {
		t.Fatal(err)
	}
}

//func TestDialTimeout(t *testing.T) {
// XXX tried to build a test for this but did not succeed. Remove or fix.
//}

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
	_, hpCfg := newHproxy(t, servers)
	time.Sleep(250 * time.Millisecond)

	_, err := http.Get("http://" + hpCfg.ListenAddress)
	wg.Done()
	if err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%T", err)
		}
	}
}

func request(serverID int, hpCfg *Config) error {
	reply, err := http.Get("http://" + hpCfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("get %v: %v", 0, err)
	}
	defer reply.Body.Close()
	switch reply.StatusCode {
	case http.StatusOK:
	default:
		return fmt.Errorf("%v replied %v", hpCfg.ListenAddress, reply.StatusCode)
	}

	// Require X-Hproxy
	ids := reply.Header.Get("X-Hproxy")
	if ids == "" {
		return errors.New("expected X-Hproxy being set")
	}

	// Read body
	var jr serverReply
	err = json.NewDecoder(reply.Body).Decode(&jr)
	if err != nil {
		return fmt.Errorf("decode: %v", err)
	}
	if jr.ID != serverID {
		return fmt.Errorf("invalid response got %v, wanted %v", jr.ID, serverID)
	}
	return nil
}

func TestProxy(t *testing.T) {
	serverID := 1337
	s := newServer(serverID)
	defer s.Close()
	servers := []string{s.URL}

	// Setup hproxy
	_, hpCfg := newHproxy(t, servers)
	time.Sleep(250 * time.Millisecond)

	// Send command
	err := request(serverID, hpCfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFanout(t *testing.T) {
	serverCount := 5

	servers := make([]string, 0, serverCount)
	for i := 0; i < serverCount; i++ {
		s := newServer(i)
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
	_, hpCfg := newHproxy(t, servers)
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
			reply, err := http.Get("http://" + hpCfg.ListenAddress)
			if err != nil {
				t.Fatalf("get %v: %v", x, err)
			}
			defer reply.Body.Close()
			switch reply.StatusCode {
			case http.StatusOK:
			default:
				panic(fmt.Sprintf("%v replied %v",
					hpCfg.ListenAddress, reply.StatusCode))
			}

			// Require X-Hproxy
			ids := reply.Header.Get("X-Hproxy")
			if ids == "" {
				panic("expected X-Hproxy being set")
			}

			var jr serverReply
			err = json.NewDecoder(reply.Body).Decode(&jr)
			if err != nil {
				t.Fatalf("decode %v: %v", x, err)
			}
			am.Lock()
			answers[jr.ID]++
			am.Unlock()

			// Verify that json id matches header id, a bit silly
			// but keeps us honest.
			if strconv.Itoa(jr.ID) != ids {
				panic("id mismatch header: " + ids +
					" json: " + strconv.Itoa(jr.ID))
			}
		}(i)
	}

	wg.Wait()
	cancel()

	// Allow 20% variance
	acceptable := (clientCount / serverCount) / (100 / 20)
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
		s := newServer(i)
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
	_, hpCfg := newHproxy(t, servers)
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
		reply, err := c.Get("http://" + hpCfg.ListenAddress)
		if err != nil {
			t.Fatalf("get %v: %v", x, err)
		}
		defer reply.Body.Close()
		switch reply.StatusCode {
		case http.StatusOK:
		default:
			panic(fmt.Sprintf("%v replied %v",
				hpCfg.ListenAddress, reply.StatusCode))
		}

		// Require X-Hproxy
		ids := reply.Header.Get("X-Hproxy")
		if ids == "" {
			panic("expected X-Hproxy being set")
		}

		var jr serverReply
		err = json.NewDecoder(reply.Body).Decode(&jr)
		if err != nil {
			t.Fatalf("decode %v: %v", x, err)
		}
		// Discard so that we can reuse connection
		if _, err := io.Copy(ioutil.Discard, reply.Body); err != nil {
			t.Fatal(err)
		}

		am.Lock()
		answers[jr.ID]++
		am.Unlock()

		// Verify that json id matches header id, a bit silly
		// but keeps us honest.
		if strconv.Itoa(jr.ID) != ids {
			panic("id mismatch header: " + ids +
				" json: " + strconv.Itoa(jr.ID))
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
