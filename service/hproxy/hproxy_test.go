package hproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
			panic("one of X-Forwarded-* not set")
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

	// Require X-Hproxy
	ids := reply.Header.Get("X-Hproxy")
	if ids == "" {
		panic("expected X-Hproxy being set")
	}

	// Expect 502
	if reply.StatusCode != http.StatusBadGateway {
		t.Fatalf("http error mismatch: got %v wanted %v",
			reply.StatusCode, http.StatusBadGateway)
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
	time.Sleep(250 * time.Millisecond)

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
	for k, v := range answers {
		if v < lowerBound || v > upperBound {
			t.Fatalf("%v out of bounds lower %v upper %v got %v",
				k, lowerBound, upperBound, v)
		}
	}
}
