package hproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		id := serverReply{ID: x}
		err := json.NewEncoder(w).Encode(id)
		if err != nil {
			panic(err)
		}
	}))
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
	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()

	// Setup hproxy
	hpCfg := NewDefaultConfig()
	hpCfg.HVMURLs = servers
	hpCfg.LogLevel = "TRACE"
	hp, err := NewServer(hpCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err = hp.Run(ctx)
		if err != nil && err != context.Canceled {
			panic(err)
		}
	}()
	time.Sleep(250 * time.Millisecond)

	// clients
	var (
		wg sync.WaitGroup
		am sync.Mutex
	)
	clientCount := serverCount * 10
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
			var jr serverReply
			err = json.NewDecoder(reply.Body).Decode(&jr)
			if err != nil {
				t.Fatalf("decode %v: %v", x, err)
			}
			am.Lock()
			answers[jr.ID]++
			am.Unlock()
		}(i)
	}

	wg.Wait()
	cancel()

	// Allow 10% variance
	acceptable := (clientCount / serverCount) / (100 / 10)
	upperBound := (clientCount / serverCount) + acceptable
	lowerBound := (clientCount / serverCount) - acceptable
	for k, v := range answers {
		if v < lowerBound || v > upperBound {
			t.Fatalf("%v out of bounds lower %v upper %v got %v",
				k, lowerBound, upperBound, v)
		}
	}
}
