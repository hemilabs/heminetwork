package p2pproxy

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestP2P(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.Network = "testnet3"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	var wg sync.WaitGroup
	errC := make(chan error, 1)
	wg.Add(1)
	go func() {
		wg.Done()
		errC <- s.Run(ctx)
	}()

	//

	select {
	case <-time.After(5 * time.Second):
		t.Log("timeout")

	case err := <-errC:
		if err != nil {
			t.Fatal(err)
		}
	}
	cancel()

	wg.Wait()
}
