// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
)

func ping(ctx context.Context, t *testing.T, p *rawpeer.RawPeer) error {
	err := p.Write(time.Second, wire.NewMsgPing(uint64(time.Now().Unix())))
	if err != nil {
		return err
	}

	for {
		msg, _, err := p.Read(time.Second)
		if errors.Is(err, wire.ErrUnknownMessage) {
			continue
		} else if err != nil {
			return err
		}
		switch msg.(type) {
		case *wire.MsgPong:
			return nil
		}
	}
}

func TestPeerManager(t *testing.T) {
	t.Skip("this test connects to testnet3")
	want := 2
	wantLoop := want * 2
	pm, err := NewPeerManager(wire.TestNet3, []string{}, want)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		err = pm.Run(ctx)
		if err != nil {
			t.Logf("%v", err)
		}
	}()

	var wg sync.WaitGroup
	for peers := 0; peers < wantLoop; {
		p, err := pm.RandomConnect(ctx)
		if err != nil {
			// Should not be reached
			t.Fatal(err)
		}
		wg.Add(1)
		go func(pp *rawpeer.RawPeer) {
			defer wg.Done()
			err := ping(ctx, t, pp)
			if err != nil {
				t.Logf("ping returned error but that's fine: %v", err)
			}
			// Always close
			err = pm.Bad(ctx, pp.String())
			if err != nil {
				panic(err)
			}
		}(p)
		peers++
		t.Logf("%v", pm)
	}

	wg.Wait()

	if len(pm.bad) < wantLoop {
		t.Fatalf("not enough bad, got %v wanted %v", len(pm.bad), wantLoop)
	}
	if len(pm.peers) != 0 {
		t.Fatalf("not enough peers, got %v wanted %v", len(pm.peers), 0)
	}
}
