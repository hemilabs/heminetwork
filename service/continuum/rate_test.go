// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hemilabs/heminetwork/v2/ttl"
)

// TestSessionRateLimit verifies that the per-session token bucket
// rate limiter (F1) drops messages when the burst is exceeded.
// Uses a real TCP server because net.Pipe is synchronous — server
// response writes block when the client doesn't drain them,
// preventing the handle loop from reaching the rate limiter.
func TestSessionRateLimit(t *testing.T) {
	preParams := loadPreParams(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	s.cfg.PeersWanted = 2
	s.cfg.PingInterval = time.Hour
	s.cfg.MaintainInterval = time.Hour
	s.cfg.InitialPingTimeout = time.Hour

	go func() {
		if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("server: %v", err)
		}
	}()

	addr := waitForListenAddress(t, s, 2*time.Second)

	// Connect a client.
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	tr := new(Transport)
	if err := tr.KeyExchange(ctx, conn); err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tr.Handshake(ctx, secret); err != nil {
		t.Fatal(err)
	}

	// Drain incoming messages (initial exchange + responses) so
	// the server's writes don't block.
	go func() {
		for {
			if _, _, err := tr.Read(); err != nil {
				return
			}
		}
	}()

	// Wait for session to register.
	waitForSessions(t, s, 1, 2*time.Second)

	// Flood with messageBurst + 50 messages.  TCP buffering
	// lets us write faster than the server processes.
	total := messageBurst + 50
	for i := 0; i < total; i++ {
		if err := tr.Write(secret.Identity, PeerNotify{
			Count: i,
		}); err != nil {
			t.Logf("write stopped at %d: %v", i, err)
			break
		}
	}

	// Poll for rate drops — the handle loop drains the TCP
	// buffer asynchronously.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.rateDropped.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	drops := s.rateDropped.Load()
	if drops == 0 {
		t.Fatalf("expected rate drops after %d messages, got 0", total)
	}
	t.Logf("rate drops: %d/%d messages", drops, total)
}

// TestEnvelopeRateLimit verifies the per-sender EncryptedPayload
// rate gate (F3) drops envelopes after exceeding the limit.
func TestEnvelopeRateLimit(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	senderSecret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	envelopeRates, err := ttl.New(64, true)
	if err != nil {
		t.Fatal(err)
	}

	naclPub, err := secret.NaClPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{
		secret:        secret,
		envelopeRates: envelopeRates,
		peers: map[Identity]*PeerRecord{
			senderSecret.Identity: {
				Identity: senderSecret.Identity,
				NaClPub:  naclPub,
			},
		},
	}

	// Send envelopeRateLimit+10 envelopes from the same sender.
	var dropped int
	for i := 0; i < envelopeRateLimit+10; i++ {
		ep, err := SealBox(
			[]byte(`{"origin_timestamp":1}`),
			naclPub,
			senderSecret,
			PPingRequest,
		)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.decryptPayload(ep)
		if err != nil {
			dropped++
		}
	}

	if dropped == 0 {
		t.Fatal("expected envelope rate drops, got 0")
	}
	if s.envRateDrops.Load() == 0 {
		t.Fatal("envRateDrops counter is 0")
	}
	t.Logf("envelope rate: %d dropped out of %d", dropped, envelopeRateLimit+10)
}

// TestConnCooldown verifies the per-IP reconnection cooldown (F5)
// rejects connections from IPs that recently received BusyResponse.
func TestConnCooldown(t *testing.T) {
	preParams := loadPreParams(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	// Start a server with PeersWanted=1.
	s := newTestServer(t, preParams, 0, "localhost:0", nil)
	s.cfg.PeersWanted = 1
	s.cfg.PingInterval = time.Hour // no pings during test
	s.cfg.MaintainInterval = time.Hour

	go func() {
		if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("server: %v", err)
		}
	}()

	addr := waitForListenAddress(t, s, 2*time.Second)

	// Client 1: connect and fill the single slot.
	conn1, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn1.Close() })
	tr1 := new(Transport)
	if err := tr1.KeyExchange(ctx, conn1); err != nil {
		t.Fatal(err)
	}
	sec1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tr1.Handshake(ctx, sec1); err != nil {
		t.Fatal(err)
	}
	// Drain initial messages.
	go func() {
		for {
			_, _, err := tr1.Read()
			if err != nil {
				return
			}
		}
	}()

	// Wait for session to be registered.
	waitForSessions(t, s, 1, 2*time.Second)

	// Client 2: connect — should get BusyResponse and trigger cooldown.
	conn2, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tr2 := new(Transport)
	if err := tr2.KeyExchange(ctx, conn2); err != nil {
		conn2.Close()
		t.Fatal(err)
	}
	sec2, err := NewSecret()
	if err != nil {
		conn2.Close()
		t.Fatal(err)
	}
	_, _, err = tr2.Handshake(ctx, sec2)
	if err != nil {
		conn2.Close()
		t.Fatal(err)
	}
	// Read the BusyResponse.
	_, cmd, err := tr2.Read()
	if err != nil {
		t.Fatalf("read busy: %v", err)
	}
	if _, ok := cmd.(*BusyResponse); !ok {
		t.Fatalf("expected BusyResponse, got %T", cmd)
	}
	tr2.Close()

	// Client 3: reconnect from the same IP.  The server should
	// reject via cooldown before KX.  Poll cooldownDrops to
	// confirm — the server goroutine may not have reached
	// cooldown.Put yet when we connect.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn3, err := (&net.Dialer{Timeout: 1 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			// Dial itself failed — server may have closed
			// the listener.  Check counter.
			break
		}
		if err := conn3.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			conn3.Close()
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		_, _ = conn3.Read(buf)
		conn3.Close()
		if s.cooldownDrops.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	drops := s.cooldownDrops.Load()
	if drops == 0 {
		t.Fatal("cooldownDrops counter is 0")
	}
	t.Logf("cooldown drops: %d", drops)
}
