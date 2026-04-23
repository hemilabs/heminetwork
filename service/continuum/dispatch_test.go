// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/ecdh"
	"net"
	"reflect"
	"testing"
	"time"
)

// TestDispatchMapCompleteness verifies that every incoming payload type
// that handle() could receive has an entry in payloadDispatch, and
// that no stale handlers for removed types exist.
func TestDispatchMapCompleteness(t *testing.T) {
	// Types that handle() must dispatch.  This is the authoritative
	// list — if a new wire type is added to pt2str, the developer
	// must consciously decide whether it belongs here.
	required := []reflect.Type{
		reflect.TypeFor[*PingRequest](),
		reflect.TypeFor[*PingResponse](),
		reflect.TypeFor[*PeerNotify](),
		reflect.TypeFor[*PeerListRequest](),
		reflect.TypeFor[*PeerListResponse](),
		reflect.TypeFor[*KeygenRequest](),
		reflect.TypeFor[*SignRequest](),
		reflect.TypeFor[*ReshareRequest](),
		reflect.TypeFor[*TSSMessage](),
		reflect.TypeFor[*EncryptedPayload](),
		reflect.TypeFor[*CeremonyResult](),
		reflect.TypeFor[*PeerListAdminRequest](),
		reflect.TypeFor[*CeremonyStatusRequest](),
		reflect.TypeFor[*CeremonyListRequest](),
		reflect.TypeFor[*PeerAddRequest](),
		reflect.TypeFor[*BusyResponse](),
	}

	expected := make(map[reflect.Type]bool, len(required))
	for _, rt := range required {
		expected[rt] = true
		if _, ok := payloadDispatch[rt]; !ok {
			t.Errorf("payloadDispatch missing entry for %v", rt)
		}
	}
	for rt := range payloadDispatch {
		if !expected[rt] {
			t.Errorf("payloadDispatch has unexpected entry: %v", rt)
		}
	}
}

// TestDispatchUnknownType verifies that dispatchPayload returns false
// (continue) for a type not in the map.
func TestDispatchUnknownType(t *testing.T) {
	dc := &dispatchCtx{}
	// HelloRequest is a wire type but not dispatched (handled in KX).
	exit := dispatchPayload(dc, &HelloRequest{})
	if exit {
		t.Fatal("dispatchPayload returned true for unknown type")
	}
}

// localhostTransports creates a Transport pair connected over real TCP
// on 127.0.0.1, with completed KX.  Required for admin handler tests
// because requireAdmin checks RemoteAddr() for loopback.
func localhostTransports(t *testing.T) (*Transport, *Transport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	var srvConn net.Conn
	accepted := make(chan struct{})
	go func() {
		var aerr error
		srvConn, aerr = ln.Accept()
		if aerr != nil {
			return
		}
		close(accepted)
	}()

	cliConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	<-accepted
	t.Cleanup(func() { srvConn.Close() })
	t.Cleanup(func() { cliConn.Close() })

	srv, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatal(err)
	}
	cli := new(Transport)
	errCh := make(chan error, 2)
	go func() { errCh <- srv.KeyExchange(ctx, srvConn) }()
	go func() { errCh <- cli.KeyExchange(ctx, cliConn) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("KX: %v", err)
		}
	}
	return srv, cli
}

// --- no-debugInit paths (production binary) ---

func TestHandleKeygenNoDebugInitiator(t *testing.T) {
	s, _ := NewServer(testConfig())
	s.debugInit = nil
	dc := &dispatchCtx{s: s, id: &Identity{0x01}}
	if handleKeygenRequest(dc, &KeygenRequest{}) {
		t.Fatal("expected false")
	}
}

func TestHandleSignNoDebugInitiator(t *testing.T) {
	s, _ := NewServer(testConfig())
	s.debugInit = nil
	dc := &dispatchCtx{s: s, id: &Identity{0x01}}
	if handleSignRequest(dc, &SignRequest{}) {
		t.Fatal("expected false")
	}
}

func TestHandleReshareNoDebugInitiator(t *testing.T) {
	s, _ := NewServer(testConfig())
	s.debugInit = nil
	dc := &dispatchCtx{s: s, id: &Identity{0x01}}
	if handleReshareRequest(dc, &ReshareRequest{}) {
		t.Fatal("expected false")
	}
}

// --- non-admin rejection (pipe transport, not localhost) ---

func TestHandleCeremonyStatusNonAdmin(t *testing.T) {
	s, _ := NewServer(testConfig())
	srv, _ := connectedTransports(t)
	dc := &dispatchCtx{s: s, id: &Identity{}, t: srv}
	if handleCeremonyStatusReq(dc, &CeremonyStatusRequest{}) {
		t.Fatal("expected false")
	}
}

func TestHandleCeremonyListNonAdmin(t *testing.T) {
	s, _ := NewServer(testConfig())
	srv, _ := connectedTransports(t)
	dc := &dispatchCtx{s: s, id: &Identity{}, t: srv}
	if handleCeremonyListReq(dc, &CeremonyListRequest{}) {
		t.Fatal("expected false")
	}
}

func TestHandlePeerAddReqNonAdmin(t *testing.T) {
	s, _ := NewServer(testConfig())
	srv, _ := connectedTransports(t)
	dc := &dispatchCtx{s: s, id: &Identity{}, t: srv}
	if handlePeerAddReq(dc, &PeerAddRequest{Address: "1.2.3.4:9090"}) {
		t.Fatal("expected false")
	}
}

// --- admin handler write errors (localhost TCP, then close) ---

// adminWriteErrorServer creates a Server with secret initialized,
// suitable for admin handler write error tests.
func adminWriteErrorServer(t *testing.T) (*Server, *Transport) {
	t.Helper()
	s, _ := NewServer(testConfig())
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s.secret = secret
	srv, _ := localhostTransports(t)
	srv.Close() // force write error; RemoteAddr still returns 127.0.0.1
	return s, srv
}

func TestHandleCeremonyStatusWriteError(t *testing.T) {
	s, srv := adminWriteErrorServer(t)
	dc := &dispatchCtx{s: s, id: &Identity{}, t: srv}
	if handleCeremonyStatusReq(dc, &CeremonyStatusRequest{}) {
		t.Fatal("expected false")
	}
}

func TestHandleCeremonyListWriteError(t *testing.T) {
	s, srv := adminWriteErrorServer(t)
	dc := &dispatchCtx{s: s, id: &Identity{}, t: srv}
	if handleCeremonyListReq(dc, &CeremonyListRequest{}) {
		t.Fatal("expected false")
	}
}

func TestHandlePeerListAdminWriteError(t *testing.T) {
	s, srv := adminWriteErrorServer(t)
	dc := &dispatchCtx{s: s, id: &Identity{}, t: srv}
	if handlePeerListAdmin(dc, &PeerListAdminRequest{}) {
		t.Fatal("expected false")
	}
}

func TestHandlePeerAddReqWriteError(t *testing.T) {
	s, srv := adminWriteErrorServer(t)
	dc := &dispatchCtx{ctx: t.Context(), s: s, id: &Identity{}, t: srv}
	if handlePeerAddReq(dc, &PeerAddRequest{Address: "1.2.3.4:9090"}) {
		t.Fatal("expected false")
	}
}

// --- handlePeerAdd server method ---

func TestHandlePeerAddEmptyAddress(t *testing.T) {
	s, _ := NewServer(testConfig())
	resp := s.handlePeerAdd(t.Context(), "")
	if resp.Accepted {
		t.Fatal("expected rejected for empty address")
	}
}

func TestHandlePeerAddAccepted(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	s, _ := NewServer(testConfig())
	resp := s.handlePeerAdd(ctx, "192.168.1.1:9090")
	if !resp.Accepted {
		t.Fatalf("expected accepted, got error: %v", resp.Error)
	}
	s.wg.Wait() // connectPeer fails fast due to short ctx
}

// --- handlePeerAddReq happy path (localhost, write succeeds) ---

func TestHandlePeerAddReqHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	s, _ := NewServer(testConfig())
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s.secret = secret
	srv, cli := localhostTransports(t)
	drainTransport(t, cli)
	dc := &dispatchCtx{ctx: ctx, s: s, id: &Identity{}, t: srv}
	if handlePeerAddReq(dc, &PeerAddRequest{Address: "192.168.1.1:9090"}) {
		t.Fatal("expected false")
	}
	s.wg.Wait()
}
