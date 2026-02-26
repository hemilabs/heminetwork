// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// dispatch.go replaces the handle() type switch with a
// registration-based dispatch map.  Each payload type is keyed
// by reflect.Type and mapped to a handler function.

import (
	"context"
	"reflect"
	"time"
)

// dispatchCtx bundles the per-session state that dispatch handlers
// need.  Passed by pointer to avoid copying.
type dispatchCtx struct {
	ctx        context.Context // server Run() context
	sessionCtx context.Context // per-session, cancelled on handle() exit
	s          *Server
	id         *Identity
	t          *Transport
}

// dispatchFn handles a dispatched payload.  Returns true if the
// handle() loop should exit (e.g. transport write failure or
// BusyResponse).
type dispatchFn func(dc *dispatchCtx, payload any) bool

// payloadDispatch maps wire types to their dispatch handlers.
// Built once at init time; read-only at runtime.
var payloadDispatch map[reflect.Type]dispatchFn

func init() {
	payloadDispatch = map[reflect.Type]dispatchFn{
		reflect.TypeOf((*PingRequest)(nil)):           handlePingRequest,
		reflect.TypeOf((*PingResponse)(nil)):          handlePingResponse,
		reflect.TypeOf((*PeerNotify)(nil)):            handlePeerNotify,
		reflect.TypeOf((*PeerListRequest)(nil)):       handlePeerListRequest,
		reflect.TypeOf((*PeerListResponse)(nil)):      handlePeerListResponse,
		reflect.TypeOf((*KeygenRequest)(nil)):         handleKeygenRequest,
		reflect.TypeOf((*SignRequest)(nil)):           handleSignRequest,
		reflect.TypeOf((*ReshareRequest)(nil)):        handleReshareRequest,
		reflect.TypeOf((*TSSMessage)(nil)):            handleTSSMessage,
		reflect.TypeOf((*EncryptedPayload)(nil)):      handleEncryptedPayload,
		reflect.TypeOf((*CeremonyResult)(nil)):        handleCeremonyResult,
		reflect.TypeOf((*PeerListAdminRequest)(nil)):  handlePeerListAdmin,
		reflect.TypeOf((*CeremonyStatusRequest)(nil)): handleCeremonyStatusReq,
		reflect.TypeOf((*CeremonyListRequest)(nil)):   handleCeremonyListReq,
		reflect.TypeOf((*BusyResponse)(nil)):          handleBusyResponse,
	}
}

// dispatchPayload looks up the handler for payload's type and calls
// it.  Returns true if the handle() loop should exit.
func dispatchPayload(dc *dispatchCtx, payload any) bool {
	fn, ok := payloadDispatch[reflect.TypeOf(payload)]
	if !ok {
		log.Debugf("handle %v: unhandled %T", dc.id, payload)
		return false
	}
	return fn(dc, payload)
}

// --- individual handlers ---

func handlePingRequest(dc *dispatchCtx, payload any) bool {
	v := payload.(*PingRequest)
	err := dc.t.Write(dc.s.secret.Identity, PingResponse{
		OriginTimestamp: v.OriginTimestamp,
		PeerTimestamp:   time.Now().Unix(),
	})
	if err != nil {
		log.Warningf("ping response %v: %v", dc.id, err)
		return true // write failed, exit handle()
	}
	return false
}

func handlePingResponse(dc *dispatchCtx, payload any) bool {
	// Heartbeat received — peer is alive.  Disarm the
	// ping timeout, refresh peer TTL and update LastSeen.
	_ = dc.s.pings.Cancel(*dc.id)
	dc.s.refreshPeerLastSeen(dc.sessionCtx, *dc.id)
	return false
}

func handlePeerNotify(dc *dispatchCtx, payload any) bool {
	v := payload.(*PeerNotify)
	// Remote has v.Count peers.  If they know more
	// than us, request their list.
	if v.Count > dc.s.PeerCount() {
		if err := dc.t.Write(dc.s.secret.Identity,
			PeerListRequest{}); err != nil {
			log.Warningf("peer list request %v: %v",
				dc.id, err)
		}
	}
	return false
}

func handlePeerListRequest(dc *dispatchCtx, payload any) bool {
	peers := dc.s.knownPeerList(*dc.id)
	if err := dc.t.Write(dc.s.secret.Identity,
		PeerListResponse{Peers: peers}); err != nil {
		log.Warningf("peer list response %v: %v",
			dc.id, err)
	}
	return false
}

func handlePeerListResponse(dc *dispatchCtx, payload any) bool {
	v := payload.(*PeerListResponse)
	peers := v.Peers
	if len(peers) > maxGossipPeers {
		log.Warningf("peer list from %v truncated: "+
			"%d > %d", dc.id, len(peers),
			maxGossipPeers)
		peers = peers[:maxGossipPeers]
	}
	var learned int
	for _, pr := range peers {
		if pr.Version != ProtocolVersion {
			log.Warningf("peer %v version %d != %d, rejected",
				pr.Identity, pr.Version, ProtocolVersion)
			continue
		}
		// Validate address only if present.  Peers learned
		// from the listen path may not know their own
		// address yet — they still carry useful fields
		// like NaClPub for e2e encryption.
		if pr.Address != "" {
			if err := validatePeerAddress(pr.Address); err != nil {
				log.Warningf("peer %v bad address %q: %v",
					pr.Identity, pr.Address, err)
				continue
			}
		}
		if dc.s.addPeer(dc.ctx, pr) {
			learned++
		}
	}
	if learned > 0 {
		dc.s.notifyAllPeers(dc.ctx)
	}
	return false
}

func handleKeygenRequest(dc *dispatchCtx, payload any) bool {
	v := payload.(*KeygenRequest)
	if dc.s.debugInit == nil {
		log.Warningf("handle %v: KeygenRequest ignored (no debug initiator)", dc.id)
		return false
	}
	if cr := ceremonyFromKeygen(*v); cr != nil {
		dc.s.debugInit.Submit(*cr)
	}
	return false
}

func handleSignRequest(dc *dispatchCtx, payload any) bool {
	v := payload.(*SignRequest)
	if dc.s.debugInit == nil {
		log.Warningf("handle %v: SignRequest ignored (no debug initiator)", dc.id)
		return false
	}
	if cr := ceremonyFromSign(*v); cr != nil {
		dc.s.debugInit.Submit(*cr)
	}
	return false
}

func handleReshareRequest(dc *dispatchCtx, payload any) bool {
	v := payload.(*ReshareRequest)
	if dc.s.debugInit == nil {
		log.Warningf("handle %v: ReshareRequest ignored (no debug initiator)", dc.id)
		return false
	}
	if cr := ceremonyFromReshare(*v); cr != nil {
		dc.s.debugInit.Submit(*cr)
	}
	return false
}

func handleTSSMessage(dc *dispatchCtx, payload any) bool {
	v := payload.(*TSSMessage)
	dc.s.dispatchTSSMessage(*v)
	return false
}

func handleEncryptedPayload(dc *dispatchCtx, payload any) bool {
	v := payload.(*EncryptedPayload)
	inner, err := dc.s.decryptPayload(v)
	if err != nil {
		log.Warningf("handle %v: decrypt: %v", dc.id, err)
		return false
	}
	// Re-dispatch the decrypted inner payload through the
	// same dispatch map.
	return dispatchPayload(dc, inner)
}

func handleCeremonyResult(dc *dispatchCtx, payload any) bool {
	v := payload.(*CeremonyResult)
	dc.s.handleCeremonyResult(*v)
	return false
}

func handlePeerListAdmin(dc *dispatchCtx, payload any) bool {
	if !requireAdmin(dc.t, dc.id) {
		return false
	}
	resp := dc.s.handlePeerListAdmin()
	if err := dc.t.Write(dc.s.secret.Identity, resp); err != nil {
		log.Warningf("admin peer list %v: %v", dc.id, err)
	}
	return false
}

func handleCeremonyStatusReq(dc *dispatchCtx, payload any) bool {
	v := payload.(*CeremonyStatusRequest)
	if !requireAdmin(dc.t, dc.id) {
		return false
	}
	resp := dc.s.handleCeremonyStatus(v.CeremonyID)
	if err := dc.t.Write(dc.s.secret.Identity, resp); err != nil {
		log.Warningf("admin ceremony status %v: %v", dc.id, err)
	}
	return false
}

func handleCeremonyListReq(dc *dispatchCtx, payload any) bool {
	if !requireAdmin(dc.t, dc.id) {
		return false
	}
	resp := dc.s.handleCeremonyList()
	if err := dc.t.Write(dc.s.secret.Identity, resp); err != nil {
		log.Warningf("admin ceremony list %v: %v", dc.id, err)
	}
	return false
}

func handleBusyResponse(dc *dispatchCtx, payload any) bool {
	log.Infof("peer %v at capacity, disconnecting", dc.id)
	return true // exit handle()
}
