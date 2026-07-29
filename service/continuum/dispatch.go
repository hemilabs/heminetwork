// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// dispatch.go replaces the handle() type switch with a
// registration-based dispatch map.  Each payload type is keyed
// by reflect.Type and mapped to a handler function.

import (
	"bytes"
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
		reflect.TypeFor[*PingRequest]():           handlePingRequest,
		reflect.TypeFor[*PingResponse]():          handlePingResponse,
		reflect.TypeFor[*PeerNotify]():            handlePeerNotify,
		reflect.TypeFor[*PeerListRequest]():       handlePeerListRequest,
		reflect.TypeFor[*PeerListResponse]():      handlePeerListResponse,
		reflect.TypeFor[*KeygenRequest]():         handleKeygenRequest,
		reflect.TypeFor[*SignRequest]():           handleSignRequest,
		reflect.TypeFor[*ReshareRequest]():        handleReshareRequest,
		reflect.TypeFor[*TSSMessage]():            handleTSSMessage,
		reflect.TypeFor[*EncryptedPayload]():      handleEncryptedPayload,
		reflect.TypeFor[*NaClKeyRequest]():        handleNaClKeyRequest,
		reflect.TypeFor[*NaClKeyResponse]():       handleNaClKeyResponse,
		reflect.TypeFor[*CeremonyResult]():        handleCeremonyResult,
		reflect.TypeFor[*PeerListAdminRequest]():  handlePeerListAdmin,
		reflect.TypeFor[*CeremonyStatusRequest](): handleCeremonyStatusReq,
		reflect.TypeFor[*CeremonyListRequest]():   handleCeremonyListReq,
		reflect.TypeFor[*PeerAddRequest]():        handlePeerAddReq,
		reflect.TypeFor[*BusyResponse]():          handleBusyResponse,
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
		// address yet.
		if pr.Address != "" {
			if err := validatePeerAddress(pr.Address); err != nil {
				log.Warningf("peer %v bad address %q: %v",
					pr.Identity, pr.Address, err)
				continue
			}
		}
		// Gossip is discovery metadata only.  addPeer discards
		// key material anyway; strip it here too so no future
		// addPeer refactor can be reached with gossip keys.
		pr.NaClPub = nil
		if dc.s.addPeer(dc.ctx, pr) {
			learned++
		}
	}
	if learned > 0 {
		dc.s.notifyAllPeers(dc.ctx)
	}

	// Rebuild routing table from updated gossip topology.
	dc.s.rebuildRoutes()

	return false
}

// errNoDebugInitiator is returned to a peer that wire-initiates a
// ceremony against a production build.  Ceremonies are driven by the
// blockchain there; wire initiation exists only in debug builds.
// Answering explicitly keeps the caller from waiting for a reply that
// is never coming.
const errNoDebugInitiator = "wire-initiated ceremonies are not enabled on this node"

func handleKeygenRequest(dc *dispatchCtx, payload any) bool {
	v := payload.(*KeygenRequest)
	if dc.s.debugInit == nil {
		log.Warningf("handle %v: KeygenRequest rejected (no debug initiator)", dc.id)
		if dc.t == nil {
			return false
		}
		if err := dc.t.Write(dc.s.secret.Identity, KeygenResponse{
			CeremonyID: v.CeremonyID,
			Success:    false,
			Error:      errNoDebugInitiator,
		}); err != nil {
			log.Warningf("handle %v: keygen reject: %v", dc.id, err)
		}
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
		log.Warningf("handle %v: SignRequest rejected (no debug initiator)", dc.id)
		if dc.t == nil {
			return false
		}
		if err := dc.t.Write(dc.s.secret.Identity, SignResponse{
			CeremonyID: v.CeremonyID,
			Success:    false,
			Error:      errNoDebugInitiator,
		}); err != nil {
			log.Warningf("handle %v: sign reject: %v", dc.id, err)
		}
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
		log.Warningf("handle %v: ReshareRequest rejected (no debug initiator)", dc.id)
		if dc.t == nil {
			return false
		}
		if err := dc.t.Write(dc.s.secret.Identity, ReshareResponse{
			CeremonyID: v.CeremonyID,
			Success:    false,
			Error:      errNoDebugInitiator,
		}); err != nil {
			log.Warningf("handle %v: reshare reject: %v", dc.id, err)
		}
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

// handleNaClKeyRequest answers a routed e2e key attestation request:
// sign our X25519 public key bound to the caller's challenge and route
// the response back.  The request is unauthenticated; answering only
// produces a true, domain-separated statement about our own key, so
// the sole abuse potential is making us sign — bounded by the
// per-requester rate limiter.
func handleNaClKeyRequest(dc *dispatchCtx, payload any) bool {
	v := payload.(*NaClKeyRequest)
	s := dc.s

	if len(v.Challenge) != ChallengeSize {
		s.naclXchgDrops.Add(1)
		log.Debugf("nacl key request %v: bad challenge length %d",
			dc.id, len(v.Challenge))
		return false
	}
	if bytes.Equal(ZeroChallenge[:], v.Challenge) {
		s.naclXchgDrops.Add(1)
		log.Debugf("nacl key request %v: zero challenge", dc.id)
		return false
	}
	// A request "from" ourselves is a reflection or a spoof;
	// either way there is nothing to answer.
	if v.Requester == s.secret.Identity {
		s.naclXchgDrops.Add(1)
		log.Debugf("nacl key request %v: self requester", dc.id)
		return false
	}
	// One signature per requester per window.  Honest retries run
	// at naclXchgRetry which clears the window; floods get dropped.
	// Nil guard for hand-built test servers; NewServer always sets it.
	if s.naclXchgRates != nil {
		if _, _, err := s.naclXchgRates.Get(v.Requester); err == nil {
			s.naclXchgDrops.Add(1)
			log.Debugf("nacl key request %v: rate limited", v.Requester)
			return false
		}
		s.naclXchgRates.Put(dc.ctx, naclXchgRateTTL, v.Requester,
			struct{}{}, nil, nil)
	}

	naclPub, err := s.secret.NaClPublicKey()
	// untested: NaClPublicKey cannot fail with a valid secret
	if err != nil {
		log.Errorf("nacl key request %v: own key: %v", v.Requester, err)
		return false
	}
	resp := NaClKeyResponse{
		Challenge: v.Challenge,
		NaClPub:   naclPub,
		Signature: s.secret.Sign(hashNaClKeyBinding(v.Challenge, naclPub)),
	}
	if err := s.sendTo(v.Requester, resp); err != nil {
		log.Debugf("nacl key response to %v: %v", v.Requester, err)
	}
	return false
}

// handleNaClKeyResponse verifies an e2e key attestation and binds the
// key.  The challenge is only a lookup key into our pending exchange
// state: the hash is recomputed locally and the signature must recover
// to the exact identity the challenge was issued for, so nothing an
// on-path node can alter survives verification.
func handleNaClKeyResponse(dc *dispatchCtx, payload any) bool {
	v := payload.(*NaClKeyResponse)
	s := dc.s

	if len(v.Challenge) != ChallengeSize || len(v.NaClPub) != NaClPubSize {
		s.naclXchgDrops.Add(1)
		log.Debugf("nacl key response %v: malformed", dc.id)
		return false
	}
	// Nil guard for hand-built test servers; NewServer always sets it.
	if s.naclXchg == nil {
		s.naclXchgDrops.Add(1)
		return false
	}
	val, _, err := s.naclXchg.Get(string(v.Challenge))
	if err != nil {
		// Expired, already consumed, or never ours.
		s.naclXchgDrops.Add(1)
		log.Debugf("nacl key response %v: no pending challenge", dc.id)
		return false
	}
	id, ok := val.(Identity)
	// untested: only Identity values are ever stored in naclXchg
	if !ok {
		return false
	}
	if _, err := Verify(hashNaClKeyBinding(v.Challenge, v.NaClPub),
		id, v.Signature); err != nil {
		s.naclXchgDrops.Add(1)
		log.Warningf("nacl key response for %v: bad signature: %v", id, err)
		return false
	}
	// Consume the challenge only after verification succeeds so a
	// garbage response cannot burn a pending exchange.
	// untested: only reachable if the entry expires between the Get
	// above and this Delete
	if _, err := s.naclXchg.Delete(string(v.Challenge)); err != nil {
		log.Debugf("nacl key response %v: delete pending: %v", id, err)
	}
	if err := s.bindPeerKey(dc.ctx, id, v.NaClPub); err != nil {
		log.Warningf("nacl key response %v: %v", id, err)
	}
	return false
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

func handlePeerAddReq(dc *dispatchCtx, payload any) bool {
	if !requireAdmin(dc.t, dc.id) {
		return false
	}
	v := payload.(*PeerAddRequest)
	resp := dc.s.handlePeerAdd(dc.ctx, v.Address)
	if err := dc.t.Write(dc.s.secret.Identity, resp); err != nil {
		log.Warningf("admin peer add %v: %v", dc.id, err)
	}
	return false
}

func handleBusyResponse(dc *dispatchCtx, payload any) bool {
	log.Infof("peer %v at capacity, disconnecting", dc.id)
	return true // exit handle()
}
