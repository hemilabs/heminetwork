// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hemilabs/x/tss/v3/tss"
)

// =============================================================================
// tssRetryBackoff is the fixed backoff schedule for retrying
// HandleMessage when a TSSMessage arrives before its ceremony is
// registered.  Totals ~4 seconds.
var tssRetryBackoff = []time.Duration{
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
}

// Server TSS Transport — TSSTransport over encrypted RPC sessions
//
// Bridges the TSS engine (tss.go) to the protocol layer. Outgoing
// messages from tss.go arrive via Send() in byte-prefix wire format
// and are translated to signed TSSMessage envelopes with Flags-based
// routing before being written to peer Transports.
// =============================================================================

// serverTSSTransport implements TSSTransport by wrapping the
// Server's encrypted session map. It translates between the
// tss.go byte-prefix wire format and TSSMessage.Flags routing.
type serverTSSTransport struct {
	server *Server

	// Ceremony type lookup for wire format translation.
	// Keygen/Sign use 1-byte prefix, Reshare uses 2-byte prefix.
	ctypes map[CeremonyID]CeremonyType
	mu     sync.RWMutex
}

func newServerTSSTransport(s *Server) *serverTSSTransport {
	return &serverTSSTransport{
		server: s,
		ctypes: make(map[CeremonyID]CeremonyType),
	}
}

func (st *serverTSSTransport) registerCeremony(cid CeremonyID, ct CeremonyType) {
	st.mu.Lock()
	st.ctypes[cid] = ct
	st.mu.Unlock()
}

func (st *serverTSSTransport) unregisterCeremony(cid CeremonyID) {
	st.mu.Lock()
	delete(st.ctypes, cid)
	st.mu.Unlock()
}

func (st *serverTSSTransport) ceremonyType(cid CeremonyID) (CeremonyType, bool) {
	st.mu.RLock()
	ct, ok := st.ctypes[cid]
	st.mu.RUnlock()
	return ct, ok
}

// Send implements TSSTransport. The data argument arrives from
// tss.go in byte-prefix wire format:
//
//   - keygen/sign: [broadcast:1][wireBytes]
//   - reshare:     [broadcast:1][committee_flags:1][wireBytes]
//
// It is translated to a signed TSSMessage with Flags routing
// and pure wireBytes in Data before writing to the peer Transport.
func (st *serverTSSTransport) Send(to Identity, ceremonyID CeremonyID, data []byte) error {
	if len(data) < 1 {
		return errors.New("empty TSS data")
	}

	ctype, ok := st.ceremonyType(ceremonyID)
	if !ok {
		return fmt.Errorf("ceremony %s: %w", ceremonyID, ErrUnknownCeremony)
	}

	var flags TSSMsgFlags
	var wireData []byte

	if data[0] == msgTypeBroadcast {
		flags |= TSSFlagBroadcast
	}

	if ctype == CeremonyReshare {
		if len(data) < wireHeaderLen {
			return errors.New("reshare data too short")
		}
		cflags := data[1]
		if cflags&cflagToOld != 0 {
			flags |= TSSFlagToOld
		}
		if cflags&cflagToNew != 0 {
			flags |= TSSFlagToNew
		}
		if cflags&cflagFromNew != 0 {
			flags |= TSSFlagFromNew
		}
		wireData = data[wireHeaderLen:]
	} else {
		wireData = data[1:]
	}

	hash := HashTSSMessage(ceremonyID, st.server.secret.Identity, ctype, flags, wireData)
	sig := st.server.secret.Sign(hash)

	msg := TSSMessage{
		CeremonyID: ceremonyID,
		Type:       ctype,
		From:       st.server.secret.Identity,
		Flags:      flags,
		Data:       wireData,
		Signature:  sig,
	}

	// Prefer direct session for lower latency.  If no direct
	// session exists (sparse mesh), fall back to sealed-box
	// e2e encryption with multi-hop delivery through the mesh.
	st.server.mtx.RLock()
	tr := st.server.sessions[to]
	st.server.mtx.RUnlock()

	if tr != nil {
		return tr.Write(st.server.secret.Identity, msg)
	}
	log.Debugf("tss send %s: no direct session, using encrypted envelope", to)
	return st.server.SendEncrypted(to, msg)
}

// =============================================================================
// Server RPC Dispatch — CeremonyRequest → TSS engine
// =============================================================================

// dispatchKeygen handles a keygen CeremonyRequest.  The ceremony
// runs asynchronously under the context registerCeremony hands out,
// so a verified CeremonyAbort cancels the rounds; the result is
// logged on completion.  If this node is the coordinator, it
// broadcasts CeremonyResult to all peers on success or failure.
func (s *Server) dispatchKeygen(req CeremonyRequest) {
	if len(req.Committee) == 0 {
		log.Errorf("keygen %s: empty committee", req.CeremonyID)
		return
	}

	ctx, registered := s.registerCeremony(req.CeremonyID, CeremonyKeygen,
		req.Coordinator, req.Committee)
	if !registered {
		return // duplicate of a running ceremony
	}
	s.stt.registerCeremony(req.CeremonyID, CeremonyKeygen)

	isCoordinator := req.Coordinator == s.secret.Identity

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.stt.unregisterCeremony(req.CeremonyID)

		// Bind authenticated e2e keys for the whole committee
		// before rounds start so the encrypted fallback path
		// never lacks a key mid-ceremony.
		err := s.ensureCommitteeKeys(ctx, req.Committee)
		var keyID []byte
		if err == nil {
			keyID, err = s.tss.Keygen(ctx, req.CeremonyID,
				req.Committee, req.Threshold)
		}
		if err != nil {
			log.Errorf("keygen %s: %v", req.CeremonyID, err)
			s.failCeremony(req.CeremonyID, err.Error())
			if isCoordinator {
				result := CeremonyResult{
					CeremonyID: req.CeremonyID,
					Success:    false,
					Error:      err.Error(),
					Signer:     s.secret.Identity,
				}
				result.Signature = s.secret.Sign(HashCeremonyResult(result))
				if berr := s.Broadcast(result); berr != nil {
					log.Errorf("keygen %s: broadcast failure: %v",
						req.CeremonyID, berr)
				}
			}
			return
		}
		log.Infof("keygen %s complete: key=%x",
			req.CeremonyID, keyID)
		s.mtx.Lock()
		if ci, ok := s.ceremonies[req.CeremonyID]; ok {
			ci.KeyID = keyID
		}
		s.mtx.Unlock()
		s.completeCeremony(req.CeremonyID)
		if isCoordinator {
			result := CeremonyResult{
				CeremonyID: req.CeremonyID,
				Success:    true,
				Signer:     s.secret.Identity,
			}
			result.Signature = s.secret.Sign(HashCeremonyResult(result))
			if berr := s.Broadcast(result); berr != nil {
				log.Errorf("keygen %s: broadcast result: %v",
					req.CeremonyID, berr)
			}
		}
	}()
}

// dispatchSign handles a sign CeremonyRequest.  The completed
// signature is published through CeremonyInfo.Signature, which the
// ceremony status and list RPCs return, so the caller that requested
// the signature can collect it.
func (s *Server) dispatchSign(req CeremonyRequest) {
	if len(req.Committee) == 0 {
		log.Errorf("sign %s: empty committee", req.CeremonyID)
		return
	}
	if len(req.Data) != sha256.Size {
		log.Errorf("sign %s: data must be %d bytes, got %d",
			req.CeremonyID, sha256.Size, len(req.Data))
		return
	}

	ctx, registered := s.registerCeremony(req.CeremonyID, CeremonySign,
		Identity{}, req.Committee)
	if !registered {
		return // duplicate of a running ceremony
	}
	s.stt.registerCeremony(req.CeremonyID, CeremonySign)

	var data [32]byte
	copy(data[:], req.Data)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.stt.unregisterCeremony(req.CeremonyID)

		// The signers' keys were bound during keygen, but a peer
		// record — and the key binding it holds — may have
		// expired since.
		err := s.ensureCommitteeKeys(ctx, req.Committee)
		var r, sigS []byte
		if err == nil {
			r, sigS, err = s.tss.Sign(ctx, req.CeremonyID,
				req.KeyID, req.Committee, req.Threshold, data)
		}
		if err != nil {
			log.Errorf("sign %s: %v", req.CeremonyID, err)
			s.failCeremony(req.CeremonyID, err.Error())
			return
		}
		log.Infof("sign %s complete: r=%x.. s=%x..",
			req.CeremonyID, r[:8], sigS[:8])
		s.mtx.Lock()
		if ci, ok := s.ceremonies[req.CeremonyID]; ok {
			ci.Signature = make([]byte, 0, len(r)+len(sigS))
			ci.Signature = append(ci.Signature, r...)
			ci.Signature = append(ci.Signature, sigS...)
		}
		s.mtx.Unlock()
		s.completeCeremony(req.CeremonyID)
	}()
}

// dispatchReshare handles a reshare CeremonyRequest.
func (s *Server) dispatchReshare(req CeremonyRequest) {
	if len(req.OldCommittee) == 0 || len(req.NewCommittee) == 0 {
		log.Errorf("reshare %s: empty committee",
			req.CeremonyID)
		return
	}

	// Track union of old and new committees as participants.
	allParties := make([]Identity, 0, len(req.OldCommittee)+len(req.NewCommittee))
	allParties = append(allParties, req.OldCommittee...)
	for _, np := range req.NewCommittee {
		found := false
		for _, op := range req.OldCommittee {
			if np == op {
				found = true
				break
			}
		}
		if !found {
			allParties = append(allParties, np)
		}
	}
	ctx, registered := s.registerCeremony(req.CeremonyID, CeremonyReshare,
		Identity{}, allParties)
	if !registered {
		return // duplicate of a running ceremony
	}
	s.stt.registerCeremony(req.CeremonyID, CeremonyReshare)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.stt.unregisterCeremony(req.CeremonyID)

		// Members joining in the new committee have no key bound
		// from keygen; fetch the whole union before rounds start.
		err := s.ensureCommitteeKeys(ctx, allParties)
		if err == nil {
			err = s.tss.Reshare(ctx, req.CeremonyID, req.KeyID,
				req.OldCommittee, req.NewCommittee,
				req.OldThreshold, req.NewThreshold)
		}
		if err != nil {
			log.Errorf("reshare %s: %v",
				req.CeremonyID, err)
			s.failCeremony(req.CeremonyID, err.Error())
			return
		}
		log.Infof("reshare %s complete", req.CeremonyID)
		s.completeCeremony(req.CeremonyID)
	}()
}

// ensureCommitteeKeys binds authenticated e2e keys for all ceremony
// participants, bounded by naclXchgEnsureTimeout and by the ceremony
// context.  A participant whose key cannot be fetched is unreachable
// enough that the ceremony should fail fast rather than stall in a
// round.
func (s *Server) ensureCommitteeKeys(ctx context.Context, parties []Identity) error {
	ctx, cancel := context.WithTimeout(ctx, naclXchgEnsureTimeout)
	defer cancel()
	return s.ensurePeerKeys(ctx, parties)
}

// dispatchTSSMessage verifies and routes an incoming TSSMessage to
// the TSS engine. Translates TSSMessage.Flags back to the
// byte-prefix format expected by HandleMessage.
func (s *Server) dispatchTSSMessage(msg TSSMessage) {
	if len(msg.Data) > maxWireDataLen {
		log.Errorf("tss msg from %s: data too large (%d bytes)",
			msg.From, len(msg.Data))
		return
	}

	hash := HashTSSMessage(msg.CeremonyID, msg.From, msg.Type, msg.Flags, msg.Data)
	if _, err := Verify(hash, msg.From, msg.Signature); err != nil {
		log.Errorf("tss msg from %s: bad signature: %v",
			msg.From, err)
		return
	}

	// Reconstruct byte-prefix wire format for HandleMessage.
	var data []byte
	bcast := msgTypeP2P
	if msg.Flags&TSSFlagBroadcast != 0 {
		bcast = msgTypeBroadcast
	}

	if msg.Type == CeremonyReshare {
		var cflags byte
		if msg.Flags&TSSFlagToOld != 0 {
			cflags |= cflagToOld
		}
		if msg.Flags&TSSFlagToNew != 0 {
			cflags |= cflagToNew
		}
		if msg.Flags&TSSFlagFromNew != 0 {
			cflags |= cflagFromNew
		}
		data = make([]byte, wireHeaderLen+len(msg.Data))
		data[0] = bcast
		data[1] = cflags
		copy(data[wireHeaderLen:], msg.Data)
	} else {
		data = make([]byte, 1+len(msg.Data))
		data[0] = bcast
		copy(data[1:], msg.Data)
	}

	// HandleMessage may fail transiently if the TSSMessage arrives
	// before the KeygenRequest that registers the ceremony.  This
	// is a normal race in a distributed mesh — the coordinator
	// starts producing messages immediately while the request is
	// still being routed to other committee members.  Retry with
	// backoff up to ~5 seconds before giving up.  The retry runs
	// in a goroutine to avoid blocking the connection handler
	// (which might be delivering the KeygenRequest itself).
	err := s.tss.HandleMessage(s.tssCtx, msg.From, msg.CeremonyID, data)
	if err == nil {
		return
	}
	if !errors.Is(err, ErrUnknownCeremony) {
		log.Errorf("tss msg from %s ceremony %s: %v",
			msg.From, msg.CeremonyID, err)
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for _, delay := range tssRetryBackoff {
			timer := time.NewTimer(delay)
			select {
			case <-s.tssCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			err = s.tss.HandleMessage(s.tssCtx, msg.From, msg.CeremonyID, data)
			if err == nil {
				return
			}
			if !errors.Is(err, ErrUnknownCeremony) {
				break
			}
		}
		log.Errorf("tss msg from %s ceremony %s: %v (after retries)",
			msg.From, msg.CeremonyID, err)
	}()
}

// =============================================================================
// Helpers
// =============================================================================

// partiesToIdentities converts tss-lib UnSortedPartyIDs to a slice
// of continuum Identities. Returns nil if any conversion fails.
func partiesToIdentities(pids tss.UnSortedPartyIDs) []Identity {
	if len(pids) == 0 {
		return nil
	}
	ids := make([]Identity, len(pids))
	for i, pid := range pids {
		id, err := NewIdentityFromString(pid.Id)
		if err != nil {
			log.Errorf("bad party ID %q: %v", pid.Id, err)
			return nil
		}
		ids[i] = *id
	}
	return ids
}
