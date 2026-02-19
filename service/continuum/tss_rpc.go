// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"errors"
	"fmt"
	"sync"

	"github.com/hemilabs/x/tss-lib/v2/tss"
)

// =============================================================================
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
		return fmt.Errorf("unknown ceremony %s", ceremonyID)
	}

	var flags TSSMsgFlags
	var wireData []byte

	if data[0] == 0x01 {
		flags |= TSSFlagBroadcast
	}

	if ctype == CeremonyReshare {
		if len(data) < 2 {
			return errors.New("reshare data too short")
		}
		cflags := data[1]
		if cflags&0x01 != 0 {
			flags |= TSSFlagToOld
		}
		if cflags&0x02 != 0 {
			flags |= TSSFlagToNew
		}
		if cflags&0x04 != 0 {
			flags |= TSSFlagFromNew
		}
		wireData = data[2:]
	} else {
		wireData = data[1:]
	}

	hash := HashTSSMessage(ceremonyID, wireData)
	sig := st.server.secret.Sign(hash)

	msg := TSSMessage{
		CeremonyID: ceremonyID,
		Type:       ctype,
		From:       st.server.secret.Identity,
		Flags:      flags,
		Data:       wireData,
		Signature:  sig,
	}

	st.server.mtx.RLock()
	tr := st.server.sessions[to]
	st.server.mtx.RUnlock()

	if tr == nil {
		return fmt.Errorf("no session for peer %s", to)
	}
	return tr.Write(st.server.secret.Identity, msg)
}

// =============================================================================
// Server RPC Dispatch — incoming protocol messages → TSS engine
// =============================================================================

// dispatchKeygen handles an incoming KeygenRequest. The ceremony
// runs asynchronously; the result is logged on completion.
// If this node is the coordinator, it broadcasts CeremonyResult
// to all peers on success or failure.
func (s *Server) dispatchKeygen(req KeygenRequest) {
	parties := partiesToIdentities(req.Committee)
	if parties == nil {
		log.Errorf("keygen %s: empty committee", req.CeremonyID)
		return
	}

	s.stt.registerCeremony(req.CeremonyID, CeremonyKeygen)
	s.registerCeremony(req.CeremonyID, CeremonyKeygen, req.Coordinator)

	isCoordinator := req.Coordinator == s.secret.Identity

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.stt.unregisterCeremony(req.CeremonyID)

		keyID, err := s.tss.Keygen(s.tssCtx, req.CeremonyID,
			parties, req.Threshold)
		if err != nil {
			log.Errorf("keygen %s: %v", req.CeremonyID, err)
			s.failCeremony(req.CeremonyID, err.Error())
			if isCoordinator {
				if berr := s.Broadcast(CeremonyResult{
					CeremonyID: req.CeremonyID,
					Success:    false,
					Error:      err.Error(),
				}); berr != nil {
					log.Errorf("keygen %s: broadcast failure: %v",
						req.CeremonyID, berr)
				}
			}
			return
		}
		log.Infof("keygen %s complete: key=%x",
			req.CeremonyID, keyID)
		s.completeCeremony(req.CeremonyID)
		if isCoordinator {
			if berr := s.Broadcast(CeremonyResult{
				CeremonyID: req.CeremonyID,
				Success:    true,
			}); berr != nil {
				log.Errorf("keygen %s: broadcast result: %v",
					req.CeremonyID, berr)
			}
		}
	}()
}

// dispatchSign handles an incoming SignRequest.
func (s *Server) dispatchSign(req SignRequest) {
	parties := partiesToIdentities(req.Committee)
	if parties == nil {
		log.Errorf("sign %s: empty committee", req.CeremonyID)
		return
	}
	if len(req.Data) != 32 {
		log.Errorf("sign %s: data must be 32 bytes, got %d",
			req.CeremonyID, len(req.Data))
		return
	}

	s.stt.registerCeremony(req.CeremonyID, CeremonySign)
	s.registerCeremony(req.CeremonyID, CeremonySign, Identity{})

	var data [32]byte
	copy(data[:], req.Data)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.stt.unregisterCeremony(req.CeremonyID)

		r, sigS, err := s.tss.Sign(s.tssCtx, req.CeremonyID,
			req.KeyID, parties, req.Threshold, data)
		if err != nil {
			log.Errorf("sign %s: %v", req.CeremonyID, err)
			s.failCeremony(req.CeremonyID, err.Error())
			return
		}
		log.Infof("sign %s complete: r=%x.. s=%x..",
			req.CeremonyID, r[:8], sigS[:8])
		s.completeCeremony(req.CeremonyID)
	}()
}

// dispatchReshare handles an incoming ReshareRequest.
func (s *Server) dispatchReshare(req ReshareRequest) {
	oldParties := partiesToIdentities(req.OldCommittee)
	newParties := partiesToIdentities(req.NewCommittee)
	if oldParties == nil || newParties == nil {
		log.Errorf("reshare %s: empty committee",
			req.CeremonyID)
		return
	}

	s.stt.registerCeremony(req.CeremonyID, CeremonyReshare)
	s.registerCeremony(req.CeremonyID, CeremonyReshare, Identity{})

	// Determine keyID from existing key shares. For reshare, the
	// router doesn't send a keyID — the node discovers it from
	// its local store. We use a zero keyID here; the TSS engine
	// identifies the key via committee membership.
	// XXX keyID resolution belongs in a higher-level coordinator.
	var keyID []byte

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.stt.unregisterCeremony(req.CeremonyID)

		err := s.tss.Reshare(s.tssCtx, req.CeremonyID, keyID,
			oldParties, newParties,
			req.OldThreshold, req.NewThreshold)
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

// dispatchTSSMessage verifies and routes an incoming TSSMessage to
// the TSS engine. Translates TSSMessage.Flags back to the
// byte-prefix format expected by HandleMessage.
func (s *Server) dispatchTSSMessage(msg TSSMessage) {
	hash := HashTSSMessage(msg.CeremonyID, msg.Data)
	if _, err := Verify(hash, msg.From, msg.Signature); err != nil {
		log.Errorf("tss msg from %s: bad signature: %v",
			msg.From, err)
		return
	}

	// Reconstruct byte-prefix wire format for HandleMessage.
	var data []byte
	var bcast byte
	if msg.Flags&TSSFlagBroadcast != 0 {
		bcast = 0x01
	}

	if msg.Type == CeremonyReshare {
		var cflags byte
		if msg.Flags&TSSFlagToOld != 0 {
			cflags |= 0x01
		}
		if msg.Flags&TSSFlagToNew != 0 {
			cflags |= 0x02
		}
		if msg.Flags&TSSFlagFromNew != 0 {
			cflags |= 0x04
		}
		data = make([]byte, 2+len(msg.Data))
		data[0] = bcast
		data[1] = cflags
		copy(data[2:], msg.Data)
	} else {
		data = make([]byte, 1+len(msg.Data))
		data[0] = bcast
		copy(data[1:], msg.Data)
	}

	if err := s.tss.HandleMessage(msg.From, msg.CeremonyID, data); err != nil {
		log.Errorf("tss msg from %s ceremony %s: %v",
			msg.From, msg.CeremonyID, err)
	}
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
