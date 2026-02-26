// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

// ceremony.go defines the CeremonyInitiator interface — the seam
// between "who decides what ceremony to run" (external: blockchain
// or debug) and "how to run the ceremony" (internal: TSS over p2p).
//
// In debug mode, hemictl sends protocol messages that are adapted
// to CeremonyRequest and pushed onto the channel.  In production,
// a blockchain watcher emits CeremonyRequest directly from chain
// events.  The node's ceremonyLoop reads from the channel and
// dispatches to the TSS engine.

import "context"

// CeremonyInitiator is the source of ceremony triggers.
// In debug mode, hemictl sends requests that are adapted to this
// interface.  In production, blockchain events implement it directly.
type CeremonyInitiator interface {
	// CeremonyChan returns a channel that emits ceremony requests.
	// The node reads from this channel and starts the appropriate
	// TSS ceremony.  Implementations should stop sending when
	// the context passed to the node's Run() is cancelled.
	CeremonyChan() <-chan CeremonyRequest
}

// CeremonyRequest is the unified internal type for ceremony triggers.
// Wire protocol types (KeygenRequest, SignRequest, ReshareRequest)
// are converted to CeremonyRequest at the network boundary.
type CeremonyRequest struct {
	CeremonyID  CeremonyID
	Type        CeremonyType
	Threshold   int        // keygen, sign
	Committee   []Identity // keygen: all parties, sign: signing parties
	Coordinator Identity   // keygen: broadcasts result
	KeyID       []byte     // sign, reshare
	Data        []byte     // sign: 32-byte hash

	// Reshare-specific fields.
	OldCommittee []Identity
	OldThreshold int
	NewCommittee []Identity
	NewThreshold int
}

// debugInitiator implements CeremonyInitiator for debug mode.
// The protocol dispatch loop converts incoming KeygenRequest,
// SignRequest, and ReshareRequest messages into CeremonyRequest
// and sends them here.
type debugInitiator struct {
	ch chan CeremonyRequest
}

func newDebugInitiator() *debugInitiator {
	return &debugInitiator{
		// Buffer of 1: debug mode sends one ceremony at a time and
		// polls for completion before the next.  Submit() drops on
		// full channel to avoid blocking the dispatch loop.
		ch: make(chan CeremonyRequest, 1),
	}
}

// CeremonyChan returns the channel that emits ceremony requests.
func (d *debugInitiator) CeremonyChan() <-chan CeremonyRequest {
	return d.ch
}

// Submit sends a CeremonyRequest to the initiator channel.
// Non-blocking: drops the request if the channel is full.
func (d *debugInitiator) Submit(req CeremonyRequest) {
	select {
	case d.ch <- req:
	default:
		log.Warningf("ceremony %s: initiator channel full, dropped",
			req.CeremonyID)
	}
}

// ceremonyLoop reads from the CeremonyInitiator channel and
// dispatches each request to the appropriate TSS function.
// Exits when ctx is cancelled.
func (s *Server) ceremonyLoop(ctx context.Context) {
	log.Tracef("ceremonyLoop")
	defer log.Tracef("ceremonyLoop exit")
	defer s.wg.Done()

	ch := s.initiator.CeremonyChan()
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-ch:
			if !ok {
				return
			}
			switch req.Type {
			case CeremonyKeygen:
				s.dispatchKeygen(req)
			case CeremonySign:
				s.dispatchSign(req)
			case CeremonyReshare:
				s.dispatchReshare(req)
			default:
				log.Errorf("ceremony %s: unknown type %d",
					req.CeremonyID, req.Type)
			}
		}
	}
}

// ceremonyFromKeygen converts a wire KeygenRequest to CeremonyRequest.
func ceremonyFromKeygen(req KeygenRequest) *CeremonyRequest {
	parties := partiesToIdentities(req.Committee)
	if parties == nil {
		return nil
	}
	return &CeremonyRequest{
		CeremonyID:  req.CeremonyID,
		Type:        CeremonyKeygen,
		Threshold:   req.Threshold,
		Committee:   parties,
		Coordinator: req.Coordinator,
	}
}

// ceremonyFromSign converts a wire SignRequest to CeremonyRequest.
func ceremonyFromSign(req SignRequest) *CeremonyRequest {
	parties := partiesToIdentities(req.Committee)
	if parties == nil {
		return nil
	}
	return &CeremonyRequest{
		CeremonyID: req.CeremonyID,
		Type:       CeremonySign,
		Threshold:  req.Threshold,
		Committee:  parties,
		KeyID:      req.KeyID,
		Data:       req.Data,
	}
}

// ceremonyFromReshare converts a wire ReshareRequest to CeremonyRequest.
func ceremonyFromReshare(req ReshareRequest) *CeremonyRequest {
	oldParties := partiesToIdentities(req.OldCommittee)
	newParties := partiesToIdentities(req.NewCommittee)
	if oldParties == nil || newParties == nil {
		return nil
	}
	return &CeremonyRequest{
		CeremonyID:   req.CeremonyID,
		Type:         CeremonyReshare,
		KeyID:        req.KeyID,
		OldCommittee: oldParties,
		OldThreshold: req.OldThreshold,
		NewCommittee: newParties,
		NewThreshold: req.NewThreshold,
	}
}
