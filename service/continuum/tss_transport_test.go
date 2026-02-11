// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build tss_smoke

package continuum

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hemilabs/x/tss-lib/v2/common"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/resharing"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v2/tss"
)

// =============================================================================
// tssTransportNode — RPC-driven TSS participant over encrypted Transport
// =============================================================================

// tssTransportNode is a TSS participant that communicates via the full
// continuum protocol stack: TCP → KeyExchange (ECDH) → Handshake
// (secp256k1 identity) → RPC envelope routing.
//
// Ceremonies are initiated via protocol messages (KeygenRequest,
// SignRequest, ReshareRequest) received through Transport.Read,
// and tss-lib protocol messages flow as signed TSSMessage envelopes
// through Transport.Write.
type tssTransportNode struct {
	t         *testing.T
	id        Identity
	secret    *Secret
	partyID   *tss.PartyID
	preParams *keygen.LocalPreParams

	// Key storage: keyID → key share
	keys   map[string]*keygen.LocalPartySaveData
	keysMu sync.RWMutex

	// Active ceremonies
	ceremonies   map[CeremonyID]*transportCeremony
	ceremoniesMu sync.Mutex

	// Encrypted Transport connections to peers
	transports   map[Identity]*Transport
	transportsMu sync.RWMutex
	listener     net.Listener

	// Lifecycle
	readCtx    context.Context
	readCancel context.CancelFunc
	readWg     sync.WaitGroup
}

// transportCeremony tracks an active TSS ceremony on a transport node.
type transportCeremony struct {
	ctype     CeremonyType
	party     tss.Party // sole party for keygen/sign; new party for reshare
	pids      tss.SortedPartyIDs
	pidToID   map[string]Identity // PartyID.Id → Identity
	outCh     chan tss.Message
	endCh     chan any // keygen.LocalPartySaveData or common.SignatureData
	done      chan struct{}
	threshold int
	keyID     string
	data      []byte

	// Reshare-specific fields
	oldParty tss.Party
	oldPids  tss.SortedPartyIDs
	newPids  tss.SortedPartyIDs
}

func newTSSTransportNode(t *testing.T, preParams *keygen.LocalPreParams) *tssTransportNode {
	t.Helper()

	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &tssTransportNode{
		t:          t,
		id:         secret.Identity,
		secret:     secret,
		partyID:    tss.NewPartyID(secret.String(), secret.String(), new(big.Int).SetBytes(secret.Identity[:])),
		preParams:  preParams,
		keys:       make(map[string]*keygen.LocalPartySaveData),
		ceremonies: make(map[CeremonyID]*transportCeremony),
		transports: make(map[Identity]*Transport),
		listener:   listener,
		readCtx:    ctx,
		readCancel: cancel,
	}
}

// =============================================================================
// Read loop — dispatches incoming RPC protocol messages
// =============================================================================

// startReadLoop launches a goroutine that reads protocol messages from
// an encrypted Transport and dispatches to the appropriate handler.
//
// Goroutine contract:
//
//	Owner:     tssTransportNode
//	Lifecycle: runs until Transport error or context cancel
//	Kill:      readCancel + Transport.Close
//	Tracking:  readWg
func (n *tssTransportNode) startReadLoop(tr *Transport, remoteID Identity) {
	n.readWg.Add(1)
	go func() {
		defer n.readWg.Done()
		for {
			_, cmd, err := tr.Read()
			if err != nil {
				select {
				case <-n.readCtx.Done():
					return
				default:
				}
				n.t.Logf("readLoop %s←%s: %v",
					n.id, remoteID, err)
				return
			}

			switch v := cmd.(type) {
			case *KeygenRequest:
				n.handleKeygenRequest(*v)
			case *SignRequest:
				n.handleSignRequest(*v)
			case *ReshareRequest:
				n.handleReshareRequest(*v)
			case *TSSMessage:
				n.handleTSSMessage(*v)
			}
		}
	}()
}

// =============================================================================
// Ceremony handlers — process incoming RPC commands
// =============================================================================

func (n *tssTransportNode) handleKeygenRequest(req KeygenRequest) {
	n.ceremoniesMu.Lock()
	defer n.ceremoniesMu.Unlock()

	sortedPids := tss.SortPartyIDs(req.Committee)
	ctx := tss.NewPeerContext(sortedPids)

	var ourPid *tss.PartyID
	for _, pid := range sortedPids {
		if pid.Id == n.partyID.Id {
			ourPid = pid
			break
		}
	}
	if ourPid == nil {
		n.t.Logf("Node %s not in keygen committee", n.id)
		return
	}

	pidToID := buildPIDToIdentity(sortedPids)
	params := tss.NewParameters(tss.S256(), ctx, ourPid,
		len(sortedPids), req.Threshold)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan *keygen.LocalPartySaveData, 1)

	var party *keygen.LocalParty
	if n.preParams != nil {
		party = keygen.NewLocalParty(params, outCh, endCh,
			*n.preParams).(*keygen.LocalParty)
	} else {
		party = keygen.NewLocalParty(params, outCh,
			endCh).(*keygen.LocalParty)
	}

	tc := &transportCeremony{
		ctype:     CeremonyKeygen,
		party:     party,
		pids:      sortedPids,
		pidToID:   pidToID,
		outCh:     outCh,
		endCh:     make(chan any, 1),
		done:      make(chan struct{}),
		threshold: req.Threshold,
	}
	n.ceremonies[req.CeremonyID] = tc

	go n.pumpMessages(req.CeremonyID, tc)
	go n.waitKeygenEnd(req.CeremonyID, endCh)

	if err := party.Start(); err != nil {
		n.t.Logf("Keygen start error: %v", err)
	}
}

func (n *tssTransportNode) handleSignRequest(req SignRequest) {
	n.ceremoniesMu.Lock()
	defer n.ceremoniesMu.Unlock()

	n.keysMu.RLock()
	key, ok := n.keys[string(req.KeyID)]
	n.keysMu.RUnlock()
	if !ok {
		n.t.Logf("Node %s: key %x not found for signing",
			n.id, req.KeyID)
		return
	}

	sortedPids := tss.SortPartyIDs(req.Committee)
	ctx := tss.NewPeerContext(sortedPids)

	var ourPid *tss.PartyID
	for _, pid := range sortedPids {
		if pid.Id == n.partyID.Id {
			ourPid = pid
			break
		}
	}
	if ourPid == nil {
		n.t.Logf("Node %s not in signing committee", n.id)
		return
	}

	pidToID := buildPIDToIdentity(sortedPids)
	params := tss.NewParameters(tss.S256(), ctx, ourPid,
		len(sortedPids), req.Threshold)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan *common.SignatureData, 1)

	party := signing.NewLocalParty(
		new(big.Int).SetBytes(req.Data), params, *key,
		outCh, endCh, len(req.Data)).(*signing.LocalParty)

	tc := &transportCeremony{
		ctype:     CeremonySign,
		party:     party,
		pids:      sortedPids,
		pidToID:   pidToID,
		outCh:     outCh,
		endCh:     make(chan any, 1),
		done:      make(chan struct{}),
		threshold: req.Threshold,
		keyID:     string(req.KeyID),
		data:      req.Data,
	}
	n.ceremonies[req.CeremonyID] = tc

	go n.pumpMessages(req.CeremonyID, tc)
	go n.waitSignEnd(req.CeremonyID, endCh)

	if err := party.Start(); err != nil {
		n.t.Logf("Sign start error: %v", err)
	}
}

func (n *tssTransportNode) handleReshareRequest(req ReshareRequest) {
	n.ceremoniesMu.Lock()
	defer n.ceremoniesMu.Unlock()

	selfStr := n.partyID.Id

	// Determine committee membership.
	var inOld, inNew bool
	for _, pid := range req.OldCommittee {
		if pid.Id == selfStr {
			inOld = true
			break
		}
	}
	for _, pid := range req.NewCommittee {
		if pid.Id == selfStr {
			inNew = true
			break
		}
	}
	if !inOld && !inNew {
		return
	}

	// Load existing key share if in old committee.
	var keyShare keygen.LocalPartySaveData
	var keyID string
	if inOld {
		n.keysMu.RLock()
		for k, v := range n.keys {
			keyID = k
			keyShare = *v
			break
		}
		n.keysMu.RUnlock()
	}

	// Build party contexts. New committee keys are XORed with 1
	// so tss-lib sees disjoint committees for overlapping parties.
	oldPids, ourOldPid, oldPidToID := buildReshareContext(
		req.OldCommittee, selfStr, false)
	newPids, ourNewPid, newPidToID := buildReshareContext(
		req.NewCommittee, selfStr, true)

	allPidToID := make(map[string]Identity)
	for k, v := range oldPidToID {
		allPidToID[k] = v
	}
	for k, v := range newPidToID {
		allPidToID[k] = v
	}

	oldCtx := tss.NewPeerContext(oldPids)
	newCtx := tss.NewPeerContext(newPids)

	outCh := make(chan tss.Message,
		(len(oldPids)+len(newPids))*10)
	endCh := make(chan *keygen.LocalPartySaveData, 2)

	var oldParty, newParty tss.Party

	if inOld && ourOldPid != nil {
		params := tss.NewReSharingParameters(tss.S256(),
			oldCtx, newCtx, ourOldPid,
			len(oldPids), req.OldThreshold,
			len(newPids), req.NewThreshold)
		oldParty = resharing.NewLocalParty(params,
			keyShare, outCh, endCh)
	}

	if inNew && ourNewPid != nil {
		params := tss.NewReSharingParameters(tss.S256(),
			oldCtx, newCtx, ourNewPid,
			len(oldPids), req.OldThreshold,
			len(newPids), req.NewThreshold)
		params.SetNoProofMod()
		params.SetNoProofFac()
		save := keygen.NewLocalPartySaveData(len(newPids))
		newParty = resharing.NewLocalParty(params,
			save, outCh, endCh)
	}

	expectedEnds := 0
	if inOld {
		expectedEnds++
	}
	if inNew {
		expectedEnds++
	}

	tc := &transportCeremony{
		ctype:     CeremonyReshare,
		party:     newParty,
		oldParty:  oldParty,
		oldPids:   oldPids,
		newPids:   newPids,
		pidToID:   allPidToID,
		outCh:     outCh,
		endCh:     make(chan any, expectedEnds),
		done:      make(chan struct{}),
		threshold: req.NewThreshold,
		keyID:     keyID,
	}
	n.ceremonies[req.CeremonyID] = tc

	// Forward tss-lib end channel results to ceremony.
	go func() {
		for i := 0; i < expectedEnds; i++ {
			select {
			case save := <-endCh:
				tc.endCh <- save
			case <-tc.done:
				return
			}
		}
	}()

	// Start parties before message pump. Start() writes to the
	// buffered outCh. Starting first ensures both party instances
	// exist for local self-delivery between old/new parties.
	if oldParty != nil {
		go func() {
			if err := oldParty.Start(); err != nil {
				n.t.Logf("old reshare start: %v", err)
			}
		}()
	}
	if newParty != nil {
		go func() {
			if err := newParty.Start(); err != nil {
				n.t.Logf("new reshare start: %v", err)
			}
		}()
	}

	go n.pumpReshareMessages(req.CeremonyID, tc)
}

// =============================================================================
// TSSMessage handler — verify signature and route to ceremony
// =============================================================================

func (n *tssTransportNode) handleTSSMessage(msg TSSMessage) {
	// Verify ed25519 signature.
	hash := HashTSSMessage(msg.CeremonyID, msg.Data)
	if _, err := Verify(hash, msg.From, msg.Signature); err != nil {
		n.t.Logf("Node %s: bad sig from %s: %v",
			n.id, msg.From, err)
		return
	}

	n.ceremoniesMu.Lock()
	tc, ok := n.ceremonies[msg.CeremonyID]
	n.ceremoniesMu.Unlock()
	if !ok {
		n.t.Logf("Node %s: unknown ceremony %s",
			n.id, msg.CeremonyID)
		return
	}

	// Reshare messages carry committee flags in Data[0].
	if tc.ctype == CeremonyReshare {
		n.routeReshareMessage(tc, msg)
		return
	}

	// Keygen/Sign: single party routing.
	fromIDStr := msg.From.String()
	var fromPid *tss.PartyID
	for _, pid := range tc.pids {
		if pid.Id == fromIDStr {
			fromPid = pid
			break
		}
	}
	if fromPid == nil {
		n.t.Logf("Node %s: sender %s not in ceremony",
			n.id, msg.From)
		return
	}

	parsed, err := tss.ParseWireMessage(msg.Data, fromPid,
		msg.IsBroadcast())
	if err != nil {
		n.t.Logf("Node %s: parse error: %v", n.id, err)
		return
	}

	if _, err := tc.party.Update(parsed); err != nil {
		n.t.Logf("Node %s: update error: %v", n.id, err)
	}
}

// routeReshareMessage routes an incoming TSSMessage to the correct
// reshare party instance(s) based on the Flags field.
func (n *tssTransportNode) routeReshareMessage(tc *transportCeremony, msg TSSMessage) {
	if len(msg.Data) == 0 {
		return
	}

	toOld := msg.Flags&TSSFlagToOld != 0
	toNew := msg.Flags&TSSFlagToNew != 0
	fromNew := msg.Flags&TSSFlagFromNew != 0
	fromIDStr := msg.From.String()

	findFrom := func(pids tss.SortedPartyIDs) *tss.PartyID {
		for _, pid := range pids {
			if pid.Id == fromIDStr {
				return pid
			}
		}
		return nil
	}

	isBcast := msg.IsBroadcast()

	if toOld && tc.oldParty != nil {
		var fromPid *tss.PartyID
		if fromNew {
			fromPid = findFrom(tc.newPids)
		} else {
			fromPid = findFrom(tc.oldPids)
		}
		if fromPid != nil {
			parsed, err := tss.ParseWireMessage(msg.Data,
				fromPid, isBcast)
			if err == nil {
				if _, uErr := tc.oldParty.Update(parsed); uErr != nil {
					n.t.Logf("reshare old update: %v", uErr)
				}
			}
		}
	}

	if toNew && tc.party != nil {
		var fromPid *tss.PartyID
		if fromNew {
			fromPid = findFrom(tc.newPids)
		} else {
			fromPid = findFrom(tc.oldPids)
		}
		if fromPid != nil {
			parsed, err := tss.ParseWireMessage(msg.Data,
				fromPid, isBcast)
			if err == nil {
				if _, uErr := tc.party.Update(parsed); uErr != nil {
					n.t.Logf("reshare new update: %v", uErr)
				}
			}
		}
	}
}

// =============================================================================
// Message pump — outgoing tss-lib messages → signed TSSMessage → Transport
// =============================================================================

// pumpMessages reads outgoing tss-lib messages for keygen/sign
// ceremonies, wraps them in signed TSSMessage envelopes, and writes
// them to peer Transports.
func (n *tssTransportNode) pumpMessages(cid CeremonyID, tc *transportCeremony) {
	for {
		select {
		case msg := <-tc.outCh:
			wireData, _, err := msg.WireBytes()
			if err != nil {
				continue
			}

			var flags TSSMsgFlags
			if msg.GetTo() == nil {
				flags = TSSFlagBroadcast
			}

			hash := HashTSSMessage(cid, wireData)
			sig := n.secret.Sign(hash)

			tssMsg := TSSMessage{
				CeremonyID: cid,
				Type:       tc.ctype,
				From:       n.id,
				Flags:      flags,
				Data:       wireData,
				Signature:  sig,
			}

			if msg.GetTo() == nil {
				// Broadcast to all committee peers.
				for _, pid := range tc.pids {
					if pid.Id == n.partyID.Id {
						continue
					}
					id := tc.pidToID[pid.Id]
					n.transportsMu.RLock()
					tr := n.transports[id]
					n.transportsMu.RUnlock()
					if tr != nil {
						if err := tr.Write(n.id, tssMsg); err != nil {
							n.t.Logf("pump write: %v", err)
						}
					}
				}
			} else {
				// P2P to specific peers.
				for _, dest := range msg.GetTo() {
					id := tc.pidToID[dest.Id]
					n.transportsMu.RLock()
					tr := n.transports[id]
					n.transportsMu.RUnlock()
					if tr != nil {
						if err := tr.Write(n.id, tssMsg); err != nil {
							n.t.Logf("pump write: %v", err)
						}
					}
				}
			}

		case <-tc.done:
			return
		}
	}
}

// pumpReshareMessages routes outgoing reshare messages with committee
// routing encoded in the Flags field of TSSMessage.
//
// For overlapping nodes (in both old and new committees), messages
// between local party instances are self-delivered via handleTSSMessage
// rather than through the transport.
func (n *tssTransportNode) pumpReshareMessages(cid CeremonyID, tc *transportCeremony) {
	// Build new key set for fromNew detection. Old and new key
	// spaces are disjoint (XOR 1), so a key in newKeySet means
	// the message is from the new committee party instance.
	newKeySet := make(map[string]bool)
	for _, pid := range tc.newPids {
		newKeySet[pid.KeyInt().String()] = true
	}

	for {
		select {
		case msg := <-tc.outCh:
			wireData, routing, err := msg.WireBytes()
			if err != nil {
				continue
			}

			// Build flags from routing metadata.
			var flags TSSMsgFlags
			if routing.IsBroadcast {
				flags |= TSSFlagBroadcast
			}
			if routing.IsToOldCommittee {
				flags |= TSSFlagToOld
			} else if routing.IsToOldAndNewCommittees {
				flags |= TSSFlagToOld | TSSFlagToNew
			} else {
				flags |= TSSFlagToNew
			}
			fromKey := msg.GetFrom().KeyInt()
			if newKeySet[fromKey.String()] {
				flags |= TSSFlagFromNew
			}

			hash := HashTSSMessage(cid, wireData)
			sig := n.secret.Sign(hash)

			tssMsg := TSSMessage{
				CeremonyID: cid,
				Type:       CeremonyReshare,
				From:       n.id,
				Flags:      flags,
				Data:       wireData,
				Signature:  sig,
			}

			// Send to all unique peers in both committees.
			// Self-deliver for overlapping nodes.
			sent := make(map[Identity]bool)
			allPids := make([]*tss.PartyID, 0,
				len(tc.oldPids)+len(tc.newPids))
			allPids = append(allPids, tc.oldPids...)
			allPids = append(allPids, tc.newPids...)

			deliver := func(id Identity) {
				if sent[id] {
					return
				}
				sent[id] = true
				if id == n.id {
					cp := tssMsg // copy
					go n.handleTSSMessage(cp)
					return
				}
				n.transportsMu.RLock()
				tr := n.transports[id]
				n.transportsMu.RUnlock()
				if tr != nil {
					if err := tr.Write(n.id, tssMsg); err != nil {
						n.t.Logf("reshare pump: %v", err)
					}
				}
			}

			if msg.GetTo() == nil {
				for _, pid := range allPids {
					deliver(tc.pidToID[pid.Id])
				}
			} else {
				for _, dest := range msg.GetTo() {
					deliver(tc.pidToID[dest.Id])
				}
			}

		case <-tc.done:
			return
		}
	}
}

// =============================================================================
// Completion waiters
// =============================================================================

func (n *tssTransportNode) waitKeygenEnd(cid CeremonyID, endCh <-chan *keygen.LocalPartySaveData) {
	select {
	case save := <-endCh:
		keyID := save.ECDSAPub.X().Text(16)[:16]
		n.keysMu.Lock()
		n.keys[keyID] = save
		n.keysMu.Unlock()

		n.ceremoniesMu.Lock()
		if tc, ok := n.ceremonies[cid]; ok {
			tc.endCh <- save
		}
		n.ceremoniesMu.Unlock()

		n.t.Logf("Node %s: keygen complete, keyID=%s",
			n.id, keyID)

	case <-n.t.Context().Done():
		n.t.Logf("Node %s: keygen timeout", n.id)
	}
}

func (n *tssTransportNode) waitSignEnd(cid CeremonyID, endCh <-chan *common.SignatureData) {
	select {
	case sig := <-endCh:
		n.ceremoniesMu.Lock()
		if tc, ok := n.ceremonies[cid]; ok {
			tc.endCh <- sig
		}
		n.ceremoniesMu.Unlock()

		n.t.Logf("Node %s: signing complete", n.id)

	case <-n.t.Context().Done():
		n.t.Logf("Node %s: signing timeout", n.id)
	}
}

// WaitCeremony waits for a keygen or sign ceremony to complete and
// returns the result (keygen.LocalPartySaveData or common.SignatureData).
func (n *tssTransportNode) WaitCeremony(cid CeremonyID, timeout time.Duration) (any, error) {
	ctx, cancel := context.WithTimeout(n.t.Context(), timeout)
	defer cancel()

	// Wait for ceremony to be registered (async message processing).
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	var tc *transportCeremony
	for tc == nil {
		n.ceremoniesMu.Lock()
		tc = n.ceremonies[cid]
		n.ceremoniesMu.Unlock()
		if tc != nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("unknown ceremony")
		case <-tick.C:
		}
	}

	select {
	case result := <-tc.endCh:
		return result, nil
	case <-ctx.Done():
		return nil, errors.New("timeout")
	}
}

// WaitReshare waits for a reshare ceremony to complete, collecting
// results from both old and new party instances. It stores the new
// key share on the node if this node is in the new committee.
func (n *tssTransportNode) WaitReshare(cid CeremonyID, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(n.t.Context(), timeout)
	defer cancel()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	var tc *transportCeremony
	for tc == nil {
		n.ceremoniesMu.Lock()
		tc = n.ceremonies[cid]
		n.ceremoniesMu.Unlock()
		if tc != nil {
			break
		}
		select {
		case <-ctx.Done():
			return errors.New("unknown ceremony")
		case <-tick.C:
		}
	}

	expectedEnds := 0
	if tc.oldParty != nil {
		expectedEnds++
	}
	if tc.party != nil {
		expectedEnds++
	}

	var newSave *keygen.LocalPartySaveData
	for i := 0; i < expectedEnds; i++ {
		select {
		case result := <-tc.endCh:
			save := result.(*keygen.LocalPartySaveData)
			if save.Xi != nil && save.Xi.Sign() != 0 {
				newSave = save
			}
		case <-ctx.Done():
			return errors.New("reshare timeout")
		}
	}

	if newSave != nil {
		keyID := newSave.ECDSAPub.X().Text(16)[:16]
		n.keysMu.Lock()
		n.keys[keyID] = newSave
		n.keysMu.Unlock()
	}

	return nil
}

// =============================================================================
// Mesh setup — full mesh of encrypted TCP connections
// =============================================================================

// connectTransportPair establishes an encrypted TCP channel between
// server and client: KeyExchange + Handshake + bidirectional read loops.
//
// A barrier synchronizes KX→Handshake transition. Without it, the
// client can finish KX and send its encrypted HelloRequest before the
// server's json.Decoder returns from reading the KX TransportRequest.
// The decoder buffers ahead on loopback, consuming the HelloRequest
// bytes. The server's Handshake then reads the next blob (HelloResponse)
// and fails with "unexpected command."
func connectTransportPair(t *testing.T, server, client *tssTransportNode) {
	t.Helper()

	serverTr, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatalf("NewTransportFromCurve: %v", err)
	}
	clientTr := new(Transport)

	ctx, cancel := context.WithTimeout(context.Background(),
		10*time.Second)
	defer cancel()

	// Barrier: both sides finish KX before either starts Handshake.
	var kxBarrier sync.WaitGroup
	kxBarrier.Add(2)

	errCh := make(chan error, 2)
	var serverRemoteID, clientRemoteID *Identity

	// Server: accept, key exchange, barrier, handshake.
	go func() {
		conn, aErr := server.listener.Accept()
		if aErr != nil {
			errCh <- fmt.Errorf("accept: %w", aErr)
			kxBarrier.Done()
			return
		}
		if kxErr := serverTr.KeyExchange(ctx, conn); kxErr != nil {
			errCh <- fmt.Errorf("server KX: %w", kxErr)
			kxBarrier.Done()
			return
		}
		kxBarrier.Done()
		kxBarrier.Wait()
		id, hsErr := serverTr.Handshake(ctx, server.secret)
		if hsErr != nil {
			errCh <- fmt.Errorf("server handshake: %w", hsErr)
			return
		}
		serverRemoteID = id
		errCh <- nil
	}()

	// Client: dial, key exchange, barrier, handshake.
	go func() {
		d := &net.Dialer{}
		conn, dErr := d.DialContext(ctx, "tcp",
			server.listener.Addr().String())
		if dErr != nil {
			errCh <- fmt.Errorf("dial: %w", dErr)
			kxBarrier.Done()
			return
		}
		if kxErr := clientTr.KeyExchange(ctx, conn); kxErr != nil {
			errCh <- fmt.Errorf("client KX: %w", kxErr)
			kxBarrier.Done()
			return
		}
		kxBarrier.Done()
		kxBarrier.Wait()
		id, hsErr := clientTr.Handshake(ctx, client.secret)
		if hsErr != nil {
			errCh <- fmt.Errorf("client handshake: %w", hsErr)
			return
		}
		clientRemoteID = id
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if chErr := <-errCh; chErr != nil {
			t.Fatalf("connectPair: %v", chErr)
		}
	}

	if *serverRemoteID != client.id {
		t.Fatalf("server ID mismatch: got %s want %s",
			serverRemoteID, client.id)
	}
	if *clientRemoteID != server.id {
		t.Fatalf("client ID mismatch: got %s want %s",
			clientRemoteID, server.id)
	}

	// Register transports.
	server.transportsMu.Lock()
	server.transports[client.id] = serverTr
	server.transportsMu.Unlock()

	client.transportsMu.Lock()
	client.transports[server.id] = clientTr
	client.transportsMu.Unlock()

	// Start read loops on both sides.
	server.startReadLoop(serverTr, client.id)
	client.startReadLoop(clientTr, server.id)
}

// setupTransportMesh creates n nodes and connects every pair with
// encrypted TCP transports. For i<j, node[i] acts as server.
func setupTransportMesh(t *testing.T, n int) []*tssTransportNode {
	t.Helper()

	preParams := loadPreParams(t, n)
	nodes := make([]*tssTransportNode, n)
	for i := 0; i < n; i++ {
		var pp *keygen.LocalPreParams
		if i < len(preParams) {
			pp = &preParams[i]
		}
		nodes[i] = newTSSTransportNode(t, pp)
	}

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			connectTransportPair(t, nodes[i], nodes[j])
		}
	}

	return nodes
}

func teardownTransportMesh(t *testing.T, nodes []*tssTransportNode) {
	t.Helper()

	// Phase 1: signal all read loops to stop.
	for _, n := range nodes {
		n.readCancel()
	}

	// Phase 2: close all connections (unblocks blocked reads).
	for _, n := range nodes {
		n.transportsMu.RLock()
		for id, tr := range n.transports {
			if err := tr.Close(); err != nil {
				t.Logf("close transport to %s: %v", id, err)
			}
		}
		n.transportsMu.RUnlock()
		if err := n.listener.Close(); err != nil {
			t.Logf("close listener: %v", err)
		}
	}

	// Phase 3: wait for all goroutines to exit.
	for _, n := range nodes {
		n.readWg.Wait()
	}
}

// =============================================================================
// Helpers
// =============================================================================

// transportCommittee builds a PartyID committee from transport nodes.
func transportCommittee(nodes []*tssTransportNode) tss.UnSortedPartyIDs {
	pids := make(tss.UnSortedPartyIDs, len(nodes))
	for i, n := range nodes {
		pids[i] = n.partyID
	}
	return pids
}

// buildPIDToIdentity builds a PartyID.Id → Identity mapping by
// parsing the hex-encoded identity string stored in each PartyID's Id
// field. This is correct even when the PartyID key has been XORed for
// reshare committee disambiguation.
func buildPIDToIdentity(pids tss.SortedPartyIDs) map[string]Identity {
	m := make(map[string]Identity, len(pids))
	for _, pid := range pids {
		id, err := NewIdentityFromString(pid.Id)
		if err != nil {
			continue
		}
		m[pid.Id] = *id
	}
	return m
}

// buildReshareContext builds a sorted party context for reshare,
// optionally XORing keys with 1 for the new committee.
func buildReshareContext(
	pids tss.UnSortedPartyIDs,
	selfStr string,
	isNew bool,
) (tss.SortedPartyIDs, *tss.PartyID, map[string]Identity) {
	rebuilt := make([]*tss.PartyID, len(pids))
	pidToID := make(map[string]Identity)
	for i, pid := range pids {
		key := new(big.Int).SetBytes(pid.Key)
		if isNew {
			key.Xor(key, big.NewInt(1))
		}
		rebuilt[i] = tss.NewPartyID(pid.Id, pid.Moniker, key)

		// Parse identity from hex Id string, not from key bytes
		// (key may be XORed for new committee).
		id, _ := NewIdentityFromString(pid.Id)
		if id != nil {
			pidToID[pid.Id] = *id
		}
	}

	sorted := tss.SortPartyIDs(rebuilt)
	var ourPid *tss.PartyID
	for _, pid := range sorted {
		if pid.Id == selfStr {
			ourPid = pid
			break
		}
	}

	return sorted, ourPid, pidToID
}

// initiateKeygen sends a KeygenRequest to all nodes via Transport.
// Node 0 acts as initiator: it writes to all peers via their shared
// Transports and handles the request locally.
func initiateKeygen(
	t *testing.T,
	nodes []*tssTransportNode,
	committee tss.UnSortedPartyIDs,
	cid CeremonyID,
	threshold int,
) {
	t.Helper()

	req := KeygenRequest{
		CeremonyID: cid,
		Curve:      "secp256k1",
		Threshold:  threshold,
		Committee:  committee,
	}

	initiator := nodes[0]
	for _, node := range nodes[1:] {
		initiator.transportsMu.RLock()
		tr := initiator.transports[node.id]
		initiator.transportsMu.RUnlock()
		if err := tr.Write(initiator.id, req); err != nil {
			t.Fatalf("send KeygenRequest to %s: %v",
				node.id, err)
		}
	}

	// Handle locally for the initiator.
	initiator.handleKeygenRequest(req)
}

// initiateSigning sends a SignRequest to all nodes via Transport.
func initiateSigning(
	t *testing.T,
	nodes []*tssTransportNode,
	committee tss.UnSortedPartyIDs,
	cid CeremonyID,
	keyID []byte,
	threshold int,
	data [32]byte,
) {
	t.Helper()

	req := SignRequest{
		CeremonyID: cid,
		KeyID:      keyID,
		Threshold:  threshold,
		Committee:  committee,
		Data:       data[:],
	}

	initiator := nodes[0]
	for _, node := range nodes[1:] {
		initiator.transportsMu.RLock()
		tr := initiator.transports[node.id]
		initiator.transportsMu.RUnlock()
		if err := tr.Write(initiator.id, req); err != nil {
			t.Fatalf("send SignRequest to %s: %v",
				node.id, err)
		}
	}

	initiator.handleSignRequest(req)
}

// initiateReshare sends a ReshareRequest to all nodes via Transport.
// All four nodes receive the request; each determines its own
// committee membership.
func initiateReshare(
	t *testing.T,
	nodes []*tssTransportNode,
	oldCommittee, newCommittee tss.UnSortedPartyIDs,
	cid CeremonyID,
	oldThreshold, newThreshold int,
) {
	t.Helper()

	req := ReshareRequest{
		CeremonyID:   cid,
		Curve:        "secp256k1",
		OldCommittee: oldCommittee,
		NewCommittee: newCommittee,
		OldThreshold: oldThreshold,
		NewThreshold: newThreshold,
	}

	initiator := nodes[0]
	for _, node := range nodes[1:] {
		initiator.transportsMu.RLock()
		tr := initiator.transports[node.id]
		initiator.transportsMu.RUnlock()
		if err := tr.Write(initiator.id, req); err != nil {
			t.Fatalf("send ReshareRequest to %s: %v",
				node.id, err)
		}
	}

	initiator.handleReshareRequest(req)
}

// buildSigningCommittee builds a signing committee with PartyID keys
// that match the key share's Ks. After reshare, Ks contains XORed
// keys; after keygen, Ks contains raw identity keys. This function
// transparently handles both cases.
func buildSigningCommittee(
	t *testing.T,
	nodes []*tssTransportNode,
	keyID string,
) tss.UnSortedPartyIDs {
	t.Helper()

	// Find Ks from any node that has the key.
	var ks []*big.Int
	for _, n := range nodes {
		n.keysMu.RLock()
		key := n.keys[keyID]
		n.keysMu.RUnlock()
		if key != nil {
			ks = key.Ks
			break
		}
	}
	if ks == nil {
		t.Fatalf("no node has key %s", keyID)
	}

	ksSet := make(map[string]*big.Int, len(ks))
	for _, k := range ks {
		ksSet[k.String()] = k
	}

	pids := make(tss.UnSortedPartyIDs, len(nodes))
	for i, n := range nodes {
		rawKey := new(big.Int).SetBytes(n.id[:])
		xorKey := new(big.Int).Xor(rawKey, big.NewInt(1))

		var key *big.Int
		if _, ok := ksSet[rawKey.String()]; ok {
			key = rawKey
		} else if _, ok := ksSet[xorKey.String()]; ok {
			key = xorKey
		} else {
			t.Fatalf("node %s not in key share Ks", n.id)
		}

		idStr := n.id.String()
		pids[i] = tss.NewPartyID(idStr, idStr, key)
	}

	return pids
}

// =============================================================================
// Tests — TSS ceremonies over encrypted Transport with full RPC protocol
// =============================================================================

func TestTransportKeygen(t *testing.T) {
	nodes := setupTransportMesh(t, 3)
	defer teardownTransportMesh(t, nodes)

	committee := transportCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1 // 2-of-3

	t.Log("=== Keygen over encrypted Transport ===")

	initiateKeygen(t, nodes, committee, cid, threshold)

	// Wait for completion on all nodes.
	var keyID string
	for _, node := range nodes {
		result, err := node.WaitCeremony(cid, 2*time.Minute)
		if err != nil {
			t.Fatalf("Node %s failed: %v", node.id, err)
		}
		save := result.(*keygen.LocalPartySaveData)
		keyID = save.ECDSAPub.X().Text(16)[:16]
		t.Logf("Node %s: keygen success, keyID=%s",
			node.id, keyID)
	}

	// Verify all nodes have the same public key.
	var expectedX *big.Int
	for _, node := range nodes {
		node.keysMu.RLock()
		key := node.keys[keyID]
		node.keysMu.RUnlock()
		if key == nil {
			t.Fatalf("Node %s missing key", node.id)
		}
		if expectedX == nil {
			expectedX = key.ECDSAPub.X()
		} else if expectedX.Cmp(key.ECDSAPub.X()) != 0 {
			t.Fatal("Public key mismatch between nodes")
		}
	}

	t.Log("All nodes have matching public key ✓")
}

func TestTransportKeygenAndSign(t *testing.T) {
	nodes := setupTransportMesh(t, 3)
	defer teardownTransportMesh(t, nodes)

	committee := transportCommittee(nodes)
	threshold := 1 // 2-of-3

	// === Keygen ===
	keygenCID := NewCeremonyID()
	t.Log("=== Keygen ===")

	initiateKeygen(t, nodes, committee, keygenCID, threshold)

	var keyID string
	var pubKey *ecdsa.PublicKey
	for _, node := range nodes {
		result, err := node.WaitCeremony(keygenCID, 2*time.Minute)
		if err != nil {
			t.Fatalf("Keygen failed: %v", err)
		}
		save := result.(*keygen.LocalPartySaveData)
		keyID = save.ECDSAPub.X().Text(16)[:16]
		if pubKey == nil {
			pubKey = &ecdsa.PublicKey{
				Curve: tss.S256(),
				X:     save.ECDSAPub.X(),
				Y:     save.ECDSAPub.Y(),
			}
		}
	}
	t.Logf("Keygen complete, keyID=%s", keyID)

	// === Sign ===
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("transport test message"))
	t.Log("=== Sign ===")

	initiateSigning(t, nodes, committee, signCID,
		[]byte(keyID), threshold, data)

	for _, node := range nodes {
		result, err := node.WaitCeremony(signCID, 2*time.Minute)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		sig := result.(*common.SignatureData)

		r := new(big.Int).SetBytes(sig.R)
		s := new(big.Int).SetBytes(sig.S)
		if !ecdsa.Verify(pubKey, data[:], r, s) {
			t.Fatalf("Node %s: signature verification failed",
				node.id)
		}
		t.Logf("Node %s: signature verified ✓", node.id)
	}
}

func TestTransportReshare(t *testing.T) {
	// 4 nodes: keygen {0,1,2}, reshare to {1,2,3}, sign with {1,2,3}.
	// Nodes 1 and 2 overlap both committees.
	nodes := setupTransportMesh(t, 4)
	defer teardownTransportMesh(t, nodes)

	oldCommittee := transportCommittee(nodes[:3]) // {0, 1, 2}
	newCommittee := transportCommittee(nodes[1:]) // {1, 2, 3}
	threshold := 1                                // 2-of-3

	// --- Keygen with old committee {0, 1, 2} ---
	keygenCID := NewCeremonyID()
	t.Log("=== Keygen with old committee ===")

	initiateKeygen(t, nodes[:3], oldCommittee, keygenCID, threshold)

	var keyID string
	for _, node := range nodes[:3] {
		result, err := node.WaitCeremony(keygenCID, 2*time.Minute)
		if err != nil {
			t.Fatalf("Node %s keygen: %v", node.id, err)
		}
		save := result.(*keygen.LocalPartySaveData)
		keyID = save.ECDSAPub.X().Text(16)[:16]
	}
	t.Logf("Keygen complete: keyID=%s", keyID)

	// --- Reshare: {0,1,2} → {1,2,3} ---
	reshareCID := NewCeremonyID()
	t.Log("=== Reshare ===")

	initiateReshare(t, nodes, oldCommittee, newCommittee,
		reshareCID, threshold, threshold)

	for _, node := range nodes {
		if err := node.WaitReshare(reshareCID, 3*time.Minute); err != nil {
			t.Fatalf("Node %s reshare: %v", node.id, err)
		}
	}
	t.Log("Reshare complete ✓")

	// --- Sign with new committee {1, 2, 3} ---
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("post-reshare transport test"))
	t.Log("=== Sign with new committee ===")

	// Build signing committee with keys matching post-reshare Ks.
	signCommittee := buildSigningCommittee(t, nodes[1:], keyID)

	initiateSigning(t, nodes[1:], signCommittee, signCID,
		[]byte(keyID), threshold, data)

	// Collect and verify signatures.
	var firstR, firstS []byte
	for _, node := range nodes[1:] {
		result, err := node.WaitCeremony(signCID, 2*time.Minute)
		if err != nil {
			t.Fatalf("Node %s sign: %v", node.id, err)
		}
		sig := result.(*common.SignatureData)
		if firstR == nil {
			firstR = sig.R
			firstS = sig.S
		} else if !bytes.Equal(sig.R, firstR) ||
			!bytes.Equal(sig.S, firstS) {
			t.Fatal("Signature mismatch between nodes")
		}
	}
	t.Logf("Sign after reshare: r=%x.. s=%x..",
		firstR[:8], firstS[:8])
}
