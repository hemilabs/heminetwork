// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
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
// rpcTSSNode — TSS participant over encrypted Transport, clean RPC
//
// Architecture differences from tss_transport_test.go:
//   - TSSMessage.Flags carries broadcast + committee routing as a
//     single bitfield. The deprecated Broadcast bool is not set.
//   - TSSMessage.Data is pure tss-lib WireBytes. No hand-rolled
//     byte prefixes for committee routing.
//   - All goroutines tracked via wg, all respect ctx for shutdown.
//   - ceremonyManager is a concrete type (methods on rpcTSSNode),
//     not an interface. Production RPC handler follows this pattern.
// =============================================================================

// rpcTSSNode is a TSS participant that communicates via the full
// continuum protocol stack: TCP → KX (ECDH) → Handshake (secp256k1
// identity) → signed RPC envelopes. It implements the clean
// single-layer RPC architecture where TSSMessage.Flags carries all
// routing metadata and Data is pure tss-lib bytes.
type rpcTSSNode struct {
	t         *testing.T
	id        Identity
	secret    *Secret
	partyID   *tss.PartyID
	preParams *keygen.LocalPreParams

	// Key storage: keyID → key share.
	keys   map[string]*keygen.LocalPartySaveData
	keysMu sync.RWMutex

	// Active ceremonies.
	ceremonies   map[CeremonyID]*rpcCeremony
	ceremoniesMu sync.Mutex

	// Encrypted Transport connections to peers.
	transports   map[Identity]*Transport
	transportsMu sync.RWMutex
	listener     net.Listener

	// Lifecycle. cancel + transport close unblocks all goroutines.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// corruptFn, if set, is called on each outgoing TSSMessage
	// before it is written to the wire. May modify msg in place.
	// Used by negative tests to simulate corrupt signers.
	corruptFn func(msg *TSSMessage)
}

// rpcCeremony tracks an active TSS ceremony.
type rpcCeremony struct {
	ctype   CeremonyType
	party   tss.Party          // sole party for keygen/sign; new party for reshare
	pids    tss.SortedPartyIDs // combined for reshare
	pidToID map[string]Identity
	outCh   chan tss.Message
	result  chan any // buffered to expectedEnds

	threshold int
	keyID     string

	// Reshare-specific.
	oldParty tss.Party
	oldPids  tss.SortedPartyIDs
	newPids  tss.SortedPartyIDs
}

func newRPCTSSNode(t *testing.T, preParams *keygen.LocalPreParams) *rpcTSSNode {
	t.Helper()

	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	lc := &net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen: %v", err)
	}

	return &rpcTSSNode{
		t:          t,
		id:         secret.Identity,
		secret:     secret,
		partyID:    tss.NewPartyID(secret.String(), secret.String(), new(big.Int).SetBytes(secret.Identity[:])),
		preParams:  preParams,
		keys:       make(map[string]*keygen.LocalPartySaveData),
		ceremonies: make(map[CeremonyID]*rpcCeremony),
		transports: make(map[Identity]*Transport),
		listener:   listener,
		ctx:        ctx,
		cancel:     cancel,
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
//	Owner:     rpcTSSNode
//	Lifecycle: runs until Transport.Read error or ctx cancel
//	Kill:      cancel + Transport.Close
//	Tracking:  wg
func (n *rpcTSSNode) startReadLoop(tr *Transport, remoteID Identity) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for {
			_, cmd, err := tr.Read()
			if err != nil {
				// Expected on shutdown: ctx cancelled, conn closed.
				select {
				case <-n.ctx.Done():
					return
				default:
				}
				n.t.Logf("readLoop %s←%s: %v",
					n.id, remoteID, err)
				return
			}

			switch v := cmd.(type) {
			case *KeygenRequest:
				n.handleKeygen(*v)
			case *SignRequest:
				n.handleSign(*v)
			case *ReshareRequest:
				n.handleReshare(*v)
			case *TSSMessage:
				n.handleTSSMsg(*v)
			default:
				n.t.Logf("readLoop %s←%s: unhandled %T",
					n.id, remoteID, cmd)
			}
		}
	}()
}

// =============================================================================
// Ceremony handlers — create parties, start pumps
// =============================================================================

func (n *rpcTSSNode) handleKeygen(req KeygenRequest) {
	n.ceremoniesMu.Lock()
	defer n.ceremoniesMu.Unlock()

	sortedPids := tss.SortPartyIDs(req.Committee)
	ctx := tss.NewPeerContext(sortedPids)

	ourPid := findSelf(sortedPids, n.partyID.Id)
	if ourPid == nil {
		n.t.Logf("node %s: not in keygen committee", n.id)
		return
	}

	pidToID := mapPIDToIdentity(sortedPids)
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

	c := &rpcCeremony{
		ctype:     CeremonyKeygen,
		party:     party,
		pids:      sortedPids,
		pidToID:   pidToID,
		outCh:     outCh,
		result:    make(chan any, 1),
		threshold: req.Threshold,
	}
	n.ceremonies[req.CeremonyID] = c

	n.wg.Add(2)
	go n.pumpKeysign(req.CeremonyID, c)
	go n.awaitKeygenEnd(c, endCh)

	if err := party.Start(); err != nil {
		n.t.Logf("keygen start: %v", err)
	}
}

func (n *rpcTSSNode) handleSign(req SignRequest) {
	n.ceremoniesMu.Lock()
	defer n.ceremoniesMu.Unlock()

	n.keysMu.RLock()
	key, ok := n.keys[string(req.KeyID)]
	n.keysMu.RUnlock()
	if !ok {
		n.t.Logf("node %s: key %x not found", n.id, req.KeyID)
		return
	}

	sortedPids := tss.SortPartyIDs(req.Committee)
	ctx := tss.NewPeerContext(sortedPids)

	ourPid := findSelf(sortedPids, n.partyID.Id)
	if ourPid == nil {
		n.t.Logf("node %s: not in signing committee", n.id)
		return
	}

	pidToID := mapPIDToIdentity(sortedPids)
	params := tss.NewParameters(tss.S256(), ctx, ourPid,
		len(sortedPids), req.Threshold)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan *common.SignatureData, 1)

	party := signing.NewLocalParty(
		new(big.Int).SetBytes(req.Data), params, *key,
		outCh, endCh, len(req.Data)).(*signing.LocalParty)

	c := &rpcCeremony{
		ctype:     CeremonySign,
		party:     party,
		pids:      sortedPids,
		pidToID:   pidToID,
		outCh:     outCh,
		result:    make(chan any, 1),
		threshold: req.Threshold,
		keyID:     string(req.KeyID),
	}
	n.ceremonies[req.CeremonyID] = c

	n.wg.Add(2)
	go n.pumpKeysign(req.CeremonyID, c)
	go n.awaitSignEnd(c, endCh)

	if err := party.Start(); err != nil {
		n.t.Logf("sign start: %v", err)
	}
}

func (n *rpcTSSNode) handleReshare(req ReshareRequest) {
	n.ceremoniesMu.Lock()
	defer n.ceremoniesMu.Unlock()

	selfStr := n.partyID.Id

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

	oldPids, ourOldPid, oldPidToID := makeReshareContext(
		req.OldCommittee, selfStr, false)
	newPids, ourNewPid, newPidToID := makeReshareContext(
		req.NewCommittee, selfStr, true)

	allPidToID := make(map[string]Identity,
		len(oldPidToID)+len(newPidToID))
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

	c := &rpcCeremony{
		ctype:     CeremonyReshare,
		party:     newParty,
		oldParty:  oldParty,
		oldPids:   oldPids,
		newPids:   newPids,
		pidToID:   allPidToID,
		outCh:     outCh,
		result:    make(chan any, expectedEnds),
		threshold: req.NewThreshold,
		keyID:     keyID,
	}
	n.ceremonies[req.CeremonyID] = c

	// Start parties before pump. Start() writes to buffered outCh.
	// Starting first ensures both party instances exist for local
	// self-delivery between old/new parties on overlapping nodes.
	if oldParty != nil {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			if err := oldParty.Start(); err != nil {
				n.t.Logf("old reshare start: %v", err)
			}
		}()
	}
	if newParty != nil {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			if err := newParty.Start(); err != nil {
				n.t.Logf("new reshare start: %v", err)
			}
		}()
	}

	n.wg.Add(2)
	go n.pumpReshare(req.CeremonyID, c)
	go n.awaitReshareEnd(c, endCh, expectedEnds)
}

// =============================================================================
// TSSMessage handler — verify signature, extract Flags, route
// =============================================================================

func (n *rpcTSSNode) handleTSSMsg(msg TSSMessage) {
	hash := HashTSSMessage(msg.CeremonyID, msg.Data)
	if _, err := Verify(hash, msg.From, msg.Signature); err != nil {
		n.t.Logf("node %s: bad sig from %s: %v",
			n.id, msg.From, err)
		return
	}

	n.ceremoniesMu.Lock()
	c, ok := n.ceremonies[msg.CeremonyID]
	n.ceremoniesMu.Unlock()
	if !ok {
		n.t.Logf("node %s: unknown ceremony %s",
			n.id, msg.CeremonyID)
		return
	}

	broadcast := msg.Flags&TSSFlagBroadcast != 0

	if c.ctype == CeremonyReshare {
		n.routeReshareMsg(c, msg, broadcast)
		return
	}

	// Keygen/Sign: single party.
	fromIDStr := msg.From.String()
	var fromPid *tss.PartyID
	for _, pid := range c.pids {
		if pid.Id == fromIDStr {
			fromPid = pid
			break
		}
	}
	if fromPid == nil {
		n.t.Logf("node %s: sender %s not in ceremony",
			n.id, msg.From)
		return
	}

	// Data is pure tss-lib wireBytes — no prefix stripping.
	parsed, err := tss.ParseWireMessage(msg.Data, fromPid,
		broadcast)
	if err != nil {
		n.t.Logf("node %s: parse: %v", n.id, err)
		return
	}

	if _, err := c.party.Update(parsed); err != nil {
		n.t.Logf("node %s: update: %v", n.id, err)
	}
}

// routeReshareMsg routes an incoming TSSMessage to the correct
// reshare party instance(s) using the Flags bitfield.
//
// No data prefix decoding. Routing metadata lives in TSSMessage.Flags.
func (n *rpcTSSNode) routeReshareMsg(c *rpcCeremony, msg TSSMessage, broadcast bool) {
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

	if toOld && c.oldParty != nil {
		var fromPid *tss.PartyID
		if fromNew {
			fromPid = findFrom(c.newPids)
		} else {
			fromPid = findFrom(c.oldPids)
		}
		if fromPid != nil {
			parsed, err := tss.ParseWireMessage(msg.Data,
				fromPid, broadcast)
			if err != nil {
				n.t.Logf("node %s: parse old: %v",
					n.id, err)
			} else if _, err := c.oldParty.Update(parsed); err != nil {
				n.t.Logf("node %s: update old: %v",
					n.id, err)
			}
		}
	}

	if toNew && c.party != nil {
		var fromPid *tss.PartyID
		if fromNew {
			fromPid = findFrom(c.newPids)
		} else {
			fromPid = findFrom(c.oldPids)
		}
		if fromPid != nil {
			parsed, err := tss.ParseWireMessage(msg.Data,
				fromPid, broadcast)
			if err != nil {
				n.t.Logf("node %s: parse new: %v",
					n.id, err)
			} else if _, err := c.party.Update(parsed); err != nil {
				n.t.Logf("node %s: update new: %v",
					n.id, err)
			}
		}
	}
}

// =============================================================================
// Message pumps — outgoing tss-lib messages → signed TSSMessage → Transport
// =============================================================================

// pumpKeysign reads outgoing tss-lib messages for keygen/sign
// ceremonies, wraps them in TSSMessage with Flags set, and writes
// to peer Transports. Data is pure tss-lib wireBytes.
//
// Goroutine contract:
//
//	Owner:     rpcTSSNode (one per keygen/sign ceremony)
//	Lifecycle: runs until ctx cancel
//	Tracking:  wg (Add before go)
func (n *rpcTSSNode) pumpKeysign(cid CeremonyID, c *rpcCeremony) {
	defer n.wg.Done()
	for {
		select {
		case msg := <-c.outCh:
			wireData, _, err := msg.WireBytes()
			if err != nil {
				n.t.Logf("pump %s: WireBytes: %v", cid, err)
				continue
			}

			var flags TSSMsgFlags
			if msg.GetTo() == nil {
				flags |= TSSFlagBroadcast
			}

			hash := HashTSSMessage(cid, wireData)
			sig := n.secret.Sign(hash)

			tssMsg := TSSMessage{
				CeremonyID: cid,
				Type:       c.ctype,
				From:       n.id,
				Flags:      flags,
				Data:       wireData,
				Signature:  sig,
			}

			if n.corruptFn != nil {
				n.corruptFn(&tssMsg)
			}

			n.sendTSSMsg(c, tssMsg, msg.GetTo())

		case <-n.ctx.Done():
			return
		}
	}
}

// pumpReshare routes outgoing reshare messages with committee flags
// encoded in TSSMessage.Flags — not in Data bytes.
//
// For overlapping nodes (in both old and new committees), messages
// between local party instances are self-delivered via handleTSSMsg.
//
// Goroutine contract:
//
//	Owner:     rpcTSSNode (one per reshare ceremony)
//	Lifecycle: runs until ctx cancel
//	Tracking:  wg (Add before go)
func (n *rpcTSSNode) pumpReshare(cid CeremonyID, c *rpcCeremony) {
	defer n.wg.Done()

	// New key set for fromNew detection. Old and new key spaces
	// are disjoint (XOR 1), so membership means from-new.
	newKeySet := make(map[string]bool, len(c.newPids))
	for _, pid := range c.newPids {
		newKeySet[pid.KeyInt().String()] = true
	}

	for {
		select {
		case msg := <-c.outCh:
			wireData, routing, err := msg.WireBytes()
			if err != nil {
				n.t.Logf("reshare pump %s: WireBytes: %v",
					cid, err)
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
			if newKeySet[msg.GetFrom().KeyInt().String()] {
				flags |= TSSFlagFromNew
			}

			hash := HashTSSMessage(cid, wireData)
			sig := n.secret.Sign(hash)

			// Data is PURE wireBytes. No prefix encoding.
			tssMsg := TSSMessage{
				CeremonyID: cid,
				Type:       CeremonyReshare,
				From:       n.id,
				Flags:      flags,
				Data:       wireData,
				Signature:  sig,
			}

			if n.corruptFn != nil {
				n.corruptFn(&tssMsg)
			}

			// Route to all unique peers across both committees.
			sent := make(map[Identity]bool)
			allPids := make([]*tss.PartyID, 0,
				len(c.oldPids)+len(c.newPids))
			allPids = append(allPids, c.oldPids...)
			allPids = append(allPids, c.newPids...)

			deliver := func(id Identity) {
				if sent[id] {
					return
				}
				sent[id] = true
				if id == n.id {
					// Self-deliver for overlapping nodes.
					cp := tssMsg
					go n.handleTSSMsg(cp)
					return
				}
				n.transportsMu.RLock()
				tr := n.transports[id]
				n.transportsMu.RUnlock()
				if tr != nil {
					if err := tr.Write(n.id, tssMsg); err != nil {
						n.t.Logf("reshare pump: %v",
							err)
					}
				}
			}

			if msg.GetTo() == nil {
				for _, pid := range allPids {
					deliver(c.pidToID[pid.Id])
				}
			} else {
				for _, dest := range msg.GetTo() {
					deliver(c.pidToID[dest.Id])
				}
			}

		case <-n.ctx.Done():
			return
		}
	}
}

// sendTSSMsg writes a TSSMessage to the appropriate peer Transports
// based on tss-lib routing (broadcast vs P2P).
func (n *rpcTSSNode) sendTSSMsg(c *rpcCeremony, msg TSSMessage, to []*tss.PartyID) {
	if to == nil {
		// Broadcast to all committee peers.
		for _, pid := range c.pids {
			if pid.Id == n.partyID.Id {
				continue
			}
			id := c.pidToID[pid.Id]
			n.transportsMu.RLock()
			tr := n.transports[id]
			n.transportsMu.RUnlock()
			if tr != nil {
				if err := tr.Write(n.id, msg); err != nil {
					n.t.Logf("pump write to %s: %v",
						id, err)
				}
			}
		}
	} else {
		// P2P to specific peers.
		for _, dest := range to {
			id := c.pidToID[dest.Id]
			n.transportsMu.RLock()
			tr := n.transports[id]
			n.transportsMu.RUnlock()
			if tr != nil {
				if err := tr.Write(n.id, msg); err != nil {
					n.t.Logf("pump write to %s: %v",
						id, err)
				}
			}
		}
	}
}

// =============================================================================
// Completion waiters — store results, signal test
// =============================================================================

func (n *rpcTSSNode) awaitKeygenEnd(c *rpcCeremony, endCh <-chan *keygen.LocalPartySaveData) {
	defer n.wg.Done()
	select {
	case save := <-endCh:
		keyID := save.ECDSAPub.X().Text(16)[:16]
		n.keysMu.Lock()
		n.keys[keyID] = save
		n.keysMu.Unlock()

		c.result <- save
		n.t.Logf("node %s: keygen done, key=%s", n.id, keyID)

	case <-n.ctx.Done():
	}
}

func (n *rpcTSSNode) awaitSignEnd(c *rpcCeremony, endCh <-chan *common.SignatureData) {
	defer n.wg.Done()
	select {
	case sig := <-endCh:
		c.result <- sig
		n.t.Logf("node %s: sign done", n.id)

	case <-n.ctx.Done():
	}
}

func (n *rpcTSSNode) awaitReshareEnd(c *rpcCeremony, endCh <-chan *keygen.LocalPartySaveData, expected int) {
	defer n.wg.Done()
	for i := 0; i < expected; i++ {
		select {
		case save := <-endCh:
			c.result <- save
		case <-n.ctx.Done():
			return
		}
	}
}

// waitCeremony blocks until the ceremony completes or ctx expires.
func (n *rpcTSSNode) waitCeremony(ctx context.Context, cid CeremonyID) (any, error) {
	// Poll for ceremony registration.
	var c *rpcCeremony
	for {
		n.ceremoniesMu.Lock()
		c = n.ceremonies[cid]
		n.ceremoniesMu.Unlock()
		if c != nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}

	select {
	case result := <-c.result:
		return result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// waitReshare collects results from both old and new party
// instances, stores the new key share.
func (n *rpcTSSNode) waitReshare(ctx context.Context, cid CeremonyID) error {
	var c *rpcCeremony
	for {
		n.ceremoniesMu.Lock()
		c = n.ceremonies[cid]
		n.ceremoniesMu.Unlock()
		if c != nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}

	expectedEnds := 0
	if c.oldParty != nil {
		expectedEnds++
	}
	if c.party != nil {
		expectedEnds++
	}

	var newSave *keygen.LocalPartySaveData
	for i := 0; i < expectedEnds; i++ {
		select {
		case result := <-c.result:
			save := result.(*keygen.LocalPartySaveData)
			if save.Xi != nil && save.Xi.Sign() != 0 {
				newSave = save
			}
		case <-ctx.Done():
			return ctx.Err()
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
// Mesh setup — encrypted TCP connections between all nodes
// =============================================================================

// connectRPCPair establishes an encrypted TCP channel between server
// and client: KeyExchange + Handshake + bidirectional read loops.
//
// A barrier synchronizes KX → Handshake transition. Without it, the
// client can finish KX and send its encrypted HelloRequest before the
// server's json.Decoder returns from reading the KX TransportRequest.
func connectRPCPair(t *testing.T, server, client *rpcTSSNode) {
	t.Helper()

	serverTr, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatalf("NewTransportFromCurve: %v", err)
	}
	clientTr := new(Transport)

	ctx, cancel := context.WithTimeout(context.Background(),
		10*time.Second)
	defer cancel()

	var kxBarrier sync.WaitGroup
	kxBarrier.Add(2)

	errCh := make(chan error, 2)
	var serverRemoteID, clientRemoteID *Identity

	// Server goroutine.
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

	// Client goroutine.
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
			t.Fatalf("connectRPCPair: %v", chErr)
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

// setupRPCMesh creates n nodes and connects every pair.
func setupRPCMesh(t *testing.T, n int) []*rpcTSSNode {
	t.Helper()

	preParams := loadPreParams(t, n)
	nodes := make([]*rpcTSSNode, n)
	for i := 0; i < n; i++ {
		var pp *keygen.LocalPreParams
		if i < len(preParams) {
			pp = &preParams[i]
		}
		nodes[i] = newRPCTSSNode(t, pp)
	}

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			connectRPCPair(t, nodes[i], nodes[j])
		}
	}

	return nodes
}

// teardownRPCMesh performs orderly shutdown:
//  1. Signal all goroutines via ctx cancel.
//  2. Close connections (unblocks blocked reads).
//  3. Wait for all goroutines.
func teardownRPCMesh(t *testing.T, nodes []*rpcTSSNode) {
	t.Helper()

	for _, n := range nodes {
		n.cancel()
	}

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

	for _, n := range nodes {
		n.wg.Wait()
	}
}

// =============================================================================
// Helpers
// =============================================================================

// findSelf finds our PartyID in a sorted list by Id string.
func findSelf(pids tss.SortedPartyIDs, selfID string) *tss.PartyID {
	for _, pid := range pids {
		if pid.Id == selfID {
			return pid
		}
	}
	return nil
}

// mapPIDToIdentity builds PartyID.Id → Identity by parsing the hex
// Id string. Correct even when keys are XORed for reshare.
func mapPIDToIdentity(pids tss.SortedPartyIDs) map[string]Identity {
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

// makeReshareContext builds a sorted party context for reshare,
// optionally XORing keys for new committee disambiguation.
func makeReshareContext(
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

// rpcCommittee builds a PartyID committee from rpcTSSNode list.
func rpcCommittee(nodes []*rpcTSSNode) tss.UnSortedPartyIDs {
	pids := make(tss.UnSortedPartyIDs, len(nodes))
	for i, n := range nodes {
		pids[i] = n.partyID
	}
	return pids
}

// rpcInitKeygen sends a KeygenRequest to all nodes via Transport.
// Node 0 is the initiator.
func rpcInitKeygen(
	t *testing.T,
	nodes []*rpcTSSNode,
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
	initiator.handleKeygen(req)
}

// rpcInitSign sends a SignRequest to all nodes via Transport.
func rpcInitSign(
	t *testing.T,
	nodes []*rpcTSSNode,
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
	initiator.handleSign(req)
}

// rpcInitReshare sends a ReshareRequest to all nodes via Transport.
func rpcInitReshare(
	t *testing.T,
	nodes []*rpcTSSNode,
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
	initiator.handleReshare(req)
}

// rpcSigningCommittee builds a signing committee with PartyID keys
// matching the key share's Ks. Handles both raw and XORed keys
// (post-keygen vs post-reshare).
func rpcSigningCommittee(
	t *testing.T,
	nodes []*rpcTSSNode,
	keyID string,
) tss.UnSortedPartyIDs {
	t.Helper()

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
// Tests — TSS ceremonies over encrypted Transport with TSSMessage.Flags
// =============================================================================

func TestRPCTSSKeygen(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	defer teardownRPCMesh(t, nodes)

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1 // 2-of-3

	t.Log("=== Keygen over encrypted Transport (Flags) ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(context.Background(),
		2*time.Minute)
	defer cancel()

	var keyID string
	for _, node := range nodes {
		result, err := node.waitCeremony(ctx, cid)
		if err != nil {
			t.Fatalf("node %s: %v", node.id, err)
		}
		save := result.(*keygen.LocalPartySaveData)
		keyID = save.ECDSAPub.X().Text(16)[:16]
		t.Logf("node %s: keyID=%s", node.id, keyID)
	}

	// Verify all nodes share the same public key.
	var expectedX *big.Int
	for _, node := range nodes {
		node.keysMu.RLock()
		key := node.keys[keyID]
		node.keysMu.RUnlock()
		if key == nil {
			t.Fatalf("node %s: missing key", node.id)
		}
		if expectedX == nil {
			expectedX = key.ECDSAPub.X()
		} else if expectedX.Cmp(key.ECDSAPub.X()) != 0 {
			t.Fatal("public key mismatch between nodes")
		}
	}

	t.Log("All nodes have matching public key ✓")
}

func TestRPCTSSKeygenAndSign(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	defer teardownRPCMesh(t, nodes)

	committee := rpcCommittee(nodes)
	threshold := 1 // 2-of-3

	ctx, cancel := context.WithTimeout(context.Background(),
		3*time.Minute)
	defer cancel()

	// === Keygen ===
	keygenCID := NewCeremonyID()
	t.Log("=== Keygen ===")

	rpcInitKeygen(t, nodes, committee, keygenCID, threshold)

	var keyID string
	var pubKey *ecdsa.PublicKey
	for _, node := range nodes {
		result, err := node.waitCeremony(ctx, keygenCID)
		if err != nil {
			t.Fatalf("keygen: %v", err)
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
	t.Logf("keygen done, keyID=%s", keyID)

	// === Sign ===
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("rpc tss clean architecture"))
	t.Log("=== Sign ===")

	rpcInitSign(t, nodes, committee, signCID,
		[]byte(keyID), threshold, data)

	for _, node := range nodes {
		result, err := node.waitCeremony(ctx, signCID)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sig := result.(*common.SignatureData)

		r := new(big.Int).SetBytes(sig.R)
		s := new(big.Int).SetBytes(sig.S)
		if !ecdsa.Verify(pubKey, data[:], r, s) {
			t.Fatalf("node %s: ECDSA verify failed", node.id)
		}
		t.Logf("node %s: signature verified ✓", node.id)
	}
}

func TestRPCTSSReshare(t *testing.T) {
	// 4 nodes: keygen {0,1,2}, reshare → {1,2,3}, sign with {1,2,3}.
	// Nodes 1 and 2 overlap both committees.
	nodes := setupRPCMesh(t, 4)
	defer teardownRPCMesh(t, nodes)

	oldCommittee := rpcCommittee(nodes[:3])
	newCommittee := rpcCommittee(nodes[1:])
	threshold := 1 // 2-of-3

	ctx, cancel := context.WithTimeout(context.Background(),
		5*time.Minute)
	defer cancel()

	// --- Keygen with old committee {0, 1, 2} ---
	keygenCID := NewCeremonyID()
	t.Log("=== Keygen with old committee ===")

	rpcInitKeygen(t, nodes[:3], oldCommittee, keygenCID, threshold)

	var keyID string
	for _, node := range nodes[:3] {
		result, err := node.waitCeremony(ctx, keygenCID)
		if err != nil {
			t.Fatalf("node %s keygen: %v", node.id, err)
		}
		save := result.(*keygen.LocalPartySaveData)
		keyID = save.ECDSAPub.X().Text(16)[:16]
	}
	t.Logf("keygen done: keyID=%s", keyID)

	// --- Reshare: {0,1,2} → {1,2,3} ---
	reshareCID := NewCeremonyID()
	t.Log("=== Reshare ===")

	rpcInitReshare(t, nodes, oldCommittee, newCommittee,
		reshareCID, threshold, threshold)

	for _, node := range nodes {
		if err := node.waitReshare(ctx, reshareCID); err != nil {
			t.Fatalf("node %s reshare: %v", node.id, err)
		}
	}
	t.Log("reshare done ✓")

	// --- Sign with new committee {1, 2, 3} ---
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("post-reshare clean rpc"))
	t.Log("=== Sign with new committee ===")

	signCommittee := rpcSigningCommittee(t, nodes[1:], keyID)

	rpcInitSign(t, nodes[1:], signCommittee, signCID,
		[]byte(keyID), threshold, data)

	for _, node := range nodes[1:] {
		result, err := node.waitCeremony(ctx, signCID)
		if err != nil {
			t.Fatalf("node %s sign: %v", node.id, err)
		}
		sig := result.(*common.SignatureData)
		t.Logf("node %s: sign done, r=%x..",
			node.id, sig.R[:8])
	}
}

// =============================================================================
// Negative tests — corrupt signer scenarios
//
// Each test hooks corruptFn on one node's outgoing TSSMessage pump
// and verifies the ceremony fails gracefully: no valid result is
// produced, no panic, honest nodes time out waiting.
// =============================================================================

// TestRPCTSSKeygenCorruptPostSign verifies that post-sign data
// corruption (bit flip in Data after signing) is caught by
// signature verification on the receiver. The corrupt node's
// messages are rejected at Verify and the ceremony times out.
func TestRPCTSSKeygenCorruptPostSign(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	defer teardownRPCMesh(t, nodes)

	// Node 2 flips a bit in Data after signing. Receivers
	// compute Hash(CeremonyID||corrupt_data) which won't match
	// the signature computed over the original data.
	nodes[2].corruptFn = func(msg *TSSMessage) {
		if len(msg.Data) > 0 {
			msg.Data[0] ^= 0xff
		}
	}

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1 // 2-of-3

	t.Log("=== Keygen with post-sign corruption (node 2) ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(context.Background(),
		30*time.Second)
	defer cancel()

	for _, node := range nodes {
		_, err := node.waitCeremony(ctx, cid)
		if err == nil {
			t.Fatal("ceremony must fail with corrupt signer")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("post-sign corruption rejected ✓")
}

// TestRPCTSSKeygenCorruptResigned verifies that a signer who
// corrupts tss-lib wire data and re-signs the corrupt payload
// passes signature verification but is caught at the tss-lib
// protocol level (ParseWireMessage or party.Update failure).
func TestRPCTSSKeygenCorruptResigned(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	defer teardownRPCMesh(t, nodes)

	// Node 2 corrupts wire data then re-signs so Verify passes.
	// tss-lib rejects the garbage at protocol level.
	corruptNode := nodes[2]
	corruptNode.corruptFn = func(msg *TSSMessage) {
		if len(msg.Data) > 0 {
			msg.Data[0] ^= 0xff
			hash := HashTSSMessage(msg.CeremonyID, msg.Data)
			msg.Signature = corruptNode.secret.Sign(hash)
		}
	}

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1

	t.Log("=== Keygen with re-signed corruption (node 2) ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(context.Background(),
		30*time.Second)
	defer cancel()

	for _, node := range nodes {
		_, err := node.waitCeremony(ctx, cid)
		if err == nil {
			t.Fatal("ceremony must fail with corrupt wire data")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("re-signed corruption caught at protocol level ✓")
}

// TestRPCTSSKeygenBadSignature verifies that messages with zeroed
// signatures are rejected at the Verify step.
func TestRPCTSSKeygenBadSignature(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	defer teardownRPCMesh(t, nodes)

	// Node 2 zeros its signature on every outgoing message.
	nodes[2].corruptFn = func(msg *TSSMessage) {
		for i := range msg.Signature {
			msg.Signature[i] = 0
		}
	}

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1

	t.Log("=== Keygen with zeroed signature (node 2) ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(context.Background(),
		30*time.Second)
	defer cancel()

	for _, node := range nodes {
		_, err := node.waitCeremony(ctx, cid)
		if err == nil {
			t.Fatal("ceremony must fail with bad signature")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("zeroed signature rejected ✓")
}

// TestRPCTSSKeygenSpoofIdentity verifies that a signer claiming
// to be another party (From field mismatch) is caught by Verify.
// The signature was made with node 2's key, so verifying against
// node 0's identity fails.
func TestRPCTSSKeygenSpoofIdentity(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	defer teardownRPCMesh(t, nodes)

	// Node 2 claims to be node 0.
	spoofTarget := nodes[0].id
	nodes[2].corruptFn = func(msg *TSSMessage) {
		msg.From = spoofTarget
	}

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1

	t.Log("=== Keygen with spoofed identity (node 2 → node 0) ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(context.Background(),
		30*time.Second)
	defer cancel()

	for _, node := range nodes {
		_, err := node.waitCeremony(ctx, cid)
		if err == nil {
			t.Fatal("ceremony must fail with spoofed identity")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("spoofed identity rejected ✓")
}

// TestRPCTSSSignCorruptPostSign verifies that an honest keygen
// followed by a corrupt signer during the signing ceremony causes
// signing to fail. The keygen result remains valid; only the
// signing phase is affected.
func TestRPCTSSSignCorruptPostSign(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	defer teardownRPCMesh(t, nodes)

	committee := rpcCommittee(nodes)
	threshold := 1 // 2-of-3

	ctx, cancel := context.WithTimeout(context.Background(),
		3*time.Minute)
	defer cancel()

	// === Honest keygen ===
	keygenCID := NewCeremonyID()
	t.Log("=== Honest keygen ===")

	rpcInitKeygen(t, nodes, committee, keygenCID, threshold)

	var keyID string
	for _, node := range nodes {
		result, err := node.waitCeremony(ctx, keygenCID)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		save := result.(*keygen.LocalPartySaveData)
		keyID = save.ECDSAPub.X().Text(16)[:16]
	}
	t.Logf("keygen done, keyID=%s", keyID)

	// === Corrupt sign: node 2 flips bits post-sign ===
	nodes[2].corruptFn = func(msg *TSSMessage) {
		if len(msg.Data) > 0 {
			msg.Data[0] ^= 0xff
		}
	}

	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("corrupt signer test"))
	t.Log("=== Sign with post-sign corruption (node 2) ===")

	rpcInitSign(t, nodes, committee, signCID,
		[]byte(keyID), threshold, data)

	shortCtx, shortCancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer shortCancel()

	for _, node := range nodes {
		_, err := node.waitCeremony(shortCtx, signCID)
		if err == nil {
			t.Fatal("signing must fail with corrupt signer")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("sign-phase corruption rejected ✓")
}

// TestRPCTSSReshareCorruptPostSign verifies that an honest keygen
// followed by a corrupt signer during reshare causes the reshare
// to fail. Node 2 is in both old and new committees (overlapping).
func TestRPCTSSReshareCorruptPostSign(t *testing.T) {
	// 4 nodes: keygen {0,1,2}, reshare → {1,2,3}.
	// Node 2 overlaps both committees and corrupts.
	nodes := setupRPCMesh(t, 4)
	defer teardownRPCMesh(t, nodes)

	oldCommittee := rpcCommittee(nodes[:3])
	threshold := 1

	ctx, cancel := context.WithTimeout(context.Background(),
		3*time.Minute)
	defer cancel()

	// === Honest keygen ===
	keygenCID := NewCeremonyID()
	t.Log("=== Honest keygen with {0,1,2} ===")

	rpcInitKeygen(t, nodes[:3], oldCommittee, keygenCID, threshold)

	for _, node := range nodes[:3] {
		_, err := node.waitCeremony(ctx, keygenCID)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
	}
	t.Log("keygen done")

	// === Corrupt reshare: node 2 flips bits ===
	nodes[2].corruptFn = func(msg *TSSMessage) {
		if len(msg.Data) > 0 {
			msg.Data[0] ^= 0xff
		}
	}

	newCommittee := rpcCommittee(nodes[1:])
	reshareCID := NewCeremonyID()
	t.Log("=== Reshare with corruption (node 2) ===")

	rpcInitReshare(t, nodes, oldCommittee, newCommittee,
		reshareCID, threshold, threshold)

	shortCtx, shortCancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer shortCancel()

	for _, node := range nodes {
		err := node.waitReshare(shortCtx, reshareCID)
		if err == nil {
			t.Fatal("reshare must fail with corrupt signer")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("reshare corruption rejected ✓")
}
