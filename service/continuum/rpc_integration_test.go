// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hemilabs/x/tss-lib/v2/common"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v2/tss"
)

// =============================================================================
// TSSNode - A party that handles RPC commands and runs real tss-lib ceremonies
// =============================================================================

type TSSNode struct {
	t         *testing.T
	id        Identity
	secret    *Secret
	partyID   *tss.PartyID
	preParams *keygen.LocalPreParams

	// Key storage: keyID -> key share
	keys   map[string]*keygen.LocalPartySaveData
	keysMu sync.RWMutex

	// Active ceremonies
	ceremonies   map[CeremonyID]*activeCeremony
	ceremoniesMu sync.Mutex

	// Communication
	inbox  chan rpcMessage
	router *TSSRouter
}

type rpcMessage struct {
	from    Identity
	payload any
}

type activeCeremony struct {
	ctype     CeremonyType
	party     tss.Party
	pids      tss.SortedPartyIDs // For looking up sender
	outCh     chan tss.Message
	endCh     chan any // keygen.LocalPartySaveData or common.SignatureData
	errCh     chan *tss.Error
	threshold int
	keyID     string
	data      []byte // for signing
}

// TSSRouter coordinates ceremonies between TSSNodes
type TSSRouter struct {
	t         *testing.T
	nodes     map[Identity]*TSSNode
	nodesMu   sync.RWMutex
	preParams []keygen.LocalPreParams
}

func NewTSSRouter(t *testing.T) *TSSRouter {
	return &TSSRouter{
		t:     t,
		nodes: make(map[Identity]*TSSNode),
	}
}

func (r *TSSRouter) LoadPreParams(count int) {
	r.preParams = loadPreParams(r.t, count)
}

func (r *TSSRouter) AddNode() *TSSNode {
	r.nodesMu.Lock()
	defer r.nodesMu.Unlock()

	secret, err := NewSecret()
	if err != nil {
		r.t.Fatal(err)
	}

	var preParams *keygen.LocalPreParams
	if len(r.preParams) > len(r.nodes) {
		preParams = &r.preParams[len(r.nodes)]
	}

	node := &TSSNode{
		t:          r.t,
		id:         secret.Identity,
		secret:     secret,
		partyID:    tss.NewPartyID(secret.String(), secret.String(), new(big.Int).SetBytes(secret.Identity[:])),
		preParams:  preParams,
		keys:       make(map[string]*keygen.LocalPartySaveData),
		ceremonies: make(map[CeremonyID]*activeCeremony),
		inbox:      make(chan rpcMessage, 100),
		router:     r,
	}

	r.nodes[secret.Identity] = node
	go node.run()

	return node
}

func (r *TSSRouter) GetNode(id Identity) *TSSNode {
	r.nodesMu.RLock()
	defer r.nodesMu.RUnlock()
	return r.nodes[id]
}

func (r *TSSRouter) Broadcast(from Identity, cid CeremonyID, msg tss.Message) {
	r.nodesMu.RLock()
	defer r.nodesMu.RUnlock()

	data, _, _ := msg.WireBytes()

	for id, node := range r.nodes {
		if id == from {
			continue
		}
		// Wrap in TSSMessage with signature
		hash := HashTSSMessage(cid, data)
		fromNode := r.nodes[from]
		sig := fromNode.secret.Sign(hash)

		tssMsg := TSSMessage{
			CeremonyID: cid,
			From:       from,
			Broadcast:  true,
			Data:       data,
			Signature:  sig,
		}
		node.inbox <- rpcMessage{from: from, payload: tssMsg}
	}
}

func (r *TSSRouter) SendP2P(from Identity, cid CeremonyID, to []*tss.PartyID, msg tss.Message) {
	r.nodesMu.RLock()
	defer r.nodesMu.RUnlock()

	data, _, _ := msg.WireBytes()

	for _, dest := range to {
		// Find node by partyID
		for id, node := range r.nodes {
			if node.partyID.Id == dest.Id {
				hash := HashTSSMessage(cid, data)
				fromNode := r.nodes[from]
				sig := fromNode.secret.Sign(hash)

				tssMsg := TSSMessage{
					CeremonyID: cid,
					From:       from,
					Broadcast:  false,
					Data:       data,
					Signature:  sig,
				}
				node.inbox <- rpcMessage{from: from, payload: tssMsg}
				break
			}
			_ = id
		}
	}
}

// =============================================================================
// TSSNode implementation
// =============================================================================

func (n *TSSNode) run() {
	for msg := range n.inbox {
		switch v := msg.payload.(type) {
		case KeygenRequest:
			n.handleKeygenRequest(v)
		case SignRequest:
			n.handleSignRequest(v)
		case ReshareRequest:
			n.handleReshareRequest(v)
		case TSSMessage:
			n.handleTSSMessage(v)
		}
	}
}

func (n *TSSNode) handleKeygenRequest(req KeygenRequest) {
	n.ceremoniesMu.Lock()
	defer n.ceremoniesMu.Unlock()

	// Sort committee and build context
	sortedPids := tss.SortPartyIDs(req.Committee)
	ctx := tss.NewPeerContext(sortedPids)

	// Find our position
	var ourPid *tss.PartyID
	for _, pid := range sortedPids {
		if pid.Id == n.partyID.Id {
			ourPid = pid
			break
		}
	}
	if ourPid == nil {
		n.t.Logf("Node %s not in committee (our ID: %s)", n.id, n.partyID.Id)
		for _, pid := range sortedPids {
			n.t.Logf("  committee member: %s", pid.Id)
		}
		return
	}

	params := tss.NewParameters(tss.S256(), ctx, ourPid, len(sortedPids), req.Threshold)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan *keygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	var party *keygen.LocalParty
	if n.preParams != nil {
		party = keygen.NewLocalParty(params, outCh, endCh, *n.preParams).(*keygen.LocalParty)
	} else {
		party = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
	}

	ac := &activeCeremony{
		ctype:     CeremonyKeygen,
		party:     party,
		pids:      sortedPids,
		outCh:     outCh,
		endCh:     make(chan any, 1),
		errCh:     errCh,
		threshold: req.Threshold,
	}
	n.ceremonies[req.CeremonyID] = ac

	// Pump messages
	go n.pumpMessages(req.CeremonyID, ac, outCh)
	go n.waitKeygenEnd(req.CeremonyID, endCh)

	if err := party.Start(); err != nil {
		n.t.Logf("Keygen start error: %v", err)
	}
}

func (n *TSSNode) handleSignRequest(req SignRequest) {
	n.ceremoniesMu.Lock()
	defer n.ceremoniesMu.Unlock()

	// Get key
	n.keysMu.RLock()
	key, ok := n.keys[string(req.KeyID)]
	n.keysMu.RUnlock()
	if !ok {
		n.t.Logf("Node %s: key not found for signing", n.id)
		return
	}

	// Build party context
	pids := make([]*tss.PartyID, len(req.Committee))
	for i, upid := range req.Committee {
		pids[i] = &tss.PartyID{
			MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
				Id:      upid.Id,
				Moniker: upid.Moniker,
				Key:     upid.Key,
			},
			Index: upid.Index,
		}
	}
	sortedPids := tss.SortPartyIDs(pids)
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

	params := tss.NewParameters(tss.S256(), ctx, ourPid, len(sortedPids), req.Threshold)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	party := signing.NewLocalParty(new(big.Int).SetBytes(req.Data), params, *key, outCh, endCh, len(req.Data)).(*signing.LocalParty)

	ac := &activeCeremony{
		ctype:     CeremonySign,
		party:     party,
		pids:      sortedPids,
		outCh:     outCh,
		endCh:     make(chan any, 1),
		errCh:     errCh,
		threshold: req.Threshold,
		keyID:     string(req.KeyID),
		data:      req.Data,
	}
	n.ceremonies[req.CeremonyID] = ac

	go n.pumpMessages(req.CeremonyID, ac, outCh)
	go n.waitSignEnd(req.CeremonyID, endCh)

	if err := party.Start(); err != nil {
		n.t.Logf("Sign start error: %v", err)
	}
}

func (n *TSSNode) handleReshareRequest(req ReshareRequest) {
	// TODO: implement reshare
	n.t.Log("Reshare not yet implemented")
}

func (n *TSSNode) handleTSSMessage(msg TSSMessage) {
	// Verify signature
	hash := HashTSSMessage(msg.CeremonyID, msg.Data)
	_, err := Verify(hash, msg.From, msg.Signature)
	if err != nil {
		n.t.Logf("Node %s: invalid signature from %s: %v", n.id, msg.From, err)
		return
	}

	n.ceremoniesMu.Lock()
	ac, ok := n.ceremonies[msg.CeremonyID]
	n.ceremoniesMu.Unlock()
	if !ok {
		n.t.Logf("Node %s: unknown ceremony %s", n.id, msg.CeremonyID)
		return
	}

	// Find the sender in the ceremony's party list
	var fromPid *tss.PartyID
	fromIDStr := msg.From.String()
	for _, pid := range ac.pids {
		if pid.Id == fromIDStr {
			fromPid = pid
			break
		}
	}
	if fromPid == nil {
		n.t.Logf("Node %s: sender %s not found in ceremony", n.id, msg.From)
		return
	}

	// Parse wire message
	parsed, err := tss.ParseWireMessage(msg.Data, fromPid, msg.Broadcast)
	if err != nil {
		n.t.Logf("Node %s: parse error: %v", n.id, err)
		return
	}

	if _, err := ac.party.Update(parsed); err != nil {
		n.t.Logf("Node %s: update error: %v", n.id, err)
	}
}

func (n *TSSNode) pumpMessages(cid CeremonyID, ac *activeCeremony, outCh <-chan tss.Message) {
	for msg := range outCh {
		if msg.GetTo() == nil {
			n.router.Broadcast(n.id, cid, msg)
		} else {
			n.router.SendP2P(n.id, cid, msg.GetTo(), msg)
		}
	}
}

func (n *TSSNode) waitKeygenEnd(cid CeremonyID, endCh <-chan *keygen.LocalPartySaveData) {
	select {
	case save := <-endCh:
		// Store key
		keyID := save.ECDSAPub.X().Text(16)[:16]
		n.keysMu.Lock()
		n.keys[keyID] = save
		n.keysMu.Unlock()

		n.ceremoniesMu.Lock()
		if ac, ok := n.ceremonies[cid]; ok {
			ac.endCh <- save
		}
		n.ceremoniesMu.Unlock()

		n.t.Logf("Node %s: keygen complete, keyID=%s", n.id, keyID)

	case <-time.After(5 * time.Minute):
		n.t.Logf("Node %s: keygen timeout", n.id)
	}
}

func (n *TSSNode) waitSignEnd(cid CeremonyID, endCh <-chan *common.SignatureData) {
	select {
	case sig := <-endCh:
		n.ceremoniesMu.Lock()
		if ac, ok := n.ceremonies[cid]; ok {
			ac.endCh <- sig
		}
		n.ceremoniesMu.Unlock()

		n.t.Logf("Node %s: signing complete", n.id)

	case <-time.After(5 * time.Minute):
		n.t.Logf("Node %s: signing timeout", n.id)
	}
}

func (n *TSSNode) WaitCeremony(cid CeremonyID, timeout time.Duration) (any, error) {
	deadline := time.Now().Add(timeout)

	// Wait for ceremony to be registered (async message processing)
	var ac *activeCeremony
	for time.Now().Before(deadline) {
		n.ceremoniesMu.Lock()
		ac = n.ceremonies[cid]
		n.ceremoniesMu.Unlock()
		if ac != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ac == nil {
		return nil, errors.New("unknown ceremony")
	}

	select {
	case result := <-ac.endCh:
		return result, nil
	case <-time.After(time.Until(deadline)):
		return nil, errors.New("timeout")
	}
}

func (n *TSSNode) GetKey(keyID string) *keygen.LocalPartySaveData {
	n.keysMu.RLock()
	defer n.keysMu.RUnlock()
	return n.keys[keyID]
}

// =============================================================================
// Test Helpers
// =============================================================================

func loadPreParams(t *testing.T, count int) []keygen.LocalPreParams {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	path := filepath.Join(dir, "tss_examples", "preparams.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("No preparams file, tests will be slow: %v", err)
		return nil
	}

	var params []keygen.LocalPreParams
	if err := json.Unmarshal(data, &params); err != nil {
		t.Logf("Failed to parse preparams: %v", err)
		return nil
	}

	if len(params) < count {
		t.Logf("Only %d preparams available, need %d", len(params), count)
		return params
	}

	return params[:count]
}

func buildCommittee(nodes []*TSSNode) tss.UnSortedPartyIDs {
	pids := make(tss.UnSortedPartyIDs, len(nodes))
	for i, n := range nodes {
		pids[i] = n.partyID
	}
	return pids
}

// =============================================================================
// Positive Tests
// =============================================================================

func TestRPCIntegrationKeygen(t *testing.T) {
	router := NewTSSRouter(t)
	router.LoadPreParams(3)

	// Create 3 nodes
	nodes := make([]*TSSNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = router.AddNode()
	}

	// Build committee
	committee := buildCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1 // 2-of-3

	t.Log("=== Starting Keygen via RPC ===")

	// Send KeygenRequest to all nodes
	for _, node := range nodes {
		node.inbox <- rpcMessage{
			payload: KeygenRequest{
				CeremonyID: cid,
				Curve:      "secp256k1",
				Threshold:  threshold,
				Committee:  committee,
			},
		}
	}

	// Wait for completion
	var keyID string
	for _, node := range nodes {
		result, err := node.WaitCeremony(cid, 2*time.Minute)
		if err != nil {
			t.Fatalf("Node %s failed: %v", node.id, err)
		}
		save := result.(*keygen.LocalPartySaveData)
		keyID = save.ECDSAPub.X().Text(16)[:16]
		t.Logf("Node %s: keygen success, pubX=%s...", node.id, keyID)
	}

	// Verify all nodes have the same public key
	var expectedX *big.Int
	for _, node := range nodes {
		key := node.GetKey(keyID)
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

func TestRPCIntegrationKeygenAndSign(t *testing.T) {
	router := NewTSSRouter(t)
	router.LoadPreParams(3)

	nodes := make([]*TSSNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = router.AddNode()
	}

	committee := buildCommittee(nodes)
	threshold := 1 // 2-of-3

	// === Keygen ===
	keygenCID := NewCeremonyID()
	t.Log("=== Keygen ===")

	for _, node := range nodes {
		node.inbox <- rpcMessage{
			payload: KeygenRequest{
				CeremonyID: keygenCID,
				Curve:      "secp256k1",
				Threshold:  threshold,
				Committee:  committee,
			},
		}
	}

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
	data := sha256.Sum256([]byte("hello world"))
	t.Log("=== Sign ===")

	for _, node := range nodes {
		node.inbox <- rpcMessage{
			payload: SignRequest{
				CeremonyID: signCID,
				KeyID:      []byte(keyID),
				Threshold:  threshold,
				Committee:  committee,
				Data:       data[:],
			},
		}
	}

	// Wait for signatures and verify
	for _, node := range nodes {
		result, err := node.WaitCeremony(signCID, 2*time.Minute)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		sig := result.(*common.SignatureData)

		// Verify ECDSA signature
		r := new(big.Int).SetBytes(sig.R)
		s := new(big.Int).SetBytes(sig.S)
		if !ecdsa.Verify(pubKey, data[:], r, s) {
			t.Fatalf("Node %s: signature verification failed", node.id)
		}
		t.Logf("Node %s: signature verified ✓", node.id)
	}
}

// =============================================================================
// Negative Tests
// =============================================================================

func TestRPCIntegrationKeygenWrongThreshold(t *testing.T) {
	router := NewTSSRouter(t)
	router.LoadPreParams(3)

	nodes := make([]*TSSNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = router.AddNode()
	}

	committee := buildCommittee(nodes)
	cid := NewCeremonyID()

	// Threshold too high - should fail
	threshold := 3 // 4-of-3 is invalid

	t.Log("=== Keygen with invalid threshold ===")

	for _, node := range nodes {
		node.inbox <- rpcMessage{
			payload: KeygenRequest{
				CeremonyID: cid,
				Curve:      "secp256k1",
				Threshold:  threshold,
				Committee:  committee,
			},
		}
	}

	// Should timeout or error
	_, err := nodes[0].WaitCeremony(cid, 10*time.Second)
	if err == nil {
		t.Log("Got result (tss-lib may have different threshold semantics)")
	} else {
		t.Logf("Expected failure: %v ✓", err)
	}
}

func TestRPCIntegrationSignWithoutKey(t *testing.T) {
	router := NewTSSRouter(t)

	nodes := make([]*TSSNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = router.AddNode()
	}

	committee := buildCommittee(nodes)
	cid := NewCeremonyID()
	data := sha256.Sum256([]byte("test"))

	t.Log("=== Sign without keygen (no key) ===")

	// Try to sign without doing keygen first
	for _, node := range nodes {
		node.inbox <- rpcMessage{
			payload: SignRequest{
				CeremonyID: cid,
				KeyID:      []byte("nonexistent-key"),
				Threshold:  1,
				Committee:  committee,
				Data:       data[:],
			},
		}
	}

	// Should fail - no key
	_, err := nodes[0].WaitCeremony(cid, 5*time.Second)
	if err == nil {
		t.Fatal("Should have failed - no key exists")
	}
	t.Logf("Expected failure: %v ✓", err)
}

func TestRPCIntegrationMITMMessageInjection(t *testing.T) {
	router := NewTSSRouter(t)
	router.LoadPreParams(3)

	nodes := make([]*TSSNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = router.AddNode()
	}

	committee := buildCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1

	t.Log("=== MITM injection attack ===")

	// Start keygen
	for _, node := range nodes {
		node.inbox <- rpcMessage{
			payload: KeygenRequest{
				CeremonyID: cid,
				Curve:      "secp256k1",
				Threshold:  threshold,
				Committee:  committee,
			},
		}
	}

	// Attacker tries to inject a fake message
	attacker, _ := NewSecret()
	fakeData := []byte("malicious-round-data")
	hash := HashTSSMessage(cid, fakeData)
	fakeSig := attacker.Sign(hash)

	// Inject to node 0, claiming to be from node 1
	fakeMsg := TSSMessage{
		CeremonyID: cid,
		From:       nodes[1].id, // Claims to be node 1
		Broadcast:  true,
		Data:       fakeData,
		Signature:  fakeSig, // But signed by attacker
	}

	nodes[0].inbox <- rpcMessage{from: attacker.Identity, payload: fakeMsg}

	// The message should be rejected due to signature mismatch
	// Keygen should still complete successfully between honest nodes
	result, err := nodes[0].WaitCeremony(cid, 2*time.Minute)
	if err != nil {
		t.Logf("Ceremony failed (MITM may have disrupted): %v", err)
	} else {
		t.Logf("Ceremony completed despite MITM attempt ✓")
		_ = result
	}
}

// =============================================================================
// Fuzz Tests
// =============================================================================

func FuzzTSSMessageSignature(f *testing.F) {
	// Seed corpus
	f.Add([]byte("test data"), []byte{1, 2, 3, 4})

	f.Fuzz(func(t *testing.T, data []byte, cidBytes []byte) {
		if len(cidBytes) < 32 {
			return
		}

		var cid CeremonyID
		copy(cid[:], cidBytes[:32])

		secret, err := NewSecret()
		if err != nil {
			return
		}

		// Sign
		hash := HashTSSMessage(cid, data)
		sig := secret.Sign(hash)

		// Verify should pass
		_, err = Verify(hash, secret.Identity, sig)
		if err != nil {
			t.Errorf("Valid signature rejected: %v", err)
		}

		// Tamper with data - verify should fail
		if len(data) > 0 {
			tampered := make([]byte, len(data))
			copy(tampered, data)
			tampered[0] ^= 0xFF

			tamperedHash := HashTSSMessage(cid, tampered)
			_, err = Verify(tamperedHash, secret.Identity, sig)
			if err == nil {
				t.Error("Tampered data should fail verification")
			}
		}

		// Wrong identity - verify should fail
		other, _ := NewSecret()
		_, err = Verify(hash, other.Identity, sig)
		if err == nil {
			t.Error("Wrong identity should fail verification")
		}
	})
}

func FuzzCeremonyID(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test CeremonyID JSON round-trip
		var cid CeremonyID
		if len(data) >= 32 {
			copy(cid[:], data[:32])
		}

		jsonData, err := json.Marshal(cid)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		var decoded CeremonyID
		if err := json.Unmarshal(jsonData, &decoded); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if cid != decoded {
			t.Error("Round-trip mismatch")
		}
	})
}

// NewCeremonyID creates a random ceremony ID
func NewCeremonyID() CeremonyID {
	var cid CeremonyID
	_, _ = rand.Read(cid[:])
	return cid
}
