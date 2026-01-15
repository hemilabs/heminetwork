// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
)

// MockRouter simulates a ceremony coordinator.
// It generates CeremonyIDs and routes messages between parties.
type MockRouter struct {
	mu         sync.Mutex
	parties    map[Identity]*MockParty
	ceremonies map[CeremonyID]*MockCeremony
}

// MockParty simulates a TSS party that handles RPC messages.
type MockParty struct {
	id     Identity
	secret *Secret           // Has private key for signing
	inbox  chan any          // Receives RPC messages
	outbox chan any          // Sends RPC messages
	keys   map[string][]byte // keyID -> key share (simplified)
}

// MockCeremony tracks state for an active ceremony.
type MockCeremony struct {
	id        CeremonyID
	ctype     CeremonyType
	parties   []Identity
	threshold int
	responses map[Identity]bool
	messages  []TSSMessage
	done      bool
	err       error
}

func NewMockRouter() *MockRouter {
	return &MockRouter{
		parties:    make(map[Identity]*MockParty),
		ceremonies: make(map[CeremonyID]*MockCeremony),
	}
}

// AddPartyWithSecret creates a party with a real keypair for signing.
func (r *MockRouter) AddPartyWithSecret(secret *Secret) *MockParty {
	r.mu.Lock()
	defer r.mu.Unlock()

	p := &MockParty{
		id:     secret.Identity,
		secret: secret,
		inbox:  make(chan any, 100),
		outbox: make(chan any, 100),
		keys:   make(map[string][]byte),
	}
	r.parties[secret.Identity] = p
	return p
}

// AddParty creates a party with a random identity (no signing capability).
func (r *MockRouter) AddParty(id Identity) *MockParty {
	r.mu.Lock()
	defer r.mu.Unlock()

	p := &MockParty{
		id:     id,
		inbox:  make(chan any, 100),
		outbox: make(chan any, 100),
		keys:   make(map[string][]byte),
	}
	r.parties[id] = p
	return p
}

func (r *MockRouter) NewCeremonyID() CeremonyID {
	var id CeremonyID
	_, _ = rand.Read(id[:])
	return id
}

func (r *MockRouter) StartKeygen(parties []Identity, threshold int) (CeremonyID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(parties) < 2 {
		return CeremonyID{}, errors.New("need at least 2 parties")
	}
	if threshold < 1 || threshold >= len(parties) {
		return CeremonyID{}, errors.New("invalid threshold")
	}

	cid := r.NewCeremonyID()
	r.ceremonies[cid] = &MockCeremony{
		id:        cid,
		ctype:     CeremonyKeygen,
		parties:   parties,
		threshold: threshold,
		responses: make(map[Identity]bool),
	}

	// Send KeygenRequest to all parties
	for _, pid := range parties {
		if p, ok := r.parties[pid]; ok {
			p.inbox <- KeygenRequest{
				CeremonyID: cid,
				Curve:      "secp256k1",
				Threshold:  threshold,
			}
		}
	}

	return cid, nil
}

func (r *MockRouter) StartSign(cid CeremonyID, parties []Identity, threshold int, keyID []byte, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(data) != 32 {
		return errors.New("data must be 32 bytes")
	}
	if len(parties) < threshold+1 {
		return errors.New("not enough parties for threshold")
	}

	r.ceremonies[cid] = &MockCeremony{
		id:        cid,
		ctype:     CeremonySign,
		parties:   parties,
		threshold: threshold,
		responses: make(map[Identity]bool),
	}

	// Send SignRequest to all parties
	for _, pid := range parties {
		if p, ok := r.parties[pid]; ok {
			p.inbox <- SignRequest{
				CeremonyID: cid,
				KeyID:      keyID,
				Threshold:  threshold,
				Data:       data,
			}
		}
	}

	return nil
}

// HashTSSMessage computes the hash that should be signed for a TSSMessage.
// Hash = SHA256(CeremonyID || Data)
func HashTSSMessage(cid CeremonyID, data []byte) []byte {
	h := sha256.New()
	h.Write(cid[:])
	h.Write(data)
	return h.Sum(nil)
}

// RouteTSSMessage routes a message after verifying the signature.
func (r *MockRouter) RouteTSSMessage(msg TSSMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ceremony, ok := r.ceremonies[msg.CeremonyID]
	if !ok {
		return errors.New("unknown ceremony")
	}

	// Verify sender is part of ceremony
	found := false
	for _, p := range ceremony.parties {
		if p == msg.From {
			found = true
			break
		}
	}
	if !found {
		return errors.New("sender not in ceremony")
	}

	// Verify signature
	hash := HashTSSMessage(msg.CeremonyID, msg.Data)
	_, err := Verify(hash, msg.From, msg.Signature)
	if err != nil {
		return errors.New("invalid signature: " + err.Error())
	}

	ceremony.messages = append(ceremony.messages, msg)

	// Route to recipients
	if msg.Broadcast {
		for _, pid := range ceremony.parties {
			if pid == msg.From {
				continue
			}
			if p, ok := r.parties[pid]; ok {
				p.inbox <- msg
			}
		}
	}
	// P2P routing would check msg destination

	return nil
}

func (r *MockRouter) HandleResponse(from Identity, resp any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch v := resp.(type) {
	case KeygenResponse:
		c, ok := r.ceremonies[v.CeremonyID]
		if !ok {
			return errors.New("unknown ceremony")
		}
		c.responses[from] = v.Success
		if !v.Success {
			c.err = errors.New(v.Error)
		}

	case SignResponse:
		c, ok := r.ceremonies[v.CeremonyID]
		if !ok {
			return errors.New("unknown ceremony")
		}
		c.responses[from] = v.Success
		if !v.Success {
			c.err = errors.New(v.Error)
		}

	case CeremonyResult:
		c, ok := r.ceremonies[v.CeremonyID]
		if !ok {
			return errors.New("unknown ceremony")
		}
		c.responses[from] = v.Success
		if !v.Success && v.Error != "" {
			c.err = errors.New(v.Error)
		}
		if len(c.responses) == len(c.parties) {
			c.done = true
		}

	case CeremonyAbort:
		c, ok := r.ceremonies[v.CeremonyID]
		if !ok {
			return errors.New("unknown ceremony")
		}
		c.done = true
		c.err = errors.New(v.Reason)
	}

	return nil
}

func (r *MockRouter) GetCeremony(cid CeremonyID) *MockCeremony {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ceremonies[cid]
}

// =============================================================================
// Positive Test Cases
// =============================================================================

func TestRPCKeygenRequestResponse(t *testing.T) {
	router := NewMockRouter()

	// Create 3 parties
	var ids []Identity
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		ids = append(ids, id)
		router.AddParty(id)
	}

	// Start keygen
	cid, err := router.StartKeygen(ids, 1) // 2-of-3
	if err != nil {
		t.Fatalf("StartKeygen: %v", err)
	}

	// Each party should receive KeygenRequest
	for _, id := range ids {
		p := router.parties[id]
		select {
		case msg := <-p.inbox:
			req, ok := msg.(KeygenRequest)
			if !ok {
				t.Fatalf("expected KeygenRequest, got %T", msg)
			}
			if req.CeremonyID != cid {
				t.Fatal("ceremony ID mismatch")
			}
			if req.Threshold != 1 {
				t.Fatalf("threshold = %d, want 1", req.Threshold)
			}

			// Party acknowledges
			_ = router.HandleResponse(id, KeygenResponse{
				CeremonyID: cid,
				Success:    true,
			})
		default:
			t.Fatal("party did not receive KeygenRequest")
		}
	}

	t.Log("All parties received KeygenRequest and responded ✓")
}

func TestRPCSignRequestResponse(t *testing.T) {
	router := NewMockRouter()

	var ids []Identity
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		ids = append(ids, id)
		router.AddParty(id)
	}

	// Create ceremony ID and start signing
	cid := router.NewCeremonyID()
	keyID := []byte("test-key-id")
	data := make([]byte, 32)
	_, _ = rand.Read(data)

	err := router.StartSign(cid, ids, 1, keyID, data) // 2-of-3
	if err != nil {
		t.Fatalf("StartSign: %v", err)
	}

	// Each party receives SignRequest
	for _, id := range ids {
		p := router.parties[id]
		select {
		case msg := <-p.inbox:
			req, ok := msg.(SignRequest)
			if !ok {
				t.Fatalf("expected SignRequest, got %T", msg)
			}
			if req.CeremonyID != cid {
				t.Fatal("ceremony ID mismatch")
			}
			if string(req.KeyID) != string(keyID) {
				t.Fatal("keyID mismatch")
			}
			if string(req.Data) != string(data) {
				t.Fatal("data mismatch")
			}

			// Party responds with signature
			_ = router.HandleResponse(id, SignResponse{
				CeremonyID: cid,
				Success:    true,
				R:          []byte("fake-r"),
				S:          []byte("fake-s"),
			})
		default:
			t.Fatal("party did not receive SignRequest")
		}
	}

	t.Log("All parties received SignRequest and responded ✓")
}

func TestRPCTSSMessageRouting(t *testing.T) {
	router := NewMockRouter()

	// Create parties with real secrets for signing
	var secrets []*Secret
	var ids []Identity
	for i := 0; i < 3; i++ {
		secret, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, secret)
		ids = append(ids, secret.Identity)
		router.AddPartyWithSecret(secret)
	}

	// Setup ceremony
	cid, _ := router.StartKeygen(ids, 1)

	// Drain KeygenRequests
	for _, id := range ids {
		<-router.parties[id].inbox
	}

	// Party 0 broadcasts a TSS message with valid signature
	data := []byte("round1-data")
	hash := HashTSSMessage(cid, data)
	sig := secrets[0].Sign(hash)

	msg := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyKeygen,
		From:       ids[0],
		Broadcast:  true,
		Data:       data,
		Signature:  sig,
	}

	err := router.RouteTSSMessage(msg)
	if err != nil {
		t.Fatalf("RouteTSSMessage: %v", err)
	}

	// Parties 1 and 2 should receive it
	for i := 1; i < 3; i++ {
		p := router.parties[ids[i]]
		select {
		case recv := <-p.inbox:
			tssMsg, ok := recv.(TSSMessage)
			if !ok {
				t.Fatalf("expected TSSMessage, got %T", recv)
			}
			if tssMsg.From != ids[0] {
				t.Fatal("wrong sender")
			}
			if string(tssMsg.Data) != "round1-data" {
				t.Fatal("data mismatch")
			}
		default:
			t.Fatalf("party %d did not receive broadcast", i)
		}
	}

	// Party 0 should NOT receive its own broadcast
	select {
	case <-router.parties[ids[0]].inbox:
		t.Fatal("sender received its own broadcast")
	default:
		// Good
	}

	t.Log("TSS message broadcast routing works ✓")
}

func TestRPCTSSMessageSignatureVerification(t *testing.T) {
	router := NewMockRouter()

	// Create parties with real secrets
	var secrets []*Secret
	var ids []Identity
	for i := 0; i < 3; i++ {
		secret, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, secret)
		ids = append(ids, secret.Identity)
		router.AddPartyWithSecret(secret)
	}

	cid, _ := router.StartKeygen(ids, 1)

	// Drain KeygenRequests
	for _, id := range ids {
		<-router.parties[id].inbox
	}

	// Test 1: Valid signature passes
	data := []byte("valid-data")
	hash := HashTSSMessage(cid, data)
	sig := secrets[0].Sign(hash)

	msg := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyKeygen,
		From:       ids[0],
		Broadcast:  true,
		Data:       data,
		Signature:  sig,
	}

	err := router.RouteTSSMessage(msg)
	if err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	t.Log("Valid signature accepted ✓")

	// Test 2: Wrong signer (party 1 signs, claims to be party 0)
	wrongSig := secrets[1].Sign(hash)
	msgWrongSigner := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyKeygen,
		From:       ids[0], // Claims to be party 0
		Broadcast:  true,
		Data:       data,
		Signature:  wrongSig, // But signed by party 1
	}

	err = router.RouteTSSMessage(msgWrongSigner)
	if err == nil {
		t.Fatal("wrong signer should be rejected")
	}
	t.Log("Wrong signer rejected ✓")

	// Test 3: Tampered data (signature doesn't match)
	msgTampered := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyKeygen,
		From:       ids[0],
		Broadcast:  true,
		Data:       []byte("tampered-data"), // Different data
		Signature:  sig,                     // Original signature
	}

	err = router.RouteTSSMessage(msgTampered)
	if err == nil {
		t.Fatal("tampered data should be rejected")
	}
	t.Log("Tampered data rejected ✓")

	// Test 4: Wrong ceremony ID in hash
	otherCID := router.NewCeremonyID()
	router.mu.Lock()
	router.ceremonies[otherCID] = &MockCeremony{
		id:        otherCID,
		ctype:     CeremonyKeygen,
		parties:   ids,
		threshold: 1,
		responses: make(map[Identity]bool),
	}
	router.mu.Unlock()

	// Sign for different ceremony
	wrongHash := HashTSSMessage(otherCID, data)
	wrongCIDSig := secrets[0].Sign(wrongHash)

	msgWrongCID := TSSMessage{
		CeremonyID: cid, // Claims ceremony cid
		Type:       CeremonyKeygen,
		From:       ids[0],
		Broadcast:  true,
		Data:       data,
		Signature:  wrongCIDSig, // But signed for otherCID
	}

	err = router.RouteTSSMessage(msgWrongCID)
	if err == nil {
		t.Fatal("wrong ceremony ID in signature should be rejected")
	}
	t.Log("Wrong ceremony ID rejected ✓")

	// Test 5: Empty signature
	msgNoSig := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyKeygen,
		From:       ids[0],
		Broadcast:  true,
		Data:       data,
		Signature:  nil,
	}

	err = router.RouteTSSMessage(msgNoSig)
	if err == nil {
		t.Fatal("empty signature should be rejected")
	}
	t.Log("Empty signature rejected ✓")

	// Test 6: Garbage signature
	msgGarbageSig := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyKeygen,
		From:       ids[0],
		Broadcast:  true,
		Data:       data,
		Signature:  []byte("garbage"),
	}

	err = router.RouteTSSMessage(msgGarbageSig)
	if err == nil {
		t.Fatal("garbage signature should be rejected")
	}
	t.Log("Garbage signature rejected ✓")
}

func TestRPCCeremonyResult(t *testing.T) {
	router := NewMockRouter()

	var ids []Identity
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		ids = append(ids, id)
		router.AddParty(id)
	}

	cid, _ := router.StartKeygen(ids, 1)

	// All parties report success
	for _, id := range ids {
		_ = router.HandleResponse(id, CeremonyResult{
			CeremonyID: cid,
			Success:    true,
		})
	}

	c := router.GetCeremony(cid)
	if !c.done {
		t.Fatal("ceremony should be done")
	}
	if c.err != nil {
		t.Fatalf("ceremony should have no error: %v", c.err)
	}

	t.Log("Ceremony completion tracking works ✓")
}

// =============================================================================
// Negative Test Cases
// =============================================================================

func TestRPCKeygenInvalidThreshold(t *testing.T) {
	router := NewMockRouter()

	var ids []Identity
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		ids = append(ids, id)
		router.AddParty(id)
	}

	// Threshold too high (need t+1 <= n, so t < n)
	_, err := router.StartKeygen(ids, 3) // 4-of-3 invalid
	if err == nil {
		t.Fatal("expected error for invalid threshold")
	}

	// Threshold too low
	_, err = router.StartKeygen(ids, 0) // 1-of-3 invalid (threshold must be >= 1)
	if err == nil {
		t.Fatal("expected error for zero threshold")
	}

	t.Log("Invalid threshold rejected ✓")
}

func TestRPCKeygenTooFewParties(t *testing.T) {
	router := NewMockRouter()

	var id Identity
	_, _ = rand.Read(id[:])
	router.AddParty(id)

	_, err := router.StartKeygen([]Identity{id}, 1)
	if err == nil {
		t.Fatal("expected error for single party")
	}

	t.Log("Too few parties rejected ✓")
}

func TestRPCSignInvalidDataLength(t *testing.T) {
	router := NewMockRouter()

	var ids []Identity
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		ids = append(ids, id)
		router.AddParty(id)
	}

	cid := router.NewCeremonyID()

	// Data too short
	err := router.StartSign(cid, ids, 1, []byte("key"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for short data")
	}

	// Data too long
	longData := make([]byte, 64)
	err = router.StartSign(cid, ids, 1, []byte("key"), longData)
	if err == nil {
		t.Fatal("expected error for long data")
	}

	t.Log("Invalid data length rejected ✓")
}

func TestRPCSignNotEnoughParties(t *testing.T) {
	router := NewMockRouter()

	var ids []Identity
	for i := 0; i < 2; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		ids = append(ids, id)
		router.AddParty(id)
	}

	cid := router.NewCeremonyID()
	data := make([]byte, 32)

	// 2 parties but threshold requires 3
	err := router.StartSign(cid, ids, 2, []byte("key"), data)
	if err == nil {
		t.Fatal("expected error for not enough parties")
	}

	t.Log("Not enough parties rejected ✓")
}

func TestRPCTSSMessageUnknownCeremony(t *testing.T) {
	router := NewMockRouter()

	secret, _ := NewSecret()
	router.AddPartyWithSecret(secret)

	// Random ceremony ID that doesn't exist
	var fakeCID CeremonyID
	_, _ = rand.Read(fakeCID[:])

	data := []byte("data")
	hash := HashTSSMessage(fakeCID, data)
	sig := secret.Sign(hash)

	msg := TSSMessage{
		CeremonyID: fakeCID,
		From:       secret.Identity,
		Broadcast:  true,
		Data:       data,
		Signature:  sig,
	}

	err := router.RouteTSSMessage(msg)
	if err == nil {
		t.Fatal("expected error for unknown ceremony")
	}

	t.Log("Unknown ceremony rejected ✓")
}

func TestRPCTSSMessageUnauthorizedSender(t *testing.T) {
	router := NewMockRouter()

	// Create ceremony with 2 parties
	var ids []Identity
	for i := 0; i < 2; i++ {
		secret, _ := NewSecret()
		ids = append(ids, secret.Identity)
		router.AddPartyWithSecret(secret)
	}

	cid, _ := router.StartKeygen(ids, 1)

	// Third party not in ceremony tries to send
	outsider, _ := NewSecret()
	router.AddPartyWithSecret(outsider)

	data := []byte("malicious")
	hash := HashTSSMessage(cid, data)
	sig := outsider.Sign(hash)

	msg := TSSMessage{
		CeremonyID: cid,
		From:       outsider.Identity,
		Broadcast:  true,
		Data:       data,
		Signature:  sig,
	}

	err := router.RouteTSSMessage(msg)
	if err == nil {
		t.Fatal("expected error for unauthorized sender")
	}

	t.Log("Unauthorized sender rejected ✓")
}

func TestRPCCeremonyAbort(t *testing.T) {
	router := NewMockRouter()

	var ids []Identity
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		ids = append(ids, id)
		router.AddParty(id)
	}

	cid, _ := router.StartKeygen(ids, 1)

	// One party aborts
	_ = router.HandleResponse(ids[0], CeremonyAbort{
		CeremonyID: cid,
		Reason:     "party went offline",
	})

	c := router.GetCeremony(cid)
	if !c.done {
		t.Fatal("ceremony should be done after abort")
	}
	if c.err == nil {
		t.Fatal("ceremony should have error after abort")
	}
	if c.err.Error() != "party went offline" {
		t.Fatalf("wrong error: %v", c.err)
	}

	t.Log("Ceremony abort works ✓")
}

func TestRPCKeygenResponseFailure(t *testing.T) {
	router := NewMockRouter()

	var ids []Identity
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		ids = append(ids, id)
		router.AddParty(id)
	}

	cid, _ := router.StartKeygen(ids, 1)

	// One party reports failure
	_ = router.HandleResponse(ids[0], KeygenResponse{
		CeremonyID: cid,
		Success:    false,
		Error:      "no preparams available",
	})

	c := router.GetCeremony(cid)
	if c.err == nil {
		t.Fatal("ceremony should have error")
	}
	if c.err.Error() != "no preparams available" {
		t.Fatalf("wrong error: %v", c.err)
	}

	t.Log("Keygen failure handling works ✓")
}

func TestRPCReshareRequest(t *testing.T) {
	router := NewMockRouter()

	var oldIDs, newIDs []Identity
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		oldIDs = append(oldIDs, id)
		router.AddParty(id)
	}
	for i := 0; i < 3; i++ {
		var id Identity
		_, _ = rand.Read(id[:])
		newIDs = append(newIDs, id)
		router.AddParty(id)
	}

	cid := router.NewCeremonyID()

	// Manually create reshare ceremony and send requests
	router.mu.Lock()
	allParties := append(oldIDs, newIDs...)
	router.ceremonies[cid] = &MockCeremony{
		id:        cid,
		ctype:     CeremonyReshare,
		parties:   allParties,
		threshold: 1,
		responses: make(map[Identity]bool),
	}
	router.mu.Unlock()

	// Send ReshareRequest to all parties
	for _, pid := range allParties {
		if p, ok := router.parties[pid]; ok {
			p.inbox <- ReshareRequest{
				CeremonyID:   cid,
				Curve:        "secp256k1",
				OldThreshold: 1,
				NewThreshold: 1,
			}
		}
	}

	// Verify all parties receive it
	for _, pid := range allParties {
		p := router.parties[pid]
		select {
		case msg := <-p.inbox:
			req, ok := msg.(ReshareRequest)
			if !ok {
				t.Fatalf("expected ReshareRequest, got %T", msg)
			}
			if req.CeremonyID != cid {
				t.Fatal("ceremony ID mismatch")
			}

			_ = router.HandleResponse(pid, ReshareResponse{
				CeremonyID: cid,
				Success:    true,
			})
		default:
			t.Fatal("party did not receive ReshareRequest")
		}
	}

	t.Log("Reshare request/response works ✓")
}

// =============================================================================
// Critical Security Tests - TSSMessage Signature Verification
// =============================================================================
// These tests verify the core security property: a routing node CANNOT inject
// fake TSS messages because it cannot forge signatures for other parties.
//
// The Identity -> Signature verification flow:
// 1. TSSMessage contains From (Identity) and Signature
// 2. Identity = ripemd160(compressed_secp256k1_pubkey)
// 3. Signature is ECDSA compact signature over Hash(CeremonyID || Data)
// 4. Verify() recovers pubkey from signature, computes Identity, checks match
//
// If verification fails, the message is rejected. This prevents:
// - Routing nodes from injecting fake messages
// - Replay attacks across ceremonies (CeremonyID in hash)
// - Data tampering (Data in hash)

func TestCriticalMITMPrevention(t *testing.T) {
	// Scenario: Alice, Bob, Charlie in ceremony. Router is MITM.
	// Router tries to inject fake message claiming to be from Alice.

	router := NewMockRouter()

	// Create real parties with secrets
	alice, _ := NewSecret()
	bob, _ := NewSecret()
	charlie, _ := NewSecret()

	router.AddPartyWithSecret(alice)
	router.AddPartyWithSecret(bob)
	router.AddPartyWithSecret(charlie)

	ids := []Identity{alice.Identity, bob.Identity, charlie.Identity}
	cid, _ := router.StartKeygen(ids, 1)

	// Drain setup messages
	for _, id := range ids {
		<-router.parties[id].inbox
	}

	// ATTACK: Router (or any MITM) tries to forge a message from Alice
	// The attacker does NOT have Alice's private key
	attackerSecret, _ := NewSecret() // Attacker's own key

	forgedData := []byte("malicious-round1-data")
	hash := HashTSSMessage(cid, forgedData)

	// Attacker signs with their own key but claims From=Alice
	attackerSig := attackerSecret.Sign(hash)

	forgedMsg := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyKeygen,
		From:       alice.Identity, // LIES: claims to be Alice
		Broadcast:  true,
		Data:       forgedData,
		Signature:  attackerSig, // Signed by attacker, not Alice
	}

	err := router.RouteTSSMessage(forgedMsg)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: Forged message accepted!")
	}

	t.Logf("MITM attack blocked: %v ✓", err)

	// Verify the error is specifically about identity mismatch
	if err.Error() != "invalid signature: "+ErrIdentityMismatch.Error() {
		t.Logf("Error was: %v (expected identity mismatch)", err)
	}
}

func TestCriticalReplayPrevention(t *testing.T) {
	// Scenario: Valid message from ceremony A cannot be replayed in ceremony B

	router := NewMockRouter()

	alice, _ := NewSecret()
	bob, _ := NewSecret()

	router.AddPartyWithSecret(alice)
	router.AddPartyWithSecret(bob)

	ids := []Identity{alice.Identity, bob.Identity}

	// Create two ceremonies
	cidA, _ := router.StartKeygen(ids, 1)
	cidB, _ := router.StartKeygen(ids, 1)

	// Drain setup
	for _, id := range ids {
		<-router.parties[id].inbox
		<-router.parties[id].inbox
	}

	// Alice sends valid message in ceremony A
	data := []byte("round1-data")
	hashA := HashTSSMessage(cidA, data)
	sigA := alice.Sign(hashA)

	validMsg := TSSMessage{
		CeremonyID: cidA,
		Type:       CeremonyKeygen,
		From:       alice.Identity,
		Broadcast:  true,
		Data:       data,
		Signature:  sigA,
	}

	// Valid in ceremony A
	err := router.RouteTSSMessage(validMsg)
	if err != nil {
		t.Fatalf("valid message rejected: %v", err)
	}
	t.Log("Valid message in ceremony A accepted ✓")

	// ATTACK: Replay the same message in ceremony B
	replayMsg := TSSMessage{
		CeremonyID: cidB, // Different ceremony!
		Type:       CeremonyKeygen,
		From:       alice.Identity,
		Broadcast:  true,
		Data:       data, // Same data
		Signature:  sigA, // Same signature (for ceremony A)
	}

	err = router.RouteTSSMessage(replayMsg)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: Replay attack succeeded!")
	}

	t.Logf("Replay attack blocked: %v ✓", err)
}

func TestCriticalDataIntegrity(t *testing.T) {
	// Scenario: Routing node intercepts message and modifies Data

	router := NewMockRouter()

	alice, _ := NewSecret()
	bob, _ := NewSecret()

	router.AddPartyWithSecret(alice)
	router.AddPartyWithSecret(bob)

	ids := []Identity{alice.Identity, bob.Identity}
	cid, _ := router.StartKeygen(ids, 1)

	// Drain setup
	for _, id := range ids {
		<-router.parties[id].inbox
	}

	// Alice sends valid message
	originalData := []byte("honest-round1-data")
	hash := HashTSSMessage(cid, originalData)
	sig := alice.Sign(hash)

	// ATTACK: Router modifies the data in transit
	tamperedData := []byte("evil-modified-data")

	tamperedMsg := TSSMessage{
		CeremonyID: cid,
		Type:       CeremonyKeygen,
		From:       alice.Identity,
		Broadcast:  true,
		Data:       tamperedData, // Modified!
		Signature:  sig,          // Original signature
	}

	err := router.RouteTSSMessage(tamperedMsg)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: Tampered message accepted!")
	}

	t.Logf("Data tampering blocked: %v ✓", err)
}

func TestIdentityDerivation(t *testing.T) {
	// Verify that Identity is correctly derived from pubkey
	// This is the foundation of the signature verification

	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Identity should be ripemd160 of compressed pubkey
	pubkey := secret.privateKey.PubKey()
	expectedID := NewIdentityFromPub(pubkey)

	if secret.Identity != expectedID {
		t.Fatal("Identity mismatch from pubkey derivation")
	}

	// Sign something and verify we can recover the identity
	data := []byte("test data")
	hash := sha256.Sum256(data)
	sig := secret.Sign(hash[:])

	recoveredPub, err := Verify(hash[:], secret.Identity, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	recoveredID := NewIdentityFromPub(recoveredPub)
	if recoveredID != secret.Identity {
		t.Fatal("Recovered identity doesn't match")
	}

	t.Log("Identity derivation and verification works ✓")
}
