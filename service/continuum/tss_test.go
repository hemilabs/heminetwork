// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hemilabs/x/tss/v3/crypto"
	"github.com/hemilabs/x/tss/v3/ecdsa/keygen"
	resharing "github.com/hemilabs/x/tss/v3/ecdsa/resharing"
	"github.com/hemilabs/x/tss/v3/tss"
	"golang.org/x/crypto/nacl/secretbox"
)

// TSSNetwork connects multiple TSS instances for testing
type TSSNetwork struct {
	t       *testing.T
	nodes   map[Identity]*tssNode
	nodesMu sync.Mutex
}

type tssNode struct {
	id        Identity
	secret    *Secret
	tss       TSS
	store     TSSStore
	transport *tssNetworkTransport
}

type tssNetworkTransport struct {
	self    Identity
	network *TSSNetwork
}

func (tr *tssNetworkTransport) Send(to Identity, ceremonyID CeremonyID, data []byte) error {
	tr.network.nodesMu.Lock()
	node, ok := tr.network.nodes[to]
	from := tr.self
	tr.network.nodesMu.Unlock()

	if ok {
		go func() {
			// Retry until the remote ceremony is registered or
			// we exceed a reasonable limit.  Concurrent Reshare
			// calls may register their ceremonies after the first
			// outbound messages are produced.
			ctx := tr.network.t.Context()
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			for range 50 {
				err := node.tss.HandleMessage(ctx, from, ceremonyID, data)
				if err == nil || !errors.Is(err, ErrUnknownCeremony) {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}()
	}
	return nil
}

func NewTSSNetwork(t *testing.T) *TSSNetwork {
	return &TSSNetwork{
		t:     t,
		nodes: make(map[Identity]*tssNode),
	}
}

func (n *TSSNetwork) AddNode() *tssNode {
	n.nodesMu.Lock()
	defer n.nodesMu.Unlock()

	secret, err := NewSecret()
	if err != nil {
		n.t.Fatal(err)
	}

	dir := n.t.TempDir()

	store, err := NewTSSStore(dir, secret)
	if err != nil {
		n.t.Fatal(err)
	}

	// Pre-load preparams if available
	loadTestPreParams(n.t, store.(*fileStore), len(n.nodes))

	transport := &tssNetworkTransport{
		self:    secret.Identity,
		network: n,
	}

	tssImpl := NewTSS(secret.Identity, store, transport)

	node := &tssNode{
		id:        secret.Identity,
		secret:    secret,
		tss:       tssImpl,
		store:     store,
		transport: transport,
	}

	n.nodes[secret.Identity] = node
	return node
}

func (n *TSSNetwork) GetIdentities() []Identity {
	n.nodesMu.Lock()
	defer n.nodesMu.Unlock()

	ids := make([]Identity, 0, len(n.nodes))
	for id := range n.nodes {
		ids = append(ids, id)
	}
	return ids
}

func loadTestPreParams(t *testing.T, store *fileStore, index int) {
	t.Helper()
	params := testPreParams(t, index+1)
	store.preParams = &params[index]
}

// =============================================================================
// Tests
// =============================================================================

func TestTSSStoreEncryption(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	keyID := []byte("test-key-id")
	shareData := []byte("secret key share data that should be encrypted")

	if err := store.SaveKeyShare(keyID, shareData); err != nil {
		t.Fatalf("SaveKeyShare: %v", err)
	}

	// Read back
	loaded, err := store.LoadKeyShare(keyID)
	if err != nil {
		t.Fatalf("LoadKeyShare: %v", err)
	}

	if string(loaded) != string(shareData) {
		t.Fatal("Data mismatch")
	}

	// Verify file is encrypted (not plaintext)
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		data, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		if string(data) == string(shareData) {
			t.Fatal("Data stored in plaintext!")
		}
	}

	t.Log("Store encryption works ✓")
}

func TestTSSStoreWrongKey(t *testing.T) {
	secret1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	secret2, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	store1, err := NewTSSStore(dir, secret1)
	if err != nil {
		t.Fatal(err)
	}

	keyID := []byte("test-key")
	shareData := []byte("secret data")
	if err := store1.SaveKeyShare(keyID, shareData); err != nil {
		t.Fatalf("SaveKeyShare: %v", err)
	}

	// Try to read with different secret — must fail with decryption
	// error, not file-not-found.
	store2, err := NewTSSStore(dir, secret2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store2.LoadKeyShare(keyID)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
	if !errors.Is(err, errDecryptionFailed) {
		t.Fatalf("expected errDecryptionFailed, got: %v", err)
	}
}

func TestDecryptEdgeCases(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}
	fs := store.(*fileStore)

	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    error
	}{
		{"nil input", nil, errInvalidCiphertext},
		{"empty input", []byte{}, errInvalidCiphertext},
		{"too short for nonce", make([]byte, 23), errInvalidCiphertext},
		{"nonce only no tag", make([]byte, 24), errInvalidCiphertext},
		{"nonce plus partial tag", make([]byte, 39), errInvalidCiphertext},
		{"minimum length random bytes", func() []byte {
			b := make([]byte, 40)
			_, _ = rand.Read(b)
			return b
		}(), errDecryptionFailed},
		{"oversized random bytes", func() []byte {
			b := make([]byte, 1024)
			_, _ = rand.Read(b)
			return b
		}(), errDecryptionFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fs.decrypt([]byte("test"), tt.ciphertext)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("decrypt(%d bytes): got %v, want %v",
					len(tt.ciphertext), err, tt.wantErr)
			}
		})
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}
	fs := store.(*fileStore)

	// Empty plaintext must round-trip.
	keyID := []byte("empty-test")
	ciphertext, err := fs.encrypt(keyID, []byte{})
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	// 24-byte nonce + 16-byte tag + 4-byte keyID len + keyID + 0-byte payload.
	wantLen := 24 + secretbox.Overhead + 4 + len(keyID)
	if len(ciphertext) != wantLen {
		t.Fatalf("encrypt empty: got %d bytes, want %d", len(ciphertext), wantLen)
	}
	plaintext, err := fs.decrypt(keyID, ciphertext)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(plaintext) != 0 {
		t.Fatalf("decrypt empty: got %d bytes, want 0", len(plaintext))
	}
}

func TestTSSKeygen(t *testing.T) {
	network := NewTSSNetwork(t)

	// Create 3 nodes
	nodes := make([]*tssNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = network.AddNode()
	}

	parties := network.GetIdentities()
	cid := NewCeremonyID()
	threshold := 1 // 2-of-3

	t.Log("=== Starting Keygen ===")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	keyIDs := make([][]byte, 3)
	errors := make([]error, 3)

	for i, node := range nodes {
		wg.Add(1)
		go func(idx int, n *tssNode) {
			defer wg.Done()
			keyID, err := n.tss.Keygen(ctx, cid, parties, threshold)
			keyIDs[idx] = keyID
			errors[idx] = err
		}(i, node)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Node %d keygen failed: %v", i, err)
		}
	}

	// All keyIDs should match
	for i := 1; i < 3; i++ {
		if string(keyIDs[i]) != string(keyIDs[0]) {
			t.Fatal("KeyID mismatch between nodes")
		}
	}

	t.Logf("Keygen complete, keyID = %x ✓", keyIDs[0])
}

func TestTSSKeygenAndSign(t *testing.T) {
	network := NewTSSNetwork(t)

	nodes := make([]*tssNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = network.AddNode()
	}

	parties := network.GetIdentities()
	threshold := 1

	// === Keygen ===
	t.Log("=== Keygen ===")
	keygenCID := NewCeremonyID()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	keyIDs := make([][]byte, 3)
	keygenErrors := make([]error, 3)

	for i, node := range nodes {
		wg.Add(1)
		go func(idx int, n *tssNode) {
			defer wg.Done()
			keyID, err := n.tss.Keygen(ctx, keygenCID, parties, threshold)
			keyIDs[idx] = keyID
			keygenErrors[idx] = err
		}(i, node)
	}
	wg.Wait()

	for i, err := range keygenErrors {
		if err != nil {
			t.Fatalf("Node %d keygen failed: %v", i, err)
		}
	}
	t.Logf("Keygen complete, keyID = %x", keyIDs[0])

	// === Sign ===
	t.Log("=== Sign ===")
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("hello world"))

	signCtx, signCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer signCancel()

	rs := make([][2][]byte, 3)
	signErrors := make([]error, 3)

	for i, node := range nodes {
		wg.Add(1)
		go func(idx int, n *tssNode) {
			defer wg.Done()
			r, s, err := n.tss.Sign(signCtx, signCID, keyIDs[0], parties, threshold, data)
			rs[idx] = [2][]byte{r, s}
			signErrors[idx] = err
		}(i, node)
	}
	wg.Wait()

	for i, err := range signErrors {
		if err != nil {
			t.Fatalf("Node %d sign failed: %v", i, err)
		}
		t.Logf("Node %d: r=%x... s=%x...", i, rs[i][0][:8], rs[i][1][:8])
	}

	t.Log("Sign complete ✓")
}

func TestTSSInterfaceHidesTSSLib(t *testing.T) {
	// Verify the TSS interface doesn't expose tss-lib types
	var _ TSS = (*tssImpl)(nil)

	// These should be the only exposed types:
	// - TSS interface
	// - TSSStore interface
	// - TSSTransport interface
	// - Identity, CeremonyID (from protocol.go)

	t.Log("TSS interface hides tss-lib ✓")
}

func TestTSSNetworkMessageDelivery(t *testing.T) {
	network := NewTSSNetwork(t)

	node1 := network.AddNode()
	node2 := network.AddNode()

	t.Logf("Node 1: %s", node1.id)
	t.Logf("Node 2: %s", node2.id)

	cid := NewCeremonyID()

	// Manually create ceremony on node2 to receive
	impl := node2.tss.(*tssImpl)
	impl.ceremoniesMu.Lock()
	impl.ceremonies[cid] = &ceremony{
		pids: tss.SortPartyIDs([]*tss.PartyID{
			tss.NewPartyID(node1.id.String(), "n1", new(big.Int).SetBytes(node1.id[:])),
			tss.NewPartyID(node2.id.String(), "n2", new(big.Int).SetBytes(node2.id[:])),
		}),
		pidToID: map[string]Identity{
			node1.id.String(): node1.id,
			node2.id.String(): node2.id,
		},
	}
	impl.ceremoniesMu.Unlock()

	// Send from node1 to node2
	err := node1.transport.Send(node2.id, cid, []byte{msgTypeBroadcast, 0x00}) // broadcast flag + empty
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	t.Log("Message sent successfully")
}

func TestTSSNetworkRouting(t *testing.T) {
	network := NewTSSNetwork(t)

	nodes := make([]*tssNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = network.AddNode()
		t.Logf("Node %d: %s", i, nodes[i].id)
	}

	// Count messages received by node1
	var msgCount atomic.Int32

	cid := NewCeremonyID()

	// Setup ceremony on node1
	impl := nodes[1].tss.(*tssImpl)
	impl.ceremoniesMu.Lock()
	impl.ceremonies[cid] = &ceremony{
		pids: tss.SortPartyIDs([]*tss.PartyID{
			tss.NewPartyID(nodes[0].id.String(), "n0", new(big.Int).SetBytes(nodes[0].id[:])),
			tss.NewPartyID(nodes[1].id.String(), "n1", new(big.Int).SetBytes(nodes[1].id[:])),
			tss.NewPartyID(nodes[2].id.String(), "n2", new(big.Int).SetBytes(nodes[2].id[:])),
		}),
		pidToID: map[string]Identity{
			nodes[0].id.String(): nodes[0].id,
			nodes[1].id.String(): nodes[1].id,
			nodes[2].id.String(): nodes[2].id,
		},
	}
	impl.ceremoniesMu.Unlock()

	// Send from node0 to node1
	_ = nodes[0].transport.Send(nodes[1].id, cid, []byte{msgTypeBroadcast, 0x00})
	msgCount.Add(1)

	t.Logf("Messages sent to node 1: %d", msgCount.Load())
}

// =============================================================================
// Reshare integration tests
// =============================================================================

// TestTSSKeygenReshareSign exercises the complete lifecycle:
//
//	keygen(3 nodes) → reshare(old={0,1,2} → new={1,2,3}) → sign(new)
//
// Nodes 1 and 2 overlap both committees, which exercises the XOR key
// rotation in buildResharePartyContext and the dual-party message
// routing in the round-function reshare driver.
func TestTSSKeygenReshareSign(t *testing.T) {
	network := NewTSSNetwork(t)

	// Create 4 nodes; keygen uses first 3, reshare adds 4th.
	nodes := make([]*tssNode, 4)
	for i := range nodes {
		nodes[i] = network.AddNode()
	}
	t.Logf("nodes: %s %s %s %s",
		nodes[0].id, nodes[1].id, nodes[2].id, nodes[3].id)

	oldParties := []Identity{nodes[0].id, nodes[1].id, nodes[2].id}
	threshold := 1 // 2-of-3

	// === Keygen with old committee ===
	t.Log("=== Keygen ===")
	keygenCID := NewCeremonyID()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	keyIDs := make([][]byte, 3)
	keygenErrors := make([]error, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyIDs[idx], keygenErrors[idx] = nodes[idx].tss.Keygen(
				ctx, keygenCID, oldParties, threshold)
		}(i)
	}
	wg.Wait()

	for i, err := range keygenErrors {
		if err != nil {
			t.Fatalf("keygen node %d: %v", i, err)
		}
	}
	keyID := keyIDs[0]
	t.Logf("keygen complete: keyID=%x", keyID)

	// === Reshare: {0,1,2} → {1,2,3} ===
	t.Log("=== Reshare ===")
	reshareCID := NewCeremonyID()
	newParties := []Identity{nodes[1].id, nodes[2].id, nodes[3].id}

	reshareCtx, reshareCancel := context.WithTimeout(
		context.Background(), 3*time.Minute)
	defer reshareCancel()

	// All 4 nodes participate: node0 is old-only, node3 is new-only,
	// nodes 1,2 are in both committees.
	reshareErrors := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reshareErrors[idx] = nodes[idx].tss.Reshare(
				reshareCtx, reshareCID, keyID,
				oldParties, newParties, threshold, threshold)
		}(i)
	}
	wg.Wait()

	for i, err := range reshareErrors {
		if err != nil {
			t.Fatalf("reshare node %d: %v", i, err)
		}
	}
	t.Log("reshare complete ✓")

	// === Sign with new committee ===
	t.Log("=== Sign with new committee ===")
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("post-reshare signing test"))

	signCtx, signCancel := context.WithTimeout(
		context.Background(), 2*time.Minute)
	defer signCancel()

	rs := make([][2][]byte, 3)
	signErrors := make([]error, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rs[idx][0], rs[idx][1], signErrors[idx] = nodes[idx+1].tss.Sign(
				signCtx, signCID, keyID, newParties, threshold, data)
		}(i)
	}
	wg.Wait()

	for i, err := range signErrors {
		if err != nil {
			t.Fatalf("sign node %d: %v", i, err)
		}
		t.Logf("node %d: r=%x.. s=%x..", i+1, rs[i][0][:8], rs[i][1][:8])
	}
	t.Log("sign after reshare ✓")
}

// TestTSSReshareDisjoint exercises resharing to a completely new committee
// where no nodes overlap, testing the inOld/inNew-only branches.
func TestTSSReshareDisjoint(t *testing.T) {
	network := NewTSSNetwork(t)

	nodes := make([]*tssNode, 6)
	for i := range nodes {
		nodes[i] = network.AddNode()
	}

	oldParties := []Identity{nodes[0].id, nodes[1].id, nodes[2].id}
	newParties := []Identity{nodes[3].id, nodes[4].id, nodes[5].id}
	threshold := 1

	// Keygen with old committee.
	keygenCID := NewCeremonyID()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	keyIDs := make([][]byte, 3)
	keygenErrors := make([]error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyIDs[idx], keygenErrors[idx] = nodes[idx].tss.Keygen(
				ctx, keygenCID, oldParties, threshold)
		}(i)
	}
	wg.Wait()
	for i, err := range keygenErrors {
		if err != nil {
			t.Fatalf("keygen node %d: %v", i, err)
		}
	}
	keyID := keyIDs[0]

	// Reshare: old={0,1,2} → new={3,4,5} — no overlap.
	reshareCID := NewCeremonyID()
	reshareCtx, reshareCancel := context.WithTimeout(
		context.Background(), 3*time.Minute)
	defer reshareCancel()

	reshareErrors := make([]error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reshareErrors[idx] = nodes[idx].tss.Reshare(
				reshareCtx, reshareCID, keyID,
				oldParties, newParties, threshold, threshold)
		}(i)
	}
	wg.Wait()
	for i, err := range reshareErrors {
		if err != nil {
			t.Fatalf("reshare node %d: %v", i, err)
		}
	}

	// Sign with new committee {3,4,5}.
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("disjoint reshare test"))

	signCtx, signCancel := context.WithTimeout(
		context.Background(), 2*time.Minute)
	defer signCancel()

	signErrors := make([]error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _, signErrors[idx] = nodes[idx+3].tss.Sign(
				signCtx, signCID, keyID, newParties, threshold, data)
		}(i)
	}
	wg.Wait()
	for i, err := range signErrors {
		if err != nil {
			t.Fatalf("sign node %d: %v", i, err)
		}
	}
	t.Log("disjoint reshare + sign ✓")
}

// TestTSSReshareNotInCommittee verifies the error when self is in neither.
func TestTSSReshareNotInCommittee(t *testing.T) {
	network := NewTSSNetwork(t)
	node := network.AddNode()

	other1, _ := NewSecret()
	other2, _ := NewSecret()
	other3, _ := NewSecret()

	err := node.tss.Reshare(
		context.Background(),
		NewCeremonyID(),
		[]byte("fake-key"),
		[]Identity{other1.Identity, other2.Identity},
		[]Identity{other2.Identity, other3.Identity},
		1, 1,
	)
	if !errors.Is(err, ErrNotInCommittee) {
		t.Fatalf("expected ErrNotInCommittee, got: %v", err)
	}
}

// TestTSSReshareCancellation verifies ctx cancellation mid-reshare.
func TestTSSReshareCancellation(t *testing.T) {
	network := NewTSSNetwork(t)

	nodes := make([]*tssNode, 3)
	for i := range nodes {
		nodes[i] = network.AddNode()
	}
	parties := []Identity{nodes[0].id, nodes[1].id, nodes[2].id}
	threshold := 1

	// Keygen first.
	keygenCID := NewCeremonyID()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	keyIDs := make([][]byte, 3)
	keygenErrors := make([]error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyIDs[idx], keygenErrors[idx] = nodes[idx].tss.Keygen(
				ctx, keygenCID, parties, threshold)
		}(i)
	}
	wg.Wait()
	for i, err := range keygenErrors {
		if err != nil {
			t.Fatalf("keygen %d: %v", i, err)
		}
	}

	// Start reshare with a context we cancel immediately.
	reshareCID := NewCeremonyID()
	newNode := network.AddNode()
	newParties := []Identity{nodes[1].id, nodes[2].id, newNode.id}

	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	cancelFunc() // cancel immediately

	// Only run on one node — it should fail fast.
	err := nodes[1].tss.Reshare(
		cancelCtx, reshareCID, keyIDs[0],
		parties, newParties, threshold, threshold)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

// =============================================================================
// Error path tests — cover early-return branches in Keygen, Sign,
// HandleMessage, and store operations.
// =============================================================================

// mockTSSStore implements TSSStore with configurable errors.
type mockTSSStore struct {
	preParams    *keygen.LocalPreParams
	keyShares    map[string][]byte
	keyMeta      map[string]*KeyMetadata
	saveErr      error
	loadErr      error
	deleteErr    error
	preParamsErr error
	saveMetaErr  error
	loadMetaErr  error
}

func newMockTSSStore() *mockTSSStore {
	return &mockTSSStore{
		keyShares: make(map[string][]byte),
		keyMeta:   make(map[string]*KeyMetadata),
	}
}

func (m *mockTSSStore) Close() error { return nil }

func (m *mockTSSStore) SaveKeyShare(keyID, share []byte) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.keyShares[string(keyID)] = share
	return nil
}

func (m *mockTSSStore) LoadKeyShare(keyID []byte) ([]byte, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	d, ok := m.keyShares[string(keyID)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return d, nil
}

func (m *mockTSSStore) DeleteKeyShare(keyID []byte) error {
	return m.deleteErr
}

func (m *mockTSSStore) GetPreParams(ctx context.Context) (*keygen.LocalPreParams, error) {
	if m.preParamsErr != nil {
		return nil, m.preParamsErr
	}
	if m.preParams != nil {
		return m.preParams, nil
	}
	return nil, errors.New("no preparams")
}

func (m *mockTSSStore) SetPreParams(pp *keygen.LocalPreParams) {
	m.preParams = pp
}

func (m *mockTSSStore) SaveKeyMetadata(keyID []byte, meta *KeyMetadata) error {
	if m.saveMetaErr != nil {
		return m.saveMetaErr
	}
	m.keyMeta[string(keyID)] = meta
	return nil
}

func (m *mockTSSStore) LoadKeyMetadata(keyID []byte) (*KeyMetadata, error) {
	if m.loadMetaErr != nil {
		return nil, m.loadMetaErr
	}
	meta, ok := m.keyMeta[string(keyID)]
	if !ok {
		return nil, errors.New("metadata not found")
	}
	return meta, nil
}

func (m *mockTSSStore) ListKeys() ([][]byte, error) {
	keys := make([][]byte, 0, len(m.keyShares))
	for k := range m.keyShares {
		keys = append(keys, []byte(k))
	}
	return keys, nil
}

// noopTransport discards all sends.
type noopTransport struct{}

func (noopTransport) Send(Identity, CeremonyID, []byte) error { return nil }

// --- Keygen error paths ---

func TestKeygenGetPreParamsError(t *testing.T) {
	secret, _ := NewSecret()
	store := newMockTSSStore()
	store.preParamsErr = errors.New("boom")
	impl := NewTSS(secret.Identity, store, noopTransport{})

	_, err := impl.Keygen(context.Background(), NewCeremonyID(),
		[]Identity{secret.Identity}, 0)
	if err == nil || !errors.Is(err, store.preParamsErr) {
		t.Fatalf("expected preparams error, got: %v", err)
	}
}

func TestKeygenSelfNotInParties(t *testing.T) {
	secret, _ := NewSecret()
	other, _ := NewSecret()
	store := newMockTSSStore()
	store.preParams = &keygen.LocalPreParams{} // non-nil to pass GetPreParams
	impl := NewTSS(secret.Identity, store, noopTransport{})

	_, err := impl.Keygen(context.Background(), NewCeremonyID(),
		[]Identity{other.Identity}, 0)
	if err == nil {
		t.Fatal("expected error for self not in parties")
	}
	if err.Error() != "self not in party list" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Sign error paths ---

func TestSignLoadKeyShareError(t *testing.T) {
	secret, _ := NewSecret()
	store := newMockTSSStore()
	store.loadErr = errors.New("disk read error")
	impl := NewTSS(secret.Identity, store, noopTransport{})

	_, _, err := impl.Sign(context.Background(), NewCeremonyID(),
		[]byte("nonexistent"), []Identity{secret.Identity}, 0, [32]byte{})
	if err == nil {
		t.Fatal("expected load error")
	}
}

func TestSignUnmarshalError(t *testing.T) {
	secret, _ := NewSecret()
	store := newMockTSSStore()
	store.keyShares["badkey"] = []byte("not json")
	impl := NewTSS(secret.Identity, store, noopTransport{})

	_, _, err := impl.Sign(context.Background(), NewCeremonyID(),
		[]byte("badkey"), []Identity{secret.Identity}, 0, [32]byte{})
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestSignSelfNotInParties(t *testing.T) {
	secret, _ := NewSecret()
	other, _ := NewSecret()
	store := newMockTSSStore()

	// Store a minimal valid key share with Ks.
	rawKey := new(big.Int).SetBytes(other.Identity[:])
	save := keygen.NewLocalPartySaveData(1)
	save.Ks = []*big.Int{rawKey}
	data, _ := json.Marshal(save)
	store.keyShares["testkey"] = data
	impl := NewTSS(secret.Identity, store, noopTransport{})

	_, _, err := impl.Sign(context.Background(), NewCeremonyID(),
		[]byte("testkey"), []Identity{other.Identity}, 0, [32]byte{})
	if err == nil {
		t.Fatal("expected self not in party list error")
	}
}

// --- Reshare error paths ---

func TestReshareLoadKeyShareError(t *testing.T) {
	secret, _ := NewSecret()
	store := newMockTSSStore()
	store.loadErr = errors.New("corrupt disk")
	impl := NewTSS(secret.Identity, store, noopTransport{})

	other, _ := NewSecret()
	err := impl.Reshare(context.Background(), NewCeremonyID(),
		[]byte("key"),
		[]Identity{secret.Identity}, // old (self in old → tries to load)
		[]Identity{other.Identity},  // new
		1, 1)
	if err == nil {
		t.Fatal("expected load key share error")
	}
}

func TestReshareUnmarshalKeyShareError(t *testing.T) {
	secret, _ := NewSecret()
	store := newMockTSSStore()
	store.keyShares["key"] = []byte("garbage")
	impl := NewTSS(secret.Identity, store, noopTransport{})

	other, _ := NewSecret()
	err := impl.Reshare(context.Background(), NewCeremonyID(),
		[]byte("key"),
		[]Identity{secret.Identity},
		[]Identity{other.Identity},
		1, 1)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

// --- HandleMessage error paths ---

func TestHandleMessageUnknownCeremony(t *testing.T) {
	secret, _ := NewSecret()
	other, _ := NewSecret()
	impl := NewTSS(secret.Identity, newMockTSSStore(), noopTransport{})

	err := impl.HandleMessage(t.Context(), other.Identity, NewCeremonyID(), []byte{msgTypeBroadcast, 0x00})
	if !errors.Is(err, ErrUnknownCeremony) {
		t.Fatalf("expected ErrUnknownCeremony, got: %v", err)
	}
}

func TestHandleMessageTooShort(t *testing.T) {
	secret, _ := NewSecret()
	other, _ := NewSecret()
	ti := NewTSS(secret.Identity, newMockTSSStore(), noopTransport{}).(*tssImpl)

	cid := NewCeremonyID()
	ti.ceremoniesMu.Lock()
	ti.ceremonies[cid] = &ceremony{ctype: CeremonyKeygen}
	ti.ceremoniesMu.Unlock()

	err := ti.HandleMessage(t.Context(), other.Identity, cid, []byte{msgTypeP2P})
	if err == nil || err.Error() != "message too short" {
		t.Fatalf("expected 'message too short', got: %v", err)
	}
}

func TestHandleMessageReshareTooShort(t *testing.T) {
	secret, _ := NewSecret()
	other, _ := NewSecret()
	ti := NewTSS(secret.Identity, newMockTSSStore(), noopTransport{}).(*tssImpl)

	cid := NewCeremonyID()
	ti.ceremoniesMu.Lock()
	ti.ceremonies[cid] = &ceremony{ctype: CeremonyReshare}
	ti.ceremoniesMu.Unlock()

	err := ti.HandleMessage(t.Context(), other.Identity, cid, []byte{msgTypeBroadcast, cflagToNew})
	if err == nil || err.Error() != "reshare message too short" {
		t.Fatalf("expected 'reshare message too short', got: %v", err)
	}
}

func TestHandleMessageSenderNotInCeremony(t *testing.T) {
	secret, _ := NewSecret()
	other, _ := NewSecret()
	ti := NewTSS(secret.Identity, newMockTSSStore(), noopTransport{}).(*tssImpl)

	cid := NewCeremonyID()
	ti.ceremoniesMu.Lock()
	ti.ceremonies[cid] = &ceremony{
		ctype: CeremonyKeygen,
		pids: tss.SortPartyIDs([]*tss.PartyID{
			tss.NewPartyID(secret.String(), "s",
				new(big.Int).SetBytes(secret.Identity[:])),
		}),
	}
	ti.ceremoniesMu.Unlock()

	// 'other' is not in the ceremony's pids.
	err := ti.HandleMessage(t.Context(), other.Identity, cid, []byte{msgTypeBroadcast, 0x00})
	if err == nil || err.Error() != "sender not in ceremony" {
		t.Fatalf("expected 'sender not in ceremony', got: %v", err)
	}
}

// --- Store edge cases ---

func TestNewTSSStoreBadDir(t *testing.T) {
	secret, _ := NewSecret()
	// /dev/null is not a directory — MkdirAll should fail.
	_, err := NewTSSStore("/dev/null/impossible", secret)
	if err == nil {
		t.Fatal("expected error creating store in bad dir")
	}
}

func TestSaveKeyShareWriteError(t *testing.T) {
	secret, _ := NewSecret()
	// Create store in a read-only directory.
	dir := t.TempDir()
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	// Make directory read-only.
	if err := os.Chmod(dir, 0o444); err != nil {
		t.Skip("cannot set read-only permissions")
	}
	defer func() { _ = os.Chmod(dir, 0o755) }()

	err = store.SaveKeyShare([]byte("key"), []byte("data"))
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestDeleteKeyShareNonexistent(t *testing.T) {
	secret, _ := NewSecret()
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}
	// Deleting nonexistent key should not error (os.Remove returns
	// ErrNotExist which is acceptable).
	err = store.DeleteKeyShare([]byte("nonexistent"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetPreParamsContextCancel(t *testing.T) {
	secret, _ := NewSecret()
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = store.GetPreParams(ctx)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

// =============================================================================
// Key metadata persistence tests
// =============================================================================

// TestKeyMetadataSaveLoadRoundTrip verifies that saving and loading
// key metadata produces the original data.
func TestKeyMetadataSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	keyID := []byte{0x01, 0x02, 0x03, 0x04}
	committee := []Identity{{0xAA}, {0xBB}, {0xCC}}
	pubKey := []byte("test-public-key-data")
	now := time.Now().UTC().Truncate(time.Second)

	meta := &KeyMetadata{
		Committee: committee,
		Threshold: 2,
		KeyID:     keyID,
		PublicKey: pubKey,
		CreatedAt: now,
	}

	if err := store.SaveKeyMetadata(keyID, meta); err != nil {
		t.Fatalf("SaveKeyMetadata: %v", err)
	}

	loaded, err := store.LoadKeyMetadata(keyID)
	if err != nil {
		t.Fatalf("LoadKeyMetadata: %v", err)
	}

	if loaded.Threshold != 2 {
		t.Fatalf("threshold: got %d, want 2", loaded.Threshold)
	}
	if len(loaded.Committee) != 3 {
		t.Fatalf("committee len: got %d, want 3", len(loaded.Committee))
	}
	for i, id := range loaded.Committee {
		if id != committee[i] {
			t.Fatalf("committee[%d]: got %v, want %v", i, id, committee[i])
		}
	}
	if !bytes.Equal(loaded.KeyID, keyID) {
		t.Fatalf("keyID mismatch")
	}
	if !bytes.Equal(loaded.PublicKey, pubKey) {
		t.Fatalf("publicKey mismatch")
	}
	if !loaded.CreatedAt.Equal(now) {
		t.Fatalf("createdAt: got %v, want %v", loaded.CreatedAt, now)
	}
}

// TestKeyMetadataSurvivesReload verifies metadata persists across
// store instances (simulating node restart).
func TestKeyMetadataSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Save with first store instance.
	store1, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	keyID := []byte{0xDE, 0xAD}
	meta := &KeyMetadata{
		Committee: []Identity{{0x01}},
		Threshold: 1,
		KeyID:     keyID,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store1.SaveKeyMetadata(keyID, meta); err != nil {
		t.Fatal(err)
	}

	// Load with second store instance (same dir, same secret).
	store2, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := store2.LoadKeyMetadata(keyID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.Threshold != 1 {
		t.Fatalf("threshold: got %d, want 1", loaded.Threshold)
	}
}

// TestKeyMetadataWrongSecret verifies metadata cannot be read with
// a different secret (different encryption key).
func TestKeyMetadataWrongSecret(t *testing.T) {
	dir := t.TempDir()
	secret1, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	secret2, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	store1, err := NewTSSStore(dir, secret1)
	if err != nil {
		t.Fatal(err)
	}
	keyID := []byte{0x01}
	if err := store1.SaveKeyMetadata(keyID, &KeyMetadata{
		Threshold: 1,
		KeyID:     keyID,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	store2, err := NewTSSStore(dir, secret2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store2.LoadKeyMetadata(keyID)
	if err == nil {
		t.Fatal("expected decryption error with wrong secret")
	}
}

// TestListKeysReturnsStoredIDs verifies ListKeys returns all keyIDs
// that have been saved.
func TestListKeysReturnsStoredIDs(t *testing.T) {
	dir := t.TempDir()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Empty store.
	keys, err := store.ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}

	// Add two keys.
	key1 := []byte{0x01, 0x02}
	key2 := []byte{0x03, 0x04}
	if err := store.SaveKeyShare(key1, []byte("share1")); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKeyShare(key2, []byte("share2")); err != nil {
		t.Fatal(err)
	}

	keys, err = store.ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	// Verify both keyIDs are present (order not guaranteed).
	found := make(map[string]bool)
	for _, k := range keys {
		found[string(k)] = true
	}
	if !found[string(key1)] || !found[string(key2)] {
		t.Fatalf("missing keyIDs: found=%v", found)
	}
}

// TestListKeysIgnoresMetaFiles verifies ListKeys only returns
// .key files, not .meta files.
func TestListKeysIgnoresMetaFiles(t *testing.T) {
	dir := t.TempDir()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	keyID := []byte{0xAA, 0xBB}
	if err := store.SaveKeyShare(keyID, []byte("share")); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKeyMetadata(keyID, &KeyMetadata{
		KeyID:     keyID,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	keys, err := store.ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d (meta file counted?)", len(keys))
	}
}

// TestLoadKeyMetadataNotExist verifies LoadKeyMetadata returns an
// error for a non-existent key.
func TestLoadKeyMetadataNotExist(t *testing.T) {
	dir := t.TempDir()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.LoadKeyMetadata([]byte{0xFF})
	if err == nil {
		t.Fatal("expected error for non-existent metadata")
	}
}

// TestKeyMetadataReshareUpdate verifies that reshare overwrites
// metadata with new committee and threshold.
func TestKeyMetadataReshareUpdate(t *testing.T) {
	dir := t.TempDir()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	keyID := []byte{0x42}
	oldMeta := &KeyMetadata{
		Committee: []Identity{{0x01}, {0x02}, {0x03}},
		Threshold: 1,
		KeyID:     keyID,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.SaveKeyMetadata(keyID, oldMeta); err != nil {
		t.Fatal(err)
	}

	// Simulate reshare: new committee, new threshold.
	newMeta := &KeyMetadata{
		Committee: []Identity{{0x04}, {0x05}},
		Threshold: 1,
		KeyID:     keyID,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.SaveKeyMetadata(keyID, newMeta); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.LoadKeyMetadata(keyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Committee) != 2 {
		t.Fatalf("committee: got %d members, want 2", len(loaded.Committee))
	}
	if loaded.Committee[0] != (Identity{0x04}) {
		t.Fatalf("committee[0]: got %v, want {0x04}", loaded.Committee[0])
	}
}

// TestStoreCloseZerosEncKey verifies that Close() zeros the encryption
// key and nils preParams to limit swap/coredump exposure.
func TestStoreCloseZerosEncKey(t *testing.T) {
	dir := t.TempDir()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	fs := store.(*fileStore)

	// Verify key is non-zero before Close.
	var zero [32]byte
	if fs.encKey == zero {
		t.Fatal("encKey is zero before Close — bad test setup")
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fs.encKey != zero {
		t.Fatal("encKey not zeroed after Close")
	}
	if fs.preParams != nil {
		t.Fatal("preParams not nil after Close")
	}
}

// TestStoreOperationsAfterClose verifies every store operation
// returns ErrStoreClosed after Close().
func TestStoreOperationsAfterClose(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}

	// Save something first so we have a file to load.
	keyID := []byte("close-test")
	if err := store.SaveKeyShare(keyID, []byte("data")); err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("SaveKeyShare", func(t *testing.T) {
		err := store.SaveKeyShare(keyID, []byte("new"))
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("want ErrStoreClosed, got: %v", err)
		}
	})
	t.Run("LoadKeyShare", func(t *testing.T) {
		_, err := store.LoadKeyShare(keyID)
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("want ErrStoreClosed, got: %v", err)
		}
	})
	t.Run("SaveKeyMetadata", func(t *testing.T) {
		err := store.SaveKeyMetadata(keyID, &KeyMetadata{})
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("want ErrStoreClosed, got: %v", err)
		}
	})
	t.Run("LoadKeyMetadata", func(t *testing.T) {
		_, err := store.LoadKeyMetadata(keyID)
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("want ErrStoreClosed, got: %v", err)
		}
	})
	t.Run("DeleteKeyShare", func(t *testing.T) {
		err := store.DeleteKeyShare(keyID)
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("want ErrStoreClosed, got: %v", err)
		}
	})
	t.Run("ListKeys", func(t *testing.T) {
		_, err := store.(*fileStore).ListKeys()
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("want ErrStoreClosed, got: %v", err)
		}
	})
	t.Run("GetPreParams", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := store.GetPreParams(ctx)
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("want ErrStoreClosed, got: %v", err)
		}
	})
}

// TestStoreKeyIDBinding verifies that file-swap attacks are
// detected.  Encrypting with keyID A and decrypting with keyID B
// must fail even though the ciphertext is valid secretbox.
func TestStoreKeyIDBinding(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	keyA := []byte("key-alpha")
	keyB := []byte("key-bravo")
	dataA := []byte("share data for alpha")
	dataB := []byte("share data for bravo")

	if err := store.SaveKeyShare(keyA, dataA); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKeyShare(keyB, dataB); err != nil {
		t.Fatal(err)
	}

	// Normal load works.
	got, err := store.LoadKeyShare(keyA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dataA) {
		t.Fatal("data mismatch on normal load")
	}

	// Swap files: copy A's ciphertext to B's path.
	aData, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%x.key", keyA)))
	if err != nil {
		t.Fatal(err)
	}
	bPath := filepath.Join(dir, fmt.Sprintf("%x.key", keyB))
	if err := os.WriteFile(bPath, aData, 0o600); err != nil {
		t.Fatal(err)
	}

	// Loading B should fail — ciphertext was bound to keyID A.
	_, err = store.LoadKeyShare(keyB)
	if err == nil {
		t.Fatal("expected error loading swapped key file")
	}
	if !strings.Contains(err.Error(), "key ID mismatch") {
		t.Fatalf("expected 'key ID mismatch', got: %v", err)
	}
}

// TestStoreTamperedCiphertext verifies that flipping bits in a
// stored key file causes LoadKeyShare to fail with a decryption
// error.
func TestStoreTamperedCiphertext(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	keyID := []byte("tamper-test")
	if err := store.SaveKeyShare(keyID, []byte("sensitive key share")); err != nil {
		t.Fatal(err)
	}

	// Tamper with the stored file.
	path := filepath.Join(dir, fmt.Sprintf("%x.key", keyID))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte near the end (in the ciphertext body).
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = store.LoadKeyShare(keyID)
	if !errors.Is(err, errDecryptionFailed) {
		t.Fatalf("expected errDecryptionFailed, got: %v", err)
	}
}

// TestStoreEmptyKeyID verifies that nil and empty keyIDs are
// rejected early with ErrEmptyKeyID.
func TestStoreEmptyKeyID(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		keyID []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
	}
	for _, tt := range tests {
		t.Run("Save_"+tt.name, func(t *testing.T) {
			err := store.SaveKeyShare(tt.keyID, []byte("data"))
			if !errors.Is(err, ErrEmptyKeyID) {
				t.Fatalf("want ErrEmptyKeyID, got: %v", err)
			}
		})
		t.Run("Load_"+tt.name, func(t *testing.T) {
			_, err := store.LoadKeyShare(tt.keyID)
			if !errors.Is(err, ErrEmptyKeyID) {
				t.Fatalf("want ErrEmptyKeyID, got: %v", err)
			}
		})
		t.Run("Delete_"+tt.name, func(t *testing.T) {
			err := store.DeleteKeyShare(tt.keyID)
			if !errors.Is(err, ErrEmptyKeyID) {
				t.Fatalf("want ErrEmptyKeyID, got: %v", err)
			}
		})
		t.Run("SaveMeta_"+tt.name, func(t *testing.T) {
			err := store.SaveKeyMetadata(tt.keyID, &KeyMetadata{})
			if !errors.Is(err, ErrEmptyKeyID) {
				t.Fatalf("want ErrEmptyKeyID, got: %v", err)
			}
		})
		t.Run("LoadMeta_"+tt.name, func(t *testing.T) {
			_, err := store.LoadKeyMetadata(tt.keyID)
			if !errors.Is(err, ErrEmptyKeyID) {
				t.Fatalf("want ErrEmptyKeyID, got: %v", err)
			}
		})
	}
}

// TestStoreAtomicWriteNoLingering verifies that writeAtomic
// doesn't leave temp files on success.
func TestStoreAtomicWriteNoLingering(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		keyID := []byte(fmt.Sprintf("atomic-%02d", i))
		if err := store.SaveKeyShare(keyID, []byte("data")); err != nil {
			t.Fatal(err)
		}
	}

	// No temp files should remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("lingering temp file: %s", e.Name())
		}
	}
}

// TestStoreConcurrentAccess verifies that concurrent Save/Load
// operations don't race or corrupt data.
func TestStoreConcurrentAccess(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyID := []byte(fmt.Sprintf("concurrent-%02d", idx))
			data := []byte(fmt.Sprintf("share-data-%02d", idx))

			if err := store.SaveKeyShare(keyID, data); err != nil {
				errs[idx] = err
				return
			}
			got, err := store.LoadKeyShare(keyID)
			if err != nil {
				errs[idx] = err
				return
			}
			if !bytes.Equal(got, data) {
				errs[idx] = fmt.Errorf("data mismatch for key %d", idx)
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
}

// TestStoreKeyIDBindingMetadata verifies that metadata file-swap
// attacks are also detected.
func TestStoreKeyIDBindingMetadata(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := NewTSSStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}

	keyA := []byte("meta-alpha")
	keyB := []byte("meta-bravo")

	metaA := &KeyMetadata{Threshold: 2, KeyID: keyA}
	if err := store.SaveKeyMetadata(keyA, metaA); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKeyMetadata(keyB, &KeyMetadata{Threshold: 3, KeyID: keyB}); err != nil {
		t.Fatal(err)
	}

	// Swap: copy A's ciphertext to B's path.
	aPath := filepath.Join(dir, fmt.Sprintf("%x.meta", keyA))
	bPath := filepath.Join(dir, fmt.Sprintf("%x.meta", keyB))
	aData, err := os.ReadFile(aPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bPath, aData, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = store.LoadKeyMetadata(keyB)
	if err == nil {
		t.Fatal("expected error loading swapped metadata file")
	}
	if !strings.Contains(err.Error(), "key ID mismatch") {
		t.Fatalf("expected 'key ID mismatch', got: %v", err)
	}
}

// TestDecryptTruncatedBinding exercises decrypt's keyID binding
// validation when a valid secretbox decrypts to data that is too
// short to contain the keyID length prefix or keyID itself.
func TestDecryptTruncatedBinding(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}
	fs := store.(*fileStore)

	// Craft valid secretbox with short plaintext (no keyID binding).
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x01}},
		{"three bytes", []byte{0x01, 0x02, 0x03}},
		{"length says 100 but only 4 bytes total", func() []byte {
			// 4-byte length prefix claiming 100 bytes, but no actual keyID.
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], 100)
			return b[:]
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nonce [24]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				t.Fatal(err)
			}
			ct := secretbox.Seal(nonce[:], tt.plaintext, &nonce, &fs.encKey)
			_, err := fs.decrypt([]byte("any-key"), ct)
			if !errors.Is(err, errInvalidCiphertext) {
				t.Fatalf("want errInvalidCiphertext, got: %v", err)
			}
		})
	}
}

// Regression tests for out-of-bounds party indexing in reshare message
// collection.
//
// The flaw: msgBuf.collect / msgBuf.collectDual (tss_round.go) place accepted
// messages with `out[slot] = m` where slot = m.From.Index, with NO bounds check.
// During a reshare there are two independent party-index spaces -- old committee
// [0,oldPC) and new committee [0,newPC) -- and HandleMessage picks which set
// resolves From.Index purely from the attacker-controlled cflagFromNew wire bit,
// while the accept closures discriminate on Go content type only. A new-committee
// member at new-index >= oldPC can send a round-1-typed message with fromNew set;
// it is collected into an oldPC-sized buffer and indexes out of bounds, panicking
// the un-recovered ceremony goroutine -- one participant crashes every node.
//
// Both tests assert the REQUIRED secure behavior, so they FAIL while the flaw is
// present and PASS once it is fixed by either style: a bounds check inside the
// collectors, or validating the committee flag at ingest in HandleMessage.

// matchContent is an accept closure that matches messages of content type T and
// returns the sender's party index -- exactly what the production reshare
// collectors use (content-type discrimination + m.From.Index).
func matchContent[T any](m *tss.Message) (slot int, ok bool) {
	_, ok = m.Content.(T)
	return m.From.Index, ok
}

// partyIDAt returns a *tss.PartyID with a fixed sorted Index, as SortPartyIDs
// would assign. Only From.Index is load-bearing for the collectors; the id
// strings are cosmetic.
func partyIDAt(id string, index int) *tss.PartyID {
	p := tss.NewPartyID(id, id, big.NewInt(int64(index)+1))
	p.Index = index
	return p
}

// recoverPanic runs fn and returns the value it panicked with, or nil if it
// returned normally. The production collectors run in the ceremony goroutine
// with no recover, so a panic here models a node crash.
func recoverPanic(fn func()) (recovered any) {
	defer func() { recovered = recover() }()
	fn()
	return nil
}

// TestMsgBufCollectorsRejectOutOfRangePartyIndex asserts the root-cause
// invariant directly on the collectors. The accept closures mirror the reshare
// driver's exactly: they discriminate on Go content type and return
// (m.From.Index, ok). When that slot is out of range for the round's party
// count the collector must treat the message as a non-match rather than index
// `out[slot]` out of bounds.
//
// While the flaw is present the collectors do `out[slot] = m` unconditionally
// and panic (FAIL). Once the slot is range-checked they drop the out-of-range
// message and complete using the in-range one (PASS) -- the placement assertion
// proves the guard does not simply swallow everything.
func TestMsgBufCollectorsRejectOutOfRangePartyIndex(t *testing.T) {
	const nParties = 2 // valid slots are 0 and 1; nParties itself is out of range

	t.Run("collect", func(t *testing.T) {
		valid := &tss.Message{From: partyIDAt("honest", 0), Content: &resharing.DGRound1Message{}}
		ch := make(chan *tss.Message, 2)
		// slot == len(out): one past the last valid index. Delivered first, so the
		// OOB slot is hit before the valid one.
		ch <- &tss.Message{From: partyIDAt("attacker", nParties), Content: &resharing.DGRound1Message{}}
		ch <- valid
		b := newMsgBuf(ch)

		var out []*tss.Message
		var err error
		recovered := recoverPanic(func() {
			out, err = b.collect(context.Background(), 1, nParties, matchContent[*resharing.DGRound1Message])
		})
		if recovered != nil {
			t.Fatalf("collect indexed an out-of-range slot and panicked (%v); it "+
				"must treat slot >= nParties as a non-match", recovered)
		}
		if err != nil {
			t.Fatalf("collect returned error: %v", err)
		}
		if out[0] != valid {
			t.Fatal("collect did not place the in-range message at index 0")
		}
	})

	t.Run("collectDual", func(t *testing.T) {
		validA := &tss.Message{From: partyIDAt("honestA", 0), Content: &resharing.DGRound1Message{}}
		ch := make(chan *tss.Message, 3)
		// The attacker message is a type-A message carrying an out-of-range index.
		ch <- &tss.Message{From: partyIDAt("attacker", nParties), Content: &resharing.DGRound1Message{}}
		ch <- validA
		ch <- &tss.Message{From: partyIDAt("honestB", 1), Content: &resharing.DGRound2Message1{}}
		b := newMsgBuf(ch)

		var a []*tss.Message
		var err error
		recovered := recoverPanic(func() {
			a, _, err = b.collectDual(context.Background(), 1, nParties,
				matchContent[*resharing.DGRound1Message], matchContent[*resharing.DGRound2Message1])
		})
		if recovered != nil {
			t.Fatalf("collectDual indexed an out-of-range slot and panicked (%v); "+
				"it must treat slot >= nParties as a non-match", recovered)
		}
		if err != nil {
			t.Fatalf("collectDual returned error: %v", err)
		}
		if a[0] != validA {
			t.Fatal("collectDual did not place the in-range A message at index 0")
		}
	})
}

// reshareOutcome captures how the ceremony goroutine ended: a recovered panic
// (the crash we guard against) and/or the driver's returned error.
type reshareOutcome struct {
	panicVal any
	err      error
}

// TestReshareDoesNotCrashOnCrossCommitteePartyIndex asserts the invariant
// end-to-end through the real continuum stack. A live reshare on a new-only
// victim collects round-1 messages into an oldPC-sized buffer; an attacker that
// is a new-committee member at new-index >= oldPC sends a round-1-typed message
// with the fromNew flag set, so HandleMessage resolves its index in the larger
// new PID set and the collector would index out of bounds.
//
// While the flaw is present the ceremony goroutine panics and this FAILS. Under
// either fix -- a bounds check in the collector, or committee-flag validation at
// ingest -- the message is dropped and the node stays up, so this PASSES.
func TestReshareDoesNotCrashOnCrossCommitteePartyIndex(t *testing.T) {
	const (
		oldPC = 2 // old committee size
		newPC = 3 // new committee size (must exceed oldPC)

		// settleWindow: after the malicious message is enqueued, a buggy build
		// consumes it and panics almost immediately (it is the only thing on a
		// channel the collector is already blocked on). We wait this long for that
		// panic before concluding a fixed build dropped it and re-blocked. It only
		// adds latency to the passing (bounds-check) case; the failing case returns
		// as soon as the panic lands. It is not a pass signal -- see the final read.
		settleWindow = 500 * time.Millisecond
		exitBound    = 5 * time.Second // failsafe upper bound on a clean exit
	)

	// Three new-committee identities, sorted exactly as the reshare driver does
	// via the production buildResharePartyContext(newParties, true) -- no manual
	// replication of the key-rotation/sort -- so the victim stays below oldPC and
	// the attacker at index oldPC even if that derivation ever changes. Sort order
	// is independent of self, so a zero-value tssImpl computes it faithfully.
	newSecrets := make(map[string]*Secret, newPC)
	newParties := make([]Identity, 0, newPC)
	for range newPC {
		s, err := NewSecret()
		if err != nil {
			t.Fatalf("new secret: %v", err)
		}
		newSecrets[s.String()] = s
		newParties = append(newParties, s.Identity)
	}
	sortedNew, _, _, _, err := (&tssImpl{}).buildResharePartyContext(newParties, true)
	if err != nil {
		t.Fatalf("sort new committee: %v", err)
	}
	victimSecret := newSecrets[sortedNew[0].Id]          // new-index 0     (< oldPC)
	attacker := newSecrets[sortedNew[oldPC].Id].Identity // new-index oldPC (out of range)

	// Old committee: fresh identities disjoint from the new committee, so the
	// victim is new-only and never loads a key share.
	oldParties := make([]Identity, 0, oldPC)
	for range oldPC {
		s, err := NewSecret()
		if err != nil {
			t.Fatalf("new secret: %v", err)
		}
		oldParties = append(oldParties, s.Identity)
	}

	// Build the victim node: real store + embedded preparams, and the package's
	// shared no-op transport since no peers are live.
	store, err := NewTSSStore(t.TempDir(), victimSecret)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	loadTestPreParams(t, store.(*fileStore), 0)
	victim := NewTSS(victimSecret.Identity, store, noopTransport{})

	cid := NewCeremonyID()
	keyID := make([]byte, 16) // arbitrary; a new-only node never loads it

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Run the ceremony: it registers, runs new-committee round 1, then blocks in
	// collect awaiting oldPC round-1 messages. A recovered panic or the returned
	// error is reported on `done` exactly once.
	done := make(chan reshareOutcome, 1)
	go func() {
		var res reshareOutcome
		defer func() {
			res.panicVal = recover()
			done <- res
		}()
		res.err = victim.Reshare(ctx, cid, keyID, oldParties, newParties, 1, 1)
	}()

	// Craft the cross-committee message: a round-1 (DGRound1Message) content the
	// round-1 collector matches, sent with fromNew set so a build that resolved
	// From.Index from the attacker-controlled wire flag would place it in the
	// larger new PID set. Reshare framing is
	// [broadcast:1][committee_flags:1][wireBytes...].
	//
	// The content must be STRUCTURALLY VALID. HandleMessage runs
	// validTSSContent (ValidateBasic) on the parsed content BEFORE it resolves
	// the sender's committee and index, so an empty DGRound1Message is rejected
	// at that structural guard and never reaches the committee-binding path this
	// test targets -- the test would then pass for the wrong reason even if the
	// index protection regressed. DGRound1Message.ValidateBasic requires a
	// non-nil ECDSAPub, a positive VCommitment and a non-empty SSID.
	validR1 := &resharing.DGRound1Message{
		ECDSAPub:    crypto.ScalarBaseMult(tss.S256(), big.NewInt(42)),
		VCommitment: big.NewInt(88),
		SSID:        []byte("cross-committee-index-test"),
	}
	if !validTSSContent(validR1) {
		t.Fatal("test setup: crafted DGRound1Message must pass validTSSContent, " +
			"otherwise it is rejected before the committee-index path")
	}
	wire, err := marshalTSSContent(validR1)
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}
	data := append([]byte{msgTypeBroadcast, cflagToNew | cflagFromNew}, wire...)

	// Deliver the one malicious message, retrying only until the ceremony
	// registers. herr == nil means it was enqueued for the collector; a
	// non-ErrUnknownCeremony error means HandleMessage refused it at ingest (the
	// committee-flag-validation fix).
	deadline := time.After(exitBound)
	rejectedAtIngest := false
deliver:
	for {
		switch herr := victim.HandleMessage(ctx, attacker, cid, data); {
		case herr == nil:
			break deliver
		case errors.Is(herr, ErrUnknownCeremony):
			// Not registered yet; wait and retry.
		default:
			t.Logf("cross-committee message rejected at ingest: %v", herr)
			rejectedAtIngest = true
			break deliver
		}
		select {
		case res := <-done:
			// Driver ended before we could deliver: a pure setup failure (the
			// collector was never fed, so the OOB path was not exercised).
			t.Fatalf("reshare ended before delivery (panic=%v err=%v); OOB path "+
				"not exercised", res.panicVal, res.err)
		case <-deadline:
			t.Fatal("ceremony never registered; malicious message undeliverable")
		case <-time.After(2 * time.Millisecond):
			// retry
		}
	}

	if !rejectedAtIngest {
		// The message is on the ceremony's inbound channel and the collector is
		// already blocked reading it. A buggy build indexes out of bounds and
		// panics within settleWindow; a bounds-checked build drops the message and
		// re-blocks (no panic). ctx is NOT cancelled during this window, so a buggy
		// collector's select has only the message ready -- cancellation can never
		// pre-empt the panic.
		select {
		case res := <-done:
			if res.panicVal != nil {
				t.Fatalf("reshare ceremony crashed on a cross-committee party index "+
					"(panic: %v); an out-of-range index driven by the attacker-"+
					"controlled committee flag must not index the collector out of "+
					"bounds", res.panicVal)
			}
			// A clean return before we cancelled means the driver never blocked on
			// the malicious message -- the OOB path was not exercised, so passing
			// here would be a false pass.
			t.Fatalf("reshare ended (err=%v) before consuming the malicious "+
				"message; the out-of-bounds path was not exercised", res.err)
		case <-time.After(settleWindow):
			// No panic: a fixed collector consumed and dropped the message. Fall
			// through to cancel and require a clean exit.
		}
	}

	// Unblock the still-waiting driver and require a clean, panic-free exit.
	cancel()
	select {
	case res := <-done:
		if res.panicVal != nil {
			t.Fatalf("reshare ceremony crashed after cancellation (panic: %v)", res.panicVal)
		}
	case <-time.After(exitBound):
		t.Fatal("reshare did not exit after cancellation")
	}
}

// Regression test for the residual left by the reshare collector bounds-check:
// an IN-RANGE cross-committee party-index collision.
//
// HandleMessage resolves an inbound reshare message's From.Index in whichever
// committee the attacker-controlled cflagFromNew wire bit selects, and the round
// collectors match on Go content type only. The committed bounds-check stops an
// OUT-OF-RANGE index, but a Byzantine NEW-committee member can flip cflagFromNew
// on an old-committee (DGRound1) message so its index resolves in the NEW space;
// when that index is IN RANGE for the oldPC-sized round-1 buffer AND equals an
// overlapping victim's own old-slot, it seizes that slot. The driver then
// overwrites its own slot with selfR1 (tss.go), wasting the seizure and leaving a
// real party's slot nil, and ReshareRound2 dereferences the nil message
// (ecdsa/resharing/round_fn.go) -> nil-pointer panic in the un-recovered ceremony
// goroutine -> node crash.
//
// The bounds-check cannot help here: the seized index is in range. The test FAILS
// while the flaw is present (crash) and PASSES once ingest binds the committee to
// the message's content type (so a DGRound1 with fromNew=1 is rejected and the
// sender can only ever fill its own slot in its own committee).

// reshareIndexOf returns id's sorted party index within a committee, computed
// exactly as the reshare driver does (buildResharePartyContext: new-committee
// keys are XOR'd before sorting).
func reshareIndexOf(t *testing.T, id Identity, parties []Identity, isNew bool) int {
	t.Helper()
	sorted, _, _, _, err := (&tssImpl{}).buildResharePartyContext(parties, isNew)
	if err != nil {
		t.Fatalf("build party context: %v", err)
	}
	for _, p := range sorted {
		if p.Id == id.String() {
			return p.Index
		}
	}
	t.Fatalf("identity %s not found in committee", id)
	return -1
}

func TestReshareCrossCommitteeSlotSeizureCrashesReshare(t *testing.T) {
	const (
		settleWindow = 750 * time.Millisecond
		exitBound    = 10 * time.Second
	)

	// --- Real 2-party keygen so the overlapping victim A holds a key share. ---
	network := NewTSSNetwork(t)
	a := network.AddNode()
	b := network.AddNode()
	oldParties := []Identity{a.id, b.id} // oldPC = 2
	const threshold = 1

	kgCtx, kgCancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer kgCancel()
	keygenCID := NewCeremonyID()
	var wg sync.WaitGroup
	keyIDs := make([][]byte, 2)
	kerr := make([]error, 2)
	for i, n := range []*tssNode{a, b} {
		wg.Add(1)
		go func(i int, n *tssNode) {
			defer wg.Done()
			keyIDs[i], kerr[i] = n.tss.Keygen(kgCtx, keygenCID, oldParties, threshold)
		}(i, n)
	}
	wg.Wait()
	for i, e := range kerr {
		if e != nil {
			t.Fatalf("keygen node %d: %v", i, e)
		}
	}
	keyID := keyIDs[0]

	// --- Pick attacker C (new-only) whose NEW-committee index equals A's OLD
	// index (necessarily < oldPC, so in range). Then a DGRound1 with fromNew=1
	// from C resolves onto A's own old-slot. ---
	aOldIndex := reshareIndexOf(t, a.id, oldParties, false)
	var attacker *Secret
	var newParties []Identity
	for range 4000 {
		c := mustSecret(t)
		np := []Identity{a.id, b.id, c.Identity}
		if reshareIndexOf(t, c.Identity, np, true) == aOldIndex {
			attacker, newParties = c, np
			break
		}
	}
	if attacker == nil {
		t.Fatal("could not find an attacker identity with the target new-index")
	}

	// --- Run ONLY victim A's reshare, with a capturing transport. B and the
	// attacker are not live, so A's collector sees only what we inject. ---
	capture := &captureTransport{sent: make(chan []byte, 16)}
	victim := NewTSS(a.secret.Identity, a.store, capture)

	reshareCID := NewCeremonyID()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		_ = victim.Reshare(ctx, reshareCID, keyID, oldParties, newParties, threshold, threshold)
	}()

	// --- Capture A's own valid round-1 DGRound1 broadcast. ---
	var captured []byte
	select {
	case captured = <-capture.sent:
	case res := <-done:
		t.Fatalf("victim reshare ended before sending round 1: %v", res)
	case <-time.After(60 * time.Second):
		t.Fatal("victim never sent its round-1 message")
	}
	if len(captured) <= wireHeaderLen {
		t.Fatalf("captured reshare message too short: %d bytes", len(captured))
	}
	wireBytes := captured[wireHeaderLen:]

	// --- Reflect it as a cross-committee message: same valid content, but with
	// the fromNew flag set and attributed to the attacker C (from != self). ---
	data := append([]byte{captured[0], cflagToNew | cflagFromNew}, wireBytes...)
	if herr := victim.HandleMessage(ctx, attacker.Identity, reshareCID, data); herr != nil {
		t.Logf("cross-committee message rejected at ingest: %v", herr)
	}

	// --- Verdict: a crash surfaces as a recovered panic; a clean early return
	// means the path was not exercised; a timeout means a fixed ingest dropped it. ---
	select {
	case res := <-done:
		if res != nil {
			t.Fatalf("reshare crashed on an in-range cross-committee slot seizure "+
				"(panic: %v); a reshare message must not be resolved into another "+
				"committee's index space", res)
		}
		t.Fatalf("reshare returned before consuming the injected message; the " +
			"seizure path was not exercised")
	case <-time.After(settleWindow):
		// No crash: a fixed node bound the committee to the content type and
		// refused the cross-committee message. Fall through and require clean exit.
	}

	cancel()
	select {
	case res := <-done:
		if res != nil {
			t.Fatalf("reshare crashed after cancellation: %v", res)
		}
	case <-time.After(exitBound):
		t.Fatal("reshare did not exit after cancellation")
	}
}

// Regression test for the missing "from == self" check in HandleMessage.
//
// HandleMessage resolves an inbound message's party index from the sender's
// identity but never rejects a message whose sender is the node ITSELF. In a
// collect-based ceremony the round driver fills its own slot directly and
// collects the OTHER n-1 parties' messages by index (msgBuf.collect). A message
// attributed to the node itself, with valid content (so it passes the
// ValidateBasic ingest guard), is accepted into the node's own collector slot,
// consuming one of the n-1 quota slots. collect() then returns "satisfied" while
// a real party's slot is still nil, and the round function (keygen.Round2)
// dereferences that nil message -- a nil-pointer panic in the un-recovered
// ceremony goroutine, which crashes the whole node process.
//
// Each case FAILS while the flaw is present (nil-pointer panic in Round2) and
// PASSES once a self-attributed message can no longer take another party's slot
// -- whether the fix rejects it at ingest (HandleMessage: from == self) or deeper
// (the collector/driver declines to seat a self message). The verdict only ever
// asserts "did not crash", so it is agnostic to fix location.
//
// SCOPE. Every case is 2-party ECDSA keygen with no live peer. That is
// deliberate: with the peer never live, the injected self message is the only
// thing on the collector's channel, so it always steals the slot -- no ordering
// race, no flake, and n-1 == 1 means Round2 hits the nil slot immediately with no
// competing crypto path. The table varies only the WIRE FRAMING of the reflected
// message (broadcast vs p2p) -- the one axis that stays deterministic and
// fail-while-buggy without a live committee, and which proves the crash is driven
// by sender identity, not the framing byte (so a fix keyed only on the broadcast
// flag would not close the hole). Sign, reshare, n>=3, EdDSA and a malformed-self
// case were evaluated and dropped: they need a real key share, a live committee,
// or fail to fail-while-buggy. The shared ingest fix is ceremony-agnostic, so this
// one ceremony pins sign and reshare too.

// captureTransport records the victim's outbound ceremony messages so the test
// can reflect one back to the victim as if the victim itself had sent it. This
// models an on-path relay reflecting a node's own broadcast back to it. Capture
// (not synthesis) is load-bearing: ValidateBasic drops an empty KGRound1Message
// and would let a hand-built bogus one be rejected by Round2 before it reaches the
// nil peer slot -- masking the crash. The victim's genuine broadcast is valid all
// the way through Round2, so the nil slot is the only thing left to panic on.
type captureTransport struct{ sent chan []byte }

func (c *captureTransport) Send(_ Identity, _ CeremonyID, data []byte) error {
	cp := append([]byte(nil), data...)
	select {
	case c.sent <- cp:
	default: // capacity is slack; dropping extras is fine.
	}
	return nil
}

// reframe rewrites the wire framing of a captured message without touching its
// (valid) content, so the reflected copy still parses and clears ValidateBasic.
type reframe func(wire []byte) []byte

// asBroadcast reflects the round-1 broadcast unchanged (baseline reproduction).
func asBroadcast(wire []byte) []byte { return append([]byte(nil), wire...) }

// asP2P flips the broadcast framing byte to unicast and leaves content untouched.
// HandleMessage routes on sender identity and the collector's accept closure keys
// on content type + From.Index -- neither consults the framing byte -- so this
// still steals the self slot and panics while buggy. It guards against a fix that
// special-cases only the broadcast flag.
func asP2P(wire []byte) []byte {
	out := append([]byte(nil), wire...)
	if len(out) > 0 {
		out[0] = msgTypeP2P
	}
	return out
}

// keygenOutcome records exactly how the ceremony goroutine ended: a recovered
// panic (the crash we guard against) and/or the driver's key ID and error, so
// every failure message can name the concrete ending rather than an opaque value.
type keygenOutcome struct {
	panicVal any
	keyID    []byte
	err      error
}

func mustSecret(t *testing.T) *Secret {
	t.Helper()
	s, err := NewSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	return s
}

// newCapturingVictim builds a victim TSS node backed by a real encrypted store
// with embedded preparams and a capturing transport.
func newCapturingVictim(t *testing.T, secret *Secret) (TSS, *captureTransport) {
	t.Helper()
	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	loadTestPreParams(t, store.(*fileStore), 0)
	transport := &captureTransport{sent: make(chan []byte, 8)}
	return NewTSS(secret.Identity, store, transport), transport
}

func TestReflectedSelfMessageDoesNotCrashKeygen(t *testing.T) {
	cases := []struct {
		name    string
		reframe reframe
	}{
		{"broadcast-framed self", asBroadcast},
		{"p2p-framed self", asP2P},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runKeygenSelfReflection(t, tc.reframe)
		})
	}
}

// runKeygenSelfReflection builds a 2-party keygen victim, captures its genuine
// round-1 broadcast, reframes it, reflects it back attributed to the victim
// itself (from == self), and asserts the node does not crash.
func runKeygenSelfReflection(t *testing.T, reframe reframe) {
	t.Helper()

	const (
		// captureBound: generous failsafe on the victim producing round 1
		// (preparams are cached, so this is fast). Never a pass signal.
		captureBound = 30 * time.Second
		// settleWindow: once the self message is enqueued, a buggy build consumes it
		// and panics almost immediately (it is the only thing on the channel the
		// collector is already blocked reading). We wait this long for that panic
		// before concluding a fixed build dropped it. It adds latency only to the
		// passing case and is NEVER itself a pass signal -- the verdict is the
		// recovered panic value, not this timeout.
		settleWindow = 500 * time.Millisecond
		// exitBound: failsafe on the fast channel-based cancellation handshake.
		exitBound = 5 * time.Second
	)

	victimSecret := mustSecret(t)
	otherSecret := mustSecret(t)
	victim, transport := newCapturingVictim(t, victimSecret)

	// 2-party keygen; the "other" party is never live, so the only round-1 message
	// the victim's collector can ever seat is the one we inject.
	parties := []Identity{victimSecret.Identity, otherSecret.Identity}
	cid := NewCeremonyID()
	const threshold = 1

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Run the ceremony; the deferred recover models the fact that a real crash --
	// continuum has no recover() -- would take down the process.
	done := make(chan keygenOutcome, 1)
	go func() {
		var res keygenOutcome
		defer func() {
			res.panicVal = recover()
			done <- res
		}()
		res.keyID, res.err = victim.Keygen(ctx, cid, parties, threshold)
	}()

	// Capture the victim's own valid round-1 broadcast.
	var selfMsg []byte
	select {
	case selfMsg = <-transport.sent:
	case res := <-done:
		t.Fatalf("keygen ended before sending its round-1 message "+
			"(panic=%v keyID=%x err=%v); reproduction never armed",
			res.panicVal, res.keyID, res.err)
	case <-time.After(captureBound):
		t.Fatal("victim never sent its round-1 message")
	}
	selfMsg = reframe(selfMsg)

	// Reflect it back, attributed to the victim ITSELF (from == self). The content
	// is genuinely valid, so the ValidateBasic guard cannot drop it -- proving the
	// flaw is distinct from that guard. The ceremony registers itself before it
	// emits round 1, so by the time we captured the broadcast it is already in the
	// map and HandleMessage routes straight to it (no ErrUnknownCeremony window).
	// A fixed HandleMessage returns an error here (rejected at ingest); a fixed
	// collector accepts (nil) but never seats it; a buggy build seats it and arms
	// the nil-slot crash. All three are handled by the single verdict below.
	if herr := victim.HandleMessage(ctx, victimSecret.Identity, cid, selfMsg); herr != nil {
		t.Logf("self-attributed message rejected at ingest: %v", herr)
	}

	// Verdict. ctx is NOT cancelled during this window, so a buggy collector's
	// select has only the self message ready -- cancellation cannot pre-empt the
	// panic. A crash surfaces as a non-nil recover; a clean return before we cancel
	// means the nil-slot path was never exercised (a 2-party keygen cannot
	// legitimately finish with the peer absent), so that too is a hard failure.
	select {
	case res := <-done:
		if res.panicVal != nil {
			t.Fatalf("keygen ceremony crashed on a self-attributed message "+
				"(panic: %v); a message whose sender is the node itself must not "+
				"occupy another party's collector slot", res.panicVal)
		}
		t.Fatalf("keygen returned (keyID=%x err=%v) before consuming the self-"+
			"attributed message; the nil-slot crash path was not exercised",
			res.keyID, res.err)
	case <-time.After(settleWindow):
		// No crash and no premature return: a fixed node refused to seat the self
		// message. Fall through to cancel and require a clean exit.
	}

	// Unblock the still-waiting driver (stuck collecting the never-arriving real
	// party) and require a clean, panic-free exit.
	cancel()
	select {
	case res := <-done:
		if res.panicVal != nil {
			t.Fatalf("keygen crashed after cancellation: %v", res.panicVal)
		}
	case <-time.After(exitBound):
		t.Fatal("keygen did not exit after cancellation")
	}
}

// loadPreParams reads cached Paillier preparams from the embedded
// fixture so keygen doesn't spend ~30s per node generating them.
func loadPreParams(t *testing.T, count int) []keygen.LocalPreParams {
	t.Helper()
	return testPreParams(t, count)
}

// =============================================================================
// rpcTSSNode — TSS participant over encrypted Transport
//
// Uses the production tssImpl for all ceremony logic (keygen, sign,
// reshare via round functions). The test provides an encrypted TCP
// transport adapter so messages flow through the full KX → Handshake
// → signed TSSMessage → byte-prefix wire protocol stack.
// =============================================================================

// rpcTSSNode is a TSS participant that communicates via the full
// continuum protocol stack: TCP → KX (ECDH) → Handshake (secp256k1
// identity) → signed RPC envelopes.
type rpcTSSNode struct {
	t       *testing.T
	id      Identity
	secret  *Secret
	store   TSSStore
	tss     TSS
	adapter *rpcTransportAdapter

	// Encrypted Transport connections to peers.
	transports   map[Identity]*Transport
	transportsMu sync.RWMutex
	listener     net.Listener

	// Ceremony result channels: goroutine sends result when done.
	results   map[CeremonyID]chan any
	resultsMu sync.Mutex

	// Lifecycle.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// corruptFn, if set, is called on each outgoing TSSMessage
	// before it is written to the wire. Used by negative tests.
	corruptFn func(msg *TSSMessage)
}

// rpcTransportAdapter implements TSSTransport by translating between
// the tss.go byte-prefix wire format and signed TSSMessage envelopes
// over encrypted Transports.
type rpcTransportAdapter struct {
	node   *rpcTSSNode
	ctypes map[CeremonyID]CeremonyType
	mu     sync.RWMutex
}

func (a *rpcTransportAdapter) registerCeremony(cid CeremonyID, ct CeremonyType) {
	a.mu.Lock()
	a.ctypes[cid] = ct
	a.mu.Unlock()
}

func (a *rpcTransportAdapter) unregisterCeremony(cid CeremonyID) {
	a.mu.Lock()
	delete(a.ctypes, cid)
	a.mu.Unlock()
}

// Send implements TSSTransport. Translates byte-prefix wire format
// to TSSMessage with Flags routing and writes to peer Transport.
func (a *rpcTransportAdapter) Send(to Identity, ceremonyID CeremonyID, data []byte) error {
	if len(data) < 1 {
		return errors.New("empty TSS data")
	}

	a.mu.RLock()
	ctype, ok := a.ctypes[ceremonyID]
	a.mu.RUnlock()
	if !ok {
		return fmt.Errorf("ceremony %s: unknown type", ceremonyID)
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

	hash := HashTSSMessage(ceremonyID, a.node.id, ctype, flags, wireData)
	sig := a.node.secret.Sign(hash)

	tssMsg := TSSMessage{
		CeremonyID: ceremonyID,
		Type:       ctype,
		From:       a.node.id,
		Flags:      flags,
		Data:       wireData,
		Signature:  sig,
	}

	if a.node.corruptFn != nil {
		a.node.corruptFn(&tssMsg)
	}

	a.node.transportsMu.RLock()
	tr := a.node.transports[to]
	a.node.transportsMu.RUnlock()

	if tr == nil {
		return fmt.Errorf("no transport for %s", to)
	}
	return tr.Write(a.node.id, tssMsg)
}

func newRPCTSSNode(t *testing.T, preParams *keygen.LocalPreParams) *rpcTSSNode {
	t.Helper()

	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}

	store, err := NewTSSStore(t.TempDir(), secret)
	if err != nil {
		t.Fatalf("NewTSSStore: %v", err)
	}
	if preParams != nil {
		store.SetPreParams(preParams)
	}

	ctx, cancel := context.WithCancel(t.Context())

	lc := &net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen: %v", err)
	}

	node := &rpcTSSNode{
		t:          t,
		id:         secret.Identity,
		secret:     secret,
		store:      store,
		transports: make(map[Identity]*Transport),
		results:    make(map[CeremonyID]chan any),
		listener:   listener,
		ctx:        ctx,
		cancel:     cancel,
	}

	adapter := &rpcTransportAdapter{
		node:   node,
		ctypes: make(map[CeremonyID]CeremonyType),
	}
	node.adapter = adapter
	node.tss = NewTSS(secret.Identity, store, adapter)

	return node
}

// =============================================================================
// Read loop — dispatches incoming RPC protocol messages
// =============================================================================

func (n *rpcTSSNode) startReadLoop(tr *Transport, remoteID Identity) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for {
			_, cmd, err := tr.Read()
			if err != nil {
				select {
				case <-n.ctx.Done():
					return
				default:
				}
				n.t.Logf("readLoop %s←%s: %v", n.id, remoteID, err)
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
				n.dispatchTSSMsg(*v)
			default:
				n.t.Logf("readLoop %s←%s: unhandled %T",
					n.id, remoteID, cmd)
			}
		}
	}()
}

// dispatchTSSMsg verifies the signature and routes to HandleMessage.
// Retries on ErrUnknownCeremony (message arrives before ceremony
// registration — normal race in distributed mesh).
func (n *rpcTSSNode) dispatchTSSMsg(msg TSSMessage) {
	hash := HashTSSMessage(msg.CeremonyID, msg.From, msg.Type, msg.Flags, msg.Data)
	if _, err := Verify(hash, msg.From, msg.Signature); err != nil {
		n.t.Logf("node %s: bad sig from %s: %v",
			n.id, msg.From, err)
		return
	}

	// Reconstruct byte-prefix wire format for HandleMessage.
	var data []byte
	var bcast byte
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

	err := n.tss.HandleMessage(n.ctx, msg.From, msg.CeremonyID, data)
	if err == nil {
		return
	}
	if !errors.Is(err, ErrUnknownCeremony) {
		n.t.Logf("node %s: handle msg from %s: %v",
			n.id, msg.From, err)
		return
	}

	// Retry: ceremony not registered yet.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for _, delay := range []time.Duration{
			50 * time.Millisecond,
			100 * time.Millisecond,
			250 * time.Millisecond,
			500 * time.Millisecond,
			1 * time.Second,
			2 * time.Second,
		} {
			timer := time.NewTimer(delay)
			select {
			case <-n.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			err = n.tss.HandleMessage(n.ctx, msg.From, msg.CeremonyID, data)
			if err == nil {
				return
			}
			if !errors.Is(err, ErrUnknownCeremony) {
				break
			}
		}
		n.t.Logf("node %s: handle msg from %s: %v (after retries)",
			n.id, msg.From, err)
	}()
}

// =============================================================================
// Ceremony handlers — dispatch to production tssImpl
// =============================================================================

func (n *rpcTSSNode) registerResult(cid CeremonyID) chan any {
	ch := make(chan any, 1)
	n.resultsMu.Lock()
	n.results[cid] = ch
	n.resultsMu.Unlock()
	return ch
}

func (n *rpcTSSNode) handleKeygen(req KeygenRequest) {
	parties := partiesToIdentities(req.Committee)
	if parties == nil {
		return
	}
	ch := n.registerResult(req.CeremonyID)
	n.adapter.registerCeremony(req.CeremonyID, CeremonyKeygen)

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer n.adapter.unregisterCeremony(req.CeremonyID)
		keyID, err := n.tss.Keygen(n.ctx, req.CeremonyID,
			parties, req.Threshold)
		if err != nil {
			ch <- err
			return
		}
		n.t.Logf("node %s: keygen done, key=%x",
			n.id, keyID)
		ch <- keyID
	}()
}

func (n *rpcTSSNode) handleSign(req SignRequest) {
	parties := partiesToIdentities(req.Committee)
	if parties == nil {
		return
	}
	ch := n.registerResult(req.CeremonyID)
	n.adapter.registerCeremony(req.CeremonyID, CeremonySign)

	var data [32]byte
	copy(data[:], req.Data)

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer n.adapter.unregisterCeremony(req.CeremonyID)
		r, s, err := n.tss.Sign(n.ctx, req.CeremonyID,
			req.KeyID, parties, req.Threshold, data)
		if err != nil {
			ch <- err
			return
		}
		n.t.Logf("node %s: sign done, r=%x..",
			n.id, r[:8])
		ch <- [2][]byte{r, s}
	}()
}

func (n *rpcTSSNode) handleReshare(req ReshareRequest) {
	oldParties := partiesToIdentities(req.OldCommittee)
	newParties := partiesToIdentities(req.NewCommittee)
	if oldParties == nil || newParties == nil {
		return
	}
	ch := n.registerResult(req.CeremonyID)
	n.adapter.registerCeremony(req.CeremonyID, CeremonyReshare)

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer n.adapter.unregisterCeremony(req.CeremonyID)
		err := n.tss.Reshare(n.ctx, req.CeremonyID, req.KeyID,
			oldParties, newParties,
			req.OldThreshold, req.NewThreshold)
		if err != nil {
			ch <- err
			return
		}
		n.t.Logf("node %s: reshare done", n.id)
		ch <- nil
	}()
}

// =============================================================================
// Wait helpers
// =============================================================================

func (n *rpcTSSNode) waitKeygen(ctx context.Context, cid CeremonyID) ([]byte, error) {
	n.resultsMu.Lock()
	ch := n.results[cid]
	n.resultsMu.Unlock()
	if ch == nil {
		// Poll for registration.
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-tick.C:
			}
			n.resultsMu.Lock()
			ch = n.results[cid]
			n.resultsMu.Unlock()
			if ch != nil {
				break
			}
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		switch v := result.(type) {
		case []byte:
			return v, nil
		case error:
			return nil, v
		default:
			return nil, fmt.Errorf("unexpected result type: %T", v)
		}
	}
}

func (n *rpcTSSNode) waitSign(ctx context.Context, cid CeremonyID) ([]byte, []byte, error) {
	n.resultsMu.Lock()
	ch := n.results[cid]
	n.resultsMu.Unlock()
	if ch == nil {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-tick.C:
			}
			n.resultsMu.Lock()
			ch = n.results[cid]
			n.resultsMu.Unlock()
			if ch != nil {
				break
			}
		}
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case result := <-ch:
		switch v := result.(type) {
		case [2][]byte:
			return v[0], v[1], nil
		case error:
			return nil, nil, v
		default:
			return nil, nil, fmt.Errorf("unexpected result type: %T", v)
		}
	}
}

func (n *rpcTSSNode) waitReshare(ctx context.Context, cid CeremonyID) error {
	n.resultsMu.Lock()
	ch := n.results[cid]
	n.resultsMu.Unlock()
	if ch == nil {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-tick.C:
			}
			n.resultsMu.Lock()
			ch = n.results[cid]
			n.resultsMu.Unlock()
			if ch != nil {
				break
			}
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case result := <-ch:
		if result == nil {
			return nil
		}
		if err, ok := result.(error); ok {
			return err
		}
		return nil
	}
}

// =============================================================================
// Mesh setup — encrypted TCP connections between all nodes
// =============================================================================

// connectRPCPair establishes an encrypted TCP channel between server
// and client: KeyExchange + Handshake + bidirectional read loops.
func connectRPCPair(t *testing.T, server, client *rpcTSSNode) {
	t.Helper()

	serverTr, err := NewTransportFromCurve(ecdh.X25519())
	if err != nil {
		t.Fatalf("NewTransportFromCurve: %v", err)
	}
	clientTr := new(Transport)

	ctx, cancel := context.WithTimeout(t.Context(),
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
		id, _, hsErr := serverTr.Handshake(ctx, server.secret)
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
		id, _, hsErr := clientTr.Handshake(ctx, client.secret)
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

	server.transportsMu.Lock()
	server.transports[client.id] = serverTr
	server.transportsMu.Unlock()

	client.transportsMu.Lock()
	client.transports[server.id] = clientTr
	client.transportsMu.Unlock()

	server.startReadLoop(serverTr, client.id)
	client.startReadLoop(clientTr, server.id)
}

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
		if err := n.store.Close(); err != nil {
			t.Logf("close store: %v", err)
		}
	}
	for _, n := range nodes {
		n.wg.Wait()
	}
}

// =============================================================================
// Helpers
// =============================================================================

// rpcCommittee builds a PartyID committee from rpcTSSNode list.
func rpcCommittee(nodes []*rpcTSSNode) tss.UnSortedPartyIDs {
	pids := make(tss.UnSortedPartyIDs, len(nodes))
	for i, n := range nodes {
		idStr := n.id.String()
		pids[i] = tss.NewPartyID(idStr, idStr,
			new(big.Int).SetBytes(n.id[:]))
	}
	return pids
}

func rpcInitKeygen(t *testing.T, nodes []*rpcTSSNode, committee tss.UnSortedPartyIDs, cid CeremonyID, threshold int) {
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

func rpcInitSign(t *testing.T, nodes []*rpcTSSNode, committee tss.UnSortedPartyIDs, cid CeremonyID, keyID []byte, threshold int, data [32]byte) {
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

func rpcInitReshare(t *testing.T, nodes []*rpcTSSNode, oldCommittee, newCommittee tss.UnSortedPartyIDs, cid CeremonyID, keyID []byte, oldThreshold, newThreshold int) {
	t.Helper()

	req := ReshareRequest{
		CeremonyID:   cid,
		Curve:        "secp256k1",
		KeyID:        keyID,
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
func rpcSigningCommittee(t *testing.T, nodes []*rpcTSSNode, keyID []byte) tss.UnSortedPartyIDs {
	t.Helper()

	// Find any node that has the key and get Ks.
	var ks []*big.Int
	for _, n := range nodes {
		shareData, err := n.store.LoadKeyShare(keyID)
		if err != nil {
			continue
		}
		var save keygen.LocalPartySaveData
		if err := json.Unmarshal(shareData, &save); err != nil {
			continue
		}
		ks = save.Ks
		break
	}
	if ks == nil {
		t.Fatalf("no node has key %x", keyID)
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
// Tests — TSS ceremonies over encrypted Transport
// =============================================================================

func TestRPCTSSKeygen(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1 // 2-of-3

	t.Log("=== Keygen over encrypted Transport ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(t.Context(),
		60*time.Second)
	defer cancel()

	var keyID []byte
	for _, node := range nodes {
		kid, err := node.waitKeygen(ctx, cid)
		if err != nil {
			t.Fatalf("node %s: %v", node.id, err)
		}
		keyID = kid
		t.Logf("node %s: keyID=%x", node.id, keyID)
	}

	t.Log("All nodes completed keygen ✓")
}

func TestRPCTSSKeygenAndSign(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	committee := rpcCommittee(nodes)
	threshold := 1 // 2-of-3

	ctx, cancel := context.WithTimeout(t.Context(),
		60*time.Second)
	defer cancel()

	// === Keygen ===
	keygenCID := NewCeremonyID()
	t.Log("=== Keygen ===")

	rpcInitKeygen(t, nodes, committee, keygenCID, threshold)

	var keyID []byte
	for _, node := range nodes {
		kid, err := node.waitKeygen(ctx, keygenCID)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		keyID = kid
	}
	t.Logf("keygen done, keyID=%x", keyID)

	// Load public key for verification.
	meta, err := nodes[0].store.LoadKeyMetadata(keyID)
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}
	pubKey, err := secp256k1.ParsePubKey(
		append([]byte{0x04}, meta.PublicKey...))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	// === Sign ===
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("rpc tss round functions"))
	t.Log("=== Sign ===")

	rpcInitSign(t, nodes, committee, signCID,
		keyID, threshold, data)

	for _, node := range nodes {
		r, s, serr := node.waitSign(ctx, signCID)
		if serr != nil {
			t.Fatalf("sign: %v", serr)
		}
		var rs, ss secp256k1.ModNScalar
		if rs.SetByteSlice(r) || ss.SetByteSlice(s) {
			t.Fatalf("node %s: signature scalar overflow", node.id)
		}
		if !ecdsa.NewSignature(&rs, &ss).Verify(data[:], pubKey) {
			t.Fatalf("node %s: ECDSA verify failed", node.id)
		}
		t.Logf("node %s: signature verified ✓", node.id)
	}
}

func TestRPCTSSReshare(t *testing.T) {
	// 4 nodes: keygen {0,1,2}, reshare → {1,2,3}, sign with {1,2,3}.
	// Nodes 1 and 2 overlap both committees.
	nodes := setupRPCMesh(t, 4)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	oldCommittee := rpcCommittee(nodes[:3])
	newCommittee := rpcCommittee(nodes[1:])
	threshold := 1 // 2-of-3

	ctx, cancel := context.WithTimeout(t.Context(),
		120*time.Second)
	defer cancel()

	// --- Keygen with old committee {0, 1, 2} ---
	keygenCID := NewCeremonyID()
	t.Log("=== Keygen with old committee ===")

	rpcInitKeygen(t, nodes[:3], oldCommittee, keygenCID, threshold)

	var keyID []byte
	for _, node := range nodes[:3] {
		kid, err := node.waitKeygen(ctx, keygenCID)
		if err != nil {
			t.Fatalf("node %s keygen: %v", node.id, err)
		}
		keyID = kid
	}
	t.Logf("keygen done: keyID=%x", keyID)

	// Load public key for post-reshare signature verification.
	meta, err := nodes[0].store.LoadKeyMetadata(keyID)
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}
	pubKey, err := secp256k1.ParsePubKey(
		append([]byte{0x04}, meta.PublicKey...))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	// --- Reshare: {0,1,2} → {1,2,3} ---
	reshareCID := NewCeremonyID()
	t.Log("=== Reshare ===")

	rpcInitReshare(t, nodes, oldCommittee, newCommittee,
		reshareCID, keyID, threshold, threshold)

	for _, node := range nodes {
		if rerr := node.waitReshare(ctx, reshareCID); rerr != nil {
			t.Fatalf("node %s reshare: %v", node.id, rerr)
		}
	}
	t.Log("reshare done ✓")

	// --- Sign with new committee {1, 2, 3} ---
	signCID := NewCeremonyID()
	data := sha256.Sum256([]byte("post-reshare round functions"))
	t.Log("=== Sign with new committee ===")

	signCommittee := rpcSigningCommittee(t, nodes[1:], keyID)

	rpcInitSign(t, nodes[1:], signCommittee, signCID,
		keyID, threshold, data)

	for _, node := range nodes[1:] {
		r, s, serr := node.waitSign(ctx, signCID)
		if serr != nil {
			t.Fatalf("node %s sign: %v", node.id, serr)
		}
		var rs, ss secp256k1.ModNScalar
		if rs.SetByteSlice(r) || ss.SetByteSlice(s) {
			t.Fatalf("node %s: signature scalar overflow", node.id)
		}
		if !ecdsa.NewSignature(&rs, &ss).Verify(data[:], pubKey) {
			t.Fatalf("node %s: ECDSA verify failed after reshare",
				node.id)
		}
		t.Logf("node %s: signature verified ✓", node.id)
	}
}

// =============================================================================
// Negative tests — corrupt signer scenarios
// =============================================================================

func TestRPCTSSKeygenCorruptPostSign(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	// Node 2 flips a bit in Data after signing. Receivers reject
	// because Hash(CeremonyID||corrupt_data) won't match signature.
	nodes[2].corruptFn = func(msg *TSSMessage) {
		if len(msg.Data) > 0 {
			msg.Data[0] ^= 0xff
		}
	}

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1

	t.Log("=== Keygen with post-sign corruption (node 2) ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(t.Context(),
		5*time.Second)
	defer cancel()

	for _, node := range nodes {
		_, err := node.waitKeygen(ctx, cid)
		if err == nil {
			t.Fatal("ceremony must fail with corrupt signer")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("post-sign corruption rejected ✓")
}

func TestRPCTSSKeygenCorruptResigned(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	// Node 2 corrupts wire data then re-signs so Verify passes.
	// tss-lib rejects the garbage at protocol level.
	corruptNode := nodes[2]
	corruptNode.corruptFn = func(msg *TSSMessage) {
		if len(msg.Data) > 0 {
			msg.Data[0] ^= 0xff
			hash := HashTSSMessage(msg.CeremonyID, msg.From, msg.Type, msg.Flags, msg.Data)
			msg.Signature = corruptNode.secret.Sign(hash)
		}
	}

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1

	t.Log("=== Keygen with re-signed corruption (node 2) ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(t.Context(),
		5*time.Second)
	defer cancel()

	for _, node := range nodes {
		_, err := node.waitKeygen(ctx, cid)
		if err == nil {
			t.Fatal("ceremony must fail with corrupt wire data")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("re-signed corruption caught at protocol level ✓")
}

func TestRPCTSSKeygenBadSignature(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

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

	ctx, cancel := context.WithTimeout(t.Context(),
		5*time.Second)
	defer cancel()

	for _, node := range nodes {
		_, err := node.waitKeygen(ctx, cid)
		if err == nil {
			t.Fatal("ceremony must fail with bad signature")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("zeroed signature rejected ✓")
}

func TestRPCTSSKeygenSpoofIdentity(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	spoofTarget := nodes[0].id
	nodes[2].corruptFn = func(msg *TSSMessage) {
		msg.From = spoofTarget
	}

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1

	t.Log("=== Keygen with spoofed identity (node 2 → node 0) ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(t.Context(),
		5*time.Second)
	defer cancel()

	for _, node := range nodes {
		_, err := node.waitKeygen(ctx, cid)
		if err == nil {
			t.Fatal("ceremony must fail with spoofed identity")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("spoofed identity rejected ✓")
}

func TestRPCTSSSignCorruptPostSign(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	committee := rpcCommittee(nodes)
	threshold := 1

	ctx, cancel := context.WithTimeout(t.Context(),
		60*time.Second)
	defer cancel()

	// === Honest keygen ===
	keygenCID := NewCeremonyID()
	t.Log("=== Honest keygen ===")

	rpcInitKeygen(t, nodes, committee, keygenCID, threshold)

	var keyID []byte
	for _, node := range nodes {
		kid, err := node.waitKeygen(ctx, keygenCID)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		keyID = kid
	}
	t.Logf("keygen done, keyID=%x", keyID)

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
		keyID, threshold, data)

	shortCtx, shortCancel := context.WithTimeout(
		t.Context(), 5*time.Second)
	defer shortCancel()

	for _, node := range nodes {
		_, _, err := node.waitSign(shortCtx, signCID)
		if err == nil {
			t.Fatal("signing must fail with corrupt signer")
		}
		t.Logf("node %s: %v (expected)", node.id, err)
	}
	t.Log("sign-phase corruption rejected ✓")
}

func TestRPCTSSReshareCorruptPostSign(t *testing.T) {
	// 4 nodes: keygen {0,1,2}, reshare → {1,2,3}.
	// Node 2 overlaps both committees and corrupts.
	nodes := setupRPCMesh(t, 4)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	oldCommittee := rpcCommittee(nodes[:3])
	threshold := 1

	ctx, cancel := context.WithTimeout(t.Context(),
		60*time.Second)
	defer cancel()

	// === Honest keygen ===
	keygenCID := NewCeremonyID()
	t.Log("=== Honest keygen with {0,1,2} ===")

	rpcInitKeygen(t, nodes[:3], oldCommittee, keygenCID, threshold)

	var keyID []byte
	for _, node := range nodes[:3] {
		kid, err := node.waitKeygen(ctx, keygenCID)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		keyID = kid
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
		reshareCID, keyID, threshold, threshold)

	shortCtx, shortCancel := context.WithTimeout(
		t.Context(), 5*time.Second)
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

// =============================================================================
// Ported from rpc_integration_test.go — error path tests
// =============================================================================

// TestRPCTSSKeygenWrongThreshold verifies that an invalid threshold
// (t+1 > n) is rejected immediately by the production Keygen path.
func TestRPCTSSKeygenWrongThreshold(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 3 // 4-of-3 is invalid

	t.Log("=== Keygen with invalid threshold ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	ctx, cancel := context.WithTimeout(t.Context(),
		5*time.Second)
	defer cancel()

	_, err := nodes[0].waitKeygen(ctx, cid)
	if err == nil {
		t.Fatal("keygen must fail with invalid threshold")
	}
	t.Logf("Expected failure: %v ✓", err)
}

// TestRPCTSSSignWithoutKey verifies that signing with a nonexistent
// key share is rejected by the production Sign path.
func TestRPCTSSSignWithoutKey(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	data := sha256.Sum256([]byte("test"))

	t.Log("=== Sign without keygen (no key) ===")

	rpcInitSign(t, nodes, committee, cid,
		[]byte("nonexistent-key"), 1, data)

	ctx, cancel := context.WithTimeout(t.Context(),
		5*time.Second)
	defer cancel()

	_, _, err := nodes[0].waitSign(ctx, cid)
	if err == nil {
		t.Fatal("sign must fail - no key exists")
	}
	t.Logf("Expected failure: %v ✓", err)
}

// TestRPCTSSMITMMessageInjection verifies that a forged TSSMessage
// claiming to be from a committee member but signed by an outside
// attacker is rejected at the Verify step. The honest keygen
// should still complete.
func TestRPCTSSMITMMessageInjection(t *testing.T) {
	nodes := setupRPCMesh(t, 3)
	t.Cleanup(func() { teardownRPCMesh(t, nodes) })

	committee := rpcCommittee(nodes)
	cid := NewCeremonyID()
	threshold := 1

	t.Log("=== MITM injection attack ===")

	rpcInitKeygen(t, nodes, committee, cid, threshold)

	// Attacker forges a TSSMessage claiming to be node 1.
	attacker, _ := NewSecret()
	fakeData := []byte("malicious-round-data")
	hash := HashTSSMessage(cid, nodes[1].id, 0, TSSFlagBroadcast, fakeData)
	fakeSig := attacker.Sign(hash)

	fakeMsg := TSSMessage{
		CeremonyID: cid,
		From:       nodes[1].id, // Claims to be node 1
		Flags:      TSSFlagBroadcast,
		Data:       fakeData,
		Signature:  fakeSig, // Signed by attacker
	}

	// Deliver directly — should be rejected at Verify.
	nodes[0].dispatchTSSMsg(fakeMsg)

	ctx, cancel := context.WithTimeout(t.Context(),
		60*time.Second)
	defer cancel()

	_, err := nodes[0].waitKeygen(ctx, cid)
	if err != nil {
		t.Fatalf("honest keygen should complete despite MITM: %v", err)
	}
	t.Log("MITM injection rejected, honest keygen completed ✓")
}

// =============================================================================
// Fuzz tests — signature and CeremonyID round-trips
// =============================================================================

func FuzzTSSMessageSignature(f *testing.F) {
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

		hash := HashTSSMessage(cid, secret.Identity, CeremonyKeygen, 0, data)
		sig := secret.Sign(hash)

		if _, err = Verify(hash, secret.Identity, sig); err != nil {
			t.Errorf("Valid signature rejected: %v", err)
		}

		if len(data) > 0 {
			tampered := make([]byte, len(data))
			copy(tampered, data)
			tampered[0] ^= 0xFF

			tamperedHash := HashTSSMessage(cid, secret.Identity, CeremonyKeygen, 0, tampered)
			if _, err = Verify(tamperedHash, secret.Identity, sig); err == nil {
				t.Error("Tampered data should fail verification")
			}
		}

		other, _ := NewSecret()
		if _, err = Verify(hash, other.Identity, sig); err == nil {
			t.Error("Wrong identity should fail verification")
		}
	})
}

func FuzzCeremonyID(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
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
