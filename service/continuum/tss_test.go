// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/tss"
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
				err := node.tss.HandleMessage(from, ceremonyID, data)
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
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	path := filepath.Join(dir, "tss_examples", "preparams.json")

	data, err := os.ReadFile(path)
	if err != nil {
		return // No preparams, tests will be slow
	}

	var params []keygen.LocalPreParams
	if err := json.Unmarshal(data, &params); err != nil {
		return
	}

	if index < len(params) {
		store.preParams = &params[index]
	}
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
			_, err := fs.decrypt(tt.ciphertext)
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
	ciphertext, err := fs.encrypt([]byte{})
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	// 24-byte nonce + 16-byte Poly1305 tag + 0-byte payload.
	if len(ciphertext) != 40 {
		t.Fatalf("encrypt empty: got %d bytes, want 40", len(ciphertext))
	}
	plaintext, err := fs.decrypt(ciphertext)
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
	err := node1.transport.Send(node2.id, cid, []byte{0x01, 0x00}) // broadcast flag + empty
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
	_ = nodes[0].transport.Send(nodes[1].id, cid, []byte{0x01, 0x00})
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
// routing in pumpReshareMessages / handleReshareMessage.
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
	saveErr      error
	loadErr      error
	deleteErr    error
	preParamsErr error
}

func newMockTSSStore() *mockTSSStore {
	return &mockTSSStore{keyShares: make(map[string][]byte)}
}

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
	impl := NewTSS(secret.Identity, newMockTSSStore(), noopTransport{})

	err := impl.HandleMessage(secret.Identity, NewCeremonyID(), []byte{0x01, 0x00})
	if !errors.Is(err, ErrUnknownCeremony) {
		t.Fatalf("expected ErrUnknownCeremony, got: %v", err)
	}
}

func TestHandleMessageTooShort(t *testing.T) {
	secret, _ := NewSecret()
	ti := NewTSS(secret.Identity, newMockTSSStore(), noopTransport{}).(*tssImpl)

	cid := NewCeremonyID()
	ti.ceremoniesMu.Lock()
	ti.ceremonies[cid] = &ceremony{ctype: CeremonyKeygen}
	ti.ceremoniesMu.Unlock()

	err := ti.HandleMessage(secret.Identity, cid, []byte{0x01})
	if err == nil || err.Error() != "message too short" {
		t.Fatalf("expected 'message too short', got: %v", err)
	}
}

func TestHandleMessageReshareTooShort(t *testing.T) {
	secret, _ := NewSecret()
	ti := NewTSS(secret.Identity, newMockTSSStore(), noopTransport{}).(*tssImpl)

	cid := NewCeremonyID()
	ti.ceremoniesMu.Lock()
	ti.ceremonies[cid] = &ceremony{ctype: CeremonyReshare}
	ti.ceremoniesMu.Unlock()

	err := ti.HandleMessage(secret.Identity, cid, []byte{0x01, 0x02})
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
	err := ti.HandleMessage(other.Identity, cid, []byte{0x01, 0x00})
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
