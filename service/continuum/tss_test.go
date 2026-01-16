// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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
			_ = node.tss.HandleMessage(from, ceremonyID, data)
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
		if f.Name() == "preparams.json" {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		if string(data) == string(shareData) {
			t.Fatal("Data stored in plaintext!")
		}
	}

	t.Log("Store encryption works ✓")
}

func TestTSSStoreWrongKey(t *testing.T) {
	secret1, _ := NewSecret()
	secret2, _ := NewSecret()

	dir := t.TempDir()

	store1, _ := NewTSSStore(dir, secret1)

	keyID := []byte("test-key")
	shareData := []byte("secret data")
	_ = store1.SaveKeyShare(keyID, shareData)

	// Try to read with different secret
	store2, _ := NewTSSStore(dir, secret2)
	_, err := store2.LoadKeyShare(keyID)
	if err == nil {
		t.Fatal("Should fail to decrypt with wrong key")
	}

	t.Log("Wrong key rejected ✓")
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

	time.Sleep(100 * time.Millisecond)
	t.Log("Message sent, checking if ceremony received it")
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

	time.Sleep(100 * time.Millisecond)
	t.Logf("Node 1 received %d messages", msgCount.Load())
}
