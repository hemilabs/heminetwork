// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v3/tss"
)

// loadPreParams reads cached Paillier preparams from the test fixtures
// directory so keygen doesn't spend ~30s per node generating them.
func loadPreParams(t *testing.T, count int) []keygen.LocalPreParams {
	t.Helper()
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
	hash := HashTSSMessage(msg.CeremonyID, msg.Data)
	if _, err := Verify(hash, msg.From, msg.Signature); err != nil {
		n.t.Logf("node %s: bad sig from %s: %v",
			n.id, msg.From, err)
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

func rpcInitReshare(
	t *testing.T,
	nodes []*rpcTSSNode,
	oldCommittee, newCommittee tss.UnSortedPartyIDs,
	cid CeremonyID,
	keyID []byte,
	oldThreshold, newThreshold int,
) {
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
func rpcSigningCommittee(
	t *testing.T,
	nodes []*rpcTSSNode,
	keyID []byte,
) tss.UnSortedPartyIDs {
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
	pubKey := &ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     new(big.Int).SetBytes(meta.PublicKey[:32]),
		Y:     new(big.Int).SetBytes(meta.PublicKey[32:]),
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
		rInt := new(big.Int).SetBytes(r)
		sInt := new(big.Int).SetBytes(s)
		if !ecdsa.Verify(pubKey, data[:], rInt, sInt) {
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
	pubKey := &ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     new(big.Int).SetBytes(meta.PublicKey[:32]),
		Y:     new(big.Int).SetBytes(meta.PublicKey[32:]),
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
		rInt := new(big.Int).SetBytes(r)
		sInt := new(big.Int).SetBytes(s)
		if !ecdsa.Verify(pubKey, data[:], rInt, sInt) {
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
			hash := HashTSSMessage(msg.CeremonyID, msg.Data)
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
	hash := HashTSSMessage(cid, fakeData)
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

		hash := HashTSSMessage(cid, data)
		sig := secret.Sign(hash)

		if _, err = Verify(hash, secret.Identity, sig); err != nil {
			t.Errorf("Valid signature rejected: %v", err)
		}

		if len(data) > 0 {
			tampered := make([]byte, len(data))
			copy(tampered, data)
			tampered[0] ^= 0xFF

			tamperedHash := HashTSSMessage(cid, tampered)
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
