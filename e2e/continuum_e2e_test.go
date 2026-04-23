// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build continuum_debug

package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"
	"golang.org/x/sync/errgroup"

	"github.com/hemilabs/heminetwork/v2/service/continuum"
)

// TestTenNodeCeremonyFlow is an e2e test that spins up 10 full
// transfunctioner daemons with constrained connectivity
// (PeersWanted=3), waits for gossip convergence, then runs a
// complete TSS ceremony lifecycle:
//
//  1. Keygen  — committee of 5, threshold 2 (need 3 to sign)
//  2. Sign    — 3 signers from the keygen committee
//  3. Reshare — old committee (5) → new committee (5, partial overlap)
//  4. Sign    — 3 signers from the NEW committee, same key
//  5. Sign    — 3 signers from the NEW committee, different data
//
// The sparse mesh (PeersWanted=3 < committee=5) forces multi-hop
// encrypted envelope delivery for TSS messages between non-adjacent
// committee members, exercising the full crypto stack: v2 wire
// framing, sealed-box e2e encryption, HKDF session salt, and
// keyID-bound TSSStore persistence.
func TestTenNodeCeremonyFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("10-node e2e ceremony test is slow")
	}

	const (
		n            = 10
		peersWanted  = 3 // sparse: most committee pairs lack direct sessions
		threshold    = 2 // t=2, need t+1=3 to sign
		committeeLen = 5
	)

	preParams := loadFixturePreParams(t, n)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	g, gctx := errgroup.WithContext(ctx)

	servers := make([]*continuum.Server, n)
	addrs := make([]string, n)
	secrets := make([]*continuum.Secret, n)

	// Configure package-level logger (init() hardcodes INFO).
	// Chain topology: each node connects to the previous.
	for i := 0; i < n; i++ {
		secret, err := continuum.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		secrets[i] = secret

		home := filepath.Join(t.TempDir(), fmt.Sprintf("node%d", i))
		dataDir := filepath.Join(home, secret.String())
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		// Write cached preparams to avoid slow generation.
		pp, err := json.MarshalIndent(preParams[i], "  ", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, "preparams.json"), pp, 0o400); err != nil {
			t.Fatal(err)
		}

		var connect []string
		if i > 0 {
			connect = []string{addrs[i-1]}
		}

		cfg := continuum.NewDefaultConfig()
		cfg.DNS = "off"
		cfg.Home = home
		cfg.ListenAddress = "localhost:0"
		cfg.LogLevel = "continuum=INFO"
		cfg.PrivateKey = secret.DebugPrivateKeyHex()
		cfg.PeersWanted = peersWanted
		cfg.Connect = connect
		cfg.AdminListenAddress = "localhost:0"
		cfg.MaintainInterval = 10 * time.Minute // chain topology only; no maintain churn
		cfg.InitialPingTimeout = 2 * time.Minute

		server, err := continuum.NewServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		servers[i] = server

		idx := i
		g.Go(func() error { return servers[idx].Run(gctx) })

		addrs[i] = waitForListen(t, servers[i], 5*time.Second)

		t.Logf("node %d: %v at %s", i, servers[i].Identity(), addrs[i])
	}

	// Wait for gossip convergence — all peers known with NaCl
	// pubkeys.  Does NOT require full session connectivity
	// (PeersWanted=3 means sparse mesh).
	waitForGossip(t, servers, n, 90*time.Second)
	t.Log("gossip converged: all 10 nodes know each other")

	// Chain topology provides stable sessions — no maintain churn.

	// Collect identities.
	peerIDs := make([]continuum.Identity, n)
	for i := 0; i < n; i++ {
		peerIDs[i] = servers[i].Identity()
	}

	// Admin transport to inject ceremony RPCs.
	adminSecret, adminTr := adminDial(t, ctx, servers[0])

	// ---------------------------------------------------------------
	// Phase 1: Keygen — committee of 5, threshold 2
	// ---------------------------------------------------------------
	keygenCommittee, _ := continuum.Elect([]byte("e2e-keygen"), peerIDs, committeeLen)
	keygenCID := continuum.NewCeremonyID()
	keygenPartyIDs := continuum.IdentitiesToPartyIDs(keygenCommittee)

	t.Logf("keygen: committee=%d threshold=%d", len(keygenCommittee), threshold)
	for _, dest := range keygenCommittee {
		if err := adminTr.WriteTo(adminSecret.Identity, dest, 12,
			continuum.KeygenRequest{
				CeremonyID:  keygenCID,
				Curve:       "secp256k1",
				Committee:   keygenPartyIDs,
				Threshold:   threshold,
				Coordinator: keygenCommittee[0],
			}); err != nil {
			t.Fatalf("send KeygenRequest to %v: %v", dest, err)
		}
	}
	waitForCeremonyDone(t, servers, keygenCID, 120*time.Second)
	t.Log("phase 1: keygen complete")

	// Find keyID from coordinator's store.
	keyID := findKey(t, servers, keygenCommittee[0])
	t.Logf("keyID: %x", keyID)

	// ---------------------------------------------------------------
	// Phase 2: Sign — 3 signers from keygen committee
	// ---------------------------------------------------------------
	signCommittee1 := keygenCommittee[:threshold+1]
	signCID1 := continuum.NewCeremonyID()
	t.Logf("sign 1: signers=%d", len(signCommittee1))
	sendSign(t, adminTr, adminSecret, signCommittee1, signCID1, keyID,
		hashMsg("first message to sign"), threshold)
	waitForCeremonyDone(t, servers, signCID1, 120*time.Second)
	t.Log("phase 2: sign complete")

	// ---------------------------------------------------------------
	// Phase 3: Reshare — old → new committee (partial overlap)
	// ---------------------------------------------------------------
	newCommittee := buildNewCommittee(t, keygenCommittee, peerIDs, committeeLen, 2)
	oldPartyIDs := continuum.IdentitiesToPartyIDs(keygenCommittee)
	newPartyIDs := continuum.IdentitiesToPartyIDs(newCommittee)
	reshareCID := continuum.NewCeremonyID()

	t.Logf("reshare: old=%d new=%d", len(keygenCommittee), len(newCommittee))
	union := idUnion(keygenCommittee, newCommittee)
	for _, dest := range union {
		if err := adminTr.WriteTo(adminSecret.Identity, dest, 12,
			continuum.ReshareRequest{
				CeremonyID:   reshareCID,
				Curve:        "secp256k1",
				KeyID:        keyID,
				OldCommittee: oldPartyIDs,
				NewCommittee: newPartyIDs,
				OldThreshold: threshold,
				NewThreshold: threshold,
			}); err != nil {
			t.Fatalf("send ReshareRequest to %v: %v", dest, err)
		}
	}
	waitForCeremonyDone(t, servers, reshareCID, 180*time.Second)
	t.Log("phase 3: reshare complete")

	// ---------------------------------------------------------------
	// Phase 4: Sign with NEW committee
	// ---------------------------------------------------------------
	signCommittee2 := newCommittee[:threshold+1]
	signCID2 := continuum.NewCeremonyID()
	t.Logf("sign 2: signers=%d (post-reshare)", len(signCommittee2))
	sendSign(t, adminTr, adminSecret, signCommittee2, signCID2, keyID,
		hashMsg("second message after reshare"), threshold)
	waitForCeremonyDone(t, servers, signCID2, 120*time.Second)
	t.Log("phase 4: post-reshare sign complete")

	// ---------------------------------------------------------------
	// Phase 5: Sign again — different data, proves key is alive
	// ---------------------------------------------------------------
	signCID3 := continuum.NewCeremonyID()
	t.Logf("sign 3: signers=%d (different data)", len(signCommittee2))
	sendSign(t, adminTr, adminSecret, signCommittee2, signCID3, keyID,
		hashMsg("third message proves key is alive"), threshold)
	waitForCeremonyDone(t, servers, signCID3, 120*time.Second)
	t.Log("phase 5: second post-reshare sign complete")

	t.Log("ALL PHASES COMPLETE: keygen → sign → reshare → sign → sign")
	cancel()
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// --- helpers ---

func loadFixturePreParams(t *testing.T, count int) []keygen.LocalPreParams {
	t.Helper()
	data, err := os.ReadFile("../service/continuum/testdata/preparams.json")
	if err != nil {
		t.Fatalf("read preparams fixture: %v", err)
	}
	var params []keygen.LocalPreParams
	if err := json.Unmarshal(data, &params); err != nil {
		t.Fatalf("parse preparams: %v", err)
	}
	if count > len(params) {
		t.Fatalf("need %d preparams, fixture has %d", count, len(params))
	}
	return params[:count]
}

func waitForListen(t *testing.T, s *continuum.Server, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if addr := s.ListenAddress(); addr != "" {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start listening")
	return ""
}

func waitForGossip(t *testing.T, servers []*continuum.Server, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ready := true
		for i := 0; i < n; i++ {
			peers := servers[i].KnownPeers()
			if len(peers) < n {
				ready = false
				break
			}
			for _, pr := range peers {
				if len(pr.NaClPub) != continuum.NaClPubSize {
					ready = false
					break
				}
			}
			if !ready {
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Dump state for debugging.
	for i := 0; i < n; i++ {
		t.Logf("node %d: peers=%d sessions=%d",
			i, servers[i].PeerCount(), len(servers[i].SessionIdentities()))
	}
	t.Fatal("gossip did not converge")
}

// adminDial connects to a node's admin port.  The admin listener
// has no capacity limit and doesn't compete with PeersWanted.
func adminDial(t *testing.T, ctx context.Context, s *continuum.Server) (*continuum.Secret, *continuum.Transport) {
	t.Helper()
	secret, err := continuum.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	addr := waitForAdminListen(t, s, 5*time.Second)
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := new(continuum.Transport)
	if err := tr.KeyExchange(ctx, conn); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, _, err := tr.Handshake(ctx, secret); err != nil {
		tr.Close()
		t.Fatal(err)
	}
	t.Logf("admin connected to %s", addr)
	t.Cleanup(func() { tr.Close() })
	return secret, tr
}

func waitForAdminListen(t *testing.T, s *continuum.Server, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if addr := s.AdminListenAddress(); addr != "" {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("admin listener did not start")
	return ""
}

func waitForCeremonyDone(t *testing.T, servers []*continuum.Server, cid continuum.CeremonyID, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		allDone := true
		for _, s := range servers {
			info := s.CeremonyStatus(cid)
			if info == nil {
				continue // not a participant
			}
			if info.Status == "running" {
				allDone = false
				break
			}
			if info.Status == "failed" {
				t.Fatalf("ceremony %s failed on %v: %s", cid, s.Identity(), info.Error)
			}
		}
		if allDone {
			// Verify at least one node completed.
			for _, s := range servers {
				info := s.CeremonyStatus(cid)
				if info != nil && info.Status == "complete" {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	for i, s := range servers {
		info := s.CeremonyStatus(cid)
		if info != nil {
			t.Logf("node %d: status=%s error=%q", i, info.Status, info.Error)
		}
	}
	t.Fatalf("ceremony %s timed out", cid)
}

func findKey(t *testing.T, servers []*continuum.Server, coord continuum.Identity) []byte {
	t.Helper()
	for _, s := range servers {
		if s.Identity() != coord {
			continue
		}
		keys := s.ListKeyIDs()
		if len(keys) == 0 {
			t.Fatal("no key files on coordinator")
		}
		return keys[0]
	}
	t.Fatal("coordinator not found")
	return nil
}

func sendSign(t *testing.T, adminTr *continuum.Transport, adminSecret *continuum.Secret, committee []continuum.Identity, cid continuum.CeremonyID, keyID []byte, data [32]byte, threshold int) {
	t.Helper()
	partyIDs := continuum.IdentitiesToPartyIDs(committee)
	for _, dest := range committee {
		if err := adminTr.WriteTo(adminSecret.Identity, dest, 12,
			continuum.SignRequest{
				CeremonyID: cid,
				KeyID:      keyID,
				Committee:  partyIDs,
				Threshold:  threshold,
				Data:       data[:],
			}); err != nil {
			t.Fatalf("send SignRequest to %v: %v", dest, err)
		}
	}
}

func buildNewCommittee(t *testing.T, old, all []continuum.Identity, size, overlap int) []continuum.Identity {
	t.Helper()
	used := make(map[continuum.Identity]bool)
	for _, id := range old {
		used[id] = true
	}
	result := make([]continuum.Identity, size)
	copy(result[:overlap], old[len(old)-overlap:])
	idx := overlap
	for _, id := range all {
		if idx >= size {
			break
		}
		if !used[id] {
			result[idx] = id
			idx++
		}
	}
	if idx < size {
		t.Fatalf("cannot fill new committee: got %d, need %d", idx, size)
	}
	return result
}

func idUnion(a, b []continuum.Identity) []continuum.Identity {
	seen := make(map[continuum.Identity]bool)
	var out []continuum.Identity
	for _, id := range a {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range b {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func hashMsg(msg string) [32]byte {
	return sha256.Sum256([]byte(msg))
}
