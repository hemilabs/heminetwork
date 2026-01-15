// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tss_examples

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"fmt"
	"testing"
	"time"

	"github.com/hemilabs/x/tss-lib/v2/common"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/resharing"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v2/tss"
)

// PartyIdentity represents a party's persistent identity.
// The TSSKey rotates with each reshare, but PubKey stays constant.
type PartyIdentity struct {
	PubKey string   // Persistent identity (e.g., compressed secp256k1 pubkey)
	Name   string   // Human-readable name
	TSSKey *big.Int // Rotates each reshare - used for tss-lib routing
}

// NewPartyIdentity creates a new party identity with a random TSSKey.
func NewPartyIdentity(pubKey, name string) *PartyIdentity {
	return &PartyIdentity{
		PubKey: pubKey,
		Name:   name,
		TSSKey: common.MustGetRandomInt(rand.Reader, 256),
	}
}

// RotateKey generates a new TSSKey for resharing.
// This makes the party appear as a "new" party to tss-lib while
// maintaining the same persistent identity.
func (p *PartyIdentity) RotateKey() {
	p.TSSKey = common.MustGetRandomInt(rand.Reader, 256)
}

// ToPartyID converts to tss-lib PartyID.
// id = persistent pubkey, moniker = name, key = rotating TSSKey
func (p *PartyIdentity) ToPartyID() *tss.PartyID {
	return tss.NewPartyID(p.PubKey, p.Name, p.TSSKey)
}

// partyUpdate routes a message to a party.
func partyUpdate(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	if party.PartyID() == msg.GetFrom() {
		return
	}
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}

// doKeygen performs distributed key generation.
func doKeygen(t *testing.T, curve *tss.Parameters, threshold int, pids tss.SortedPartyIDs, preParams []keygen.LocalPreParams) ([]*keygen.LocalPartySaveData, error) {
	t.Logf("Keygen: %d-of-%d", threshold+1, len(pids))

	pc := tss.NewPeerContext(pids)
	parties := make([]*keygen.LocalParty, 0, len(pids))

	errCh := make(chan *tss.Error, len(pids))
	outCh := make(chan tss.Message, len(pids)*len(pids))
	endCh := make(chan *keygen.LocalPartySaveData, len(pids))

	for i := 0; i < len(pids); i++ {
		params := tss.NewParameters(curve.EC(), pc, pids[i], len(pids), threshold)
		var p *keygen.LocalParty
		if preParams != nil && i < len(preParams) {
			p = keygen.NewLocalParty(params, outCh, endCh, preParams[i]).(*keygen.LocalParty)
		} else {
			p = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		}
		parties = append(parties, p)
		go func(party *keygen.LocalParty) {
			if err := party.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	keys := make([]*keygen.LocalPartySaveData, len(pids))
	for done := 0; done < len(pids); {
		select {
		case err := <-errCh:
			return nil, err.Cause()
		case end := <-endCh:
			index, err := end.OriginalIndex()
			if err != nil {
				return nil, err
			}
			keys[index] = end
			done++
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, p := range parties {
					if p.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go partyUpdate(p, msg, errCh)
				}
			} else {
				go partyUpdate(parties[dest[0].Index], msg, errCh)
			}
		}
	}

	return keys, nil
}

// doSign performs threshold signing and returns signature data from all participants.
func doSign(t *testing.T, curve *tss.Parameters, threshold int, pids tss.SortedPartyIDs, keys []*keygen.LocalPartySaveData, data []byte) ([]*common.SignatureData, error) {
	t.Logf("Signing: %d-of-%d", threshold+1, len(pids))

	signCtx := tss.NewPeerContext(pids)
	parties := make([]*signing.LocalParty, 0, len(pids))

	errCh := make(chan *tss.Error, len(pids))
	outCh := make(chan tss.Message, len(pids)*len(pids))
	endCh := make(chan *common.SignatureData, len(pids))

	for i := 0; i < len(pids); i++ {
		params := tss.NewParameters(curve.EC(), signCtx, pids[i], len(pids), threshold)
		p := signing.NewLocalParty(new(big.Int).SetBytes(data), params,
			*keys[i], outCh, endCh, len(data)).(*signing.LocalParty)
		parties = append(parties, p)
		go func(party *signing.LocalParty) {
			if err := party.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	sigs := make([]*common.SignatureData, 0, len(pids))
	for done := 0; done < len(pids); {
		select {
		case err := <-errCh:
			return nil, err.Cause()
		case sig := <-endCh:
			sigs = append(sigs, sig)
			done++
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, p := range parties {
					if p.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go partyUpdate(p, msg, errCh)
				}
			} else {
				go partyUpdate(parties[dest[0].Index], msg, errCh)
			}
		}
	}

	return sigs, nil
}

// doSignAndVerify performs signing and verifies each signature with ECDSA.
func doSignAndVerify(t *testing.T, curve *tss.Parameters, threshold int, pids tss.SortedPartyIDs, keys []*keygen.LocalPartySaveData, data []byte) error {
	sigs, err := doSign(t, curve, threshold, pids, keys, data)
	if err != nil {
		return err
	}

	// Get public key from any key share (they all have the same)
	pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
	pk := ecdsa.PublicKey{
		Curve: curve.EC(),
		X:     pkX,
		Y:     pkY,
	}

	// Verify each signature
	for i, sig := range sigs {
		r := new(big.Int).SetBytes(sig.R)
		s := new(big.Int).SetBytes(sig.S)
		if !ecdsa.Verify(&pk, data, r, s) {
			t.Errorf("Signature %d failed verification", i)
			return err
		}
	}
	t.Logf("All %d signatures verified ✓", len(sigs))

	return nil
}

// doReshare performs key resharing from old committee to new committee.
func doReshare(t *testing.T, curve *tss.Parameters, oldThreshold, newThreshold int, oldPids, newPids tss.SortedPartyIDs, oldKeys []*keygen.LocalPartySaveData) ([]*keygen.LocalPartySaveData, error) {
	t.Logf("Resharing: %d-of-%d -> %d-of-%d", oldThreshold+1, len(oldPids), newThreshold+1, len(newPids))

	// Verify committees are disjoint (by key, not by identity)
	oldKeySet := make(map[string]bool)
	for _, pid := range oldPids {
		oldKeySet[string(pid.GetKey())] = true
	}
	for _, pid := range newPids {
		if oldKeySet[string(pid.GetKey())] {
			t.Fatalf("Party %s has same TSSKey in both committees - must rotate keys for overlap", pid.GetId())
		}
	}

	oldCtx := tss.NewPeerContext(oldPids)
	newCtx := tss.NewPeerContext(newPids)

	oldPartyByKey := make(map[string]*resharing.LocalParty)
	newPartyByKey := make(map[string]*resharing.LocalParty)

	errCh := make(chan *tss.Error, (len(oldPids)+len(newPids))*4)
	outCh := make(chan tss.Message, (len(oldPids)+len(newPids))*20)
	endCh := make(chan *keygen.LocalPartySaveData, len(oldPids)+len(newPids))

	// Initialize old committee parties
	for i, pid := range oldPids {
		params := tss.NewReSharingParameters(curve.EC(), oldCtx, newCtx, pid,
			len(oldPids), oldThreshold, len(newPids), newThreshold)
		p := resharing.NewLocalParty(params, *oldKeys[i], outCh, endCh).(*resharing.LocalParty)
		oldPartyByKey[string(pid.GetKey())] = p
	}

	// Initialize new committee parties
	for _, pid := range newPids {
		key := string(pid.GetKey())
		params := tss.NewReSharingParameters(curve.EC(), oldCtx, newCtx, pid,
			len(oldPids), oldThreshold, len(newPids), newThreshold)
		params.SetNoProofMod()
		params.SetNoProofFac()

		save := keygen.NewLocalPartySaveData(len(newPids))
		p := resharing.NewLocalParty(params, save, outCh, endCh).(*resharing.LocalParty)
		newPartyByKey[key] = p
	}

	// Start all parties
	for _, p := range oldPartyByKey {
		go func(party *resharing.LocalParty) {
			if err := party.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}
	for _, p := range newPartyByKey {
		go func(party *resharing.LocalParty) {
			if err := party.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	newKeys := make([]*keygen.LocalPartySaveData, len(newPids))
	endedNew := 0

	timeout := time.After(5 * time.Minute)
	for endedNew < len(newPids) {
		select {
		case <-timeout:
			return nil, context.DeadlineExceeded
		case err := <-errCh:
			return nil, err.Cause()

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				continue
			}

			fromKey := string(msg.GetFrom().GetKey())

			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destPID := range dest {
					destKey := string(destPID.GetKey())
					if p, ok := oldPartyByKey[destKey]; ok {
						if destKey == fromKey {
							continue
						}
						go partyUpdateByKey(p, msg, errCh)
					}
				}
			}

			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destPID := range dest {
					destKey := string(destPID.GetKey())
					if p, ok := newPartyByKey[destKey]; ok {
						go partyUpdateByKey(p, msg, errCh)
					}
				}
			}

		case save := <-endCh:
			if save.Xi != nil {
				index, err := save.OriginalIndex()
				if err != nil {
					return nil, err
				}
				newKeys[index] = save
				endedNew++
			}
		}
	}

	return newKeys, nil
}

// partyUpdateByKey routes a message without self-check (for resharing).
func partyUpdateByKey(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	wireBytes, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}

	parsedMsg, err := tss.ParseWireMessage(wireBytes, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}

	if _, err := party.Update(parsedMsg); err != nil {
		errCh <- err
	}
}

// loadOrGeneratePreParams loads preparams from file or generates them.
func loadOrGeneratePreParams(t *testing.T, count int) []keygen.LocalPreParams {
	// Find the preparams file relative to this test file
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	path := filepath.Join(dir, "preparams.json")

	// Try to load existing
	if data, err := os.ReadFile(path); err == nil {
		var params []keygen.LocalPreParams
		if err := json.Unmarshal(data, &params); err == nil {
			if len(params) >= count {
				t.Logf("Loaded %d preparams from %s", count, path)
				return params[:count]
			}
			t.Logf("Found %d preparams, need %d - generating more...", len(params), count)
		}
	}

	// Generate what we need (slow, ~30s each)
	t.Logf("Generating %d preparams (this takes a while)...", count)
	params := make([]keygen.LocalPreParams, count)

	// Parallelize generation
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, runtime.NumCPU())

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pp, err := keygen.GeneratePreParams(5 * time.Minute)
			if err != nil {
				t.Errorf("Failed to generate preparam %d: %v", idx, err)
				return
			}

			mu.Lock()
			params[idx] = *pp
			generated := 0
			for _, p := range params {
				if p.PaillierSK != nil && p.PaillierSK.N != nil {
					generated++
				}
			}
			t.Logf("Generated %d/%d preparams", generated, count)
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Save for next time
	data, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		t.Logf("Warning: failed to marshal preparams: %v", err)
	} else if err := os.WriteFile(path, data, 0644); err != nil {
		t.Logf("Warning: failed to save preparams to %s: %v", path, err)
	} else {
		t.Logf("Saved %d preparams to %s", count, path)
	}

	return params
}

// verifyPublicKeyPreserved checks that all key shares have the same public key.
func verifyPublicKeyPreserved(t *testing.T, keys []*keygen.LocalPartySaveData, expectedX *big.Int) {
	for i, key := range keys {
		if key.ECDSAPub.X().Cmp(expectedX) != 0 {
			t.Fatalf("Key %d has different public key X", i)
		}
	}
}

// verifyAllKeysMatch checks that all key shares derive the same public key.
func verifyAllKeysMatch(t *testing.T, keys []*keygen.LocalPartySaveData) *big.Int {
	if len(keys) == 0 {
		t.Fatal("No keys provided")
	}

	expectedX := keys[0].ECDSAPub.X()
	expectedY := keys[0].ECDSAPub.Y()

	for i, key := range keys {
		if key.ECDSAPub.X().Cmp(expectedX) != 0 || key.ECDSAPub.Y().Cmp(expectedY) != 0 {
			t.Fatalf("Key %d has different public key", i)
		}
	}

	t.Logf("All %d keys have matching public key ✓", len(keys))
	return expectedX
}

// buildKeyLookup creates a map from party identity to key share.
func buildKeyLookup(pids tss.SortedPartyIDs, keys []*keygen.LocalPartySaveData) map[string]*keygen.LocalPartySaveData {
	m := make(map[string]*keygen.LocalPartySaveData)
	for i, pid := range pids {
		m[pid.GetId()] = keys[i]
	}
	return m
}

// selectKeys extracts keys for a subset of parties.
func selectKeys(pids tss.SortedPartyIDs, keyLookup map[string]*keygen.LocalPartySaveData) []*keygen.LocalPartySaveData {
	keys := make([]*keygen.LocalPartySaveData, len(pids))
	for i, pid := range pids {
		keys[i] = keyLookup[pid.GetId()]
		if keys[i] == nil {
			panic("key not found for " + pid.GetId())
		}
	}
	return keys
}

// curveParams returns tss parameters for secp256k1.
func curveParams() *tss.Parameters {
	// Create a dummy parameters just to get the curve
	dummyPid := tss.NewPartyID("dummy", "dummy", big.NewInt(1))
	pids := tss.SortPartyIDs([]*tss.PartyID{dummyPid})
	pc := tss.NewPeerContext(pids)
	return tss.NewParameters(tss.S256(), pc, dummyPid, 1, 0)
}

// createParties creates n party identities with names party_000, party_001, etc.
func createParties(n int) []*PartyIdentity {
	parties := make([]*PartyIdentity, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("party_%03d", i)
		pubKey := fmt.Sprintf("02%s_pubkey", name)
		parties[i] = NewPartyIdentity(pubKey, name)
	}
	return parties
}

// partiesToPids converts party identities to sorted party IDs.
func partiesToPids(parties []*PartyIdentity) tss.SortedPartyIDs {
	pids := make([]*tss.PartyID, len(parties))
	for i, p := range parties {
		pids[i] = p.ToPartyID()
	}
	return tss.SortPartyIDs(pids)
}
