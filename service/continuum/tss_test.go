// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/x/tss-lib/v2/common"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/resharing"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v2/tss"
)

func partyUpdate(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	// do not send a message from this party back to itself
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
		return
	}
}

func sign(t *testing.T, curve elliptic.Curve, threshold int, pids tss.SortedPartyIDs, keys []*keygen.LocalPartySaveData, data []byte) error {
	t.Logf("Signing data %v/%v", threshold, len(pids))
	signCtx := tss.NewPeerContext(pids)
	parties := make([]*signing.LocalParty, 0, len(pids))

	errCh := make(chan *tss.Error, len(pids))
	outCh := make(chan tss.Message, len(pids))
	endCh := make(chan *common.SignatureData, len(pids))

	// init the parties
	for i := 0; i < len(pids); i++ {
		params := tss.NewParameters(curve, signCtx, pids[i], len(pids), threshold)
		p := signing.NewLocalParty(new(big.Int).SetBytes(data), params,
			*keys[i], outCh, endCh, len(data)).(*signing.LocalParty)
		parties = append(parties, p)
		go func(party *signing.LocalParty) {
			if err := party.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	signData := make([]*common.SignatureData, 0, len(pids))
	// we use len(pids) to test all sigs but it works with threshold as
	// well. I tested that.
	for done := 0; done != len(pids); {
		select {
		case err := <-errCh:
			return err
		case end := <-endCh:
			signData = append(signData, end)
			done++
			t.Logf("end: threshold %v %v/%v", threshold, done, len(pids))
			break
		case msg := <-outCh:
			dest := msg.GetTo()
			switch dest {
			case nil:
				// broadcast
				t.Logf("broadcast from: %v", msg.GetFrom())
				for _, p := range parties {
					if p.PartyID().Index == msg.GetFrom().Index {
						// skip self
						continue
					}
					go partyUpdate(p, msg, errCh)
				}
			default:
				// send p2p
				if dest[0].Index == msg.GetFrom().Index {
					return fmt.Errorf("party %d send a message self (%d)",
						dest[0].Index, msg.GetFrom().Index)
				}
				t.Logf("p2p: %v -> %v", msg.GetFrom(), dest)
				go partyUpdate(parties[dest[0].Index], msg, errCh)
			}
		}
	}

	// Verify sigs
	for i := 0; i < len(keys); i++ {
		pkX, pkY := keys[i].ECDSAPub.X(), keys[i].ECDSAPub.Y()
		pk := ecdsa.PublicKey{
			Curve: curve,
			X:     pkX,
			Y:     pkY,
		}
		for j := 0; j < len(signData); j++ {
			if !ecdsa.Verify(&pk, data, new(big.Int).SetBytes(signData[j].R),
				new(big.Int).SetBytes(signData[j].S)) {
				// i and j are mixed but all should succeed
				return fmt.Errorf("signer failed: %v %v", i, j)
			}
		}
	}
	return nil
}

func reshare(t *testing.T, curve elliptic.Curve, oldThreshold, newThreshold int, oldPids, newPids tss.SortedPartyIDs, oldKeys []*keygen.LocalPartySaveData) error {
	t.Logf("Resharing data %v/%v -> %v/%v", oldThreshold, len(oldPids),
		newThreshold, len(newPids))

	totalPids := len(oldPids) + len(newPids)
	errCh := make(chan *tss.Error, totalPids)
	outCh := make(chan tss.Message, totalPids)
	endCh := make(chan *keygen.LocalPartySaveData, totalPids)

	// init both party contexts
	oldCtx := tss.NewPeerContext(oldPids)
	newCtx := tss.NewPeerContext(newPids)

	// init old parties
	oldParties := make([]*resharing.LocalParty, 0, len(oldPids))
	for i := 0; i < len(oldPids); i++ {
		params := tss.NewReSharingParameters(curve, oldCtx, newCtx, oldPids[i],
			len(oldPids), oldThreshold, len(newPids), newThreshold)
		p := resharing.NewLocalParty(params, *oldKeys[i], outCh, endCh).(*resharing.LocalParty)
		oldParties = append(oldParties, p)
	}

	// init new parties
	newParties := make([]*resharing.LocalParty, 0, len(newPids))
	for i := 0; i < len(newPids); i++ {
		params := tss.NewReSharingParameters(curve, oldCtx, newCtx, oldPids[i],
			len(oldPids), oldThreshold, len(newPids), newThreshold)

		// XXX DO NOT USE IN UNTRUSTED SETTING
		params.SetNoProofMod()
		params.SetNoProofFac()
		// XXX DO NOT USE IN UNTRUSTED SETTING

		newKeys := keygen.NewLocalPartySaveData(len(newPids))
		panic(spew.Sdump(newPids))
		p := resharing.NewLocalParty(params, newKeys, outCh, endCh).(*resharing.LocalParty)
		newParties = append(newParties, p)
	}

	_ = errCh

	//signData := make([]*common.SignatureData, 0, len(pids))
	//// we use len(pids) to test all sigs but it works with threshold as
	//// well. I tested that.
	//for done := 0; done != len(pids); {
	//	select {
	//	case err := <-errCh:
	//		return err
	//	case end := <-endCh:
	//		signData = append(signData, end)
	//		done++
	//		t.Logf("end: threshold %v %v/%v", threshold, done, len(pids))
	//		break
	//	case msg := <-outCh:
	//		dest := msg.GetTo()
	//		switch dest {
	//		case nil:
	//			// broadcast
	//			t.Logf("broadcast from: %v", msg.GetFrom())
	//			for _, p := range parties {
	//				if p.PartyID().Index == msg.GetFrom().Index {
	//					// skip self
	//					continue
	//				}
	//				go partyUpdate(p, msg, errCh)
	//			}
	//		default:
	//			// send p2p
	//			if dest[0].Index == msg.GetFrom().Index {
	//				return fmt.Errorf("party %d send a message self (%d)",
	//					dest[0].Index, msg.GetFrom().Index)
	//			}
	//			t.Logf("p2p: %v -> %v", msg.GetFrom(), dest)
	//			go partyUpdate(parties[dest[0].Index], msg, errCh)
	//		}
	//	}
	//}

	//// Verify sigs
	//for i := 0; i < len(keys); i++ {
	//	pkX, pkY := keys[i].ECDSAPub.X(), keys[i].ECDSAPub.Y()
	//	pk := ecdsa.PublicKey{
	//		Curve: curve,
	//		X:     pkX,
	//		Y:     pkY,
	//	}
	//	for j := 0; j < len(signData); j++ {
	//		if !ecdsa.Verify(&pk, data, new(big.Int).SetBytes(signData[j].R),
	//			new(big.Int).SetBytes(signData[j].S)) {
	//			// i and j are mixed but all should succeed
	//			return fmt.Errorf("signer failed: %v %v", i, j)
	//		}
	//	}
	//}
	return nil
}

func TestTSS(t *testing.T) {
	var preParams *keygen.LocalPreParams

	// Generate testdata if it does not exist.
	testDataDir := "testdata"
	preparamsFilename := filepath.Join(testDataDir, "preparams.json")
	ppf, err := os.Open(preparamsFilename)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(testDataDir, 0o755); err != nil {
			t.Fatal(err)
		}

		// When using the keygen party it is recommended that you
		// pre-compute the "safe primes" and Paillier secret beforehand
		// because this can take some time.  This code will generate
		// those parameters using a concurrency limit equal to the
		// number of available CPU cores.
		preParams, err = keygen.GeneratePreParamsWithContextAndRandom(t.Context(),
			rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jpp, err := json.MarshalIndent(preParams, "  ", "  ")
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(preparamsFilename, jpp, 0o644)
		if err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	} else {
		var pp keygen.LocalPreParams
		if err := json.NewDecoder(ppf).Decode(&pp); err != nil {
			t.Fatal(err)
		}
	}

	// Create three parties, note that the keys are big.Int however they
	// should be public keys. We will use secp256k1 later in our code.
	//
	// Set up the parameters
	// Note: The `id` and `moniker` fields are for convenience to allow you
	// to easily track participants.
	//
	// The `id` should be a unique string representing this party in the
	// network and `moniker` can be anything (even left blank).
	//
	// The `uniqueKey` is a unique identifying key for this peer (such as
	// its p2p public key) as a big.Int.
	keyAlice := common.MustGetRandomInt(rand.Reader, 256)
	keyBob := common.MustGetRandomInt(rand.Reader, 256)
	keyCharlie := common.MustGetRandomInt(rand.Reader, 256)

	alice := tss.NewPartyID("alice", "alice monicker", keyAlice)
	bob := tss.NewPartyID("bob", "bob monicker", keyBob)
	charlie := tss.NewPartyID("charlie", "charlie monicker", keyCharlie)

	// Parties can be JSON encoded and is the result that all participants
	// should see. Meaning Alice, Bob and Charlie all saw the same
	// participants and sorted them.
	pids := tss.SortPartyIDs(tss.UnSortedPartyIDs{alice, bob, charlie})
	parties := make([]*keygen.LocalParty, 0, len(pids))
	pc := tss.NewPeerContext(pids)

	// Select elliptic curve
	var curve elliptic.Curve
	usesecp256k1 := true
	if usesecp256k1 {
		curve = tss.S256() // secp256k1
	} else {
		curve = tss.Edwards() // ed25519
	}

	// The underlying code uses channels to communicate, each node will
	// have these channels regardless of broadcast. In this example we are
	// going to skip network comms, encryption of the broadcast data and
	// signing of each individual round.
	errCh := make(chan *tss.Error, len(pids))
	outCh := make(chan tss.Message, len(pids))
	endCh := make(chan *keygen.LocalPartySaveData, len(pids))

	// The following code must be executed by all parties.
	threshold := len(pids) - 1
	for i := 0; i < len(pids); i++ {
		var p *keygen.LocalParty
		params := tss.NewParameters(curve, pc, pids[i], len(pids), threshold)
		p = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		parties = append(parties, p)
		go func(party *keygen.LocalParty) {
			t.Logf("start %v", party)
			if err := party.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	// Keygen phase
	keys := make([]*keygen.LocalPartySaveData, len(pids))
	for done := 0; done != len(pids); {
		select {
		case err := <-errCh:
			t.Fatal(err)
		case end := <-endCh:
			index, err := end.OriginalIndex()
			if err != nil {
				t.Fatalf("keygen save data index: %v", err)
			}
			keys[index] = end
			done++
			t.Logf("end: index %v %v/%v", index, done, len(pids))
			break
		case msg := <-outCh:
			dest := msg.GetTo()
			switch dest {
			case nil:
				// broadcast
				t.Logf("broadcast from: %v", msg.GetFrom())
				for _, p := range parties {
					if p.PartyID().Index == msg.GetFrom().Index {
						// skip self
						continue
					}
					go partyUpdate(p, msg, errCh)
				}
			default:
				// send p2p
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d send a message self (%d)",
						dest[0].Index, msg.GetFrom().Index)
				}
				t.Logf("p2p: %v -> %v", msg.GetFrom(), dest)
				go partyUpdate(parties[dest[0].Index], msg, errCh)
			}
		}
	}

	// Let's sign something
	data := []byte("Hello, world!")
	if err := sign(t, curve, threshold, pids, keys, data); err != nil {
		t.Fatal(err)
	}

	// Alice is trash! Replace with Dan and add Erin.
	keyDan := common.MustGetRandomInt(rand.Reader, 256)
	dan := tss.NewPartyID("dan", "dan monicker", keyDan)
	keyErin := common.MustGetRandomInt(rand.Reader, 256)
	erin := tss.NewPartyID("erin", "erin monicker", keyErin)
	newPids := tss.SortPartyIDs(tss.UnSortedPartyIDs{bob, charlie, dan, erin})
	newThreshold := len(newPids) - 1
	// XXX return something here since we are "losing" keys?
	if err := reshare(t, curve, threshold, newThreshold, pids, newPids, keys); err != nil {
		t.Fatal(err)
	}
}
