// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
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

func reshare(t *testing.T, curve elliptic.Curve, oldThreshold, newThreshold int, oldPids, newPids tss.SortedPartyIDs, oldKeys []*keygen.LocalPartySaveData) ([]*keygen.LocalPartySaveData, error) {
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
			len(newPids), oldThreshold, len(newPids), newThreshold)
		p := resharing.NewLocalParty(params, *oldKeys[i], outCh, endCh).(*resharing.LocalParty)
		oldParties = append(oldParties, p)
	}

	// init new parties
	newParties := make([]*resharing.LocalParty, 0, len(newPids))
	for i := 0; i < len(newPids); i++ {
		params := tss.NewReSharingParameters(curve, oldCtx, newCtx, newPids[i],
			len(newPids), oldThreshold, len(newPids), newThreshold)

		// XXX DO NOT USE IN UNTRUSTED SETTING
		// params.SetNoProofMod()
		// params.SetNoProofFac()
		// XXX DO NOT USE IN UNTRUSTED SETTING

		// XXX the local pre params are missing from params
		newKeys := keygen.NewLocalPartySaveData(len(newPids))
		fmt.Printf("reshare %v\n", newPids[i])
		// subset = keygen.BuildLocalSaveDataSubset(key, params.OldParties().IDs())
		// keygen.keysToIndices() = x
		p := resharing.NewLocalParty(params, newKeys, outCh, endCh).(*resharing.LocalParty)
		newParties = append(newParties, p)
	}

	// start the old parties; they will send messages
	for _, P := range oldParties {
		go func(P *resharing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newParties {
		go func(P *resharing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	newKeys := make([]*keygen.LocalPartySaveData, len(newParties))
	for done := 0; done != len(newPids); {
		select {
		case err := <-errCh:
			t.Errorf("Error: %s", err)
			return nil, err
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				return nil, errors.New("did not expect a msg to have a nil destination during resharing")
			}
			if msg.IsToOldAndNewCommittees() {
				t.Logf("broadcast from: %v", msg.GetFrom())
				spew.Dump(dest)
				for _, destP := range dest[:len(oldParties)] {
					go partyUpdate(oldParties[destP.Index], msg, errCh)
				}
				for _, destP := range dest[len(oldParties):] {
					go partyUpdate(newParties[destP.Index], msg, errCh)
				}
				continue
			}

			t.Logf("p2p: %v -> %v", msg.GetFrom(), dest)

			if msg.IsToOldCommittee() {
				for _, destP := range dest[:len(oldParties)] {
					go partyUpdate(oldParties[destP.Index], msg, errCh)
				}
			} else {
				for _, destP := range dest {
					go partyUpdate(newParties[destP.Index], msg, errCh)
				}
			}
		case save := <-endCh:
			// old committee members that aren't receiving a share have their Xi zeroed
			if save.Xi != nil {
				index, err := save.OriginalIndex()
				if err != nil {
					return nil, err
				}
				newKeys[index] = save
				done++
			}
		}
	}
	return newKeys, nil
}

func TestTSS(t *testing.T) {
	var preParams keygen.LocalPreParams

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
		pp, err := keygen.GeneratePreParamsWithContextAndRandom(t.Context(),
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
		preParams = *pp
	} else if err != nil {
		t.Fatal(err)
	} else {
		if err := json.NewDecoder(ppf).Decode(&preParams); err != nil {
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
		// p = keygen.NewLocalParty(params, outCh, endCh, preParams).(*keygen.LocalParty)
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
	newPids := tss.SortPartyIDs(tss.UnSortedPartyIDs{alice, bob, charlie})
	_ = dan
	_ = erin
	//	newPids := tss.SortPartyIDs(tss.UnSortedPartyIDs{dan, erin})
	newThreshold := len(newPids) - 1
	// XXX return something here since we are "losing" keys?
	newKeys, err := reshare(t, curve, threshold, newThreshold, pids, newPids, keys)
	if err != nil {
		t.Fatal(err)
	}

	// Let's sign something
	data = []byte("Bye, world!")
	if err := sign(t, curve, newThreshold, newPids, newKeys, data); err != nil {
		t.Fatal(err)
	}
}

type TSSParty struct {
	LocalPreParams *keygen.LocalPreParams
	PartyID        *tss.PartyID
}

// XXX unexport
type TSSCeremony struct {
	Curve              elliptic.Curve
	Threshold          int
	SortedPartyIDs     tss.SortedPartyIDs
	PeerContext        *tss.PeerContext
	SelfIndex          int
	Party              tss.Party
	LocalPartySaveData *keygen.LocalPartySaveData
}

func TSSNewParty(ctx context.Context, name string) (*TSSParty, error) {
	lpp, err := keygen.GeneratePreParamsWithContextAndRandom(ctx, rand.Reader)
	if err != nil {
		return nil, err
	}

	key := common.MustGetRandomInt(rand.Reader, 256) // XXX this is shit
	return &TSSParty{
		LocalPreParams: lpp,
		PartyID:        tss.NewPartyID(name, name+" monicker", key),
	}, nil
}

func NewTSSCeremony(curve elliptic.Curve, threshold int, parties []*TSSParty) (*TSSCeremony, error) {
	if len(parties) == 0 || threshold > len(parties) {
		return nil, fmt.Errorf("invalid threshold %v/%v", threshold, len(parties))
	}

	upids := make(tss.UnSortedPartyIDs, 0, len(parties))
	for _, v := range parties {
		upids = append(upids, v.PartyID)
	}
	spids := tss.SortPartyIDs(upids)
	return &TSSCeremony{
		Curve:          curve,
		Threshold:      threshold,
		SortedPartyIDs: spids,
		PeerContext:    tss.NewPeerContext(spids),
		SelfIndex:      -1,
	}, nil
}

func (c *TSSCeremony) Start(ctx context.Context, self *TSSParty, outCh chan tss.Message) error {
	// Make sure self is indeed a ceremony memeber
	key := self.PartyID.GetKey()
	for k, v := range c.SortedPartyIDs {
		if bytes.Equal(v.GetKey(), key) {
			c.SelfIndex = k
		}
	}
	if c.SelfIndex < 0 {
		return fmt.Errorf("not a participant: %x", key)
	}

	params := tss.NewParameters(c.Curve, c.PeerContext, self.PartyID,
		len(c.SortedPartyIDs), c.Threshold)
	errCh := make(chan *tss.Error)
	endCh := make(chan *keygen.LocalPartySaveData)
	c.Party = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
	go func() {
		if err := c.Party.Start(); err != nil {
			errCh <- err
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-errCh:
			return err

		case end := <-endCh:
			c.LocalPartySaveData = end
			return nil
		}
	}

	return nil
}

func send(msg tss.Message, index int, p tss.Party) error {
	b, _, err := msg.WireBytes()
	if err != nil {
		return err
	}
	ok, err := p.UpdateFromBytes(b, msg.GetFrom(), msg.IsBroadcast())
	if !ok {
		return fmt.Errorf("update failed %v: %v", index, p)
	}
	return nil
}

func broadcast(t *testing.T, msg tss.Message, ceremonies []*TSSCeremony) error {
	for _, c := range ceremonies {
		if c.SelfIndex == msg.GetFrom().Index {
			// skip self
			continue
		}
		t.Logf("broadcast from: %v updating %v",
			msg.GetFrom(), c.SelfIndex)
		err := send(msg, c.SelfIndex, c.Party)
		if err != nil {
			return err
		}
	}
	return nil
}

func p2p(t *testing.T, msg tss.Message, ceremonies []*TSSCeremony) error {
	// Find correct ceremony
	for _, to := range msg.GetTo() {
		var c *TSSCeremony
		for _, cm := range ceremonies {
			if cm.SelfIndex == to.Index {
				c = cm
				break
			}
		}
		if c == nil {
			return fmt.Errorf("ceremony not found: %v", to.Index)
		}

		t.Logf("%v -> %v", msg.GetFrom(), to)
		err := send(msg, c.SelfIndex, c.Party)
		if err != nil {
			return err
		}

	}
	return nil
}

func handle(t *testing.T, msg tss.Message, ceremonies []*TSSCeremony) error {
	if msg.IsBroadcast() {
		return broadcast(t, msg, ceremonies)
	}
	return p2p(t, msg, ceremonies)
}

func router(t *testing.T, outCh chan tss.Message, ceremonies []*TSSCeremony) error {
	for {
		select {
		case <-t.Context().Done():
			return t.Context().Err()

		case msg := <-outCh:
			if err := handle(t, msg, ceremonies); err != nil {
				return err
			}
		}
	}
}

func TestTSSExhaustive(t *testing.T) {
	parties := []string{"alice", "bob", "charlie"}
	unsortedTSSParties := make([]*TSSParty, 0, len(parties))
	for _, v := range parties {
		party, err := TSSNewParty(t.Context(), v)
		if err != nil {
			t.Fatal(err)
		}
		unsortedTSSParties = append(unsortedTSSParties, party)

		t.Logf("%v: %x", party.PartyID.GetId(), party.PartyID.GetKey())
	}

	// Setup ceremony for all parties, this would come in over continuum to
	// all clients.
	threshold := len(unsortedTSSParties) - 1

	// Select elliptic curve
	var curve elliptic.Curve
	usesecp256k1 := true
	if usesecp256k1 {
		curve = tss.S256() // secp256k1
	} else {
		curve = tss.Edwards() // ed25519
	}

	// Create a ceremony for each participant. Yes, they are identical but
	// this is to simulate individual client machine.
	ceremonies := make([]*TSSCeremony, 0, len(unsortedTSSParties))
	for range unsortedTSSParties {
		ceremony, err := NewTSSCeremony(curve, threshold, unsortedTSSParties)
		if err != nil {
			t.Fatal(err)
		}
		ceremonies = append(ceremonies, ceremony)
	}

	// Launch ceremony for all parties.
	if len(unsortedTSSParties) != len(ceremonies) {
		t.Fatalf("you done fucked up %v != %v", len(unsortedTSSParties),
			len(ceremonies))
	}
	var wg sync.WaitGroup
	outCh := make(chan tss.Message, 10) // coordinator
	for k := range unsortedTSSParties {
		// This is a bit hard to read since we have to call Start with
		// a party to identify ourself.  The the gist is, all
		// ceremonies are identical so we can just iterate over the
		// unsorted array and use the index party as self.
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			c := ceremonies[i]
			self := unsortedTSSParties[i]

			t.Logf("Start: %v", self.PartyID)
			err := c.Start(t.Context(), self, outCh)
			if err != nil {
				panic(err)
			}
		}(k)
	}

	// This simulates network communication
	go router(t, outCh, ceremonies)

	t.Logf("waiting")
	wg.Wait()
}
