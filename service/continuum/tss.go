// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hemilabs/x/tss-lib/v2/common"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/resharing"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v2/tss"
	"golang.org/x/crypto/nacl/secretbox"
)

// =============================================================================
// TSS Interface - Clean API hiding tss-lib internals
// =============================================================================

// TSS provides threshold signature operations.
type TSS interface {
	Keygen(ctx context.Context, ceremonyID CeremonyID, parties []Identity, threshold int) (keyID []byte, err error)
	Sign(ctx context.Context, ceremonyID CeremonyID, keyID []byte, parties []Identity, threshold int, data [32]byte) (r, s []byte, err error)
	Reshare(ctx context.Context, ceremonyID CeremonyID, keyID []byte, oldParties, newParties []Identity, oldThreshold, newThreshold int) error
	HandleMessage(from Identity, ceremonyID CeremonyID, data []byte) error
}

// TSSTransport handles outbound message delivery.
type TSSTransport interface {
	Send(to Identity, ceremonyID CeremonyID, data []byte) error
}

// TSSStore handles encrypted key share storage.
type TSSStore interface {
	SaveKeyShare(keyID []byte, share []byte) error
	LoadKeyShare(keyID []byte) ([]byte, error)
	DeleteKeyShare(keyID []byte) error
	GetPreParams() (*keygen.LocalPreParams, error)
}

// =============================================================================
// TSSStore Implementation
// =============================================================================

type fileStore struct {
	dir       string
	encKey    [32]byte
	preParams *keygen.LocalPreParams
	mu        sync.Mutex
}

func NewTSSStore(dir string, secret *Secret) (TSSStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	h := sha256.Sum256(secret.privateKey.Serialize())
	return &fileStore{dir: dir, encKey: h}, nil
}

func (s *fileStore) keyPath(keyID []byte) string {
	return filepath.Join(s.dir, fmt.Sprintf("%x.key", keyID))
}

func (s *fileStore) SaveKeyShare(keyID []byte, share []byte) error {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	encrypted := secretbox.Seal(nonce[:], share, &nonce, &s.encKey)
	return os.WriteFile(s.keyPath(keyID), encrypted, 0o600)
}

func (s *fileStore) LoadKeyShare(keyID []byte) ([]byte, error) {
	encrypted, err := os.ReadFile(s.keyPath(keyID))
	if err != nil {
		return nil, err
	}
	if len(encrypted) < 24 {
		return nil, errors.New("invalid encrypted data")
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &nonce, &s.encKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}
	return decrypted, nil
}

func (s *fileStore) DeleteKeyShare(keyID []byte) error {
	return os.Remove(s.keyPath(keyID))
}

func (s *fileStore) GetPreParams() (*keygen.LocalPreParams, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.preParams != nil {
		return s.preParams, nil
	}
	path := filepath.Join(s.dir, "preparams.json")
	if data, err := os.ReadFile(path); err == nil {
		var pp keygen.LocalPreParams
		if err := json.Unmarshal(data, &pp); err == nil {
			s.preParams = &pp
			return s.preParams, nil
		}
	}
	pp, err := keygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		return nil, err
	}
	if data, err := json.Marshal(pp); err == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
	s.preParams = pp
	return s.preParams, nil
}

// =============================================================================
// TSS Implementation
// =============================================================================

type tssImpl struct {
	store        TSSStore
	transport    TSSTransport
	self         Identity
	ceremonies   map[CeremonyID]*ceremony
	ceremoniesMu sync.Mutex
}

type ceremony struct {
	ctype     CeremonyType
	party     tss.Party
	pids      tss.SortedPartyIDs
	pidToID   map[string]Identity
	outCh     chan tss.Message
	endCh     chan any
	errCh     chan error
	done      chan struct{}
	threshold int
	keyID     []byte
}

func NewTSS(self Identity, store TSSStore, transport TSSTransport) TSS {
	return &tssImpl{
		store:      store,
		transport:  transport,
		self:       self,
		ceremonies: make(map[CeremonyID]*ceremony),
	}
}

func (t *tssImpl) Keygen(ctx context.Context, ceremonyID CeremonyID, parties []Identity, threshold int) ([]byte, error) {
	preParams, err := t.store.GetPreParams()
	if err != nil {
		return nil, fmt.Errorf("get preparams: %w", err)
	}

	pids, ourPid, pidToID, err := t.buildPartyContext(parties)
	if err != nil {
		return nil, err
	}

	peerCtx := tss.NewPeerContext(pids)
	params := tss.NewParameters(tss.S256(), peerCtx, ourPid, len(pids), threshold)

	outCh := make(chan tss.Message, len(pids)*10)
	endCh := make(chan *keygen.LocalPartySaveData, 1)

	party := keygen.NewLocalParty(params, outCh, endCh, *preParams).(*keygen.LocalParty)

	c := &ceremony{
		ctype:     CeremonyKeygen,
		party:     party,
		pids:      pids,
		pidToID:   pidToID,
		outCh:     outCh,
		endCh:     make(chan any, 1),
		errCh:     make(chan error, 1),
		done:      make(chan struct{}),
		threshold: threshold,
	}

	t.ceremoniesMu.Lock()
	t.ceremonies[ceremonyID] = c
	t.ceremoniesMu.Unlock()

	defer func() {
		t.ceremoniesMu.Lock()
		delete(t.ceremonies, ceremonyID)
		t.ceremoniesMu.Unlock()
	}()

	go t.pumpMessages(ceremonyID, c)
	go func() {
		select {
		case save := <-endCh:
			c.endCh <- save
		case <-c.done:
		}
	}()

	if err := party.Start(); err != nil {
		return nil, fmt.Errorf("start keygen: %w", err.Cause())
	}

	select {
	case <-ctx.Done():
		close(c.done)
		return nil, ctx.Err()
	case err := <-c.errCh:
		close(c.done)
		return nil, err
	case result := <-c.endCh:
		close(c.done)
		save := result.(*keygen.LocalPartySaveData)
		keyID := sha256.Sum256(save.ECDSAPub.X().Bytes())
		shareData, err := json.Marshal(save)
		if err != nil {
			return nil, fmt.Errorf("marshal key share: %w", err)
		}
		if err := t.store.SaveKeyShare(keyID[:16], shareData); err != nil {
			return nil, fmt.Errorf("save key share: %w", err)
		}
		return keyID[:16], nil
	}
}

func (t *tssImpl) Sign(ctx context.Context, ceremonyID CeremonyID, keyID []byte, parties []Identity, threshold int, data [32]byte) ([]byte, []byte, error) {
	shareData, err := t.store.LoadKeyShare(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("load key share: %w", err)
	}

	var keyShare keygen.LocalPartySaveData
	if err := json.Unmarshal(shareData, &keyShare); err != nil {
		return nil, nil, fmt.Errorf("unmarshal key share: %w", err)
	}

	pids, ourPid, pidToID, err := t.buildPartyContext(parties)
	if err != nil {
		return nil, nil, err
	}

	peerCtx := tss.NewPeerContext(pids)
	params := tss.NewParameters(tss.S256(), peerCtx, ourPid, len(pids), threshold)

	outCh := make(chan tss.Message, len(pids)*10)
	endCh := make(chan *common.SignatureData, 1)

	party := signing.NewLocalParty(new(big.Int).SetBytes(data[:]), params, keyShare, outCh, endCh, 32).(*signing.LocalParty)

	c := &ceremony{
		ctype:     CeremonySign,
		party:     party,
		pids:      pids,
		pidToID:   pidToID,
		outCh:     outCh,
		endCh:     make(chan any, 1),
		errCh:     make(chan error, 1),
		done:      make(chan struct{}),
		threshold: threshold,
		keyID:     keyID,
	}

	t.ceremoniesMu.Lock()
	t.ceremonies[ceremonyID] = c
	t.ceremoniesMu.Unlock()

	defer func() {
		t.ceremoniesMu.Lock()
		delete(t.ceremonies, ceremonyID)
		t.ceremoniesMu.Unlock()
	}()

	go t.pumpMessages(ceremonyID, c)
	go func() {
		select {
		case sig := <-endCh:
			c.endCh <- sig
		case <-c.done:
		}
	}()

	if err := party.Start(); err != nil {
		return nil, nil, fmt.Errorf("start signing: %w", err.Cause())
	}

	select {
	case <-ctx.Done():
		close(c.done)
		return nil, nil, ctx.Err()
	case err := <-c.errCh:
		close(c.done)
		return nil, nil, err
	case result := <-c.endCh:
		close(c.done)
		sig := result.(*common.SignatureData)
		return sig.R, sig.S, nil
	}
}

func (t *tssImpl) Reshare(ctx context.Context, ceremonyID CeremonyID, keyID []byte, oldParties, newParties []Identity, oldThreshold, newThreshold int) error {
	shareData, err := t.store.LoadKeyShare(keyID)
	if err != nil {
		return fmt.Errorf("load key share: %w", err)
	}

	var keyShare keygen.LocalPartySaveData
	if err := json.Unmarshal(shareData, &keyShare); err != nil {
		return fmt.Errorf("unmarshal key share: %w", err)
	}

	oldPids, _, oldPidToID, err := t.buildPartyContext(oldParties)
	if err != nil {
		return fmt.Errorf("build old context: %w", err)
	}

	newPids, ourNewPid, newPidToID, err := t.buildPartyContext(newParties)
	if err != nil {
		return fmt.Errorf("build new context: %w", err)
	}

	oldCtx := tss.NewPeerContext(oldPids)
	newCtx := tss.NewPeerContext(newPids)
	params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx, ourNewPid,
		len(oldPids), oldThreshold, len(newPids), newThreshold)

	outCh := make(chan tss.Message, (len(oldPids)+len(newPids))*10)
	endCh := make(chan *keygen.LocalPartySaveData, 1)

	party := resharing.NewLocalParty(params, keyShare, outCh, endCh).(*resharing.LocalParty)

	allPids := make(tss.SortedPartyIDs, 0, len(oldPids)+len(newPids))
	allPids = append(allPids, oldPids...)
	allPids = append(allPids, newPids...)

	allPidToID := make(map[string]Identity)
	for k, v := range oldPidToID {
		allPidToID[k] = v
	}
	for k, v := range newPidToID {
		allPidToID[k] = v
	}

	c := &ceremony{
		ctype:     CeremonyReshare,
		party:     party,
		pids:      allPids,
		pidToID:   allPidToID,
		outCh:     outCh,
		endCh:     make(chan any, 1),
		errCh:     make(chan error, 1),
		done:      make(chan struct{}),
		threshold: newThreshold,
		keyID:     keyID,
	}

	t.ceremoniesMu.Lock()
	t.ceremonies[ceremonyID] = c
	t.ceremoniesMu.Unlock()

	defer func() {
		t.ceremoniesMu.Lock()
		delete(t.ceremonies, ceremonyID)
		t.ceremoniesMu.Unlock()
	}()

	go t.pumpMessages(ceremonyID, c)
	go func() {
		select {
		case save := <-endCh:
			c.endCh <- save
		case <-c.done:
		}
	}()

	if err := party.Start(); err != nil {
		return fmt.Errorf("start resharing: %w", err.Cause())
	}

	select {
	case <-ctx.Done():
		close(c.done)
		return ctx.Err()
	case err := <-c.errCh:
		close(c.done)
		return err
	case result := <-c.endCh:
		close(c.done)
		save := result.(*keygen.LocalPartySaveData)
		newShareData, err := json.Marshal(save)
		if err != nil {
			return fmt.Errorf("marshal new key share: %w", err)
		}
		if err := t.store.SaveKeyShare(keyID, newShareData); err != nil {
			return fmt.Errorf("save new key share: %w", err)
		}
		return nil
	}
}

func (t *tssImpl) HandleMessage(from Identity, ceremonyID CeremonyID, data []byte) error {
	t.ceremoniesMu.Lock()
	c, ok := t.ceremonies[ceremonyID]
	t.ceremoniesMu.Unlock()

	if !ok {
		return errors.New("unknown ceremony")
	}

	fromIDStr := from.String()
	var fromPid *tss.PartyID
	for _, pid := range c.pids {
		if pid.Id == fromIDStr {
			fromPid = pid
			break
		}
	}
	if fromPid == nil {
		return errors.New("sender not in ceremony")
	}

	if len(data) < 2 {
		return errors.New("message too short")
	}
	isBroadcast := data[0] == 0x01
	wireData := data[1:]

	parsed, err := tss.ParseWireMessage(wireData, fromPid, isBroadcast)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}

	// tss-lib update errors are non-fatal (e.g., duplicate messages)
	_, _ = c.party.Update(parsed)

	return nil
}

func (t *tssImpl) buildPartyContext(parties []Identity) (tss.SortedPartyIDs, *tss.PartyID, map[string]Identity, error) {
	pids := make([]*tss.PartyID, len(parties))
	pidToID := make(map[string]Identity)
	for i, id := range parties {
		idStr := id.String()
		pids[i] = tss.NewPartyID(idStr, idStr, new(big.Int).SetBytes(id[:]))
		pidToID[idStr] = id
	}

	sorted := tss.SortPartyIDs(pids)

	selfStr := t.self.String()
	var ourPid *tss.PartyID
	for _, pid := range sorted {
		if pid.Id == selfStr {
			ourPid = pid
			break
		}
	}
	if ourPid == nil {
		return nil, nil, nil, errors.New("self not in party list")
	}

	return sorted, ourPid, pidToID, nil
}

func (t *tssImpl) pumpMessages(ceremonyID CeremonyID, c *ceremony) {
	for {
		select {
		case msg := <-c.outCh:
			wireData, _, err := msg.WireBytes()
			if err != nil {
				continue
			}

			// Prepend broadcast flag: 0x01 = broadcast, 0x00 = p2p
			var data []byte
			if msg.GetTo() == nil {
				data = append([]byte{0x01}, wireData...)
				for _, pid := range c.pids {
					if pid.Id == t.self.String() {
						continue
					}
					to := c.pidToID[pid.Id]
					_ = t.transport.Send(to, ceremonyID, data)
				}
			} else {
				data = append([]byte{0x00}, wireData...)
				for _, dest := range msg.GetTo() {
					to := c.pidToID[dest.Id]
					_ = t.transport.Send(to, ceremonyID, data)
				}
			}

		case <-c.done:
			return
		}
	}
}
