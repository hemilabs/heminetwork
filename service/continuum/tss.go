// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hemilabs/x/tss-lib/v2/common"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/resharing"
	"github.com/hemilabs/x/tss-lib/v2/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v2/tss"
	"golang.org/x/crypto/hkdf"
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
	Close() error
	SaveKeyShare(keyID []byte, share []byte) error
	LoadKeyShare(keyID []byte) ([]byte, error)
	DeleteKeyShare(keyID []byte) error
	GetPreParams(ctx context.Context) (*keygen.LocalPreParams, error)
	SetPreParams(pp *keygen.LocalPreParams)

	// Key metadata — persists committee and threshold alongside
	// key shares so reshare can discover the old committee
	// automatically.
	SaveKeyMetadata(keyID []byte, meta *KeyMetadata) error
	LoadKeyMetadata(keyID []byte) (*KeyMetadata, error)
	ListKeys() ([][]byte, error)
}

// KeyMetadata records the committee, threshold, and public key
// associated with a TSS key share.  Populated at keygen completion,
// updated at reshare completion (new committee, new threshold).
// Persisted alongside the key share so reshare can discover the
// old committee automatically without operator input.
type KeyMetadata struct {
	Committee []Identity `json:"committee"`
	Threshold int        `json:"threshold"`
	KeyID     []byte     `json:"key_id"`
	PublicKey []byte     `json:"public_key"`
	CreatedAt time.Time  `json:"created_at"`
}

// =============================================================================
// TSSStore Implementation
// =============================================================================

// Store encryption errors.  Use errors.Is to distinguish decryption
// failures (wrong key, tampered data) from I/O errors.
var (
	errInvalidCiphertext = errors.New("invalid ciphertext")
	errDecryptionFailed  = errors.New("decryption failed")
)

type fileStore struct {
	dir       string
	encKey    [32]byte
	preParams *keygen.LocalPreParams
	mu        sync.Mutex
}

// Close zeros the encryption key to limit exposure in swap files
// and core dumps.
func (s *fileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.encKey {
		s.encKey[i] = 0
	}
	s.preParams = nil
	return nil
}

func NewTSSStore(dir string, secret *Secret) (TSSStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Derive encryption key from the signing key using HKDF with
	// domain separation.  The salt matches the transport layer
	// constant; the info string is unique to the store.
	var encKey [32]byte
	r := hkdf.New(sha256.New, secret.privateKey.Serialize(),
		[]byte("continuum-hkdf-salt-v1"), []byte("continuum-store-v1"))
	if _, err := io.ReadFull(r, encKey[:]); err != nil {
		return nil, fmt.Errorf("derive store key: %w", err)
	}
	return &fileStore{dir: dir, encKey: encKey}, nil
}

func (s *fileStore) keyPath(keyID []byte) string {
	return filepath.Join(s.dir, fmt.Sprintf("%x.key", keyID))
}

func (s *fileStore) encrypt(plaintext []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// Seal appends ciphertext to nonce[:].  The slice has len=24,
	// cap=24, so Go allocates a fresh backing array for the output.
	// The &nonce pointer still references the stack array for the
	// actual encryption.  No aliasing — but do not pre-grow nonce's
	// capacity or the output overwrites the nonce in-place.
	return secretbox.Seal(nonce[:], plaintext, &nonce, &s.encKey), nil
}

func (s *fileStore) decrypt(ciphertext []byte) ([]byte, error) {
	// Minimum: 24-byte nonce + secretbox.Overhead (16-byte Poly1305 tag).
	if len(ciphertext) < 24+secretbox.Overhead {
		return nil, errInvalidCiphertext
	}
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])
	decrypted, ok := secretbox.Open(nil, ciphertext[24:], &nonce, &s.encKey)
	if !ok {
		return nil, errDecryptionFailed
	}
	return decrypted, nil
}

func (s *fileStore) SaveKeyShare(keyID []byte, share []byte) error {
	log.Tracef("SaveKeyShare %x", keyID)
	encrypted, err := s.encrypt(share)
	if err != nil {
		return err
	}
	return os.WriteFile(s.keyPath(keyID), encrypted, 0o600)
}

func (s *fileStore) LoadKeyShare(keyID []byte) ([]byte, error) {
	log.Tracef("LoadKeyShare %x", keyID)
	encrypted, err := os.ReadFile(s.keyPath(keyID))
	if err != nil {
		return nil, err
	}
	return s.decrypt(encrypted)
}

func (s *fileStore) DeleteKeyShare(keyID []byte) error {
	log.Tracef("DeleteKeyShare %x", keyID)
	return os.Remove(s.keyPath(keyID))
}

func (s *fileStore) metaPath(keyID []byte) string {
	return filepath.Join(s.dir, fmt.Sprintf("%x.meta", keyID))
}

// SaveKeyMetadata encrypts and persists key metadata alongside
// the key share file.
func (s *fileStore) SaveKeyMetadata(keyID []byte, meta *KeyMetadata) error {
	log.Tracef("SaveKeyMetadata %x", keyID)
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	encrypted, err := s.encrypt(data)
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(keyID), encrypted, 0o600)
}

// LoadKeyMetadata decrypts and returns key metadata for the given
// keyID.  Returns os.ErrNotExist if no metadata file exists.
func (s *fileStore) LoadKeyMetadata(keyID []byte) (*KeyMetadata, error) {
	log.Tracef("LoadKeyMetadata %x", keyID)
	encrypted, err := os.ReadFile(s.metaPath(keyID))
	if err != nil {
		return nil, err
	}
	data, err := s.decrypt(encrypted)
	if err != nil {
		return nil, err
	}
	var meta KeyMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	return &meta, nil
}

// ListKeys scans the store directory for key share files and
// returns their keyIDs.
func (s *fileStore) ListKeys() ([][]byte, error) {
	log.Tracef("ListKeys")
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var keys [][]byte //nolint:prealloc // unknown entry count after filtering
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".key") {
			continue
		}
		hexID := strings.TrimSuffix(name, ".key")
		keyID, err := hex.DecodeString(hexID)
		if err != nil {
			continue // skip malformed filenames
		}
		keys = append(keys, keyID)
	}
	return keys, nil
}

// GetPreParams returns cached Paillier preparams or generates fresh
// ones.  Generation takes ~30s and holds the mutex for the duration;
// concurrent callers block until the first generation completes.
func (s *fileStore) GetPreParams(ctx context.Context) (*keygen.LocalPreParams, error) {
	log.Tracef("GetPreParams")
	defer log.Tracef("GetPreParams exit")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.preParams != nil {
		return s.preParams, nil
	}
	log.Infof("generating Paillier preparams (this takes ~30s)")
	pp, err := keygen.GeneratePreParamsWithContextAndRandom(ctx, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate preparams: %w", err)
	}
	s.preParams = pp
	return s.preParams, nil
}

// SetPreParams seeds the store with pre-loaded preparams so that
// GetPreParams returns immediately without generating fresh ones.
func (s *fileStore) SetPreParams(pp *keygen.LocalPreParams) {
	s.mu.Lock()
	s.preParams = pp
	s.mu.Unlock()
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
	errCh     chan error
	done      chan struct{}
	threshold int
	keyID     []byte

	// Reshare only: dual party support for overlapping committees.
	// oldParty runs the old committee role; party runs the new committee role.
	oldParty   tss.Party
	oldPids    tss.SortedPartyIDs
	newPids    tss.SortedPartyIDs
	oldKeyToID map[string]Identity // PartyID key bytes → Identity
	newKeyToID map[string]Identity // PartyID key bytes → Identity
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
	preParams, err := t.store.GetPreParams(ctx)
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

	go t.pumpMessages(ctx, ceremonyID, c)

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
	case save := <-endCh:
		close(c.done)
		keyID := sha256.Sum256(save.ECDSAPub.X().Bytes())
		shareData, err := json.Marshal(save)
		if err != nil {
			return nil, fmt.Errorf("marshal key share: %w", err)
		}
		if err := t.store.SaveKeyShare(keyID[:16], shareData); err != nil {
			return nil, fmt.Errorf("save key share: %w", err)
		}
		// Persist metadata so reshare can discover the committee
		// and threshold without operator input.
		pubKey := append(save.ECDSAPub.X().Bytes(),
			save.ECDSAPub.Y().Bytes()...)
		meta := &KeyMetadata{
			Committee: parties,
			Threshold: threshold,
			KeyID:     keyID[:16],
			PublicKey: pubKey,
			CreatedAt: time.Now().UTC(),
		}
		if err := t.store.SaveKeyMetadata(keyID[:16], meta); err != nil {
			return nil, fmt.Errorf("save key metadata: %w", err)
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

	pids, ourPid, pidToID, err := t.buildSigningPartyContext(parties, keyShare.Ks)
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

	go t.pumpMessages(ctx, ceremonyID, c)

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
	case sig := <-endCh:
		close(c.done)
		return sig.R, sig.S, nil
	}
}

func (t *tssImpl) Reshare(ctx context.Context, ceremonyID CeremonyID, keyID []byte, oldParties, newParties []Identity, oldThreshold, newThreshold int) error {
	// Determine self's committee membership.
	inOld := false
	for _, id := range oldParties {
		if id == t.self {
			inOld = true
			break
		}
	}
	inNew := false
	for _, id := range newParties {
		if id == t.self {
			inNew = true
			break
		}
	}
	if !inOld && !inNew {
		return ErrNotInCommittee
	}

	// Load existing key share only if self is in the old committee.
	var keyShare keygen.LocalPartySaveData
	if inOld {
		shareData, err := t.store.LoadKeyShare(keyID)
		if err != nil {
			return fmt.Errorf("load key share: %w", err)
		}
		if err := json.Unmarshal(shareData, &keyShare); err != nil {
			return fmt.Errorf("unmarshal key share: %w", err)
		}
	}

	// Build party contexts with key rotation for new committee.
	// Old committee uses Identity bytes as PartyID key.
	// New committee XORs keys with 1 so tss-lib sees disjoint
	// committees even when parties overlap.
	oldPids, ourOldPid, oldPidToID, oldKeyToID, err := t.buildResharePartyContext(oldParties, false)
	if err != nil {
		return fmt.Errorf("build old context: %w", err)
	}
	newPids, ourNewPid, newPidToID, newKeyToID, err := t.buildResharePartyContext(newParties, true)
	if err != nil {
		return fmt.Errorf("build new context: %w", err)
	}

	oldCtx := tss.NewPeerContext(oldPids)
	newCtx := tss.NewPeerContext(newPids)

	outCh := make(chan tss.Message, (len(oldPids)+len(newPids))*10)
	endCh := make(chan *keygen.LocalPartySaveData, 2)

	// Create party instances. Overlapping nodes get two instances.
	var oldParty, newParty tss.Party

	if inOld {
		params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx,
			ourOldPid, len(oldPids), oldThreshold,
			len(newPids), newThreshold)
		oldParty = resharing.NewLocalParty(params, keyShare, outCh, endCh)
	}

	if inNew {
		preParams, err := t.store.GetPreParams(ctx)
		if err != nil {
			return fmt.Errorf("get preparams for reshare: %w", err)
		}
		params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx,
			ourNewPid, len(oldPids), oldThreshold,
			len(newPids), newThreshold)
		save := keygen.NewLocalPartySaveData(len(newPids))
		save.LocalPreParams = *preParams
		newParty = resharing.NewLocalParty(params, save, outCh, endCh)
	}

	// Combined pidToID for message routing.
	allPidToID := make(map[string]Identity)
	for k, v := range oldPidToID {
		allPidToID[k] = v
	}
	for k, v := range newPidToID {
		allPidToID[k] = v
	}

	c := &ceremony{
		ctype:      CeremonyReshare,
		party:      newParty,
		oldParty:   oldParty,
		pidToID:    allPidToID,
		oldPids:    oldPids,
		newPids:    newPids,
		oldKeyToID: oldKeyToID,
		newKeyToID: newKeyToID,
		outCh:      outCh,
		errCh:      make(chan error, 2),
		done:       make(chan struct{}),
		threshold:  newThreshold,
		keyID:      keyID,
	}

	t.ceremoniesMu.Lock()
	t.ceremonies[ceremonyID] = c
	t.ceremoniesMu.Unlock()

	defer func() {
		t.ceremoniesMu.Lock()
		delete(t.ceremonies, ceremonyID)
		t.ceremoniesMu.Unlock()
	}()

	// Start parties BEFORE the message pump. Start() writes to the
	// buffered outCh but won't block. Starting parties first ensures
	// that when pumpReshareMessages self-delivers messages between
	// local old/new parties, both have already been initialized and
	// can accept updates.
	expectedEnds := 0
	if inOld {
		expectedEnds++
	}
	if inNew {
		expectedEnds++
	}

	if oldParty != nil {
		go func() {
			if err := oldParty.Start(); err != nil {
				select {
				case <-ctx.Done():
				case c.errCh <- fmt.Errorf("start old resharing: %w", err.Cause()):
				}
			}
		}()
	}
	if newParty != nil {
		go func() {
			if err := newParty.Start(); err != nil {
				select {
				case <-ctx.Done():
				case c.errCh <- fmt.Errorf("start new resharing: %w", err.Cause()):
				}
			}
		}()
	}

	go t.pumpReshareMessages(ctx, ceremonyID, c)

	// Collect results. New committee party produces Xi != nil.
	var newSave *keygen.LocalPartySaveData
	received := 0
	for received < expectedEnds {
		select {
		case <-ctx.Done():
			close(c.done)
			return ctx.Err()
		case err := <-c.errCh:
			close(c.done)
			return err
		case save := <-endCh:
			received++
			if save.Xi != nil && save.Xi.Sign() != 0 {
				newSave = save
			}
		}
	}
	close(c.done)

	// Save new key share if self is in the new committee.
	if newSave != nil {
		newShareData, err := json.Marshal(newSave)
		if err != nil {
			return fmt.Errorf("marshal new key share: %w", err)
		}
		if err := t.store.SaveKeyShare(keyID, newShareData); err != nil {
			return fmt.Errorf("save new key share: %w", err)
		}
		// Update metadata with new committee and threshold.
		pubKey := append(newSave.ECDSAPub.X().Bytes(),
			newSave.ECDSAPub.Y().Bytes()...)
		meta := &KeyMetadata{
			Committee: newParties,
			Threshold: newThreshold,
			KeyID:     keyID,
			PublicKey: pubKey,
			CreatedAt: time.Now().UTC(),
		}
		if err := t.store.SaveKeyMetadata(keyID, meta); err != nil {
			return fmt.Errorf("save key metadata: %w", err)
		}
	}

	return nil
}

func (t *tssImpl) HandleMessage(from Identity, ceremonyID CeremonyID, data []byte) error {
	t.ceremoniesMu.Lock()
	c, ok := t.ceremonies[ceremonyID]
	t.ceremoniesMu.Unlock()

	if !ok {
		return ErrUnknownCeremony
	}

	if c.ctype == CeremonyReshare {
		// Reshare wire format: [broadcast:1][committee_flags:1][wireBytes]
		if len(data) < 3 {
			return errors.New("reshare message too short")
		}
		isBroadcast := data[0] == 0x01
		return t.handleReshareMessage(from, c, data[1], isBroadcast, data[2:])
	}

	// Keygen/Sign wire format: [broadcast:1][wireBytes]
	if len(data) < 2 {
		return errors.New("message too short")
	}

	isBroadcast := data[0] == 0x01
	wireData := data[1:]

	// Keygen/Sign: single party routing.
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

	parsed, err := tss.ParseWireMessage(wireData, fromPid, isBroadcast)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}

	// tss-lib update errors are non-fatal (e.g., duplicate messages)
	_, _ = c.party.Update(parsed)

	return nil
}

// handleReshareMessage routes an incoming reshare message to the
// correct party instance(s) based on committee target flags.
//
// Committee flags byte:
//
//	bit 0: to old committee
//	bit 1: to new committee
//	bit 2: from new committee (sender key is XORed)
func (t *tssImpl) handleReshareMessage(from Identity, c *ceremony, cflags byte, isBroadcast bool, wireData []byte) error {
	toOld := cflags&0x01 != 0
	toNew := cflags&0x02 != 0
	fromNew := cflags&0x04 != 0
	fromIDStr := from.String()

	// Reconstruct the sender's PartyID with the correct key.
	// The sender encodes whether it used old or new (XORed) key.
	findFromPid := func(pids tss.SortedPartyIDs) *tss.PartyID {
		for _, pid := range pids {
			if pid.Id == fromIDStr {
				return pid
			}
		}
		return nil
	}

	if toOld && c.oldParty != nil {
		var fromPid *tss.PartyID
		if fromNew {
			fromPid = findFromPid(c.newPids)
		} else {
			fromPid = findFromPid(c.oldPids)
		}
		if fromPid != nil {
			parsed, err := tss.ParseWireMessage(wireData, fromPid, isBroadcast)
			if err != nil {
				return fmt.Errorf("parse reshare msg for old party: %w", err)
			}
			// Non-fatal update errors.
			_, _ = c.oldParty.Update(parsed)
		}
	}

	if toNew && c.party != nil {
		var fromPid *tss.PartyID
		if fromNew {
			fromPid = findFromPid(c.newPids)
		} else {
			fromPid = findFromPid(c.oldPids)
		}
		if fromPid != nil {
			parsed, err := tss.ParseWireMessage(wireData, fromPid, isBroadcast)
			if err != nil {
				return fmt.Errorf("parse reshare msg for new party: %w", err)
			}
			// Non-fatal update errors.
			_, _ = c.party.Update(parsed)
		}
	}

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

// buildSigningPartyContext builds PartyIDs for signing, using the key
// share's Ks to derive the correct party keys. After reshare, Ks
// contains XORed keys; after keygen, Ks contains raw identity keys.
// This function transparently handles both cases by matching each
// signer's identity to the corresponding key in Ks.
func (t *tssImpl) buildSigningPartyContext(
	parties []Identity,
	ks []*big.Int,
) (tss.SortedPartyIDs, *tss.PartyID, map[string]Identity, error) {
	// Build a set of valid keys from the save data.
	ksSet := make(map[string]*big.Int, len(ks))
	for _, k := range ks {
		ksSet[k.String()] = k
	}

	pids := make([]*tss.PartyID, len(parties))
	pidToID := make(map[string]Identity)
	for i, id := range parties {
		idStr := id.String()
		rawKey := new(big.Int).SetBytes(id[:])
		xorKey := new(big.Int).Xor(rawKey, big.NewInt(1))

		// Match against Ks: try raw first, then XORed.
		var key *big.Int
		if _, ok := ksSet[rawKey.String()]; ok {
			key = rawKey
		} else if _, ok := ksSet[xorKey.String()]; ok {
			key = xorKey
		} else {
			return nil, nil, nil, fmt.Errorf(
				"signer %s not found in key share Ks", idStr)
		}
		pids[i] = tss.NewPartyID(idStr, idStr, key)
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

// For the new committee, keys are XORed with 1 so tss-lib sees
// disjoint committees even when parties overlap. Returns both
// id-based and key-based identity maps for message routing.
func (t *tssImpl) buildResharePartyContext(
	parties []Identity,
	isNew bool,
) (tss.SortedPartyIDs, *tss.PartyID, map[string]Identity, map[string]Identity, error) {
	pids := make([]*tss.PartyID, len(parties))
	pidToID := make(map[string]Identity) // PartyID.Id → Identity
	keyToID := make(map[string]Identity) // PartyID key bytes → Identity
	for i, id := range parties {
		idStr := id.String()
		key := new(big.Int).SetBytes(id[:])
		if isNew {
			key.Xor(key, big.NewInt(1))
		}
		pids[i] = tss.NewPartyID(idStr, idStr, key)
		pidToID[idStr] = id
		keyToID[string(key.Bytes())] = id
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
	// ourPid may be nil if self is not in this committee (valid).
	return sorted, ourPid, pidToID, keyToID, nil
}

func (t *tssImpl) pumpMessages(ctx context.Context, ceremonyID CeremonyID, c *ceremony) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
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
		}
	}
}

// pumpReshareMessages routes outgoing reshare messages with committee
// target flags encoded in the wire format.
//
// Wire format: [broadcast:1][committee_flags:1][wireBytes]
//
// The broadcast byte (position 0) is consumed by the transport layer.
// The committee flags byte (position 1) rides inside the transport
// payload and is consumed by handleReshareMessage:
//
//	bit 0: to old committee
//	bit 1: to new committee
//	bit 2: from new committee (sender key is XORed)
//
// For overlapping nodes (in both old and new committees), messages
// between the two local party instances are delivered directly via
// handleReshareMessage rather than through the transport.
func (t *tssImpl) pumpReshareMessages(ctx context.Context, ceremonyID CeremonyID, c *ceremony) {
	// Build lookup of new committee keys for fromNew detection.
	// Old and new key spaces are disjoint (XOR 1), so a key
	// appearing in newKeySet means the message is from the
	// new committee party instance.
	newKeySet := make(map[string]bool)
	for _, pid := range c.newPids {
		newKeySet[pid.KeyInt().String()] = true
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case msg := <-c.outCh:
			wireData, routing, err := msg.WireBytes()
			if err != nil {
				continue
			}

			// Build broadcast byte for transport layer.
			var bcast byte
			if routing.IsBroadcast {
				bcast = 0x01
			}

			// Build committee flags byte.
			var cflags byte
			if routing.IsToOldCommittee {
				cflags |= 0x01
			} else if routing.IsToOldAndNewCommittees {
				cflags |= 0x01 | 0x02
			} else {
				// Default: to new committee.
				cflags |= 0x02
			}

			// Determine from committee by checking key space.
			fromKey := msg.GetFrom().KeyInt()
			if newKeySet[fromKey.String()] {
				cflags |= 0x04 // from new committee
			}

			isBroadcast := bcast == 0x01

			// Build transport payload: [broadcast][cflags][wireData]
			data := make([]byte, 2+len(wireData))
			data[0] = bcast
			data[1] = cflags
			copy(data[2:], wireData)

			dest := msg.GetTo()
			if dest == nil {
				// Broadcast: send to all unique peers,
				// plus deliver locally for overlapping party.
				sent := make(map[Identity]bool)
				for _, pid := range c.oldPids {
					id := c.pidToID[pid.Id]
					if sent[id] {
						continue
					}
					sent[id] = true
					if id == t.self {
						wd := make([]byte, len(wireData))
						copy(wd, wireData)
						go func(cf byte, b bool, w []byte) {
							_ = t.handleReshareMessage(t.self, c, cf, b, w)
						}(cflags, isBroadcast, wd)
						continue
					}
					_ = t.transport.Send(id, ceremonyID, data)
				}
				for _, pid := range c.newPids {
					id := c.pidToID[pid.Id]
					if sent[id] {
						continue
					}
					sent[id] = true
					if id == t.self {
						wd := make([]byte, len(wireData))
						copy(wd, wireData)
						go func(cf byte, b bool, w []byte) {
							_ = t.handleReshareMessage(t.self, c, cf, b, w)
						}(cflags, isBroadcast, wd)
						continue
					}
					_ = t.transport.Send(id, ceremonyID, data)
				}
			} else {
				sent := make(map[Identity]bool)
				for _, destPID := range dest {
					id := c.pidToID[destPID.Id]
					if sent[id] {
						continue
					}
					sent[id] = true
					if id == t.self {
						wd := make([]byte, len(wireData))
						copy(wd, wireData)
						go func(cf byte, b bool, w []byte) {
							_ = t.handleReshareMessage(t.self, c, cf, b, w)
						}(cflags, isBroadcast, wd)
						continue
					}
					_ = t.transport.Send(id, ceremonyID, data)
				}
			}
		}
	}
}
