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

	"github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v3/ecdsa/resharing"
	"github.com/hemilabs/x/tss-lib/v3/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v3/tss"
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
	HandleMessage(ctx context.Context, from Identity, ceremonyID CeremonyID, data []byte) error
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
	var keys [][]byte
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
	ctype   CeremonyType
	pids    tss.SortedPartyIDs
	pidToID map[string]Identity
	keyID   []byte

	// Round-function path: HandleMessage delivers parsed messages
	// here; the ceremony driver reads with select on ctx.Done().
	// Buffers are sized generously (n*4 keygen, n*10 sign,
	// (old+new)*10 reshare) so HandleMessage rarely blocks; the
	// caller's ctx breaks the send if the ceremony has finished.
	inCh chan *tss.Message

	// Reshare only: dual PID sets for message routing.
	oldPids tss.SortedPartyIDs
	newPids tss.SortedPartyIDs
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
	log.Tracef("Keygen %x", ceremonyID)
	defer log.Tracef("Keygen %x exit", ceremonyID)

	if threshold < 0 || threshold >= len(parties) {
		return nil, fmt.Errorf("invalid threshold %d for %d parties", threshold, len(parties))
	}

	preParams, err := t.store.GetPreParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("get preparams: %w", err)
	}

	pids, ourPid, pidToID, err := t.buildPartyContext(parties)
	if err != nil {
		return nil, err
	}

	n := len(pids)
	ourIdx := ourPid.Index
	peerCtx := tss.NewPeerContext(pids)
	params := tss.NewParameters(tss.S256(), peerCtx, ourPid, n, threshold)
	params.SetCeremonyID(ceremonyID[:])
	params.SetSSIDNonce(0)

	c := &ceremony{
		ctype:   CeremonyKeygen,
		pids:    pids,
		pidToID: pidToID,
		inCh:    make(chan *tss.Message, n*4),
	}
	t.ceremoniesMu.Lock()
	t.ceremonies[ceremonyID] = c
	t.ceremoniesMu.Unlock()
	defer func() {
		t.ceremoniesMu.Lock()
		delete(t.ceremonies, ceremonyID)
		t.ceremoniesMu.Unlock()
	}()

	// Round 1
	state, r1out, err := keygen.Round1(ctx, params, *preParams)
	if err != nil {
		return nil, fmt.Errorf("keygen round 1: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r1out.Messages); err != nil {
		return nil, fmt.Errorf("send r1: %w", err)
	}

	buf := newMsgBuf(c.inCh)
	selfR1 := r1out.Messages[0]
	r1All, err := buf.collect(ctx, n-1, n, func(m *tss.Message) (int, bool) {
		_, ok := m.Content.(*keygen.KGRound1Message)
		return m.From.Index, ok
	})
	if err != nil {
		return nil, fmt.Errorf("collect r1: %w", err)
	}
	r1All[ourIdx] = selfR1

	// Round 2
	r2out, err := keygen.Round2(ctx, state, r1All)
	if err != nil {
		return nil, fmt.Errorf("keygen round 2: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r2out.Messages); err != nil {
		return nil, fmt.Errorf("send r2: %w", err)
	}

	r2p2p, r2bcast, err := buf.collectDual(ctx, n-1, n,
		func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*keygen.KGRound2Message1)
			return m.From.Index, ok
		},
		func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*keygen.KGRound2Message2)
			return m.From.Index, ok
		},
	)
	if err != nil {
		return nil, fmt.Errorf("collect r2: %w", err)
	}
	r2p2p[ourIdx] = state.ExportR2P2PSelf()
	r2bcast[ourIdx] = state.ExportR2BcastSelf()

	// Round 3
	r3out, err := keygen.Round3(ctx, state, r2p2p, r2bcast)
	if err != nil {
		return nil, fmt.Errorf("keygen round 3: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r3out.Messages); err != nil {
		return nil, fmt.Errorf("send r3: %w", err)
	}

	selfR3 := r3out.Messages[0]
	r3All, err := buf.collect(ctx, n-1, n, func(m *tss.Message) (int, bool) {
		_, ok := m.Content.(*keygen.KGRound3Message)
		return m.From.Index, ok
	})
	if err != nil {
		return nil, fmt.Errorf("collect r3: %w", err)
	}
	r3All[ourIdx] = selfR3

	// Round 4
	r4out, err := keygen.Round4(ctx, state, r3All)
	if err != nil {
		return nil, fmt.Errorf("keygen round 4: %w", err)
	}

	save := r4out.Save
	keyID := sha256.Sum256(save.ECDSAPub.X().Bytes())
	shareData, err := json.Marshal(save)
	if err != nil {
		return nil, fmt.Errorf("marshal key share: %w", err)
	}
	if err := t.store.SaveKeyShare(keyID[:16], shareData); err != nil {
		return nil, fmt.Errorf("save key share: %w", err)
	}
	pubKey := make([]byte, 64)
	save.ECDSAPub.X().FillBytes(pubKey[:32])
	save.ECDSAPub.Y().FillBytes(pubKey[32:])
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

func (t *tssImpl) Sign(ctx context.Context, ceremonyID CeremonyID, keyID []byte, parties []Identity, threshold int, data [32]byte) ([]byte, []byte, error) {
	log.Tracef("Sign %x key=%x", ceremonyID, keyID)
	defer log.Tracef("Sign %x exit", ceremonyID)

	if threshold < 0 || threshold >= len(parties) {
		return nil, nil, fmt.Errorf("invalid threshold %d for %d parties", threshold, len(parties))
	}

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

	n := len(pids)
	ourIdx := ourPid.Index
	peerCtx := tss.NewPeerContext(pids)
	params := tss.NewParameters(tss.S256(), peerCtx, ourPid, n, threshold)
	params.SetCeremonyID(ceremonyID[:])
	params.SetSSIDNonce(0)

	c := &ceremony{
		ctype:   CeremonySign,
		pids:    pids,
		pidToID: pidToID,
		keyID:   keyID,
		inCh:    make(chan *tss.Message, n*10),
	}
	t.ceremoniesMu.Lock()
	t.ceremonies[ceremonyID] = c
	t.ceremoniesMu.Unlock()
	defer func() {
		t.ceremoniesMu.Lock()
		delete(t.ceremonies, ceremonyID)
		t.ceremoniesMu.Unlock()
	}()

	msg := new(big.Int).SetBytes(data[:])

	// Round 1
	state, r1out, err := signing.SignRound1(params, keyShare, msg, nil, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 1: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r1out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r1: %w", err)
	}

	buf := newMsgBuf(c.inCh)
	r1p2p, r1bcast, err := buf.collectDual(ctx, n-1, n,
		func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*signing.SignRound1Message1)
			return m.From.Index, ok
		},
		func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*signing.SignRound1Message2)
			return m.From.Index, ok
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("collect sign r1: %w", err)
	}

	// Round 2
	r2out, err := signing.SignRound2(ctx, state, r1p2p, r1bcast)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 2: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r2out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r2: %w", err)
	}

	r2p2p, err := buf.collect(ctx, n-1, n, func(m *tss.Message) (int, bool) {
		_, ok := m.Content.(*signing.SignRound2Message)
		return m.From.Index, ok
	})
	if err != nil {
		return nil, nil, fmt.Errorf("collect sign r2: %w", err)
	}

	// Round 3
	r3out, err := signing.SignRound3(ctx, state, r2p2p)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 3: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r3out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r3: %w", err)
	}

	selfR3 := r3out.Messages[0]
	r3bcast, err := buf.collect(ctx, n-1, n, func(m *tss.Message) (int, bool) {
		_, ok := m.Content.(*signing.SignRound3Message)
		return m.From.Index, ok
	})
	if err != nil {
		return nil, nil, fmt.Errorf("collect sign r3: %w", err)
	}
	r3bcast[ourIdx] = selfR3

	// Round 4
	r4out, err := signing.SignRound4(state, r3bcast)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 4: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r4out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r4: %w", err)
	}

	selfR4 := r4out.Messages[0]
	r4bcast, err := buf.collect(ctx, n-1, n, func(m *tss.Message) (int, bool) {
		_, ok := m.Content.(*signing.SignRound4Message)
		return m.From.Index, ok
	})
	if err != nil {
		return nil, nil, fmt.Errorf("collect sign r4: %w", err)
	}
	r4bcast[ourIdx] = selfR4

	// Round 5
	r5out, err := signing.SignRound5(state, r4bcast)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 5: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r5out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r5: %w", err)
	}
	selfR5 := r5out.Messages[0]

	// Round 6 (no inbound needed)
	r6out, err := signing.SignRound6(state)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 6: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r6out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r6: %w", err)
	}
	selfR6 := r6out.Messages[0]

	// Collect Round 5 + Round 6 (interleaved)
	r5bcast, r6bcast, err := buf.collectDual(ctx, n-1, n,
		func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*signing.SignRound5Message)
			return m.From.Index, ok
		},
		func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*signing.SignRound6Message)
			return m.From.Index, ok
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("collect sign r5+r6: %w", err)
	}
	r5bcast[ourIdx] = selfR5
	r6bcast[ourIdx] = selfR6

	// Round 7
	r7out, err := signing.SignRound7(state, r5bcast, r6bcast)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 7: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r7out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r7: %w", err)
	}
	selfR7 := r7out.Messages[0]

	// Round 8 (no inbound needed)
	r8out, err := signing.SignRound8(state)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 8: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r8out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r8: %w", err)
	}
	selfR8 := r8out.Messages[0]

	// Collect Round 7 + Round 8 (interleaved)
	r7bcast, r8bcast, err := buf.collectDual(ctx, n-1, n,
		func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*signing.SignRound7Message)
			return m.From.Index, ok
		},
		func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*signing.SignRound8Message)
			return m.From.Index, ok
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("collect sign r7+r8: %w", err)
	}
	r7bcast[ourIdx] = selfR7
	r8bcast[ourIdx] = selfR8

	// Round 9
	r9out, err := signing.SignRound9(state, r7bcast, r8bcast)
	if err != nil {
		return nil, nil, fmt.Errorf("sign round 9: %w", err)
	}
	if err := t.sendRound(c, ceremonyID, r9out.Messages); err != nil {
		return nil, nil, fmt.Errorf("send sign r9: %w", err)
	}

	selfR9 := r9out.Messages[0]
	r9bcast, err := buf.collect(ctx, n-1, n, func(m *tss.Message) (int, bool) {
		_, ok := m.Content.(*signing.SignRound9Message)
		return m.From.Index, ok
	})
	if err != nil {
		return nil, nil, fmt.Errorf("collect sign r9: %w", err)
	}
	r9bcast[ourIdx] = selfR9

	// Finalize
	final, err := signing.SignFinalize(state, r9bcast)
	if err != nil {
		return nil, nil, fmt.Errorf("sign finalize: %w", err)
	}

	return final.Signature.R, final.Signature.S, nil
}

func (t *tssImpl) Reshare(ctx context.Context, ceremonyID CeremonyID, keyID []byte, oldParties, newParties []Identity, oldThreshold, newThreshold int) error {
	log.Tracef("Reshare %x key=%x old=%d new=%d", ceremonyID, keyID, len(oldParties), len(newParties))
	defer log.Tracef("Reshare %x exit", ceremonyID)

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

	// Get pre-params if self is in the new committee.
	var preParams keygen.LocalPreParams
	if inNew {
		pp, err := t.store.GetPreParams(ctx)
		if err != nil {
			return fmt.Errorf("get preparams for reshare: %w", err)
		}
		preParams = *pp
	}

	// Build party contexts with key rotation for new committee.
	oldPids, ourOldPid, oldPidToID, _, err := t.buildResharePartyContext(oldParties, false)
	if err != nil {
		return fmt.Errorf("build old context: %w", err)
	}
	newPids, ourNewPid, newPidToID, _, err := t.buildResharePartyContext(newParties, true)
	if err != nil {
		return fmt.Errorf("build new context: %w", err)
	}

	oldPC := len(oldPids)
	newPC := len(newPids)

	oldCtx := tss.NewPeerContext(oldPids)
	newCtx := tss.NewPeerContext(newPids)

	// Combined pidToID for message routing.
	allPidToID := make(map[string]Identity)
	for k, v := range oldPidToID {
		allPidToID[k] = v
	}
	for k, v := range newPidToID {
		allPidToID[k] = v
	}

	c := &ceremony{
		ctype:   CeremonyReshare,
		pidToID: allPidToID,
		oldPids: oldPids,
		newPids: newPids,
		keyID:   keyID,
		inCh:    make(chan *tss.Message, (oldPC+newPC)*10),
	}
	t.ceremoniesMu.Lock()
	t.ceremonies[ceremonyID] = c
	t.ceremoniesMu.Unlock()
	defer func() {
		t.ceremoniesMu.Lock()
		delete(t.ceremonies, ceremonyID)
		t.ceremoniesMu.Unlock()
	}()

	// Create round-function states. Overlapping nodes get two
	// states — one per committee role.
	var oldState, newState *resharing.ReshareState

	// ================================================================
	// Round 1: old committee produces DGRound1Message → new committee
	// ================================================================
	var selfR1 *tss.Message
	if inOld {
		params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx,
			ourOldPid, oldPC, oldThreshold, newPC, newThreshold)
		params.SetCeremonyID(ceremonyID[:])
		params.SetSSIDNonce(0)
		st, out, rerr := resharing.ReshareRound1(params, keyShare, keygen.LocalPreParams{})
		if rerr != nil {
			return fmt.Errorf("reshare round 1 (old): %w", rerr)
		}
		oldState = st
		if serr := t.sendReshareRound(c, ceremonyID, out.Messages, false); serr != nil {
			return fmt.Errorf("send reshare r1: %w", serr)
		}
		if len(out.Messages) > 0 {
			selfR1 = out.Messages[0]
		}
	}
	if inNew {
		params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx,
			ourNewPid, oldPC, oldThreshold, newPC, newThreshold)
		params.SetCeremonyID(ceremonyID[:])
		params.SetSSIDNonce(0)
		save := keygen.NewLocalPartySaveData(newPC)
		save.LocalPreParams = preParams
		st, _, rerr := resharing.ReshareRound1(params, save, preParams)
		if rerr != nil {
			return fmt.Errorf("reshare round 1 (new): %w", rerr)
		}
		newState = st
	}

	buf := newMsgBuf(c.inCh)

	// New committee needs Round 1 messages from old committee.
	var r1Msgs []*tss.Message
	if inNew {
		nR1 := oldPC
		if inOld {
			nR1-- // self already available
		}
		r1Msgs = make([]*tss.Message, oldPC)
		if nR1 > 0 {
			collected, cerr := buf.collect(ctx, nR1, oldPC, func(m *tss.Message) (int, bool) {
				_, ok := m.Content.(*resharing.DGRound1Message)
				return m.From.Index, ok
			})
			if cerr != nil {
				return fmt.Errorf("collect reshare r1: %w", cerr)
			}
			copy(r1Msgs, collected)
		}
		if selfR1 != nil {
			r1Msgs[ourOldPid.Index] = selfR1
		}
	}

	// ================================================================
	// Round 2: new committee produces DGRound2Message1 (→ new) +
	//          DGRound2Message2 ACK (→ old)
	// ================================================================
	var selfR2Msg1, selfR2Msg2 *tss.Message
	if inNew {
		out, rerr := resharing.ReshareRound2(newState, r1Msgs)
		if rerr != nil {
			return fmt.Errorf("reshare round 2 (new): %w", rerr)
		}
		if serr := t.sendReshareRound(c, ceremonyID, out.Messages, true); serr != nil {
			return fmt.Errorf("send reshare r2: %w", serr)
		}
		for _, msg := range out.Messages {
			pm := msg
			switch pm.Content.(type) {
			case *resharing.DGRound2Message1:
				selfR2Msg1 = pm
			case *resharing.DGRound2Message2:
				selfR2Msg2 = pm
			}
		}
	}
	if inOld {
		if _, rerr := resharing.ReshareRound2(oldState, r1Msgs); rerr != nil {
			return fmt.Errorf("reshare round 2 (old): %w", rerr)
		}
	}

	// Old committee collects DGRound2Message2 ACK from new committee.
	// (Used by Round 3 which is old-committee only.)
	var r2AckMsgs []*tss.Message
	if inOld {
		nR2Ack := newPC
		if inNew {
			nR2Ack-- // have self from output
		}
		collected, cerr := buf.collect(ctx, nR2Ack, newPC, func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*resharing.DGRound2Message2)
			return m.From.Index, ok
		})
		if cerr != nil {
			return fmt.Errorf("collect reshare r2 ack: %w", cerr)
		}
		r2AckMsgs = collected
		if selfR2Msg2 != nil {
			r2AckMsgs[ourNewPid.Index] = selfR2Msg2
		}
	}

	// New committee collects DGRound2Message1 from new peers.
	// (Used by Round 4 which is new-committee only.)
	var r2NewMsgs []*tss.Message
	if inNew {
		nR2New := newPC - 1 // always have self
		collected, cerr := buf.collect(ctx, nR2New, newPC, func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*resharing.DGRound2Message1)
			return m.From.Index, ok
		})
		if cerr != nil {
			return fmt.Errorf("collect reshare r2 new: %w", cerr)
		}
		r2NewMsgs = collected
		if selfR2Msg1 != nil {
			r2NewMsgs[ourNewPid.Index] = selfR2Msg1
		}
	}

	// ================================================================
	// Round 3: old committee sends VSS shares (P2P → new) +
	//          decommitment (broadcast → new)
	// ================================================================
	var selfR3Bcast *tss.Message
	var selfR3P2P *tss.Message // P2P to our new role (overlapping)
	if inOld {
		out, rerr := resharing.ReshareRound3(oldState, r2AckMsgs)
		if rerr != nil {
			return fmt.Errorf("reshare round 3 (old): %w", rerr)
		}
		if serr := t.sendReshareRound(c, ceremonyID, out.Messages, false); serr != nil {
			return fmt.Errorf("send reshare r3: %w", serr)
		}
		for _, msg := range out.Messages {
			pm := msg
			switch pm.Content.(type) {
			case *resharing.DGRound3Message1:
				if inNew {
					for _, to := range pm.To {
						if to.Id == ourNewPid.Id {
							selfR3P2P = pm
						}
					}
				}
			case *resharing.DGRound3Message2:
				selfR3Bcast = pm
			}
		}
	}
	if inNew {
		if _, rerr := resharing.ReshareRound3(newState, r2AckMsgs); rerr != nil {
			return fmt.Errorf("reshare round 3 (new): %w", rerr)
		}
	}

	// New committee collects Round 3 messages from old committee.
	var r3P2P, r3Bcast []*tss.Message
	if inNew {
		nR3 := oldPC
		if inOld {
			nR3-- // have self from output
		}
		var cerr error
		r3P2P, cerr = buf.collect(ctx, nR3, oldPC, func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*resharing.DGRound3Message1)
			return m.From.Index, ok
		})
		if cerr != nil {
			return fmt.Errorf("collect reshare r3 p2p: %w", cerr)
		}
		if selfR3P2P != nil {
			r3P2P[ourOldPid.Index] = selfR3P2P
		}

		r3Bcast, cerr = buf.collect(ctx, nR3, oldPC, func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*resharing.DGRound3Message2)
			return m.From.Index, ok
		})
		if cerr != nil {
			return fmt.Errorf("collect reshare r3 bcast: %w", cerr)
		}
		if selfR3Bcast != nil {
			r3Bcast[ourOldPid.Index] = selfR3Bcast
		}
	}

	// ================================================================
	// Round 4: new committee verifies, produces FacProof (P2P → new) +
	//          ACK (broadcast → old+new)
	// ================================================================
	var selfR4Bcast *tss.Message
	if inNew {
		out, rerr := resharing.ReshareRound4(ctx, newState, r2NewMsgs, r3P2P, r3Bcast)
		if rerr != nil {
			return fmt.Errorf("reshare round 4 (new): %w", rerr)
		}
		if serr := t.sendReshareRound(c, ceremonyID, out.Messages, true); serr != nil {
			return fmt.Errorf("send reshare r4: %w", serr)
		}
		for _, msg := range out.Messages {
			pm := msg
			if _, ok := pm.Content.(*resharing.DGRound4Message2); ok {
				selfR4Bcast = pm
			}
		}
	}
	if inOld {
		if _, rerr := resharing.ReshareRound4(ctx, oldState, nil, nil, nil); rerr != nil {
			return fmt.Errorf("reshare round 4 (old): %w", rerr)
		}
	}

	// New committee collects DGRound4Message1 P2P from new peers.
	var r4P2P []*tss.Message
	if inNew {
		nR4P2P := newPC - 1 // self is excluded from P2P
		r4P2P, err = buf.collect(ctx, nR4P2P, newPC, func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*resharing.DGRound4Message1)
			return m.From.Index, ok
		})
		if err != nil {
			return fmt.Errorf("collect reshare r4 p2p: %w", err)
		}
	}

	// All nodes collect DGRound4Message2 broadcast from new committee.
	var r4Bcast []*tss.Message
	{
		nR4Bcast := newPC
		if inNew {
			nR4Bcast-- // have self from output
		}
		r4Bcast, err = buf.collect(ctx, nR4Bcast, newPC, func(m *tss.Message) (int, bool) {
			_, ok := m.Content.(*resharing.DGRound4Message2)
			return m.From.Index, ok
		})
		if err != nil {
			return fmt.Errorf("collect reshare r4 bcast: %w", err)
		}
		if selfR4Bcast != nil {
			r4Bcast[ourNewPid.Index] = selfR4Bcast
		}
	}

	// ================================================================
	// Round 5: finalize
	// ================================================================
	if inNew {
		out, rerr := resharing.ReshareRound5(newState, r4P2P, r4Bcast)
		if rerr != nil {
			return fmt.Errorf("reshare round 5 (new): %w", rerr)
		}
		if out.Save != nil {
			newShareData, merr := json.Marshal(out.Save)
			if merr != nil {
				return fmt.Errorf("marshal new key share: %w", merr)
			}
			if serr := t.store.SaveKeyShare(keyID, newShareData); serr != nil {
				return fmt.Errorf("save new key share: %w", serr)
			}
			pubKey := make([]byte, 64)
			out.Save.ECDSAPub.X().FillBytes(pubKey[:32])
			out.Save.ECDSAPub.Y().FillBytes(pubKey[32:])
			meta := &KeyMetadata{
				Committee: newParties,
				Threshold: newThreshold,
				KeyID:     keyID,
				PublicKey: pubKey,
				CreatedAt: time.Now().UTC(),
			}
			if serr := t.store.SaveKeyMetadata(keyID, meta); serr != nil {
				return fmt.Errorf("save key metadata: %w", serr)
			}
		}
	}
	if inOld {
		if _, rerr := resharing.ReshareRound5(oldState, nil, r4Bcast); rerr != nil {
			return fmt.Errorf("reshare round 5 (old): %w", rerr)
		}
	}

	return nil
}

func (t *tssImpl) HandleMessage(ctx context.Context, from Identity, ceremonyID CeremonyID, data []byte) error {
	log.Tracef("HandleMessage from=%s ceremony=%x len=%d", from, ceremonyID, len(data))

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
		isBroadcast := data[0] == msgTypeBroadcast
		cflags := data[1]
		wireData := data[wireHeaderLen:]
		fromNew := cflags&cflagFromNew != 0

		// Parse with correct PID set based on sender committee.
		fromIDStr := from.String()
		pids := c.oldPids
		if fromNew {
			pids = c.newPids
		}
		var fromPid *tss.PartyID
		for _, pid := range pids {
			if pid.Id == fromIDStr {
				fromPid = pid
				break
			}
		}
		if fromPid == nil {
			return errors.New("sender not in reshare ceremony")
		}
		parsed, err := parseTSSWireMessage(wireData, fromPid, isBroadcast)
		if err != nil {
			return fmt.Errorf("parse reshare message: %w", err)
		}
		select {
		case c.inCh <- parsed:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}

	// Keygen/Sign wire format: [broadcast:1][wireBytes]
	if len(data) < 2 {
		return errors.New("message too short")
	}

	isBroadcast := data[0] == msgTypeBroadcast
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

	parsed, err := parseTSSWireMessage(wireData, fromPid, isBroadcast)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}

	select {
	case c.inCh <- parsed:
	case <-ctx.Done():
		return ctx.Err()
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
