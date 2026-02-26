// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/crypto/ripemd160"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hemilabs/x/tss-lib/v2/tss"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// The continuum protocol is a simple gossipy P2P system.
//
// The continuum transfunctioner is a very mysterious and powerful device and
// its mystery is exceeded only by its power.
//
// Continuum runs directly on top of TCP and can run in the clear since it does
// its own encryption. It is a streaming protocol that prefixes encrypted
// payloads with a size (that is capped). If the message is too large the
// receiver will drop the connection and potentially blacklist the caller.
//
// Communication should occur between a transport "client" and a "server",
// where the server determines the type of Curve and encryption keys derived
// by both. Communication between these two parties is initiated by performing
// a key exchange, followed by a handshake where the other party's identity
// is verified. After this, envelopes can be shared freely between both sides.
//
// An envelope is constructed on the wire as: [size+nonce][header+payload].
// The size and nonce are unencrypted, the former being used to validate the
// amount of data to be read, and the latter for decrypting the message.
//
// Once an envelope is decrypted there are two distinct pieces, a header
// and a message + payload. The header contains information akin to TCP
// and is used to route the envelope and specify the payload command type.
// A message is for the reader and an envelope should be routed to a third party.
//
// Version
//	1:
//		Defaults to JSON encoding
//
// Options (default):
//	encoding=json
//	compression=no
//
// Transport encryption is done in two phases:
//	1. Key Exchange
//	2. Handshake
//
// Phase one is an ordered set of commands. It uses a server-first approach
// where the client either agrees to what is being dictated or drops the
// connection if it doesn't.
//	1. Server generates an ephemeral transport private key (ETK) based on a
//	pre-determined curve, e.g. X25519. It sends the corresponding public
//	key (ETP) to the client in cleartext using a TransportRequest JSON
//	blob.
//
//	2. Client reads and decodes the JSON TransportRequest and extracts the
//	suggested curve from the server ETP. If the curve is agreeable it
//	replies with a freshly generated  ETP using the same mechanism as the
//	server. If the curve is not agreeable it should hang up.
//
//	3. Both sides verify the transport protocol version in TransportRequest.
//	4. Both sides calculate the shared transport secret using Elliptic
//	Curve Diffie-Hellman (ECDH). Next they derive two directional
//	shared transport encryption keys using an HMAC-based key derivation
//	function (HKDF). The hash used is SHA256, salt is
//	"continuum-hkdf-salt-v1" and the info strings are
//	"continuum-s2c-v1" (server-to-client) and "continuum-c2s-v1"
//	(client-to-server). This ensures that each direction uses a
//	unique key, containing the blast radius if a nonce ever repeats.
//
// At this point, both sides have directional keys which they use to encrypt
// all packets going forward using NaCl's secretbox. The server encrypts with
// the s2c key and decrypts with the c2s key; the client does the inverse.
// Protocol requires one
// packet per secretbox and the wire format is 24 bits of cleartext that
// designates encrypted blob length. The encrypted blob comprises of a 24 byte
// nonce plus ciphertext. Decrypting is done by calling secretbox open using
// the directional key and nonce.
//
// Note on nonces: When using secretbox it is imperative to not use duplicate
// nonces. In order to prevent reuse both sides generate a random 256 bit key
// and every time a new packet is sent a counter is incremented and then fed
// into an HMAC to generate a guaranteed unique nonce.
//
// Phase two, the handshake, is an unordered set of commands that both sides
// perform to establish and verify the identity of the counterparty. Do note
// that at this point every command is sent through the encrypted tunnel using
// an envelope (see below).
//	1. Both sides send a HelloRequest that contains a version, their
//	identity, a challenge, options etc.
//	2. Both sides read the HelloRequest and validate its contents prior to
//	replying with a HelloResponse. By protocol, either side can hang up at
//	any time if they feel their counterparty is misbehaving. It is
//	important to note that the challenge that must be signed is the SHA256
//	of the counterparty challenge and ETP.
//	3. Both sides read the HelloResponse and derive the remote's ETP from
//	the signature. The derived ETP must match the provided identity to
//	prove ownership of the accompanying private key. Additionally, the
//	identity may be stored in a DNS TXT record that is associated with the
//	remote host.
//	TODO: define DNS mechanism in more detail.
//
// In the continuum protocol every host has a long lived identity. This
// identity is the RIPEMD160 digest of a public secp256k1 compressed key. This
// means that every host has a long lived secp256k1 private key that is used to
// sign various things over its life-cycle and uniquely identify itself within
// the protocol.
//
// An envelope is defined as an encrypted blob that contains a header and a
// command. A header is akin to a TCP header that contains routing
// information, TTL and hints for the remote side to aid in command decoding.
//
// TODO:
//	* routing
//	* TTL
//	* gossip rules
//	* uniqueness of commands
//	* envelope wrapped in envelope (encrypted routing)
//	* commands

// PayloadType identifies the command type carried by an envelope.
type PayloadType string

// Payload type constants for all protocol commands.
const (
	PHelloRequest    PayloadType = "hello"
	PHelloResponse   PayloadType = "hello-response"
	PPingRequest     PayloadType = "ping"
	PPingResponse    PayloadType = "ping-response"
	PKeygenRequest   PayloadType = "keygen"
	PKeygenResponse  PayloadType = "keygen-response"
	PReshareRequest  PayloadType = "reshare"
	PReshareResponse PayloadType = "reshare-response"
	PSignRequest     PayloadType = "sign"
	PSignResponse    PayloadType = "sign-response"
	PTSSMessage      PayloadType = "tss"
	PCeremonyResult  PayloadType = "ceremony-result"
	PCeremonyAbort   PayloadType = "ceremony-abort"

	// Gossip
	PPeerNotify       PayloadType = "peer-notify"
	PPeerListRequest  PayloadType = "peer-list-request"
	PPeerListResponse PayloadType = "peer-list-response"

	// End-to-end encryption
	PEncryptedPayload PayloadType = "encrypted"

	// Admin (localhost only)
	PPeerListAdminRequest   PayloadType = "peer-list-admin"
	PPeerListAdminResponse  PayloadType = "peer-list-admin-response"
	PCeremonyStatusRequest  PayloadType = "ceremony-status"
	PCeremonyStatusResponse PayloadType = "ceremony-status-response"
	PCeremonyListRequest    PayloadType = "ceremony-list"
	PCeremonyListResponse   PayloadType = "ceremony-list-response"

	// Session management
	PBusyResponse PayloadType = "busy"
)

var (
	pt2str = map[reflect.Type]PayloadType{
		reflect.TypeOf(HelloRequest{}):     PHelloRequest,
		reflect.TypeOf(HelloResponse{}):    PHelloResponse,
		reflect.TypeOf(PingRequest{}):      PPingRequest,
		reflect.TypeOf(PingResponse{}):     PPingResponse,
		reflect.TypeOf(KeygenRequest{}):    PKeygenRequest,
		reflect.TypeOf(KeygenResponse{}):   PKeygenResponse,
		reflect.TypeOf(ReshareRequest{}):   PReshareRequest,
		reflect.TypeOf(ReshareResponse{}):  PReshareResponse,
		reflect.TypeOf(SignRequest{}):      PSignRequest,
		reflect.TypeOf(SignResponse{}):     PSignResponse,
		reflect.TypeOf(TSSMessage{}):       PTSSMessage,
		reflect.TypeOf(CeremonyResult{}):   PCeremonyResult,
		reflect.TypeOf(CeremonyAbort{}):    PCeremonyAbort,
		reflect.TypeOf(PeerNotify{}):       PPeerNotify,
		reflect.TypeOf(PeerListRequest{}):  PPeerListRequest,
		reflect.TypeOf(PeerListResponse{}): PPeerListResponse,
		reflect.TypeOf(EncryptedPayload{}): PEncryptedPayload,

		// Admin
		reflect.TypeOf(PeerListAdminRequest{}):   PPeerListAdminRequest,
		reflect.TypeOf(PeerListAdminResponse{}):  PPeerListAdminResponse,
		reflect.TypeOf(CeremonyStatusRequest{}):  PCeremonyStatusRequest,
		reflect.TypeOf(CeremonyStatusResponse{}): PCeremonyStatusResponse,
		reflect.TypeOf(CeremonyListRequest{}):    PCeremonyListRequest,
		reflect.TypeOf(CeremonyListResponse{}):   PCeremonyListResponse,

		// Session management
		reflect.TypeOf(BusyResponse{}): PBusyResponse,
	}

	str2pt map[PayloadType]reflect.Type
)

func init() {
	// reverse pt2str map
	str2pt = make(map[PayloadType]reflect.Type, len(pt2str))
	for k, v := range pt2str {
		str2pt[v] = k
	}
}

// PayloadHash is a wrapper around sha256 to enable human readable encoding.
// It is used as a unique identifier for the command.
type PayloadHash [32]byte

// MarshalJSON satisfies the JSON Encode interface.
func (p PayloadHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(p[:]))
}

// UnmarshalJSON satisfies the JSON Decode interface.
func (p *PayloadHash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(d) != len(p) {
		return fmt.Errorf("invalid length: %v", len(d))
	}
	copy(p[:], d)
	return nil
}

// String returns the payloadhash as a hexadecimal encoded string.
func (p PayloadHash) String() string {
	return hex.EncodeToString(p[:])
}

// NewPayloadHash returns a PayloadHash type that hashes x.
func NewPayloadHash(x []byte) *PayloadHash {
	p := PayloadHash(sha256.Sum256(x))
	return &p
}

// NewPayloadFromCommand returns the json encoding of a given command, along
// with its hash.
func NewPayloadFromCommand(cmd any) (*PayloadHash, []byte, error) {
	jc, err := json.Marshal(cmd)
	if err != nil {
		return nil, nil, err
	}
	return NewPayloadHash(jc), jc, nil
}

// Header is a part of every message sent by transport, and contains
// information about identity of the sender and intended receiver, as well as
// the payload.
type Header struct {
	PayloadType PayloadType `json:"payloadtype"`           // Hint to decode payload
	PayloadHash PayloadHash `json:"payloadhash"`           // Message identifier
	Origin      Identity    `json:"origin"`                // Origin identity
	Destination *Identity   `json:"destination,omitempty"` // Intended receiver
	TTL         uint8       `json:"ttl"`                   // Time To Live
	// Path []Identity // Deferred: requires per-hop signing (see SOW4 §9).
}

// HelloRequest is the first command that is sent to the other side after the
// key exchange phase. It advertises the version the node is running and some
// desired options. The challenge must be signed by the remote node.
type HelloRequest struct {
	Version   uint32            `json:"version"`           // Version number
	Options   map[string]string `json:"options,omitempty"` // x=y
	Identity  Identity          `json:"identity"`          // Advertise our identity
	Challenge []byte            `json:"challenge"`         // Random challenge, min 32 bytes
	NaClPub   []byte            `json:"nacl_pub"`          // X25519 public key for e2e encryption
}

// HelloResponse returns the signed challenge. The remote identity is derived
// from the signature.
type HelloResponse struct {
	Signature []byte `json:"signature"` // Signature of Challenge
}

// PingRequest is a ping to the other side.
type PingRequest struct {
	OriginTimestamp int64 `json:"origintimestamp"` // Sender timestamp
}

// PingResponse is the response to a ping request.
type PingResponse struct {
	OriginTimestamp int64 `json:"origintimestamp"` // Copy the value back
	PeerTimestamp   int64 `json:"peertimestamp"`   // Remote timestamp
}

// PeerRecord describes a known peer for gossip exchange.
type PeerRecord struct {
	Identity Identity `json:"identity"`
	Address  string   `json:"address"`            // host:port
	NaClPub  []byte   `json:"nacl_pub,omitempty"` // X25519 public key for e2e encryption
	Version  uint32   `json:"version"`            // ProtocolVersion at time of discovery
	LastSeen int64    `json:"last_seen"`          // unix timestamp
}

// PeerNotify announces that the sender has new peer information.
// The receiver may request the full list if interested.
type PeerNotify struct {
	Count int `json:"count"` // number of peers we know about
}

// PeerListRequest requests the sender's known peer list.
type PeerListRequest struct{}

// PeerListResponse contains the sender's known peer list.
type PeerListResponse struct {
	Peers []PeerRecord `json:"peers"`
}

// EncryptedPayload wraps a nacl box-encrypted payload for end-to-end
// encryption.  The outer Header carries routing information in the
// clear; the payload is encrypted to the destination's X25519 public
// key.  Intermediate routers can read the Header but not the Payload.
//
// Sender is self-asserted but implicitly authenticated: the recipient
// uses Sender to look up the NaCl public key for box.Open, which will
// fail if the actual sender's private key doesn't match.  A tampered
// Sender field causes decryption failure, not impersonation.
type EncryptedPayload struct {
	Nonce      [24]byte    `json:"nonce"`      // nacl box nonce
	Ciphertext []byte      `json:"ciphertext"` // nacl box sealed
	Sender     Identity    `json:"sender"`     // for recipient to look up sender's NaCl pub
	InnerType  PayloadType `json:"inner_type"` // type hint for decoding after decryption
}

// KeygenRequest initiates a key generation ceremony.
// Sent by the router to all participating parties.
type KeygenRequest struct {
	CeremonyID  CeremonyID           `json:"ceremonyid"`  // Unique ceremony identifier
	Curve       string               `json:"curve"`       // Curve for TSS
	Committee   tss.UnSortedPartyIDs `json:"committee"`   // Signing committee
	Threshold   int                  `json:"threshold"`   // Threshold (t, need t+1 to sign)
	Coordinator Identity             `json:"coordinator"` // First elected member; broadcasts result
}

// KeygenResponse acknowledges a keygen request.
type KeygenResponse struct {
	CeremonyID CeremonyID `json:"ceremonyid"` // Echo back ceremony ID
	Success    bool       `json:"success"`    // Whether party accepted
	Error      string     `json:"error,omitempty"`
}

// CeremonyID uniquely identifies a ceremony instance.
// Generated by the router when initiating a ceremony.
type CeremonyID [32]byte

// String returns the hex encoded string of the ceremony ID.
func (c CeremonyID) String() string {
	return hex.EncodeToString(c[:])
}

// MarshalJSON satisfies the JSON Encode interface.
func (c CeremonyID) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(c[:]))
}

// UnmarshalJSON satisfies the JSON Decode interface.
func (c *CeremonyID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(d) != len(c) {
		return fmt.Errorf("invalid ceremony id length: %v", len(d))
	}
	copy(c[:], d)
	return nil
}

// CeremonyType identifies the type of TSS ceremony.
type CeremonyType uint8

const (
	CeremonyKeygen  CeremonyType = 1
	CeremonyReshare CeremonyType = 2
	CeremonySign    CeremonyType = 3
)

// String returns the string representation of the ceremony type.
func (c CeremonyType) String() string {
	switch c {
	case CeremonyKeygen:
		return "keygen"
	case CeremonyReshare:
		return "reshare"
	case CeremonySign:
		return "sign"
	default:
		return fmt.Sprintf("unknown(%d)", c)
	}
}

// Ceremony status values.
const (
	CeremonyRunning  = "running"
	CeremonyComplete = "complete"
	CeremonyFailed   = "failed"
)

// ReshareRequest initiates a reshare ceremony.
// Sent by the router to all participating parties.
type ReshareRequest struct {
	CeremonyID   CeremonyID           `json:"ceremonyid"`   // Unique ceremony identifier
	Curve        string               `json:"curve"`        // Elliptic curve (e.g., "secp256k1")
	KeyID        []byte               `json:"keyid"`        // Key to reshare
	OldCommittee tss.UnSortedPartyIDs `json:"oldcommittee"` // Current key holders
	NewCommittee tss.UnSortedPartyIDs `json:"newcommittee"` // New key holders
	OldThreshold int                  `json:"oldthreshold"` // Current threshold (t, need t+1 to sign)
	NewThreshold int                  `json:"newthreshold"` // New threshold
}

// ReshareResponse acknowledges a reshare request.
type ReshareResponse struct {
	CeremonyID CeremonyID `json:"ceremonyid"` // Echo back ceremony ID
	Success    bool       `json:"success"`    // Whether party accepted the request
	Error      string     `json:"error,omitempty"`
}

// SignRequest initiates a signing ceremony.
// Sent by the router to participating parties.
type SignRequest struct {
	CeremonyID CeremonyID           `json:"ceremonyid"` // Unique ceremony identifier
	KeyID      []byte               `json:"keyid"`      // Identifies which TSS key to use
	Committee  tss.UnSortedPartyIDs `json:"committee"`  // Signing parties
	Threshold  int                  `json:"threshold"`  // Threshold (t, need t+1 to sign)
	Data       []byte               `json:"data"`       // Hash to sign (32 bytes)
}

// SignResponse returns the signature or error.
type SignResponse struct {
	CeremonyID CeremonyID `json:"ceremonyid"`
	Success    bool       `json:"success"`
	R          []byte     `json:"r,omitempty"` // Signature R component
	S          []byte     `json:"s,omitempty"` // Signature S component
	Error      string     `json:"error,omitempty"`
}

// TSSMsgFlags encodes broadcast and committee routing metadata as a
// single bitfield on TSSMessage.
type TSSMsgFlags byte

const (
	TSSFlagBroadcast TSSMsgFlags = 1 << iota // Broadcast to all parties
	TSSFlagToOld                             // Route to old committee (reshare)
	TSSFlagToNew                             // Route to new committee (reshare)
	TSSFlagFromNew                           // Sender is new committee (reshare)
)

// TSSMessage wraps tss-lib protocol messages exchanged between parties.
// The message MUST be signed to prevent injection by routing nodes.
type TSSMessage struct {
	CeremonyID CeremonyID   `json:"ceremonyid"` // Which ceremony this belongs to
	Type       CeremonyType `json:"type"`       // Ceremony type hint
	From       Identity     `json:"from"`       // Originating party (for sig verification)
	Flags      TSSMsgFlags  `json:"flags"`      // Broadcast + committee routing
	Data       []byte       `json:"data"`       // tss-lib WireBytes()
	Signature  []byte       `json:"signature"`  // Sign(Hash(CeremonyID || Data))
}

// IsBroadcast reports whether the message is broadcast to all parties.
func (m TSSMessage) IsBroadcast() bool {
	return m.Flags&TSSFlagBroadcast != 0
}

// HashTSSMessage computes the hash that must be signed for a
// TSSMessage. Hash = SHA256(CeremonyID || Data).
func HashTSSMessage(cid CeremonyID, data []byte) []byte {
	h := sha256.New()
	h.Write(cid[:])
	h.Write(data)
	return h.Sum(nil)
}

// NewCeremonyID generates a random ceremony identifier.
func NewCeremonyID() CeremonyID {
	var cid CeremonyID
	if _, err := rand.Read(cid[:]); err != nil {
		panic(fmt.Errorf("read random: %w", err))
	}
	return cid
}

// CeremonyResult signals ceremony completion to the router.
type CeremonyResult struct {
	CeremonyID CeremonyID `json:"ceremonyid"`
	Success    bool       `json:"success"`
	Error      string     `json:"error,omitempty"`
}

// CeremonyAbort signals ceremony termination.
// Can be sent by any party or the router.
type CeremonyAbort struct {
	CeremonyID CeremonyID `json:"ceremonyid"`
	Reason     string     `json:"reason"`
}

// =============================================================================
// Admin RPC types (localhost only)
// =============================================================================

// PeerListAdminRequest requests the full peer map with session status.
type PeerListAdminRequest struct{}

// PeerListAdminResponse contains all known peers with connection status.
type PeerListAdminResponse struct {
	Peers []PeerAdminRecord `json:"peers"`
}

// PeerAdminRecord extends PeerRecord with session status.
type PeerAdminRecord struct {
	PeerRecord
	Connected bool `json:"connected"` // has active session
	Self      bool `json:"self"`      // true if this is the server's own record
}

// CeremonyStatusRequest queries the status of a specific ceremony.
type CeremonyStatusRequest struct {
	CeremonyID CeremonyID `json:"ceremony_id"`
}

// CeremonyStatusResponse reports the status of a ceremony.
type CeremonyStatusResponse struct {
	CeremonyID CeremonyID `json:"ceremony_id"`
	Found      bool       `json:"found"`
	Type       string     `json:"type,omitempty"`       // "keygen", "reshare", "sign"
	Status     string     `json:"status,omitempty"`     // "running", "complete", "failed"
	StartTime  int64      `json:"start_time,omitempty"` // unix timestamp
	KeyID      []byte     `json:"key_id,omitempty"`     // set after keygen completes
	Committee  []Identity `json:"committee,omitempty"`  // ceremony participants
	Error      string     `json:"error,omitempty"`
}

// CeremonyListRequest requests all known ceremonies.
type CeremonyListRequest struct{}

// CeremonyListResponse returns all known ceremonies with their status.
type CeremonyListResponse struct {
	Ceremonies []CeremonyStatusResponse `json:"ceremonies"`
}

// BusyResponse is sent post-handshake when the server is at capacity.
// The connecting peer should close the transport and retry later.
type BusyResponse struct{}

// ErrAdminNotLocal is returned when an admin request arrives from a
// non-localhost connection.
var ErrAdminNotLocal = errors.New("admin request rejected: not localhost")

// BroadcastDestination is the all-zeros Identity sentinel used as
// Header.Destination to indicate a broadcast message.  Every node
// processes the message locally AND forwards to all connected peers.
var BroadcastDestination = Identity{}

// broadcastWhitelist is the set of payload types allowed to use the
// broadcast primitive.  Non-whitelisted types with BroadcastDestination
// are silently dropped.
var broadcastWhitelist = map[reflect.Type]bool{
	reflect.TypeOf(CeremonyResult{}): true,
	reflect.TypeOf(CeremonyAbort{}):  true,
}

// IsBroadcastable reports whether cmd is a broadcast-type payload.
// Handles both value and pointer types.
func IsBroadcastable(cmd any) bool {
	t := reflect.TypeOf(cmd)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return broadcastWhitelist[t]
}

// Protocol and transport wire constants.
const (
	TransportVersion = 1 // Transport protocol version

	ProtocolVersion = 1 // Node version

	TransportNonceSize = 24         // 24 bytes, per secretbox
	TransportMaxSize   = 0x00ffffff // 24 bit, 3 bytes

	ChallengeSize = 32 // 32 bytes random data

	NaClPubSize = 32 // X25519 public key length

	dnsAppName = "transfunctioner" // Expected "v=" value in DNS TXT record
)

// ZeroChallenge is an all-zeros challenge value used as an invalid sentinel.
// Handshake rejects challenges that compare equal to this.
var ZeroChallenge = [ChallengeSize]byte{}

// Nonce is used by transport for message encryption / decryption.
// It is first generated during key exchange, and is atomically
// incremented by every message sent, producing a new value.
type Nonce struct {
	counter atomic.Uint64
	key     [TransportNonceSize]byte
}

// Next returns the next nonce by atomically incrementing the nonce counter and
// then running an HMAC-SHA256 over the big endian encoding of it. Since sha256
// is 32 bytes and the nonce is 24 the bottom 8 bytes are clipped.
func (n *Nonce) Next() *[TransportNonceSize]byte {
	var (
		counter [8]byte
		nonce   [TransportNonceSize]byte
	)
	binary.BigEndian.PutUint64(counter[:], n.counter.Add(1))
	h := hmac.New(sha256.New, n.key[:])
	_, err := h.Write(counter[:])
	if err != nil {
		panic(err)
	}
	copy(nonce[:], h.Sum(nil))
	return &nonce
}

// NewNonce returns a new Nonce type. This is used to guarantee a unique nonce
// that can be used with secretbox.
func NewNonce() (*Nonce, error) {
	n := &Nonce{}
	_, err := rand.Read(n.key[:])
	// untested: rand.Read fails only on OS entropy exhaustion (unrecoverable)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// Hash160 is a utility function that returns the ripemd160 hash for the
// provided data.
func Hash160(data []byte) []byte {
	ripemd := ripemd160.New()
	ripemd.Write(data[:])
	return ripemd.Sum(nil)
}

// Hash256 is a utility function that returns the sha256 of multiple byte
// slices.
func Hash256(data []byte, extraData ...[]byte) []byte {
	hash := sha256.New()
	_, err := hash.Write(data[:])
	if err != nil {
		panic(err)
	}
	for _, v := range extraData {
		_, err := hash.Write(v)
		if err != nil {
			panic(err)
		}
	}
	return hash.Sum(nil)
}

// Identity is how a node is identified. It simply is the ripemd160 of the
// public key.
type Identity [ripemd160.Size]byte // ripemd160 of compressed pubkey

// String returns the hex encoded string of the identity.
func (i Identity) String() string {
	return hex.EncodeToString(i[:])
}

// Bytes returns a copy of identity as a byte slice.
func (i Identity) Bytes() []byte {
	return append([]byte{}, i[:]...) // Copy; append(i[:]) rejected by linter.
}

// UnmarshalJSON satisfies the JSON Decode interface.
func (i *Identity) UnmarshalJSON(data []byte) error {
	var d string
	err := json.Unmarshal(data, &d)
	if err != nil {
		return err
	}
	ni, err := NewIdentityFromString(d)
	if err != nil {
		return err
	}
	copy(i[:], ni[:])
	return nil
}

// MarshalJSON satisfies the JSON Encode interface.
func (i Identity) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(i[:]))
}

// NewIdentityFromPub returns a new identity for the provided public key.
func NewIdentityFromPub(pub *secp256k1.PublicKey) Identity {
	id := Hash160(pub.SerializeCompressed())
	var i Identity
	copy(i[:], id)
	return i
}

// NewIdentityFromString returns a new identity for the provided string encoded
// public key.
func NewIdentityFromString(identity string) (*Identity, error) {
	id, err := hex.DecodeString(identity)
	if err != nil {
		return nil, err
	}
	i := Identity{}
	if len(id) != len(i) {
		return nil, errors.New("invalid identity")
	}
	copy(i[:], id)
	return &i, nil
}

// Secret is the ephemeral private key that a node uses for signing challenges.
// It also provides the publicly known derived Identity.
type Secret struct {
	privateKey *secp256k1.PrivateKey

	Identity // Provides stringer
}

// PublicKey returns the public key of the secret.
func (s Secret) PublicKey() *secp256k1.PublicKey {
	return s.privateKey.PubKey()
}

// Sign signs a hash and returns the signature. Don't be a smartass and send
// anything but a hash into this function.
func (s Secret) Sign(hash []byte) []byte {
	return ecdsa.SignCompact(s.privateKey, hash[:], true)
}

// NaClPrivateKey returns the X25519 private key derived from the
// secp256k1 private key using domain-separated SHA256.
func (s Secret) NaClPrivateKey() (*ecdh.PrivateKey, error) {
	h := sha256.New()
	h.Write([]byte("continuum-x25519-v1"))
	h.Write(s.privateKey.Serialize())
	seed := h.Sum(nil)
	return ecdh.X25519().NewPrivateKey(seed)
}

// NaClPublicKey returns the X25519 public key bytes corresponding to
// the derived private key.
func (s Secret) NaClPublicKey() ([]byte, error) {
	priv, err := s.NaClPrivateKey()
	// untested: NaClPrivateKey derives curve25519 from valid secp256k1; cannot fail with valid secret
	if err != nil {
		return nil, err
	}
	return priv.PublicKey().Bytes(), nil
}

// SealBox encrypts plaintext to the recipient's X25519 public key
// using the sender's X25519 private key.  Returns an EncryptedPayload
// with a random nonce, the sender's identity, and the inner type hint.
func SealBox(plaintext []byte, recipientPub []byte, senderPriv *ecdh.PrivateKey, senderID Identity, innerType PayloadType) (*EncryptedPayload, error) {
	if len(recipientPub) != NaClPubSize {
		return nil, fmt.Errorf("recipient %w: len %d", ErrInvalidNaClPub, len(recipientPub))
	}

	var nonce [24]byte
	// untested: rand.Read fails only on OS entropy exhaustion
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	var pub, priv [32]byte
	copy(pub[:], recipientPub)
	copy(priv[:], senderPriv.Bytes())

	sealed := box.Seal(nil, plaintext, &nonce, &pub, &priv)
	return &EncryptedPayload{
		Nonce:      nonce,
		Ciphertext: sealed,
		Sender:     senderID,
		InnerType:  innerType,
	}, nil
}

// OpenBox decrypts an EncryptedPayload using the recipient's X25519
// private key and the sender's X25519 public key.
func OpenBox(ep *EncryptedPayload, senderPub []byte, recipientPriv *ecdh.PrivateKey) ([]byte, error) {
	if len(senderPub) != NaClPubSize {
		return nil, fmt.Errorf("sender %w: len %d", ErrInvalidNaClPub, len(senderPub))
	}

	var pub, priv [32]byte
	copy(pub[:], senderPub)
	copy(priv[:], recipientPriv.Bytes())

	plaintext, ok := box.Open(nil, ep.Ciphertext, &ep.Nonce, &pub, &priv)
	if !ok {
		return nil, errors.New("nacl box open failed")
	}
	return plaintext, nil
}

// Verify verifies that hash was signed by the provided identity. It returns
// the derived compact public key.
func Verify(hash []byte, remote Identity, sig []byte) (*secp256k1.PublicKey, error) {
	publicKey, compact, err := ecdsa.RecoverCompact(sig, hash[:])
	if err != nil {
		return nil, err
	}
	if !compact {
		return nil, ErrNotCompact
	}
	recoveredID := NewIdentityFromPub(publicKey)
	if !bytes.Equal(recoveredID[:], remote[:]) {
		return nil, ErrIdentityMismatch
	}
	return publicKey, nil
}

// NewSecretFromPrivate returns a secret type for the provided private key.
func NewSecretFromPrivate(privateKey *secp256k1.PrivateKey) *Secret {
	return &Secret{
		privateKey: privateKey,
		Identity:   NewIdentityFromPub(privateKey.PubKey()),
	}
}

// NewSecretFromString returns a Secret for the provided hex-encoded private
// key string.
func NewSecretFromString(secret string) (*Secret, error) {
	s, err := hex.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	// This may not always be the case and may need to be a range.
	if len(s) != 32 {
		return nil, fmt.Errorf("invalid key")
	}
	return NewSecretFromPrivate(secp256k1.PrivKeyFromBytes(s)), nil
}

// NewSecret returns a secret type with a randomly generated private key.
func NewSecret() (*Secret, error) {
	s, err := secp256k1.GeneratePrivateKey()
	// untested: secp256k1.GeneratePrivateKey wraps crypto/rand, fails only on OS entropy exhaustion
	if err != nil {
		return nil, err
	}
	return NewSecretFromPrivate(s), nil
}

// TransportRequest advertises the ephemeral public key. It is the only command
// that travels in the clear.
type TransportRequest struct {
	Version   uint32 `json:"version"`
	PublicKey []byte `json:"publickey"`
}

// Sentinel errors returned by transport and handshake operations.
var (
	ErrDecrypt                = errors.New("could not decrypt")
	ErrIdentityMismatch       = errors.New("identity mismatch")
	ErrInvalidChallenge       = errors.New("invalid challenge")
	ErrInvalidPublicKey       = errors.New("invalid public key")
	ErrInvalidSecretboxLength = errors.New("invalid secretbox length")
	ErrInvalidTXTRecord       = errors.New("invalid TXT record")
	ErrNoConn                 = errors.New("no connection")
	ErrNotCompact             = errors.New("not a compact public key")
	ErrNoSuitableCurve        = errors.New("no suitable curve found")
	ErrUnsupportedVersion     = errors.New("unsupported version")
	ErrMessageTooLarge        = errors.New("message too large")
	ErrInvalidNaClPub         = errors.New("invalid nacl public key")
	ErrUseBroadcast           = errors.New("broadcast-type payload: use Broadcast(), not SendEncrypted()")
	ErrNotInCommittee         = errors.New("self not in old or new committee")
	ErrUnknownCeremony        = errors.New("unknown ceremony")

	// placeholders until we decide on timeout handling
	readTimeout  time.Duration = 4 * time.Second
	writeTimeout time.Duration = 4 * time.Second
)

// Transport is an opaque type that provides encrypted transport for
// arbitrarily sized cleartext.
//
// Server Example:
//
//	server, _ := NewTransportFromCurve(ecdh.P256())
//	serverSecret, _ := NewSecret()
//	l := net.ListenConfig{}
//	listener, _ := l.Listen(ctx, "tcp", <ADDRESS:PORT>)
//	conn, _ := listener.Accept()
//	server.KeyExchange(ctx, conn)
//	derivedClient, _ := server.Handshake(ctx, serverSecret)
//
// Client Example:
//
//	client := new(Transport)
//	clientSecret, _ := NewSecret()
//	d := &net.Dialer{}
//	conn, _ := d.DialContext(ctx, "tcp", <ADDRESS:PORT>)
//	client.KeyExchange(ctx, conn)
//	derivedServer, _ := client.Handshake(ctx, clientSecret)
type Transport struct {
	mtx sync.Mutex

	// Transport encryption bits
	isServer   bool             // server or client
	curve      ecdh.Curve       // transport encryption curve
	us         *ecdh.PrivateKey // our transport ephemeral private key
	them       *ecdh.PublicKey  // their ephemeral public key
	encryptKey *[32]byte        // directional encryption key (our sends)
	decryptKey *[32]byte        // directional decryption key (their sends)
	nonce      *Nonce           // transport nonce

	conn net.Conn
}

// allowedCurves are the curves that the server and client are allowed to use.
// Note that the server side dictates which curve the client must use. If the
// client does not approve it should hang up.
var allowedCurves = []ecdh.Curve{ecdh.X25519(), ecdh.P521(), ecdh.P384(), ecdh.P256()}

// String returns what mode this transport is in.
func (t *Transport) String() string {
	if t.isServer {
		return "server"
	}
	return "client"
}

// Curve returns the curve name.
func (t *Transport) Curve() string {
	return fmt.Sprintf("%v", t.curve) // Can't directly call the stringer.
}

// NewTransportFromCurve creates a server transport for the provided curve.
// This is the listening side.
func NewTransportFromCurve(curve ecdh.Curve) (*Transport, error) {
	privateKey, err := curve.GenerateKey(rand.Reader)
	// untested: ecdh.GenerateKey wraps rand.Reader, fails only on OS entropy exhaustion
	if err != nil {
		return nil, err
	}

	return &Transport{
		curve:    curve,
		us:       privateKey,
		isServer: true,
	}, nil
}

// newTransportFromPublicKey creates a client transport based on the server
// public key. This is the connecting side.
//
// This utility function is probably only useful in tests.
func newTransportFromPublicKey(publicKey []byte) (*Transport, error) {
	t := new(Transport)
	err := t.setTransportFromPublicKey(publicKey)
	return t, err
}

// setTransportFromPublicKey is used during Handshake to fill out the client
// side ephemeral key. The correct curve is picked based on the public key that
// is passed in.
func (t *Transport) setTransportFromPublicKey(publicKey []byte) error {
	for _, curve := range allowedCurves {
		theirPublicKey, err := curve.NewPublicKey(publicKey)
		if err != nil {
			continue
		}

		privateKey, err := curve.GenerateKey(rand.Reader)
		// untested: ecdh.GenerateKey wraps rand.Reader, fails only on OS entropy exhaustion
		if err != nil {
			return err
		}
		t.mtx.Lock()
		t.curve = curve
		t.us = privateKey
		t.them = theirPublicKey
		t.mtx.Unlock()
		return nil
	}

	return ErrNoSuitableCurve
}

// Close closes the underlying connection but leaves the ephemeral encryption
// key and connection set. This is deliberate to prevent reuse.
func (t *Transport) Close() error {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.conn == nil {
		return ErrNoConn
	}
	return t.conn.Close()
}

// RemoteAddr returns the remote network address of the underlying
// connection.  Used for localhost-only admin RPC gating.
func (t *Transport) RemoteAddr() net.Addr {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.conn == nil {
		return nil
	}
	return t.conn.RemoteAddr()
}

// KeyExchange returns directional encryption keys for the provided private and
// public keys. The keys are derived from the shared ECDH secret using HKDF
// with SHA256, a protocol-specific salt, and directional info strings.
// Returns (serverToClientKey, clientToServerKey, error).
func KeyExchange(us *ecdh.PrivateKey, them *ecdh.PublicKey) (*[32]byte, *[32]byte, error) {
	// Shared secret seed.
	shared, err := us.ECDH(them)
	// untested: ECDH cannot fail with two valid keys from the same curve
	if err != nil {
		return nil, nil, err
	}

	hkdfSalt := []byte("continuum-hkdf-salt-v1")

	// Derive server-to-client key.
	var s2cKey [32]byte
	s2c := hkdf.New(sha256.New, shared, hkdfSalt, []byte("continuum-s2c-v1"))
	// untested: HKDF is a PRF with no I/O; io.ReadFull on it cannot fail
	if _, err := io.ReadFull(s2c, s2cKey[:]); err != nil {
		return nil, nil, err
	}

	// Derive client-to-server key.
	var c2sKey [32]byte
	c2s := hkdf.New(sha256.New, shared, hkdfSalt, []byte("continuum-c2s-v1"))
	// untested: HKDF is a PRF with no I/O; io.ReadFull on it cannot fail
	if _, err := io.ReadFull(c2s, c2sKey[:]); err != nil {
		return nil, nil, err
	}

	return &s2cKey, &c2sKey, nil
}

// readJSONLine reads from conn one byte at a time until it encounters a
// newline, then unmarshals the accumulated bytes into v.  This avoids
// json.NewDecoder which buffers ahead and can consume bytes that belong
// to subsequent encrypted messages on the same connection.
func readJSONLine(conn net.Conn, v any) error {
	const maxLen = 4096
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return err
		}
		if n == 1 {
			buf = append(buf, b[0])
			if len(buf) > maxLen {
				return fmt.Errorf("%w: %d bytes", ErrMessageTooLarge, len(buf))
			}
			if b[0] == '\n' {
				return json.Unmarshal(buf, v)
			}
		}
	}
}

// KeyExchange performs a series of reads and writes to establish directional
// transport encryption keys between the server and the client. Each side
// derives a server-to-client and client-to-server key from ECDH. The server
// dictates the curve.
func (t *Transport) KeyExchange(ctx context.Context, conn net.Conn) error {
	var (
		them         *ecdh.PublicKey
		tr           TransportRequest
		greatSuccess bool
	)

	// If KeyExchange is aborted the connection is killed.
	defer func() {
		if !greatSuccess {
			// untested: Close() error is logged not returned; cosmetic on real connections
			if err := conn.Close(); err != nil {
				log.Errorf("KeyExchange: %v", err)
			}
		}
	}()

	// The key exchange should finish in less than 5 seconds.
	// The deadline is set on the net.Conn directly because the KX
	// reads/writes are not context-aware (crypto/ecdh).  The parent
	// context is used for cancellation in the caller.
	timeout := 5 * time.Second
	// untested: SetDeadline cannot fail on real net.TCPConn; requires mock net.Conn
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if t.isServer {
		// Send TransportRequest
		// untested: json.Encode of TransportRequest (only []byte + uint32) cannot fail
		if err := json.NewEncoder(conn).Encode(TransportRequest{
			Version:   TransportVersion,
			PublicKey: t.us.PublicKey().Bytes(),
		}); err != nil {
			return err
		}

		// Read TransportRequest
		if err := readJSONLine(conn, &tr); err != nil {
			return err
		}
		// log.Infof("server read %v", spew.Sdump(tr))
	} else {
		// Read TransportRequest
		if err := readJSONLine(conn, &tr); err != nil {
			return err
		}
		// log.Infof("client read %v", spew.Sdump(tr))

		if err := t.setTransportFromPublicKey(tr.PublicKey); err != nil {
			return err
		}

		// Send TransportRequest
		if err := json.NewEncoder(conn).Encode(TransportRequest{
			Version:   TransportVersion,
			PublicKey: t.us.PublicKey().Bytes(),
		}); err != nil {
			return err
		}
	}

	// Validate other side TransportRequest
	if tr.Version != TransportVersion {
		return ErrUnsupportedVersion
	}
	if len(tr.PublicKey) <= 0 {
		return ErrInvalidPublicKey
	}

	them, err := t.curve.NewPublicKey(tr.PublicKey)
	if err != nil {
		return err
	}
	s2cKey, c2sKey, err := KeyExchange(t.us, them)
	// untested: KeyExchange wraps ECDH; cannot fail with valid curve keys
	if err != nil {
		return err
	}

	nonce, err := NewNonce()
	// untested: NewNonce wraps rand.Read; fails only on OS entropy exhaustion
	if err != nil {
		return err
	}

	// Reset deadline for connection
	// untested: SetDeadline cannot fail on real net.TCPConn; requires mock net.Conn
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	// Assign directional keys based on role.
	t.mtx.Lock()
	if t.isServer {
		t.encryptKey = s2cKey
		t.decryptKey = c2sKey
	} else {
		t.encryptKey = c2sKey
		t.decryptKey = s2cKey
	}
	t.them = them
	t.nonce = nonce
	t.conn = conn
	t.mtx.Unlock()

	greatSuccess = true // High five!

	return nil
}

// encrypt encrypts the passed in slice. The returned encrypted data is
// prepended with a length and a nonce. This is to facilitate writes directly
// on the wire.
func (t *Transport) encrypt(cleartext []byte) ([]byte, error) {
	ts := TransportNonceSize + len(cleartext) + secretbox.Overhead
	if ts > TransportMaxSize {
		return nil, ErrMessageTooLarge
	}

	// Encode size to prefix nonce
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(ts))
	nonce := t.nonce.Next()
	blob := secretbox.Seal(append(size[1:4], nonce[:]...), cleartext, nonce,
		t.encryptKey)

	// diagnostic
	// untested: diagnostic assertion; unreachable unless secretbox implementation is broken
	if ts != len(blob)-3 {
		panic(fmt.Errorf("encryption diagnostic: wanted %v got %v",
			ts, len(blob)))
	}
	return blob, nil
}

// decrypt decrypts the passed in ciphertext. The ciphertext must be prefixed
// with the nonce. Note that the three byte length must have been clipped off.
func (t *Transport) decrypt(ciphertext []byte) ([]byte, error) {
	// Make sure we have received enough bytes to decrypt.
	if len(ciphertext) < TransportNonceSize+1+secretbox.Overhead {
		return nil, ErrInvalidSecretboxLength
	}

	var nonce [TransportNonceSize]byte
	copy(nonce[:], ciphertext[:TransportNonceSize])
	cleartext, ok := secretbox.Open(nil, ciphertext[TransportNonceSize:], &nonce,
		t.decryptKey)
	if !ok {
		return nil, ErrDecrypt
	}
	return cleartext, nil
}

// Handshake advertises to the other side what version and options this
// transport wishes to use. It is also used to verify that the derived Identity
// did indeed sign the challenge. If dnsName is non-empty, it is advertised
// in the hello options so the remote can verify our identity via DNS TXT
// lookup. Returns the remote identity, their advertised DNS name (empty
// if they did not advertise one), and their X25519 public key for e2e
// encryption.
func (t *Transport) Handshake(ctx context.Context, secret *Secret, dnsName string) (*Identity, string, []byte, error) {
	var ourChallenge [32]byte
	_, err := rand.Read(ourChallenge[:])
	// untested: rand.Read fails only on OS entropy exhaustion
	if err != nil {
		return nil, "", nil, err
	}

	naclPub, err := secret.NaClPublicKey()
	// untested: NaClPublicKey wraps NaClPrivateKey; cannot fail with valid secret
	if err != nil {
		return nil, "", nil, fmt.Errorf("nacl public key: %w", err)
	}

	opts := map[string]string{
		"encoding":    "json",
		"compression": "none",
	}
	if dnsName != "" {
		opts["dns"] = dnsName
	}

	// Write HelloRequest
	err = t.Write(secret.Identity, HelloRequest{
		Version:   ProtocolVersion,
		Identity:  secret.Identity,
		Challenge: ourChallenge[:],
		Options:   opts,
		NaClPub:   naclPub,
	})
	if err != nil {
		return nil, "", nil, err
	}

	// Read Hello
	_, cmd, _, err := t.read(readTimeout)
	if err != nil {
		return nil, "", nil, err
	}
	helloRequest, ok := cmd.(*HelloRequest)
	if !ok {
		return nil, "", nil, fmt.Errorf("unexpected command: %T, wanted HelloRequest", cmd)
	}
	// Validate HelloRequest
	if helloRequest.Version != ProtocolVersion {
		return nil, "", nil, ErrUnsupportedVersion
	}
	if len(helloRequest.Challenge) != ChallengeSize {
		return nil, "", nil, ErrInvalidChallenge
	}
	if bytes.Equal(ZeroChallenge[:], helloRequest.Challenge) {
		return nil, "", nil, ErrInvalidChallenge
	}
	// Validate NaCl public key length when present.
	if len(helloRequest.NaClPub) > 0 && len(helloRequest.NaClPub) != NaClPubSize {
		return nil, "", nil, fmt.Errorf("%w: len %d", ErrInvalidNaClPub, len(helloRequest.NaClPub))
	}

	// Sign combined challenge that is represented by the sha256 hash of
	// their challenge plus ephemeral transport public key and reply.
	combinedChallenge := Hash256(helloRequest.Challenge, t.them.Bytes())
	if err := t.Write(secret.Identity, HelloResponse{
		Signature: secret.Sign(combinedChallenge),
	}); err != nil {
		return nil, "", nil, err
	}

	// Read HelloResponse
	header2, cmd2, _, err := t.read(readTimeout)
	if err != nil {
		return nil, "", nil, err
	}
	_ = header2
	helloResponse, ok := cmd2.(*HelloResponse)
	if !ok {
		return nil, "", nil, fmt.Errorf("unexpected command: %T", cmd2)
	}

	// Verify signature over sha256(our challenge + our transport public key)
	linkedChallenge := Hash256(ourChallenge[:], t.us.PublicKey().Bytes())
	themPub, err := Verify(linkedChallenge[:], helloRequest.Identity,
		helloResponse.Signature)
	if err != nil {
		return nil, "", nil, err
	}

	themID := NewIdentityFromPub(themPub)
	theirDNS := helloRequest.Options["dns"]

	return &themID, theirDNS, helloRequest.NaClPub, nil
}

// readBlob locks the connection and reads a size and the associated blob into
// a slice and returns that. It is locked for the duration to prevent
// interleaved reads.
func (t *Transport) readBlob(timeout time.Duration) ([]byte, error) {
	t.mtx.Lock()
	conn := t.conn
	t.mtx.Unlock()

	if timeout != 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
	} else {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}

	// Blob size is 24 bits or 3 bytes encoded in big endian
	var (
		sizeRE [4]byte
		at     int
		sizeR  uint32
	)
	for {
		n, err := conn.Read(sizeRE[1:4]) // read 3 bytes for the nonce+ciphertext
		if err != nil {
			return nil, err
		}
		at += n
		// untested: partial 3-byte size read; net.Pipe and TCP deliver small reads atomically
		if at < 3 {
			continue
		}
		sizeR = binary.BigEndian.Uint32(sizeRE[:])
		break
	}

	// untested: 3-byte size field max (16MB) equals TransportMaxSize; unreachable with valid framing
	if sizeR > TransportMaxSize {
		return nil, ErrMessageTooLarge
	}

	blob := make([]byte, sizeR)
	at = 0
	for {
		n, err := conn.Read(blob[at:])
		if err != nil {
			return nil, err
		}
		at += n
		if at < len(blob) {
			continue
		}
		return blob, nil
	}
}

// read reads the next encrypted blob from the connection stream.
// Returns the parsed header, payload, and the raw cleartext bytes
// (header+payload before JSON parsing).  The cleartext is used for
// message deduplication and forwarding.
func (t *Transport) read(timeout time.Duration) (*Header, any, []byte, error) {
	ciphertext, err := t.readBlob(timeout)
	if err != nil {
		return nil, nil, nil, err
	}
	cleartext, err := t.decrypt(ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}

	// log.Infof("%v: read cleartext %v", t, spew.Sdump(cleartext))
	jd := json.NewDecoder(bytes.NewReader(cleartext))
	var header Header
	if err := jd.Decode(&header); err != nil {
		return nil, nil, nil, err
	}
	// log.Infof("%v: read %v", t, header.PayloadType)

	// Extract payload portion from cleartext for hash verification
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal header: %w", err)
	}
	if len(cleartext) <= len(headerBytes) {
		return nil, nil, nil, fmt.Errorf("cleartext too short for payload")
	}
	payloadBytes := cleartext[len(headerBytes):]

	// Verify payload hash matches the declared hash in header
	expectedHash := NewPayloadHash(payloadBytes)
	if !bytes.Equal(header.PayloadHash[:], expectedHash[:]) {
		return nil, nil, nil, fmt.Errorf("payload hash mismatch: got %v, want %v",
			expectedHash, header.PayloadHash)
	}

	ct, ok := str2pt[header.PayloadType]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unsupported: %v", header.PayloadType)
	}
	cmd := reflect.New(ct)
	if err := jd.Decode(cmd.Interface()); err != nil {
		return nil, nil, nil, err
	}
	return &header, cmd.Interface(), cleartext, nil
}

// Read reads and decrypts the next command from the connection stream. It
// returns the header and command.
func (t *Transport) Read() (*Header, any, error) {
	h, cmd, _, err := t.read(0 * time.Second) // blocks; ping TTL handles idle
	return h, cmd, err
}

// ReadEnvelope reads the next command and also returns the raw cleartext
// bytes (transport-decrypted but not yet parsed).  Used by handle() for
// message deduplication and forwarding.
func (t *Transport) ReadEnvelope() (*Header, any, []byte, error) {
	return t.read(0 * time.Second) // blocks; ping TTL handles idle
}

// write encrypts the passed in cleartext and writes it to the connection
// stream. This function takes the lock to prevent interleaving writes.
func (t *Transport) write(timeout time.Duration, cleartext []byte) error {
	request, err := t.encrypt(cleartext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Don't interleave writes
	t.mtx.Lock()
	defer t.mtx.Unlock()

	// Timeout
	if timeout != 0 {
		if err := t.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
	} else {
		// untested: SetWriteDeadline cannot fail on real net.TCPConn; requires mock net.Conn
		if err := t.conn.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
	}

	var at int
	for {
		n, err := t.conn.Write(request[at:])
		if err != nil {
			return err
		}
		at += n
		// untested: partial write loop; net.Pipe writes atomically, TCP buffers make this near-impossible
		if at < len(request) {
			continue
		}
		return nil
	}
}

// Write creates a new payload and header and sends that to the peer.
//
// For routed messages that need an explicit destination, use
// WriteRouted which sets the destination identity and TTL.
func (t *Transport) Write(origin Identity, cmd any) error {
	pt, ok := pt2str[reflect.TypeOf(cmd)]
	if !ok {
		return fmt.Errorf("invalid command type: %T", cmd)
	}
	hash, payload, err := NewPayloadFromCommand(cmd)
	// untested: NewPayloadFromCommand uses json.Marshal on wire types; cannot fail with valid cmd
	if err != nil {
		return err
	}
	header, err := json.Marshal(Header{
		PayloadType: pt,
		PayloadHash: *hash,
		Origin:      origin,
		Destination: nil,
		TTL:         1, // expires at the receiver
	})
	// untested: json.Marshal of Header (strings + []byte) cannot fail
	if err != nil {
		return err
	}
	return t.write(writeTimeout, append(header, payload...))
}

// WriteTo creates a routed payload with a specific destination and TTL,
// then sends it through the transport.  Used for messages that may need
// multi-hop forwarding.
func (t *Transport) WriteTo(origin, destination Identity, ttlHops uint8, cmd any) error {
	pt, ok := pt2str[reflect.TypeOf(cmd)]
	if !ok {
		return fmt.Errorf("invalid command type: %T", cmd)
	}
	hash, payload, err := NewPayloadFromCommand(cmd)
	// untested: NewPayloadFromCommand uses json.Marshal on wire types; cannot fail with valid cmd
	if err != nil {
		return err
	}
	header, err := json.Marshal(Header{
		PayloadType: pt,
		PayloadHash: *hash,
		Origin:      origin,
		Destination: &destination,
		TTL:         ttlHops,
	})
	// untested: json.Marshal of Header (strings + []byte) cannot fail
	if err != nil {
		return err
	}
	return t.write(writeTimeout, append(header, payload...))
}

// WriteHeader writes an envelope with the given header and payload command.
// Used for forwarding: the caller provides a modified header (e.g.
// decremented TTL) and the already-parsed payload.
func (t *Transport) WriteHeader(h Header, cmd any) error {
	_, payload, err := NewPayloadFromCommand(cmd)
	if err != nil {
		return err
	}
	header, err := json.Marshal(h)
	// untested: json.Marshal of Header (strings + []byte) cannot fail
	if err != nil {
		return err
	}
	return t.write(writeTimeout, append(header, payload...))
}

// kvFromTxt converts a TXT record to a key value map. The format is typical INI
// file style. E.g. "v=transfunctioner identity=myidentity key=value".
func kvFromTxt(txt string) (map[string]string, error) {
	s := strings.Split(txt, "; ")
	m := make(map[string]string)
	for _, v := range s {
		kv := strings.SplitN(v, "=", 2)
		if len(kv) != 2 {
			return nil, ErrInvalidTXTRecord
		}
		m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return m, nil
}

// TXTRecordFromAddress returns one and only one TXT record that is associated
// with an address.
//
// Note: reverse DNS is unreliable in cloud environments (AWS, Cloudflare).
// A future DNS rework will switch to forward-lookup with hints provided
// during the encrypted handshake.  See SOW4 §9 deferred items.
func TXTRecordFromAddress(ctx context.Context, resolver *net.Resolver, addr net.Addr) (map[string]string, error) {
	if resolver == nil {
		resolver = &net.Resolver{}
	}

	h, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, fmt.Errorf("dns split: %w", err)
	}
	rl, err := resolver.LookupAddr(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("dns lookup: %w", err)
	}
	if len(rl) < 1 {
		return nil, fmt.Errorf("dns lookup: no records for %v", addr)
	}
	txts, err := resolver.LookupTXT(ctx, rl[0])
	if err != nil {
		return nil, err
	}
	if len(txts) != 1 {
		return nil, fmt.Errorf("dns no txt records: %v", len(txts))
	}
	return kvFromTxt(txts[0])
}

// VerifyRemoteDNSIdentity verifies that passed in identity matches its
// associated TXT record identity. This can be used to determine if a server or
// client are indeed who they claim they are.
//
// Note: reverse DNS verification is unreliable in cloud environments.
// A future DNS rework will switch to forward-lookup verification.
// See SOW4 §9 deferred items.
func VerifyRemoteDNSIdentity(ctx context.Context, r *net.Resolver, addr net.Addr, id Identity) (bool, error) {
	m, err := TXTRecordFromAddress(ctx, r, addr)
	if err != nil {
		return false, err
	}
	// Port field present in TXT record but unused; kept for
	// future forward-lookup DNS rework.

	if m["v"] != dnsAppName {
		return false, fmt.Errorf("dns invalid app name: '%v'", m["v"])
	}
	remoteDNSID, err := NewIdentityFromString(m["identity"])
	if err != nil {
		return false, fmt.Errorf("dns invalid identity: %w", err)
	}
	return bytes.Equal(id[:], remoteDNSID[:]), nil
}

// TODO(dns-rework): add VerifyRemoteDNSIdentityByHostname for forward-lookup
// verification to replace reverse-DNS approach.
