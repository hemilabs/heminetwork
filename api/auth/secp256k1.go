// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/davecgh/go-spew/spew"
	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/version"
)

const (
	CmdSecp256k1Error                  protocol.Command = "secp256k1-error"
	CmdSecp256k1Hello                                   = "secp256k1-hello"
	CmdSecp256k1HelloChallenge                          = "secp256k1-hello-challenge"
	CmdSecp256k1HelloChallengeAccepted                  = "secp256k1-hello-challenge-accepted"
)

// Secp256k1Hello is a client->server command that sends the client Secp256k1
// public key.
type Secp256k1Hello struct {
	// UserAgent is the client user agent.
	UserAgent string `json:"userAgent,omitempty"`

	// PublicKey is the client compressed public key.
	PublicKey string `json:"publickey"`
}

// Secp256k1HelloChallenge is a server->client command that challenges the
// client to sign the hash of the provided message.
type Secp256k1HelloChallenge struct {
	Message string `json:"message"`
}

// Secp256k1HelloChallengeAccepted is a client->server command containing the
// signature of the Secp256k1HelloChallenge.Message hash.
type Secp256k1HelloChallengeAccepted struct {
	Signature string `json:"signature"`
}

func handleSecp256k1Hello(message string, h *Secp256k1Hello) (*dcrsecpk256k1.PublicKey, *AuthenticateMessage, *Secp256k1HelloChallenge, error) {
	log.Tracef("handleSecp256k1Hello")
	defer log.Tracef("handleSecp256k1Hello exit")

	pkb, err := hex.DecodeString(h.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode key: %w", err)
	}
	pubKey, err := dcrsecpk256k1.ParsePubKey(pkb)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse public key: %w", err)
	}
	am, err := NewAuthenticateMessage(fmt.Sprintf("Hello: %x\nMessage: %v\n",
		pubKey.SerializeCompressed(), message))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new authenticate message: %w", err)
	}

	hc := &Secp256k1HelloChallenge{
		Message: hex.EncodeToString(am.Serialize()),
	}
	return pubKey, am, hc, nil
}

func handleSecp256k1HelloChallenge(privKey *dcrsecpk256k1.PrivateKey, hc *Secp256k1HelloChallenge) (*Secp256k1HelloChallengeAccepted, error) {
	log.Tracef("handleSecp256k1HelloChallenge")
	defer log.Tracef("handleSecp256k1HelloChallenge exit")

	message, err := hex.DecodeString(hc.Message)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	am, err := NewAuthenticateFromBytes(message)
	if err != nil {
		return nil, fmt.Errorf("new authenticator message: %w", err)
	}

	signatureHash := am.Hash()
	signature := dcrecdsa.SignCompact(privKey, signatureHash[:], true)
	return &Secp256k1HelloChallengeAccepted{
		Signature: hex.EncodeToString(signature),
	}, nil
}

func handleSecp256k1HelloChallengeAccepted(am *AuthenticateMessage, hca *Secp256k1HelloChallengeAccepted) (*dcrsecpk256k1.PublicKey, error) {
	log.Tracef("handleSecp256k1HelloChallengeAccepted")
	defer log.Tracef("handleSecp256k1HelloChallengeAccepted exit")

	signature, err := hex.DecodeString(hca.Signature)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	signatureHash := am.Hash()
	derived, _, err := dcrecdsa.RecoverCompact(signature, signatureHash[:])
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	return derived, nil
}

type Secp256k1Auth struct {
	privKey *dcrsecpk256k1.PrivateKey // client private key
	pubKey  *dcrsecpk256k1.PublicKey  // client public key

	remoteUserAgent string                   // client user agent
	remotePubKey    *dcrsecpk256k1.PublicKey // server side remote key (client)
}

func NewSecp256k1AuthClient(privKey *dcrsecpk256k1.PrivateKey) (*Secp256k1Auth, error) {
	return &Secp256k1Auth{privKey: privKey, pubKey: privKey.PubKey()}, nil
}

func NewSecp256k1AuthServer() (*Secp256k1Auth, error) {
	return &Secp256k1Auth{}, nil
}

func (s *Secp256k1Auth) RemoteUserAgent() string {
	return s.remoteUserAgent
}

func (s *Secp256k1Auth) RemotePublicKey() *dcrsecpk256k1.PublicKey {
	pub := *s.remotePubKey
	return &pub
}

// Commands returns the protocol commands for this authenticator.
func (s *Secp256k1Auth) Commands() map[protocol.Command]reflect.Type {
	return map[protocol.Command]reflect.Type{
		CmdSecp256k1Hello:                  reflect.TypeOf(Secp256k1Hello{}),
		CmdSecp256k1HelloChallenge:         reflect.TypeOf(Secp256k1HelloChallenge{}),
		CmdSecp256k1HelloChallengeAccepted: reflect.TypeOf(Secp256k1HelloChallengeAccepted{}),
	}
}

func (s *Secp256k1Auth) HandshakeClient(ctx context.Context, conn protocol.APIConn) error {
	log.Tracef("HandshakeClient")
	defer log.Tracef("HandshakeClient exit")

	pubKey := hex.EncodeToString(s.pubKey.SerializeCompressed())
	id := "Hello:" + pubKey
	err := protocol.Write(ctx, conn, s, id, Secp256k1Hello{
		UserAgent: version.UserAgent(),
		PublicKey: pubKey,
	})
	if err != nil {
		return err
	}

	state := 0 // Connection state machine
	for {
		_, _, payload, err := protocol.Read(ctx, conn, s)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		log.Tracef(spew.Sdump(payload))

		switch c := payload.(type) {
		case *Secp256k1HelloChallenge:
			// Verify state
			if state != 0 {
				return fmt.Errorf("hello unexpected state: %v", state)
			}

			hca, err := handleSecp256k1HelloChallenge(s.privKey, c)
			if err != nil {
				return fmt.Errorf("handleSecp256k1HelloChallenge: %w", err)
			}

			requestID := "HelloChallengeAccepted:" + pubKey
			err = protocol.Write(ctx, conn, s, requestID, hca)
			if err != nil {
				return fmt.Errorf("write HelloChallengeAccepted: %w", err)
			}

			// Exit state machine
			log.Tracef("HandshakeClient complete")
			return nil

		default:
			return fmt.Errorf("unexpected command: %T", payload)
		}
	}
}

func (s *Secp256k1Auth) HandshakeServer(ctx context.Context, conn protocol.APIConn) error {
	log.Tracef("HandshakeServer")
	defer log.Tracef("HandshakeServer exit")

	var am *AuthenticateMessage
	state := 0 // Connection state machine
	for {
		_, _, payload, err := protocol.Read(ctx, conn, s)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		log.Tracef(spew.Sdump(payload))

		switch c := payload.(type) {
		case *Secp256k1Hello:
			// Verify state
			if state != 0 {
				return fmt.Errorf("hello unexpected state: %v", state)
			}
			var hc *Secp256k1HelloChallenge
			s.pubKey, am, hc, err = handleSecp256k1Hello("I am not a robot!", c)
			if err != nil {
				return fmt.Errorf("could not create hello challenge: %v",
					state)
			}

			err = protocol.Write(ctx, conn, s,
				"HelloChallenge:"+c.PublicKey, hc)
			if err != nil {
				return fmt.Errorf("write HelloChallenge: %w", err)
			}

		case *Secp256k1HelloChallengeAccepted:
			// Verify state
			if state != 1 {
				return fmt.Errorf("hello challenge accepted unexpected state: %v", state)
			}
			if am == nil {
				return errors.New("hello challenge accepted message not set")
			}

			derived, err := handleSecp256k1HelloChallengeAccepted(am, c)
			if err != nil {
				return fmt.Errorf("handleSecp256k1HelloChallengeAccepted: %w", err)
			}

			// Exit state machine
			if !derived.IsEqual(s.pubKey) {
				return errors.New("handleSecp256k1HelloChallengeAccepted: not the same signer")
			}
			s.remotePubKey = derived
			log.Tracef("HandshakeServer complete: %x",
				derived.SerializeCompressed())
			return nil

		default:
			return fmt.Errorf("unexpected command: %T", payload)
		}

		state++
	}
}
