// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/juju/loggo"
)

const (
	daemonName      = "auth"
	defaultLogLevel = daemonName + "=INFO"

	nonceLength = 16
)

var (
	log = loggo.GetLogger(daemonName)

	zeroNonce = [nonceLength]byte{}
)

// AuthenticateMessage
type AuthenticateMessage struct {
	Nonce   [nonceLength]byte // random nonce
	Message string            // human readable message
}

func NewAuthenticateMessage(message string) (*AuthenticateMessage, error) {
	am := &AuthenticateMessage{
		Message: message,
	}
	_, err := io.ReadFull(rand.Reader, am.Nonce[:])
	if err != nil {
		return nil, fmt.Errorf("readfull: %w", err)
	}
	return am, nil
}

func MustNewAuthenticateMessage(message string) *AuthenticateMessage {
	am, err := NewAuthenticateMessage(message)
	if err != nil {
		panic(err)
	}
	return am
}

func NewAuthenticateFromBytes(b []byte) (*AuthenticateMessage, error) {
	if len(b) < nonceLength {
		return nil, errors.New("authenicate message too short")
	}
	am := &AuthenticateMessage{}
	copy(am.Nonce[0:], b[:nonceLength])
	am.Message = string(b[nonceLength:])
	if bytes.Equal(am.Nonce[:], zeroNonce[:]) {
		return nil, errors.New("invalid nonce")
	}
	return am, nil
}

func (am *AuthenticateMessage) Serialize() []byte {
	b := make([]byte, nonceLength+len(am.Message))
	copy(b[:nonceLength], am.Nonce[:])
	copy(b[nonceLength:], []byte(am.Message))
	return b
}

func (am *AuthenticateMessage) Hash() []byte {
	hash := sha256.Sum256(am.Serialize())
	return hash[:]
}
