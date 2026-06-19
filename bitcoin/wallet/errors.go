// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import "errors"

var (
	ErrNilArgument          = errors.New("nil argument")
	ErrIndexOutOfRange      = errors.New("index out of range")
	ErrInvalidScalar        = errors.New("invalid scalar")
	ErrInvalidSigHashType   = errors.New("invalid sighash type")
	ErrUnsupportedScript    = errors.New("unsupported script class")
	ErrPubKeyMismatch       = errors.New("public key does not match address")
	ErrParseSig             = errors.New("parse signature")
	ErrInvalidSig           = errors.New("invalid signature")
	ErrNonCanonicalSig      = errors.New("non-canonical signature")
	ErrSigHashDefaultECDSA  = errors.New("SigHashDefault is not valid for ECDSA")
	ErrInvalidSigHashLength = errors.New("invalid sighash length")
	ErrInvalidSigLength     = errors.New("invalid signature length")
	ErrInvalidPubKeyLength  = errors.New("invalid pubkey length")
)
