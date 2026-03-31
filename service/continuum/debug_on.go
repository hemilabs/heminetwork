// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build continuum_debug

package continuum

import "encoding/hex"

// serverDebugInit returns a debugInitiator for debug builds.
// This allows wire-initiated ceremonies via hemictl commands.
func serverDebugInit() *debugInitiator {
	return newDebugInitiator()
}

// DebugPrivateKeyHex returns the hex-encoded secp256k1 private key.
// Only available in debug builds for test infrastructure.  Production
// binaries do not compile this function.
func (s Secret) DebugPrivateKeyHex() string {
	return hex.EncodeToString(s.privateKey.Serialize())
}
