// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build !continuum_debug

package continuum

// serverDebugInit returns nil in production builds.
// Wire-initiated ceremonies are rejected when debugInit is nil.
func serverDebugInit() *debugInitiator {
	return nil
}
