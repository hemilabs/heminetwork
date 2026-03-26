// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build continuum_debug

package continuum

// serverDebugInit returns a debugInitiator for debug builds.
// This allows wire-initiated ceremonies via hemictl commands.
func serverDebugInit() *debugInitiator {
	return newDebugInitiator()
}
