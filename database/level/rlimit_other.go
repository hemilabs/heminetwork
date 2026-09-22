// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build !unix

package level

// nofileLimit returns the soft file descriptor limit and whether it
// could be determined. Not available on this platform.
func nofileLimit() (uint64, bool) {
	return 0, false
}
