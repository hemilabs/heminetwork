// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build unix

package level

import "syscall"

// nofileLimit returns the soft RLIMIT_NOFILE and whether it could be
// determined.
func nofileLimit() (uint64, bool) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		// Unreachable in practice; see checkFileLimit.
		return 0, false
	}
	return lim.Cur, true
}
