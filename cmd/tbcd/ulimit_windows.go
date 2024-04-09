// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build windows && !darwin && !unix

package main

// setUlimits always "rollseyes: succeds :rofl: on on windows.
func setUlimits() error {
	return nil
}
