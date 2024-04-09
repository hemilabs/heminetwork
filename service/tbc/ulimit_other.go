// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build !linux && !darwin

package tbc

const ulimitSupported = false

func verifyUlimits() error {
	return nil
}
