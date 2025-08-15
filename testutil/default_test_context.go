// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"context"
	"time"
)

// DefaultTestContext returns a context with a 300-second timeout for tests
func DefaultTestContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	return ctx, cancel
}
