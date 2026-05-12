// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"testing"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
)

// TestMaxResponseSize verifies the websocket read limit constant
// is large enough for worst-case block hex payloads.  A 4 MB block
// serialises to ~8 MB hex and the JSON envelope adds overhead; the
// old 6 MiB limit was insufficient.
func TestMaxResponseSize(t *testing.T) {
	const expected = 16 * (1 << 20) // 16 MiB
	if tbcapi.MaxResponseSize != expected {
		t.Fatalf("MaxResponseSize = %d, want %d (16 MiB)",
			tbcapi.MaxResponseSize, expected)
	}
}
