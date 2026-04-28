// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"encoding/json"
	"testing"

	"github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"

	_ "embed"
)

//go:embed testdata/preparams.json
var embeddedPreParams []byte

// testPreParams returns cached Paillier preparams from the embedded
// fixture.  Falls back to nil if the fixture can't be parsed (which
// means tests will generate fresh ones and be slow).
func testPreParams(t *testing.T, count int) []keygen.LocalPreParams {
	t.Helper()
	var params []keygen.LocalPreParams
	if err := json.Unmarshal(embeddedPreParams, &params); err != nil {
		t.Fatalf("parse embedded preparams: %v", err)
	}
	if count > len(params) {
		t.Fatalf("need %d preparams, fixture has %d", count, len(params))
	}
	return params[:count]
}
