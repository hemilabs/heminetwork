// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hemi

import (
	"testing"

	"github.com/hemilabs/heminetwork/database/bfgd"
)

func TestBtcFinalityZeroEffectiveHeight(t *testing.T) {
	fin, err := L2BTCFinalityFromBfgd(&bfgd.L2BTCFinality{}, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}

	if fin.BTCFinality != -9 {
		t.Fatalf("should have set finality to -9, received %d", fin)
	}
}

func TestBtcFinalityUpperBound(t *testing.T) {
	fin, err := L2BTCFinalityFromBfgd(&bfgd.L2BTCFinality{}, 1000, 1)
	if err != nil {
		t.Fatal(err)
	}

	if fin.BTCFinality != 100 {
		t.Fatalf("should have set upper bound at 100, received %d", fin)
	}
}
