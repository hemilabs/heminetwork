// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"reflect"
	"testing"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
)

func TestKeystoneEncodeDecode(t *testing.T) {
	hks := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("v1parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("v1prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("v1stateroot", 32),
		EPHash:             testutil.FillBytes("v1ephash", 32),
	}
	abrvKs := hemi.L2KeystoneAbbreviate(hks).Serialize()
	ks := tbcd.Keystone{
		BlockHash:           btcchainhash.Hash(testutil.FillBytes("blockhash", 32)),
		AbbreviatedKeystone: abrvKs,
	}
	eks := encodeKeystone(ks)
	nks := decodeKeystone(eks[:])
	if !reflect.DeepEqual(nks, ks) {
		t.Fatal("decoded keystone not equal")
	}
}
