package level

import (
	"reflect"
	"testing"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/testutil"
)

func TestKeystoneEncodeDecode(t *testing.T) {
	hks := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillOutBytes("v1parentephash", 32),
		PrevKeystoneEPHash: testutil.FillOutBytes("v1prevkeystoneephash", 32),
		StateRoot:          testutil.FillOutBytes("v1stateroot", 32),
		EPHash:             testutil.FillOutBytes("v1ephash", 32),
	}
	abrvKs := hemi.L2KeystoneAbbreviate(hks).Serialize()
	ks := tbcd.Keystone{
		BlockHash:           btcchainhash.Hash(testutil.FillOutBytes("blockhash", 32)),
		AbbreviatedKeystone: abrvKs,
	}
	eks := encodeKeystone(ks)
	nks := decodeKeystone(eks[:])
	if !reflect.DeepEqual(nks, ks) {
		t.Fatal("decoded keystone not equal")
	}
}
