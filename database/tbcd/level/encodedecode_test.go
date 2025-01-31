package level

import (
	"reflect"
	"testing"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/hemi"
)

func TestKeystoneEncodeDecode(t *testing.T) {
	hks := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       fillOutBytes("v1parentephash", 32),
		PrevKeystoneEPHash: fillOutBytes("v1prevkeystoneephash", 32),
		StateRoot:          fillOutBytes("v1stateroot", 32),
		EPHash:             fillOutBytes("v1ephash", 32),
	}
	abrvKs := hemi.L2KeystoneAbbreviate(hks).Serialize()
	ks := tbcd.Keystone{
		BlockHash:           btcchainhash.Hash(fillOutBytes("blockhash", 32)),
		AbbreviatedKeystone: abrvKs,
	}
	eks := encodeKeystone(ks)
	nks := decodeKeystone(eks[:])
	if !reflect.DeepEqual(nks, ks) {
		t.Fatal("decoded keystone not equal")
	}
}
