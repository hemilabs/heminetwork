// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
)

func TestMempoolFees(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mp, err := mempoolNew()
	if err != nil {
		t.Fatal(err)
	}

	for k := range 4 {
		for i := range 1000 {
			uniqueBytes := make([]byte, 8)
			binary.BigEndian.PutUint32(uniqueBytes[0:4], uint32(k))
			binary.BigEndian.PutUint32(uniqueBytes[4:8], uint32(i))

			ch, err := chainhash.NewHashFromStr(hex.EncodeToString(uniqueBytes))
			if err != nil {
				t.Fatal(err)
			}
			mptx := mempoolTx{
				id:       *ch,
				inserted: time.Now(),
				weight:   3000,
				size:     1000,
				inValue:  int64(3000 + k*500),
				outValue: 1000,
			}
			mp.txsInsert(ctx, &mptx)
		}
	}

	recs, err := mp.GetRecommendedFees(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(spew.Sdump(recs))
}
