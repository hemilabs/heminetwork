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

	for k := range 7 {
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
				expires:  time.Now().Add(1 * time.Minute),
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

func TestMempoolReaping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mp, err := mempoolNew()
	if err != nil {
		t.Fatal(err)
	}

	const (
		txNum  = 1000
		rounds = 5
	)
	expire := time.Now().Add(50 * time.Millisecond)

	for k := range rounds {
		for i := range txNum {
			uniqueBytes := make([]byte, 32)
			binary.BigEndian.PutUint32(uniqueBytes[0:15], uint32(i))
			binary.BigEndian.PutUint32(uniqueBytes[16:32], uint32(k))
			ch, err := chainhash.NewHash(uniqueBytes)
			if err != nil {
				t.Fatal(err)
			}

			mptx := mempoolTx{
				id:      *ch,
				expires: expire.Add(time.Duration(k) * time.Second),
			}
			mp.txsInsert(ctx, &mptx)
		}
	}

	size, _ := mp.stats(ctx)
	if size != txNum*rounds {
		t.Fatalf("mempool has %v txs, expected %v", size, txNum*rounds)
	}

	for k := range rounds {
		time.Sleep(time.Until(expire.Add(time.Duration(k) * time.Second)))
		mp.reap()

		size, _ = mp.stats(ctx)
		if size != (txNum*rounds)-((k+1)*txNum) {
			t.Fatalf("mempool has %v txs, expected %v", size, 0)
		}
		t.Logf("%v txs purged at %v", (txNum*rounds)-size, time.Since(expire).Seconds())
	}
}
