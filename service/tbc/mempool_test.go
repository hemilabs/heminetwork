// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

func TestMempoolFees(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mp, err := MempoolNew()
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
			mp.TxsInsert(ctx, &mptx)
		}
	}

	recs, err := mp.GetRecommendedFees(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(spew.Sdump(recs))
}

func TestMempoolMassReaping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mp, err := MempoolNew()
	if err != nil {
		t.Fatal(err)
	}

	const (
		txNum    = 1000
		rounds   = 5
		totalTxs = txNum * rounds
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
			mp.TxsInsert(ctx, &mptx)
		}
	}

	size, _ := mp.stats(ctx)
	if size != totalTxs {
		t.Fatalf("mempool has %v txs, expected %v", size, totalTxs)
	}

	for k := range rounds {
		time.Sleep(time.Until(expire.Add(time.Duration(k) * time.Second)))

		mp.reap()

		size, _ = mp.stats(ctx)
		if size != totalTxs-((k+1)*txNum) {
			t.Fatalf("mempool has %v txs, expected %v", size, 0)
		}
		t.Logf("%v txs reaped at %v, %v txs left", txNum, time.Since(expire).Seconds(), size)
	}
}

func TestMempoolReaping(t *testing.T) {
	type testTableItem struct {
		name           string
		txNum          int
		waitTime       time.Duration
		txExpireOffset time.Duration
		expectedOut    int
	}

	testTable := []testTableItem{
		{
			name:        "TestAllOut",
			txNum:       10,
			waitTime:    0,
			expectedOut: 10,
		},
		{
			name:           "TestAllIn",
			txNum:          10,
			waitTime:       0,
			txExpireOffset: time.Hour,
			expectedOut:    0,
		},
		{
			name:           "TestHalfIn",
			txNum:          10,
			waitTime:       500 * time.Millisecond,
			txExpireOffset: 100 * time.Millisecond,
			expectedOut:    5,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			mp, err := MempoolNew()
			if err != nil {
				t.Fatal(err)
			}

			curTime := time.Now()
			sleepUntil := curTime.Add(tti.waitTime)

			txsToInsert := createTxs(tti.txNum, curTime, tti.txExpireOffset)
			for _, tx := range txsToInsert {
				mp.TxsInsert(ctx, &tx)
			}

			size, _ := mp.stats(ctx)
			if size != tti.txNum {
				t.Fatalf("mempool has %v txs, expected %v", size, tti.txNum)
			}

			time.Sleep(time.Until(sleepUntil))
			mp.reap()

			for txIndex := range tti.expectedOut {
				if _, ok := mp.txs[txsToInsert[txIndex].id]; ok {
					t.Fatalf("expected %v to be out", txsToInsert[txIndex].id)
				}
			}

			for i := tti.expectedOut; i != tti.txNum; i++ {
				if _, ok := mp.txs[txsToInsert[i].id]; !ok {
					t.Fatalf("expected %v to be in", txsToInsert[i].id)
				}
			}
		})
	}
}

func TestMempoolRemove(t *testing.T) {
	type testTableItem struct {
		name       string
		txIDs      []string
		toRemove   []string
		expectedIn []string
	}

	testTable := []testTableItem{
		{
			name:     "TestRemoveAll",
			txIDs:    []string{"a", "b", "c", "d", "e"},
			toRemove: []string{"a", "b", "c", "d", "e"},
		},
		{
			name:       "TestRemoveNone",
			txIDs:      []string{"a", "b", "c", "d", "e"},
			expectedIn: []string{"a", "b", "c", "d", "e"},
		},
		{
			name:       "TestRemoveHalf",
			txIDs:      []string{"a", "b", "c", "d", "e"},
			toRemove:   []string{"a", "b", "c"},
			expectedIn: []string{"d", "e"},
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			mp, err := MempoolNew()
			if err != nil {
				t.Fatal(err)
			}

			for _, id := range tti.txIDs {
				ch, err := chainhash.NewHash(fillOutBytes(id, 32))
				if err != nil {
					t.Fatal(err)
				}

				mptx := mempoolTx{
					id:      *ch,
					expires: time.Now().Add(1 * time.Hour),
				}
				mp.TxsInsert(ctx, &mptx)
			}

			remTxs := make([]chainhash.Hash, 0, len(tti.toRemove))
			for _, id := range tti.toRemove {
				hash, err := chainhash.NewHash(fillOutBytes(id, 32))
				if err != nil {
					panic(err)
				}
				remTxs = append(remTxs, *hash)
			}

			mp.txsRemove(ctx, remTxs)

			for _, id := range tti.toRemove {
				hash, err := chainhash.NewHash(fillOutBytes(id, 32))
				if err != nil {
					panic(err)
				}
				if _, ok := mp.txs[*hash]; ok {
					t.Fatalf("expected %v to be removed", id)
				}
			}

			for _, id := range tti.expectedIn {
				hash, err := chainhash.NewHash(fillOutBytes(id, 32))
				if err != nil {
					panic(err)
				}
				if _, ok := mp.txs[*hash]; !ok {
					t.Fatalf("expected %v be in mempool", id)
				}
			}
		})
	}
}

func TestMempoolFiltering(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mp, err := MempoolNew()
	if err != nil {
		t.Fatal(err)
	}

	const (
		txNum       = 10
		numToFilter = 5
	)
	utxos := make([]tbcd.Utxo, 0, txNum)

	for i := range txNum {
		uniqueBytes := make([]byte, 32)
		binary.BigEndian.PutUint32(uniqueBytes[0:32], uint32(i))
		ch, err := chainhash.NewHash(uniqueBytes)
		if err != nil {
			t.Fatal(err)
		}
		utxo := tbcd.NewUtxo([32]byte(uniqueBytes), 1000, 0)
		utxos = append(utxos, utxo)

		if len(utxos) > numToFilter {
			opp := wire.NewOutPoint(ch, 0)
			mptx := mempoolTx{
				id:      *ch,
				expires: time.Now().Add(1 * time.Hour),
				txins:   map[wire.OutPoint]struct{}{*opp: {}},
			}
			mp.TxsInsert(ctx, &mptx)
		}
	}

	filtered, err := mp.FilterUtxos(ctx, utxos)
	if err != nil {
		t.Fatal(err)
	}

	if len(filtered) != txNum-numToFilter {
		t.Fatalf("expected %d utxos filtered, got %d", numToFilter, len(utxos)-len(filtered))
	}

	for k, f := range filtered {
		if diff := deep.Equal(f, utxos[k]); len(diff) > 0 {
			t.Fatalf("unexpected diff %s", diff)
		}
	}
}

func BenchmarkMempoolFilter(b *testing.B) {
	for _, mempoolTxNum := range []int{1, 10, 100, 1000, 10000} {
		for _, txInNum := range []int{1, 10, 100, 1000, 10000} {
			mp, err := MempoolNew()
			if err != nil {
				b.Fatal(err)
			}
			utxos := make([]tbcd.Utxo, 0, txInNum*mempoolTxNum)
			// Create new mempoolTx
			for k := range mempoolTxNum {
				txIdBytes := make([]byte, 32)
				binary.BigEndian.PutUint32(txIdBytes[0:32], uint32(k))
				txId, err := chainhash.NewHash(txIdBytes)
				if err != nil {
					b.Fatal(err)
				}

				mptx := mempoolTx{
					id:      *txId,
					expires: time.Now().Add(10 * time.Hour),
					txins:   make(map[wire.OutPoint]struct{}),
				}
				// Create utxo and add it to the mempoolTx
				for i := range txInNum {
					uniqueBytes := make([]byte, 32)
					binary.BigEndian.PutUint32(uniqueBytes[0:15], uint32(i))
					binary.BigEndian.PutUint32(uniqueBytes[16:32], uint32(k))

					utxo := tbcd.NewUtxo([32]byte(uniqueBytes), 1000, uint32(i))
					utxos = append(utxos, utxo)

					opp := wire.NewOutPoint(utxo.ChainHash(), utxo.OutputIndex())
					mptx.txins[*opp] = struct{}{}
				}
				mp.TxsInsert(b.Context(), &mptx)
			}

			// Shuffle created utxos
			rand.Shuffle(len(utxos), func(i, j int) { utxos[i], utxos[j] = utxos[j], utxos[i] })

			// Pick up to 1000 random utxos
			toFilter := utxos[0:min(1000, len(utxos))]

			b.Run(fmt.Sprintf("benchmark %d mempoolTxs with %d txins", mempoolTxNum, txInNum), func(b *testing.B) {
				for b.Loop() {
					_, err = mp.FilterUtxos(b.Context(), toFilter)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func createTxs(count int, expiration time.Time, increase time.Duration) []mempoolTx {
	txs := make([]mempoolTx, 0, count)
	for i := range count {
		uniqueBytes := make([]byte, 32)
		binary.BigEndian.PutUint32(uniqueBytes, uint32(i))
		ch, err := chainhash.NewHash(uniqueBytes)
		if err != nil {
			panic(err)
		}

		mptx := mempoolTx{
			id:      *ch,
			expires: expiration.Add(time.Duration(i+1) * increase),
		}
		txs = append(txs, mptx)
	}

	return txs
}
