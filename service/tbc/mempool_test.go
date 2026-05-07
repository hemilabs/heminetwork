// Copyright (c) 2025-2026 Hemi Labs, Inc.
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

	"github.com/hemilabs/heminetwork/v2/api"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
)

func TestMempoolFees(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}

	for k := range 7 {
		for i := range 1000 {
			uniqueBytes := make([]byte, 8)
			binary.BigEndian.PutUint32(uniqueBytes[0:4], uint32(k))
			binary.BigEndian.PutUint32(uniqueBytes[4:8], uint32(i))
			ch := testutil.String2Hash(hex.EncodeToString(uniqueBytes))
			mptx := MempoolTx{
				id:       *ch,
				expires:  time.Now().Add(1 * time.Minute),
				weight:   3000,
				size:     1000,
				inValue:  int64(3000 + k*500),
				outValue: 1000,
			}
			if err = mp.TxInsert(ctx, &mptx); err != nil {
				t.Fatal(err)
			}
		}
	}

	recs, err := mp.GetRecommendedFees(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(spew.Sdump(recs))
}

func TestMempoolMassReaping(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	mp, err := NewMempool()
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
			ch := testutil.Bytes2Hash(uniqueBytes)
			mptx := MempoolTx{
				id:      *ch,
				expires: expire.Add(time.Duration(k) * time.Second),
			}
			if err = mp.TxInsert(ctx, &mptx); err != nil {
				t.Fatal(err)
			}
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
			ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
			defer cancel()

			mp, err := NewMempool()
			if err != nil {
				t.Fatal(err)
			}

			curTime := time.Now()
			sleepUntil := curTime.Add(tti.waitTime)

			txsToInsert := createTxs(tti.txNum, curTime, tti.txExpireOffset)
			for _, tx := range txsToInsert {
				if err = mp.TxInsert(ctx, &tx); err != nil {
					t.Fatal(err)
				}
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
			ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
			defer cancel()

			mp, err := NewMempool()
			if err != nil {
				t.Fatal(err)
			}

			for _, id := range tti.txIDs {
				ch := testutil.Bytes2Hash(testutil.FillBytes(id, 32))
				mptx := MempoolTx{
					id:      *ch,
					expires: time.Now().Add(1 * time.Hour),
				}
				if err = mp.TxInsert(ctx, &mptx); err != nil {
					t.Fatal(err)
				}
			}

			remTxs := make([]chainhash.Hash, 0, len(tti.toRemove))
			for _, id := range tti.toRemove {
				hash := testutil.Bytes2Hash(testutil.FillBytes(id, 32))
				remTxs = append(remTxs, *hash)
			}

			mp.txsRemove(ctx, remTxs)

			for _, id := range tti.toRemove {
				hash := testutil.Bytes2Hash(testutil.FillBytes(id, 32))
				if _, ok := mp.txs[*hash]; ok {
					t.Fatalf("expected %v to be removed", id)
				}
			}

			for _, id := range tti.expectedIn {
				hash := testutil.Bytes2Hash(testutil.FillBytes(id, 32))
				if _, ok := mp.txs[*hash]; !ok {
					t.Fatalf("expected %v be in mempool", id)
				}
			}
		})
	}
}

func TestMempoolFiltering(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	mp, err := NewMempool()
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
		ch := testutil.Bytes2Hash(uniqueBytes)
		utxo := tbcd.NewUtxo([32]byte(uniqueBytes), 1000, 0)
		utxos = append(utxos, utxo)

		if len(utxos) > numToFilter {
			opp := wire.NewOutPoint(ch, 0)
			msgTx := wire.NewMsgTx(2)
			msgTx.AddTxIn(&wire.TxIn{PreviousOutPoint: *opp})
			mptx := NewMempoolTx(msgTx)
			mptx.id = *ch
			mptx.expires = time.Now().Add(1 * time.Hour)
			if err = mp.TxInsert(ctx, &mptx); err != nil {
				t.Fatal(err)
			}
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
			mp, err := NewMempool()
			if err != nil {
				b.Fatal(err)
			}
			utxos := make([]tbcd.Utxo, 0, txInNum*mempoolTxNum)
			// Create new MempoolTx
			for k := range mempoolTxNum {
				txIdBytes := make([]byte, 32)
				binary.BigEndian.PutUint32(txIdBytes[0:32], uint32(k))
				txId := testutil.Bytes2Hash(txIdBytes)
				msgTx := wire.NewMsgTx(2)
				// Create utxo and add it to the MempoolTx
				for i := range txInNum {
					uniqueBytes := make([]byte, 32)
					binary.BigEndian.PutUint32(uniqueBytes[0:15], uint32(i))
					binary.BigEndian.PutUint32(uniqueBytes[16:32], uint32(k))

					utxo := tbcd.NewUtxo([32]byte(uniqueBytes), 1000, uint32(i))
					utxos = append(utxos, utxo)

					opp := wire.NewOutPoint(utxo.ChainHash(), utxo.OutputIndex())
					msgTx.AddTxIn(&wire.TxIn{PreviousOutPoint: *opp})
				}
				mptx := NewMempoolTx(msgTx)
				mptx.id = *txId
				mptx.expires = time.Now().Add(10 * time.Hour)
				if err = mp.TxInsert(b.Context(), &mptx); err != nil {
					b.Fatal(err)
				}
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

func createTxs(count int, expiration time.Time, increase time.Duration) []MempoolTx {
	txs := make([]MempoolTx, 0, count)
	for i := range count {
		uniqueBytes := make([]byte, 32)
		binary.BigEndian.PutUint32(uniqueBytes, uint32(i))
		ch := testutil.Bytes2Hash(uniqueBytes)

		mptx := MempoolTx{
			id:      *ch,
			expires: expiration.Add(time.Duration(i+1) * increase),
		}
		txs = append(txs, mptx)
	}

	return txs
}

func TestUnconfirmedUtxos(t *testing.T) {
	ctx := t.Context()

	script1 := []byte{
		0x00, 0x14, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	script2 := []byte{
		0x00, 0x14, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	sh1 := tbcd.NewScriptHashFromScript(script1)
	sh2 := tbcd.NewScriptHashFromScript(script2)

	t.Run("empty mempool", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}
		utxos, shs, _, err := mp.UnconfirmedUtxos(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(utxos) != 0 || len(shs) != 0 {
			t.Fatalf("empty mempool: got %d utxos, %d shs", len(utxos), len(shs))
		}
	})

	t.Run("returns all outputs with script hashes", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash: *testutil.String2Hash("aa"), Index: 0,
			},
		})
		tx.AddTxOut(wire.NewTxOut(50000, script1))
		tx.AddTxOut(wire.NewTxOut(10000, script2))

		err = mp.TxInsert(ctx, &MempoolTx{
			id: tx.TxHash(), expires: time.Now().Add(time.Hour), tx: tx,
		})
		if err != nil {
			t.Fatal(err)
		}

		utxos, shs, _, err := mp.UnconfirmedUtxos(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(utxos) != 2 {
			t.Fatalf("got %d utxos, want 2", len(utxos))
		}
		if len(shs) != 2 {
			t.Fatalf("got %d script hashes, want 2", len(shs))
		}

		// Verify script hashes match outputs.
		found := map[tbcd.ScriptHash]uint64{}
		for i, u := range utxos {
			found[shs[i]] = u.Value()
		}
		if found[sh1] != 50000 {
			t.Errorf("script1 value = %d, want 50000", found[sh1])
		}
		if found[sh2] != 10000 {
			t.Errorf("script2 value = %d, want 10000", found[sh2])
		}
	})

	t.Run("chain of unconfirmed txs returns all outputs and spent", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}

		txA := wire.NewMsgTx(2)
		txA.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash: *testutil.String2Hash("bb"), Index: 0,
			},
		})
		txA.AddTxOut(wire.NewTxOut(30000, script1))
		txAid := txA.TxHash()

		err = mp.TxInsert(ctx, &MempoolTx{
			id: txAid, expires: time.Now().Add(time.Hour), tx: txA,
		})
		if err != nil {
			t.Fatal(err)
		}

		// TX B spends TX A output 0.
		txB := wire.NewMsgTx(2)
		txB.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: txAid, Index: 0},
		})
		txB.AddTxOut(wire.NewTxOut(29000, script2))

		err = mp.TxInsert(ctx, &MempoolTx{
			id: txB.TxHash(), expires: time.Now().Add(time.Hour), tx: txB,
		})
		if err != nil {
			t.Fatal(err)
		}

		utxos, _, spent, err := mp.UnconfirmedUtxos(ctx)
		if err != nil {
			t.Fatal(err)
		}

		// Both outputs returned.
		if len(utxos) != 2 {
			t.Fatalf("got %d utxos, want 2", len(utxos))
		}

		// Spent outpoints include TX A:0 (spent by TX B) plus
		// the external input spent by TX A.
		if len(spent) != 2 {
			t.Fatalf("got %d spent outpoints, want 2", len(spent))
		}
	})

	t.Run("multiple txs aggregated", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}

		for i := range 5 {
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  *testutil.String2Hash(fmt.Sprintf("%02x", i)),
					Index: 0,
				},
			})
			tx.AddTxOut(wire.NewTxOut(int64(1000*(i+1)), script1))

			err = mp.TxInsert(ctx, &MempoolTx{
				id: tx.TxHash(), expires: time.Now().Add(time.Hour), tx: tx,
			})
			if err != nil {
				t.Fatal(err)
			}
		}

		utxos, shs, _, err := mp.UnconfirmedUtxos(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(utxos) != 5 {
			t.Fatalf("got %d utxos, want 5", len(utxos))
		}

		var total uint64
		for i, u := range utxos {
			total += u.Value()
			if shs[i] != sh1 {
				t.Errorf("utxo %d: wrong script hash", i)
			}
		}
		wantTotal := uint64(1000 + 2000 + 3000 + 4000 + 5000)
		if total != wantTotal {
			t.Errorf("total = %d, want %d", total, wantTotal)
		}
	})

	t.Run("nil tx entries skipped", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}

		// Simulate an inv-only entry (tx not yet downloaded).
		mp.txs[*testutil.String2Hash("cc")] = nil

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash: *testutil.String2Hash("dd"), Index: 0,
			},
		})
		tx.AddTxOut(wire.NewTxOut(7777, script1))

		err = mp.TxInsert(ctx, &MempoolTx{
			id: tx.TxHash(), expires: time.Now().Add(time.Hour), tx: tx,
		})
		if err != nil {
			t.Fatal(err)
		}

		utxos, _, _, err := mp.UnconfirmedUtxos(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(utxos) != 1 {
			t.Fatalf("got %d utxos, want 1", len(utxos))
		}
	})
}

func TestNewMempoolTx(t *testing.T) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash: *testutil.String2Hash("aa"), Index: 0,
		},
	})
	tx.AddTxOut(wire.NewTxOut(50000, []byte{0x51}))

	mptx := NewMempoolTx(tx)
	if mptx.id != tx.TxHash() {
		t.Errorf("id mismatch: got %v, want %v", mptx.id, tx.TxHash())
	}
	if mptx.tx != tx {
		t.Error("tx pointer not stored")
	}
}

func TestMempoolUtxosServer(t *testing.T) {
	ctx := t.Context()

	script := []byte{
		0x00, 0x14, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	t.Run("mempool disabled", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{
			cfg:     &Config{MempoolEnabled: false},
			mempool: mp,
		}

		utxos, shs, spent, err := s.MempoolUtxos(ctx)
		if err == nil {
			t.Fatal("expected error when mempool disabled")
		}
		if utxos != nil || shs != nil || spent != nil {
			t.Fatal("disabled mempool should return nil")
		}
	})

	t.Run("returns all outputs with spent", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{
			cfg:     &Config{MempoolEnabled: true},
			mempool: mp,
		}

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash: *testutil.String2Hash("bb"), Index: 0,
			},
		})
		tx.AddTxOut(wire.NewTxOut(42000, script))

		err = mp.TxInsert(ctx, &MempoolTx{
			id: tx.TxHash(), expires: time.Now().Add(time.Hour), tx: tx,
		})
		if err != nil {
			t.Fatal(err)
		}

		utxos, shs, spent, err := s.MempoolUtxos(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(utxos) != 1 {
			t.Fatalf("got %d utxos, want 1", len(utxos))
		}
		if utxos[0].Value() != 42000 {
			t.Errorf("value = %d, want 42000", utxos[0].Value())
		}
		if shs[0] != tbcd.NewScriptHashFromScript(script) {
			t.Error("script hash mismatch")
		}
		if len(spent) != 1 {
			t.Fatalf("got %d spent, want 1", len(spent))
		}
		if spent[0].Hash != *testutil.String2Hash("bb") || spent[0].Index != 0 {
			t.Error("spent outpoint mismatch")
		}
	})
}

func TestHandleMempoolUtxosRequest(t *testing.T) {
	ctx := t.Context()

	script := []byte{
		0x00, 0x14, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	t.Run("mempool disabled returns error", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{
			cfg:     &Config{MempoolEnabled: false},
			mempool: mp,
		}

		resp, _ := s.handleMempoolUtxosRequest(ctx, &tbcapi.MempoolUtxosRequest{})
		mResp, ok := resp.(*tbcapi.MempoolUtxosResponse)
		if !ok {
			t.Fatalf("wrong type: %T", resp)
		}
		if mResp.Error == nil {
			t.Fatal("expected error for disabled mempool")
		}
	})

	t.Run("returns filtered utxos and spent outpoints", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{
			cfg:     &Config{MempoolEnabled: true},
			mempool: mp,
		}

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash: *testutil.String2Hash("cc"), Index: 0,
			},
		})
		tx.AddTxOut(wire.NewTxOut(99000, script))
		tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))

		mptx := NewMempoolTx(tx)
		mptx.expires = time.Now().Add(time.Hour)
		if err := mp.TxInsert(ctx, &mptx); err != nil {
			t.Fatal(err)
		}

		// Filter for the known script only.
		sh := tbcd.NewScriptHashFromScript(script)
		resp, err := s.handleMempoolUtxosRequest(ctx, &tbcapi.MempoolUtxosRequest{
			ScriptHashes: []api.ByteSlice{sh[:]},
		})
		if err != nil {
			t.Fatal(err)
		}
		mResp, ok := resp.(*tbcapi.MempoolUtxosResponse)
		if !ok {
			t.Fatalf("wrong type: %T", resp)
		}
		if mResp.Error != nil {
			t.Fatalf("unexpected error: %v", mResp.Error)
		}
		if len(mResp.UTXOs) != 1 {
			t.Fatalf("got %d utxos, want 1 (only script match)", len(mResp.UTXOs))
		}
		if len(mResp.SpentOutpoints) != 1 {
			t.Fatalf("got %d spent, want 1", len(mResp.SpentOutpoints))
		}
		if mResp.UTXOs[0].ScriptHash != chainhash.Hash(sh) {
			t.Error("script hash mismatch")
		}
	})

	t.Run("empty script hashes returns error", func(t *testing.T) {
		mp, err := NewMempool()
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{
			cfg:     &Config{MempoolEnabled: true},
			mempool: mp,
		}

		resp, err := s.handleMempoolUtxosRequest(ctx, &tbcapi.MempoolUtxosRequest{})
		if err != nil {
			t.Fatal(err)
		}
		mResp, ok := resp.(*tbcapi.MempoolUtxosResponse)
		if !ok {
			t.Fatalf("wrong type: %T", resp)
		}
		if mResp.Error == nil {
			t.Fatal("expected error for empty script_hashes")
		}
	})
}

func TestInMempoolWithNilEntries(t *testing.T) {
	ctx := t.Context()

	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate inv-only entry (tx announced but not downloaded).
	mp.txs[*testutil.String2Hash("aa")] = nil

	// Insert a real tx that spends outpoint bb:0.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash: *testutil.String2Hash("bb"), Index: 0,
		},
	})
	tx.AddTxOut(wire.NewTxOut(5000, []byte{0x51}))

	mptx := NewMempoolTx(tx)
	mptx.expires = time.Now().Add(time.Hour)
	if err := mp.TxInsert(ctx, &mptx); err != nil {
		t.Fatal(err)
	}

	// Also insert an entry with non-nil MempoolTx but nil tx field.
	mp.mtx.Lock()
	mp.txs[*testutil.String2Hash("cc")] = &MempoolTx{
		id:      *testutil.String2Hash("cc"),
		expires: time.Now().Add(time.Hour),
		tx:      nil,
	}
	mp.mtx.Unlock()

	// bb:0 is spent by the real tx.
	utxoBB := tbcd.NewUtxo(*testutil.String2Hash("bb"), 10000, 0)
	filtered, err := mp.FilterUtxos(ctx, []tbcd.Utxo{utxoBB})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 0 {
		t.Fatalf("bb:0 should be filtered out, got %d", len(filtered))
	}

	// dd:0 is NOT spent by anything.
	utxoDD := tbcd.NewUtxo(*testutil.String2Hash("dd"), 20000, 0)
	filtered, err = mp.FilterUtxos(ctx, []tbcd.Utxo{utxoDD})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 {
		t.Fatalf("dd:0 should survive, got %d", len(filtered))
	}

	// UnconfirmedUtxos should skip nil entries.
	utxos, _, _, err := mp.UnconfirmedUtxos(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 1 {
		t.Fatalf("got %d utxos, want 1 (only real tx)", len(utxos))
	}
}

func TestHandleMempoolInfoRequestWithStats(t *testing.T) {
	ctx := t.Context()

	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg:     &Config{MempoolEnabled: true},
		mempool: mp,
	}

	// Empty mempool.
	resp, err := s.handleMempoolInfoRequest(ctx, &tbcapi.MempoolInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	mResp := resp.(*tbcapi.MempoolInfoResponse)
	if mResp.Error != nil {
		t.Fatalf("unexpected error: %v", mResp.Error)
	}
	if mResp.TxNum != 0 {
		t.Errorf("tx num = %d, want 0", mResp.TxNum)
	}

	// Insert a tx.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash: *testutil.String2Hash("ee"), Index: 0,
		},
	})
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))

	mptx := &MempoolTx{
		id:      tx.TxHash(),
		expires: time.Now().Add(time.Hour),
		size:    250,
		tx:      tx,
	}
	if err := mp.TxInsert(ctx, mptx); err != nil {
		t.Fatal(err)
	}

	resp, err = s.handleMempoolInfoRequest(ctx, &tbcapi.MempoolInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	mResp = resp.(*tbcapi.MempoolInfoResponse)
	if mResp.TxNum != 1 {
		t.Errorf("tx num = %d, want 1", mResp.TxNum)
	}
	if mResp.Size == 0 {
		t.Error("size should be > 0")
	}
}

func TestUnconfirmedUtxosNoOutputs(t *testing.T) {
	ctx := t.Context()

	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}

	// Tx with inputs but no outputs (degenerate but valid struct).
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash: *testutil.String2Hash("ff"), Index: 0,
		},
	})

	err = mp.TxInsert(ctx, &MempoolTx{
		id: tx.TxHash(), expires: time.Now().Add(time.Hour), tx: tx,
	})
	if err != nil {
		t.Fatal(err)
	}

	utxos, shs, spent, err := mp.UnconfirmedUtxos(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 0 {
		t.Errorf("got %d utxos, want 0", len(utxos))
	}
	if len(shs) != 0 {
		t.Errorf("got %d shs, want 0", len(shs))
	}
	if len(spent) != 1 {
		t.Errorf("got %d spent, want 1", len(spent))
	}
}
