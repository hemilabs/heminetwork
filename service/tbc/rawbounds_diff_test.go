// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

// TestZZDifferentialAgainstBtcd is O2's method: any payload btcd DESERIALIZES but the guard REFUSES
// is a false reject, which under Holocene is the silent-fork direction.
func TestZZDifferentialAgainstBtcd(t *testing.T) {
	r := rand.New(rand.NewSource(20260830))
	var blkFalse, txFalse, blkOK, txOK, blkWithTxs int
	for i := 0; i < 400000; i++ {
		n := 1 + r.Intn(200)
		p := make([]byte, n)
		r.Read(p)
		// Bias a large share toward well-formed-looking block prefixes.
		if i%3 == 0 && n > 82 {
			for j := 0; j < 80; j++ {
				p[j] = byte(r.Intn(256))
			}
			p[80] = byte(r.Intn(4))
		}
		// Generate a structurally VALID block, not random bytes.
		//
		// The random path produces only txCount==0 blocks, for which boundRawBlockCounts returns nil
		// unconditionally -- so the block half of this differential was STRUCTURALLY INCAPABLE of
		// reporting a false reject, and its "near-vacuous" floor counted ACCEPTED payloads rather
		// than EXERCISED ones, so it did not catch that. Measured: it reported 20,308 blocks and 0
		// false rejects while never once exercising the transaction scan.
		if i%2 == 0 {
			var gbk bytes.Buffer
			gbk.Write(make([]byte, wire.MaxBlockHeaderPayload))
			ntx := 1 + r.Intn(3)
			_ = wire.WriteVarInt(&gbk, 0, uint64(ntx))
			for t2 := 0; t2 < ntx; t2++ {
				gt := wire.NewMsgTx(1)
				for k := 0; k < 1+r.Intn(3); k++ {
					in := &wire.TxIn{Sequence: 0xffffffff, SignatureScript: make([]byte, r.Intn(20))}
					r.Read(in.SignatureScript)
					gt.AddTxIn(in)
				}
				for k := 0; k < r.Intn(3); k++ {
					pk := make([]byte, r.Intn(20))
					r.Read(pk)
					gt.AddTxOut(&wire.TxOut{Value: int64(r.Intn(1 << 20)), PkScript: pk})
				}
				_ = gt.SerializeNoWitness(&gbk)
			}
			p = gbk.Bytes()
		}

		var mb wire.MsgBlock
		if mb.Deserialize(bytes.NewReader(p)) == nil {
			blkOK++
			if len(mb.Transactions) > 0 {
				blkWithTxs++
			}
			if err := boundRawBlockCounts(p); err != nil {
				blkFalse++
				if blkFalse <= 3 {
					t.Errorf("BLOCK FALSE REJECT (%d bytes, %d txs): %v", len(p), len(mb.Transactions), err)
				}
			}
		}
		// Structurally VALID transactions: random bytes almost never form one, so generate them.
		gen := wire.NewMsgTx(int32(r.Intn(3)))
		for k := 0; k < 1+r.Intn(4); k++ {
			in := &wire.TxIn{Sequence: 0xffffffff, SignatureScript: make([]byte, r.Intn(40))}
			r.Read(in.SignatureScript)
			if r.Intn(2) == 0 {
				for w := 0; w < r.Intn(3); w++ {
					item := make([]byte, r.Intn(20))
					r.Read(item)
					in.Witness = append(in.Witness, item)
				}
			}
			gen.AddTxIn(in)
		}
		for k := 0; k < r.Intn(4); k++ {
			pk := make([]byte, r.Intn(30))
			r.Read(pk)
			gen.AddTxOut(&wire.TxOut{Value: int64(r.Intn(1 << 30)), PkScript: pk})
		}
		var gb bytes.Buffer
		if gen.Serialize(&gb) == nil {
			p = gb.Bytes()
		}

		var mt wire.MsgTx
		if mt.Deserialize(bytes.NewReader(p)) == nil {
			txOK++
			if err := boundRawTxCounts(p); err != nil {
				txFalse++
				if txFalse <= 3 {
					t.Errorf("TX FALSE REJECT (%d bytes, %d in %d out): %v", len(p), len(mt.TxIn), len(mt.TxOut), err)
				}
			}
		}
	}
	t.Logf("DIFFERENTIAL: btcd accepted %d blocks / %d txs; guard false rejects: blocks=%d txs=%d",
		blkOK, txOK, blkFalse, txFalse)
	// The floor must count EXERCISED payloads, not merely accepted ones. blkOK alone is satisfied by
	// txCount==0 blocks that never reach the transaction scan at all.
	if blkOK < 100 || txOK < 100 || blkWithTxs < 100 {
		t.Fatalf("differential is near-vacuous: %d blocks accepted, %d of them with transactions, "+
			"%d txs. A block with no transactions exercises none of the scan, so blkWithTxs is the "+
			"number that matters.", blkOK, blkWithTxs, txOK)
	}
	t.Logf("EXERCISED: %d of %d accepted blocks carried transactions", blkWithTxs, blkOK)
}
