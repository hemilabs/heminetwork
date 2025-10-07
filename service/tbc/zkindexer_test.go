// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
)

func TestZKEncodeRetrieve(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()

	createFullZKDB(ctx, t, home, 10)
}

func createFullZKDB(ctx context.Context, t *testing.T, home string, value uint64) map[tbcd.ZKIndexKey][]byte {
	cfg, err := level.NewConfig("localnet", home, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Create all types of indexes using encoders
	cache := make(map[tbcd.ZKIndexKey][]byte, 5)
	index := 99
	blockHash := testutil.RandomHash()
	txId := testutil.RandomHash()
	prevHash := testutil.RandomHash()

	// ScriptHash
	shbytes := testutil.FillBytes(fmt.Sprintf("scripthash%d", index), len(tbcd.ScriptHash{}))
	sh := tbcd.NewScriptHashFromScript(shbytes)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], value)
	cache[tbcd.ZKIndexKey(sh[:])] = v[:]

	// SpentOut
	spo := tbcd.NewSpentOutput(chainhash.Hash(sh), uint32(index),
		*blockHash, *txId, *prevHash, uint32(index-1), 0)
	cache[tbcd.ZKIndexKey(spo[:])] = nil

	// SpendingOut
	sok := tbcd.NewSpendingOutpointKey(*prevHash,
		uint32(index), *blockHash, uint32(index-1))
	cache[tbcd.ZKIndexKey(sok[:])] = tbcd.NewSpendingOutpointValueSlice(*txId, uint32(index))

	// SpendableOut
	so := tbcd.NewSpendableOutput(chainhash.Hash(sh), uint32(index),
		*blockHash, *txId, 0)
	cache[tbcd.ZKIndexKey(so[:])] = nil

	// Outpoint
	op := tbcd.NewOutpoint(*txId, 0)
	txOut := wire.TxOut{Value: 10, PkScript: txId[:]}
	cache[tbcd.ZKIndexKey(op[:])] = tbcd.NewTxOut(&txOut)

	// Insert into DB

	cloned := maps.Clone(cache)
	err = db.BlockZKUpdate(ctx, 1, cloned, chainhash.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// Retrieve values by encoded key and assert values

	// Outpoint
	rv, rid, err := db.ZKValueAndScriptByOutpoint(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	if value != rv {
		t.Fatalf("expected %v, got %v", value, rv)
	}
	if !bytes.Equal(txId[:], rid) {
		t.Fatalf("expected %x, got %x", txId, rid)
	}

	// ScriptHash
	rv, err = db.ZKBalanceByScriptHash(ctx, sh)
	if err != nil {
		t.Fatal(err)
	}
	if value != rv {
		t.Fatalf("expected %v, got %v", value, rv)
	}

	// SpentOut
	out, err := db.ZKSpentOutputs(ctx, sh)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("ZKSpentOutputs out len = %d, want 1", len(out))
	}
	rout := out[0]
	if !bytes.Equal(sh[:], rout.ScriptHash[:]) {
		t.Fatalf("got %x, expected %x", rout.ScriptHash[:], sh)
	}
	if index != int(rout.BlockHeight) {
		t.Fatalf("got %v, expected %v", rout.BlockHeight, index)
	}
	if !bytes.Equal(blockHash[:], rout.BlockHash[:]) {
		t.Fatalf("got %x, expected %x", rout.BlockHash, blockHash)
	}
	if !bytes.Equal(txId[:], rout.TxID[:]) {
		t.Fatalf("got %x, expected %x", rout.TxID, txId)
	}
	if !bytes.Equal(prevHash[:], rout.PrevOutpointHash[:]) {
		t.Fatalf("got %x, expected %x", rout.PrevOutpointHash, prevHash)
	}
	if index-1 != int(rout.PrevOutpointIndex) {
		t.Fatalf("got %v, expected %v", rout.PrevOutpointIndex, index-1)
	}
	if rout.TxInIndex != 0 {
		t.Fatalf("got %v, expected %v", rout.TxInIndex, 0)
	}

	// SpendableOut
	sout, err := db.ZKSpendableOutputs(ctx, sh)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("ZKSpendableOutputs out len = %d, want 1", len(out))
	}
	srout := sout[0]
	if !bytes.Equal(sh[:], srout.ScriptHash[:]) {
		t.Fatalf("got %x, expected %x", srout.ScriptHash[:], sh)
	}
	if index != int(srout.BlockHeight) {
		t.Fatalf("expected %v, got %v", srout.BlockHeight, index)
	}
	if !bytes.Equal(blockHash[:], srout.BlockHash[:]) {
		t.Fatalf("got %x, expected %x", srout.BlockHash, blockHash)
	}
	if !bytes.Equal(txId[:], srout.TxID[:]) {
		t.Fatalf("got %x, expected %x", srout.TxID, txId)
	}
	if srout.TxOutIndex != 0 {
		t.Fatalf("expected %v, got %v", srout.TxOutIndex, 0)
	}

	// SpendingOut
	spout, err := db.ZKSpendingOutpoints(ctx, *prevHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(spout) != 1 {
		t.Fatalf("ZKSpendingOutpoints out len = %d, want 1", len(out))
	}
	sprout := spout[0]
	if index != int(sprout.BlockHeight) {
		t.Fatalf("expected %v, got %v", sprout.BlockHeight, index)
	}
	if !bytes.Equal(blockHash[:], sprout.BlockHash[:]) {
		t.Fatalf("expected %x, got %x", sprout.BlockHash, blockHash)
	}
	if !bytes.Equal(prevHash[:], sprout.TxID[:]) {
		t.Fatalf("expected %x, got %x", sprout.TxID, prevHash)
	}
	if uint32(index-1) != sprout.VOutIndex {
		t.Fatalf("expected %v, got %v", sprout.VOutIndex, index)
	}
	sv := sprout.SpendingOutpoint
	if !bytes.Equal(txId[:], sv.TxID[:]) {
		t.Fatalf("expected %x, got %x", sv.TxID, txId)
	}
	if uint32(index) != sv.Index {
		t.Fatalf("expected %v, got %v", sv.Index, index)
	}

	return cache
}
