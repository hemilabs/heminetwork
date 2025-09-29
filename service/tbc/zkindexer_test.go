// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
	"github.com/hemilabs/heminetwork/v2/testutil"
)

func TestZKEncodeRetrieve(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()
	cfg, err := level.NewConfig("localnet", home,
		"", "")
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
	blockHash := randomHash()
	txId := randomHash()
	prevHash := randomHash()
	var balance uint64 = 10

	// ScriptHash
	shbytes := testutil.FillBytes(fmt.Sprintf("scripthash%d", index), len(tbcd.ScriptHash{}))
	sh := tbcd.NewScriptHashFromScript(shbytes)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], balance)
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

	err = db.BlockZKUpdate(ctx, 1, cache, chainhash.Hash{})
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve values by encoded key and assert values

	// Outpoint
	rv, rid, err := db.ZKValueAndScriptByOutpoint(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	if balance != rv {
		t.Fatalf("expected %v, got %v", balance, rv)
	}
	if !bytes.Equal(txId[:], rid) {
		t.Fatalf("expected %x, got %x", txId, rid)
	}

	// ScriptHash
	rv, err = db.ZKBalanceByScriptHash(ctx, sh)
	if err != nil {
		t.Fatal(err)
	}
	if balance != rv {
		t.Fatalf("expected %v, got %v", balance, rv)
	}

	// SpentOut
	out, err := db.ZKSpentOutputs(ctx, sh)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 spent output, got %d", len(out))
	}
	rout := out[0]
	if !bytes.Equal(sh[:], rout.ScriptHash[:]) {
		t.Fatalf("expected %x, got %x", sh, rout.ScriptHash[:])
	}
	if index != int(rout.BlockHeight) {
		t.Fatalf("expected %v, got %v", index, rout.BlockHeight)
	}
	if !bytes.Equal(blockHash[:], rout.BlockHash[:]) {
		t.Fatalf("expected %x, got %x", blockHash, rout.BlockHash)
	}
	if !bytes.Equal(txId[:], rout.TxID[:]) {
		t.Fatalf("expected %x, got %x", txId, rout.TxID)
	}
	if !bytes.Equal(prevHash[:], rout.PrevOutpointHash[:]) {
		t.Fatalf("expected %x, got %x", prevHash, rout.PrevOutpointHash)
	}
	if index-1 != int(rout.PrevOutpointIndex) {
		t.Fatalf("expected %v, got %v", index-1, rout.PrevOutpointIndex)
	}
	if rout.TxInIndex != 0 {
		t.Fatalf("expected %v, got %v", 0, rout.TxInIndex)
	}

	// SpendableOut
	sout, err := db.ZKSpendableOutputs(ctx, sh)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 spendable output, got %d", len(out))
	}
	srout := sout[0]
	if !bytes.Equal(sh[:], srout.ScriptHash[:]) {
		t.Fatalf("expected %x, got %x", sh, srout.ScriptHash[:])
	}
	if index != int(srout.BlockHeight) {
		t.Fatalf("expected %v, got %v", index, srout.BlockHeight)
	}
	if !bytes.Equal(blockHash[:], srout.BlockHash[:]) {
		t.Fatalf("expected %x, got %x", blockHash, srout.BlockHash)
	}
	if !bytes.Equal(txId[:], srout.TxID[:]) {
		t.Fatalf("expected %x, got %x", txId, srout.TxID)
	}
	if srout.TxOutIndex != 0 {
		t.Fatalf("expected %v, got %v", 0, srout.TxOutIndex)
	}

	// SpendingOut
	spout, err := db.ZKSpendingOutpoints(ctx, *prevHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(spout) != 1 {
		t.Fatalf("expected 1 spending output, got %d", len(out))
	}
	sprout := spout[0]
	if index != int(sprout.BlockHeight) {
		t.Fatalf("expected %v, got %v", index, sprout.BlockHeight)
	}
	if !bytes.Equal(blockHash[:], sprout.BlockHash[:]) {
		t.Fatalf("expected %x, got %x", blockHash, sprout.BlockHash)
	}
	if !bytes.Equal(prevHash[:], sprout.TxID[:]) {
		t.Fatalf("expected %x, got %x", prevHash, sprout.TxID)
	}
	if uint32(index-1) != sprout.VOutIndex {
		t.Fatalf("expected %v, got %v", index, sprout.VOutIndex)
	}
	sv := sprout.SpendingOutpoint
	if !bytes.Equal(txId[:], sv.TxID[:]) {
		t.Fatalf("expected %x, got %x", txId, sv.TxID)
	}
	if uint32(index) != sv.Index {
		t.Fatalf("expected %v, got %v", index, sv.Index)
	}
}

func randomHash() *chainhash.Hash {
	b := make([]byte, len(chainhash.Hash{}))
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	h, err := chainhash.NewHash(b)
	if err != nil {
		panic(err)
	}
	return h
}
