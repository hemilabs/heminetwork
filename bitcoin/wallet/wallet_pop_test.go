// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul/memory"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
)

// popFixture sets up a P2PKH key in zuul, a single funding UTXO,
// and a fresh L2Keystone suitable for PoP construction.
type popFixture struct {
	params   *chaincfg.Params
	zuul     zuul.Zuul
	priv     *btcec.PrivateKey
	pkScript []byte
	utxo     *tbcapi.UTXO
	keystone *hemi.L2Keystone
	outpoint wire.OutPoint
}

func newPoPFixture(t *testing.T) *popFixture {
	t.Helper()
	params := &chaincfg.TestNet3Params

	m, err := memory.New(params)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PutKey(&zuul.NamedKey{Name: "pop", PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}

	pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	fundHash := chainhash.DoubleHashH([]byte("pop-regression-funding-txid-000"))
	utxo := &tbcapi.UTXO{
		TxId:     fundHash,
		OutIndex: 0,
		Value:    btcutil.Amount(500_000),
	}

	keystone := &hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      0xbadc0ffe,
		L2BlockNumber:      0xdeadbeef,
		ParentEPHash:       testutil.SHA256([]byte{1, 1, 3, 7}),
		PrevKeystoneEPHash: testutil.SHA256([]byte{0x04, 0x20, 69}),
		StateRoot:          testutil.SHA256([]byte("Hello, world!")),
		EPHash:             testutil.SHA256([]byte{0xaa, 0x55}),
	}

	return &popFixture{
		params:   params,
		zuul:     m,
		priv:     priv,
		pkScript: pkScript,
		utxo:     utxo,
		keystone: keystone,
		outpoint: wire.OutPoint{Hash: fundHash, Index: 0},
	}
}

// TestPoPTransactionStructure verifies PoPTransactionCreate produces
// the expected shape: exactly one input, an OP_RETURN output carrying
// the abbreviated keystone, and a PrevOuts entry for the single input
// holding both the UTXO value and pkScript.
func TestPoPTransactionStructure(t *testing.T) {
	f := newPoPFixture(t)

	popTx, prevOuts, err := PoPTransactionCreate(f.keystone,
		uint32(time.Now().Unix()), 10.0,
		[]*tbcapi.UTXO{f.utxo}, f.pkScript)
	if err != nil {
		t.Fatalf("PoPTransactionCreate: %v", err)
	}

	if got := len(popTx.TxIn); got != 1 {
		t.Fatalf("PoP tx must have exactly 1 input, got %d", got)
	}
	if got := popTx.TxIn[0].PreviousOutPoint; got != f.outpoint {
		t.Fatalf("input outpoint mismatch: got %v want %v", got, f.outpoint)
	}

	// Locate the OP_RETURN output.
	var opReturnScript []byte
	opReturnIdx := -1
	for i, out := range popTx.TxOut {
		if len(out.PkScript) > 0 && out.PkScript[0] == txscript.OP_RETURN {
			opReturnScript = out.PkScript
			opReturnIdx = i
			break
		}
	}
	if opReturnIdx < 0 {
		t.Fatal("PoP tx missing OP_RETURN output")
	}
	if popTx.TxOut[opReturnIdx].Value != 0 {
		t.Fatalf("OP_RETURN output must have zero value, got %d",
			popTx.TxOut[opReturnIdx].Value)
	}

	// Round-trip: the OP_RETURN must parse back to the same abbreviated
	// keystone we started with.
	parsed, err := pop.ParseTransactionL2FromOpReturn(opReturnScript)
	if err != nil {
		t.Fatalf("ParseTransactionL2FromOpReturn: %v", err)
	}
	want := hemi.L2KeystoneAbbreviate(*f.keystone)
	gotBytes := parsed.L2Keystone.Serialize()
	wantBytes := want.Serialize()
	if !bytes.Equal(gotBytes[:], wantBytes[:]) {
		t.Fatalf("abbreviated keystone round-trip mismatch")
	}

	// PrevOuts must carry the funding UTXO's value and script so
	// that any future signing path (including witness sighash)
	// has the amount available.
	prev, ok := prevOuts[f.outpoint.String()]
	if !ok {
		t.Fatal("prevOuts missing funding outpoint")
	}
	if prev.Value != int64(f.utxo.Value) {
		t.Fatalf("prevOuts value mismatch: got %d want %d",
			prev.Value, int64(f.utxo.Value))
	}
	if !bytes.Equal(prev.PkScript, f.pkScript) {
		t.Fatalf("prevOuts pkScript mismatch")
	}
}

// TestPoPTransactionSignValidates runs a PoP transaction through the
// full construction + signing + verification path.  The signed input
// must satisfy the script engine with its previous pkScript, proving
// the signature is well-formed and matches the right key.
//
// This guards against regressions in the script-class dispatch added
// to TransactionSign: if the P2PKH legacy path is ever broken, this
// test fails.
func TestPoPTransactionSignValidates(t *testing.T) {
	f := newPoPFixture(t)

	popTx, prevOuts, err := PoPTransactionCreate(f.keystone,
		uint32(time.Now().Unix()), 10.0,
		[]*tbcapi.UTXO{f.utxo}, f.pkScript)
	if err != nil {
		t.Fatalf("PoPTransactionCreate: %v", err)
	}

	err = TransactionSign(f.params, f.zuul, popTx, prevOuts)
	if err != nil {
		t.Fatalf("TransactionSign: %v", err)
	}

	// A signed P2PKH input has a non-empty SignatureScript and no witness.
	if len(popTx.TxIn[0].SignatureScript) == 0 {
		t.Fatal("PoP input missing SignatureScript after signing")
	}
	if len(popTx.TxIn[0].Witness) != 0 {
		t.Fatalf("PoP P2PKH input must not have witness data, got %d elements",
			len(popTx.TxIn[0].Witness))
	}

	prev := prevOuts[f.outpoint.String()]
	if err := verifyInput(popTx, 0, prev); err != nil {
		t.Fatalf("script engine rejected signed PoP input: %v", err)
	}
}

// TestPoPNoWitnessDataLeak verifies that a signed P2PKH PoP transaction
// has zero witness data across all inputs.  A witness on a legacy input
// is a protocol violation that some nodes would reject; the refactored
// signing path must never emit witness data for non-segwit inputs.
func TestPoPNoWitnessDataLeak(t *testing.T) {
	f := newPoPFixture(t)

	popTx, prevOuts, err := PoPTransactionCreate(f.keystone,
		uint32(time.Now().Unix()), 10.0,
		[]*tbcapi.UTXO{f.utxo}, f.pkScript)
	if err != nil {
		t.Fatal(err)
	}
	if err := TransactionSign(f.params, f.zuul, popTx, prevOuts); err != nil {
		t.Fatal(err)
	}

	if popTx.HasWitness() {
		t.Fatal("P2PKH PoP transaction must not have witness data")
	}
	for i, txIn := range popTx.TxIn {
		if len(txIn.Witness) != 0 {
			t.Fatalf("input %d has witness data: %d elements", i, len(txIn.Witness))
		}
	}
}

// TestPoPSighashCacheSafeOnLegacyOnly is a regression guard for the
// sighash cache computation introduced in the P2WPKH work.
//
// TransactionSign unconditionally calls txscript.NewTxSigHashes to
// precompute the BIP-143 midstate for witness inputs.  For legacy-only
// transactions (the PoP case) that call must not panic, must not
// corrupt the prevOuts fetcher, and must still allow the P2PKH path
// to sign correctly.  Running the full PoP flow multiple times in a
// tight loop catches any hidden state dependency that would surface
// as non-determinism.
func TestPoPSighashCacheSafeOnLegacyOnly(t *testing.T) {
	for i := 0; i < 5; i++ {
		f := newPoPFixture(t)

		popTx, prevOuts, err := PoPTransactionCreate(f.keystone,
			uint32(time.Now().Unix()), 10.0,
			[]*tbcapi.UTXO{f.utxo}, f.pkScript)
		if err != nil {
			t.Fatalf("iteration %d: PoPTransactionCreate: %v", i, err)
		}

		err = TransactionSign(f.params, f.zuul, popTx, prevOuts)
		if err != nil {
			t.Fatalf("iteration %d: TransactionSign: %v", i, err)
		}

		prev := prevOuts[f.outpoint.String()]
		if err := verifyInput(popTx, 0, prev); err != nil {
			t.Fatalf("iteration %d: engine rejected signed input: %v", i, err)
		}
	}
}

// TestPoPPrevOutsFetcherRoundTrip exercises prevOutsFetcher directly
// against a PoP-shaped prevOuts map.  Silent loss of an entry would
// cause NewTxSigHashes to dereference a nil TxOut and panic; this
// test asserts the fetcher returns the expected amount and pkScript
// for the one and only PoP input.
func TestPoPPrevOutsFetcherRoundTrip(t *testing.T) {
	f := newPoPFixture(t)

	_, prevOuts, err := PoPTransactionCreate(f.keystone,
		uint32(time.Now().Unix()), 10.0,
		[]*tbcapi.UTXO{f.utxo}, f.pkScript)
	if err != nil {
		t.Fatal(err)
	}

	fetcher := prevOutsFetcher(prevOuts)
	got := fetcher.FetchPrevOutput(f.outpoint)
	if got == nil {
		t.Fatal("fetcher returned nil for known outpoint (key parse failure)")
	}
	if got.Value != int64(f.utxo.Value) {
		t.Fatalf("fetcher value mismatch: got %d want %d",
			got.Value, int64(f.utxo.Value))
	}
	if !bytes.Equal(got.PkScript, f.pkScript) {
		t.Fatalf("fetcher pkScript mismatch")
	}
}
